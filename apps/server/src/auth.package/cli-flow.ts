// CLI ログインのフロー資格情報(AUTH_SPEC §4-1 (1) / §4-2)。
//
// start は無記録(裁定 DH)であり、フローの真正性は 2 系統の HMAC-SHA-256 で
// 無状態に検証する:
//
// - flowToken: CLI 専用の bearer 資格情報。自己完結の署名形式
//   `v1.<expMs>.<randHex>.<macHex>` で、**flowId を署名対象に含める**(§4-1 (1)
//   の要件 — 「被害者の flowId + 自前の flowToken」の組み替えで他人のフローを
//   poll する経路の遮断)。ブラウザチャネルには決して載せない
// - vsig: verificationUrl のクエリ(flowId・期限・userCode・発行パラメータ)
//   全体を覆うブラウザ脚用 MAC。URL の知識はポーリング資格を一切与えない
//
// 2 系統は**用途タグでドメイン分離**し、署名入力は LP(長さ前置き)符号化で
// 一意に復号可能にする(§4-2 — フィールド境界の曖昧さで別の入力列が同じ
// バイト列に潰れない)。LP エンコーダは packages/crypto の既存実装を使う
// (プリミティブの発明ではない)。この鍵は E2EE の鍵素材ではない
// (CRYPTO_SPEC の対象外 — §4-2 に明記。短命なログインフロー資格の完全性のみ)。

import { decodeHex, encodeHex, encodeLengthPrefixed } from "@maruhi/crypto";

import { constantTimeEqual } from "../ids.ts";

/** フローの期限(AUTH_SPEC §4-1 (1) 起草値 15 分)。 */
export const CLI_FLOW_TTL_MS = 15 * 60 * 1000;

// ドメイン分離の用途タグ(§4-2 — 一方が他方として検証を通らない)
const FLOW_TOKEN_DOMAIN = "maruhi/v1/cli-flow-token";
const VSIG_DOMAIN = "maruhi/v1/cli-verify-url";

const FLOW_TOKEN_VERSION = "v1";
const SIGNING_KEY_BYTES = 32;
const FLOW_TOKEN_RANDOM_BYTES = 32;

/**
 * D1 保存の鍵素材(hex)を WebCrypto の HMAC 鍵へインポートする。形式不正は
 * defect(鍵は自分の生成経路 — FlowSigningKeyRepo — でしか書かれない)。
 */
export async function importFlowSigningKey(keyHex: string): Promise<CryptoKey> {
  const raw = decodeHex(keyHex);
  if (raw === null || raw.length !== SIGNING_KEY_BYTES) {
    throw new Error("stored flow signing key is not 32-byte hex");
  }
  return crypto.subtle.importKey(
    "raw",
    raw as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

async function macHex(
  key: CryptoKey,
  domain: string,
  fields: readonly (string | number)[],
): Promise<string> {
  const bytes = encodeLengthPrefixed([domain, ...fields]);
  return encodeHex(new Uint8Array(await crypto.subtle.sign("HMAC", key, bytes as BufferSource)));
}

// ---------------------------------------------------------------------------
// userCode(§4-1 (2) — 照合用の短い表示コード。秘密ではない)
// ---------------------------------------------------------------------------

// 視認混同の少ない 32 字(Crockford Base32 の字面)。256 % 32 = 0 なので
// バイト値の mod にバイアスはない
const USER_CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** 照合用コード(`XXXX-XXXX`)。CLI と承認ページの双方に表示する摩擦装置。 */
export function generateUserCode(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  let code = "";
  for (const [index, byte] of bytes.entries()) {
    if (index === 4) {
      code += "-";
    }
    code += USER_CODE_ALPHABET[byte % 32];
  }
  return code;
}

// ---------------------------------------------------------------------------
// flowToken(§4-1 (1) — CLI 専用 bearer。ブラウザチャネル禁止)
// ---------------------------------------------------------------------------

/** 自己完結の flowToken を発行する(256-bit 乱数 + flowId + 期限を MAC で覆う)。 */
export async function createFlowToken(
  key: CryptoKey,
  flowId: string,
  expiresAtMs: number,
): Promise<string> {
  const random = encodeHex(crypto.getRandomValues(new Uint8Array(FLOW_TOKEN_RANDOM_BYTES)));
  const mac = await macHex(key, FLOW_TOKEN_DOMAIN, [flowId, random, expiresAtMs]);
  return `${FLOW_TOKEN_VERSION}.${expiresAtMs}.${random}.${mac}`;
}

/**
 * poll の無状態検証(§4-1 (5)): MAC・**署名内 flowId と提示 flowId の組一致**・
 * 期限。判定順は MAC が先(期限は署名済みの自己申告値であり、MAC が通らない
 * トークンの期限は意味を持たない)。invalid = 一様拒否(CliFlowRejected)、
 * expired = 正当な保持者への型付き終了指示(CliFlowExpired — §4-2)。
 */
type FlowTokenVerdict = "valid" | "expired" | "invalid";

export async function verifyFlowToken(
  key: CryptoKey,
  flowId: string,
  flowToken: string,
  nowMs: number,
): Promise<FlowTokenVerdict> {
  const parts = flowToken.split(".");
  if (parts.length !== 4) {
    return "invalid";
  }
  const [version, expiresPart, random, mac] = parts as [string, string, string, string];
  if (version !== FLOW_TOKEN_VERSION || !/^\d{1,15}$/.test(expiresPart)) {
    return "invalid";
  }
  const expiresAtMs = Number(expiresPart);
  const expected = await macHex(key, FLOW_TOKEN_DOMAIN, [flowId, random, expiresAtMs]);
  if (!constantTimeEqual(mac, expected)) {
    return "invalid";
  }
  return expiresAtMs > nowMs ? "valid" : "expired";
}

// ---------------------------------------------------------------------------
// vsig(§4-1 (1) — verificationUrl のブラウザ脚用 MAC)
// ---------------------------------------------------------------------------

/**
 * verificationUrl が運ぶ vsig 済みパラメータ一式(§4-1 (1))。scopes は URL に
 * 載せた JSON 文字列そのままを署名・検証する(正規形の再解釈をしない)。
 */
export interface CliVerifyParams {
  readonly flowId: string;
  readonly expiresAtMs: number;
  readonly userCode: string;
  readonly tokenName: string;
  readonly scopesJson: string;
  readonly expiresInDays: number;
}

function vsigFields(params: CliVerifyParams): readonly (string | number)[] {
  return [
    params.flowId,
    params.expiresAtMs,
    params.userCode,
    params.tokenName,
    params.scopesJson,
    params.expiresInDays,
  ];
}

export async function computeVsig(key: CryptoKey, params: CliVerifyParams): Promise<string> {
  return macHex(key, VSIG_DOMAIN, vsigFields(params));
}

/** vsig 済みパラメータから verify URL のクエリを組む(start と案内リンクで共有)。 */
export function verificationQuery(params: CliVerifyParams, vsig: string): URLSearchParams {
  const query = new URLSearchParams();
  query.set("flow", params.flowId);
  query.set("exp", String(params.expiresAtMs));
  query.set("code", params.userCode);
  query.set("name", params.tokenName);
  query.set("scopes", params.scopesJson);
  query.set("days", String(params.expiresInDays));
  query.set("vsig", vsig);
  return query;
}

/** ブラウザ脚が受け取る生クエリ(verify のクエリ / callback の cookie 復元)。 */
interface RawCliVerifyQuery {
  readonly flow?: string | undefined;
  readonly exp?: string | undefined;
  readonly code?: string | undefined;
  readonly name?: string | undefined;
  readonly scopes?: string | undefined;
  readonly days?: string | undefined;
  readonly vsig?: string | undefined;
}

/**
 * verify 到達の無状態検証(§4-1 (3)): 欠落・改竄・期限切れはすべて null =
 * 一様なエラーページ(§4-2 — 出し分けない。GitHub へのリダイレクトが起きる
 * 前に fail-closed)。検証を通った場合のみ確定パラメータを返す。
 */
export async function verifyCliVerifyQuery(
  key: CryptoKey,
  raw: RawCliVerifyQuery,
  nowMs: number,
): Promise<CliVerifyParams | null> {
  const { flow, exp, code, name, scopes, days, vsig } = raw;
  if (
    flow === undefined ||
    exp === undefined ||
    code === undefined ||
    name === undefined ||
    scopes === undefined ||
    days === undefined ||
    vsig === undefined
  ) {
    return null;
  }
  if (!/^\d{1,15}$/.test(exp) || !/^\d{1,4}$/.test(days)) {
    return null;
  }
  const params: CliVerifyParams = {
    flowId: flow,
    expiresAtMs: Number(exp),
    userCode: code,
    tokenName: name,
    scopesJson: scopes,
    expiresInDays: Number(days),
  };
  const expected = await computeVsig(key, params);
  if (!constantTimeEqual(vsig, expected)) {
    return null;
  }
  return params.expiresAtMs > nowMs ? params : null;
}
