// 招待リンクの組み立て・解釈(AUTH_SPEC §15-3)。
//
// リンク形式:
//   https://<web-origin>/invite#v=1&t=<token>&p=<project_id>&h=<head_hash_hex>
//     &s=<head_seq>&iu=<inviter_user_id>&if=<inviter_key_fp_hex>&r=<role>
//
// フラグメント(# 以降)はサーバーへ送信されない。`p/h/s` は招待リンクアンカー
// (CRYPTO_SPEC §6.3 (a))、`iu/if` は相互確認(§6.5)の照合材料、`r` は付与予定
// role の表示専用パラメータ(省略可 — 2026-08-15 追補。真実源は招待レコード)。
//
// <web-origin> には CLI セッションの server origin を使う(B1b 裁定):
// 招待は 7 日で失効するため(§15-1)、Web 受諾画面が別 origin に載る将来が
// 来ても、その時点で旧リンクは全て失効済みであり移行問題は構造的に生じない。
// 解釈側は origin に依存しない(フラグメントのみを読む)。
//
// `t=` は招待トークンの生値なので `Redacted` で運ぶ。組み立て済みリンクも
// トークンを内包する以上ただの表示可能文字列ではないため `Redacted<string>`
// で返し、剥がすのは表示の直前(invite.ts — エージェントゲートの後ろ)だけに
// 限る。

import { isProjectId } from "@maruhi/core";
import { Redacted } from "effect";

/** 招待トークンのワイヤ形式(api-schema の InviteTokenSchema と同一)。 */
const INVITE_TOKEN = /^maruhi_inv_[0-9A-Za-z]{43}$/;

const HEX_64 = /^[0-9a-f]{64}$/;
const HEX_32 = /^[0-9a-f]{32}$/;
const ROLES = ["reader", "member", "admin"] as const;

/** 招待で付与できる role(owner は招待経由で付与しない — §15-1)。 */
export type InviteRole = (typeof ROLES)[number];

/** リンクが運ぶアンカー + 相互確認材料(§15-3 の p/h/s/iu/if)。 */
export interface InviteLinkData {
  readonly token: Redacted.Redacted<string>;
  readonly projectId: string;
  readonly headHashHex: string;
  readonly headSeq: number;
  readonly inviterUserId: string;
  readonly inviterKeyFingerprintHex: string;
  /** 表示専用の付与予定 role(r — 省略可。追補前のリンクは null)。 */
  readonly role: InviteRole | null;
}

/** `maruhi invite accept <link|token>` の入力の解釈結果。 */
export type InviteAcceptInput =
  | { readonly kind: "link"; readonly link: InviteLinkData }
  | { readonly kind: "token"; readonly token: Redacted.Redacted<string> };

/**
 * §15-3 のリンクを組み立てる(パラメータ順は仕様の記載順で固定)。
 *
 * 戻り値もトークンを内包するため `Redacted` のまま返す。剥がすのは表示側。
 */
export function buildInviteLink(input: {
  readonly origin: string;
  readonly token: Redacted.Redacted<string>;
  readonly projectId: string;
  readonly headHashHex: string;
  readonly headSeq: number;
  readonly inviterUserId: string;
  readonly inviterKeyFingerprintHex: string;
  readonly role: InviteRole;
}): Redacted.Redacted<string> {
  const params = [
    ["v", "1"],
    // 剥がす理由: リンク文字列そのものの組み立て。結果は再び Redacted で包み、
    // 生の文字列がこの関数の外へ出ないようにする
    ["t", Redacted.value(input.token)],
    ["p", input.projectId],
    ["h", input.headHashHex],
    ["s", String(input.headSeq)],
    ["iu", input.inviterUserId],
    ["if", input.inviterKeyFingerprintHex],
    ["r", input.role],
  ] as const;
  const fragment = params.map(([name, value]) => `${name}=${encodeURIComponent(value)}`).join("&");
  return Redacted.make(`${input.origin}/invite#${fragment}`, { label: "invite-link" });
}

/** 解釈失敗の理由(呼び出し側がエラーメッセージへ写す)。 */
export type InviteInputRejection =
  | "not-a-link-or-token"
  | "unsupported-version"
  | "missing-or-invalid-fragment-params";

/**
 * `<link|token>` 入力の解釈。リンクは必須パラメータの欠落・形式不正を
 * **黙って生トークン扱いへ降格させず**エラーにする(壊れたリンクをアンカー
 * なし受諾へ滑り込ませない)。`r` は省略可、ただし存在する場合は正しい role
 * であることを要求する(表示専用でも壊れた値は改竄・破損の兆候)。
 */
/** パターン検証つきのフラグメントパラメータ取得(不一致 = null)。 */
function fragmentParam(params: URLSearchParams, name: string, pattern: RegExp): string | null {
  const value = params.get(name);
  return value !== null && pattern.test(value) ? value : null;
}

/** `s=`(検証済みヘッド seq)の解釈(正整数の 10 進のみ)。 */
function parseHeadSeq(params: URLSearchParams): number | null {
  const text = fragmentParam(params, "s", /^[1-9][0-9]*$/);
  if (text === null) {
    return null;
  }
  const value = Number.parseInt(text, 10);
  return Number.isSafeInteger(value) ? value : null;
}

/** `r=`(表示専用 role)の解釈: 省略 = null、存在するなら正しい role のみ。 */
function parseLinkRole(params: URLSearchParams): InviteRole | null | "invalid" {
  const text = params.get("r");
  if (text === null) {
    return null;
  }
  return ROLES.find((known) => known === text) ?? "invalid";
}

/** フラグメント(v=1 検証済み)からのリンクデータの解釈(不正 = null)。 */
function parseLinkData(params: URLSearchParams): InviteLinkData | null {
  const token = fragmentParam(params, "t", INVITE_TOKEN);
  const projectId = params.get("p");
  const headHashHex = fragmentParam(params, "h", HEX_64);
  const headSeq = parseHeadSeq(params);
  const inviterUserId = fragmentParam(params, "iu", /^[\s\S]{1,1024}$/);
  const inviterKeyFingerprintHex = fragmentParam(params, "if", HEX_32);
  const role = parseLinkRole(params);
  if (
    token === null ||
    projectId === null ||
    !isProjectId(projectId) ||
    headHashHex === null ||
    headSeq === null ||
    inviterUserId === null ||
    inviterKeyFingerprintHex === null ||
    role === "invalid"
  ) {
    return null;
  }
  return {
    token: Redacted.make(token, { label: "invite-token" }),
    projectId,
    headHashHex,
    headSeq,
    inviterUserId,
    inviterKeyFingerprintHex,
    role,
  };
}

export function parseInviteAcceptInput(
  raw: Redacted.Redacted<string>,
): InviteAcceptInput | { readonly kind: "rejected"; readonly reason: InviteInputRejection } {
  // 剥がす理由: リンク / トークンの構文解釈にはバイト列そのものが要る。入力は
  // 引数層(`Argument.redacted` — ADR-0016 第 2 段階の invite 移行)から
  // Redacted のまま届き、生値はこの関数の外へ出ない — トークンは再び Redacted で
  // 包んで返し、リンクの他パラメータ(p/h/s/iu/if/r)は非機密メタデータである
  const trimmed = Redacted.value(raw).trim();
  if (INVITE_TOKEN.test(trimmed)) {
    return { kind: "token", token: Redacted.make(trimmed, { label: "invite-token" }) };
  }
  const hashIndex = trimmed.indexOf("#");
  if (hashIndex < 0) {
    return { kind: "rejected", reason: "not-a-link-or-token" };
  }
  const params = new URLSearchParams(trimmed.slice(hashIndex + 1));
  const version = params.get("v");
  if (version === null) {
    return { kind: "rejected", reason: "missing-or-invalid-fragment-params" };
  }
  if (version !== "1") {
    return { kind: "rejected", reason: "unsupported-version" };
  }
  const link = parseLinkData(params);
  if (link === null) {
    return { kind: "rejected", reason: "missing-or-invalid-fragment-params" };
  }
  return { kind: "link", link };
}
