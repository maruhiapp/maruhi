// 招待リンクの組み立て・解釈(AUTH_SPEC §15-3 — 2026-09-13 IV 改訂・v2)。
//
// リンク形式:
//   https://<web-origin>/invite#v=2&i=<invite_id>&k=<link_seed_hex>&p=<project_id>
//     &h=<head_hash_hex>&s=<head_seq>&iu=<inviter_user_id>&ie=<inviter_enc_pub_hex>
//     &is=<inviter_sig_pub_hex>&r=<role>&sk=<scope_kind>&se=<environment_id の comma 区切り>
//     [&il=<inviter_github_login>]&sig=<issue_signature_hex>
//
// フラグメント(# 以降)はサーバーへ送信されない。`k` はリンク鍵の種(CRYPTO_SPEC
// §6.5 — 受諾側が Ed25519 鍵ペアを導出してリンク署名を作る。サーバーは受け取らない)、
// `i` / `p` / `h` / `s` / `r` / `sk` / `se` / `iu` / `ie` / `is` は発行文(発行署名 `sig`
// が覆う — 招待者のチェーン sig 鍵)、`il` は裏付け元(GitHub)の照合材料(自己申告・
// 署名外・省略可)。旧 `if`(FP)は廃止し、FP は `ie` ‖ `is` から導出する。
// `sk` / `se` は付与予定 scope(2026-09-14 ES — `sk=all` なら `se` は空。K2 の CLI は
// `all` のみ発行し、`--env` は K4)。
//
// <web-origin> には CLI セッションの server origin を使う(B1b 裁定)。解釈側は
// origin に依存しない(フラグメントのみを読む)。
//
// `k` は招待の秘密なので `Redacted` で運ぶ。組み立て済みリンクも種を内包する以上
// ただの表示可能文字列ではないため `Redacted<string>` で返し、剥がすのは表示の
// 直前(invite.ts — エージェントゲートの後ろ)だけに限る。`v=1` リンクと生トークン
// は受け付けない(互換経路を作らない 2026-09-13 所有者裁定)。

import { isEnvironmentId, isProjectId } from "@maruhi/core";
import type { ScopeKind } from "@maruhi/crypto";
import { Redacted } from "effect";

const HEX_64 = /^[0-9a-f]{64}$/;
const HEX_128 = /^[0-9a-f]{128}$/;
const ROLES = ["reader", "member", "admin"] as const;
const SCOPE_KINDS: readonly ScopeKind[] = ["all", "listed"];
/** scope の環境リスト上限(CRYPTO_SPEC §6.2 — grant_server の scope と同じ 256)。 */
const MAX_SCOPE_ENVIRONMENTS = 256;
/** 招待 id(ULID — Crockford Base32 26 文字。api-schema の InviteIdSchema と同一)。 */
const INVITE_ID = /^[0-9A-HJKMNP-TV-Z]{26}$/;
/** GitHub login(1〜39 文字の英数字とハイフン。先頭・末尾はハイフン不可)。 */
export const GITHUB_LOGIN = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;

/** 招待で付与できる role(owner は招待経由で付与しない — §15-1)。 */
export type InviteRole = (typeof ROLES)[number];

/** リンクが運ぶ発行文 + 種 + 裏付け元の照合材料(§15-3 の v2 パラメータ)。 */
export interface InviteLinkData {
  readonly inviteId: string;
  /** リンク鍵の種(32 バイト hex — 招待の秘密)。 */
  readonly linkSeedHex: Redacted.Redacted<string>;
  readonly projectId: string;
  readonly headHashHex: string;
  readonly headSeq: number;
  readonly inviterUserId: string;
  readonly inviterEncPubHex: string;
  readonly inviterSigPubHex: string;
  readonly role: InviteRole;
  /** 付与予定 scope(2026-09-14 ES — 発行署名が覆う。`all` なら環境リストは空)。 */
  readonly scopeKind: ScopeKind;
  readonly scopeEnvironmentIds: readonly string[];
  /** 招待者の GitHub login(自己申告・署名外。省略時は null)。 */
  readonly inviterLogin: string | null;
  readonly issueSignatureHex: string;
}

/**
 * §15-3 のリンクを組み立てる(パラメータ順は仕様の記載順で固定)。
 *
 * 戻り値も種を内包するため `Redacted` のまま返す。剥がすのは表示側。
 */
export function buildInviteLink(input: {
  readonly origin: string;
  readonly link: InviteLinkData;
}): Redacted.Redacted<string> {
  const { link } = input;
  const params: (readonly [string, string])[] = [
    ["v", "2"],
    ["i", link.inviteId],
    // 剥がす理由: リンク文字列そのものの組み立て。結果は再び Redacted で包み、
    // 生の文字列がこの関数の外へ出ないようにする
    ["k", Redacted.value(link.linkSeedHex)],
    ["p", link.projectId],
    ["h", link.headHashHex],
    ["s", String(link.headSeq)],
    ["iu", link.inviterUserId],
    ["ie", link.inviterEncPubHex],
    ["is", link.inviterSigPubHex],
    ["r", link.role],
    ["sk", link.scopeKind],
    ["se", link.scopeEnvironmentIds.join(",")],
    ...(link.inviterLogin === null ? [] : [["il", link.inviterLogin] as const]),
    ["sig", link.issueSignatureHex],
  ];
  const fragment = params.map(([name, value]) => `${name}=${encodeURIComponent(value)}`).join("&");
  return Redacted.make(`${input.origin}/invite#${fragment}`, { label: "invite-link" });
}

/** 解釈失敗の理由(呼び出し側がエラーメッセージへ写す)。 */
export type InviteInputRejection =
  | "not-a-link"
  | "unsupported-version"
  | "missing-or-invalid-fragment-params";

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

/** `il=`(招待者の GitHub login)の解釈: 省略 = null、存在するなら login の形のみ。 */
function parseInviterLogin(params: URLSearchParams): string | null | "invalid" {
  const text = params.get("il");
  if (text === null) {
    return null;
  }
  return GITHUB_LOGIN.test(text) ? text : "invalid";
}

/** 必須の文字列パラメータ(名前 → 形式)。 */
const STRING_PARAMS = {
  i: INVITE_ID,
  k: HEX_64,
  h: HEX_64,
  iu: /^[\s\S]{1,1024}$/,
  ie: HEX_64,
  is: HEX_64,
  sig: HEX_128,
} as const;

type StringParams = Readonly<Record<keyof typeof STRING_PARAMS, string>>;

/** 必須文字列パラメータの一括取得(1 つでも欠落・不正なら null)。 */
function stringParams(params: URLSearchParams): StringParams | null {
  const out: Partial<Record<keyof typeof STRING_PARAMS, string>> = {};
  for (const [name, pattern] of Object.entries(STRING_PARAMS) as [
    keyof typeof STRING_PARAMS,
    RegExp,
  ][]) {
    const value = fragmentParam(params, name, pattern);
    if (value === null) {
      return null;
    }
    out[name] = value;
  }
  return out as StringParams;
}

/**
 * `sk=` / `se=`(付与予定 scope)の解釈: kind は閉集合、`all` なら `se` は空、`listed` は
 * comma 区切りの environment_id(§12-1 形式・重複なし・256 以下。空 = どの環境も
 * 付与しない listed)。構造規則は CRYPTO_SPEC §6.2 の scope と同じ(不正 = null)
 */
function parseScope(
  params: URLSearchParams,
): { readonly scopeKind: ScopeKind; readonly scopeEnvironmentIds: readonly string[] } | null {
  const kind = SCOPE_KINDS.find((known) => known === params.get("sk"));
  const text = params.get("se");
  if (kind === undefined || text === null) {
    return null;
  }
  if (kind === "all") {
    return text === "" ? { scopeKind: "all", scopeEnvironmentIds: [] } : null;
  }
  const ids = text === "" ? [] : text.split(",");
  if (
    ids.length > MAX_SCOPE_ENVIRONMENTS ||
    !ids.every((id) => isEnvironmentId(id)) ||
    new Set(ids).size !== ids.length
  ) {
    return null;
  }
  return { scopeKind: "listed", scopeEnvironmentIds: ids };
}

/** `p=`(プロジェクト ID)の解釈。 */
function parseProjectId(params: URLSearchParams): string | null {
  const value = params.get("p");
  return value !== null && isProjectId(value) ? value : null;
}

/** フラグメント(v=2 検証済み)からのリンクデータの解釈(不正 = null)。 */
function parseLinkData(params: URLSearchParams): InviteLinkData | null {
  const strings = stringParams(params);
  const projectId = parseProjectId(params);
  const headSeq = parseHeadSeq(params);
  const role = ROLES.find((known) => known === params.get("r")) ?? null;
  const scope = parseScope(params);
  const inviterLogin = parseInviterLogin(params);
  if (
    strings === null ||
    projectId === null ||
    headSeq === null ||
    role === null ||
    scope === null ||
    inviterLogin === "invalid"
  ) {
    return null;
  }
  return {
    inviteId: strings.i,
    linkSeedHex: Redacted.make(strings.k, { label: "invite-link-seed" }),
    projectId,
    headHashHex: strings.h,
    headSeq,
    inviterUserId: strings.iu,
    inviterEncPubHex: strings.ie,
    inviterSigPubHex: strings.is,
    role,
    scopeKind: scope.scopeKind,
    scopeEnvironmentIds: scope.scopeEnvironmentIds,
    inviterLogin,
    issueSignatureHex: strings.sig,
  };
}

/**
 * `<link>` 入力の解釈。必須パラメータの欠落・形式不正・旧版(`v=1`)・生トークンは
 * すべてエラーにする(壊れたリンクをアンカーなし受諾へ滑り込ませない。旧版・
 * 生トークンは互換経路なし — 再発行を案内する)。
 */
export function parseInviteAcceptInput(raw: Redacted.Redacted<string>):
  | { readonly kind: "link"; readonly link: InviteLinkData }
  | {
      readonly kind: "rejected";
      readonly reason: InviteInputRejection;
    } {
  // 剥がす理由: リンクの構文解釈にはバイト列そのものが要る。入力は引数層
  // (`Argument.redacted` — ADR-0016)から Redacted のまま届き、生値はこの関数の
  // 外へ出ない — 種は再び Redacted で包んで返し、他のパラメータは公開値である
  const trimmed = Redacted.value(raw).trim();
  const hashIndex = trimmed.indexOf("#");
  if (hashIndex < 0) {
    return { kind: "rejected", reason: "not-a-link" };
  }
  const params = new URLSearchParams(trimmed.slice(hashIndex + 1));
  const version = params.get("v");
  if (version === null) {
    return { kind: "rejected", reason: "missing-or-invalid-fragment-params" };
  }
  if (version !== "2") {
    return { kind: "rejected", reason: "unsupported-version" };
  }
  const link = parseLinkData(params);
  if (link === null) {
    return { kind: "rejected", reason: "missing-or-invalid-fragment-params" };
  }
  return { kind: "link", link };
}
