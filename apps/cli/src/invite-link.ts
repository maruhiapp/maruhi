// Building and interpreting invite links (AUTH_SPEC §15-3 —
// 2026-09-13 IV revision, v2).
//
// Link format:
//   https://<web-origin>/invite#v=2&i=<invite_id>&k=<link_seed_hex>&p=<project_id>
//     &h=<head_hash_hex>&s=<head_seq>&iu=<inviter_user_id>&ie=<inviter_enc_pub_hex>
//     &is=<inviter_sig_pub_hex>&r=<role>&sk=<scope_kind>&se=<comma-separated environment_id>
//     [&il=<inviter_github_login>]&sig=<issue_signature_hex>
//
// The fragment (after #) is never sent to the server. `k` is the
// link key's seed (CRYPTO_SPEC §6.5 — the acceptor derives an Ed25519
// keypair from it and makes the link signature; the server never
// receives it); `i` / `p` / `h` / `s` / `r` / `sk` / `se` / `iu` /
// `ie` / `is` are the issuance statement (covered by the issue
// signature `sig` — the inviter's chain sig key); `il` is the
// checking material of the backing source (GitHub) (self-declared,
// unsigned, optional). The old `if` (FP) is abolished; the FP is
// derived from `ie` ‖ `is`. `sk` / `se` are the scope to be granted
// (2026-09-14 ES — when `sk=all`, `se` is empty. The K2 CLI only
// issues `all`; `--env` is K4).
//
// <web-origin> uses the CLI session's server origin (ruling B1b).
// The interpreting side does not depend on the origin (only the
// fragment is read).
//
// `k` is the invite's secret, so it travels as `Redacted`. A built
// link also embeds the seed, so it is not a mere displayable string —
// it is returned as `Redacted<string>`, and unwrapping is limited to
// just before display (invite.ts — behind the agent gate). `v=1`
// links and raw tokens are not accepted (the 2026-09-13 owner ruling
// of no compatibility path).

import { isEnvironmentId, isProjectId } from "@maruhi/core";
import type { ScopeKind } from "@maruhi/crypto";
import { Redacted } from "effect";

const HEX_64 = /^[0-9a-f]{64}$/;
const HEX_128 = /^[0-9a-f]{128}$/;
const ROLES = ["reader", "member", "admin"] as const;
const SCOPE_KINDS: readonly ScopeKind[] = ["all", "listed"];
/** Cap on scope's environment list (CRYPTO_SPEC §6.2 — the same 256 as grant_server's scope). */
const MAX_SCOPE_ENVIRONMENTS = 256;
/** Invite id (ULID — 26 Crockford Base32 chars. Identical to api-schema's InviteIdSchema). */
const INVITE_ID = /^[0-9A-HJKMNP-TV-Z]{26}$/;
/** GitHub login (1–39 chars of alphanumerics and hyphens; no leading/trailing hyphen). */
export const GITHUB_LOGIN = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;

/** Roles grantable via an invite (owner is never granted via an invite — §15-1). */
export type InviteRole = (typeof ROLES)[number];

/** The issuance statement + seed + backing-source check material a link carries (the §15-3 v2 parameters). */
export interface InviteLinkData {
  readonly inviteId: string;
  /** The link key's seed (32-byte hex — the invite's secret). */
  readonly linkSeedHex: Redacted.Redacted<string>;
  readonly projectId: string;
  readonly headHashHex: string;
  readonly headSeq: number;
  readonly inviterUserId: string;
  readonly inviterEncPubHex: string;
  readonly inviterSigPubHex: string;
  readonly role: InviteRole;
  /** The scope to be granted (2026-09-14 ES — covered by the issue signature. With `all`, the environment list is empty). */
  readonly scopeKind: ScopeKind;
  readonly scopeEnvironmentIds: readonly string[];
  /** The inviter's GitHub login (self-declared, unsigned; null when omitted). */
  readonly inviterLogin: string | null;
  readonly issueSignatureHex: string;
}

/**
 * Builds a §15-3 link (parameter order is fixed to the spec's
 * listed order).
 *
 * The return value embeds the seed too, so it is returned still
 * `Redacted`. Unwrapping is the display side's job.
 */
export function buildInviteLink(input: {
  readonly origin: string;
  readonly link: InviteLinkData;
}): Redacted.Redacted<string> {
  const { link } = input;
  const params: (readonly [string, string])[] = [
    ["v", "2"],
    ["i", link.inviteId],
    // Why it is unwrapped: assembling the link string itself. The
    // result is wrapped in Redacted again so the raw string never
    // leaves this function
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

/** Reason for a parse failure (the caller maps it to an error message). */
export type InviteInputRejection =
  | "not-a-link"
  | "unsupported-version"
  | "missing-or-invalid-fragment-params";

/** Fetches a fragment parameter with pattern validation (mismatch = null). */
function fragmentParam(params: URLSearchParams, name: string, pattern: RegExp): string | null {
  const value = params.get(name);
  return value !== null && pattern.test(value) ? value : null;
}

/** Interprets `s=` (the verified head seq) (decimal positive integers only). */
function parseHeadSeq(params: URLSearchParams): number | null {
  const text = fragmentParam(params, "s", /^[1-9][0-9]*$/);
  if (text === null) {
    return null;
  }
  const value = Number.parseInt(text, 10);
  return Number.isSafeInteger(value) ? value : null;
}

/** Interprets `il=` (the inviter's GitHub login): omitted = null; when present, only the login shape. */
function parseInviterLogin(params: URLSearchParams): string | null | "invalid" {
  const text = params.get("il");
  if (text === null) {
    return null;
  }
  return GITHUB_LOGIN.test(text) ? text : "invalid";
}

/** The required string parameters (name → format). */
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

/** Bulk-fetch of the required string parameters (null on any missing/malformed). */
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
 * Interprets `sk=` / `se=` (the scope to be granted): kind is a
 * closed set; with `all`, `se` is empty; `listed` is a
 * comma-separated environment_id list (§12-1 format, no duplicates,
 * at most 256. Empty = a listed that grants no environment). The
 * structural rules are the same as CRYPTO_SPEC §6.2's scope
 * (malformed = null)
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

/** Interprets `p=` (the project ID). */
function parseProjectId(params: URLSearchParams): string | null {
  const value = params.get("p");
  return value !== null && isProjectId(value) ? value : null;
}

/** Interprets the link data from the fragment (v=2 verified) (malformed = null). */
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
 * Interprets the `<link>` input. Missing required parameters,
 * malformed formats, the old version (`v=1`), and raw tokens are all
 * errors (a broken link must not slide into an anchorless accept.
 * The old version and raw tokens have no compatibility path — guide
 * to re-issuing).
 */
export function parseInviteAcceptInput(raw: Redacted.Redacted<string>):
  | { readonly kind: "link"; readonly link: InviteLinkData }
  | {
      readonly kind: "rejected";
      readonly reason: InviteInputRejection;
    } {
  // Why it is unwrapped: parsing the link's syntax needs the byte
  // string itself. The input arrives still Redacted from the argument
  // layer (`Argument.Redacted` — ADR-0016), and the raw value never
  // leaves this function — the seed is wrapped in Redacted again on
  // return; the other parameters are public values
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
