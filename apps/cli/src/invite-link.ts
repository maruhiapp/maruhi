import {
  decodeEnvironmentId,
  decodeUserId,
  isEnvironmentId,
  decodeProjectId,
  isProjectId,
  type EnvironmentId,
  type ProjectId,
  type UserId,
} from "@maruhi/core";
import type { ScopeKind } from "@maruhi/crypto";
import { Redacted } from "effect";

const HEX_64 = /^[0-9a-f]{64}$/;
const HEX_128 = /^[0-9a-f]{128}$/;
const ROLES = ["reader", "member", "admin"] as const;
const SCOPE_KINDS: readonly ScopeKind[] = ["all", "listed"];
const MAX_SCOPE_ENVIRONMENTS = 256;
const INVITE_ID = /^[0-9A-HJKMNP-TV-Z]{26}$/;
export const GITHUB_LOGIN = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;

export type InviteRole = (typeof ROLES)[number];

export interface InviteLinkData {
  readonly inviteId: string;
  readonly linkSeedHex: Redacted.Redacted<string>;
  readonly projectId: ProjectId;
  readonly headHashHex: string;
  readonly headSeq: number;
  readonly inviterUserId: UserId;
  readonly inviterEncPubHex: string;
  readonly inviterSigPubHex: string;
  readonly role: InviteRole;
  readonly scopeKind: ScopeKind;
  readonly scopeEnvironmentIds: readonly EnvironmentId[];
  readonly inviterLogin: string | null;
  readonly issueSignatureHex: string;
}

export function buildInviteLink(input: {
  readonly origin: string;
  readonly link: InviteLinkData;
}): Redacted.Redacted<string> {
  const { link } = input;
  const params: (readonly [string, string])[] = [
    ["v", "2"],
    ["i", link.inviteId],
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

export type InviteInputRejection =
  | "not-a-link"
  | "unsupported-version"
  | "missing-or-invalid-fragment-params";

function fragmentParam(params: URLSearchParams, name: string, pattern: RegExp): string | null {
  const value = params.get(name);
  return value !== null && pattern.test(value) ? value : null;
}

function parseHeadSeq(params: URLSearchParams): number | null {
  const text = fragmentParam(params, "s", /^[1-9][0-9]*$/);
  if (text === null) {
    return null;
  }
  const value = Number.parseInt(text, 10);
  return Number.isSafeInteger(value) ? value : null;
}

function parseInviterLogin(params: URLSearchParams): string | null | "invalid" {
  const text = params.get("il");
  if (text === null) {
    return null;
  }
  return GITHUB_LOGIN.test(text) ? text : "invalid";
}

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

function parseScope(params: URLSearchParams): {
  readonly scopeKind: ScopeKind;
  readonly scopeEnvironmentIds: readonly EnvironmentId[];
} | null {
  const kind = SCOPE_KINDS.find((known) => known === params.get("sk"));
  const text = params.get("se");
  if (kind === undefined || text === null) {
    return null;
  }
  if (kind === "all") {
    return text === "" ? { scopeKind: "all", scopeEnvironmentIds: [] } : null;
  }
  const ids = text === "" ? [] : text.split(",");
  if (ids.length > MAX_SCOPE_ENVIRONMENTS || new Set(ids).size !== ids.length) {
    return null;
  }
  if (!ids.every(isEnvironmentId)) {
    return null;
  }
  return { scopeKind: "listed", scopeEnvironmentIds: ids.map(decodeEnvironmentId) };
}

function parseProjectId(params: URLSearchParams): ProjectId | null {
  const value = params.get("p");
  return value !== null && isProjectId(value) ? decodeProjectId(value) : null;
}

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
    inviterLogin === "invalid" ||
    strings.iu.trim() === ""
  ) {
    return null;
  }
  return {
    inviteId: strings.i,
    linkSeedHex: Redacted.make(strings.k, { label: "invite-link-seed" }),
    projectId,
    headHashHex: strings.h,
    headSeq,
    inviterUserId: decodeUserId(strings.iu),
    inviterEncPubHex: strings.ie,
    inviterSigPubHex: strings.is,
    role,
    scopeKind: scope.scopeKind,
    scopeEnvironmentIds: scope.scopeEnvironmentIds,
    inviterLogin,
    issueSignatureHex: strings.sig,
  };
}

export function parseInviteAcceptInput(raw: Redacted.Redacted<string>):
  | { readonly kind: "link"; readonly link: InviteLinkData }
  | {
      readonly kind: "rejected";
      readonly reason: InviteInputRejection;
    } {
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
