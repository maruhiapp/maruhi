// Flow credentials for CLI login (AUTH_SPEC §4-1 (1) / §4-2).
//
// start is unrecorded (ruling DH), and flow authenticity is verified
// statelessly by two HMAC-SHA-256 lines:
//
// - flowToken: a CLI-only bearer credential. A self-contained signature
//   format `v1.<expMs>.<randHex>.<macHex>` that **includes flowId in the
//   signed content** (the §4-1 (1) requirement — closes the path of polling
//   someone else's flow by recombining "the victim's flowId + one's own
//   flowToken"). Never placed on the browser channel
// - vsig: a browser-leg MAC covering the whole verificationUrl query
//   (flowId, expiry, userCode, issued parameters). Knowledge of the URL
//   grants no polling capability at all
//
// The two lines are **domain-separated by purpose tags**, and signature
// inputs are LP (length-prefixed) encoded to be uniquely decodable (§4-2 —
// field-boundary ambiguity must not collapse different input sequences into
// the same byte string). The LP encoder uses the existing implementation in
// packages/crypto (not primitive invention). This key is not E2EE key
// material (outside CRYPTO_SPEC's scope — stated in §4-2; integrity of
// short-lived login-flow credentials only).

import { decodeHex, encodeHex, encodeLengthPrefixed } from "@maruhi/crypto";

import { constantTimeEqual } from "../ids.ts";

/** Flow lifetime (AUTH_SPEC §4-1 (1) drafted value: 15 minutes). */
export const CLI_FLOW_TTL_MS = 15 * 60 * 1000;

// Purpose tags for domain separation (§4-2 — one must not pass verification as the other)
const FLOW_TOKEN_DOMAIN = "maruhi/v1/cli-flow-token";
const VSIG_DOMAIN = "maruhi/v1/cli-verify-url";

const FLOW_TOKEN_VERSION = "v1";
const SIGNING_KEY_BYTES = 32;
const FLOW_TOKEN_RANDOM_BYTES = 32;

/**
 * Imports D1-stored key material (hex) as a WebCrypto HMAC key. Malformed
 * input is a defect (the key is only ever written via our own generation
 * path — FlowSigningKeyRepo).
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
// userCode (§4-1 (2) — a short display code for human comparison. Not a secret)
// ---------------------------------------------------------------------------

// 32 characters chosen for low visual ambiguity (the Crockford Base32
// alphabet). Since 256 % 32 = 0, taking the mod of byte values is unbiased
const USER_CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** Comparison code (`XXXX-XXXX`). A friction device shown on both the CLI and the approval page. */
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
// flowToken (§4-1 (1) — CLI-only bearer. Never on the browser channel)
// ---------------------------------------------------------------------------

/** Issues a self-contained flowToken (a MAC covering 256-bit randomness + flowId + expiry). */
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
 * Stateless verification for poll (§4-1 (5)): MAC, **pairwise match of the
 * flowId inside the signature and the presented flowId**, and expiry. The
 * MAC is checked first (the expiry is a signed self-declared value; the
 * expiry of a token whose MAC fails means nothing). invalid = uniform
 * rejection (CliFlowRejected); expired = a typed termination instruction to
 * a legitimate holder (CliFlowExpired — §4-2).
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
// vsig (§4-1 (1) — the browser-leg MAC for verificationUrl)
// ---------------------------------------------------------------------------

/**
 * The set of vsig'd parameters carried by verificationUrl (§4-1 (1)).
 * scopes is signed and verified as the JSON string placed on the URL
 * verbatim (no reinterpretation of the canonical form).
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

/** Builds the verify URL query from the vsig'd parameters (shared by start and the guidance link). */
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

/** The raw query the browser leg receives (verify's query / callback's cookie restore). */
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
 * Stateless verification of a verify arrival (§4-1 (3)): missing, tampered,
 * or expired all yield null = a uniform error page (§4-2 — no
 * differentiation; fail-closed before any redirect to GitHub happens).
 * Returns the settled parameters only when verification passes.
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
