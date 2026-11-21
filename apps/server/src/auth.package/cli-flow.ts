import { decodeHex, encodeHex, encodeLengthPrefixed } from "@maruhi/crypto";
import { Effect } from "effect";
import { SecureRandom } from "effect/crypto";

import { constantTimeEqual, randomHex } from "../ids.ts";

export const CLI_FLOW_TTL_MS = 15 * 60 * 1000;

const FLOW_TOKEN_DOMAIN = "maruhi/v1/cli-flow-token";
const VSIG_DOMAIN = "maruhi/v1/cli-verify-url";

const FLOW_TOKEN_VERSION = "v1";
const SIGNING_KEY_BYTES = 32;
const FLOW_TOKEN_RANDOM_BYTES = 32;

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

const USER_CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export const generateUserCode = (): Effect.Effect<string, never, SecureRandom.SecureRandom> =>
  Effect.flatMap(SecureRandom.SecureRandom, (random) =>
    Effect.map(random.randomBytes(8), (bytes) => {
      let code = "";
      for (const [index, byte] of bytes.entries()) {
        if (index === 4) {
          code += "-";
        }
        code += USER_CODE_ALPHABET[byte % 32];
      }
      return code;
    }),
  );

export const createFlowToken = (
  key: CryptoKey,
  flowId: string,
  expiresAtMs: number,
): Effect.Effect<string, never, SecureRandom.SecureRandom> =>
  Effect.flatMap(randomHex(FLOW_TOKEN_RANDOM_BYTES), (random) =>
    Effect.map(
      Effect.promise(() => macHex(key, FLOW_TOKEN_DOMAIN, [flowId, random, expiresAtMs])),
      (mac) => `${FLOW_TOKEN_VERSION}.${expiresAtMs}.${random}.${mac}`,
    ),
  );

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

interface RawCliVerifyQuery {
  readonly flow?: string | undefined;
  readonly exp?: string | undefined;
  readonly code?: string | undefined;
  readonly name?: string | undefined;
  readonly scopes?: string | undefined;
  readonly days?: string | undefined;
  readonly vsig?: string | undefined;
}

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
