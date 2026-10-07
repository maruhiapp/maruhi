// Shared helpers for workload-lease integration tests.
//
// Assumes the fixture of data-scenario.ts (registerDataScenario): each test
// file calls registerDataScenario() before writing its describes, and the
// helpers here reference data-scenario's live binding (fixture).

import type { LeasedDek } from "@maruhi/api-schema";
import {
  computeLeaseClaimsDigest,
  encodeHex,
  exportEncryptionPublicKey,
  generateEncryptionKeyPair,
  type KeyFingerprintHex,
  unwrapLeaseDek,
} from "@maruhi/crypto";
import { SELF } from "cloudflare:test";
import { expect } from "vitest";

import { JSON_HEADERS } from "./auth.ts";
import { hexBytes, wrapDekToServer } from "./data-crypto.ts";
import {
  appendOperation,
  createEnvironmentOk,
  OWNER,
  projectId,
  requestJson,
} from "./data-fixture.ts";
import { createVariableOk, ENV, fixture, token, VAR } from "./data-scenario.ts";
import { deploymentKey, LEASE_AUDIENCE, LEASE_SUBJECT } from "./lease.ts";
import { OIDC_ISSUER } from "./oidc-issuer.ts";

/** The workload's ephemeral key (assumed generated in memory per job —
 * §9.1). */
export async function workloadKeyPair() {
  const pair = await generateEncryptionKeyPair();
  const publicKey = await exportEncryptionPublicKey(pair.publicKey);
  return { pair, publicKeyHex: encodeHex(publicKey) };
}

/** The default lease policy (issuer / audience match + one exact-match
 * constraint on sub). */
export function defaultPolicy(subject = LEASE_SUBJECT) {
  return [
    {
      issuerUrl: OIDC_ISSUER,
      audience: LEASE_AUDIENCE,
      claimConstraints: [{ claimName: "sub", claimValue: subject }],
    },
  ];
}

export type LeasePolicy = ReturnType<typeof defaultPolicy>;

/** The owner appends a grant_server (addressed to a really-derived
 * deployment key). */
export async function grantServer(input: {
  readonly scope: readonly string[];
  readonly leasePolicy?: LeasePolicy;
}): Promise<KeyFingerprintHex> {
  const key = await deploymentKey();
  await appendOperation(fixture, OWNER, {
    op: "grant_server",
    payload: {
      serverEncPubHex: key.encPubHex,
      serverKeyFingerprintHex: key.fingerprintHex,
      scopeEnvironmentIds: input.scope,
      leasePolicy: input.leasePolicy ?? defaultPolicy(),
    },
  });
  return key.fingerprintHex;
}

/** The owner backfills the server-addressed wrap (the §12-6
 * right-after-grant path). */
export async function backfillServerWrap(
  epoch: number,
  dek: Uint8Array,
  environmentId: string = ENV,
): Promise<void> {
  const key = await deploymentKey();
  const wrap = await wrapDekToServer({
    projectId,
    environmentId,
    epoch,
    dek,
    serverKeyFingerprintHex: key.fingerprintHex,
    serverEncPubHex: key.encPubHex,
    signerUserId: OWNER,
  });
  const response = await requestJson("POST", `/environments/${environmentId}/deks`, token(OWNER), {
    deks: [wrap],
  });
  expect(response.status).toBe(204);
}

export interface LeaseBody {
  readonly projectId: string;
  readonly environmentId: string;
  readonly currentEpoch: number;
  readonly chain: readonly unknown[];
  readonly headSeq: number;
  readonly headHashHex: string;
  /** The bundled environment manifest (§14-2 — required since 0.28-draft). */
  readonly manifest: {
    readonly manifestVersion: number;
    readonly epoch: number;
    readonly issuerUserId: string;
  };
  readonly variables: readonly {
    readonly variableId: string;
    readonly value: {
      readonly nonceHex: string;
      readonly ciphertextHex: string;
      readonly aad: unknown;
    };
  }[];
  readonly leases: readonly LeasedDek[];
}

export async function requestLease(input: {
  readonly oidcToken: string;
  readonly ephemeralPubHex: string;
  readonly environmentId?: string;
  readonly project?: string;
}): Promise<Response> {
  const target = input.project ?? projectId;
  return SELF.fetch(
    `https://maruhi.test/projects/${target}/environments/${input.environmentId ?? ENV}/lease`,
    {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({
        oidcToken: input.oidcToken,
        ephemeralPubHex: input.ephemeralPubHex,
      }),
    },
  );
}

/** Builds a "leaseable state" set up through grant + backfill + one
 * variable. */
export async function readyProject(): Promise<{ readonly dek: Uint8Array }> {
  const dek = await createEnvironmentOk(fixture, ENV, "App");
  await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
  await grantServer({ scope: [ENV] });
  await backfillServerWrap(1, dek);
  return { dek };
}

/** Extracts a required element of the response (keeps later assertions off
 * optional chaining). */
export function requireFirst<T>(items: readonly T[], what: string): T {
  const first = items[0];
  if (first === undefined) {
    throw new Error(`lease response has no ${what}`);
  }
  return first;
}

/** A binary string via the same lenient decode as the server's
 * decodeBase64Url (through atob). */
function decodeBase64UrlToBinary(segment: string): string {
  const padded = segment
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(segment.length + ((4 - (segment.length % 4)) % 4), "=");
  return atob(padded);
}

/**
 * Replaces the final character of the signature segment with "a different
 * character that decodes to the same bytes under the server's lenient
 * decode" (malleability of the unused bits in the last base64url group). The
 * mutated token changes neither the signed content (header.payload) nor the
 * signature bytes, so it passes signature verification but is a different
 * raw string — a reproduction of an attacker manipulation showing that a
 * first-come binding would break if it hashed the raw token.
 */
export function malleateSignatureSegment(compactJws: string): string {
  const parts = compactJws.split(".");
  const [header, payload, sig] = parts;
  if (parts.length !== 3 || header === undefined || payload === undefined || sig === undefined) {
    throw new Error("not a compact JWS");
  }
  const target = decodeBase64UrlToBinary(sig);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const lastIndex = sig.length - 1;
  for (const candidate of alphabet) {
    if (candidate === sig[lastIndex]) {
      continue;
    }
    const mutated = sig.slice(0, lastIndex) + candidate;
    if (decodeBase64UrlToBinary(mutated) === target) {
      return `${header}.${payload}.${mutated}`;
    }
  }
  throw new Error("no byte-identical alternative for the final signature character");
}

/** Computes the workload-side claims_digest (a recomputation independent of
 * the server — §9.1). */
export async function claimsDigestOf(subject = LEASE_SUBJECT): Promise<string> {
  const digest = await computeLeaseClaimsDigest({
    issuerUrl: OIDC_ISSUER,
    subject,
    audience: LEASE_AUDIENCE,
  });
  if (!digest.ok) {
    throw new Error("claims digest computation failed");
  }
  return digest.value;
}

/** Opens a lease wrap with the ephemeral key (the receiving-side procedure
 * of §9.1). */
export async function openLease(input: {
  readonly lease: LeasedDek;
  readonly workloadKeyPair: Awaited<ReturnType<typeof workloadKeyPair>>["pair"];
  readonly claimsDigestHex: string;
}) {
  return unwrapLeaseDek({
    workloadKeyPair: input.workloadKeyPair,
    wrapped: {
      enc: hexBytes(input.lease.encHex),
      ciphertext: hexBytes(input.lease.ciphertextHex),
    },
    context: {
      projectId,
      environmentId: ENV,
      epoch: input.lease.epoch,
      claimsDigestHex: input.claimsDigestHex,
    },
  });
}
