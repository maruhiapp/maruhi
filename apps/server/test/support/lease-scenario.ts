import type { LeasedDek } from "@maruhi/api-schema";
import {
  computeLeaseClaimsDigest,
  encodeHex,
  exportEncryptionPublicKey,
  generateEncryptionKeyPair,
  type KeyFingerprintHex,
  unwrapLeaseDek,
} from "@maruhi/crypto";
import { hexBytes, testEnvironmentId, testProjectId, wrapDekTo } from "@maruhi/test-kit";
import { SELF } from "cloudflare:test";
import { expect } from "vite-plus/test";

import { JSON_HEADERS } from "./auth.ts";
import { identityOf } from "./data-crypto.ts";
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

export async function workloadKeyPair() {
  const pair = await generateEncryptionKeyPair();
  const publicKey = await exportEncryptionPublicKey(pair.publicKey);
  return { pair, publicKeyHex: encodeHex(publicKey) };
}

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
      scopeEnvironmentIds: input.scope.map(testEnvironmentId),
      leasePolicy: input.leasePolicy ?? defaultPolicy(),
    },
  });
  return key.fingerprintHex;
}

export async function backfillServerWrap(
  epoch: number,
  dek: Uint8Array,
  environmentId: string = ENV,
): Promise<void> {
  const key = await deploymentKey();
  const wrap = await wrapDekTo({
    projectId,
    environmentId,
    epoch,
    dek,
    recipient: { userId: key.fingerprintHex, encPubHex: key.encPubHex },
    recipientClass: "server",
    signer: identityOf(OWNER),
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

export async function readyProject(): Promise<{ readonly dek: Uint8Array }> {
  const dek = await createEnvironmentOk(fixture, ENV, "App");
  await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
  await grantServer({ scope: [ENV] });
  await backfillServerWrap(1, dek);
  return { dek };
}

export function requireFirst<T>(items: readonly T[], what: string): T {
  const first = items[0];
  if (first === undefined) {
    throw new Error(`lease response has no ${what}`);
  }
  return first;
}

function decodeBase64UrlToBinary(segment: string): string {
  const padded = segment
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(segment.length + ((4 - (segment.length % 4)) % 4), "=");
  return atob(padded);
}

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
      projectId: testProjectId(projectId),
      environmentId: testEnvironmentId(ENV),
      epoch: input.lease.epoch,
      claimsDigestHex: input.claimsDigestHex,
    },
  });
}
