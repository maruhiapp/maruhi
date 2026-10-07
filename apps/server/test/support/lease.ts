// Test helpers for workload leases (AUTH_SPEC §14).
//
// - Building and ES256-signing OIDC tokens (the key is the dummy in
//   support/oidc-issuer.ts; outboundService serves the JWKS of the same key)
// - The deployment keypair (actually derived from the SERVER_ENC_KEY_IKM
//   binding — .dev.vars.example's dummy, injected by vitest.config.ts).
//   Because tests check as far as "the server can really open a wrap
//   addressed to itself", they use the real derived key, not a dummy public
//   key
//
// All key material is disposable test-only dummies and is never used in real
// environments.

import {
  computeServerKeyFingerprint,
  decodeHex,
  deriveEncryptionKeyPair,
  encodeHex,
  exportEncryptionPublicKey,
  type KeyFingerprintHex,
} from "@maruhi/crypto";
import { testKeyFingerprintHex } from "@maruhi/crypto/test-support";
import { env } from "cloudflare:test";

import { OIDC_ISSUER, OIDC_KID, OIDC_PRIVATE_JWK } from "./oidc-issuer.ts";

/** The default audience used in lease tests (simulates a deployment's
 * origin). */
export const LEASE_AUDIENCE = "https://maruhi.test";

/** The default subject (the GitHub Actions `sub` claim form). */
export const LEASE_SUBJECT = "repo:maruhi-test/demo:ref:refs/heads/main";

export interface DeploymentKey {
  readonly encPubHex: string;
  readonly fingerprintHex: KeyFingerprintHex;
}

let cachedKey: DeploymentKey | undefined;

/**
 * The public side of the deployment key actually derived from
 * SERVER_ENC_KEY_IKM. Identical to what the server derives in
 * `server-key.ts` (RFC 9180 DeriveKeyPair is deterministic).
 */
export async function deploymentKey(): Promise<DeploymentKey> {
  if (cachedKey !== undefined) {
    return cachedKey;
  }
  // The same binding the worker derives its keypair from
  const ikm = decodeHex(env.SERVER_ENC_KEY_IKM ?? "");
  if (ikm === null || ikm.length === 0) {
    throw new Error("SERVER_ENC_KEY_IKM binding is not set to hex");
  }
  const pair = await deriveEncryptionKeyPair({ ikm });
  if (!pair.ok) {
    throw new Error("deployment key derivation failed");
  }
  const publicKey = await exportEncryptionPublicKey(pair.value.publicKey);
  const fingerprint = await computeServerKeyFingerprint(publicKey);
  if (!fingerprint.ok) {
    throw new Error("deployment key fingerprint failed");
  }
  cachedKey = {
    encPubHex: encodeHex(publicKey),
    fingerprintHex: testKeyFingerprintHex(encodeHex(fingerprint.value)),
  };
  return cachedKey;
}

function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

const encodeSegment = (value: unknown): string =>
  base64Url(new TextEncoder().encode(JSON.stringify(value)));

export interface TokenOptions {
  readonly issuer?: string;
  readonly subject?: string;
  readonly audience?: string | readonly string[];
  /** Extra claims (to make claim constraints match or not). */
  readonly claims?: Readonly<Record<string, unknown>>;
  readonly expSeconds?: number;
  readonly iatSeconds?: number;
  readonly alg?: string;
  readonly kid?: string | null;
  /** If true, tampers with the signature by 1 byte (for the
   * signature-invalid check). */
  readonly tamperSignature?: boolean;
  /** Omits exp / iat (for the missing-claim check). */
  readonly omit?: readonly string[];
  /** Puts `crit` on the JOSE header (for the RFC 7515 §4.1.11 rejection
   * check). */
  readonly crit?: readonly string[];
}

/**
 * Builds and signs an ES256 OIDC token. `alg` / `kid` are replaceable so
 * that rejection of a non-allowlisted alg and an unknown kid can be checked
 * on the real path (swapping only the header keeps the same signing key =
 * produces a shape that would pass an implementation that "trusts the
 * header's alg").
 */
export async function makeOidcToken(options: TokenOptions = {}): Promise<string> {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const header = {
    alg: options.alg ?? "ES256",
    typ: "JWT",
    ...(options.kid === null ? {} : { kid: options.kid ?? OIDC_KID }),
    ...(options.crit === undefined ? {} : { crit: options.crit }),
  };
  const omit = new Set(options.omit ?? []);
  const claims: Record<string, unknown> = {
    iss: options.issuer ?? OIDC_ISSUER,
    sub: options.subject ?? LEASE_SUBJECT,
    aud: options.audience ?? LEASE_AUDIENCE,
    ...(omit.has("exp") ? {} : { exp: options.expSeconds ?? nowSeconds + 300 }),
    ...(omit.has("iat") ? {} : { iat: options.iatSeconds ?? nowSeconds - 5 }),
    ...options.claims,
  };
  const signingInput = `${encodeSegment(header)}.${encodeSegment(claims)}`;
  const key = await crypto.subtle.importKey(
    "jwk",
    OIDC_PRIVATE_JWK as unknown as JsonWebKey,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      new TextEncoder().encode(signingInput),
    ),
  );
  if (options.tamperSignature === true) {
    signature[0] = (signature[0] ?? 0) ^ 0x01;
  }
  return `${signingInput}.${base64Url(signature)}`;
}
