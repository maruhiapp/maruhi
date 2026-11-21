import { encodeHex } from "./bytes.ts";
import type { EnvironmentId, ProjectId } from "./chain-types.ts";
import type { WrappedDek } from "./dek-wrap.ts";
import { encodeLengthPrefixed } from "./encoding.ts";
import type { CryptoError, CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import { hpkeSuite } from "./hpke.ts";
import type { EncryptionKey, EncryptionKeyPair } from "./keys.ts";
import { SUITE_ID } from "./suite.ts";

const LEASE_WRAP_DOMAIN = `${SUITE_ID}/lease-wrap`;
const LEASE_CLAIMS_DOMAIN = `${SUITE_ID}/lease-claims`;
const DEK_BYTES = 32;
const CLAIMS_DIGEST_HEX_LENGTH = 32 * 2;

export interface LeaseClaims {
  readonly issuerUrl: string;
  readonly subject: string;
  readonly audience: string;
}

export interface LeaseWrapContext {
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly epoch: number;
  readonly claimsDigestHex: string;
}

function invalidInput(field: string): { readonly ok: false; readonly error: CryptoError } {
  return { ok: false, error: { kind: "InvalidInput", field } };
}

export function buildLeaseClaimsBytes(claims: LeaseClaims): Uint8Array {
  return encodeLengthPrefixed([
    LEASE_CLAIMS_DOMAIN,
    claims.issuerUrl,
    claims.subject,
    claims.audience,
  ]);
}

export async function computeLeaseClaimsDigest(claims: LeaseClaims): Promise<CryptoResult<string>> {
  if (claims.issuerUrl.length === 0) {
    return invalidInput("claims issuerUrl");
  }
  if (claims.subject.length === 0) {
    return invalidInput("claims subject");
  }
  if (claims.audience.length === 0) {
    return invalidInput("claims audience");
  }
  return { ok: true, value: encodeHex(await sha256(buildLeaseClaimsBytes(claims))) };
}

function contextInvalidField(context: LeaseWrapContext): string | null {
  if (!Number.isSafeInteger(context.epoch) || context.epoch < 0) {
    return "context epoch";
  }
  if (!new RegExp(`^[0-9a-f]{${CLAIMS_DIGEST_HEX_LENGTH}}$`).test(context.claimsDigestHex)) {
    return "context claimsDigestHex";
  }
  return null;
}

export function buildLeaseWrapInfo(context: LeaseWrapContext): Uint8Array {
  return encodeLengthPrefixed([
    LEASE_WRAP_DOMAIN,
    context.projectId,
    context.environmentId,
    context.epoch,
    context.claimsDigestHex,
  ]);
}

export async function wrapLeaseDek(input: {
  readonly workloadPublicKey: EncryptionKey;
  readonly dek: Uint8Array;
  readonly context: LeaseWrapContext;
}): Promise<CryptoResult<WrappedDek>> {
  if (input.dek.length !== DEK_BYTES) {
    return invalidInput("dek length");
  }
  const invalidField = contextInvalidField(input.context);
  if (invalidField !== null) {
    return invalidInput(invalidField);
  }
  try {
    const { encapsulatedSecret, ciphertext } = await hpkeSuite().Seal(
      input.workloadPublicKey,
      input.dek,
      { info: buildLeaseWrapInfo(input.context) },
    );
    return { ok: true, value: { enc: encapsulatedSecret, ciphertext } };
  } catch {
    return { ok: false, error: { kind: "DekWrapFailed" } };
  }
}

export async function unwrapLeaseDek(input: {
  readonly workloadKeyPair: EncryptionKeyPair;
  readonly wrapped: WrappedDek;
  readonly context: LeaseWrapContext;
}): Promise<CryptoResult<Uint8Array>> {
  const invalidField = contextInvalidField(input.context);
  if (invalidField !== null) {
    return invalidInput(invalidField);
  }
  try {
    const dek = await hpkeSuite().Open(
      input.workloadKeyPair,
      input.wrapped.enc,
      input.wrapped.ciphertext,
      { info: buildLeaseWrapInfo(input.context) },
    );
    return { ok: true, value: dek };
  } catch {
    return { ok: false, error: { kind: "DekUnwrapFailed" } };
  }
}
