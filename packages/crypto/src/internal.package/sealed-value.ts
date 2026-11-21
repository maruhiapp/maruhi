import type { EnvironmentId, ProjectId, UserId, VariableId } from "./chain-types.ts";
import { encodeLengthPrefixed } from "./encoding.ts";
import type { CryptoError, CryptoResult } from "./errors.ts";
import { hpkeSuite } from "./hpke.ts";
import type { EncryptionKey, EncryptionKeyPair } from "./keys.ts";
import { SUITE_ID } from "./suite.ts";

const SEALED_VALUE_DOMAIN = `${SUITE_ID}/sealed-value`;

export const PROPOSAL_ID_BYTES = 16;
const PROPOSAL_ID_PATTERN = new RegExp(`^[0-9a-f]{${PROPOSAL_ID_BYTES * 2}}$`);

export const MAX_SEALED_VALUE_BYTES = 64 * 1024 - 16;

export interface SealedValueContext {
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly proposalId: string;
  readonly variableId: VariableId;
  readonly baseVersion: number;
  readonly recipientUserId: UserId;
}

export interface SealedValue {
  readonly enc: Uint8Array;
  readonly ciphertext: Uint8Array;
}

function invalidInput(field: string): { readonly ok: false; readonly error: CryptoError } {
  return { ok: false, error: { kind: "InvalidInput", field } };
}

export function isProposalId(value: string): boolean {
  return PROPOSAL_ID_PATTERN.test(value);
}

function contextInvalidField(context: SealedValueContext): string | null {
  if (!isProposalId(context.proposalId)) {
    return "context proposalId";
  }
  if (!Number.isSafeInteger(context.baseVersion) || context.baseVersion < 1) {
    return "context baseVersion";
  }
  for (const [field, value] of [
    ["context projectId", context.projectId],
    ["context environmentId", context.environmentId],
    ["context variableId", context.variableId],
    ["context recipientUserId", context.recipientUserId],
  ] as const) {
    if (value.length === 0) {
      return field;
    }
  }
  return null;
}

export function buildSealedValueInfo(context: SealedValueContext): Uint8Array {
  return encodeLengthPrefixed([
    SEALED_VALUE_DOMAIN,
    context.projectId,
    context.environmentId,
    context.proposalId,
    context.variableId,
    context.baseVersion,
    context.recipientUserId,
  ]);
}

export async function sealProposedValue(input: {
  readonly recipientPublicKey: EncryptionKey;
  readonly value: Uint8Array;
  readonly context: SealedValueContext;
}): Promise<CryptoResult<SealedValue>> {
  if (input.value.length === 0 || input.value.length > MAX_SEALED_VALUE_BYTES) {
    return invalidInput("value length");
  }
  const invalidField = contextInvalidField(input.context);
  if (invalidField !== null) {
    return invalidInput(invalidField);
  }
  try {
    const { encapsulatedSecret, ciphertext } = await hpkeSuite().Seal(
      input.recipientPublicKey,
      input.value,
      { info: buildSealedValueInfo(input.context) },
    );
    return { ok: true, value: { enc: encapsulatedSecret, ciphertext } };
  } catch {
    return { ok: false, error: { kind: "DekWrapFailed" } };
  }
}

export async function openProposedValue(input: {
  readonly recipientKeyPair: EncryptionKeyPair;
  readonly sealed: SealedValue;
  readonly context: SealedValueContext;
}): Promise<CryptoResult<Uint8Array>> {
  const invalidField = contextInvalidField(input.context);
  if (invalidField !== null) {
    return invalidInput(invalidField);
  }
  try {
    const value = await hpkeSuite().Open(
      input.recipientKeyPair,
      input.sealed.enc,
      input.sealed.ciphertext,
      { info: buildSealedValueInfo(input.context) },
    );
    return { ok: true, value };
  } catch {
    return { ok: false, error: { kind: "DekUnwrapFailed" } };
  }
}
