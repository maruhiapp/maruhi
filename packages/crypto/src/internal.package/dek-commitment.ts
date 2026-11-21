import { encodeHex } from "./bytes.ts";
import type { EnvironmentId, ProjectId } from "./chain-types.ts";
import { encodeLengthPrefixed } from "./encoding.ts";
import type { CryptoError, CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";

const DEK_BYTES = 32;
const COMMITMENT_HEX_LENGTH = 32 * 2;

export interface DekCommitmentContext {
  readonly suite: string;
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly epoch: number;
}

function invalidInput(field: string): { readonly ok: false; readonly error: CryptoError } {
  return { ok: false, error: { kind: "InvalidInput", field } };
}

function contextInvalidField(context: DekCommitmentContext): string | null {
  if (context.suite.length === 0) {
    return "context suite";
  }
  if (!Number.isSafeInteger(context.epoch) || context.epoch < 1) {
    return "context epoch";
  }
  return null;
}

export function buildDekCommitmentBytes(
  context: DekCommitmentContext,
  dek: Uint8Array,
): Uint8Array {
  return encodeLengthPrefixed([
    `${context.suite}/dek-commit`,
    context.projectId,
    context.environmentId,
    context.epoch,
    encodeHex(dek),
  ]);
}

export async function computeDekCommitment(input: {
  readonly context: DekCommitmentContext;
  readonly dek: Uint8Array;
}): Promise<CryptoResult<string>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  if (input.dek.length !== DEK_BYTES) {
    return invalidInput("dek");
  }
  return {
    ok: true,
    value: encodeHex(await sha256(buildDekCommitmentBytes(input.context, input.dek))),
  };
}

export async function verifyDekCommitment(input: {
  readonly context: DekCommitmentContext;
  readonly dek: Uint8Array;
  readonly expectedCommitmentHex: string;
}): Promise<CryptoResult<void>> {
  if (
    input.expectedCommitmentHex.length !== COMMITMENT_HEX_LENGTH ||
    !/^[0-9a-f]+$/.test(input.expectedCommitmentHex)
  ) {
    return invalidInput("expectedCommitmentHex");
  }
  const computed = await computeDekCommitment({ context: input.context, dek: input.dek });
  if (!computed.ok) {
    return computed;
  }
  return computed.value === input.expectedCommitmentHex
    ? { ok: true, value: undefined }
    : { ok: false, error: { kind: "DekCommitmentMismatch" } };
}
