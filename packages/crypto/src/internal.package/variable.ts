import type { EnvironmentId, ProjectId, VariableId } from "./chain-types.ts";
import { encodeLengthPrefixed } from "./encoding.ts";
import type { CryptoError, CryptoResult } from "./errors.ts";
import { SUITE_ID } from "./suite.ts";

export interface VariableContext {
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly epoch: number;
  readonly variableId: VariableId;
  readonly version: number;
}

export interface EncryptedVariable {
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
}

const DEK_BYTES = 32;
const NONCE_BYTES = 12;

function invalidInput(field: string): { readonly ok: false; readonly error: CryptoError } {
  return { ok: false, error: { kind: "InvalidInput", field } };
}

function checkContextNumbers(context: VariableContext): string | null {
  if (!Number.isSafeInteger(context.epoch) || context.epoch < 0) {
    return "context epoch";
  }
  if (!Number.isSafeInteger(context.version) || context.version < 0) {
    return "context version";
  }
  return null;
}

export function buildVariableAad(context: VariableContext): Uint8Array {
  return encodeLengthPrefixed([
    SUITE_ID,
    context.projectId,
    context.environmentId,
    context.epoch,
    context.variableId,
    context.version,
  ]);
}

async function importDek(dek: Uint8Array, usage: "encrypt" | "decrypt"): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", dek as BufferSource, "AES-GCM", false, [usage]);
}

export async function encryptVariable(input: {
  readonly dek: Uint8Array;
  readonly context: VariableContext;
  readonly plaintext: Uint8Array;
}): Promise<CryptoResult<EncryptedVariable>> {
  if (input.dek.length !== DEK_BYTES) {
    return invalidInput("dek length");
  }
  const badField = checkContextNumbers(input.context);
  if (badField !== null) {
    return invalidInput(badField);
  }
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  try {
    const key = await importDek(input.dek, "encrypt");
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: nonce as BufferSource,
          additionalData: buildVariableAad(input.context) as BufferSource,
        },
        key,
        input.plaintext as BufferSource,
      ),
    );
    return { ok: true, value: { nonce, ciphertext } };
  } catch {
    return { ok: false, error: { kind: "EncryptFailed", operation: "variable" } };
  }
}

export async function decryptVariable(input: {
  readonly dek: Uint8Array;
  readonly context: VariableContext;
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
}): Promise<CryptoResult<Uint8Array>> {
  if (input.dek.length !== DEK_BYTES) {
    return invalidInput("dek length");
  }
  if (input.nonce.length !== NONCE_BYTES) {
    return invalidInput("nonce length");
  }
  const badField = checkContextNumbers(input.context);
  if (badField !== null) {
    return invalidInput(badField);
  }
  try {
    const key = await importDek(input.dek, "decrypt");
    const plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: input.nonce as BufferSource,
          additionalData: buildVariableAad(input.context) as BufferSource,
        },
        key,
        input.ciphertext as BufferSource,
      ),
    );
    return { ok: true, value: plaintext };
  } catch {
    return { ok: false, error: { kind: "DecryptFailed", operation: "variable" } };
  }
}
