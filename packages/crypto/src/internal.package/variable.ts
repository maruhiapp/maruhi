// CRYPTO_SPEC §4: 変数値の AES-256-GCM 暗号化。
// AAD = LP(suite, project_id, environment_id, epoch, variable_id, version)。
// nonce は 96-bit ランダム生成で暗号文と併置。再利用は絶対に許されない
// (テストベクター: test-vectors/variable-encryption.json)。

import { encodeLengthPrefixed } from "./encoding.ts";
import type { CryptoError, CryptoResult } from "./errors.ts";
import { SUITE_ID } from "./suite.ts";

/** Context that cryptographically binds a variable ciphertext (CRYPTO_SPEC §4). */
export interface VariableContext {
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly variableId: string;
  readonly version: number;
}

/** An encrypted variable value: 96-bit nonce + AES-256-GCM ciphertext (ct || tag). */
export interface EncryptedVariable {
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
}

const DEK_BYTES = 32;
const NONCE_BYTES = 12;

function invalidInput(field: string): { readonly ok: false; readonly error: CryptoError } {
  return { ok: false, error: { kind: "InvalidInput", field } };
}

/**
 * Builds the AAD for a variable value:
 * `LP(suite, project_id, environment_id, epoch, variable_id, version)`.
 * Reuse of a ciphertext outside this context fails decryption (§4).
 */
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

/**
 * Encrypts a variable value with the epoch DEK. The nonce is freshly random
 * per call (never caller-supplied: nonce reuse must stay impossible by
 * construction).
 */
export async function encryptVariable(input: {
  readonly dek: Uint8Array;
  readonly context: VariableContext;
  readonly plaintext: Uint8Array;
}): Promise<CryptoResult<EncryptedVariable>> {
  if (input.dek.length !== DEK_BYTES) {
    return invalidInput("dek length");
  }
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
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
}

/**
 * Decrypts a variable value. Any mismatch in context (transplanted
 * environment/epoch/variable/version), nonce or ciphertext yields
 * `DecryptFailed` — no further detail, by design.
 */
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
