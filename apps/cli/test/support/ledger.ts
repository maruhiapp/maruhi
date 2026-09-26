// Mock of the recovery ledger (`GET /auth/recovery` — CRYPTO_SPEC §8). Wraps a
// key record with a known secret, serves it, and returns the recovery code.
// Shared by recovery.test.ts and device.test.ts (DK K14 — the reserve-key
// determination).

import { wrapMasterSecret } from "@maruhi/crypto";
import { Redacted } from "effect";

import { serializeStoredMasterKey, type StoredMasterKey } from "../../src/keychain.ts";
import { formatRecoveryCode } from "../../src/recovery-code.ts";
import type { TestUser } from "./crypto.ts";
import { type MockHandler, onRequest } from "./server.ts";

/** Shapes a test user's key pair into the keychain / ledger record form. */
export function storedMasterRecord(user: TestUser): StoredMasterKey {
  return {
    suite: "maruhi/v1",
    encPubHex: user.encPubHex,
    encSkHex: Redacted.make(user.encSkHex),
    sigPubHex: user.sigPubHex,
    sigSkSeedHex: Redacted.make(user.sigSkSeedHex),
  };
}

/** A record the CLI generated as a reserve key (carrying the reserve-key mark — CRYPTO_SPEC §8 / DK K16). */
export function storedReserveRecord(user: TestUser): StoredMasterKey {
  return { ...storedMasterRecord(user), kind: "reserve" };
}

/** Wraps `record` with a known secret; returns the handler serving it at GET /auth/recovery and the code. */
export async function ledgerHandlerFor(
  record: StoredMasterKey,
  userId: string,
  secret: Uint8Array,
): Promise<{ handler: MockHandler; code: string }> {
  const wrapped = await wrapMasterSecret({
    recoverySecret: secret,
    userId,
    // JSON.stringify(record) cannot be used — the secret side would be
    // wrapped redacted, producing a blob that "decrypts fine but the key is
    // unreadable" (the same trap as production recovery.ts)
    masterSecretBlob: new TextEncoder().encode(serializeStoredMasterKey(record)),
  });
  if (!wrapped.ok) {
    throw new Error("test wrap failed");
  }
  const handler = onRequest("GET", "/auth/recovery", () => ({
    status: 200,
    json: {
      suite: "maruhi/v1",
      nonceHex: Buffer.from(wrapped.value.nonce).toString("hex"),
      ciphertextHex: Buffer.from(wrapped.value.ciphertext).toString("hex"),
      updatedAtMs: 1754006400000,
    },
  }));
  return { handler, code: Redacted.value(formatRecoveryCode(Redacted.make(secret))) };
}
