import { wrapMasterSecret } from "@maruhi/crypto";
import { Redacted } from "effect";

import { serializeStoredMasterKey, type StoredMasterKey } from "../../src/keychain.ts";
import { formatRecoveryCode } from "../../src/recovery-code.ts";
import type { TestUser } from "./crypto.ts";
import { testUserId } from "./crypto.ts";
import { type MockHandler, onRequest } from "./server.ts";

export function storedMasterRecord(user: TestUser): StoredMasterKey {
  return {
    suite: "maruhi/v1",
    encPubHex: user.encPubHex,
    encSkHex: Redacted.make(user.encSkHex),
    sigPubHex: user.sigPubHex,
    sigSkSeedHex: Redacted.make(user.sigSkSeedHex),
  };
}

export function storedReserveRecord(user: TestUser): StoredMasterKey {
  return { ...storedMasterRecord(user), kind: "reserve" };
}

export async function ledgerHandlerFor(
  record: StoredMasterKey,
  userId: string,
  secret: Uint8Array,
): Promise<{ handler: MockHandler; code: string }> {
  const wrapped = await wrapMasterSecret({
    recoverySecret: secret,
    userId: testUserId(userId),
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
