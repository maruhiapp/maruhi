// 回復台帳(`GET /auth/recovery` — CRYPTO_SPEC §8)のモック。既知の secret で鍵レコードを
// ラップして配り、そのリカバリーコードを返す。recovery.test.ts と device.test.ts
// (DK K14 — 台帳の鍵の判定)が共有する。

import { wrapMasterSecret } from "@maruhi/crypto";
import { Redacted } from "effect";

import { serializeStoredMasterKey, type StoredMasterKey } from "../../src/keychain.ts";
import { formatRecoveryCode } from "../../src/recovery-code.ts";
import type { TestUser } from "./crypto.ts";
import { type MockHandler, onRequest } from "./server.ts";

/** テスト利用者の鍵対をキーチェーン / 台帳のレコードの形にする。 */
export function storedMasterRecord(user: TestUser): StoredMasterKey {
  return {
    suite: "maruhi/v1",
    encPubHex: user.encPubHex,
    encSkHex: Redacted.make(user.encSkHex),
    sigPubHex: user.sigPubHex,
    sigSkSeedHex: Redacted.make(user.sigSkSeedHex),
  };
}

/** CLI が予備鍵として生成した記録(予備鍵の印つき — CRYPTO_SPEC §8 / DK K16)。 */
export function storedReserveRecord(user: TestUser): StoredMasterKey {
  return { ...storedMasterRecord(user), kind: "reserve" };
}

/** 既知の secret で `record` をラップし、GET /auth/recovery で配るハンドラとそのコード。 */
export async function ledgerHandlerFor(
  record: StoredMasterKey,
  userId: string,
  secret: Uint8Array,
): Promise<{ handler: MockHandler; code: string }> {
  const wrapped = await wrapMasterSecret({
    recoverySecret: secret,
    userId,
    // JSON.stringify(record) は使えない — 秘密側が伏字でラップされ、
    // 「復号は成功するのに鍵が読めない」ブロブになる(本番の recovery.ts と同じ罠)
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
