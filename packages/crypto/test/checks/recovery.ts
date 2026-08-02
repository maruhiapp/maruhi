// CRYPTO_SPEC §8(リカバリーラップ)のチェック。
// ベクター: test-vectors/recovery-wrap.json。KEK 導出(salt = 空)は
// ベクター暗号文の復号成功が暗黙に固定する。wrong-salt はベクターの
// decrypt_kek_hex(空以外の salt で導出した KEK)での復号失敗を WebCrypto で検査。

import {
  encodeLengthPrefixed,
  generateRecoverySecret,
  unwrapMasterSecret,
  wrapMasterSecret,
} from "../../src/index.ts";
import recoveryVectors from "../../test-vectors/recovery-wrap.json" with { type: "json" };
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

const baseVector = recoveryVectors.vectors[0];
if (baseVector === undefined) {
  throw new Error("recovery-wrap.json: basic vector missing");
}
const base = baseVector;

async function vectorChecks(c: Checks): Promise<void> {
  // AAD 構築(LP("maruhi/v1/recovery-wrap", user_id))がベクターと一致
  c.push(
    "recovery: aad construction",
    toHex(encodeLengthPrefixed(["maruhi/v1/recovery-wrap", base.user_id])) === base.aad_hex,
  );

  // 固定ベクターの unwrap(KEK 導出 salt=空 を暗黙に固定)
  const blob = await unwrapMasterSecret({
    recoverySecret: fromHex(base.recovery_secret_hex),
    userId: base.user_id,
    wrapped: { nonce: fromHex(base.nonce_hex), ciphertext: fromHex(base.ciphertext_hex) },
  });
  c.push(
    "recovery: vector unwrap == master blob",
    blob.ok && toHex(blob.value) === base.master_secret_blob_hex,
  );
}

async function negativeChecks(c: Checks): Promise<void> {
  // aad-user-mismatch: 他ユーザーの鍵ブロブへの移植
  const otherUser = await unwrapMasterSecret({
    recoverySecret: fromHex(base.recovery_secret_hex),
    userId: "user-member-0002",
    wrapped: { nonce: fromHex(base.nonce_hex), ciphertext: fromHex(base.ciphertext_hex) },
  });
  c.push(
    "recovery negative: aad-user-mismatch",
    !otherUser.ok && otherUser.error.kind === "DecryptFailed",
  );

  // ciphertext-bit-flip
  const flip = recoveryVectors.negative.find((n) => n.name === "ciphertext-bit-flip");
  const tampered = await unwrapMasterSecret({
    recoverySecret: fromHex(base.recovery_secret_hex),
    userId: base.user_id,
    wrapped: {
      nonce: fromHex(base.nonce_hex),
      ciphertext: fromHex(flip?.ciphertext_hex ?? base.ciphertext_hex),
    },
  });
  c.push("recovery negative: ciphertext-bit-flip", !tampered.ok);

  // wrong-salt: 空以外の salt から導出された KEK(ベクター付属)では復号不能。
  // 実装 API は salt を注入できない(良いこと)ので、WebCrypto で直接検査する
  const wrongSalt = recoveryVectors.negative.find((n) => n.name === "wrong-salt");
  if (wrongSalt?.decrypt_kek_hex === undefined) {
    c.push("recovery negative: wrong-salt", false, "vector missing");
    return;
  }
  let failed = false;
  try {
    const kek = await crypto.subtle.importKey(
      "raw",
      fromHex(wrongSalt.decrypt_kek_hex) as BufferSource,
      "AES-GCM",
      false,
      ["decrypt"],
    );
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: fromHex(base.nonce_hex) as BufferSource,
        additionalData: fromHex(base.aad_hex) as BufferSource,
      },
      kek,
      fromHex(base.ciphertext_hex) as BufferSource,
    );
  } catch {
    failed = true;
  }
  c.push("recovery negative: wrong-salt", failed);
}

async function roundtripChecks(c: Checks): Promise<void> {
  const recoverySecret = generateRecoverySecret();
  const blob = fromHex(base.master_secret_blob_hex);
  const wrapped = await wrapMasterSecret({
    recoverySecret,
    userId: "user-roundtrip-0001",
    masterSecretBlob: blob,
  });
  if (!wrapped.ok) {
    c.push("recovery: roundtrip", false, "wrap failed");
    return;
  }
  const unwrapped = await unwrapMasterSecret({
    recoverySecret,
    userId: "user-roundtrip-0001",
    wrapped: wrapped.value,
  });
  c.push(
    "recovery: roundtrip",
    wrapped.value.nonce.length === 12 && unwrapped.ok && toHex(unwrapped.value) === toHex(blob),
  );

  // 別のリカバリーコードでは復号できない
  const wrongSecret = await unwrapMasterSecret({
    recoverySecret: generateRecoverySecret(),
    userId: "user-roundtrip-0001",
    wrapped: wrapped.value,
  });
  c.push("recovery: wrong secret rejected", !wrongSecret.ok);
}

export async function recoveryChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  await vectorChecks(c);
  await negativeChecks(c);
  await roundtripChecks(c);
  return c.results;
}
