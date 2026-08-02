// CRYPTO_SPEC §5(DEK ラップ)のチェック。
// panva hpke は単発 Seal を derandomize できないため(spike-c の知見)、
// 固定ベクター(hpke-js の ekm derandomize で生成)は Open 方向で検証し、
// Seal 方向はラウンドトリップで担保する。RFC 9180 公式ベクターは rfc9180.ts。

import {
  buildDekWrapInfo,
  type DekWrapContext,
  generateDek,
  generateEncryptionKeyPair,
  importEncryptionKeyPair,
  unwrapDek,
  wrapDek,
} from "../../src/index.ts";
import dekWrapVectors from "../../test-vectors/dek-wrap.json" with { type: "json" };
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

const baseVector = dekWrapVectors.vectors[0];
if (baseVector === undefined) {
  throw new Error("dek-wrap.json: basic vector missing");
}
const base = baseVector;

function baseContext(): DekWrapContext {
  return {
    projectId: base.project_id,
    environmentId: base.environment_id,
    epoch: base.epoch,
    recipientUserId: base.recipient_user_id,
  };
}

async function recipientKeyPair() {
  return importEncryptionKeyPair({
    publicKey: fromHex(dekWrapVectors.recipient_keypair.pkRm_hex),
    privateKey: fromHex(dekWrapVectors.recipient_keypair.skRm_hex),
  });
}

async function vectorOpenChecks(c: Checks): Promise<void> {
  // info 構築がベクターと一致
  c.push("dek-wrap: info construction", toHex(buildDekWrapInfo(baseContext())) === base.info_hex);

  // 固定ベクターの Open(KeyPair は非抽出でインポート)
  const pair = await recipientKeyPair();
  if (!pair.ok) {
    c.push("dek-wrap: vector open", false, "recipient key import failed");
    return;
  }
  const dek = await unwrapDek({
    recipientKeyPair: pair.value,
    wrapped: { enc: fromHex(base.enc_hex), ciphertext: fromHex(base.ciphertext_hex) },
    context: baseContext(),
  });
  c.push("dek-wrap: vector open == DEK", dek.ok && toHex(dek.value) === base.dek_hex);
}

async function negativeChecks(c: Checks): Promise<void> {
  const pair = await recipientKeyPair();
  if (!pair.ok) {
    c.push("dek-wrap: negatives", false, "recipient key import failed");
    return;
  }

  // info 系 negative は文脈差し替えで再現し、ベクターの open_info_hex と
  // info 構築が一致することも確認する
  const contexts: readonly { name: string; context: DekWrapContext }[] = [
    { name: "info-epoch-mismatch", context: { ...baseContext(), epoch: 4 } },
    {
      name: "info-recipient-mismatch",
      context: { ...baseContext(), recipientUserId: "user-owner-0001" },
    },
    {
      name: "info-environment-mismatch",
      context: { ...baseContext(), environmentId: "env-dev-0002" },
    },
  ];
  for (const m of contexts) {
    const vector = dekWrapVectors.negative.find((n) => n.name === m.name);
    const infoMatches = vector?.open_info_hex === toHex(buildDekWrapInfo(m.context));
    const result = await unwrapDek({
      recipientKeyPair: pair.value,
      wrapped: { enc: fromHex(base.enc_hex), ciphertext: fromHex(base.ciphertext_hex) },
      context: m.context,
    });
    c.push(
      `dek-wrap negative: ${m.name}`,
      infoMatches && !result.ok && result.error.kind === "DekUnwrapFailed",
    );
  }

  // enc(カプセル化公開鍵)改竄
  const encTampered = dekWrapVectors.negative.find((n) => n.name === "enc-tampered");
  if (encTampered?.enc_hex === undefined) {
    c.push("dek-wrap negative: enc-tampered", false, "vector missing");
  } else {
    const result = await unwrapDek({
      recipientKeyPair: pair.value,
      wrapped: {
        enc: fromHex(encTampered.enc_hex),
        ciphertext: fromHex(base.ciphertext_hex),
      },
      context: baseContext(),
    });
    c.push("dek-wrap negative: enc-tampered", !result.ok);
  }
}

async function roundtripChecks(c: Checks): Promise<void> {
  // Seal 方向: 自己ラウンドトリップ(受信者は生成鍵・非抽出)
  const recipient = await generateEncryptionKeyPair();
  const dek = generateDek();
  const wrapped = await wrapDek({
    recipientPublicKey: recipient.publicKey,
    dek,
    context: baseContext(),
  });
  if (!wrapped.ok) {
    c.push("dek-wrap: roundtrip", false, "wrap failed");
    return;
  }
  const unwrapped = await unwrapDek({
    recipientKeyPair: recipient,
    wrapped: wrapped.value,
    context: baseContext(),
  });
  c.push("dek-wrap: roundtrip", unwrapped.ok && toHex(unwrapped.value) === toHex(dek));

  // 文脈差し替えは Open 失敗
  const wrongContext = await unwrapDek({
    recipientKeyPair: recipient,
    wrapped: wrapped.value,
    context: { ...baseContext(), projectId: "proj-other" },
  });
  c.push("dek-wrap: roundtrip wrong context rejected", !wrongContext.ok);

  // 別の受信者鍵では Open 失敗
  const otherRecipient = await generateEncryptionKeyPair();
  const wrongKey = await unwrapDek({
    recipientKeyPair: otherRecipient,
    wrapped: wrapped.value,
    context: baseContext(),
  });
  c.push("dek-wrap: roundtrip wrong recipient rejected", !wrongKey.ok);
}

export async function dekWrapChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  await vectorOpenChecks(c);
  await negativeChecks(c);
  await roundtripChecks(c);
  return c.results;
}
