// CRYPTO_SPEC §5(DEK ラップ)のチェック。
// panva hpke は単発 Seal を derandomize できないため(spike-c の知見)、
// 固定ベクター(hpke-js の ekm derandomize で生成)は Open 方向で検証し、
// Seal 方向はラウンドトリップで担保する。RFC 9180 公式ベクターは rfc9180.ts。

import {
  buildDekWrapInfo,
  computeServerKeyFingerprint,
  type DekWrapContext,
  generateDek,
  generateEncryptionKeyPair,
  importEncryptionKeyPair,
  unwrapDek,
  wrapDek,
} from "../../src/index.ts";
import dekWrapVectors from "../../test-vectors/dek-wrap.json" with { type: "json" };
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

/** フィクスチャの必須文字列(JSON union 型で optional 化されたフィールドの検証読み出し)。 */
function fixtureString(value: string | undefined, name: string): string {
  if (value === undefined) {
    throw new Error(`dek-wrap.json: ${name} missing`);
  }
  return value;
}

const baseVector = dekWrapVectors.vectors.find((v) => v.name === "basic");
if (baseVector === undefined) {
  throw new Error("dek-wrap.json: basic vector missing");
}
const base = baseVector;
const baseRecipientUserId = fixtureString(base.recipient_user_id, "basic recipient_user_id");

// 受信者クラス server(§9): info の recipient 位置はサーバー鍵 FP
const serverVectorFound = dekWrapVectors.vectors.find((v) => v.name === "server-basic");
if (serverVectorFound === undefined) {
  throw new Error("dek-wrap.json: server-basic vector missing");
}
const serverVector = serverVectorFound;
const serverFingerprintHex = fixtureString(
  serverVector.server_key_fingerprint_hex,
  "server-basic server_key_fingerprint_hex",
);

function baseContext(): DekWrapContext {
  return {
    projectId: base.project_id,
    environmentId: base.environment_id,
    epoch: base.epoch,
    recipientUserId: baseRecipientUserId,
  };
}

function serverContext(): DekWrapContext {
  return {
    projectId: serverVector.project_id,
    environmentId: serverVector.environment_id,
    epoch: serverVector.epoch,
    // §9: recipient_user_id 位置にサーバー鍵 FP(hex 小文字)を用いる
    recipientUserId: serverFingerprintHex,
  };
}

async function recipientKeyPair() {
  return importEncryptionKeyPair({
    publicKey: fromHex(dekWrapVectors.recipient_keypair.pkRm_hex),
    privateKey: fromHex(dekWrapVectors.recipient_keypair.skRm_hex),
  });
}

async function serverKeyPair() {
  return importEncryptionKeyPair({
    publicKey: fromHex(dekWrapVectors.server_keypair.pkSm_hex),
    privateKey: fromHex(dekWrapVectors.server_keypair.skSm_hex),
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

async function serverVectorChecks(c: Checks): Promise<void> {
  // 受信者クラス server(§9): FP = SHA-256(server_enc_pub)[:16] を実装で再計算し、
  // info の recipient 位置に FP を入れた構築がベクターと一致する
  const fp = await computeServerKeyFingerprint(fromHex(dekWrapVectors.server_keypair.pkSm_hex));
  c.push(
    "dek-wrap: server key fingerprint matches vector",
    fp.ok && toHex(fp.value) === dekWrapVectors.server_keypair.server_key_fingerprint_hex,
  );
  c.push(
    "dek-wrap: server info construction",
    toHex(buildDekWrapInfo(serverContext())) === serverVector.info_hex,
  );

  const pair = await serverKeyPair();
  if (!pair.ok) {
    c.push("dek-wrap: server vector open", false, "server key import failed");
    return;
  }
  const dek = await unwrapDek({
    recipientKeyPair: pair.value,
    wrapped: {
      enc: fromHex(serverVector.enc_hex),
      ciphertext: fromHex(serverVector.ciphertext_hex),
    },
    context: serverContext(),
  });
  c.push(
    "dek-wrap: server vector open == DEK",
    dek.ok && toHex(dek.value) === serverVector.dek_hex,
  );
  // basic と同一のエポック DEK(1 つの DEK × 複数受信者クラス — §7 のラップ完全集合の形)
  c.push("dek-wrap: server vector wraps the same DEK", serverVector.dek_hex === base.dek_hex);

  // 受信者クラス間の移植負例(server 宛の info をメンバー user_id / 別 FP で組む)
  const serverNegatives: readonly { name: string; context: DekWrapContext }[] = [
    {
      name: "server-info-member-user-id",
      context: { ...serverContext(), recipientUserId: baseRecipientUserId },
    },
    {
      name: "server-info-fp-mismatch",
      context: {
        ...serverContext(),
        recipientUserId: wrongServerFingerprintHex(),
      },
    },
  ];
  for (const negative of serverNegatives) {
    const vector = dekWrapVectors.negative.find((n) => n.name === negative.name);
    const infoMatches =
      vector !== undefined &&
      "open_info_hex" in vector &&
      vector.open_info_hex === toHex(buildDekWrapInfo(negative.context));
    const result = await unwrapDek({
      recipientKeyPair: pair.value,
      wrapped: {
        enc: fromHex(serverVector.enc_hex),
        ciphertext: fromHex(serverVector.ciphertext_hex),
      },
      context: negative.context,
    });
    c.push(
      `dek-wrap negative: ${negative.name}`,
      infoMatches && !result.ok && result.error.kind === "DekUnwrapFailed",
    );
  }

  // 逆方向の移植(メンバー宛ラップの recipient 位置にサーバー FP)も Open 失敗
  const memberPair = await recipientKeyPair();
  if (!memberPair.ok) {
    c.push("dek-wrap negative: member-info-server-fp", false, "recipient key import failed");
    return;
  }
  const reverseVector = dekWrapVectors.negative.find((n) => n.name === "member-info-server-fp");
  const reverseContext: DekWrapContext = {
    ...baseContext(),
    recipientUserId: serverFingerprintHex,
  };
  const reverseInfoMatches =
    reverseVector !== undefined &&
    "open_info_hex" in reverseVector &&
    reverseVector.open_info_hex === toHex(buildDekWrapInfo(reverseContext));
  const reverse = await unwrapDek({
    recipientKeyPair: memberPair.value,
    wrapped: { enc: fromHex(base.enc_hex), ciphertext: fromHex(base.ciphertext_hex) },
    context: reverseContext,
  });
  c.push(
    "dek-wrap negative: member-info-server-fp",
    reverseInfoMatches && !reverse.ok && reverse.error.kind === "DekUnwrapFailed",
  );
}

/** server-info-fp-mismatch ベクターの「別サーバー鍵の FP」(先頭バイト反転)。 */
function wrongServerFingerprintHex(): string {
  const fp = fromHex(dekWrapVectors.server_keypair.server_key_fingerprint_hex);
  const flipped = fp.slice();
  flipped[0] = (flipped[0] ?? 0) ^ 0x01;
  return toHex(flipped);
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

async function invalidContextChecks(c: Checks): Promise<void> {
  // epoch が非負の安全な整数でない場合は throw でなく InvalidInput で返る
  const recipient = await generateEncryptionKeyPair();
  try {
    const wrapped = await wrapDek({
      recipientPublicKey: recipient.publicKey,
      dek: generateDek(),
      context: { ...baseContext(), epoch: -1 },
    });
    const unwrapped = await unwrapDek({
      recipientKeyPair: recipient,
      wrapped: { enc: fromHex(base.enc_hex), ciphertext: fromHex(base.ciphertext_hex) },
      context: { ...baseContext(), epoch: Number.NaN },
    });
    c.push(
      "dek-wrap invalid context: bad epoch",
      !wrapped.ok &&
        wrapped.error.kind === "InvalidInput" &&
        !unwrapped.ok &&
        unwrapped.error.kind === "InvalidInput",
    );
  } catch (error) {
    c.push("dek-wrap invalid context: bad epoch", false, `threw: ${String(error)}`);
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
  await serverVectorChecks(c);
  await negativeChecks(c);
  await invalidContextChecks(c);
  await roundtripChecks(c);
  return c.results;
}
