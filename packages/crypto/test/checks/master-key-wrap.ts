// CRYPTO_SPEC §8(0.9-draft / KL3 — master 鍵ラップ台帳)のチェック。
// ベクター: test-vectors/master-key-wrap.json。dek-wrap / lease-wrap と同じ構成:
// 固定ベクター(hpke-js の ekm derandomize で生成)は Open 方向で検証し、Seal 方向は
// ラウンドトリップで担保する。AES-GCM / HKDF はベクターの復号成功が導出を固定する。
// recovery-wrap.json(recovery-code 経路)は不変で、そちらは checks/recovery.ts のまま。

import {
  buildGuardianWrapInfo,
  buildHandoffWrapInfo,
  buildMasterWrapAad,
  computeHandoffRequestId,
  decodeHandoffCode,
  derivePasskeyKek,
  encodeHandoffCode,
  type EncryptionKeyPair,
  encodeLengthPrefixed,
  exportEncryptionPublicKey,
  generateEncryptionKeyPair,
  generateMasterWrapKek,
  type GuardianMode,
  type GuardianWrapContext,
  type HandoffWrapContext,
  importEncryptionKeyPair,
  joinGuardianShares,
  type MasterWrapContext,
  openGuardianShare,
  openHandoffValue,
  sealGuardianShare,
  sealHandoffValue,
  splitGuardianKek,
  unwrapMasterBlob,
  wrapMasterBlob,
} from "../../src/index.ts";
import masterWrapVectors from "../../test-vectors/master-key-wrap.json" with { type: "json" };
import recoveryVectors from "../../test-vectors/recovery-wrap.json" with { type: "json" };
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

const doc = masterWrapVectors;
const userId = doc.user_id;
const blobHex = doc.master_secret_blob_hex;

interface AeadVector {
  readonly kek_hex: string;
  readonly nonce_hex: string;
  readonly ciphertext_hex: string;
}

interface GuardianShareVector {
  readonly share_index: number;
  readonly guardian_user_id: string;
  readonly share_hex: string;
  readonly info_hex: string;
  readonly enc_hex: string;
  readonly ciphertext_hex: string;
}

interface GuardianGroupVector extends AeadVector {
  readonly name: string;
  readonly group_id: string;
  readonly mode: GuardianMode;
  readonly aad_hex: string;
  readonly shares: readonly GuardianShareVector[];
}

interface HandoffVector {
  readonly name: string;
  readonly source: string;
  readonly share_index: number;
  readonly approver_user_id: string;
  readonly request_id_hex: string;
  readonly value_hex: string;
  readonly info_hex: string;
  readonly enc_hex: string;
  readonly ciphertext_hex: string;
}

interface NegativeVector {
  readonly decrypt_aad_hex?: string;
  readonly decrypt_kek_hex?: string;
  readonly other_prf_out_hex?: string;
  readonly open_info_hex?: string;
  readonly open_enc_hex?: string;
  readonly code_symbols?: string;
}

function vectorNamed<T>(name: string): T {
  const vector = doc.vectors.find((v) => v.name === name);
  if (vector === undefined) {
    throw new Error(`master-key-wrap.json: ${name} vector missing`);
  }
  return vector as unknown as T;
}

function negativeNamed(name: string): NegativeVector {
  const vector = doc.negative.find((n) => n.name === name);
  if (vector === undefined) {
    throw new Error(`master-key-wrap.json: negative ${name} missing`);
  }
  return vector as unknown as NegativeVector;
}

const passkey = vectorNamed<
  AeadVector & { readonly wrap_id: string; readonly prf_out_hex: string; readonly aad_hex: string }
>("passkey-prf-basic");
const any2 = vectorNamed<GuardianGroupVector>("guardian-any-2");
const all3 = vectorNamed<GuardianGroupVector>("guardian-all-3");
const handoffShare = vectorNamed<HandoffVector>("handoff-guardian-share");
const handoffDevice = vectorNamed<
  HandoffVector & {
    readonly blob_wrap: {
      readonly aad_hex: string;
      readonly nonce_hex: string;
      readonly ciphertext_hex: string;
    };
  }
>("handoff-device");

const passkeyContext: MasterWrapContext = { userId, kind: "passkey-prf", wrapRef: passkey.wrap_id };
const groupContext = (g: GuardianGroupVector): MasterWrapContext => ({
  userId,
  kind: "guardian",
  wrapRef: g.group_id,
  mode: g.mode,
});
const shareContext = (g: GuardianGroupVector, s: GuardianShareVector): GuardianWrapContext => ({
  userId,
  groupId: g.group_id,
  mode: g.mode,
  shareIndex: s.share_index,
  guardianUserId: s.guardian_user_id,
});
const handoffContext = (h: HandoffVector): HandoffWrapContext => ({
  userId,
  requestId: h.request_id_hex,
  source: h.source,
  shareIndex: h.share_index,
  approverUserId: h.approver_user_id,
});

async function importPair(pk: string, sk: string): Promise<EncryptionKeyPair> {
  const pair = await importEncryptionKeyPair({ publicKey: fromHex(pk), privateKey: fromHex(sk) });
  if (!pair.ok) {
    throw new Error("master-key-wrap.json: key import failed");
  }
  return pair.value;
}

async function guardianKeyPair(guardianUserId: string): Promise<EncryptionKeyPair> {
  const keys = (doc.guardian_keypairs as Record<string, { pk_hex: string; sk_hex: string }>)[
    guardianUserId
  ];
  if (keys === undefined) {
    throw new Error(`master-key-wrap.json: guardian ${guardianUserId} keypair missing`);
  }
  return importPair(keys.pk_hex, keys.sk_hex);
}

const unwrapVector = (v: AeadVector, context: MasterWrapContext, kek?: Uint8Array) =>
  unwrapMasterBlob({
    kek: kek ?? fromHex(v.kek_hex),
    wrapped: { nonce: fromHex(v.nonce_hex), ciphertext: fromHex(v.ciphertext_hex) },
    context,
  });

/** B と user_id は recovery-wrap.json を引き継ぐ(台帳 = 同一 B のラップ集合)。 */
function provenanceChecks(c: Checks): void {
  const recovery = recoveryVectors.vectors[0];
  c.push(
    "master-wrap: B and user_id inherit recovery-wrap.json",
    recovery !== undefined &&
      recovery.user_id === userId &&
      recovery.master_secret_blob_hex === blobHex,
  );
}

async function passkeyChecks(c: Checks): Promise<void> {
  c.push(
    "master-wrap: passkey aad construction",
    toHex(buildMasterWrapAad(passkeyContext)) === passkey.aad_hex,
  );
  const kek = await derivePasskeyKek(fromHex(passkey.prf_out_hex));
  c.push("master-wrap: passkey KEK derivation", kek.ok && toHex(kek.value) === passkey.kek_hex);
  const blob = await unwrapVector(passkey, passkeyContext);
  c.push("master-wrap: passkey vector unwrap == B", blob.ok && toHex(blob.value) === blobHex);
  // 短い PRF 出力は InvalidInput(HKDF に入れない)
  const short = await derivePasskeyKek(fromHex(passkey.prf_out_hex).slice(0, 16));
  c.push(
    "master-wrap: passkey short prf output rejected",
    !short.ok && short.error.kind === "InvalidInput",
  );
}

async function openVectorShares(g: GuardianGroupVector, c: Checks): Promise<Uint8Array[]> {
  const opened: Uint8Array[] = [];
  for (const s of g.shares) {
    c.push(
      `master-wrap: ${g.name} share ${s.share_index} info construction`,
      toHex(buildGuardianWrapInfo(shareContext(g, s))) === s.info_hex,
    );
    const share = await openGuardianShare({
      guardianKeyPair: await guardianKeyPair(s.guardian_user_id),
      wrapped: { enc: fromHex(s.enc_hex), ciphertext: fromHex(s.ciphertext_hex) },
      context: shareContext(g, s),
    });
    c.push(
      `master-wrap: ${g.name} share ${s.share_index} vector open == share`,
      share.ok && toHex(share.value) === s.share_hex,
    );
    if (share.ok) {
      opened.push(share.value);
    }
  }
  return opened;
}

async function guardianGroupChecks(c: Checks, g: GuardianGroupVector): Promise<void> {
  c.push(
    `master-wrap: ${g.name} aad construction`,
    toHex(buildMasterWrapAad(groupContext(g))) === g.aad_hex,
  );
  const blob = await unwrapVector(g, groupContext(g));
  c.push(`master-wrap: ${g.name} vector unwrap == B`, blob.ok && toHex(blob.value) === blobHex);
  const opened = await openVectorShares(g, c);
  // 分片から KEK を組み立てる(any: 1 片 / all: 全片の XOR)
  const joined = joinGuardianShares({
    mode: g.mode,
    shares: g.mode === "any" ? opened.slice(0, 1) : opened,
    expectedCount: g.shares.length,
  });
  c.push(
    `master-wrap: ${g.name} joined shares == KEK`,
    joined.ok && toHex(joined.value) === g.kek_hex,
  );
  c.push(
    `master-wrap: ${g.name} share layout`,
    g.mode === "any"
      ? opened.every((s) => toHex(s) === g.kek_hex)
      : new Set(opened.map(toHex)).size === g.shares.length,
  );
}

async function handoffIdChecks(c: Checks): Promise<void> {
  const pub = fromHex(doc.handoff.ephemeral_pub_hex);
  c.push(
    "master-wrap: handoff request_id LP",
    toHex(encodeLengthPrefixed([doc.handoff.request_id_domain, doc.handoff.ephemeral_pub_hex])) ===
      doc.handoff.request_id_lp_hex,
  );
  const requestId = await computeHandoffRequestId(pub);
  c.push(
    "master-wrap: handoff request_id",
    requestId.ok && requestId.value === doc.handoff.request_id_hex,
  );
  const otherId = await computeHandoffRequestId(fromHex(doc.handoff.other_ephemeral.pk_hex));
  c.push(
    "master-wrap: other ephemeral key has its own request_id",
    otherId.ok &&
      otherId.value === doc.handoff.other_ephemeral.request_id_hex &&
      otherId.value !== doc.handoff.request_id_hex,
  );
  const code = await encodeHandoffCode(pub);
  c.push("master-wrap: handoff code encoding", code.ok && code.value === doc.handoff.code.display);
  const decoded = await decodeHandoffCode(doc.handoff.code.display);
  c.push(
    "master-wrap: handoff code decoding",
    decoded.ok && toHex(decoded.value) === doc.handoff.ephemeral_pub_hex,
  );
  // 小文字・空白・ハイフン無しの入力も同じ鍵に復号する(転記の寛容)
  const lenient = await decodeHandoffCode(
    ` ${doc.handoff.code.symbols.toLowerCase().replace(/(.{8})/g, "$1 ")} `,
  );
  c.push(
    "master-wrap: handoff code lenient input",
    lenient.ok && toHex(lenient.value) === doc.handoff.ephemeral_pub_hex,
  );
}

async function handoffOpenChecks(c: Checks, pair: EncryptionKeyPair): Promise<void> {
  for (const h of [handoffShare, handoffDevice]) {
    c.push(
      `master-wrap: ${h.name} info construction`,
      toHex(buildHandoffWrapInfo(handoffContext(h))) === h.info_hex,
    );
    const value = await openHandoffValue({
      ephemeralKeyPair: pair,
      wrapped: { enc: fromHex(h.enc_hex), ciphertext: fromHex(h.ciphertext_hex) },
      context: handoffContext(h),
    });
    c.push(
      `master-wrap: ${h.name} vector open == value`,
      value.ok && toHex(value.value) === h.value_hex,
    );
  }
  // 保護者承認は guardian-all-3 の分片 1 の再封印(値が同一)
  c.push(
    "master-wrap: handoff-guardian-share re-seals share 1 of guardian-all-3",
    handoffShare.source === all3.group_id && handoffShare.value_hex === all3.shares[0]?.share_hex,
  );
  // 端末移行: 同送されたラップを KEK_h(= 開いた値)で開くと B
  const deviceContext: MasterWrapContext = {
    userId,
    kind: "device",
    wrapRef: handoffDevice.request_id_hex,
  };
  c.push(
    "master-wrap: handoff-device blob aad construction",
    toHex(buildMasterWrapAad(deviceContext)) === handoffDevice.blob_wrap.aad_hex,
  );
  const blob = await unwrapVector(
    { kek_hex: handoffDevice.value_hex, ...handoffDevice.blob_wrap },
    deviceContext,
  );
  c.push("master-wrap: handoff-device blob unwrap == B", blob.ok && toHex(blob.value) === blobHex);
}

/** AAD 差し替え negative: ベクターの decrypt_aad_hex と AAD 構築が一致し、復号が失敗する。 */
async function aadNegativeCheck(
  c: Checks,
  name: string,
  base: AeadVector,
  context: MasterWrapContext,
): Promise<void> {
  const n = negativeNamed(name);
  const aadMatches = n.decrypt_aad_hex === toHex(buildMasterWrapAad(context));
  const result = await unwrapVector(base, context);
  c.push(
    `master-wrap negative: ${name}`,
    aadMatches && !result.ok && result.error.kind === "DecryptFailed",
  );
}

async function aadNegativeChecks(c: Checks): Promise<void> {
  await aadNegativeCheck(c, "aad-kind-mismatch", passkey, { ...passkeyContext, kind: "device" });
  await aadNegativeCheck(c, "aad-wrap-ref-mismatch", passkey, {
    ...passkeyContext,
    wrapRef: "01JMKWRAP0000000000000OTHER",
  });
  await aadNegativeCheck(c, "aad-user-mismatch", passkey, {
    ...passkeyContext,
    userId: "user-member-0002",
  });
  await aadNegativeCheck(c, "aad-mode-all-as-any", all3, { ...groupContext(all3), mode: "any" });
  await aadNegativeCheck(c, "aad-mode-any-as-all", any2, { ...groupContext(any2), mode: "all" });
  // suite-mismatch: 実装 API ではドメイン文字列を差し替えられない(型として固定)。
  // AAD の期待バイト列がベクターに存在することのみ検査し、復号失敗は
  // verify_reference.mjs(独立実装)が固定する
  c.push(
    "master-wrap negative: suite-mismatch",
    negativeNamed("suite-mismatch").decrypt_aad_hex !== undefined,
  );
}

/** hex of a successful Uint8Array result, or null(比較を 1 式に畳むための小道具)。 */
function okHex(
  result: { readonly ok: boolean; readonly value?: Uint8Array } | null,
): string | null {
  return result?.ok === true && result.value !== undefined ? toHex(result.value) : null;
}

/** ベクターの decrypt_kek_hex と一致する「間違った KEK」での復号が DecryptFailed になること。 */
async function expectWrongKek(
  c: Checks,
  name: string,
  base: AeadVector,
  context: MasterWrapContext,
  kek: Uint8Array | null,
): Promise<void> {
  const expected = negativeNamed(name).decrypt_kek_hex;
  if (kek === null || toHex(kek) !== expected) {
    c.push(`master-wrap negative: ${name}`, false, "derived KEK differs from the vector");
    return;
  }
  const result = await unwrapVector(base, context, kek);
  c.push(`master-wrap negative: ${name}`, !result.ok && result.error.kind === "DecryptFailed");
}

async function kekNegativeChecks(c: Checks): Promise<void> {
  // share-missing: n−1 片の XOR は KEK ではない。joinGuardianShares は片数不足を
  // InvalidInput で先に拒否し、片数を偽って組んだ KEK は復号失敗になる
  const twoShares = all3.shares.slice(0, 2).map((s) => fromHex(s.share_hex));
  const tooFew = joinGuardianShares({ mode: "all", shares: twoShares, expectedCount: 3 });
  c.push(
    "master-wrap negative: share-missing rejected by join",
    !tooFew.ok && tooFew.error.kind === "InvalidInput",
  );
  const partial = joinGuardianShares({ mode: "all", shares: twoShares, expectedCount: 2 });
  await expectWrongKek(
    c,
    "share-missing",
    all3,
    groupContext(all3),
    partial.ok ? partial.value : null,
  );
  // prf-salt-mismatch: 別 salt の PRF 出力 → 別 KEK → 復号失敗
  const salt = negativeNamed("prf-salt-mismatch");
  const otherKek = await derivePasskeyKek(fromHex(salt.other_prf_out_hex ?? ""));
  await expectWrongKek(
    c,
    "prf-salt-mismatch",
    passkey,
    passkeyContext,
    otherKek.ok ? otherKek.value : null,
  );
}

async function guardianNegativeChecks(c: Checks): Promise<void> {
  const share1 = all3.shares[0];
  if (share1 === undefined) {
    c.push("master-wrap negative: guardian share 1", false, "share missing");
    return;
  }
  const base = shareContext(all3, share1);
  const pair = await guardianKeyPair(share1.guardian_user_id);
  const cases: readonly { readonly name: string; readonly context: GuardianWrapContext }[] = [
    { name: "guardian-transplant-share-index", context: { ...base, shareIndex: 2 } },
    {
      name: "guardian-transplant-guardian",
      context: { ...base, guardianUserId: "user-admin-0003" },
    },
    { name: "guardian-transplant-group", context: { ...base, groupId: any2.group_id } },
    { name: "guardian-mode-relabel", context: { ...base, mode: "any" } },
  ];
  for (const m of cases) {
    const infoMatches =
      negativeNamed(m.name).open_info_hex === toHex(buildGuardianWrapInfo(m.context));
    const result = await openGuardianShare({
      guardianKeyPair: pair,
      wrapped: { enc: fromHex(share1.enc_hex), ciphertext: fromHex(share1.ciphertext_hex) },
      context: m.context,
    });
    c.push(
      `master-wrap negative: ${m.name}`,
      infoMatches && !result.ok && result.error.kind === "DekUnwrapFailed",
    );
  }
}

async function handoffNegativeChecks(c: Checks, pair: EncryptionKeyPair): Promise<void> {
  const base = handoffContext(handoffShare);
  const cases: readonly { readonly name: string; readonly context: HandoffWrapContext }[] = [
    {
      name: "handoff-transplant-request-id",
      context: { ...base, requestId: doc.handoff.other_ephemeral.request_id_hex },
    },
    {
      name: "handoff-transplant-approver",
      context: { ...base, approverUserId: "user-admin-0003" },
    },
    { name: "handoff-transplant-source", context: { ...base, source: "device" } },
    { name: "handoff-share-index-mismatch", context: { ...base, shareIndex: 2 } },
    { name: "handoff-request-id-other-key", context: base },
  ];
  for (const m of cases) {
    const n = negativeNamed(m.name);
    const infoMatches =
      n.open_info_hex === undefined || n.open_info_hex === toHex(buildHandoffWrapInfo(m.context));
    const result = await openHandoffValue({
      ephemeralKeyPair: pair,
      wrapped: {
        enc: fromHex(n.open_enc_hex ?? handoffShare.enc_hex),
        ciphertext: fromHex(handoffShare.ciphertext_hex),
      },
      context: m.context,
    });
    c.push(
      `master-wrap negative: ${m.name}`,
      infoMatches && !result.ok && result.error.kind === "DekUnwrapFailed",
    );
  }
}

async function codeNegativeChecks(c: Checks): Promise<void> {
  for (const name of [
    "handoff-code-checksum-mismatch",
    "handoff-code-bad-padding",
    "handoff-code-wrong-length",
  ]) {
    const decoded = await decodeHandoffCode(negativeNamed(name).code_symbols ?? "");
    c.push(
      `master-wrap negative: ${name}`,
      !decoded.ok &&
        decoded.error.kind === "InvalidInput" &&
        decoded.error.field === "handoff code",
    );
  }
  // アルファベット外の文字(0 / 1 / 8 / 9)は推測置換せず拒否
  const zeroForO = await decodeHandoffCode(doc.handoff.code.symbols.replace(/[A-Z]/, "0"));
  c.push("master-wrap negative: handoff code non-alphabet symbol", !zeroForO.ok);
}

async function invalidInputChecks(c: Checks): Promise<void> {
  const kek = generateMasterWrapKek();
  const blob = fromHex(blobHex);
  const wraps = await Promise.all([
    wrapMasterBlob({
      kek,
      masterSecretBlob: blob,
      context: { userId, kind: "guardian", wrapRef: "g" },
    }),
    wrapMasterBlob({
      kek,
      masterSecretBlob: blob,
      context: { userId, kind: "passkey-prf", wrapRef: "w", mode: "any" },
    }),
    wrapMasterBlob({ kek: kek.slice(0, 16), masterSecretBlob: blob, context: passkeyContext }),
  ]);
  c.push(
    "master-wrap invalid input: context mode / kek length",
    wraps.every((r) => !r.ok && r.error.kind === "InvalidInput"),
  );
  const bounds = [
    splitGuardianKek({ kek, mode: "all", count: 1 }),
    splitGuardianKek({ kek, mode: "any", count: 0 }),
    splitGuardianKek({ kek, mode: "any", count: 6 }),
    splitGuardianKek({ kek: kek.slice(0, 8), mode: "any", count: 2 }),
    joinGuardianShares({ mode: "any", shares: [kek, kek], expectedCount: 2 }),
    joinGuardianShares({ mode: "all", shares: [kek], expectedCount: 1 }),
    joinGuardianShares({ mode: "all", shares: [kek, kek.slice(0, 8)], expectedCount: 2 }),
  ];
  c.push(
    "master-wrap invalid input: split / join bounds",
    bounds.every((r) => !r.ok && r.error.kind === "InvalidInput"),
  );
  const pair = await generateEncryptionKeyPair();
  const contexts = await Promise.all([
    sealGuardianShare({
      guardianPublicKey: pair.publicKey,
      share: kek,
      context: { userId, groupId: "g", mode: "any", shareIndex: 0, guardianUserId: "u" },
    }),
    sealHandoffValue({
      ephemeralPublicKey: pair.publicKey,
      value: kek,
      context: { userId, requestId: "r", source: "", shareIndex: 0, approverUserId: "u" },
    }),
    sealHandoffValue({
      ephemeralPublicKey: pair.publicKey,
      value: kek,
      context: { userId, requestId: "r", source: "device", shareIndex: -1, approverUserId: "u" },
    }),
  ]);
  c.push(
    "master-wrap invalid input: share / handoff context",
    contexts.every((r) => !r.ok && r.error.kind === "InvalidInput"),
  );
  const badPub = await encodeHandoffCode(new Uint8Array(31));
  const badId = await computeHandoffRequestId(new Uint8Array(33));
  c.push("master-wrap invalid input: ephemeral public key length", !badPub.ok && !badId.ok);
}

async function passkeyRoundtrip(c: Checks): Promise<void> {
  const blob = fromHex(blobHex);
  const kek = await derivePasskeyKek(crypto.getRandomValues(new Uint8Array(32)));
  const context: MasterWrapContext = {
    userId: "user-roundtrip",
    kind: "passkey-prf",
    wrapRef: "w1",
  };
  if (!kek.ok) {
    c.push("master-wrap: passkey roundtrip", false, "kek derivation failed");
    return;
  }
  const wrapped = await wrapMasterBlob({ kek: kek.value, masterSecretBlob: blob, context });
  const unwrapped = wrapped.ok
    ? await unwrapMasterBlob({ kek: kek.value, wrapped: wrapped.value, context })
    : null;
  c.push(
    "master-wrap: passkey roundtrip",
    wrapped.ok &&
      wrapped.value.nonce.length === 12 &&
      unwrapped?.ok === true &&
      toHex(unwrapped.value) === toHex(blob),
  );
}

/** 1 分片を生成鍵の保護者へ seal → 本人鍵で open(別鍵では失敗)。開いた分片を返す。 */
async function sealAndOpenShare(
  share: Uint8Array,
  context: GuardianWrapContext,
): Promise<Uint8Array | null> {
  const guardian = await generateEncryptionKeyPair();
  const sealed = await sealGuardianShare({ guardianPublicKey: guardian.publicKey, share, context });
  if (!sealed.ok) {
    return null;
  }
  const opened = await openGuardianShare({
    guardianKeyPair: guardian,
    wrapped: sealed.value,
    context,
  });
  const other = await generateEncryptionKeyPair();
  const wrongKey = await openGuardianShare({
    guardianKeyPair: other,
    wrapped: sealed.value,
    context,
  });
  return opened.ok && !wrongKey.ok ? opened.value : null;
}

/** 3 分片を 3 人の生成鍵保護者へ seal → open して回収する(失敗した分片は落ちる)。 */
async function recoverShares(
  mode: GuardianMode,
  shares: readonly Uint8Array[],
): Promise<Uint8Array[]> {
  const recovered: Uint8Array[] = [];
  for (const [i, share] of shares.entries()) {
    const opened = await sealAndOpenShare(share, {
      userId: "user-roundtrip",
      groupId: `g-${mode}`,
      mode,
      shareIndex: i + 1,
      guardianUserId: `guardian-${i + 1}`,
    });
    if (opened !== null) {
      recovered.push(opened);
    }
  }
  return recovered;
}

async function guardianRoundtrip(c: Checks, mode: GuardianMode): Promise<void> {
  const blob = fromHex(blobHex);
  const groupKek = generateMasterWrapKek();
  const context: MasterWrapContext = {
    userId: "user-roundtrip",
    kind: "guardian",
    wrapRef: `g-${mode}`,
    mode,
  };
  const groupWrap = await wrapMasterBlob({ kek: groupKek, masterSecretBlob: blob, context });
  const shares = splitGuardianKek({ kek: groupKek, mode, count: 3 });
  if (!groupWrap.ok || !shares.ok) {
    c.push(`master-wrap: guardian ${mode} roundtrip`, false, "wrap / split failed");
    return;
  }
  const recovered = await recoverShares(mode, shares.value);
  const joined = joinGuardianShares({
    mode,
    shares: mode === "any" ? recovered.slice(1, 2) : recovered,
    expectedCount: 3,
  });
  const unwrapped = joined.ok
    ? await unwrapMasterBlob({ kek: joined.value, wrapped: groupWrap.value, context })
    : null;
  c.push(
    `master-wrap: guardian ${mode} roundtrip`,
    recovered.length === 3 && okHex(joined) === toHex(groupKek) && okHex(unwrapped) === blobHex,
  );
  if (mode === "all") {
    // 任意の 2 片は KEK と独立: 2 片の XOR は KEK に一致しない
    const pairJoin = joinGuardianShares({ mode, shares: recovered.slice(0, 2), expectedCount: 2 });
    c.push(
      "master-wrap: guardian all roundtrip partial shares != KEK",
      pairJoin.ok && toHex(pairJoin.value) !== toHex(groupKek),
    );
  }
}

/** 一時公開鍵 → コード → 復号 → request_id。往復が成立しなければ null。 */
async function codeRoundtrip(pub: Uint8Array): Promise<string | null> {
  const code = await encodeHandoffCode(pub);
  const decoded = code.ok ? await decodeHandoffCode(code.value) : null;
  if (okHex(decoded) !== toHex(pub) || decoded?.ok !== true) {
    return null;
  }
  const requestId = await computeHandoffRequestId(decoded.value);
  return requestId.ok ? requestId.value : null;
}

async function handoffRoundtrip(c: Checks): Promise<void> {
  // 生成した一時鍵 → コード → 復号 → request_id → seal / open
  const ephemeral = await generateEncryptionKeyPair();
  const pub = await exportEncryptionPublicKey(ephemeral.publicKey);
  const requestId = await codeRoundtrip(pub);
  const context: HandoffWrapContext = {
    userId: "user-roundtrip",
    requestId: requestId ?? "",
    source: "device",
    shareIndex: 0,
    approverUserId: "user-roundtrip",
  };
  const kekH = generateMasterWrapKek();
  const sealed = await sealHandoffValue({
    ephemeralPublicKey: ephemeral.publicKey,
    value: kekH,
    context,
  });
  if (!sealed.ok) {
    c.push("master-wrap: handoff roundtrip", false, "seal failed");
    return;
  }
  const opened = await openHandoffValue({
    ephemeralKeyPair: ephemeral,
    wrapped: sealed.value,
    context,
  });
  c.push("master-wrap: handoff roundtrip", requestId !== null && okHex(opened) === toHex(kekH));
  // 別の一時鍵では開けない(要求者プロセスが終われば承認は無価値)
  const otherEphemeral = await generateEncryptionKeyPair();
  const wrongKey = await openHandoffValue({
    ephemeralKeyPair: otherEphemeral,
    wrapped: sealed.value,
    context,
  });
  c.push("master-wrap: handoff roundtrip other ephemeral key rejected", !wrongKey.ok);
}

export async function masterKeyWrapChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  provenanceChecks(c);
  await passkeyChecks(c);
  await guardianGroupChecks(c, any2);
  await guardianGroupChecks(c, all3);
  const pair = await importPair(doc.ephemeral_keypair.pk_hex, doc.ephemeral_keypair.sk_hex);
  await handoffIdChecks(c);
  await handoffOpenChecks(c, pair);
  await aadNegativeChecks(c);
  await kekNegativeChecks(c);
  await guardianNegativeChecks(c);
  await handoffNegativeChecks(c, pair);
  await codeNegativeChecks(c);
  await invalidInputChecks(c);
  await passkeyRoundtrip(c);
  await guardianRoundtrip(c, "any");
  await guardianRoundtrip(c, "all");
  await handoffRoundtrip(c);
  return c.results;
}
