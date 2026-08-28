// データプレーン統合テスト用の実 crypto ヘルパ(workerd 内で実行)。
//
// packages/crypto の公開 API だけで実データを作る: テストベクターの固定鍵
// (chain-entries.json の keys)でチェーンエントリをテスト時に署名し、
// DEK 生成 → HPKE ラップ → AES-GCM 暗号化 → クライアント側復号までを実行する。
// フェイクの暗号文を使うのは「サーバーが中身を検証できない」ことを利用する
// 受理ポリシー系テストのみ(各テストに明記)。
// チェーン組立・ワイヤ値の共通コアは @maruhi/crypto/test-support
// (cli テスト支援と共有 — session-11 §5 裁定)。

import type {
  ChainEntry,
  ChainOperation,
  EnvValuesDigestEntry,
  MetaStatementTarget,
  UnsignedChainEntry,
  VariableContext,
} from "@maruhi/crypto";
import {
  computeChainEntryHash,
  computeDekCommitment,
  computeEnvManifestSignedBytesHash,
  computeEnvValuesDigest,
  computeMetaSignedBytesHash,
  computeVariablesDigest,
  decryptVariable,
  encodeHex,
  encryptVariable,
  generateDek,
  importEncryptionKeyPair,
  importEncryptionPublicKey,
  importSigningKeyPair,
  importSigningPublicKey,
  signChainEntry,
  signDekWrap,
  signEnvManifest,
  signMetaStatement,
  signValue,
  SUITE_ID,
  unwrapDek,
  verifyDekWrapSignature,
  wrapDek,
} from "@maruhi/crypto";
import type { BuiltChain, WireEncryptedPayload } from "@maruhi/crypto/test-support";
import {
  BASE_TIME_MS,
  buildChainWith,
  hexBytes,
  unwrapResult,
  valueContextOf,
  vectorKeys,
} from "@maruhi/crypto/test-support";

export type { BuiltChain, WireEncryptedPayload };
export { hexBytes, valueSignedBytesHashOf } from "@maruhi/crypto/test-support";

/**
 * ベクター固定鍵集合に無いユーザー ID の鍵借用。データフィクスチャの reader
 * (user-reader-0003)は 3 本目のベクター鍵(名義 user-admin-0003)を使う —
 * 鍵とユーザー ID の束縛はチェーンの add_member が行うため、ベクター JSON の
 * 名義とテストユーザー ID は独立でよい。
 */
const VECTOR_KEY_ALIASES: Record<string, string> = {
  "user-reader-0003": "user-admin-0003",
};

/** ベクター固定鍵のユーザー(user-owner-0001 / user-member-0002 / user-admin-0003 + 借用者)。 */
export function vectorKeyOf(userId: string) {
  const keys = vectorKeys[VECTOR_KEY_ALIASES[userId] ?? userId];
  if (keys === undefined) {
    throw new Error(`no vector keys for ${userId}`);
  }
  return keys;
}

/** ベクター seed でエントリを署名する(actor = entry.actor.userId の鍵)。 */
async function signAs(userId: string, unsigned: UnsignedChainEntry): Promise<ChainEntry> {
  const keys = vectorKeyOf(userId);
  const pair = unwrapResult(
    await importSigningKeyPair({
      publicKey: hexBytes(keys.sig_pub_hex),
      privateSeed: hexBytes(keys.sig_sk_seed_hex),
    }),
    "importSigningKeyPair",
  );
  return unwrapResult(
    await signChainEntry({ entry: unsigned, signingKey: pair.privateKey }),
    "signChainEntry",
  );
}

export interface ChainStep {
  readonly actorUserId: string;
  readonly operation: ChainOperation;
}

/** 既存チェーンの末尾に続く 1 エントリをテスト時署名で作る。 */
export async function signEntryAt(input: {
  readonly seq: number;
  readonly prevHashHex: string;
  readonly actorUserId: string;
  readonly operation: ChainOperation;
}): Promise<{ readonly entry: ChainEntry; readonly hash: string }> {
  const keys = vectorKeyOf(input.actorUserId);
  const unsigned: UnsignedChainEntry = {
    ...input.operation,
    suite: SUITE_ID,
    seq: input.seq,
    prevHashHex: input.prevHashHex,
    actor: { userId: input.actorUserId, keyFingerprintHex: keys.key_fingerprint_hex },
    timestampMs: BASE_TIME_MS + input.seq * 1000,
  };
  const entry = await signAs(input.actorUserId, unsigned);
  return { entry, hash: await computeChainEntryHash(entry) };
}

/**
 * 既存エントリ(ベクター本編・negative)の op / payload / actor を保ったまま
 * seq / prev を付け替えて再署名する。複合の境界 checkpoint 挿入(AUTH_SPEC §12-4)
 * でヘッドがベクターの固定 seq からずれた後の API 再生用。actor ブロックは原本を
 * 保持する(鍵 FP 不一致 negative の意味論を保つ)。seq / prev / timestamp が原本と
 * 一致する場合は Ed25519 の決定性により原本と同一バイトになる。
 */
export async function resignEntryAt(
  base: ChainEntry,
  seq: number,
  prevHashHex: string,
): Promise<{ readonly entry: ChainEntry; readonly hash: string }> {
  const { signatureHex: _signatureHex, ...rest } = base;
  const unsigned: UnsignedChainEntry = {
    ...rest,
    seq,
    prevHashHex,
    timestampMs: BASE_TIME_MS + seq * 1000,
  };
  const entry = await signAs(base.actor.userId, unsigned);
  return { entry, hash: await computeChainEntryHash(entry) };
}

/** テスト時署名で有効なチェーンを組み立てる(seq / prev_hash / timestamp は自動)。 */
export async function buildChain(steps: readonly ChainStep[]): Promise<BuiltChain> {
  return buildChainWith(
    steps.map((step) => ({
      actor: {
        userId: step.actorUserId,
        keyFingerprintHex: vectorKeyOf(step.actorUserId).key_fingerprint_hex,
      },
      operation: step.operation,
      signEntry: (unsigned) => signAs(step.actorUserId, unsigned),
    })),
  );
}

/** genesis 用の payload(actor 自身の公開鍵一式)。 */
export function genesisOperation(userId: string): ChainOperation {
  const keys = vectorKeyOf(userId);
  return {
    op: "genesis",
    payload: { encPubHex: keys.enc_pub_hex, sigPubHex: keys.sig_pub_hex },
  };
}

/** add_member 用の payload(対象のベクター公開鍵一式)。 */
export function addMemberOperation(
  targetUserId: string,
  role: "owner" | "admin" | "member" | "reader",
): ChainOperation {
  const keys = vectorKeyOf(targetUserId);
  return {
    op: "add_member",
    payload: {
      targetUserId,
      encPubHex: keys.enc_pub_hex,
      sigPubHex: keys.sig_pub_hex,
      role,
    },
  };
}

/** §5.2 のコミットメント(hex 小文字 64 文字)。 */
export async function commitmentOf(
  projectId: string,
  environmentId: string,
  epoch: number,
  dek: Uint8Array,
): Promise<string> {
  return unwrapResult(
    await computeDekCommitment({
      context: { suite: SUITE_ID, projectId, environmentId, epoch },
      dek,
    }),
    "computeDekCommitment",
  );
}

/** create_environment 用の payload(エポック 1 のコミットメント込み — §6.2)。 */
export function createEnvironmentOperation(
  environmentId: string,
  dekCommitmentHex: string,
): ChainOperation {
  return { op: "create_environment", payload: { environmentId, dekCommitmentHex } };
}

/** values_digest の正規形計算(§6.2 — active 変数の値レベル最新形。空集合可)。 */
export async function valuesDigestOf(entries: readonly EnvValuesDigestEntry[]): Promise<string> {
  return unwrapResult(await computeEnvValuesDigest(SUITE_ID, entries), "computeEnvValuesDigest");
}

/**
 * 境界 checkpoint 用の operation(当該環境 1 タプル + 空 audit head —
 * AUTH_SPEC §12-4 / CRYPTO_SPEC §6.3)。negative 用に audit head と複数タプルの
 * 上書きも許す。
 */
export function checkpointOperation(input: {
  readonly environmentId: string;
  readonly epoch: number;
  readonly manifestVersion: number;
  readonly manifestSigHashHex: string;
  readonly valuesDigestHex: string;
  readonly auditHeadHashHex?: string;
}): ChainOperation {
  return {
    op: "checkpoint",
    payload: {
      environments: [
        {
          environmentId: input.environmentId,
          epoch: input.epoch,
          manifestVersion: input.manifestVersion,
          manifestSigHashHex: input.manifestSigHashHex,
          valuesDigestHex: input.valuesDigestHex,
        },
      ],
      auditHeadHashHex: input.auditHeadHashHex ?? "",
    },
  };
}

/** rotate_epoch 用の payload(新エポックのコミットメント込み — §6.2)。 */
export function rotateEpochOperation(
  environmentId: string,
  newEpoch: number,
  dekCommitmentHex: string,
  reason = "scheduled",
): ChainOperation {
  return { op: "rotate_epoch", payload: { environmentId, newEpoch, reason, dekCommitmentHex } };
}

/** 新しい環境エポック DEK(256-bit 乱数)。 */
export function makeDek(): Uint8Array {
  return generateDek();
}

export interface WireWrappedDek {
  readonly suite: string;
  readonly epoch: number;
  /** 受信者クラス(AUTH_SPEC §12-6。省略 = member)。 */
  readonly recipientClass?: "member" | "server";
  readonly recipientUserId: string;
  readonly recipientEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly signatureHex: string;
}

/**
 * 署名なしのワイヤ表現に登録署名(CRYPTO_SPEC §5.1)を付ける。署名者は
 * ベクター固定鍵のユーザー(= API を呼ぶ主体と一致させること — §12-6)。
 * フェイクラップの受理ポリシー系テストにも使う(サーバーは中身を検証できないが
 * 署名は検証するため、フェイクにも呼び出し主体の署名が要る)。
 */
export async function signWrapAs(
  signerUserId: string,
  projectId: string,
  environmentId: string,
  wrap: Omit<WireWrappedDek, "signatureHex">,
): Promise<WireWrappedDek> {
  const keys = vectorKeyOf(signerUserId);
  const pair = unwrapResult(
    await importSigningKeyPair({
      publicKey: hexBytes(keys.sig_pub_hex),
      privateSeed: hexBytes(keys.sig_sk_seed_hex),
    }),
    "importSigningKeyPair",
  );
  const signatureHex = unwrapResult(
    await signDekWrap({
      context: {
        suite: wrap.suite,
        projectId,
        environmentId,
        epoch: wrap.epoch,
        recipientUserId: wrap.recipientUserId,
        recipientEncPubHex: wrap.recipientEncPubHex,
        encHex: wrap.encHex,
        ciphertextHex: wrap.ciphertextHex,
        signerUserId,
      },
      signingKey: pair.privateKey,
    }),
    "signDekWrap",
  );
  return { ...wrap, signatureHex };
}

/**
 * 配布されたラップの登録署名をクライアント側で検証する(CRYPTO_SPEC §5.1)。
 * 検証鍵は「チェーン上で署名者 user_id に束縛された sig 公開鍵」— テストでは
 * ベクター固定鍵から引く。
 */
export async function verifyDistributedWrapSignature(input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly recipientUserId: string;
  readonly recipientEncPubHex: string;
  readonly wrap: {
    readonly suite: string;
    readonly epoch: number;
    readonly encHex: string;
    readonly ciphertextHex: string;
    readonly signatureHex: string;
    readonly signerUserId: string;
  };
}): Promise<boolean> {
  const signerKeys = vectorKeyOf(input.wrap.signerUserId);
  const publicKey = unwrapResult(
    await importSigningPublicKey(hexBytes(signerKeys.sig_pub_hex)),
    "importSigningPublicKey",
  );
  const result = await verifyDekWrapSignature({
    context: {
      suite: input.wrap.suite,
      projectId: input.projectId,
      environmentId: input.environmentId,
      epoch: input.wrap.epoch,
      recipientUserId: input.recipientUserId,
      recipientEncPubHex: input.recipientEncPubHex,
      encHex: input.wrap.encHex,
      ciphertextHex: input.wrap.ciphertextHex,
      signerUserId: input.wrap.signerUserId,
    },
    signatureHex: input.wrap.signatureHex,
    signerPublicKey: publicKey,
  });
  return result.ok;
}

/** DEK を 1 受信者へ HPKE ラップし、署名者の登録署名付きワイヤ表現(§12-2)で返す。 */
export async function wrapDekTo(input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly dek: Uint8Array;
  readonly recipientUserId: string;
  readonly recipientEncPubHex?: string;
  /** 登録署名の署名者。API を呼ぶ主体と一致させる(§12-6 の受理条件)。 */
  readonly signerUserId: string;
}): Promise<WireWrappedDek> {
  const encPubHex = input.recipientEncPubHex ?? vectorKeyOf(input.recipientUserId).enc_pub_hex;
  const publicKey = unwrapResult(
    await importEncryptionPublicKey(hexBytes(encPubHex)),
    "importEncryptionPublicKey",
  );
  const wrapped = unwrapResult(
    await wrapDek({
      recipientPublicKey: publicKey,
      dek: input.dek,
      context: {
        projectId: input.projectId,
        environmentId: input.environmentId,
        epoch: input.epoch,
        recipientUserId: input.recipientUserId,
      },
    }),
    "wrapDek",
  );
  return signWrapAs(input.signerUserId, input.projectId, input.environmentId, {
    suite: SUITE_ID,
    epoch: input.epoch,
    recipientUserId: input.recipientUserId,
    recipientEncPubHex: encPubHex,
    encHex: encodeHex(wrapped.enc),
    ciphertextHex: encodeHex(wrapped.ciphertext),
  });
}

/**
 * 受信者クラス server のラップ(AUTH_SPEC §12-6 / CRYPTO_SPEC §9): HPKE info と
 * 登録署名の recipient 位置にサーバー鍵 FP を用いる。ラップ・署名の組み立ては
 * member と同じ経路(recipientUserId 位置の置き換えのみ)で、ワイヤに
 * recipientClass: "server" を付ける。
 */
export async function wrapDekToServer(input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly dek: Uint8Array;
  readonly serverKeyFingerprintHex: string;
  readonly serverEncPubHex: string;
  /** 登録署名の署名者。API を呼ぶ主体と一致させる(§12-6 の受理条件)。 */
  readonly signerUserId: string;
}): Promise<WireWrappedDek> {
  const wrap = await wrapDekTo({
    projectId: input.projectId,
    environmentId: input.environmentId,
    epoch: input.epoch,
    dek: input.dek,
    recipientUserId: input.serverKeyFingerprintHex,
    recipientEncPubHex: input.serverEncPubHex,
    signerUserId: input.signerUserId,
  });
  return { ...wrap, recipientClass: "server" };
}

/** DEK を複数受信者へラップする(環境作成・ローテーションの完全集合用)。 */
export async function wrapDekForAll(input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly dek: Uint8Array;
  readonly recipientUserIds: readonly string[];
  /** 登録署名の署名者。API を呼ぶ主体と一致させる(§12-6 の受理条件)。 */
  readonly signerUserId: string;
}): Promise<WireWrappedDek[]> {
  const wraps: WireWrappedDek[] = [];
  for (const recipientUserId of input.recipientUserIds) {
    wraps.push(await wrapDekTo({ ...input, recipientUserId }));
  }
  return wraps;
}

/** 値署名の宣言ヘッド(署名時点で最後に検証したチェーンヘッド — §4.1)。 */
export interface ValueChainHead {
  readonly seq: number;
  readonly hashHex: string;
}

/**
 * 署名なしワイヤ値に §4.1 の値署名を付ける(署名者 = API を呼ぶ主体と一致
 * させること — §12-5)。フェイク暗号文の受理ポリシー系テストにも使う
 * (サーバーは中身を復号できないが値署名は検証するため、フェイクにも呼び出し
 * 主体の実鍵による正しい署名が要る)。
 */
export async function signValueAs(
  writerUserId: string,
  unsigned: Omit<WireEncryptedPayload, "signatureHex">,
  head: ValueChainHead,
): Promise<WireEncryptedPayload> {
  const keys = vectorKeyOf(writerUserId);
  const pair = unwrapResult(
    await importSigningKeyPair({
      publicKey: hexBytes(keys.sig_pub_hex),
      privateSeed: hexBytes(keys.sig_sk_seed_hex),
    }),
    "importSigningKeyPair",
  );
  const withHead = {
    ...unsigned,
    chainHeadHashHex: head.hashHex,
    chainHeadSeq: head.seq,
    signatureHex: "",
  };
  const signatureHex = unwrapResult(
    await signValue({
      context: valueContextOf(withHead, writerUserId),
      signingKey: pair.privateKey,
    }),
    "signValue",
  );
  return { ...withHead, signatureHex };
}

/** 変数値を DEK で暗号化し、§4.1 の値署名付きワイヤ表現(§12-2)で返す。 */
export async function encryptValue(
  dek: Uint8Array,
  context: VariableContext,
  plaintext: string,
  signing: {
    readonly writerUserId: string;
    readonly head: ValueChainHead;
    readonly prevValueSigHashHex?: string;
  },
): Promise<WireEncryptedPayload> {
  const encrypted = unwrapResult(
    await encryptVariable({
      dek,
      context,
      plaintext: new TextEncoder().encode(plaintext),
    }),
    "encryptVariable",
  );
  return signValueAs(
    signing.writerUserId,
    {
      suite: SUITE_ID,
      aad: { ...context },
      nonceHex: encodeHex(encrypted.nonce),
      ciphertextHex: encodeHex(encrypted.ciphertext),
      prevValueSigHashHex: signing.prevValueSigHashHex ?? "",
      chainHeadHashHex: signing.head.hashHex,
      chainHeadSeq: signing.head.seq,
    },
    signing.head,
  );
}

// ---------------------------------------------------------------------------
// メタデータステートメント(CRYPTO_SPEC §4.2 / AUTH_SPEC §12-2)のテスト時署名
// ---------------------------------------------------------------------------

/** 変数ステートメントのワイヤ表現(VariableMetaStatement — §12-2)。 */
export interface WireVariableMetaStatement {
  readonly suite: string;
  readonly environmentId: string;
  readonly variableId: string;
  readonly name: string;
  readonly status: "active" | "deleted";
  readonly metaVersion: number;
  readonly prevMetaSigHashHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
}

/** 環境ステートメントのワイヤ表現(EnvironmentMetaStatement — §12-2)。 */
export type WireEnvironmentMetaStatement = Omit<WireVariableMetaStatement, "variableId">;

function metaTargetOf(statement: { readonly variableId?: string }): MetaStatementTarget {
  return statement.variableId === undefined
    ? { kind: "environment" }
    : { kind: "variable", variableId: statement.variableId };
}

function metaContextOf(
  projectId: string,
  statement: Omit<WireVariableMetaStatement, "signatureHex" | "variableId"> & {
    readonly variableId?: string;
  },
  authorUserId: string,
) {
  return {
    suite: statement.suite,
    projectId,
    environmentId: statement.environmentId,
    target: metaTargetOf(statement),
    name: statement.name,
    status: statement.status,
    metaVersion: statement.metaVersion,
    prevMetaSigHashHex: statement.prevMetaSigHashHex,
    authorUserId,
    chainHeadHashHex: statement.chainHeadHashHex,
    chainHeadSeq: statement.chainHeadSeq,
  };
}

/**
 * 署名なしステートメントに §4.2 の author 署名を付ける(署名者 = API を呼ぶ
 * 主体と一致させること — §12-5 のメタ規則)。変数(variableId あり)・環境
 * (なし)の両形を扱う。
 */
export async function signMetaStatementAs<
  T extends Omit<WireVariableMetaStatement, "signatureHex" | "variableId"> & {
    readonly variableId?: string;
  },
>(authorUserId: string, projectId: string, unsigned: T): Promise<T & { signatureHex: string }> {
  const keys = vectorKeyOf(authorUserId);
  const pair = unwrapResult(
    await importSigningKeyPair({
      publicKey: hexBytes(keys.sig_pub_hex),
      privateSeed: hexBytes(keys.sig_sk_seed_hex),
    }),
    "importSigningKeyPair",
  );
  const signatureHex = unwrapResult(
    await signMetaStatement({
      context: metaContextOf(projectId, unsigned, authorUserId),
      signingKey: pair.privateKey,
    }),
    "signMetaStatement",
  );
  return { ...unsigned, signatureHex };
}

/**
 * meta_signed_bytes の SHA-256(次 metaVersion の prevMetaSigHashHex に使う —
 * §4.2 の連鎖)。author はワイヤに載らないため明示指定する。
 */
export async function metaSignedBytesHashOf(
  projectId: string,
  statement: Omit<WireVariableMetaStatement, "variableId"> & { readonly variableId?: string },
  authorUserId: string,
): Promise<string> {
  return unwrapResult(
    await computeMetaSignedBytesHash(metaContextOf(projectId, statement, authorUserId)),
    "computeMetaSignedBytesHash",
  );
}

// ---------------------------------------------------------------------------
// 環境マニフェスト(CRYPTO_SPEC §4.3 / AUTH_SPEC §12-5 — PR-M1)
// ---------------------------------------------------------------------------

/** variables_digest の 1 エントリ(§4.3 — tombstone 込みの全変数の最新形)。 */
export interface WireDigestEntry {
  readonly variableId: string;
  readonly status: "active" | "deleted";
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
}

/** 環境マニフェストのワイヤ表現(EnvironmentManifest — §12-2)。 */
export interface WireEnvironmentManifest {
  readonly suite: typeof SUITE_ID;
  readonly environmentId: string;
  readonly epoch: number;
  readonly manifestVersion: number;
  readonly variablesDigestHex: string;
  readonly envMetaVersion: number;
  readonly envMetaSigHashHex: string;
  readonly prevManifestSigHashHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
}

/** variables_digest の正規形計算(空集合可 — §4.3)。 */
export async function digestOf(entries: readonly WireDigestEntry[]): Promise<string> {
  return unwrapResult(await computeVariablesDigest(SUITE_ID, entries), "computeVariablesDigest");
}

function manifestContextOf(
  projectId: string,
  manifest: Omit<WireEnvironmentManifest, "signatureHex">,
  issuerUserId: string,
) {
  return {
    suite: manifest.suite,
    projectId,
    environmentId: manifest.environmentId,
    epoch: manifest.epoch,
    manifestVersion: manifest.manifestVersion,
    variablesDigestHex: manifest.variablesDigestHex,
    envMetaVersion: manifest.envMetaVersion,
    envMetaSigHashHex: manifest.envMetaSigHashHex,
    prevManifestSigHashHex: manifest.prevManifestSigHashHex,
    issuerUserId,
    chainHeadHashHex: manifest.chainHeadHashHex,
    chainHeadSeq: manifest.chainHeadSeq,
  };
}

/**
 * 署名なしマニフェストに §4.3 の issuer 署名を付ける(署名者 = API を呼ぶ主体と
 * 一致させること — §12-5 (1))。
 */
export async function signEnvManifestAs(
  issuerUserId: string,
  projectId: string,
  unsigned: Omit<WireEnvironmentManifest, "signatureHex">,
): Promise<WireEnvironmentManifest> {
  const keys = vectorKeyOf(issuerUserId);
  const pair = unwrapResult(
    await importSigningKeyPair({
      publicKey: hexBytes(keys.sig_pub_hex),
      privateSeed: hexBytes(keys.sig_sk_seed_hex),
    }),
    "importSigningKeyPair",
  );
  const signatureHex = unwrapResult(
    await signEnvManifest({
      context: manifestContextOf(projectId, unsigned, issuerUserId),
      signingKey: pair.privateKey,
    }),
    "signEnvManifest",
  );
  return { ...unsigned, signatureHex };
}

/**
 * env_manifest_signed_bytes の SHA-256(次 manifestVersion の
 * prevManifestSigHashHex に使う — §4.3 の連鎖)。issuer はワイヤに載らないため
 * 明示指定する。
 */
export async function manifestSignedBytesHashOf(
  projectId: string,
  manifest: WireEnvironmentManifest,
  issuerUserId: string,
): Promise<string> {
  return unwrapResult(
    await computeEnvManifestSignedBytesHash(manifestContextOf(projectId, manifest, issuerUserId)),
    "computeEnvManifestSignedBytesHash",
  );
}

/** 変数作成に同梱するステートメント(metaVersion 1・active・prev 空)を署名して返す。 */
export async function createVariableStatement(input: {
  readonly authorUserId: string;
  readonly projectId: string;
  readonly environmentId: string;
  readonly variableId: string;
  readonly name: string;
  readonly head: ValueChainHead;
}): Promise<WireVariableMetaStatement> {
  return signMetaStatementAs(input.authorUserId, input.projectId, {
    suite: SUITE_ID,
    environmentId: input.environmentId,
    variableId: input.variableId,
    name: input.name,
    status: "active" as const,
    metaVersion: 1,
    prevMetaSigHashHex: "",
    chainHeadHashHex: input.head.hashHex,
    chainHeadSeq: input.head.seq,
  });
}

/**
 * クライアント側の受信経路の前半: 自分宛のラップ済み DEK をベクター固定鍵で
 * Open して DEK を返す(§5.2 のコミットメント照合・復号の材料)。
 */
export async function unwrapDistributedDek(input: {
  readonly recipientUserId: string;
  readonly wrapped: {
    readonly epoch: number;
    readonly encHex: string;
    readonly ciphertextHex: string;
  };
  readonly projectId: string;
  readonly environmentId: string;
}): Promise<Uint8Array> {
  const keys = vectorKeyOf(input.recipientUserId);
  const pair = unwrapResult(
    await importEncryptionKeyPair({
      publicKey: hexBytes(keys.enc_pub_hex),
      privateKey: hexBytes(keys.enc_sk_seed_hex),
    }),
    "importEncryptionKeyPair",
  );
  return unwrapResult(
    await unwrapDek({
      recipientKeyPair: pair,
      wrapped: {
        enc: hexBytes(input.wrapped.encHex),
        ciphertext: hexBytes(input.wrapped.ciphertextHex),
      },
      context: {
        projectId: input.projectId,
        environmentId: input.environmentId,
        epoch: input.wrapped.epoch,
        recipientUserId: input.recipientUserId,
      },
    }),
    "unwrapDek",
  );
}

/**
 * クライアント側の受信経路: 自分宛のラップ済み DEK を Open し、その DEK で
 * EncryptedPayload を復号する(push→pull→復号のラウンドトリップ検証)。
 */
export async function unwrapAndDecrypt(input: {
  readonly recipientUserId: string;
  readonly wrapped: {
    readonly epoch: number;
    readonly encHex: string;
    readonly ciphertextHex: string;
  };
  readonly projectId: string;
  readonly environmentId: string;
  readonly payload: WireEncryptedPayload;
}): Promise<string> {
  const dek = await unwrapDistributedDek(input);
  const plaintext = unwrapResult(
    await decryptVariable({
      dek,
      context: input.payload.aad,
      nonce: hexBytes(input.payload.nonceHex),
      ciphertext: hexBytes(input.payload.ciphertextHex),
    }),
    "decryptVariable",
  );
  return new TextDecoder().decode(plaintext);
}
