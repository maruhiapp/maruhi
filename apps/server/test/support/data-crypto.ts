// データプレーン統合テスト用の実 crypto ヘルパ(workerd 内で実行)。
//
// packages/crypto の公開 API だけで実データを作る: テストベクターの固定鍵
// (chain-entries.json の keys)でチェーンエントリをテスト時に署名し、
// DEK 生成 → HPKE ラップ → AES-GCM 暗号化 → クライアント側復号までを実行する。
// フェイクの暗号文を使うのは「サーバーが中身を検証できない」ことを利用する
// 受理ポリシー系テストのみ(各テストに明記)。

import type {
  ChainEntry,
  ChainOperation,
  CryptoResult,
  UnsignedChainEntry,
  VariableContext,
} from "@maruhi/crypto";
import {
  computeChainEntryHash,
  computeDekCommitment,
  computeValueSignedBytesHash,
  decodeHex,
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
  signValue,
  SUITE_ID,
  unwrapDek,
  verifyDekWrapSignature,
  wrapDek,
} from "@maruhi/crypto";

import { vectorKeys } from "../../../../packages/crypto/test/checks/chain-vector.ts";

const BASE_TIME_MS = 1754006400000;

function unwrapResult<T>(result: CryptoResult<T>, label: string): T {
  if (!result.ok) {
    throw new Error(`${label}: ${JSON.stringify(result.error)}`);
  }
  return result.value;
}

/** テスト内の hex は常に整形済み(decodeHex の null は組み立てバグ = throw)。 */
export function hexBytes(hex: string): Uint8Array {
  const bytes = decodeHex(hex);
  if (bytes === null) {
    throw new Error(`invalid hex in test data: ${hex.slice(0, 16)}…`);
  }
  return bytes;
}

/** ベクター固定鍵のユーザー(user-owner-0001 / user-member-0002 / user-admin-0003)。 */
export function vectorKeyOf(userId: string) {
  const keys = vectorKeys[userId];
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

export interface BuiltChain {
  readonly entries: readonly ChainEntry[];
  /** entries[i] のエントリハッシュ(CAS の親ヘッドに使う)。 */
  readonly hashes: readonly string[];
  /** プロジェクト ID = genesis エントリハッシュ(CRYPTO_SPEC §6.4)。 */
  readonly projectId: string;
}

/** テスト時署名で有効なチェーンを組み立てる(seq / prev_hash / timestamp は自動)。 */
export async function buildChain(steps: readonly ChainStep[]): Promise<BuiltChain> {
  const entries: ChainEntry[] = [];
  const hashes: string[] = [];
  let prevHashHex = "0".repeat(64);
  for (const [index, step] of steps.entries()) {
    const keys = vectorKeyOf(step.actorUserId);
    const unsigned: UnsignedChainEntry = {
      ...step.operation,
      suite: SUITE_ID,
      seq: index + 1,
      prevHashHex,
      actor: { userId: step.actorUserId, keyFingerprintHex: keys.key_fingerprint_hex },
      timestampMs: BASE_TIME_MS + index * 1000,
    };
    const entry = await signAs(step.actorUserId, unsigned);
    const hash = await computeChainEntryHash(entry);
    entries.push(entry);
    hashes.push(hash);
    prevHashHex = hash;
  }
  const projectId = hashes[0];
  if (projectId === undefined) {
    throw new Error("buildChain: empty chain");
  }
  return { entries, hashes, projectId };
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

export interface WireEncryptedPayload {
  readonly suite: string;
  readonly aad: {
    readonly projectId: string;
    readonly environmentId: string;
    readonly epoch: number;
    readonly variableId: string;
    readonly version: number;
  };
  readonly nonceHex: string;
  readonly ciphertextHex: string;
  // 値の書き込み署名ブロック(CRYPTO_SPEC §4.1 / AUTH_SPEC §12-2)
  readonly prevValueSigHashHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
}

/** 値署名の宣言ヘッド(署名時点で最後に検証したチェーンヘッド — §4.1)。 */
export interface ValueChainHead {
  readonly seq: number;
  readonly hashHex: string;
}

/** WireEncryptedPayload から §4.1 の署名コンテキストを再構成する。 */
function valueContextOf(payload: WireEncryptedPayload, writerUserId: string) {
  return {
    suite: payload.suite,
    projectId: payload.aad.projectId,
    environmentId: payload.aad.environmentId,
    epoch: payload.aad.epoch,
    variableId: payload.aad.variableId,
    version: payload.aad.version,
    nonceHex: payload.nonceHex,
    ciphertextHex: payload.ciphertextHex,
    prevValueSigHashHex: payload.prevValueSigHashHex,
    writerUserId,
    chainHeadHashHex: payload.chainHeadHashHex,
    chainHeadSeq: payload.chainHeadSeq,
  };
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

/**
 * value_signed_bytes の SHA-256(次 version の prevValueSigHashHex に使う —
 * §4.1 の連鎖)。writer はワイヤに載らないため明示指定する。
 */
export async function valueSignedBytesHashOf(
  payload: WireEncryptedPayload,
  writerUserId: string,
): Promise<string> {
  return unwrapResult(
    await computeValueSignedBytesHash(valueContextOf(payload, writerUserId)),
    "computeValueSignedBytesHash",
  );
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
  const keys = vectorKeyOf(input.recipientUserId);
  const pair = unwrapResult(
    await importEncryptionKeyPair({
      publicKey: hexBytes(keys.enc_pub_hex),
      privateKey: hexBytes(keys.enc_sk_seed_hex),
    }),
    "importEncryptionKeyPair",
  );
  const dek = unwrapResult(
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
