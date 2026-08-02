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
  decodeHex,
  decryptVariable,
  encodeHex,
  encryptVariable,
  generateDek,
  importEncryptionKeyPair,
  importEncryptionPublicKey,
  importSigningKeyPair,
  signChainEntry,
  SUITE_ID,
  unwrapDek,
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
}

/** DEK を 1 受信者へ HPKE ラップし、ワイヤ表現(§12-2)で返す。 */
export async function wrapDekTo(input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly dek: Uint8Array;
  readonly recipientUserId: string;
  readonly recipientEncPubHex?: string;
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
  return {
    suite: SUITE_ID,
    epoch: input.epoch,
    recipientUserId: input.recipientUserId,
    recipientEncPubHex: encPubHex,
    encHex: encodeHex(wrapped.enc),
    ciphertextHex: encodeHex(wrapped.ciphertext),
  };
}

/** DEK を複数受信者へラップする(環境作成・ローテーションの完全集合用)。 */
export async function wrapDekForAll(input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly dek: Uint8Array;
  readonly recipientUserIds: readonly string[];
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
}

/** 変数値を DEK で暗号化し、ワイヤ表現(§12-2)で返す。 */
export async function encryptValue(
  dek: Uint8Array,
  context: VariableContext,
  plaintext: string,
): Promise<WireEncryptedPayload> {
  const encrypted = unwrapResult(
    await encryptVariable({
      dek,
      context,
      plaintext: new TextEncoder().encode(plaintext),
    }),
    "encryptVariable",
  );
  return {
    suite: SUITE_ID,
    aad: { ...context },
    nonceHex: encodeHex(encrypted.nonce),
    ciphertextHex: encodeHex(encrypted.ciphertext),
  };
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
