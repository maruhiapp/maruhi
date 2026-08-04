// テスト用の実 crypto フィクスチャ(@maruhi/crypto の公開 API のみ)。
// 都度生成した鍵でチェーン署名・DEK ラップ・値暗号化まで実データを作る。

import type {
  ChainEntry,
  ChainOperation,
  CryptoResult,
  EncryptionKeyPair,
  SigningKeyPair,
  UnsignedChainEntry,
} from "@maruhi/crypto";
import {
  computeChainEntryHash,
  computeDekCommitment,
  computeUserKeyFingerprint,
  decodeHex,
  encodeHex,
  encryptVariable,
  exportEncryptionPrivateKey,
  exportEncryptionPublicKey,
  exportSigningPrivateSeed,
  exportSigningPublicKey,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  importEncryptionPublicKey,
  signChainEntry,
  signDekWrap,
  SUITE_ID,
  wrapDek,
} from "@maruhi/crypto";

const BASE_TIME_MS = 1754006400000;

function unwrapResult<T>(result: CryptoResult<T>, label: string): T {
  if (!result.ok) {
    throw new Error(`${label}: ${JSON.stringify(result.error)}`);
  }
  return result.value;
}

export function hexBytes(hex: string): Uint8Array {
  const bytes = decodeHex(hex);
  if (bytes === null) {
    throw new Error(`invalid hex in test data: ${hex.slice(0, 16)}…`);
  }
  return bytes;
}

/** A test user with freshly generated (exportable) master keys. */
export interface TestUser {
  readonly userId: string;
  readonly encPubHex: string;
  readonly encSkHex: string;
  readonly sigPubHex: string;
  readonly sigSkSeedHex: string;
  readonly fingerprintHex: string;
  readonly encKeyPair: EncryptionKeyPair;
  readonly sigKeyPair: SigningKeyPair;
}

export async function makeTestUser(userId: string): Promise<TestUser> {
  const encKeyPair = await generateEncryptionKeyPair({ extractable: true });
  const sigKeyPair = await generateSigningKeyPair({ extractable: true });
  const encPub = await exportEncryptionPublicKey(encKeyPair.publicKey);
  const sigPub = await exportSigningPublicKey(sigKeyPair.publicKey);
  const encSk = unwrapResult(await exportEncryptionPrivateKey(encKeyPair.privateKey), "exportEnc");
  const sigSeed = unwrapResult(await exportSigningPrivateSeed(sigKeyPair.privateKey), "exportSig");
  const fingerprint = unwrapResult(await computeUserKeyFingerprint(encPub, sigPub), "fingerprint");
  return {
    userId,
    encPubHex: encodeHex(encPub),
    encSkHex: encodeHex(encSk),
    sigPubHex: encodeHex(sigPub),
    sigSkSeedHex: encodeHex(sigSeed),
    fingerprintHex: encodeHex(fingerprint),
    encKeyPair,
    sigKeyPair,
  };
}

/**
 * プロジェクト ID(= genesis ハッシュ)に依存する op の遅延構築。§5.2 の
 * コミットメント原像は project_id を含むため、create_environment / rotate_epoch
 * の payload は genesis を組んだ後でしか確定できない。
 */
export type LazyChainOperation = (
  projectId: string,
) => ChainOperation | Promise<ChainOperation>;

export interface ChainStep {
  readonly actor: TestUser;
  readonly operation: ChainOperation | LazyChainOperation;
}

export interface BuiltChain {
  readonly entries: readonly ChainEntry[];
  readonly hashes: readonly string[];
  /** プロジェクト ID = genesis エントリハッシュ(CRYPTO_SPEC §6.4)。 */
  readonly projectId: string;
}

/** Builds a valid signed chain (seq / prev_hash / timestamp are automatic). */
export async function buildChain(steps: readonly ChainStep[]): Promise<BuiltChain> {
  const entries: ChainEntry[] = [];
  const hashes: string[] = [];
  let prevHashHex = "0".repeat(64);
  for (const [index, step] of steps.entries()) {
    const projectId = hashes[0];
    if (typeof step.operation === "function" && projectId === undefined) {
      throw new Error("buildChain: genesis step cannot depend on the project id");
    }
    const operation =
      typeof step.operation === "function" ? await step.operation(projectId ?? "") : step.operation;
    const unsigned: UnsignedChainEntry = {
      ...operation,
      suite: SUITE_ID,
      seq: index + 1,
      prevHashHex,
      actor: { userId: step.actor.userId, keyFingerprintHex: step.actor.fingerprintHex },
      timestampMs: BASE_TIME_MS + index * 1000,
    };
    const entry = unwrapResult(
      await signChainEntry({ entry: unsigned, signingKey: step.actor.sigKeyPair.privateKey }),
      "signChainEntry",
    );
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

export function genesisOp(user: TestUser): ChainOperation {
  return { op: "genesis", payload: { encPubHex: user.encPubHex, sigPubHex: user.sigPubHex } };
}

export function addMemberOp(
  target: TestUser,
  role: "owner" | "admin" | "member" | "reader",
): ChainOperation {
  return {
    op: "add_member",
    payload: {
      targetUserId: target.userId,
      encPubHex: target.encPubHex,
      sigPubHex: target.sigPubHex,
      role,
    },
  };
}

export function removeMemberOp(target: TestUser): ChainOperation {
  return { op: "remove_member", payload: { targetUserId: target.userId } };
}

/** §5.2 のコミットメント(hex 小文字 64 文字)。 */
export async function dekCommitmentFor(
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

/**
 * create_environment(エポック 1 のコミットメント込み — §6.2)。フィクスチャの
 * 実 DEK からコミットメントを計算するため、pull 側の §5.2 照合まで実データで通る。
 */
export function createEnvironmentOp(environmentId: string, dek: Uint8Array): LazyChainOperation {
  return async (projectId) => ({
    op: "create_environment",
    payload: {
      environmentId,
      dekCommitmentHex: await dekCommitmentFor(projectId, environmentId, 1, dek),
    },
  });
}

/** rotate_epoch(新エポックのコミットメント込み — §6.2)。 */
export function rotateEpochOp(
  environmentId: string,
  newEpoch: number,
  dek: Uint8Array,
): LazyChainOperation {
  return async (projectId) => ({
    op: "rotate_epoch",
    payload: {
      environmentId,
      newEpoch,
      reason: "test",
      dekCommitmentHex: await dekCommitmentFor(projectId, environmentId, newEpoch, dek),
    },
  });
}

/** grant_server(サーバー鍵はランダム生成。FP = SHA-256(enc)[:16] — §9)。 */
export async function grantServerOp(
  scopeEnvironmentIds: readonly string[],
): Promise<ChainOperation> {
  const serverPair = await generateEncryptionKeyPair({ extractable: true });
  const serverEncPub = await exportEncryptionPublicKey(serverPair.publicKey);
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", serverEncPub as BufferSource),
  );
  return {
    op: "grant_server",
    payload: {
      serverEncPubHex: encodeHex(serverEncPub),
      serverKeyFingerprintHex: encodeHex(digest.slice(0, 16)),
      scopeEnvironmentIds: [...scopeEnvironmentIds],
    },
  };
}

/** RecipientDek 形(配布応答)のワイヤ表現。 */
export interface WireRecipientDek {
  readonly suite: "maruhi/v1";
  readonly epoch: number;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly signatureHex: string;
  readonly signerUserId: string;
  readonly signerKeyFingerprintHex: string;
}

/** DEK を受信者へ HPKE ラップし、署名者の登録署名付き配布形(§12-2)で返す。 */
export async function wrapDekFor(input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly dek: Uint8Array;
  readonly recipient: TestUser;
  readonly signer: TestUser;
}): Promise<WireRecipientDek> {
  const publicKey = unwrapResult(
    await importEncryptionPublicKey(hexBytes(input.recipient.encPubHex)),
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
        recipientUserId: input.recipient.userId,
      },
    }),
    "wrapDek",
  );
  const encHex = encodeHex(wrapped.enc);
  const ciphertextHex = encodeHex(wrapped.ciphertext);
  const signatureHex = unwrapResult(
    await signDekWrap({
      context: {
        suite: SUITE_ID,
        projectId: input.projectId,
        environmentId: input.environmentId,
        epoch: input.epoch,
        recipientUserId: input.recipient.userId,
        recipientEncPubHex: input.recipient.encPubHex,
        encHex,
        ciphertextHex,
        signerUserId: input.signer.userId,
      },
      signingKey: input.signer.sigKeyPair.privateKey,
    }),
    "signDekWrap",
  );
  return {
    suite: SUITE_ID,
    epoch: input.epoch,
    encHex,
    ciphertextHex,
    signatureHex,
    signerUserId: input.signer.userId,
    signerKeyFingerprintHex: input.signer.fingerprintHex,
  };
}

/** EncryptedPayload 形のワイヤ表現。 */
export interface WireEncryptedPayload {
  readonly suite: "maruhi/v1";
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
export async function encryptValueFor(input: {
  readonly dek: Uint8Array;
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly variableId: string;
  readonly version: number;
  readonly plaintext: string;
}): Promise<WireEncryptedPayload> {
  const context = {
    projectId: input.projectId,
    environmentId: input.environmentId,
    epoch: input.epoch,
    variableId: input.variableId,
    version: input.version,
  };
  const encrypted = unwrapResult(
    await encryptVariable({
      dek: input.dek,
      context,
      plaintext: new TextEncoder().encode(input.plaintext),
    }),
    "encryptVariable",
  );
  return {
    suite: SUITE_ID,
    aad: context,
    nonceHex: encodeHex(encrypted.nonce),
    ciphertextHex: encodeHex(encrypted.ciphertext),
  };
}
