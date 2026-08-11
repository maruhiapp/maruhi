// テスト用の実 crypto フィクスチャ(@maruhi/crypto の公開 API のみ)。
// 都度生成した鍵でチェーン署名・DEK ラップ・値暗号化まで実データを作る。
// チェーン組立・ワイヤ値の共通コアは @maruhi/crypto/test-support
// (server テスト支援と共有 — session-11 §5 裁定)。

import type { ChainOperation, EncryptionKeyPair, SigningKeyPair } from "@maruhi/crypto";
import {
  computeDekCommitment,
  computeUserKeyFingerprint,
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
  signMetaStatement,
  signValue,
  SUITE_ID,
  wrapDek,
} from "@maruhi/crypto";
import type {
  BuiltChain,
  LazyChainOperation,
  WireEncryptedPayload as SharedWireEncryptedPayload,
} from "@maruhi/crypto/test-support";
import { buildChainWith, hexBytes, unwrapResult } from "@maruhi/crypto/test-support";

export type { BuiltChain, LazyChainOperation };
export { hexBytes, valueSignedBytesHashOf as valueHashOf } from "@maruhi/crypto/test-support";

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

export interface ChainStep {
  readonly actor: TestUser;
  readonly operation: ChainOperation | LazyChainOperation;
}

/** Builds a valid signed chain (seq / prev_hash / timestamp are automatic). */
export async function buildChain(steps: readonly ChainStep[]): Promise<BuiltChain> {
  return buildChainWith(
    steps.map((step) => ({
      actor: { userId: step.actor.userId, keyFingerprintHex: step.actor.fingerprintHex },
      operation: step.operation,
      signEntry: async (unsigned) =>
        unwrapResult(
          await signChainEntry({ entry: unsigned, signingKey: step.actor.sigKeyPair.privateKey }),
          "signChainEntry",
        ),
    })),
  );
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
async function dekCommitmentFor(
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

/** EncryptedPayload 形のワイヤ表現(§4.1 の署名ブロック込み — §12-2)。 */
export interface WireEncryptedPayload extends SharedWireEncryptedPayload {
  /** CLI テストは常に正規スイートのワイヤを作る(共有形は string — 検証系 negative 用)。 */
  readonly suite: "maruhi/v1";
}

/** 配布形(DistributedEncryptedPayload — writer の検証材料込み)。 */
export interface WireDistributedValue extends WireEncryptedPayload {
  readonly writerUserId: string;
  readonly writerKeyFingerprintHex: string;
}

/** 配布形の変数メタステートメント(DistributedVariableMetaStatement — §12-2)。 */
export interface WireDistributedVariableStatement {
  readonly suite: "maruhi/v1";
  readonly environmentId: string;
  readonly variableId: string;
  readonly name: string;
  readonly status: "active" | "deleted";
  readonly metaVersion: number;
  readonly prevMetaSigHashHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
  readonly authorUserId: string;
  readonly authorKeyFingerprintHex: string;
}

/** 配布形の環境メタステートメント(variableId を持たない同型)。 */
export type WireDistributedEnvironmentStatement = Omit<
  WireDistributedVariableStatement,
  "variableId"
>;

interface StatementInputBase {
  readonly projectId: string;
  readonly environmentId: string;
  readonly name: string;
  readonly author: TestUser;
  readonly head: { readonly seq: number; readonly hashHex: string };
  readonly status?: "active" | "deleted";
  readonly metaVersion?: number;
  readonly prevMetaSigHashHex?: string;
}

async function signDistributedStatement(
  input: StatementInputBase,
  target: { kind: "variable"; variableId: string } | { kind: "environment" },
): Promise<WireDistributedEnvironmentStatement> {
  const status = input.status ?? "active";
  const metaVersion = input.metaVersion ?? 1;
  const prevMetaSigHashHex = input.prevMetaSigHashHex ?? (metaVersion === 1 ? "" : "cd".repeat(32));
  const signatureHex = unwrapResult(
    await signMetaStatement({
      context: {
        suite: SUITE_ID,
        projectId: input.projectId,
        environmentId: input.environmentId,
        target,
        name: input.name,
        status,
        metaVersion,
        prevMetaSigHashHex,
        authorUserId: input.author.userId,
        chainHeadHashHex: input.head.hashHex,
        chainHeadSeq: input.head.seq,
      },
      signingKey: input.author.sigKeyPair.privateKey,
    }),
    "signMetaStatement",
  );
  return {
    suite: SUITE_ID,
    environmentId: input.environmentId,
    name: input.name,
    status,
    metaVersion,
    prevMetaSigHashHex,
    chainHeadHashHex: input.head.hashHex,
    chainHeadSeq: input.head.seq,
    signatureHex,
    authorUserId: input.author.userId,
    authorKeyFingerprintHex: input.author.fingerprintHex,
  };
}

/**
 * 変数メタステートメント(§4.2)を author 署名し、配布形(author 情報込み —
 * §12-2)で返す。既定は作成形(metaVersion 1・active・prev 空)。
 */
export async function statementFor(
  input: StatementInputBase & { readonly variableId: string },
): Promise<WireDistributedVariableStatement> {
  const statement = await signDistributedStatement(input, {
    kind: "variable",
    variableId: input.variableId,
  });
  return { ...statement, variableId: input.variableId };
}

/** 環境メタステートメントの配布形(variableId フィールドを持たない同型)。 */
export async function environmentStatementFor(
  input: StatementInputBase,
): Promise<WireDistributedEnvironmentStatement> {
  return signDistributedStatement(input, { kind: "environment" });
}

/** BuiltChain 上の宣言ヘッド(seq 位置の entry hash)。 */
export function headOf(built: BuiltChain, seq: number): { seq: number; hashHex: string } {
  const hashHex = built.hashes[seq - 1];
  if (hashHex === undefined) {
    throw new Error(`headOf: chain has no seq ${seq}`);
  }
  return { seq, hashHex };
}

/**
 * 変数値を DEK で暗号化し、writer の値署名(§4.1)付き配布形(§12-2)で返す。
 * 宣言ヘッドは writer が「署名時点で最後に検証したチェーンヘッド」の位置。
 * version > 1 の prev はテスト側で指定する(既定はダミー 64 hex — pull は
 * latest-only で prev の実在一致は検査対象外 — 裁定 B)。
 */
export async function encryptValueFor(input: {
  readonly dek: Uint8Array;
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly variableId: string;
  readonly version: number;
  /** 平文(文字列は UTF-8 エンコード。不正 UTF-8 バイト列のテスト用に bytes も可)。 */
  readonly plaintext: string | Uint8Array;
  readonly writer: TestUser;
  readonly head: { readonly seq: number; readonly hashHex: string };
  readonly prevValueSigHashHex?: string;
}): Promise<WireDistributedValue> {
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
      plaintext:
        typeof input.plaintext === "string"
          ? new TextEncoder().encode(input.plaintext)
          : input.plaintext,
    }),
    "encryptVariable",
  );
  const nonceHex = encodeHex(encrypted.nonce);
  const ciphertextHex = encodeHex(encrypted.ciphertext);
  const prevValueSigHashHex =
    input.prevValueSigHashHex ?? (input.version === 1 ? "" : "cd".repeat(32));
  const signatureHex = unwrapResult(
    await signValue({
      context: {
        suite: SUITE_ID,
        ...context,
        nonceHex,
        ciphertextHex,
        prevValueSigHashHex,
        writerUserId: input.writer.userId,
        chainHeadHashHex: input.head.hashHex,
        chainHeadSeq: input.head.seq,
      },
      signingKey: input.writer.sigKeyPair.privateKey,
    }),
    "signValue",
  );
  return {
    suite: SUITE_ID,
    aad: context,
    nonceHex,
    ciphertextHex,
    prevValueSigHashHex,
    chainHeadHashHex: input.head.hashHex,
    chainHeadSeq: input.head.seq,
    signatureHex,
    writerUserId: input.writer.userId,
    writerKeyFingerprintHex: input.writer.fingerprintHex,
  };
}
