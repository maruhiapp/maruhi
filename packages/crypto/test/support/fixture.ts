// cli / server のテスト支援(apps/cli/test/support/crypto.ts /
// apps/server/test/support/data-crypto.ts)が共有する実 crypto フィクスチャの
// 共通コア(session-11 §5 裁定の共有抽出先)。@maruhi/crypto の公開 API のみを
// 使う。鍵の出所は両側で異なる(cli = 都度生成 / server = ベクター固定鍵)ため、
// チェーン署名の手段は呼び出し側が signEntry 関数として注入する。

import type {
  ChainEntry,
  ChainOperation,
  CryptoResult,
  UnsignedChainEntry,
  ValueSignatureContext,
} from "../../src/index.ts";
import {
  computeChainEntryHash,
  computeValueSignedBytesHash,
  decodeHex,
  SUITE_ID,
} from "../../src/index.ts";

/** フィクスチャの決定的タイムスタンプ基点(2026-08-01T00:00:00Z)。 */
export const BASE_TIME_MS = 1754006400000;

/** CryptoResult を素の値へ展開する(失敗 = テストデータの組み立てバグ = throw)。 */
export function unwrapResult<T>(result: CryptoResult<T>, label: string): T {
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

/**
 * プロジェクト ID(= genesis ハッシュ)に依存する op の遅延構築。§5.2 の
 * コミットメント原像は project_id を含むため、create_environment / rotate_epoch
 * の payload は genesis を組んだ後でしか確定できない。
 */
export type LazyChainOperation = (projectId: string) => ChainOperation | Promise<ChainOperation>;

/** buildChainWith の 1 ステップ(actor の同定と署名手段は呼び出し側が与える)。 */
export interface ChainBuildStep {
  readonly actor: { readonly userId: string; readonly keyFingerprintHex: string };
  readonly operation: ChainOperation | LazyChainOperation;
  readonly signEntry: (unsigned: UnsignedChainEntry) => Promise<ChainEntry>;
}

export interface BuiltChain {
  readonly entries: readonly ChainEntry[];
  /** entries[i] のエントリハッシュ(CAS の親ヘッドに使う)。 */
  readonly hashes: readonly string[];
  /** プロジェクト ID = genesis エントリハッシュ(CRYPTO_SPEC §6.4)。 */
  readonly projectId: string;
}

/** 有効な署名済みチェーンを組み立てる(seq / prev_hash / timestamp は自動)。 */
export async function buildChainWith(steps: readonly ChainBuildStep[]): Promise<BuiltChain> {
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
      actor: step.actor,
      timestampMs: BASE_TIME_MS + index * 1000,
    };
    const entry = await step.signEntry(unsigned);
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

/** EncryptedPayload 形のワイヤ表現(§4.1 の署名ブロック込み — AUTH_SPEC §12-2)。 */
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

/** WireEncryptedPayload から §4.1 の署名コンテキストを再構成する。 */
export function valueContextOf(
  payload: WireEncryptedPayload,
  writerUserId: string,
): ValueSignatureContext {
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
 * value_signed_bytes の SHA-256(次 version の prev_value_sig_hash_hex に使う —
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
