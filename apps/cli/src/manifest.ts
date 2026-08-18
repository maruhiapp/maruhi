// 環境マニフェスト(CRYPTO_SPEC §4.3 / AUTH_SPEC §12-5)の発行・検証の CLI 共有実装。
//
// 発行(env create / rotate / push の変数作成): meta-statement.ts と同じ規律で
// 「署名した context」からワイヤを機械的に導出する(独立リテラルの再列挙は
// 1 フィールドの食い違いが静かな検証失敗になるため作らない)。
// 検証(pull 両モード・リース応答): 検証済みステートメント集合(tombstone
// 込み)からのダイジェスト再計算・エポック整合・署名 / 認可時点は
// @maruhi/crypto の verifyDistributedEnvManifest(サーバーと共有の唯一の実装 —
// §4.3)へ委譲する。
//
// **マニフェスト欠落 = 一律拒否**(§6.3 — 「未初期化なら警告」の分岐は攻撃者が
// 選べる緩和経路になるため置かない)。唯一の例外は移行経路(session-27 §14
// PR-M1): マニフェスト導入前に作成された環境の manifest_version 1 初期化は
// `maruhi env rotate --init-manifest` の明示操作でのみ、**欠落の許容**(検証の
// 緩和ではない — マニフェストが配布された場合は通常どおり全検証する)を許す。

import type { DistributedEnvironmentManifest, EnvironmentManifest } from "@maruhi/api-schema";
import type { EnvManifestContext, VariablesDigestEntry } from "@maruhi/crypto";
import {
  computeEnvManifestSignedBytesHash,
  computeVariablesDigest,
  signEnvManifest,
  SUITE_ID,
  verifyDistributedEnvManifest,
} from "@maruhi/crypto";
import { Effect } from "effect";

import { cliError, type CliError } from "./errors.ts";
import type { VerifiedProject } from "./sync.ts";

/**
 * 検証済みマニフェストの証拠材料(§14.2-5 の自己完結性 — 床のマニフェスト
 * 拡張・次 manifestVersion の prev・equivocation 証拠の比較対象)。
 */
export interface VerifiedManifest {
  readonly manifestVersion: number;
  /** 発行時点の現エポック(§4.3 の鮮度アンカー — 床規則 (c) のマニフェスト適用の材料)。 */
  readonly epoch: number;
  readonly variablesDigestHex: string;
  readonly envMetaVersion: number;
  readonly envMetaSigHashHex: string;
  readonly prevManifestSigHashHex: string;
  /** 自計算の signed bytes ハッシュ(床規則 (b) の比較対象・次 prev の根拠)。 */
  readonly signedBytesHashHex: string;
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
  readonly signatureHex: string;
  readonly issuerUserId: string;
  readonly issuerKeyFingerprintHex: string;
}

/** variables_digest の入力(検証済みステートメントの最新形 — tombstone 込み §4.3)。 */
export type ManifestDigestEntry = VariablesDigestEntry;

/** 発行の入力: 直前マニフェスト(なし = 移行経路の v1 初期化)と発行後のメタ状態。 */
export interface SignManifestInput {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  /** 発行時点の現エポック(rotate 複合 = new_epoch、それ以外 = 検証済みビューの現エポック)。 */
  readonly epoch: number;
  /** 検証済みの直前マニフェスト(null = 保存済みマニフェストなし → manifestVersion 1)。 */
  readonly previous: {
    readonly manifestVersion: number;
    readonly signedBytesHashHex: string;
  } | null;
  /** 発行後のメタ状態の全変数エントリ(tombstone 込み — §4.3 (3) の再計算対象)。 */
  readonly entries: readonly ManifestDigestEntry[];
  /** 発行後の環境メタステートメントの最新形。 */
  readonly envMeta: { readonly metaVersion: number; readonly sigHashHex: string };
  readonly issuerUserId: string;
  readonly signingKey: CryptoKey;
  /**
   * 宣言ヘッド。複合(env create / rotate)= 追記前の現ヘッド(§12-4)、
   * メタ操作 = 最後に検証したチェーンヘッド。CAS リトライで検証ビューが進めば
   * 呼び出し側が作り直す(試行ごとに署名する — meta-statement.ts と同じ規約)。
   */
  readonly chainHead: { readonly seq: number; readonly hashHex: string };
}

export interface SignedManifest {
  readonly manifest: EnvironmentManifest;
  /** 受理されたらローカル床のマニフェスト記録になる自計算ハッシュ(§6.3)。 */
  readonly manifestSigHashHex: string;
  /** 署名済みの manifestVersion / epoch(床記録・表示用)。 */
  readonly manifestVersion: number;
  readonly epoch: number;
}

/**
 * Issues the next environment manifest (CRYPTO_SPEC §4.3): computes the
 * canonical variables digest from the post-operation statement set, signs the
 * context, and derives the wire manifest mechanically from that very context
 * so the signed bytes and the wire can never drift apart.
 */
export function signNextManifest(
  input: SignManifestInput,
): Effect.Effect<SignedManifest, CliError> {
  return Effect.gen(function* () {
    const digest = yield* Effect.tryPromise({
      try: () => computeVariablesDigest(SUITE_ID, input.entries),
      catch: () => cliError("Failed to compute the manifest variables digest"),
    });
    if (!digest.ok) {
      return yield* Effect.fail(cliError("Failed to compute the manifest variables digest"));
    }
    const context: EnvManifestContext = {
      suite: SUITE_ID,
      projectId: input.verified.projectId,
      environmentId: input.environmentId,
      epoch: input.epoch,
      manifestVersion: (input.previous?.manifestVersion ?? 0) + 1,
      variablesDigestHex: digest.value,
      envMetaVersion: input.envMeta.metaVersion,
      envMetaSigHashHex: input.envMeta.sigHashHex,
      prevManifestSigHashHex: input.previous?.signedBytesHashHex ?? "",
      issuerUserId: input.issuerUserId,
      chainHeadHashHex: input.chainHead.hashHex,
      chainHeadSeq: input.chainHead.seq,
    };
    const signature = yield* Effect.tryPromise({
      try: () => signEnvManifest({ context, signingKey: input.signingKey }),
      catch: () => cliError("Failed to sign the environment manifest"),
    });
    if (!signature.ok) {
      return yield* Effect.fail(cliError("Failed to sign the environment manifest"));
    }
    const hash = yield* Effect.tryPromise({
      try: () => computeEnvManifestSignedBytesHash(context),
      catch: () => cliError("Failed to compute the manifest signed-bytes hash"),
    });
    if (!hash.ok) {
      return yield* Effect.fail(cliError("Failed to compute the manifest signed-bytes hash"));
    }
    return {
      // ワイヤはすべて署名済み context から導出する(このモジュールの存在理由。
      // suite は Literal — context には SUITE_ID を入れて構築している)
      manifest: {
        suite: SUITE_ID,
        environmentId: context.environmentId,
        epoch: context.epoch,
        manifestVersion: context.manifestVersion,
        variablesDigestHex: context.variablesDigestHex,
        envMetaVersion: context.envMetaVersion,
        envMetaSigHashHex: context.envMetaSigHashHex,
        prevManifestSigHashHex: context.prevManifestSigHashHex,
        chainHeadHashHex: context.chainHeadHashHex,
        chainHeadSeq: context.chainHeadSeq,
        signatureHex: signature.value,
      },
      manifestSigHashHex: hash.value,
      manifestVersion: context.manifestVersion,
      epoch: context.epoch,
    };
  });
}

/** 配布マニフェストの検証結果(future = 有界再同期の入口 — values.ts の共通規約)。 */
export type ManifestVerifyOutcome =
  | { readonly kind: "ok"; readonly value: VerifiedManifest }
  | { readonly kind: "future" }
  | { readonly kind: "rejected"; readonly message: string };

/**
 * Verifies one distributed environment manifest against the verified chain
 * history and the **verified** statement set (CRYPTO_SPEC §4.3 / §6.3):
 * signature / head binding / head-time authorization, epoch integrity
 * (composite issuance included), env-meta binding and the digest
 * recomputation — all through the single shared implementation in
 * @maruhi/crypto. Coordinates are rebuilt from expected values, never from
 * wire claims (§6.3-5).
 */
export async function verifyDistributedManifest(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly manifest: DistributedEnvironmentManifest;
  readonly entries: readonly ManifestDigestEntry[];
  readonly envMeta: { readonly metaVersion: number; readonly sigHashHex: string };
}): Promise<ManifestVerifyOutcome> {
  const manifest = input.manifest;
  if (manifest.environmentId !== input.environmentId) {
    return {
      kind: "rejected",
      message: `The environment manifest's coordinates do not match the requested environment ${input.environmentId} (possible transplantation)`,
    };
  }
  const result = await verifyDistributedEnvManifest({
    history: input.verified.history,
    context: {
      suite: manifest.suite,
      projectId: input.verified.projectId,
      environmentId: input.environmentId,
      epoch: manifest.epoch,
      manifestVersion: manifest.manifestVersion,
      variablesDigestHex: manifest.variablesDigestHex,
      envMetaVersion: manifest.envMetaVersion,
      envMetaSigHashHex: manifest.envMetaSigHashHex,
      prevManifestSigHashHex: manifest.prevManifestSigHashHex,
      issuerUserId: manifest.issuerUserId,
      chainHeadHashHex: manifest.chainHeadHashHex,
      chainHeadSeq: manifest.chainHeadSeq,
    },
    issuerKeyFingerprintHex: manifest.issuerKeyFingerprintHex,
    signatureHex: manifest.signatureHex,
    entries: input.entries,
    envMeta: { metaVersion: input.envMeta.metaVersion, sigHashHex: input.envMeta.sigHashHex },
    // predecessor は渡さない(latest-only 配布 — 直前マニフェストは配布されない)。
    // セッションを跨ぐ後退・同版相違・前進注入の検出は床のマニフェスト拡張
    // (floor-check.ts の規則 (a)(b)(c))が担う
  });
  if (result.ok) {
    return {
      kind: "ok",
      value: {
        manifestVersion: manifest.manifestVersion,
        epoch: manifest.epoch,
        variablesDigestHex: manifest.variablesDigestHex,
        envMetaVersion: manifest.envMetaVersion,
        envMetaSigHashHex: manifest.envMetaSigHashHex,
        prevManifestSigHashHex: manifest.prevManifestSigHashHex,
        signedBytesHashHex: result.value.signedBytesHashHex,
        chainHeadSeq: manifest.chainHeadSeq,
        chainHeadHashHex: manifest.chainHeadHashHex,
        signatureHex: manifest.signatureHex,
        issuerUserId: manifest.issuerUserId,
        issuerKeyFingerprintHex: manifest.issuerKeyFingerprintHex,
      },
    };
  }
  const error = result.error;
  if (error.kind === "EnvManifestInvalid") {
    const unknownSigner = error.reason === "issuer-unknown";
    if (
      error.reason === "chain-head-future" ||
      (unknownSigner && manifest.chainHeadSeq > input.verified.history.headSeq)
    ) {
      return { kind: "future" };
    }
    return {
      kind: "rejected",
      message: `Verification of environment ${input.environmentId}'s manifest failed (reason=${error.reason}). Statements may have been omitted, injected or replaced by the server (CRYPTO_SPEC §4.3)`,
    };
  }
  return {
    kind: "rejected",
    message: `Verification of environment ${input.environmentId}'s manifest failed (reason=${error.kind})`,
  };
}

/** マニフェスト欠落の一律拒否メッセージ(§6.3 — 唯一の許容は --init-manifest の移行経路)。 */
export function missingManifestMessage(environmentId: string): string {
  return (
    `The server did not distribute an environment manifest for ${environmentId}. ` +
    "A missing manifest is treated as manifest suppression (statement omission cannot be ruled out — CRYPTO_SPEC §6.3) and the response is rejected. " +
    "If this environment was created before manifests were introduced, a member must initialize it once with: maruhi env rotate " +
    `${environmentId} --init-manifest --reason "manifest initialization"`
  );
}
