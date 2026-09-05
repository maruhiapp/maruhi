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

import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import type { ManifestFloor } from "./floor.ts";
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
 *
 * **隣接版の prev 連鎖検証(CRYPTO_SPEC §4.3 検証規則 (1) — session-31 §3
 * M1-A1)**: 床がマニフェスト記録を持ち、配布版が床の直後
 * (pulled.manifestVersion = floor.manifestVersion + 1)なら、床は直前
 * マニフェストそのものなので、床の signed_bytes ハッシュを predecessor として
 * 共有検証器へ渡し `prevManifestSigHashHex` を厳密検証する。version の差が
 * 2 以上は latest-only の既知制約どおり中間 predecessor の実在一致を検査
 * できない(§14.3 — 検査済みと偽らない)。同版・後退は床検査(規則 (a)(b))が
 * 担う。床を持たない経路(初回同期・リース — ワークロードは床を持たない
 * 初回同期クラス §14.3-3)は floor = null で従来どおり。
 */
export async function verifyDistributedManifest(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly manifest: DistributedEnvironmentManifest;
  readonly entries: readonly ManifestDigestEntry[];
  readonly envMeta: { readonly metaVersion: number; readonly sigHashHex: string };
  /** ローカル床のマニフェスト記録(隣接 prev 検証の predecessor — null = 床なし)。 */
  readonly floorManifest?: ManifestFloor | null;
}): Promise<ManifestVerifyOutcome> {
  const manifest = input.manifest;
  if (manifest.environmentId !== input.environmentId) {
    return {
      kind: "rejected",
      message: `The environment manifest's coordinates do not match the requested environment ${input.environmentId} (possible transplantation)`,
    };
  }
  const floorManifest = input.floorManifest ?? null;
  const predecessor =
    floorManifest !== null && manifest.manifestVersion === floorManifest.manifestVersion + 1
      ? {
          signedBytesHashHex: floorManifest.manifestSigHashHex,
          epoch: floorManifest.epoch,
        }
      : undefined;
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
    // 隣接版のみ床由来の predecessor を渡す(上記)。それ以外は latest-only の
    // 既知制約どおり — セッションを跨ぐ後退・同版相違・前進注入の検出は床の
    // マニフェスト拡張(floor-check.ts の規則 (a)(b)(c))が担う
    ...(predecessor === undefined ? {} : { predecessor }),
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
    if (predecessor !== undefined && error.reason === "prev-hash-mismatch") {
      // 隣接 prev 不一致は床(検証済みの直前マニフェスト)との矛盾 = マニフェスト
      // 連鎖の分岐の証拠。第三者へ提示可能な材料(両ハッシュ・発行者・宣言ヘッド)
      // を含める(session-31 §3 M1-A1 修正案 3)
      return {
        kind: "rejected",
        message: [
          `Environment ${input.environmentId}'s manifest (manifestVersion ${manifest.manifestVersion}) declares a prev that does not match the verified predecessor recorded in the local floor (evidence of a diverged manifest chain — CRYPTO_SPEC §4.3 rule (1))`,
          `  floor record (previously verified): manifestVersion=${floorManifest?.manifestVersion ?? 0} manifest_signed_bytes_hash=${predecessor.signedBytesHashHex}`,
          `  this distribution: prevManifestSigHashHex=${manifest.prevManifestSigHashHex}`,
          `    declared head: seq=${manifest.chainHeadSeq} hash=${manifest.chainHeadHashHex}`,
          // user_id はワイヤ上は長さ制約のみの自由文字列 — 端末へ出す前に中和する
          `    issuer signature: issuer=${displayText(manifest.issuerUserId)} fp=${manifest.issuerKeyFingerprintHex}`,
          `    signature=${manifest.signatureHex}`,
          "  Preserve this output and the local floor log, and present them to the project administrators",
        ].join("\n"),
      };
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
    "If this environment was created before manifests were introduced, a member must initialize it once with: `maruhi env rotate` " +
    `${environmentId} --init-manifest --reason "manifest initialization"`
  );
}
