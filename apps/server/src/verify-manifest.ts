// 環境マニフェストのサーバー受理(AUTH_SPEC §12-5 = CRYPTO_SPEC §4.3 / §6.4)。
//
// メタは平文でありサーバーは完全検証できる(E2EE の制約がない — §4.3): 署名・
// 宣言ヘッド・認可時点・エポック整合・prev 連鎖に加えて、**受理後のメタ状態
// (同梱ステートメント適用後の全変数ステートメント + 環境メタステートメント)
// から variablesDigestHex / envMetaVersion / envMetaSigHashHex を再計算して
// 申告値との一致まで**受理条件とする(§12-5 (7))。不正クライアントの偽
// マニフェスト持ち込みは受理段で全部落ちる。
//
// manifestVersion CAS(§12-5 (6))は保存済み最新マニフェスト(保持は最新 1 通 —
// environment_manifests の PRIMARY KEY = environment_id)に対して判定し、同梱
// される metaVersion CAS と同一トランザクション(DO permit 下の同一プログラム)で
// 解決される。409 は最新 manifestVersion のみを返す(勝者のハッシュを載せない
// 規律は metaVersion CAS と同一)。
//
// 検証本体は @maruhi/crypto の verifyDistributedEnvManifest(サーバー / CLI の
// 共有実装 — §4.3 の「正規形実装は 1 つだけ」)。エポック整合の複合形(宣言
// ヘッドの次エントリがエポックを確立する — §12-5 (4) の「同梱エントリ適用後の
// 状態」)は、複合プログラムが**エントリ適用後の履歴索引**を渡すことで同じ
// 検証器がそのまま判定する。

import type {
  ChainHistoryIndex,
  ChainMember,
  EnvManifestEnvMeta,
  ManifestInvalidReason,
  VariablesDigestEntry,
} from "@maruhi/crypto";
import { verifyDistributedEnvManifest } from "@maruhi/crypto";
import { Effect } from "effect";

import type { EnvManifestInput, ManifestRejectReason } from "./data-plane.ts";
import { rejectData } from "./data-plane.ts";
import { DataStore } from "./data-store.ts";

/**
 * crypto の詳細理由 → ワイヤ理由への写像(値・メタの 3 語彙共有 + マニフェスト
 * 固有 2 理由 — AUTH_SPEC §12-5)。網羅は Record 型が静的に強制する。
 */
const MANIFEST_REJECT_REASONS: Readonly<Record<ManifestInvalidReason, ManifestRejectReason>> = {
  "signature-invalid": "signature-invalid",
  "chain-head-mismatch": "chain-head-unknown",
  "chain-head-future": "chain-head-unknown",
  "issuer-unknown": "chain-head-state-mismatch",
  "issuer-not-member-at-head": "chain-head-state-mismatch",
  "issuer-key-mismatch-at-head": "chain-head-state-mismatch",
  "issuer-role-insufficient-at-head": "chain-head-state-mismatch",
  "environment-not-created-at-head": "manifest-epoch-mismatch",
  "epoch-not-current-at-head": "manifest-epoch-mismatch",
  // 旧エポックを焼き込んだ前進 manifestVersion(predecessor とのエポック後退)も
  // エポック不整合として拒否する(§12-5 の 422 区分)
  "epoch-regressed": "manifest-epoch-mismatch",
  "env-meta-mismatch": "manifest-digest-mismatch",
  "variables-digest-mismatch": "manifest-digest-mismatch",
  "prev-shape-mismatch": "chain-head-state-mismatch",
  "prev-hash-mismatch": "chain-head-state-mismatch",
};

/**
 * 受理後のメタ状態の変数ステートメント集合(tombstone 込み — §4.3)を組み立てる:
 * 保存済みの最新形に、今回の操作で受理されるステートメント(検証済み —
 * signedBytesHashHex はサーバー再計算)を適用した形。変数を伴わない操作
 * (環境 rename・rotate・環境作成)は override なし。
 */
export const manifestDigestEntries = (
  environmentId: string,
  override: {
    readonly variableId: string;
    readonly status: "active" | "deleted";
    readonly metaVersion: number;
    readonly signedBytesHashHex: string;
  } | null,
) =>
  Effect.gen(function* () {
    const store = yield* DataStore;
    const stored = yield* store.variableDigestEntries(environmentId);
    if (override === null) {
      return stored;
    }
    const entry: VariablesDigestEntry = {
      variableId: override.variableId,
      status: override.status,
      metaVersion: override.metaVersion,
      metaSigHashHex: override.signedBytesHashHex,
    };
    const rest = stored.filter((candidate) => candidate.variableId !== override.variableId);
    return [...rest, entry];
  });

/**
 * 保存済みの環境メタステートメントの最新形(metaVersion + サーバー再計算
 * ハッシュ)。環境メタを変えない操作(変数のメタ操作・rotate)のマニフェストが
 * 束縛すべき envMeta の期待値。行の欠落は不変条件違反(環境行とステートメントは
 * 複合受理で原子的に作られる)= defect。
 */
export const storedEnvMeta = (environmentId: string) =>
  Effect.gen(function* () {
    const store = yield* DataStore;
    const environment = yield* store.findEnvironment(environmentId);
    if (environment === null) {
      return yield* Effect.die(new Error("environment row missing for manifest acceptance"));
    }
    const anchor = yield* store.environmentMetaAnchor(environmentId, environment.latestMetaVersion);
    if (anchor === null) {
      return yield* Effect.die(new Error("environment meta statement row missing"));
    }
    return { metaVersion: environment.latestMetaVersion, sigHashHex: anchor.signedBytesHashHex };
  });

/**
 * 非複合のメタ操作(変数の作成・rename・削除、環境 rename)の共通形:
 * マニフェスト受理(§12-5)+ 書き込みフェーズ用のクロージャ。
 * `digestOverride` は同梱ステートメント適用後の当該変数エントリ(変数を
 * 伴わない操作は null)、`envMeta` 省略 = 保存済み環境メタ(環境 rename は
 * 適用後 = 同梱ステートメント自身を渡す)。
 */
export const acceptManifestForMetaOp = (input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly history: ChainHistoryIndex;
  readonly member: ChainMember;
  readonly manifest: EnvManifestInput;
  readonly digestOverride: {
    readonly variableId: string;
    readonly status: "active" | "deleted";
    readonly metaVersion: number;
    readonly signedBytesHashHex: string;
  } | null;
  readonly envMeta?: EnvManifestEnvMeta;
}) =>
  Effect.gen(function* () {
    // v1 ブートストラップのヘッドピン留め(AUTH_SPEC §12-5 (6) の明確化 —
    // 2026-08-18 PR #81 pullfrog レビュー対応): 保存済みマニフェストなし →
    // v1 受理では、宣言ヘッド後にローテーションが挟まっても manifestVersion
    // CAS(最新 0 のまま)が 409 で落とせず、「受理時点の現エポック独立検査を
    // 置かない」論証(§12-5)が v1 に限って成立しない。複合経路のピン留め
    // (composite-programs.ts の manifestChainHead)と同型に、宣言ヘッド =
    // 受理時点の現ヘッドを要求して stale エポックの焼き込みを塞ぐ(ハッシュの
    // 一致は crypto のヘッド束縛検査が担う — ここは位置のみ)
    if (
      input.manifest.manifestVersion === 1 &&
      input.manifest.chainHeadSeq !== input.history.headSeq
    ) {
      return yield* rejectData({ kind: "payload-mismatch", field: "manifestChainHead" });
    }
    const signedBytesHashHex = yield* acceptEnvManifest({
      projectId: input.projectId,
      environmentId: input.environmentId,
      history: input.history,
      member: input.member,
      manifest: input.manifest,
      entries: yield* manifestDigestEntries(input.environmentId, input.digestOverride),
      envMeta: input.envMeta ?? (yield* storedEnvMeta(input.environmentId)),
    });
    const store = yield* DataStore;
    return {
      /** 書き込みフェーズ(単一の Effect.sync)内で呼ぶ — 最新 1 通の upsert(§12-8)。 */
      writeSync: (nowMs: number): void => {
        store.write.upsertEnvironmentManifest(
          input.environmentId,
          input.manifest,
          signedBytesHashHex,
          { userId: input.member.userId, keyFingerprintHex: input.member.keyFingerprintHex },
          nowMs,
        );
      },
    };
  });

/**
 * マニフェストの受理列(§12-5 の (1)〜(7)): manifestVersion CAS(6。409 は
 * 最新番号のみ)→ 保存済み直前マニフェストのアンカー取得(prev 検査 (5) と
 * エポック単調性の predecessor)→ crypto の複合検証(署名者一致 (1)・ヘッド
 * 実在 (2)・認可時点 (3)・エポック整合 (4)・ダイジェスト / 環境メタ再計算 (7))。
 * 成功時はサーバー再計算の signed_bytes ハッシュを返す(保存行に書く)。
 *
 * `history` は非複合のメタ操作では受理時点のチェーン、複合(環境作成・rotate)
 * では**同梱エントリ適用後**の履歴索引(§12-5 (4) の判定基準)。
 */
export const acceptEnvManifest = (input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly history: ChainHistoryIndex;
  readonly member: ChainMember;
  readonly manifest: EnvManifestInput;
  /** 受理後のメタ状態から再構成した集合(manifestDigestEntries)。 */
  readonly entries: readonly VariablesDigestEntry[];
  /** 受理後の環境メタステートメントの最新形(metaVersion + サーバー再計算ハッシュ)。 */
  readonly envMeta: EnvManifestEnvMeta;
}) =>
  Effect.gen(function* () {
    const store = yield* DataStore;
    const anchor = yield* store.environmentManifestAnchor(input.environmentId);
    // CAS(§12-5 (6)): 申告 == 最新 + 1 のみ。マニフェスト導入前に作成された
    // 環境は行なし(最新 0)から v1 を確立する(移行手順 — session-27 §14)
    const latestVersion = anchor?.manifestVersion ?? 0;
    if (input.manifest.manifestVersion !== latestVersion + 1) {
      return yield* rejectData({
        kind: "manifest-version-conflict",
        currentManifestVersion: latestVersion,
      });
    }
    const verified = yield* Effect.promise(() =>
      verifyDistributedEnvManifest({
        history: input.history,
        context: {
          suite: input.manifest.suite,
          // 座標はサーバー側の値から再構成する(§12-5 — ワイヤ申告値から組まない)
          projectId: input.projectId,
          environmentId: input.environmentId,
          epoch: input.manifest.epoch,
          manifestVersion: input.manifest.manifestVersion,
          variablesDigestHex: input.manifest.variablesDigestHex,
          envMetaVersion: input.manifest.envMetaVersion,
          envMetaSigHashHex: input.manifest.envMetaSigHashHex,
          prevManifestSigHashHex: input.manifest.prevManifestSigHashHex,
          // issuer = 呼び出し主体(§12-5 (1))。検証鍵とヘッド時点の束縛一致は
          // FP(受理時点のチェーン導出メンバー)で verifyDistributedEnvManifest が検査
          issuerUserId: input.member.userId,
          chainHeadHashHex: input.manifest.chainHeadHashHex,
          chainHeadSeq: input.manifest.chainHeadSeq,
        },
        issuerKeyFingerprintHex: input.member.keyFingerprintHex,
        signatureHex: input.manifest.signatureHex,
        entries: input.entries,
        envMeta: input.envMeta,
        predecessor:
          anchor === null
            ? undefined
            : { signedBytesHashHex: anchor.signedBytesHashHex, epoch: anchor.epoch },
      }),
    );
    if (verified.ok) {
      return verified.value.signedBytesHashHex;
    }
    if (verified.error.kind === "EnvManifestInvalid") {
      return yield* rejectData({
        kind: "manifest-rejected",
        reason: MANIFEST_REJECT_REASONS[verified.error.reason],
      });
    }
    // InvalidInput / KeyImportFailed は Schema 検証済みワイヤ + 検証済みチェーン
    // 由来の鍵では到達しない(実装バグ = defect。エラー値に秘密は含まれない)
    return yield* Effect.die(new Error(`manifest verification failed: ${verified.error.kind}`));
  });
