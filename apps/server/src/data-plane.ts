// データプレーン(AUTH_SPEC §12)の共有部: RPC 境界を渡る型・拒否理由・
// 認可ガード(チェーン導出 role と環境 scope — CRYPTO_SPEC §6.2)。
//
// 拒否は DataRejectedError 1 種に畳み、DO の RPC 境界では DataOutcome の
// 判別 union として渡す(worker が api-schema の型付きエラーへ写像する)。

import type { AuditActor } from "@maruhi/core";
import { auditPayloadWith } from "@maruhi/core";
import type {
  ChainDevice,
  ChainHistoryIndex,
  ChainInvalidReason,
  ChainMember,
  ChainState,
  EffectivePermission,
  Role,
} from "@maruhi/crypto";
import { effectivePermissionOf, scopeIncludesEnvironment } from "@maruhi/crypto";
import { Data, Effect } from "effect";

import type { AuditEventInput } from "./audit-store.ts";
import type { StateCache, StoredChain } from "./chain-store.ts";
import { ChainStore, deriveStoredState } from "./chain-store.ts";

// ---------------------------------------------------------------------------
// RPC 境界を渡る入力・値(structured clone 安全な素のオブジェクトのみ)
// ---------------------------------------------------------------------------

/**
 * データ操作の監査アクター(AUDIT_SPEC §2)。worker が認証主体から
 * auditActorOf(@maruhi/core — 写像の唯一の実装)で作る。
 * 鍵 FP は持たない — ほとんどのデータ操作は署名を伴わないため。署名を伴う
 * 唯一の例外は DEK ラップ登録(CRYPTO_SPEC §5.1)で、その署名者 FP は worker
 * でなく DO がチェーン導出メンバーから取り、dek.registered イベントに写す。
 */
export type DataActor = AuditActor;

/**
 * スイート識別子(CRYPTO_SPEC §2 設計原則 4)。ワイヤは Schema の Literal が
 * 強制するため、RPC 境界・保存行の型もこの literal で表す(AUTH_SPEC §12-2)。
 */
export type WireSuite = "maruhi/v1";

/**
 * DEK ラップの受信者クラス(AUTH_SPEC §12-6): member = チェーン上の
 * 現メンバー、server = 有効な grant_server のサーバー鍵。省略時は member。
 * server クラスでは recipientUserId 位置にサーバー鍵 FP(hex 小文字)が入る
 * (HPKE info / §5.1 署名対象と同じ置き換え — CRYPTO_SPEC §9)。
 */
export type DekRecipientClass = "member" | "server";

/**
 * 1 受信者宛のラップ済み DEK(AUTH_SPEC §12-6。ワイヤ表現と構造一致)。
 * signatureHex は登録署名(CRYPTO_SPEC §5.1)— 署名者は API 呼び出し主体と
 * 厳密一致(§12-6)のため、ワイヤ・RPC 境界に署名者 ID は載せない。
 */
export interface DekWrapInput {
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly recipientClass?: DekRecipientClass;
  readonly recipientUserId: string;
  readonly recipientEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly signatureHex: string;
}

/**
 * 保存済みラップの参照(§12-6 の修復経路の削除単位)。`recipientEncPubHex` は端末軸
 * (2026-09-19 DK — スロットは端末ごと)。省略時は当該 (epoch, 受信者) のスロットが
 * ちょうど 1 つのときだけ消す(複数なら 422 duplicate-recipient — 設計録 §8 K3-3)。
 */
export interface DekWrapRefInput {
  readonly epoch: number;
  readonly recipientClass?: DekRecipientClass;
  readonly recipientUserId: string;
  readonly recipientEncPubHex?: string;
}

/**
 * ステートメントのライフサイクル状態(CRYPTO_SPEC §4.2)。declared は変数の
 * レイアウト v2 限定(環境メタと v1 レイアウトは 2 値のまま — ワイヤ Schema が
 * 強制し、DO 側は保存・検証の型として 3 値を受ける)。
 */
export type MetaStatementStatusInput = "active" | "deleted" | "declared";

/** varType の閉集合(CRYPTO_SPEC §4.2 — `""` = 未指定)。 */
export type MetaVarTypeInput = "" | "string" | "number" | "boolean" | "url";

/**
 * レイアウト v2 のスキーマ欄(CRYPTO_SPEC §4.2 / AUTH_SPEC §12-2)。required は
 * ワイヤの boolean のまま運ぶ(署名対象の "true" / "false" 文字列への写像は
 * 検証点 — verify-meta.ts — の 1 箇所で行う)。
 */
export interface MetaVariableSchemaInput {
  readonly varType: MetaVarTypeInput;
  readonly required: boolean;
  readonly description: string;
}

/**
 * メタデータステートメントの保存入力(CRYPTO_SPEC §4.2 / AUTH_SPEC §12-5)。
 * 座標(environment / variable)は worker が URL・ステートメント申告値の一致を
 * 検査済みで、DO は保存先座標から署名対象を再構成する(§12-5 — ワイヤの申告値
 * から組まない)。author = 呼び出し主体が契約のため author の ID / FP はここに
 * 載せない(DO が受理時点のチェーン導出メンバーから取る)。
 */
export interface MetaStatementInput {
  readonly suite: WireSuite;
  readonly name: string;
  readonly status: MetaStatementStatusInput;
  readonly metaVersion: number;
  /** 直前ステートメントの signed_bytes の SHA-256(metaVersion 1 は空文字列)。 */
  readonly prevMetaSigHashHex: string;
  /**
   * ワイヤの layoutVersion(§12-2 — 省略 = 1)。ワイヤ Schema は明示値 2 以上
   * のみ通し、サポート範囲({1, 2})超過は署名検証より前の受理検査が
   * `unsupported-layout` の 422 で拒否する(裁定 CR)。
   */
  readonly layoutVersion?: number;
  /** レイアウト v2 のスキーマ欄(layoutVersion 明示時は必ず存在 — ワイヤ形)。 */
  readonly schema?: MetaVariableSchemaInput;
  /** author が署名時点で最後に検証したチェーンヘッド(§4.2 の認可時点束縛)。 */
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  /** ステートメント署名(Ed25519 — CRYPTO_SPEC §4.2)。 */
  readonly signatureHex: string;
}

/**
 * 配布されるメタデータステートメント(DistributedVariableMetaStatement /
 * DistributedEnvironmentMetaStatement と構造一致 — 変数用は variableId 付き)。
 * 保存済みの署名ブロックと author(受理時点の user_id + チェーン導出鍵 FP)を
 * そのまま返す(削除済み author の過去ステートメントの検証可能性 — §12-2)。
 */
export interface DistributedMetaStatementValue {
  readonly suite: WireSuite;
  readonly environmentId: string;
  readonly name: string;
  /** 環境ステートメントは 2 値のまま(declared は変数の v2 限定 — §4.2)。 */
  readonly status: "active" | "deleted";
  readonly metaVersion: number;
  readonly prevMetaSigHashHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
  readonly authorUserId: string;
  readonly authorKeyFingerprintHex: string;
}

/**
 * 変数ステートメントの配布形(variableId 付き)。レイアウト v2 の運搬
 * フィールドは v2 の保存行でのみ 4 つ揃って存在する(v1 の配布へ新フィールドを
 * 足さない — §12-2)。
 */
export interface DistributedVariableMetaStatementValue extends Omit<
  DistributedMetaStatementValue,
  "status"
> {
  readonly variableId: string;
  readonly status: MetaStatementStatusInput;
  readonly layoutVersion?: number;
  readonly varType?: MetaVarTypeInput;
  readonly required?: boolean;
  readonly description?: string;
}

/**
 * 環境マニフェストの保存入力(CRYPTO_SPEC §4.3 / AUTH_SPEC §12-5)。
 * 座標(environment)は worker が URL との一致を検査済みで、DO は保存先座標から
 * 署名対象を再構成する(§12-5 — ワイヤの申告値から組まない)。issuer = 呼び出し
 * 主体が契約のため issuer の ID / FP はここに載せない(DO が受理時点のチェーン
 * 導出メンバーから取る)。
 */
export interface EnvManifestInput {
  readonly suite: WireSuite;
  /** 発行時点(宣言ヘッド時点)の現エポック(§4.3 の鮮度アンカー)。 */
  readonly epoch: number;
  readonly manifestVersion: number;
  readonly variablesDigestHex: string;
  readonly envMetaVersion: number;
  readonly envMetaSigHashHex: string;
  /** 直前マニフェストの signed_bytes の SHA-256(manifestVersion 1 は空文字列)。 */
  readonly prevManifestSigHashHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  /** マニフェスト署名(Ed25519 — CRYPTO_SPEC §4.3)。 */
  readonly signatureHex: string;
}

/**
 * 配布される環境マニフェスト(DistributedEnvironmentManifest と構造一致)。
 * 保存済みの署名ブロックと issuer(受理時点の user_id + チェーン導出鍵 FP)を
 * そのまま返す(削除済み issuer の過去マニフェストの検証可能性 — §12-2)。
 */
export interface DistributedEnvManifestValue extends EnvManifestInput {
  readonly environmentId: string;
  readonly issuerUserId: string;
  readonly issuerKeyFingerprintHex: string;
}

/**
 * 変数値の保存入力。AAD 構成要素のうち座標(project / environment / variable)は
 * worker が URL との一致を検査済み(§12-2)。DO は状態依存の epoch / version と
 * 値署名(§12-5 = CRYPTO_SPEC §4.1 / §6.4)を検査する。
 * writer = 呼び出し主体が契約のため writer の ID / FP はここに載せない
 * (DO が受理時点のチェーン導出メンバーから取る)。
 */
export interface ValueInput {
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly version: number;
  readonly nonceHex: string;
  readonly ciphertextHex: string;
  /** 直前 version の value_signed_bytes の SHA-256(version 1 は空文字列)。 */
  readonly prevValueSigHashHex: string;
  /** writer が署名時点で最後に検証したチェーンヘッド(§4.1 の認可時点束縛)。 */
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  /** 値の書き込み署名(Ed25519 — CRYPTO_SPEC §4.1)。 */
  readonly signatureHex: string;
}

export interface EnvironmentSummaryValue {
  readonly environmentId: string;
  readonly currentEpoch: number;
  /** 最新の環境メタステートメント(削除済み環境は deleted ステートメント)。 */
  readonly statement: DistributedMetaStatementValue;
}

export interface VariableVersionValue {
  readonly variableId: string;
  readonly version: number;
  readonly epoch: number;
}

/**
 * 一括 pull の 1 変数(§12-7)。保存済みの署名ブロックと writer(受理時点の
 * user_id + チェーン導出鍵 FP)を配布する — 現メンバー集合から再導出しない
 * (削除済み writer の過去値もチェーン履歴の当時の鍵で検証可能にするため)。
 * サーバー再計算の signed_bytes ハッシュは配布しない(検証者が自ら再計算する)。
 */
export interface PulledVariableValue {
  readonly variableId: string;
  readonly version: number;
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly nonceHex: string;
  readonly ciphertextHex: string;
  readonly prevValueSigHashHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
  readonly writerUserId: string;
  readonly writerKeyFingerprintHex: string;
}

/**
 * 配布されるラップ(RecipientDek と構造一致)。署名・署名者情報(登録受理時の
 * チェーン導出メンバーの user_id + 鍵 FP)を運び、配布時のクライアント検証
 * (CRYPTO_SPEC §5.1)を可能にする。
 */
export interface RecipientDekValue {
  readonly suite: WireSuite;
  readonly epoch: number;
  /**
   * 受信者の端末鍵(enc 公開鍵 — AUTH_SPEC §12-6 の端末軸。2026-09-19 DK)。同じ人の
   * 複数端末宛のラップが同じ応答に並ぶため、受信者は自分の端末鍵の行だけを開封する
   * (開封失敗を毒ラップと取り違えない)。
   */
  readonly recipientEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly signatureHex: string;
  readonly signerUserId: string;
  readonly signerKeyFingerprintHex: string;
}

/** チェックポイント時点の値スナップショットの 1 エントリ(配布形 — §12-7)。 */
export interface CheckpointSnapshotEntryValue {
  readonly variableId: string;
  readonly version: number;
  readonly valueSigHashHex: string;
}

/**
 * 配布されるチェックポイント時点の値スナップショット(api-schema の
 * CheckpointValueSnapshot と構造一致 — §12-7 / §14-2)。
 * 供給源は checkpoint 受理時に原子保存した行そのもの(§16-2 — 再構成しない)。
 * chainSeq / entryHashHex は保存済みの対応 checkpoint の位置(クライアント側では
 * advisory locator — 検証基準はチェーン導出)。
 */
export interface CheckpointSnapshotValue {
  readonly chainSeq: number;
  readonly entryHashHex: string;
  readonly values: readonly CheckpointSnapshotEntryValue[];
}

/**
 * 値付き応答の省略可能な検証材料フィールド(§12-7 / §14-2): 保存行があれば
 * 必ず載せ、なければキー自体を置かない(optionalKey のワイヤ形)。pull と
 * lease の応答組み立てが共有する(分岐を各プログラムに重複させない)。
 */
export function optionalDistributionFields(
  manifest: DistributedEnvManifestValue | null,
  checkpointSnapshot: CheckpointSnapshotValue | null,
): {
  readonly manifest?: DistributedEnvManifestValue;
  readonly checkpointSnapshot?: CheckpointSnapshotValue;
} {
  return {
    ...(manifest === null ? {} : { manifest }),
    ...(checkpointSnapshot === null ? {} : { checkpointSnapshot }),
  };
}

export interface EnvironmentPullValue {
  readonly environmentId: string;
  readonly currentEpoch: number;
  /** 環境自身の最新メタステートメント(§12-7 の検証材料の同梱)。 */
  readonly statement: DistributedMetaStatementValue;
  /** アクティブ変数ごとの最新ステートメント + 最新バージョン。 */
  readonly variables: readonly (PulledVariableValue & {
    readonly statement: DistributedVariableMetaStatementValue;
  })[];
  /** 削除済み変数の deleted ステートメント(保存・配布し続ける — §12-5)。 */
  readonly deletedVariables: readonly DistributedVariableMetaStatementValue[];
  /**
   * declared 変数の最新ステートメント(§12-7 — 値・バージョンは存在しない。
   * マニフェストのダイジェスト再計算の材料)。declared が無い環境では省略
   * (ワイヤの optionalKey と同型)。
   */
  readonly declaredVariables?: readonly DistributedVariableMetaStatementValue[];
  readonly deks: readonly RecipientDekValue[];
  /** schemaPolicy の advisory 同梱(§12-7 / §12-11 — 常に載せる)。 */
  readonly schemaPolicy: SchemaPolicy;
  /**
   * 最新の環境マニフェスト(§12-7)。undefined はマニフェスト
   * 導入前に作成された環境の移行完了までの過渡状態のみ(保存行があれば必ず
   * 同梱する — クライアント側は欠落 = 一律拒否 §6.3)。
   */
  readonly manifest?: DistributedEnvManifestValue;
  /**
   * チェックポイント時点の値スナップショット列挙(§12-7)。
   * 当該環境のエントリを含む最新 checkpoint の保存行があれば必ず同梱する
   * (クライアント規則 2 は「基準あり + 列挙なし」を拒否する — CRYPTO_SPEC §6.3)。
   * undefined は基準 checkpoint を持たない環境のみ。
   */
  readonly checkpointSnapshot?: CheckpointSnapshotValue;
}

/**
 * メタデータのみモードの応答(§12-7): 値(暗号文)と DEK を
 * 含まない。§6.3 のメタ検証材料(環境 + アクティブ変数の最新ステートメント +
 * tombstone)のみを運ぶ。var.read は記録されない(AUDIT_SPEC §3.3)。
 */
export interface EnvironmentMetadataPullValue {
  readonly environmentId: string;
  readonly currentEpoch: number;
  /** 環境自身の最新メタステートメント。 */
  readonly statement: DistributedMetaStatementValue;
  /**
   * 削除済みでない全変数の最新ステートメント(値は伴わない)。declared 変数の
   * ステートメントもここに載る(§12-7 — status が判別を担う)。
   */
  readonly variables: readonly DistributedVariableMetaStatementValue[];
  /** 削除済み変数の deleted ステートメント(§12-5)。 */
  readonly deletedVariables: readonly DistributedVariableMetaStatementValue[];
  /** 最新の環境マニフェスト(メタ検証の完全性はこのモードでも同水準 — §12-7)。 */
  readonly manifest?: DistributedEnvManifestValue;
  /** schemaPolicy の advisory 同梱(§12-7 / §12-11 — 常に載せる)。 */
  readonly schemaPolicy: SchemaPolicy;
}

/** 環境一覧の RPC 値(§12-4 + schemaPolicy の advisory 同梱 — §12-7)。 */
export interface EnvironmentListValue {
  readonly environments: readonly EnvironmentSummaryValue[];
  readonly schemaPolicy: SchemaPolicy;
}

// ---------------------------------------------------------------------------
// 拒否理由(worker が api-schema の型付きエラーへ写像する)
// ---------------------------------------------------------------------------

export type ResourceConflictReason = "exists" | "retired" | "duplicate-name";

/**
 * 環境の 409 は表示名の衝突のみ: ID の一意性はチェーン合意規則
 * `duplicate-environment`(chain-entry-invalid)が担う
 * (CRYPTO_SPEC §6.2 / AUTH_SPEC §12-4)。
 */
export type EnvironmentConflictReason = "duplicate-name";

export type DekWrapRejectReason =
  | "recipient-not-member"
  | "recipient-not-granted"
  | "recipient-key-mismatch"
  | "recipient-missing"
  | "duplicate-recipient"
  | "epoch-out-of-range"
  | "scope-out-of-range"
  | "signature-invalid";

/**
 * 値署名の 422 理由(AUTH_SPEC §12-5。仮裁定 C — 仕様の 3 理由のみ):
 * signature-invalid = valid-format の Ed25519 失敗 / chain-head-unknown =
 * 有効署名だが宣言 seq 不在またはその seq の保存 hash 不一致 /
 * chain-head-state-mismatch = head は既知だが head 時点の鍵・role・環境・
 * エポック不一致、または保存 predecessor と prev 不一致。
 */
export type ValueSignatureRejectReason =
  | "signature-invalid"
  | "chain-head-unknown"
  | "chain-head-state-mismatch";

/**
 * メタステートメントの 422 理由: 値署名の 3 語彙(session-12 §6-7)に、仕様が
 * エラー名を明示するレイアウト v2 の 2 理由を加える — `layout-regression` =
 * v2 変数への v1 後続(レイアウト単調性 — §12-5)、`unsupported-layout` =
 * 申告 layoutVersion がサポート範囲超過(「古いサーバー × 新しいクライアント」の
 * 正常系 — 裁定 CR。署名不正に潰さない)。chain-head-state-mismatch はヘッド
 * 時点の在籍・鍵束縛・role、prev の形 / 保存 predecessor との不一致、削除後の
 * 再ステートメント(revived-after-delete)、active → declared の遷移
 * (declared-after-active)を含む。api-schema の MetaStatementRejectReasonSchema
 * と一致させる。
 */
export type MetaStatementRejectReason =
  | ValueSignatureRejectReason
  | "layout-regression"
  | "unsupported-layout";

/**
 * プロジェクトのスキーマポリシー(AUTH_SPEC §12-11 — 既定 disabled)。受理
 * 判定は受理時点のポリシー(project DO の直列化の中で読む)。
 */
export type SchemaPolicy = "disabled" | "enabled" | "locked";

/** schemaPolicy 由来の 422 理由(§12-11 / §12-5)。 */
export type SchemaPolicyRejectReason = "schema-policy-disabled" | "schema-required";

/** スキーマ description の受理検査(§12-8)の 422 理由。 */
export type SchemaDescriptionRejectReason = "too-long" | "control-characters";

/**
 * ヘッド申告の 422 理由も同じ 3 語彙を共有する(AUTH_SPEC §16-1 — 新理由
 * コードを作らない)。chain-head-unknown は seq が現ヘッドより先の場合を含む
 * (クライアント側の再同期分岐 — chain-head-future — はサーバーには無い)。
 */
export type AttestationRejectReason = ValueSignatureRejectReason;

/**
 * 環境マニフェストの 422 理由(AUTH_SPEC §12-5): 既存 3 語彙を
 * 共有し、マニフェスト固有の 2 理由(ダイジェスト再計算不一致・エポック不整合)を
 * 加える。api-schema の ManifestRejectReasonSchema と一致させる。
 */
export type ManifestRejectReason =
  | ValueSignatureRejectReason
  | "manifest-digest-mismatch"
  | "manifest-epoch-mismatch"
  // チェックポイント束縛(CRYPTO_SPEC §4.3 (2) / §6.3 整合規則 1)
  | "checkpoint-binding-mismatch"
  | "checkpoint-equivocation"
  | "checkpoint-regressed";

/**
 * checkpoint 内容突合の 422 理由(CRYPTO_SPEC §6.4 / AUTH_SPEC §16-2)。
 * api-schema の CheckpointMismatchReasonSchema と一致させる。
 */
export type CheckpointMismatchReason =
  | "manifest-mismatch"
  | "values-digest-mismatch"
  | "audit-head-unknown"
  | "audit-head-stale"
  | "environment-deleted";

/**
 * `propose` の受理ポリシー違反の理由(AUTH_SPEC §12-8 — 2026-09-16 K5)。
 * api-schema の ProposalLimitReasonSchema と一致させる。
 */
export type ProposalLimitReason = "pending-proposals" | "proposal-lifetime";

export type DataLimitResource =
  | "environments"
  | "environment-rows"
  | "variables"
  | "variable-rows"
  | "versions"
  | "meta-versions"
  | "project-ciphertext-bytes"
  | "dek-wraps-per-request"
  | "dek-wrap-rows"
  | "rotation-dismissals-per-request"
  // DO ストレージ総量ガード(§12-8。storage-guard.ts。limit = 拒否閾値バイト)
  | "project-storage-bytes";

export type DataRejection =
  | { readonly kind: "not-initialized" }
  | { readonly kind: "not-member" }
  | { readonly kind: "insufficient-role" }
  // 対象環境 ∉ 呼び出し主体のチェーン導出 scope(AUTH_SPEC §9-2 / §12-3 —
  // 2026-09-15 ES K3。role 403 の直後・存在 404 の前。worker が
  // ForbiddenError〔insufficient-scope〕へ写す)
  | { readonly kind: "insufficient-scope" }
  | { readonly kind: "environment-not-found"; readonly environmentId: string }
  | {
      readonly kind: "environment-conflict";
      readonly environmentId: string;
      readonly reason: EnvironmentConflictReason;
    }
  // チェーン受理系(複合リクエスト §12-4 と汎用チェーン API — chain-do.ts —
  // の両方が使う。worker が api-schema の ChainHeadConflict / ChainEntryInvalid /
  // ChainEntryTooLarge / ChainCapacityExceeded / CompositeRequired へ写像する)
  | {
      readonly kind: "composite-required";
      readonly op: "create_environment" | "rotate_epoch";
    }
  // 端末数の受理ポリシー(AUTH_SPEC §12-8 / CRYPTO_SPEC §6.4 — 2026-09-19 DK K3):
  // `add_device` の受理時に actor の有効な端末が上限(16)に達している。worker が
  // api-schema の DeviceLimit(422)へ写す。合意規則ではない
  | { readonly kind: "device-limit"; readonly limit: number }
  // 四眼の `propose` の受理ポリシー(AUTH_SPEC §12-8 / CRYPTO_SPEC §6.4 — 2026-09-16
  // K5): pending 上限(期限切れは数えない)と `expires_at_ms` の上界。worker が
  // api-schema の ProposalLimit(422)へ写す。語彙は ProposalLimitReasonSchema と一致
  | {
      readonly kind: "proposal-limit";
      readonly reason: ProposalLimitReason;
      readonly limit: number;
    }
  // checkpoint の内容突合(CRYPTO_SPEC §6.4 / AUTH_SPEC §16-2 — 境界同梱分
  // 〔複合の適用後基準 — §12-4〕と standalone 分〔受理時点 = 適用前基準〕の
  // 両経路で共通。語彙は api-schema の CheckpointMismatchReasonSchema と一致)
  | {
      readonly kind: "checkpoint-state-mismatch";
      readonly reason: CheckpointMismatchReason;
    }
  // 監査ヘッド派生列の有界伸長が未完了(AUDIT_SPEC §5.1)。
  // 監査ヘッドを読む全経路(GET /audit-head・standalone 受理・境界複合の
  // 非空公証)で、上限到達時に古い列で unknown / stale を判定する代わりに
  // 返す retryable 拒否(worker が api-schema の AuditHeadNotReady〔503〕へ写像)
  | { readonly kind: "audit-head-not-ready" }
  | {
      readonly kind: "chain-head-conflict";
      readonly currentHeadSeq: number;
      readonly currentHeadHashHex: string;
    }
  | {
      readonly kind: "chain-entry-invalid";
      readonly seq: number;
      readonly reason: ChainInvalidReason;
    }
  | { readonly kind: "chain-entry-too-large"; readonly limitBytes: number }
  | {
      readonly kind: "chain-capacity-exceeded";
      readonly maxEntries: number;
      readonly maxTotalBytes: number;
    }
  // 複合内整合検査(§12-4): URL 座標と同梱エントリ payload の不一致
  | { readonly kind: "payload-mismatch"; readonly field: string }
  | { readonly kind: "variable-not-found"; readonly variableId: string }
  | {
      readonly kind: "variable-conflict";
      readonly variableId: string;
      readonly reason: ResourceConflictReason;
    }
  | { readonly kind: "version-conflict"; readonly currentVersion: number }
  | { readonly kind: "epoch-conflict"; readonly currentEpoch: number }
  | { readonly kind: "value-rejected"; readonly reason: ValueSignatureRejectReason }
  | { readonly kind: "meta-rejected"; readonly reason: MetaStatementRejectReason }
  // schemaPolicy の受理ゲート(§12-11): disabled 下の v2 新規採用 /
  // locked 下の varType なし作成
  | { readonly kind: "schema-policy-rejected"; readonly reason: SchemaPolicyRejectReason }
  // declared 変数への通常 push(§12-5 — activation 複合を要求する)
  | { readonly kind: "activation-required"; readonly variableId: string }
  // スキーマ description の受理検査(§12-8 — 1024 コードポイント・制御文字なし)
  | { readonly kind: "description-rejected"; readonly reason: SchemaDescriptionRejectReason }
  | { readonly kind: "meta-version-conflict"; readonly currentMetaVersion: number }
  | { readonly kind: "manifest-rejected"; readonly reason: ManifestRejectReason }
  // manifestVersion CAS(§12-5 (6))。最新番号のみを返す(勝者のハッシュを
  // 載せない規律は metaVersion CAS と同一)
  | { readonly kind: "manifest-version-conflict"; readonly currentManifestVersion: number }
  | { readonly kind: "name-not-nfc" }
  | { readonly kind: "dek-wrap-rejected"; readonly reason: DekWrapRejectReason }
  | {
      readonly kind: "dek-wrap-exists";
      readonly epoch: number;
      readonly recipientUserId: string;
      /**
       * 占有ラップの保存済み受信者 enc 公開鍵(AUTH_SPEC §12-6)。
       * 非機密(全歴史鍵はチェーン配布済み)。再追加バックフィルの 409 で、
       * クライアントが登録済み / 旧鍵ラップを厳密比較で判定する材料。
       */
      readonly storedRecipientEncPubHex: string;
    }
  | {
      readonly kind: "dek-wrap-not-found";
      readonly epoch: number;
      readonly recipientUserId: string;
    }
  | {
      readonly kind: "rotation-flag-not-found";
      readonly environmentId: string;
      readonly variableId: string;
    }
  | {
      readonly kind: "limit-exceeded";
      readonly resource: DataLimitResource;
      readonly limit: number;
    }
  // ヘッド申告(CRYPTO_SPEC §6.6 / AUTH_SPEC §16-1)
  | { readonly kind: "attestation-rejected"; readonly reason: AttestationRejectReason }
  // seq 後退(黙って成功させない — 保存済み seq を返す。同一 seq は冪等 204)
  | { readonly kind: "attestation-regression"; readonly storedSeq: number }
  | { readonly kind: "attestation-rate-limited"; readonly retryAfterSeconds: number };

/** データプレーンのプログラムが失敗として運ぶ唯一の型付きエラー。 */
export class DataRejectedError extends Data.TaggedError("DataRejected")<{
  readonly rejection: DataRejection;
}> {}

export const rejectData = (rejection: DataRejection): DataRejectedError =>
  new DataRejectedError({ rejection });

/** RPC 境界(structured clone)を渡るデータ操作の結果。 */
export type DataOutcome<T> =
  | { readonly kind: "ok"; readonly value: T }
  | { readonly kind: "rejected"; readonly rejection: DataRejection };

// ---------------------------------------------------------------------------
// 認可ガード(チェーン導出 role — CRYPTO_SPEC §6.2 / AUTH_SPEC §12-3)
// ---------------------------------------------------------------------------

const ROLE_RANK: Record<Role, number> = { reader: 1, member: 2, admin: 3, owner: 4 };

/** チェーン role の下限判定(reader < member < admin < owner)。招待 API の
 * worker 側水準判定(handlers-invites.ts)とも共有する(rank 表を増殖させない)。 */
export function roleAtLeast(role: Role, minimum: Role): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[minimum];
}

/**
 * A chain member together with **the device that signed this request** (2026-09-19
 * DK — K3。設計録 dk-design.md §8 K3-1): the key every chain-external signature of
 * the request is attributed to (受理時点の署名者 FP・DEK ラップの受信者鍵・監査行の
 * FP)and the effective permission that device holds — `(min(role, role_cap), scope ∩
 * device scope)`(CRYPTO_SPEC §6.2)。The device is resolved **from the signature
 * itself** (`withSigningDevice` — the caller's active devices are tried in
 * fingerprint order; key uniqueness across current members makes at most one
 * verify) or, for chain entries, from `entry.actor.keyFingerprintHex` (`deviceOf`).
 * The advisory device registry (AUTH_SPEC §13-11) is never an input here.
 */
export interface MemberWithDevice extends ChainMember {
  readonly device: ChainDevice;
  readonly keyFingerprintHex: string;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  /** The signing device's effective permission (§6.2 — the input of the second-stage authorization). */
  readonly permission: EffectivePermission;
}

/** `member` + 指定 FP の有効な端末(無ければ undefined — 呼び出し側が理由コードを選ぶ)。 */
export function deviceOf(
  member: ChainMember,
  keyFingerprintHex: string,
): MemberWithDevice | undefined {
  const device = member.devices.get(keyFingerprintHex);
  return device === undefined ? undefined : withDevice(member, device);
}

function withDevice(member: ChainMember, device: ChainDevice): MemberWithDevice {
  return {
    ...member,
    device,
    keyFingerprintHex: device.keyFingerprintHex,
    encPubHex: device.encPubHex,
    sigPubHex: device.sigPubHex,
    permission: effectivePermissionOf(member, device),
  };
}

/** 呼び出し主体の有効な端末を FP 昇順で(試行順を決定的にする — 結果は順序に依らない)。 */
function activeDevicesOf(member: ChainMember): readonly MemberWithDevice[] {
  return [...member.devices.values()]
    .toSorted((a, b) => (a.keyFingerprintHex < b.keyFingerprintHex ? -1 : 1))
    .map((device) => withDevice(member, device));
}

/**
 * A rejection that only says "this signature does not verify under this key" —
 * the one outcome that makes `withSigningDevice` try the caller's next device.
 * Every other rejection (head unknown, state mismatch, CAS, …) is final for the
 * device that produced it: a signature that verified under one key has found
 * its device, and a non-signature rejection cannot be cured by another key.
 */
function isSignatureInvalidRejection(rejection: DataRejection): boolean {
  switch (rejection.kind) {
    case "value-rejected":
    case "meta-rejected":
    case "manifest-rejected":
    case "attestation-rejected":
    case "dek-wrap-rejected":
      return rejection.reason === "signature-invalid";
    default:
      return false;
  }
}

/**
 * Resolves the request's signing device from a signature (設計録 §8 K3-1 —
 * 案 a-3): runs `attempt` with each of the member's active devices in
 * fingerprint order until one does not answer `signature-invalid`. Returns that
 * device with the attempt's value. When every device answers `signature-invalid`
 * the last such rejection is returned (fail-closed — the signature belongs to no
 * active device of the caller: a revoked device, a foreign key, or garbage).
 * At most 16 devices (AUTH_SPEC §12-8) bound the trial.
 */
export function withSigningDevice<A, R>(
  member: ChainMember,
  attempt: (device: MemberWithDevice) => Effect.Effect<A, DataRejectedError, R>,
): Effect.Effect<{ readonly device: MemberWithDevice; readonly value: A }, DataRejectedError, R> {
  return Effect.gen(function* () {
    const candidates = activeDevicesOf(member);
    if (candidates.length === 0) {
      // 検証済みチェーンの現メンバーは端末を 1 つ以上持つ(§6.2 last-device-protected)
      return yield* Effect.die(new Error("internal: a current member has no active device"));
    }
    let lastRejection: DataRejectedError | null = null;
    for (const device of candidates) {
      // signature-invalid だけを「次の端末を試す」に畳む。他の拒否はその端末で確定
      const outcome: { readonly verified: A } | { readonly retry: DataRejectedError } =
        yield* attempt(device).pipe(
          Effect.map((value) => ({ verified: value })),
          Effect.catchTag("DataRejected", (error) =>
            isSignatureInvalidRejection(error.rejection)
              ? Effect.succeed({ retry: error })
              : Effect.fail(error),
          ),
        );
      if ("verified" in outcome) {
        return { device, value: outcome.verified };
      }
      lastRejection = outcome.retry;
    }
    // candidates は非空なので lastRejection は必ず設定されている
    return yield* Effect.fail(
      lastRejection ?? rejectData({ kind: "value-rejected", reason: "signature-invalid" }),
    );
  });
}

/**
 * Second-stage authorization (設計録 §8 K3-1): the signing device's **effective**
 * permission must satisfy the same role floor and (when an environment is
 * targeted) the same scope predicate the person already passed at the first
 * stage. Same reason codes as the first stage (403 — AUTH_SPEC §12-3). A device
 * never exceeds its person, so this can only narrow what the first stage let
 * through.
 *
 * Reachability (設計録 §8 K3 実装録): on the composite, checkpoint and DEK-register
 * paths this is the check that produces the 403 (pinned by
 * membership-negatives-composite / device-ops tests). On the value push, metadata
 * statement, manifest and attestation paths the crypto layer's declared-head
 * authorization (CRYPTO_SPEC §6.3 — `deviceStateAt`, effective permission since
 * DK K2) runs first inside signature verification and rejects a capped device
 * with 422 `chain-head-state-mismatch`; a device cap is immutable and the
 * person's role is bounded by the first stage, so no request passes the
 * declared-head check and fails here. Those call sites are defense in depth by
 * construction, not a coverage gap — do not delete them, and do not expect a
 * test to reach them.
 */
export function ensureDevicePermission(
  device: MemberWithDevice,
  minimum: Role,
  environmentId?: string,
): Effect.Effect<void, DataRejectedError> {
  if (!roleAtLeast(device.permission.role, minimum)) {
    return Effect.fail(rejectData({ kind: "insufficient-role" }));
  }
  if (
    environmentId !== undefined &&
    !scopeIncludesEnvironment(device.permission.scope, environmentId)
  ) {
    return Effect.fail(rejectData({ kind: "insufficient-scope" }));
  }
  return Effect.void;
}

/**
 * チェーン導出 role の下限検査(複合プログラム — composite-programs.ts — と共有)。
 * 第 1 段(人の role — 設計録 §8 K3-1): 端末の実効権限は人の権限を超えないので、
 * ここで落ちる主体は端末でも落ちる。署名した端末の実効権限(第 2 段)は署名検証の
 * 後に ensureDevicePermission で判定する。
 */
export function requireRole(
  state: ChainState,
  callerUserId: string,
  minimum: Role,
): Effect.Effect<ChainMember, DataRejectedError> {
  const member = state.members.get(callerUserId);
  if (member === undefined) {
    // §11-2: 非メンバーには現ヘッド・受理判定を含む一切を返さない(worker が 404 に写す)
    return Effect.fail(rejectData({ kind: "not-member" }));
  }
  return roleAtLeast(member.role, minimum)
    ? Effect.succeed(member)
    : Effect.fail(rejectData({ kind: "insufficient-role" }));
}

/**
 * 環境対象 op の scope 判定(AUTH_SPEC §12-3 の「環境 ∈ scope」列 — CRYPTO_SPEC
 * §6.2 の検証状態が導出した scope。2026-09-15 ES K3): role 下限の直後・
 * 環境の存在(データ行)の前に置く(設計録 es-design.md §9 K3-C — チェーン導出
 * 状態だけで決まる検査を、保存状態を読む検査より先に)。判定は
 * `scopeIncludesEnvironment`(`all` = 全環境)の 1 述語で、環境の作成
 * (§12-3「scope = all」行)も同じ述語で判定する — `listed` の scope に未存在の
 * 環境 id は含まれえないため `all` の主体だけが通る(§6.2 と同じ形)。
 */
function requireEnvironmentInScope<M extends ChainMember>(
  member: M,
  environmentId: string,
): Effect.Effect<M, DataRejectedError> {
  return scopeIncludesEnvironment(member.scope, environmentId)
    ? Effect.succeed(member)
    : Effect.fail(rejectData({ kind: "insufficient-scope" }));
}

/**
 * role 下限 → scope の 2 段(§12-3 の判定順)。環境対象 op のうち、チェーン全体を
 * 自前でロードする経路(複合 — composite-programs.ts、standalone checkpoint —
 * checkpoint-accept.ts)が使う。データプレーンのプログラムは
 * requireEnvironmentAccess(下)を使う。
 */
export function requireRoleInScope(
  state: ChainState,
  callerUserId: string,
  minimum: Role,
  environmentId: string,
): Effect.Effect<ChainMember, DataRejectedError> {
  return Effect.flatMap(requireRole(state, callerUserId, minimum), (member) =>
    requireEnvironmentInScope(member, environmentId),
  );
}

/**
 * requireMemberState の結果: 導出状態・履歴索引(値署名の宣言ヘッド時点検証の
 * 入力 — CRYPTO_SPEC §4.1 / §6.4)に加えて、呼び出し主体のチェーンメンバー
 * (登録署名・値署名の検証鍵と署名者 FP の源 — §5.1 / §4.1)と、プロジェクト ID
 * (= genesis エントリハッシュ。署名対象の座標)を返す。
 */
export interface MemberContext {
  readonly state: ChainState;
  readonly history: ChainHistoryIndex;
  /**
   * The caller as a **person** (role・scope・端末集合). The device that signed the
   * request is resolved later from the signature (`withSigningDevice`) or the
   * entry actor (`deviceOf`) — 設計録 §8 K3-1. Unsigned operations (reads,
   * deletions, dismissals) have no device and are judged on the person alone.
   */
  readonly member: ChainMember;
  readonly projectId: string;
}

/** 初期化済みチェーン(genesis ハッシュの存在を型で保証した StoredChain)。 */
export type InitializedChain = StoredChain & {
  readonly headHashHex: string;
  readonly genesisHashHex: string;
};

/**
 * チェーンのロードと初期化検査(データ操作・複合受理の共通前段)。未初期化は
 * not-initialized、headSeq > 0 なのに genesis / ヘッドが欠けるのはストレージ
 * 破損(defect)。
 */
export const loadInitializedChain: Effect.Effect<InitializedChain, DataRejectedError, ChainStore> =
  Effect.gen(function* () {
    const store = yield* ChainStore;
    const chain = yield* store.load;
    if (chain.headSeq === 0 || chain.headHashHex === null) {
      return yield* rejectData({ kind: "not-initialized" });
    }
    if (chain.genesisHashHex === null) {
      return yield* Effect.die(new Error("initialized chain is missing its genesis hash"));
    }
    return { ...chain, headHashHex: chain.headHashHex, genesisHashHex: chain.genesisHashHex };
  });

/**
 * データ操作に共通する前段: 未初期化の検査 → チェーン導出 → メンバーシップと
 * role 下限の検査(§12-3 の判定順)。導出はチェーン API と同じキャッシュを流用する。
 */
export const requireMemberState = (
  callerUserId: string,
  minimum: Role,
  cache: StateCache,
): Effect.Effect<MemberContext, DataRejectedError, ChainStore> =>
  Effect.gen(function* () {
    const chain = yield* loadInitializedChain;
    const { state, history } = yield* deriveStoredState(chain, cache);
    const member = yield* requireRole(state, callerUserId, minimum);
    return { state, history, member, projectId: chain.genesisHashHex };
  });

/**
 * 環境対象のデータ操作に共通する前段(§12-3): requireMemberState(未初期化 →
 * メンバーシップ → role 下限)→ **環境 ∈ 呼び出し主体の scope**(403
 * insufficient-scope)。環境の存在(データ行 — requireActiveEnvironment)は
 * この後に呼び出し側が検査する(設計録 §9 K3-C: role → scope → 存在)。
 * 環境を持たない / scope 不問の経路(環境一覧・メタのみ pull・フラグ・監査)は
 * requireMemberState をそのまま使う — 関数を分けることで「不問」と「呼び忘れ」を
 * 型で区別する。
 */
export const requireEnvironmentAccess = (
  callerUserId: string,
  minimum: Role,
  environmentId: string,
  cache: StateCache,
): Effect.Effect<MemberContext, DataRejectedError, ChainStore> =>
  Effect.gen(function* () {
    const context = yield* requireMemberState(callerUserId, minimum, cache);
    yield* requireEnvironmentInScope(context.member, environmentId);
    return context;
  });

/**
 * 環境の現エポック = チェーン導出値(CRYPTO_SPEC §6.2 / §6.3)。
 * 環境の存在自体がチェーン導出(`create_environment`)なので「未観測なら
 * 初期値 1」の既定値は持たない。データ行は複合受理(§12-4)でチェーンエントリと
 * 原子的に作られるため、アクティブなデータ行があるのにチェーンに環境がないのは
 * 不変条件違反(ストレージ / 実装バグ)であり defect として落とす。
 */
export function currentEpochOf(state: ChainState, environmentId: string): number {
  const environment = state.environments.get(environmentId);
  if (environment === undefined) {
    throw new Error("environment missing from chain-derived state");
  }
  return environment.currentEpoch;
}

/**
 * データ操作の監査イベントを組み立てる(AUDIT_SPEC §3.3)。actor の
 * auth_method は列ではなく payload JSON に載せる(§5.1: 頻出属性のみ列に昇格)。
 * actor の鍵 FP は原則持たない(チェーンミラーの専有)が、**dek.registered のみ
 * 例外**として登録署名(CRYPTO_SPEC §5.1)の署名者 FP を actorKeyFingerprintHex
 * に写す(AUDIT_SPEC §3.3 — 監査行とチェーン外署名の突合用)。
 */
export function dataEvent(
  actor: DataActor,
  serverTs: number,
  event: string,
  fields: Pick<
    AuditEventInput,
    | "environmentId"
    | "variableId"
    | "epoch"
    | "version"
    | "targetUserId"
    | "targetKeyFingerprintHex"
    | "payload"
    | "actorKeyFingerprintHex"
  >,
): AuditEventInput {
  const payload = auditPayloadWith(actor, fields.payload);
  return {
    ...fields,
    event,
    serverTs,
    actorType: "user",
    actorUserId: actor.userId,
    ...(actor.apiTokenId === undefined ? {} : { actorApiTokenId: actor.apiTokenId }),
    ...(Object.keys(payload).length === 0 ? {} : { payload }),
  };
}
