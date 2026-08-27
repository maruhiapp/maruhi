// データプレーンのストレージ(DO SQLite)を隔離する Effect サービス。
//
// - テーブルは do-schema.ts(DO コンストラクタが DDL 適用済み)
// - 環境・変数の削除は tombstone(deleted_at)。ID 再利用禁止(AUTH_SPEC §12-1)の
//   判定に使う。暗号文(variable_versions)とラップ(dek_wraps)は即時削除
// - Drizzle 見送りの判断は do-schema.ts 冒頭コメントと docs/notes/session-07.md

import { Context, Effect, Layer } from "effect";

import type {
  DekWrapInput,
  DistributedEnvManifestValue,
  DistributedMetaStatementValue,
  DistributedVariableMetaStatementValue,
  EnvManifestInput,
  MetaStatementInput,
  MetaStatementStatusInput,
  PulledVariableValue,
  RecipientDekValue,
  ValueInput,
  WireSuite,
} from "./data-plane.ts";
import { LEASE_WINDOW_MS } from "./policy.ts";
import type { StoredServerWrap } from "./server-key.ts";

interface EnvironmentRow {
  readonly environmentId: string;
  readonly name: string;
  /** 最新ステートメントの metaVersion(導出キャッシュ — metaVersion CAS 用)。 */
  readonly latestMetaVersion: number;
  readonly deletedAtMs: number | null;
}

export interface VariableRow {
  readonly variableId: string;
  readonly name: string;
  readonly latestMetaVersion: number;
  readonly latestVersion: number;
  readonly deletedAtMs: number | null;
}

/** ラップ登録署名の署名者(dek_wraps の signer_* 列に保存する)。 */
export interface WrapSignerInfo {
  readonly userId: string;
  readonly keyFingerprintHex: string;
}

/**
 * 値の writer(variable_versions の writer_* 列に保存する — 受理時点の
 * チェーン導出メンバーの user_id + 鍵 FP。CRYPTO_SPEC §4.1 / AUTH_SPEC §12-5)。
 */
export interface ValueWriterInfo {
  readonly userId: string;
  readonly keyFingerprintHex: string;
}

/**
 * 保存済みバージョンの検証アンカー: サーバー再計算の signed_bytes ハッシュと
 * 当時のエポック。次 version の prev 検査(§12-5 の 5)の入力。
 */
interface VersionAnchor {
  readonly signedBytesHashHex: string;
  readonly epoch: number;
}

/**
 * ステートメントの author(*_meta_statements の author_* 列に保存する —
 * 受理時点のチェーン導出メンバーの user_id + 鍵 FP。CRYPTO_SPEC §4.2)。
 */
export interface MetaAuthorInfo {
  readonly userId: string;
  readonly keyFingerprintHex: string;
}

/**
 * 保存済みステートメントの検証アンカー: サーバー再計算の signed_bytes ハッシュと
 * status。次 metaVersion の prev 検査と削除後の再ステートメント拒否
 * (§12-5 のメタ規則)の入力。
 */
interface MetaAnchor {
  readonly signedBytesHashHex: string;
  readonly status: MetaStatementStatusInput;
}

/**
 * variables_digest の 1 エントリ(CRYPTO_SPEC §4.3 — @maruhi/crypto の
 * VariablesDigestEntry と構造一致。data-store は crypto に依存しないため
 * 構造型で持つ)。
 */
interface VariableDigestEntryRow {
  readonly variableId: string;
  readonly status: MetaStatementStatusInput;
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
}

/**
 * checkpoint values_digest の 1 エントリ(CRYPTO_SPEC §6.2 — @maruhi/crypto の
 * EnvValuesDigestEntry と構造一致。data-store は crypto に依存しないため
 * 構造型で持つ)。2026-08-27 セッション 33 = PR-F3b。
 */
export interface CheckpointValueEntryRow {
  readonly variableId: string;
  readonly version: number;
  readonly valueSigHashHex: string;
}

/**
 * 境界 checkpoint のタプル + チェーン位置(スナップショット保存の入力 —
 * CRYPTO_SPEC §6.4 / AUTH_SPEC §16-2 の「再構成した値スナップショット列挙 +
 * 対応 checkpoint seq / hash」の座標部分)。
 */
export interface CheckpointSnapshotInput {
  readonly chainSeq: number;
  readonly entryHashHex: string;
  readonly epoch: number;
  readonly manifestVersion: number;
  readonly manifestSigHashHex: string;
  readonly valuesDigestHex: string;
}

/**
 * 保存済み最新マニフェストの検証アンカー: manifestVersion(CAS — §12-5 (6))・
 * サーバー再計算の signed_bytes ハッシュ(prev 検査 — (5))・当時のエポック
 * (predecessor のエポック単調性検査)。
 */
interface EnvManifestAnchor {
  readonly manifestVersion: number;
  readonly signedBytesHashHex: string;
  readonly epoch: number;
}

/** アクティブ数と行数(tombstone 込み)。§12-8 の数量ポリシー判定用。 */
interface ResourceCounts {
  readonly active: number;
  readonly rows: number;
}

/**
 * 保存済みラップの受信者情報(存在検査 + 上書き禁止 409 の応答材料 —
 * AUTH_SPEC §12-6)。クラスは削除経路の突合、enc 公開鍵は 409 応答に載せる
 * `storedRecipientEncPubHex` の唯一の源。
 */
interface StoredWrapRecipient {
  readonly recipientClass: string;
  readonly recipientEncPubHex: string;
}

/**
 * 書き込みの同期関数群。1 操作の全書き込み(監査追記を含む)を 1 つの同期
 * ブロック(= 同一イベントループタスク)にまとめて呼ぶことで、クラッシュ時の
 * 部分書き込みを構造的に防ぐ(DO SQLite の書き込みはタスク単位で原子コミット)。
 * 検証(読み取り)は Effect 側のメソッドで書き込みフェーズの前に済ませる。
 */
export interface DataWriteOps {
  /** 環境行の挿入。name / latest_meta_version は直後の insertEnvironmentMetaStatement が確定する。 */
  readonly insertEnvironment: (environmentId: string, name: string, nowMs: number) => void;
  /**
   * 環境ステートメント行の挿入 + 環境行キャッシュ(name / latest_meta_version)の
   * 同期更新。作成・rename・削除の全経路で同じ同期ブロック内から呼ぶ。
   */
  readonly insertEnvironmentMetaStatement: (
    environmentId: string,
    statement: MetaStatementInput,
    signedBytesHashHex: string,
    author: MetaAuthorInfo,
    nowMs: number,
  ) => void;
  /**
   * tombstone 化 + 配下データ(変数・変数ステートメント・バージョン・ラップ)の
   * 即時削除。環境自身の削除ステートメント(insertEnvironmentMetaStatement)は
   * 保存・配布し続ける(§12-4)。
   */
  readonly retireEnvironment: (environmentId: string, nowMs: number) => void;
  readonly insertVariable: (
    environmentId: string,
    variableId: string,
    name: string,
    nowMs: number,
  ) => void;
  /** 変数ステートメント行の挿入 + 変数行キャッシュの同期更新(環境版と同型)。 */
  readonly insertVariableMetaStatement: (
    environmentId: string,
    variableId: string,
    statement: MetaStatementInput,
    signedBytesHashHex: string,
    author: MetaAuthorInfo,
    nowMs: number,
  ) => void;
  /** tombstone 化 + 全バージョン(暗号文)の即時削除。deleted ステートメントは残る。 */
  readonly retireVariable: (environmentId: string, variableId: string, nowMs: number) => void;
  /**
   * 環境マニフェストの upsert(CRYPTO_SPEC §4.3 / AUTH_SPEC §12-5)。保持は
   * 環境ごとに**最新 1 通のみ**(§12-5 — 過去行を要する検証経路が存在しない)。
   * issuer は受理時点のチェーン導出メンバー(= 署名検証に使った鍵の持ち主)。
   */
  readonly upsertEnvironmentManifest: (
    environmentId: string,
    manifest: EnvManifestInput,
    signedBytesHashHex: string,
    issuer: MetaAuthorInfo,
    nowMs: number,
  ) => void;
  /**
   * 境界 checkpoint の値スナップショットの保存(CRYPTO_SPEC §6.4 / AUTH_SPEC
   * §16-2 — 2026-08-27): 環境ごとの最新包含 checkpoint のタプルを upsert し、
   * 値スナップショット列挙を環境単位で全置換する。payload に含まれない環境の
   * 既存スナップショットは変更しない(A のみ再 checkpoint しても B の基準は
   * 失われない — §6.4)。チェーン追記と同じ同期ブロック内から呼ぶ。
   */
  readonly upsertCheckpointSnapshot: (
    environmentId: string,
    checkpoint: CheckpointSnapshotInput,
    values: readonly CheckpointValueEntryRow[],
    nowMs: number,
  ) => void;
  /** バージョン行の挿入と latest_version の前進(書き込みロック下で呼ぶ)。 */
  readonly insertVersion: (
    environmentId: string,
    variableId: string,
    value: ValueInput,
    ciphertextBytes: number,
    signedBytesHashHex: string,
    writer: ValueWriterInfo,
    nowMs: number,
  ) => void;
  /**
   * ラップ行の挿入。signer は登録受理時のチェーン導出メンバー(= 署名検証に
   * 使った鍵の持ち主 — CRYPTO_SPEC §5.1)。
   */
  readonly insertWrap: (
    environmentId: string,
    wrap: DekWrapInput,
    signer: WrapSignerInfo,
    nowMs: number,
  ) => void;
  /** §12-6 修復経路: 1 ラップの削除(存在検証は呼び出し側が済ませる)。 */
  readonly deleteWrap: (environmentId: string, epoch: number, recipientUserId: string) => void;
  /**
   * §12-6 の再追加受理時掃除(2026-08-15): 対象 user_id 宛(受信者クラス
   * member)で受信者 enc 公開鍵が `keepEncPubHex` と一致しないラップを削除し、
   * 削除した (環境, エポック) を返す(dek.deleted の監査行の材料)。現行チェーン
   * 鍵のラップは対象にならない(上書き禁止の不変条件は不変)。add_member 受理の
   * 書き込みフェーズ(単一タスク)内から呼ぶ。
   */
  readonly deleteStaleMemberWraps: (
    recipientUserId: string,
    keepEncPubHex: string,
  ) => readonly StaleWrapRef[];
}

/** 掃除で削除されたラップの座標(dek.deleted 監査行の材料)。 */
export interface StaleWrapRef {
  readonly environmentId: string;
  readonly epoch: number;
}

interface DataStoreShape {
  readonly findEnvironment: (environmentId: string) => Effect.Effect<EnvironmentRow | null>;
  readonly countEnvironments: Effect.Effect<ResourceCounts>;
  readonly environmentNameTaken: (
    name: string,
    excludeEnvironmentId: string | null,
  ) => Effect.Effect<boolean>;
  /** 全環境(削除済み込み)の最新ステートメント付き一覧(環境一覧応答用)。 */
  readonly listEnvironmentStatements: Effect.Effect<
    readonly { environmentId: string; statement: DistributedMetaStatementValue }[]
  >;
  /** 1 環境の最新ステートメント(pull 応答用。行が無いのは不変条件違反 = null)。 */
  readonly environmentStatement: (
    environmentId: string,
  ) => Effect.Effect<DistributedMetaStatementValue | null>;
  /** 環境ステートメントの検証アンカー(prev 検査 — §12-5 のメタ規則)。 */
  readonly environmentMetaAnchor: (
    environmentId: string,
    metaVersion: number,
  ) => Effect.Effect<MetaAnchor | null>;
  /**
   * 最新の環境マニフェスト(配布形 — §12-7 の同梱材料)。マニフェスト導入前に
   * 作成された環境は初期化(最初のメタ操作 / rotate)まで null(移行の過渡状態)。
   */
  readonly environmentManifest: (
    environmentId: string,
  ) => Effect.Effect<DistributedEnvManifestValue | null>;
  /**
   * 最新マニフェストの検証アンカー(manifestVersion CAS = §12-5 (6) と prev
   * 検査 = (5) の材料。epoch は predecessor のエポック単調性検査に使う)。
   */
  readonly environmentManifestAnchor: (
    environmentId: string,
  ) => Effect.Effect<EnvManifestAnchor | null>;

  readonly findVariable: (
    environmentId: string,
    variableId: string,
  ) => Effect.Effect<VariableRow | null>;
  readonly countVariables: (environmentId: string) => Effect.Effect<ResourceCounts>;
  readonly variableNameTaken: (
    environmentId: string,
    name: string,
    excludeVariableId: string | null,
  ) => Effect.Effect<boolean>;
  readonly listActiveVariables: (
    environmentId: string,
  ) => Effect.Effect<readonly { variableId: string; name: string }[]>;
  /** 変数ステートメントの検証アンカー(prev 検査 — §12-5 のメタ規則)。 */
  readonly variableMetaAnchor: (
    environmentId: string,
    variableId: string,
    metaVersion: number,
  ) => Effect.Effect<MetaAnchor | null>;
  /** 削除済み変数の deleted ステートメント一覧(pull で配布し続ける — §12-5)。 */
  readonly deletedVariableStatements: (
    environmentId: string,
  ) => Effect.Effect<readonly DistributedVariableMetaStatementValue[]>;
  /** アクティブ変数の最新ステートメント一覧(メタデータのみモード — §12-7)。 */
  readonly activeVariableStatements: (
    environmentId: string,
  ) => Effect.Effect<readonly DistributedVariableMetaStatementValue[]>;
  /**
   * 全変数(tombstone 込み)の最新ステートメントのダイジェストタプル
   * (CRYPTO_SPEC §4.3 の variables_digest 再計算材料 — §12-5 (7))。
   * metaSigHashHex はサーバー再計算の signed_bytes ハッシュ。
   */
  readonly variableDigestEntries: (
    environmentId: string,
  ) => Effect.Effect<readonly VariableDigestEntryRow[]>;
  /**
   * checkpoint values_digest の再計算材料(§6.4 の内容突合 — 受理時点の保存
   * 状態): active 変数の最新 version とサーバー再計算の value_signed_bytes
   * ハッシュ。tombstone は含めない(§6.2 — active 変数のみ。tombstone は
   * マニフェスト側が捕捉する)。
   */
  readonly checkpointValueEntries: (
    environmentId: string,
  ) => Effect.Effect<readonly CheckpointValueEntryRow[]>;

  /** アクティブ変数の最新バージョン + 最新ステートメント一覧(一括 pull 用)。 */
  readonly latestVersions: (
    environmentId: string,
  ) => Effect.Effect<
    readonly (PulledVariableValue & { statement: DistributedVariableMetaStatementValue })[]
  >;
  /** 保存済みバージョンの検証アンカー(prev 検査 — §12-5 の 5)。 */
  readonly versionAnchor: (
    environmentId: string,
    variableId: string,
    version: number,
  ) => Effect.Effect<VersionAnchor | null>;
  /** プロジェクトの累積暗号文バイト(現在保存中の量。§12-8)。 */
  readonly totalCiphertextBytes: Effect.Effect<number>;

  readonly countWrapsForEpoch: (environmentId: string, epoch: number) => Effect.Effect<number>;
  /** プロジェクト全体の DEK ラップ行数(現在保存中の量。§12-8)。 */
  readonly countWrapRows: Effect.Effect<number>;
  /**
   * 保存済みラップの受信者クラスと enc 公開鍵(行がなければ null)。削除経路は
   * クラスとリクエストの class を突合する — クライアント申告の class をそのまま
   * 監査列の選択に使わせない(AUDIT_SPEC §1-2 の列意味論をワイヤ入力から切り離す)。
   * enc 公開鍵は上書き禁止 409 の応答材料(AUTH_SPEC §12-6 — 2026-08-15)。
   */
  readonly wrapStoredRecipient: (
    environmentId: string,
    epoch: number,
    recipientUserId: string,
  ) => Effect.Effect<StoredWrapRecipient | null>;
  readonly listWrapsForRecipient: (
    environmentId: string,
    recipientUserId: string,
  ) => Effect.Effect<readonly RecipientDekValue[]>;
  /**
   * サーバー鍵 FP 宛のラップ(受信者クラス server)を全エポック分返す
   * (AUTH_SPEC §14 のリース経路 — CRYPTO_SPEC §9.1)。listWrapsForRecipient と
   * 分けているのは配布の意味論が違うため: あちらは**受信者本人への配布**で
   * 登録署名と署名者情報を運ぶが、こちらは**サーバー自身が開封する材料**であり
   * 応答へは出ない(開封 → 再ラップの結果だけが出る — server-key.ts)。
   */
  readonly listServerWraps: (
    environmentId: string,
    serverKeyFingerprintHex: string,
  ) => Effect.Effect<readonly StoredServerWrap[]>;
  /**
   * 固定窓の**判定のみ**(消費しない — §14-3 / AUDIT_SPEC §3.5)。窓が切れて
   * いれば 0 から数え直した扱いになる。判定と消費を分けているのは、
   * 「窓を消費してよいのは実際に発行した(記録した)ときだけ」という規律を
   * 呼び出し側で表現するため(pullfrog 指摘 — PR #65)。
   */
  readonly checkLeaseWindow: (
    kind: LeaseWindowKind,
    limit: number,
    nowMs: number,
  ) => Effect.Effect<LeaseWindowDecision>;
  /**
   * 固定窓の消費(1 件計上)。窓が切れていれば開始時刻を now に巻き直す。
   * DO の permit 下で直列化されているため、判定 → 消費の間に割り込みはない。
   */
  readonly recordLeaseWindowUse: (kind: LeaseWindowKind, nowMs: number) => void;
  /**
   * 先着束縛(AUTH_SPEC §14-1。2026-08-15 裁定)の照会: 生存期限内の束縛行が
   * あれば束縛先の一時公開鍵を返す。期限切れ行は**行の物理削除(GC)に依存せず**
   * expires_at 条件で無視する — 判定の正しさを GC のタイミングから切り離す。
   * `bindingKeyHex` は JWS signing input のハッシュ(生トークンのハッシュでは
   * ない — programs-lease.ts の LeaseTokenFacts.bindingKeyHex の doc)。
   */
  readonly leaseBinding: (bindingKeyHex: string, nowMs: number) => Effect.Effect<string | null>;
  /**
   * 先着束縛の記録(発行・監査・窓消費と同一の同期ブロックで呼ぶ — §14-1)。
   * 既存行(同一キー + 同一鍵の冪等リトライ)は上書きしない。あわせて
   * 期限切れ行を GC する(行数の上界 = 発行レート窓 × 保持期間 — policy.ts)。
   */
  readonly recordLeaseBinding: (
    bindingKeyHex: string,
    ephemeralPubHex: string,
    expiresAtMs: number,
    nowMs: number,
  ) => void;

  readonly write: DataWriteOps;
}

/** 固定窓の種別(§14-3 発行 / AUDIT_SPEC §3.5 拒否記録)。 */
type LeaseWindowKind = "issued" | "denied";

/** 固定窓の判定結果(超過時は窓の残り秒数を返す — §13-3 の先例と同型)。 */
interface LeaseWindowDecision {
  readonly allowed: boolean;
  readonly retryAfterSeconds: number;
}

export class DataStore extends Context.Service<DataStore, DataStoreShape>()("DataStore") {}

// ---------------------------------------------------------------------------
// 行デコードの安全層: 必須列の存在・型を検査し、不一致は説明付き defect にする。
// String(...) / Number(...) の素通しは列名 typo / rename を文字列 "undefined" や
// NaN として通過させるため、行 → ドメイン型の写像は必ずここを経由する
// (storedSuite / statementOf の status 検査 — 「未知値は defect」— の全列への拡張)。
// ---------------------------------------------------------------------------

type StoredRow = Record<string, unknown>;

/** 列の存在検査(SELECT 句とデコーダの列名不一致 = 実装バグの検出)。 */
function columnValue(row: StoredRow, column: string): unknown {
  const value = row[column];
  if (value === undefined) {
    throw new Error(`stored row is missing column "${column}"`);
  }
  return value;
}

function stringColumn(row: StoredRow, column: string): string {
  const value = columnValue(row, column);
  if (typeof value !== "string") {
    throw new Error(`stored column "${column}" is not a string`);
  }
  return value;
}

function numberColumn(row: StoredRow, column: string): number {
  const value = columnValue(row, column);
  if (typeof value !== "number") {
    throw new Error(`stored column "${column}" is not a number`);
  }
  return value;
}

function nullableNumberColumn(row: StoredRow, column: string): number | null {
  const value = columnValue(row, column);
  if (value !== null && typeof value !== "number") {
    throw new Error(`stored column "${column}" is not a number or NULL`);
  }
  return value;
}

function countsOf(row: StoredRow | undefined): ResourceCounts {
  if (row === undefined) {
    return { active: 0, rows: 0 };
  }
  // SUM(CASE ...) は 0 行のとき NULL を返すため 0 に読み替える(COUNT は常に数値)
  const active = nullableNumberColumn(row, "active_rows");
  return { active: active ?? 0, rows: numberColumn(row, "total_rows") };
}

/**
 * 保存済み suite 列の読み出し。書き込み経路は Schema の Literal(§12-2)が
 * 強制するため、既知以外の値はストレージ破損として defect に落とす
 * (cast で握り潰さない)。
 */
function storedSuite(value: unknown): WireSuite {
  if (value !== "maruhi/v1") {
    throw new Error("unexpected suite in stored row");
  }
  return value;
}

/**
 * メタステートメント列(environmentId / variableId を除く共通部)のデコード。
 * prefix は latestVersions の SQL 別名(ms_*)用 — 擬似行オブジェクトの組み立てを
 * せず、別名付きの行をそのまま読む。
 */
function statementColumns(
  row: StoredRow,
  prefix: string,
): Omit<DistributedMetaStatementValue, "environmentId"> {
  const status = stringColumn(row, `${prefix}status`);
  if (status !== "active" && status !== "deleted") {
    // 書き込み経路は Schema の Literal が強制する(既知以外はストレージ破損)
    throw new Error("unexpected status in stored meta statement row");
  }
  return {
    suite: storedSuite(columnValue(row, `${prefix}suite`)),
    name: stringColumn(row, `${prefix}name`),
    status,
    metaVersion: numberColumn(row, `${prefix}meta_version`),
    prevMetaSigHashHex: stringColumn(row, `${prefix}prev_meta_sig_hash_hex`),
    chainHeadHashHex: stringColumn(row, `${prefix}chain_head_hash_hex`),
    chainHeadSeq: numberColumn(row, `${prefix}chain_head_seq`),
    signatureHex: stringColumn(row, `${prefix}signature_hex`),
    authorUserId: stringColumn(row, `${prefix}author_user_id`),
    authorKeyFingerprintHex: stringColumn(row, `${prefix}author_key_fingerprint`),
  };
}

/** メタステートメント行 → 配布形(author 込み。environmentId は列から取る)。 */
function statementOf(row: StoredRow): DistributedMetaStatementValue {
  return { environmentId: stringColumn(row, "environment_id"), ...statementColumns(row, "") };
}

function variableStatementOf(row: StoredRow): DistributedVariableMetaStatementValue {
  return { ...statementOf(row), variableId: stringColumn(row, "variable_id") };
}

function anchorOf(row: StoredRow | undefined): MetaAnchor | null {
  if (row === undefined) {
    return null;
  }
  const status = stringColumn(row, "status");
  if (status !== "active" && status !== "deleted") {
    throw new Error("unexpected status in stored meta statement row");
  }
  return { signedBytesHashHex: stringColumn(row, "signed_bytes_hash_hex"), status };
}

// 配布(§12-2)は signed_bytes_hash_hex を選択しない = 配布しない(検証者が
// 自ら再計算する)。アンカー照会(anchorOf)だけがハッシュ列を読む
const MS_COLUMNS =
  "ms.environment_id, ms.suite, ms.name, ms.status, ms.meta_version, ms.prev_meta_sig_hash_hex, ms.chain_head_hash_hex, ms.chain_head_seq, ms.signature_hex, ms.author_user_id, ms.author_key_fingerprint";

const makeEnvironmentQueries = (sql: SqlStorage) => ({
  findEnvironment: (environmentId: string) =>
    Effect.sync(() => {
      const row = sql
        .exec(
          "SELECT environment_id, name, latest_meta_version, deleted_at FROM environments WHERE environment_id = ?",
          environmentId,
        )
        .toArray()[0];
      if (row === undefined) {
        return null;
      }
      return {
        environmentId: stringColumn(row, "environment_id"),
        name: stringColumn(row, "name"),
        latestMetaVersion: numberColumn(row, "latest_meta_version"),
        deletedAtMs: nullableNumberColumn(row, "deleted_at"),
      };
    }),
  countEnvironments: Effect.sync(() => {
    const row = sql
      .exec(
        `SELECT COUNT(*) AS total_rows, SUM(CASE WHEN deleted_at IS NULL THEN 1 ELSE 0 END) AS active_rows
         FROM environments`,
      )
      .toArray()[0];
    return countsOf(row);
  }),
  environmentNameTaken: (name: string, excludeEnvironmentId: string | null) =>
    Effect.sync(() => {
      const rows = sql
        .exec(
          `SELECT 1 FROM environments
           WHERE name = ? AND deleted_at IS NULL AND environment_id != ? LIMIT 1`,
          name,
          excludeEnvironmentId ?? "",
        )
        .toArray();
      return rows.length > 0;
    }),
  // 削除済み環境も deleted ステートメント付きで列挙する(削除の否認・無断
  // 復活の検出材料 — §12-4。クライアントはステートメントの status で判別する)
  listEnvironmentStatements: Effect.sync(() =>
    sql
      .exec(
        `SELECT ${MS_COLUMNS}
         FROM environments e
         JOIN environment_meta_statements ms
           ON ms.environment_id = e.environment_id
          AND ms.meta_version = e.latest_meta_version
         ORDER BY e.created_at, e.environment_id`,
      )
      .toArray()
      .map((row) => ({
        environmentId: stringColumn(row, "environment_id"),
        statement: statementOf(row),
      })),
  ),
  environmentStatement: (environmentId: string) =>
    Effect.sync(() => {
      const row = sql
        .exec(
          `SELECT ${MS_COLUMNS}
           FROM environments e
           JOIN environment_meta_statements ms
             ON ms.environment_id = e.environment_id
            AND ms.meta_version = e.latest_meta_version
           WHERE e.environment_id = ?`,
          environmentId,
        )
        .toArray()[0];
      return row === undefined ? null : statementOf(row);
    }),
  environmentMetaAnchor: (environmentId: string, metaVersion: number) =>
    Effect.sync(() =>
      anchorOf(
        sql
          .exec(
            `SELECT signed_bytes_hash_hex, status FROM environment_meta_statements
             WHERE environment_id = ? AND meta_version = ?`,
            environmentId,
            metaVersion,
          )
          .toArray()[0],
      ),
    ),
  // 配布(§12-2)は signed_bytes_hash_hex を選択しない = 配布しない(検証者が
  // 自ら再計算する — ステートメント配布と同じ規律)
  environmentManifest: (environmentId: string) =>
    Effect.sync(() => {
      const row = sql
        .exec(
          `SELECT environment_id, suite, epoch, manifest_version, variables_digest_hex,
                  env_meta_version, env_meta_sig_hash_hex, prev_manifest_sig_hash_hex,
                  chain_head_hash_hex, chain_head_seq, signature_hex,
                  issuer_user_id, issuer_key_fingerprint
           FROM environment_manifests WHERE environment_id = ?`,
          environmentId,
        )
        .toArray()[0];
      if (row === undefined) {
        return null;
      }
      return {
        environmentId: stringColumn(row, "environment_id"),
        suite: storedSuite(columnValue(row, "suite")),
        epoch: numberColumn(row, "epoch"),
        manifestVersion: numberColumn(row, "manifest_version"),
        variablesDigestHex: stringColumn(row, "variables_digest_hex"),
        envMetaVersion: numberColumn(row, "env_meta_version"),
        envMetaSigHashHex: stringColumn(row, "env_meta_sig_hash_hex"),
        prevManifestSigHashHex: stringColumn(row, "prev_manifest_sig_hash_hex"),
        chainHeadHashHex: stringColumn(row, "chain_head_hash_hex"),
        chainHeadSeq: numberColumn(row, "chain_head_seq"),
        signatureHex: stringColumn(row, "signature_hex"),
        issuerUserId: stringColumn(row, "issuer_user_id"),
        issuerKeyFingerprintHex: stringColumn(row, "issuer_key_fingerprint"),
      };
    }),
  environmentManifestAnchor: (environmentId: string) =>
    Effect.sync(() => {
      const row = sql
        .exec(
          `SELECT manifest_version, signed_bytes_hash_hex, epoch
           FROM environment_manifests WHERE environment_id = ?`,
          environmentId,
        )
        .toArray()[0];
      if (row === undefined) {
        return null;
      }
      return {
        manifestVersion: numberColumn(row, "manifest_version"),
        signedBytesHashHex: stringColumn(row, "signed_bytes_hash_hex"),
        epoch: numberColumn(row, "epoch"),
      };
    }),
});

const makeVariableQueries = (sql: SqlStorage) => ({
  findVariable: (environmentId: string, variableId: string) =>
    Effect.sync(() => {
      const row = sql
        .exec(
          `SELECT variable_id, name, latest_meta_version, latest_version, deleted_at FROM variables
           WHERE environment_id = ? AND variable_id = ?`,
          environmentId,
          variableId,
        )
        .toArray()[0];
      if (row === undefined) {
        return null;
      }
      return {
        variableId: stringColumn(row, "variable_id"),
        name: stringColumn(row, "name"),
        latestMetaVersion: numberColumn(row, "latest_meta_version"),
        latestVersion: numberColumn(row, "latest_version"),
        deletedAtMs: nullableNumberColumn(row, "deleted_at"),
      };
    }),
  variableMetaAnchor: (environmentId: string, variableId: string, metaVersion: number) =>
    Effect.sync(() =>
      anchorOf(
        sql
          .exec(
            `SELECT signed_bytes_hash_hex, status FROM variable_meta_statements
             WHERE environment_id = ? AND variable_id = ? AND meta_version = ?`,
            environmentId,
            variableId,
            metaVersion,
          )
          .toArray()[0],
      ),
    ),
  deletedVariableStatements: (environmentId: string) =>
    Effect.sync(() =>
      sql
        .exec(
          `SELECT ms.variable_id, ${MS_COLUMNS}
           FROM variables v
           JOIN variable_meta_statements ms
             ON ms.environment_id = v.environment_id
            AND ms.variable_id = v.variable_id
            AND ms.meta_version = v.latest_meta_version
           WHERE v.environment_id = ? AND v.deleted_at IS NOT NULL
           ORDER BY v.created_at, v.variable_id`,
          environmentId,
        )
        .toArray()
        .map(variableStatementOf),
    ),
  // deletedVariableStatements の active 側(メタデータのみモード — §12-7):
  // 最新ステートメントのみ。値・DEK は選択しない(配布しないため触りもしない)
  activeVariableStatements: (environmentId: string) =>
    Effect.sync(() =>
      sql
        .exec(
          `SELECT ms.variable_id, ${MS_COLUMNS}
           FROM variables v
           JOIN variable_meta_statements ms
             ON ms.environment_id = v.environment_id
            AND ms.variable_id = v.variable_id
            AND ms.meta_version = v.latest_meta_version
           WHERE v.environment_id = ? AND v.deleted_at IS NULL
           ORDER BY v.created_at, v.variable_id`,
          environmentId,
        )
        .toArray()
        .map(variableStatementOf),
    ),
  countVariables: (environmentId: string) =>
    Effect.sync(() => {
      const row = sql
        .exec(
          `SELECT COUNT(*) AS total_rows, SUM(CASE WHEN deleted_at IS NULL THEN 1 ELSE 0 END) AS active_rows
           FROM variables WHERE environment_id = ?`,
          environmentId,
        )
        .toArray()[0];
      return countsOf(row);
    }),
  // variables_digest の再計算材料(§12-5 (7)): tombstone 込みの全変数の最新形。
  // 正規順(variable_id のバイト昇順)は crypto の computeVariablesDigest が
  // 内部で確立するため、ここでは順序を規範にしない
  variableDigestEntries: (environmentId: string) =>
    Effect.sync(() =>
      sql
        .exec(
          `SELECT v.variable_id, ms.status, ms.meta_version, ms.signed_bytes_hash_hex
           FROM variables v
           JOIN variable_meta_statements ms
             ON ms.environment_id = v.environment_id
            AND ms.variable_id = v.variable_id
            AND ms.meta_version = v.latest_meta_version
           WHERE v.environment_id = ?
           ORDER BY v.variable_id`,
          environmentId,
        )
        .toArray()
        .map((row): VariableDigestEntryRow => {
          const status = stringColumn(row, "status");
          if (status !== "active" && status !== "deleted") {
            throw new Error("unexpected status in stored meta statement row");
          }
          return {
            variableId: stringColumn(row, "variable_id"),
            status,
            metaVersion: numberColumn(row, "meta_version"),
            metaSigHashHex: stringColumn(row, "signed_bytes_hash_hex"),
          };
        }),
    ),
  // checkpoint values_digest の再計算材料(§6.4): active 変数の最新 version と
  // 保存済み value_signed_bytes ハッシュ。正規順(variable_id のバイト昇順)は
  // crypto の computeEnvValuesDigest が内部で確立するため、順序を規範にしない
  checkpointValueEntries: (environmentId: string) =>
    Effect.sync(() =>
      sql
        .exec(
          `SELECT v.variable_id, vv.version, vv.signed_bytes_hash_hex
           FROM variables v
           JOIN variable_versions vv
             ON vv.environment_id = v.environment_id
            AND vv.variable_id = v.variable_id
            AND vv.version = v.latest_version
           WHERE v.environment_id = ? AND v.deleted_at IS NULL
           ORDER BY v.variable_id`,
          environmentId,
        )
        .toArray()
        .map((row): CheckpointValueEntryRow => ({
          variableId: stringColumn(row, "variable_id"),
          version: numberColumn(row, "version"),
          valueSigHashHex: stringColumn(row, "signed_bytes_hash_hex"),
        })),
    ),
  variableNameTaken: (environmentId: string, name: string, excludeVariableId: string | null) =>
    Effect.sync(() => {
      const rows = sql
        .exec(
          `SELECT 1 FROM variables
           WHERE environment_id = ? AND name = ? AND deleted_at IS NULL AND variable_id != ? LIMIT 1`,
          environmentId,
          name,
          excludeVariableId ?? "",
        )
        .toArray();
      return rows.length > 0;
    }),
  listActiveVariables: (environmentId: string) =>
    Effect.sync(() =>
      sql
        .exec(
          `SELECT variable_id, name FROM variables
           WHERE environment_id = ? AND deleted_at IS NULL ORDER BY created_at, variable_id`,
          environmentId,
        )
        .toArray()
        .map((row) => ({
          variableId: stringColumn(row, "variable_id"),
          name: stringColumn(row, "name"),
        })),
    ),
});

const makeVersionQueries = (sql: SqlStorage) => ({
  // 配布(§12-7)は保存済みの署名ブロックと writer / author をそのまま返す
  // (現メンバー集合から再導出しない — 削除済み writer / author の過去データの
  // 検証可能性)。signed_bytes_hash_hex は値・ステートメントとも選択しない =
  // 配布しない(AUTH_SPEC §12-2)
  latestVersions: (environmentId: string) =>
    Effect.sync(() =>
      sql
        .exec(
          `SELECT v.variable_id, vv.version, vv.suite, vv.epoch, vv.nonce_hex, vv.ciphertext_hex,
                  vv.prev_value_sig_hash_hex, vv.chain_head_hash_hex, vv.chain_head_seq,
                  vv.signature_hex, vv.writer_user_id, vv.writer_key_fingerprint,
                  ms.suite AS ms_suite, ms.name AS ms_name, ms.status AS ms_status,
                  ms.meta_version AS ms_meta_version,
                  ms.prev_meta_sig_hash_hex AS ms_prev_meta_sig_hash_hex,
                  ms.chain_head_hash_hex AS ms_chain_head_hash_hex,
                  ms.chain_head_seq AS ms_chain_head_seq,
                  ms.signature_hex AS ms_signature_hex,
                  ms.author_user_id AS ms_author_user_id,
                  ms.author_key_fingerprint AS ms_author_key_fingerprint
           FROM variables v
           JOIN variable_versions vv
             ON vv.environment_id = v.environment_id
            AND vv.variable_id = v.variable_id
            AND vv.version = v.latest_version
           JOIN variable_meta_statements ms
             ON ms.environment_id = v.environment_id
            AND ms.variable_id = v.variable_id
            AND ms.meta_version = v.latest_meta_version
           WHERE v.environment_id = ? AND v.deleted_at IS NULL
           ORDER BY v.created_at, v.variable_id`,
          environmentId,
        )
        .toArray()
        .map((row) => ({
          variableId: stringColumn(row, "variable_id"),
          version: numberColumn(row, "version"),
          suite: storedSuite(columnValue(row, "suite")),
          epoch: numberColumn(row, "epoch"),
          nonceHex: stringColumn(row, "nonce_hex"),
          ciphertextHex: stringColumn(row, "ciphertext_hex"),
          prevValueSigHashHex: stringColumn(row, "prev_value_sig_hash_hex"),
          chainHeadHashHex: stringColumn(row, "chain_head_hash_hex"),
          chainHeadSeq: numberColumn(row, "chain_head_seq"),
          signatureHex: stringColumn(row, "signature_hex"),
          writerUserId: stringColumn(row, "writer_user_id"),
          writerKeyFingerprintHex: stringColumn(row, "writer_key_fingerprint"),
          // ステートメント部は ms_* 別名列をそのまま読む(statementColumns の
          // prefix)。環境 ID は WHERE 句の引数、変数 ID は行の値
          statement: {
            environmentId,
            variableId: stringColumn(row, "variable_id"),
            ...statementColumns(row, "ms_"),
          },
        })),
    ),
  versionAnchor: (environmentId: string, variableId: string, version: number) =>
    Effect.sync(() => {
      const row = sql
        .exec(
          `SELECT signed_bytes_hash_hex, epoch FROM variable_versions
           WHERE environment_id = ? AND variable_id = ? AND version = ?`,
          environmentId,
          variableId,
          version,
        )
        .toArray()[0];
      if (row === undefined) {
        return null;
      }
      return {
        signedBytesHashHex: stringColumn(row, "signed_bytes_hash_hex"),
        epoch: numberColumn(row, "epoch"),
      };
    }),
  totalCiphertextBytes: Effect.sync(() => {
    const row = sql
      .exec("SELECT COALESCE(SUM(ciphertext_bytes), 0) AS total FROM variable_versions")
      .toArray()[0];
    return row === undefined ? 0 : numberColumn(row, "total");
  }),
});

const makeWrapQueries = (sql: SqlStorage) => ({
  countWrapsForEpoch: (environmentId: string, epoch: number) =>
    Effect.sync(() => {
      const row = sql
        .exec(
          "SELECT COUNT(*) AS n FROM dek_wraps WHERE environment_id = ? AND epoch = ?",
          environmentId,
          epoch,
        )
        .toArray()[0];
      return row === undefined ? 0 : numberColumn(row, "n");
    }),
  countWrapRows: Effect.sync(() => {
    const row = sql.exec("SELECT COUNT(*) AS n FROM dek_wraps").toArray()[0];
    return row === undefined ? 0 : numberColumn(row, "n");
  }),
  wrapStoredRecipient: (environmentId: string, epoch: number, recipientUserId: string) =>
    Effect.sync(() => {
      const row = sql
        .exec(
          "SELECT recipient_class, recipient_enc_pub_hex FROM dek_wraps WHERE environment_id = ? AND epoch = ? AND recipient_user_id = ? LIMIT 1",
          environmentId,
          epoch,
          recipientUserId,
        )
        .toArray()[0];
      return row === undefined
        ? null
        : {
            recipientClass: stringColumn(row, "recipient_class"),
            recipientEncPubHex: stringColumn(row, "recipient_enc_pub_hex"),
          };
    }),
  // 配布は本人宛のみ(§12-6)。server クラスの行は識別子形式が交わらないため
  // user_id では引けないが、クラス条件を明示して境界を固定する
  listWrapsForRecipient: (environmentId: string, recipientUserId: string) =>
    Effect.sync(() =>
      selectWrapRows(sql, {
        environmentId,
        recipientClass: "member",
        recipientUserId,
        extraColumns: "signature_hex, signer_user_id, signer_key_fingerprint",
      }).map((row) => ({
        ...wrapBodyOf(row),
        signatureHex: stringColumn(row, "signature_hex"),
        signerUserId: stringColumn(row, "signer_user_id"),
        signerKeyFingerprintHex: stringColumn(row, "signer_key_fingerprint"),
      })),
    ),
  // FP でも絞るのは、失効 → 別鍵での再 grant を挟んだ環境に旧サーバー鍵宛の
  // 行が残っていた場合に、現行鍵で開封できない行を掴まないため(開封失敗は
  // 毒ラップと区別できず、503 の理由を濁らせる)
  listServerWraps: (environmentId: string, serverKeyFingerprintHex: string) =>
    Effect.sync(() =>
      selectWrapRows(sql, {
        environmentId,
        recipientClass: "server",
        recipientUserId: serverKeyFingerprintHex,
      }).map((row) => wrapBodyOf(row)),
    ),
  checkLeaseWindow: (kind: LeaseWindowKind, limit: number, nowMs: number) =>
    Effect.sync(() => {
      const current = leaseWindowRow(sql, kind, nowMs);
      // 窓切れ・初回・時計の巻き戻しはいずれも「0 から数え直し」= 常に許可
      if (current === null || current.count < limit) {
        return { allowed: true, retryAfterSeconds: 0 };
      }
      return {
        allowed: false,
        retryAfterSeconds: Math.ceil((LEASE_WINDOW_MS - current.elapsed) / 1000),
      };
    }),
  recordLeaseWindowUse: (kind: LeaseWindowKind, nowMs: number) => {
    if (leaseWindowRow(sql, kind, nowMs) === null) {
      sql.exec(
        `INSERT INTO lease_windows (kind, window_start, count) VALUES (?, ?, 1)
         ON CONFLICT(kind) DO UPDATE SET window_start = excluded.window_start, count = 1`,
        kind,
        nowMs,
      );
      return;
    }
    sql.exec("UPDATE lease_windows SET count = count + 1 WHERE kind = ?", kind);
  },
  leaseBinding: (bindingKeyHex: string, nowMs: number) =>
    Effect.sync(() => {
      const row = sql
        .exec(
          "SELECT ephemeral_pub_hex FROM lease_bindings WHERE binding_key_hex = ? AND expires_at > ?",
          bindingKeyHex,
          nowMs,
        )
        .toArray()[0];
      return row === undefined ? null : stringColumn(row, "ephemeral_pub_hex");
    }),
  recordLeaseBinding: (
    bindingKeyHex: string,
    ephemeralPubHex: string,
    expiresAtMs: number,
    nowMs: number,
  ) => {
    // GC を先に置くことで、期限切れの同一キー残骸が主キー衝突で新しい束縛の
    // 記録を妨げない(照会側は expires_at 条件で既に無視している)
    sql.exec("DELETE FROM lease_bindings WHERE expires_at <= ?", nowMs);
    sql.exec(
      `INSERT INTO lease_bindings (binding_key_hex, ephemeral_pub_hex, expires_at)
       VALUES (?, ?, ?) ON CONFLICT(binding_key_hex) DO NOTHING`,
      bindingKeyHex,
      ephemeralPubHex,
      expiresAtMs,
    );
  },
});

/**
 * 現在有効な固定窓の行(窓切れ・初回・時計の巻き戻しは null = 数え直し)。
 * 判定と消費が同じ「有効な窓」の定義を共有するための 1 箇所。
 */
function leaseWindowRow(
  sql: SqlStorage,
  kind: LeaseWindowKind,
  nowMs: number,
): { readonly count: number; readonly elapsed: number } | null {
  const row = sql
    .exec("SELECT window_start, count FROM lease_windows WHERE kind = ?", kind)
    .toArray()[0];
  if (row === undefined) {
    return null;
  }
  const elapsed = nowMs - numberColumn(row, "window_start");
  if (elapsed >= LEASE_WINDOW_MS || elapsed < 0) {
    return null;
  }
  return { count: numberColumn(row, "count"), elapsed };
}

/**
 * ラップ行の共通 SELECT(配布とリース材料で列だけが違う)。並びは epoch 昇順。
 */
function selectWrapRows(
  sql: SqlStorage,
  query: {
    readonly environmentId: string;
    readonly recipientClass: "member" | "server";
    readonly recipientUserId: string;
    readonly extraColumns?: string;
  },
): readonly Record<string, SqlStorageValue>[] {
  const extra = query.extraColumns === undefined ? "" : `, ${query.extraColumns}`;
  return sql
    .exec(
      `SELECT suite, epoch, enc_hex, ciphertext_hex${extra}
       FROM dek_wraps
       WHERE environment_id = ? AND recipient_class = ? AND recipient_user_id = ?
       ORDER BY epoch`,
      query.environmentId,
      query.recipientClass,
      query.recipientUserId,
    )
    .toArray();
}

/**
 * ラップ行の共通部。`storedSuite` は未知スイートを defect にする(v1 の書き込み
 * 経路では生まれない値であり、黙って v1 として配布・再ラップしない — §13-5 の
 * リカバリーブロブと同じ規律)。
 */
function wrapBodyOf(row: Record<string, SqlStorageValue>): {
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly encHex: string;
  readonly ciphertextHex: string;
} {
  return {
    suite: storedSuite(columnValue(row, "suite")),
    epoch: numberColumn(row, "epoch"),
    encHex: stringColumn(row, "enc_hex"),
    ciphertextHex: stringColumn(row, "ciphertext_hex"),
  };
}

/** ステートメント行の INSERT(変数・環境共通の列並び。テーブル名だけ差し替える)。 */
function insertStatementRow(
  sql: SqlStorage,
  table: "variable_meta_statements" | "environment_meta_statements",
  keys: readonly (string | number)[],
  statement: MetaStatementInput,
  signedBytesHashHex: string,
  author: MetaAuthorInfo,
  nowMs: number,
): void {
  const keyColumns =
    table === "variable_meta_statements"
      ? "environment_id, variable_id, meta_version"
      : "environment_id, meta_version";
  sql.exec(
    `INSERT INTO ${table}
       (${keyColumns}, suite, name, status, prev_meta_sig_hash_hex,
        chain_head_hash_hex, chain_head_seq, signature_hex, signed_bytes_hash_hex,
        author_user_id, author_key_fingerprint, created_at)
     VALUES (${keys.map(() => "?").join(", ")}, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ...keys,
    statement.suite,
    statement.name,
    statement.status,
    statement.prevMetaSigHashHex,
    statement.chainHeadHashHex,
    statement.chainHeadSeq,
    statement.signatureHex,
    signedBytesHashHex,
    author.userId,
    author.keyFingerprintHex,
    nowMs,
  );
}

const makeWriteOps = (sql: SqlStorage): DataWriteOps => ({
  // latest_meta_version は 0 で挿入し、同じ同期ブロック内の
  // insertEnvironmentMetaStatement(metaVersion 1)が確定する
  insertEnvironment: (environmentId, name, nowMs) => {
    sql.exec(
      "INSERT INTO environments (environment_id, name, latest_meta_version, created_at, deleted_at) VALUES (?, ?, 0, ?, NULL)",
      environmentId,
      name,
      nowMs,
    );
  },
  insertEnvironmentMetaStatement: (environmentId, statement, signedBytesHashHex, author, nowMs) => {
    insertStatementRow(
      sql,
      "environment_meta_statements",
      [environmentId, statement.metaVersion],
      statement,
      signedBytesHashHex,
      author,
      nowMs,
    );
    sql.exec(
      "UPDATE environments SET name = ?, latest_meta_version = ? WHERE environment_id = ?",
      statement.name,
      statement.metaVersion,
      environmentId,
    );
  },
  retireEnvironment: (environmentId, nowMs) => {
    sql.exec(
      "UPDATE environments SET deleted_at = ? WHERE environment_id = ?",
      nowMs,
      environmentId,
    );
    sql.exec("DELETE FROM variables WHERE environment_id = ?", environmentId);
    // 配下の変数ステートメントも即時削除する(§12-4 の配下データ)。環境自身の
    // ステートメント連鎖(deleted 込み)は environment_meta_statements に残る —
    // 環境 ID はチェーン合意規則で再利用不能のため、変数側に検出材料は残らない
    sql.exec("DELETE FROM variable_meta_statements WHERE environment_id = ?", environmentId);
    sql.exec("DELETE FROM variable_versions WHERE environment_id = ?", environmentId);
    sql.exec("DELETE FROM dek_wraps WHERE environment_id = ?", environmentId);
    // 環境マニフェストもカスケード削除する(§12-4 — 2026-08-18: 削除済み環境には
    // 配布チャネルが存在せず、配布されないサーバー保存物に検出材料としての残存
    // 価値がない。環境自身の deleted ステートメントが終端の検出材料)
    sql.exec("DELETE FROM environment_manifests WHERE environment_id = ?", environmentId);
    // チェックポイントのタプル・値スナップショットも同じ論法でカスケード削除
    // (§12-4 — 2026-08-27: 削除済み環境のスナップショットに配布チャネルはない)
    sql.exec("DELETE FROM environment_checkpoints WHERE environment_id = ?", environmentId);
    sql.exec("DELETE FROM checkpoint_snapshot_values WHERE environment_id = ?", environmentId);
  },
  insertVariable: (environmentId, variableId, name, nowMs) => {
    sql.exec(
      `INSERT INTO variables (environment_id, variable_id, name, latest_meta_version, latest_version, created_at, deleted_at)
       VALUES (?, ?, ?, 0, 0, ?, NULL)`,
      environmentId,
      variableId,
      name,
      nowMs,
    );
  },
  insertVariableMetaStatement: (
    environmentId,
    variableId,
    statement,
    signedBytesHashHex,
    author,
    nowMs,
  ) => {
    insertStatementRow(
      sql,
      "variable_meta_statements",
      [environmentId, variableId, statement.metaVersion],
      statement,
      signedBytesHashHex,
      author,
      nowMs,
    );
    sql.exec(
      "UPDATE variables SET name = ?, latest_meta_version = ? WHERE environment_id = ? AND variable_id = ?",
      statement.name,
      statement.metaVersion,
      environmentId,
      variableId,
    );
  },
  retireVariable: (environmentId, variableId, nowMs) => {
    sql.exec(
      "UPDATE variables SET deleted_at = ? WHERE environment_id = ? AND variable_id = ?",
      nowMs,
      environmentId,
      variableId,
    );
    sql.exec(
      "DELETE FROM variable_versions WHERE environment_id = ? AND variable_id = ?",
      environmentId,
      variableId,
    );
  },
  // 保持は環境ごとに最新 1 通のみ(§12-5 — upsert で置き換え、行を蓄積しない)
  upsertEnvironmentManifest: (environmentId, manifest, signedBytesHashHex, issuer, nowMs) => {
    sql.exec(
      `INSERT INTO environment_manifests
         (environment_id, manifest_version, suite, epoch, variables_digest_hex,
          env_meta_version, env_meta_sig_hash_hex, prev_manifest_sig_hash_hex,
          chain_head_hash_hex, chain_head_seq, signature_hex, signed_bytes_hash_hex,
          issuer_user_id, issuer_key_fingerprint, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (environment_id) DO UPDATE SET
         manifest_version = excluded.manifest_version,
         suite = excluded.suite,
         epoch = excluded.epoch,
         variables_digest_hex = excluded.variables_digest_hex,
         env_meta_version = excluded.env_meta_version,
         env_meta_sig_hash_hex = excluded.env_meta_sig_hash_hex,
         prev_manifest_sig_hash_hex = excluded.prev_manifest_sig_hash_hex,
         chain_head_hash_hex = excluded.chain_head_hash_hex,
         chain_head_seq = excluded.chain_head_seq,
         signature_hex = excluded.signature_hex,
         signed_bytes_hash_hex = excluded.signed_bytes_hash_hex,
         issuer_user_id = excluded.issuer_user_id,
         issuer_key_fingerprint = excluded.issuer_key_fingerprint,
         created_at = excluded.created_at`,
      environmentId,
      manifest.manifestVersion,
      manifest.suite,
      manifest.epoch,
      manifest.variablesDigestHex,
      manifest.envMetaVersion,
      manifest.envMetaSigHashHex,
      manifest.prevManifestSigHashHex,
      manifest.chainHeadHashHex,
      manifest.chainHeadSeq,
      manifest.signatureHex,
      signedBytesHashHex,
      issuer.userId,
      issuer.keyFingerprintHex,
      nowMs,
    );
  },
  upsertCheckpointSnapshot: (environmentId, checkpoint, values, nowMs) => {
    sql.exec(
      `INSERT INTO environment_checkpoints
         (environment_id, chain_seq, entry_hash_hex, epoch, manifest_version,
          manifest_sig_hash_hex, values_digest_hex, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (environment_id) DO UPDATE SET
         chain_seq = excluded.chain_seq,
         entry_hash_hex = excluded.entry_hash_hex,
         epoch = excluded.epoch,
         manifest_version = excluded.manifest_version,
         manifest_sig_hash_hex = excluded.manifest_sig_hash_hex,
         values_digest_hex = excluded.values_digest_hex,
         created_at = excluded.created_at`,
      environmentId,
      checkpoint.chainSeq,
      checkpoint.entryHashHex,
      checkpoint.epoch,
      checkpoint.manifestVersion,
      checkpoint.manifestSigHashHex,
      checkpoint.valuesDigestHex,
      nowMs,
    );
    // 列挙は環境単位の全置換(受理時点状態そのもの — §6.4 の upsert 意味論)
    sql.exec("DELETE FROM checkpoint_snapshot_values WHERE environment_id = ?", environmentId);
    for (const value of values) {
      sql.exec(
        `INSERT INTO checkpoint_snapshot_values
           (environment_id, variable_id, version, value_sig_hash_hex)
         VALUES (?, ?, ?, ?)`,
        environmentId,
        value.variableId,
        value.version,
        value.valueSigHashHex,
      );
    }
  },
  insertVersion: (
    environmentId,
    variableId,
    value,
    ciphertextBytes,
    signedBytesHashHex,
    writer,
    nowMs,
  ) => {
    sql.exec(
      `INSERT INTO variable_versions
         (environment_id, variable_id, version, suite, epoch, nonce_hex, ciphertext_hex, ciphertext_bytes,
          prev_value_sig_hash_hex, chain_head_hash_hex, chain_head_seq, signature_hex,
          signed_bytes_hash_hex, writer_user_id, writer_key_fingerprint, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      environmentId,
      variableId,
      value.version,
      value.suite,
      value.epoch,
      value.nonceHex,
      value.ciphertextHex,
      ciphertextBytes,
      value.prevValueSigHashHex,
      value.chainHeadHashHex,
      value.chainHeadSeq,
      value.signatureHex,
      signedBytesHashHex,
      writer.userId,
      writer.keyFingerprintHex,
      nowMs,
    );
    sql.exec(
      "UPDATE variables SET latest_version = ? WHERE environment_id = ? AND variable_id = ?",
      value.version,
      environmentId,
      variableId,
    );
  },
  insertWrap: (environmentId, wrap, signer, nowMs) => {
    sql.exec(
      `INSERT INTO dek_wraps
         (environment_id, epoch, recipient_class, recipient_user_id, suite, recipient_enc_pub_hex, enc_hex, ciphertext_hex,
          signature_hex, signer_user_id, signer_key_fingerprint, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      environmentId,
      wrap.epoch,
      wrap.recipientClass ?? "member",
      wrap.recipientUserId,
      wrap.suite,
      wrap.recipientEncPubHex,
      wrap.encHex,
      wrap.ciphertextHex,
      wrap.signatureHex,
      signer.userId,
      signer.keyFingerprintHex,
      nowMs,
    );
  },
  deleteWrap: (environmentId, epoch, recipientUserId) => {
    sql.exec(
      "DELETE FROM dek_wraps WHERE environment_id = ? AND epoch = ? AND recipient_user_id = ?",
      environmentId,
      epoch,
      recipientUserId,
    );
  },
  // SELECT → DELETE の 2 文だが同一同期タスク内(permit 下・原子コミット)。
  // 走査は主キー前方一致を使えない(recipient は主キー第 3 成分)ため全行
  // 走査になるが、行数は §12-8 の累積上限が束縛し、add_member は低頻度の
  // 管理操作である
  deleteStaleMemberWraps: (recipientUserId, keepEncPubHex) => {
    const stale = sql
      .exec(
        `SELECT environment_id, epoch FROM dek_wraps
         WHERE recipient_user_id = ? AND recipient_class = 'member'
           AND recipient_enc_pub_hex != ?
         ORDER BY environment_id, epoch`,
        recipientUserId,
        keepEncPubHex,
      )
      .toArray()
      .map((row) => ({
        environmentId: stringColumn(row, "environment_id"),
        epoch: numberColumn(row, "epoch"),
      }));
    if (stale.length > 0) {
      sql.exec(
        `DELETE FROM dek_wraps
         WHERE recipient_user_id = ? AND recipient_class = 'member'
           AND recipient_enc_pub_hex != ?`,
        recipientUserId,
        keepEncPubHex,
      );
    }
    return stale;
  },
});

export const dataStoreLayer = (sql: SqlStorage): Layer.Layer<DataStore> =>
  Layer.sync(DataStore, () => ({
    ...makeEnvironmentQueries(sql),
    ...makeVariableQueries(sql),
    ...makeVersionQueries(sql),
    ...makeWrapQueries(sql),
    write: makeWriteOps(sql),
  }));
