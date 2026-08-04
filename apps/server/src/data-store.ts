// データプレーンのストレージ(DO SQLite)を隔離する Effect サービス。
//
// - テーブルは do-schema.ts(DO コンストラクタが DDL 適用済み)
// - 環境・変数の削除は tombstone(deleted_at)。ID 再利用禁止(AUTH_SPEC §12-1)の
//   判定に使う。暗号文(variable_versions)とラップ(dek_wraps)は即時削除
// - Drizzle 見送りの判断は do-schema.ts 冒頭コメントと docs/notes/session-07.md

import { Context, Effect, Layer } from "effect";

import type {
  DekWrapInput,
  DistributedMetaStatementValue,
  DistributedVariableMetaStatementValue,
  MetaStatementInput,
  MetaStatementStatusInput,
  PulledVariableValue,
  RecipientDekValue,
  ValueInput,
  WireSuite,
} from "./data-plane.ts";

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

/** アクティブ数と行数(tombstone 込み)。§12-8 の数量ポリシー判定用。 */
interface ResourceCounts {
  readonly active: number;
  readonly rows: number;
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
  readonly wrapExists: (
    environmentId: string,
    epoch: number,
    recipientUserId: string,
  ) => Effect.Effect<boolean>;
  readonly listWrapsForRecipient: (
    environmentId: string,
    recipientUserId: string,
  ) => Effect.Effect<readonly RecipientDekValue[]>;

  readonly write: DataWriteOps;
}

export class DataStore extends Context.Service<DataStore, DataStoreShape>()("DataStore") {}

function countsOf(row: Record<string, unknown> | undefined): ResourceCounts {
  return { active: Number(row?.["active_rows"] ?? 0), rows: Number(row?.["total_rows"] ?? 0) };
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

/** メタステートメント行 → 配布形(author 込み。environmentId は列から取る)。 */
function statementOf(row: Record<string, unknown>): DistributedMetaStatementValue {
  const status = String(row["status"]);
  if (status !== "active" && status !== "deleted") {
    // 書き込み経路は Schema の Literal が強制する(既知以外はストレージ破損)
    throw new Error("unexpected status in stored meta statement row");
  }
  return {
    suite: storedSuite(row["suite"]),
    environmentId: String(row["environment_id"]),
    name: String(row["name"]),
    status,
    metaVersion: Number(row["meta_version"]),
    prevMetaSigHashHex: String(row["prev_meta_sig_hash_hex"]),
    chainHeadHashHex: String(row["chain_head_hash_hex"]),
    chainHeadSeq: Number(row["chain_head_seq"]),
    signatureHex: String(row["signature_hex"]),
    authorUserId: String(row["author_user_id"]),
    authorKeyFingerprintHex: String(row["author_key_fingerprint"]),
  };
}

function variableStatementOf(row: Record<string, unknown>): DistributedVariableMetaStatementValue {
  return { ...statementOf(row), variableId: String(row["variable_id"]) };
}

function anchorOf(row: Record<string, unknown> | undefined): MetaAnchor | null {
  if (row === undefined) {
    return null;
  }
  const status = String(row["status"]);
  if (status !== "active" && status !== "deleted") {
    throw new Error("unexpected status in stored meta statement row");
  }
  return { signedBytesHashHex: String(row["signed_bytes_hash_hex"]), status };
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
        environmentId: String(row["environment_id"]),
        name: String(row["name"]),
        latestMetaVersion: Number(row["latest_meta_version"]),
        deletedAtMs: row["deleted_at"] === null ? null : Number(row["deleted_at"]),
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
        environmentId: String(row["environment_id"]),
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
        variableId: String(row["variable_id"]),
        name: String(row["name"]),
        latestMetaVersion: Number(row["latest_meta_version"]),
        latestVersion: Number(row["latest_version"]),
        deletedAtMs: row["deleted_at"] === null ? null : Number(row["deleted_at"]),
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
        .map((row) => ({ variableId: String(row["variable_id"]), name: String(row["name"]) })),
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
          variableId: String(row["variable_id"]),
          version: Number(row["version"]),
          suite: storedSuite(row["suite"]),
          epoch: Number(row["epoch"]),
          nonceHex: String(row["nonce_hex"]),
          ciphertextHex: String(row["ciphertext_hex"]),
          prevValueSigHashHex: String(row["prev_value_sig_hash_hex"]),
          chainHeadHashHex: String(row["chain_head_hash_hex"]),
          chainHeadSeq: Number(row["chain_head_seq"]),
          signatureHex: String(row["signature_hex"]),
          writerUserId: String(row["writer_user_id"]),
          writerKeyFingerprintHex: String(row["writer_key_fingerprint"]),
          statement: variableStatementOf({
            environment_id: environmentId,
            variable_id: row["variable_id"],
            suite: row["ms_suite"],
            name: row["ms_name"],
            status: row["ms_status"],
            meta_version: row["ms_meta_version"],
            prev_meta_sig_hash_hex: row["ms_prev_meta_sig_hash_hex"],
            chain_head_hash_hex: row["ms_chain_head_hash_hex"],
            chain_head_seq: row["ms_chain_head_seq"],
            signature_hex: row["ms_signature_hex"],
            author_user_id: row["ms_author_user_id"],
            author_key_fingerprint: row["ms_author_key_fingerprint"],
          }),
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
        signedBytesHashHex: String(row["signed_bytes_hash_hex"]),
        epoch: Number(row["epoch"]),
      };
    }),
  totalCiphertextBytes: Effect.sync(() => {
    const row = sql
      .exec("SELECT COALESCE(SUM(ciphertext_bytes), 0) AS total FROM variable_versions")
      .toArray()[0];
    return Number(row?.["total"] ?? 0);
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
      return Number(row?.["n"] ?? 0);
    }),
  countWrapRows: Effect.sync(() => {
    const row = sql.exec("SELECT COUNT(*) AS n FROM dek_wraps").toArray()[0];
    return Number(row?.["n"] ?? 0);
  }),
  wrapExists: (environmentId: string, epoch: number, recipientUserId: string) =>
    Effect.sync(() => {
      const rows = sql
        .exec(
          "SELECT 1 FROM dek_wraps WHERE environment_id = ? AND epoch = ? AND recipient_user_id = ? LIMIT 1",
          environmentId,
          epoch,
          recipientUserId,
        )
        .toArray();
      return rows.length > 0;
    }),
  listWrapsForRecipient: (environmentId: string, recipientUserId: string) =>
    Effect.sync(() =>
      sql
        .exec(
          `SELECT suite, epoch, enc_hex, ciphertext_hex, signature_hex, signer_user_id, signer_key_fingerprint
           FROM dek_wraps
           WHERE environment_id = ? AND recipient_user_id = ? ORDER BY epoch`,
          environmentId,
          recipientUserId,
        )
        .toArray()
        .map((row) => ({
          suite: storedSuite(row["suite"]),
          epoch: Number(row["epoch"]),
          encHex: String(row["enc_hex"]),
          ciphertextHex: String(row["ciphertext_hex"]),
          signatureHex: String(row["signature_hex"]),
          signerUserId: String(row["signer_user_id"]),
          signerKeyFingerprintHex: String(row["signer_key_fingerprint"]),
        })),
    ),
});

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
         (environment_id, epoch, recipient_user_id, suite, recipient_enc_pub_hex, enc_hex, ciphertext_hex,
          signature_hex, signer_user_id, signer_key_fingerprint, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      environmentId,
      wrap.epoch,
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
});

export const dataStoreLayer = (sql: SqlStorage): Layer.Layer<DataStore> =>
  Layer.sync(DataStore, () => ({
    ...makeEnvironmentQueries(sql),
    ...makeVariableQueries(sql),
    ...makeVersionQueries(sql),
    ...makeWrapQueries(sql),
    write: makeWriteOps(sql),
  }));
