// データプレーンのストレージ(DO SQLite)を隔離する Effect サービス。
//
// - テーブルは do-schema.ts(DO コンストラクタが DDL 適用済み)
// - 環境・変数の削除は tombstone(deleted_at)。ID 再利用禁止(AUTH_SPEC §12-1)の
//   判定に使う。暗号文(variable_versions)とラップ(dek_wraps)は即時削除
// - Drizzle 見送りの判断は do-schema.ts 冒頭コメントと docs/notes/session-07.md

import { Context, Effect, Layer } from "effect";

import type {
  DekWrapInput,
  PulledVariableValue,
  RecipientDekValue,
  ValueInput,
  WireSuite,
} from "./data-plane.ts";

export interface EnvironmentRow {
  readonly environmentId: string;
  readonly name: string;
  readonly deletedAtMs: number | null;
}

export interface VariableRow {
  readonly variableId: string;
  readonly name: string;
  readonly latestVersion: number;
  readonly deletedAtMs: number | null;
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
  readonly insertEnvironment: (environmentId: string, name: string, nowMs: number) => void;
  readonly setEnvironmentName: (environmentId: string, name: string) => void;
  /** tombstone 化 + 配下データ(変数・バージョン・ラップ)の即時削除。 */
  readonly retireEnvironment: (environmentId: string, nowMs: number) => void;
  readonly insertVariable: (
    environmentId: string,
    variableId: string,
    name: string,
    nowMs: number,
  ) => void;
  readonly setVariableName: (environmentId: string, variableId: string, name: string) => void;
  /** tombstone 化 + 全バージョン(暗号文)の即時削除。 */
  readonly retireVariable: (environmentId: string, variableId: string, nowMs: number) => void;
  /** バージョン行の挿入と latest_version の前進(書き込みロック下で呼ぶ)。 */
  readonly insertVersion: (
    environmentId: string,
    variableId: string,
    value: ValueInput,
    ciphertextBytes: number,
    nowMs: number,
  ) => void;
  readonly insertWrap: (environmentId: string, wrap: DekWrapInput, nowMs: number) => void;
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
  readonly listEnvironments: Effect.Effect<readonly { environmentId: string; name: string }[]>;

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

  /** アクティブ変数の最新バージョン一覧(一括 pull 用)。 */
  readonly latestVersions: (environmentId: string) => Effect.Effect<readonly PulledVariableValue[]>;
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

const makeEnvironmentQueries = (sql: SqlStorage) => ({
  findEnvironment: (environmentId: string) =>
    Effect.sync(() => {
      const row = sql
        .exec(
          "SELECT environment_id, name, deleted_at FROM environments WHERE environment_id = ?",
          environmentId,
        )
        .toArray()[0];
      if (row === undefined) {
        return null;
      }
      return {
        environmentId: String(row["environment_id"]),
        name: String(row["name"]),
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
  listEnvironments: Effect.sync(() =>
    sql
      .exec(
        "SELECT environment_id, name FROM environments WHERE deleted_at IS NULL ORDER BY created_at, environment_id",
      )
      .toArray()
      .map((row) => ({
        environmentId: String(row["environment_id"]),
        name: String(row["name"]),
      })),
  ),
});

const makeVariableQueries = (sql: SqlStorage) => ({
  findVariable: (environmentId: string, variableId: string) =>
    Effect.sync(() => {
      const row = sql
        .exec(
          `SELECT variable_id, name, latest_version, deleted_at FROM variables
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
        latestVersion: Number(row["latest_version"]),
        deletedAtMs: row["deleted_at"] === null ? null : Number(row["deleted_at"]),
      };
    }),
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
  latestVersions: (environmentId: string) =>
    Effect.sync(() =>
      sql
        .exec(
          `SELECT v.variable_id, v.name, vv.version, vv.suite, vv.epoch, vv.nonce_hex, vv.ciphertext_hex
           FROM variables v
           JOIN variable_versions vv
             ON vv.environment_id = v.environment_id
            AND vv.variable_id = v.variable_id
            AND vv.version = v.latest_version
           WHERE v.environment_id = ? AND v.deleted_at IS NULL
           ORDER BY v.created_at, v.variable_id`,
          environmentId,
        )
        .toArray()
        .map((row) => ({
          variableId: String(row["variable_id"]),
          name: String(row["name"]),
          version: Number(row["version"]),
          suite: storedSuite(row["suite"]),
          epoch: Number(row["epoch"]),
          nonceHex: String(row["nonce_hex"]),
          ciphertextHex: String(row["ciphertext_hex"]),
        })),
    ),
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
          `SELECT suite, epoch, enc_hex, ciphertext_hex FROM dek_wraps
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
        })),
    ),
});

const makeWriteOps = (sql: SqlStorage): DataWriteOps => ({
  insertEnvironment: (environmentId, name, nowMs) => {
    sql.exec(
      "INSERT INTO environments (environment_id, name, created_at, deleted_at) VALUES (?, ?, ?, NULL)",
      environmentId,
      name,
      nowMs,
    );
  },
  setEnvironmentName: (environmentId, name) => {
    sql.exec("UPDATE environments SET name = ? WHERE environment_id = ?", name, environmentId);
  },
  retireEnvironment: (environmentId, nowMs) => {
    sql.exec(
      "UPDATE environments SET deleted_at = ? WHERE environment_id = ?",
      nowMs,
      environmentId,
    );
    sql.exec("DELETE FROM variables WHERE environment_id = ?", environmentId);
    sql.exec("DELETE FROM variable_versions WHERE environment_id = ?", environmentId);
    sql.exec("DELETE FROM dek_wraps WHERE environment_id = ?", environmentId);
  },
  insertVariable: (environmentId, variableId, name, nowMs) => {
    sql.exec(
      `INSERT INTO variables (environment_id, variable_id, name, latest_version, created_at, deleted_at)
       VALUES (?, ?, ?, 0, ?, NULL)`,
      environmentId,
      variableId,
      name,
      nowMs,
    );
  },
  setVariableName: (environmentId, variableId, name) => {
    sql.exec(
      "UPDATE variables SET name = ? WHERE environment_id = ? AND variable_id = ?",
      name,
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
  insertVersion: (environmentId, variableId, value, ciphertextBytes, nowMs) => {
    sql.exec(
      `INSERT INTO variable_versions
         (environment_id, variable_id, version, suite, epoch, nonce_hex, ciphertext_hex, ciphertext_bytes, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      environmentId,
      variableId,
      value.version,
      value.suite,
      value.epoch,
      value.nonceHex,
      value.ciphertextHex,
      ciphertextBytes,
      nowMs,
    );
    sql.exec(
      "UPDATE variables SET latest_version = ? WHERE environment_id = ? AND variable_id = ?",
      value.version,
      environmentId,
      variableId,
    );
  },
  insertWrap: (environmentId, wrap, nowMs) => {
    sql.exec(
      `INSERT INTO dek_wraps
         (environment_id, epoch, recipient_user_id, suite, recipient_enc_pub_hex, enc_hex, ciphertext_hex, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      environmentId,
      wrap.epoch,
      wrap.recipientUserId,
      wrap.suite,
      wrap.recipientEncPubHex,
      wrap.encHex,
      wrap.ciphertextHex,
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
