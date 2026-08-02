// データプレーンのストレージ(DO SQLite)を隔離する Effect サービス。
//
// - テーブルは do-schema.ts(DO コンストラクタが DDL 適用済み)
// - 環境・変数の削除は tombstone(deleted_at)。ID 再利用禁止(AUTH_SPEC §12-1)の
//   判定に使う。暗号文(variable_versions)とラップ(dek_wraps)は即時削除
// - Drizzle 見送りの判断は do-schema.ts 冒頭コメントと docs/notes/session-07.md

import { Context, Effect, Layer } from "effect";

import type { DekWrapInput, PulledVariableValue, RecipientDekValue } from "./data-plane.ts";

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

interface DataStoreShape {
  readonly findEnvironment: (environmentId: string) => Effect.Effect<EnvironmentRow | null>;
  readonly countEnvironments: Effect.Effect<ResourceCounts>;
  readonly environmentNameTaken: (
    name: string,
    excludeEnvironmentId: string | null,
  ) => Effect.Effect<boolean>;
  readonly insertEnvironment: (
    environmentId: string,
    name: string,
    nowMs: number,
  ) => Effect.Effect<void>;
  readonly setEnvironmentName: (environmentId: string, name: string) => Effect.Effect<void>;
  /** tombstone 化 + 配下データ(変数・バージョン・ラップ)の即時削除。 */
  readonly retireEnvironment: (environmentId: string, nowMs: number) => Effect.Effect<void>;
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
  readonly insertVariable: (
    environmentId: string,
    variableId: string,
    name: string,
    nowMs: number,
  ) => Effect.Effect<void>;
  readonly setVariableName: (
    environmentId: string,
    variableId: string,
    name: string,
  ) => Effect.Effect<void>;
  /** tombstone 化 + 全バージョン(暗号文)の即時削除。 */
  readonly retireVariable: (
    environmentId: string,
    variableId: string,
    nowMs: number,
  ) => Effect.Effect<void>;
  readonly listActiveVariables: (
    environmentId: string,
  ) => Effect.Effect<readonly { variableId: string; name: string }[]>;

  /** バージョン行の挿入と latest_version の前進(書き込みロック下で呼ぶ)。 */
  readonly insertVersion: (
    environmentId: string,
    variableId: string,
    version: number,
    epoch: number,
    nonceHex: string,
    ciphertextHex: string,
    ciphertextBytes: number,
    nowMs: number,
  ) => Effect.Effect<void>;
  /** アクティブ変数の最新バージョン一覧(一括 pull 用)。 */
  readonly latestVersions: (environmentId: string) => Effect.Effect<readonly PulledVariableValue[]>;
  /** プロジェクトの累積暗号文バイト(現在保存中の量。§12-8)。 */
  readonly totalCiphertextBytes: Effect.Effect<number>;

  readonly countWrapsForEpoch: (environmentId: string, epoch: number) => Effect.Effect<number>;
  readonly wrapExists: (
    environmentId: string,
    epoch: number,
    recipientUserId: string,
  ) => Effect.Effect<boolean>;
  readonly insertWrap: (
    environmentId: string,
    wrap: DekWrapInput,
    nowMs: number,
  ) => Effect.Effect<void>;
  readonly listWrapsForRecipient: (
    environmentId: string,
    recipientUserId: string,
  ) => Effect.Effect<readonly RecipientDekValue[]>;
}

export class DataStore extends Context.Service<DataStore, DataStoreShape>()("DataStore") {}

function countsOf(row: Record<string, unknown> | undefined): ResourceCounts {
  return { active: Number(row?.["active_rows"] ?? 0), rows: Number(row?.["total_rows"] ?? 0) };
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
  insertEnvironment: (environmentId: string, name: string, nowMs: number) =>
    Effect.sync(() => {
      sql.exec(
        "INSERT INTO environments (environment_id, name, created_at, deleted_at) VALUES (?, ?, ?, NULL)",
        environmentId,
        name,
        nowMs,
      );
    }),
  setEnvironmentName: (environmentId: string, name: string) =>
    Effect.sync(() => {
      sql.exec("UPDATE environments SET name = ? WHERE environment_id = ?", name, environmentId);
    }),
  retireEnvironment: (environmentId: string, nowMs: number) =>
    Effect.sync(() => {
      sql.exec(
        "UPDATE environments SET deleted_at = ? WHERE environment_id = ?",
        nowMs,
        environmentId,
      );
      sql.exec("DELETE FROM variables WHERE environment_id = ?", environmentId);
      sql.exec("DELETE FROM variable_versions WHERE environment_id = ?", environmentId);
      sql.exec("DELETE FROM dek_wraps WHERE environment_id = ?", environmentId);
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
  insertVariable: (environmentId: string, variableId: string, name: string, nowMs: number) =>
    Effect.sync(() => {
      sql.exec(
        `INSERT INTO variables (environment_id, variable_id, name, latest_version, created_at, deleted_at)
         VALUES (?, ?, ?, 0, ?, NULL)`,
        environmentId,
        variableId,
        name,
        nowMs,
      );
    }),
  setVariableName: (environmentId: string, variableId: string, name: string) =>
    Effect.sync(() => {
      sql.exec(
        "UPDATE variables SET name = ? WHERE environment_id = ? AND variable_id = ?",
        name,
        environmentId,
        variableId,
      );
    }),
  retireVariable: (environmentId: string, variableId: string, nowMs: number) =>
    Effect.sync(() => {
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
  insertVersion: (
    environmentId: string,
    variableId: string,
    version: number,
    epoch: number,
    nonceHex: string,
    ciphertextHex: string,
    ciphertextBytes: number,
    nowMs: number,
  ) =>
    Effect.sync(() => {
      sql.exec(
        `INSERT INTO variable_versions
           (environment_id, variable_id, version, epoch, nonce_hex, ciphertext_hex, ciphertext_bytes, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        environmentId,
        variableId,
        version,
        epoch,
        nonceHex,
        ciphertextHex,
        ciphertextBytes,
        nowMs,
      );
      sql.exec(
        "UPDATE variables SET latest_version = ? WHERE environment_id = ? AND variable_id = ?",
        version,
        environmentId,
        variableId,
      );
    }),
  latestVersions: (environmentId: string) =>
    Effect.sync(() =>
      sql
        .exec(
          `SELECT v.variable_id, v.name, vv.version, vv.epoch, vv.nonce_hex, vv.ciphertext_hex
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
  insertWrap: (environmentId: string, wrap: DekWrapInput, nowMs: number) =>
    Effect.sync(() => {
      sql.exec(
        `INSERT INTO dek_wraps
           (environment_id, epoch, recipient_user_id, recipient_enc_pub_hex, enc_hex, ciphertext_hex, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        environmentId,
        wrap.epoch,
        wrap.recipientUserId,
        wrap.recipientEncPubHex,
        wrap.encHex,
        wrap.ciphertextHex,
        nowMs,
      );
    }),
  listWrapsForRecipient: (environmentId: string, recipientUserId: string) =>
    Effect.sync(() =>
      sql
        .exec(
          `SELECT epoch, enc_hex, ciphertext_hex FROM dek_wraps
           WHERE environment_id = ? AND recipient_user_id = ? ORDER BY epoch`,
          environmentId,
          recipientUserId,
        )
        .toArray()
        .map((row) => ({
          epoch: Number(row["epoch"]),
          encHex: String(row["enc_hex"]),
          ciphertextHex: String(row["ciphertext_hex"]),
        })),
    ),
});

export const dataStoreLayer = (sql: SqlStorage): Layer.Layer<DataStore> =>
  Layer.sync(DataStore, () => ({
    ...makeEnvironmentQueries(sql),
    ...makeVariableQueries(sql),
    ...makeVersionQueries(sql),
    ...makeWrapQueries(sql),
  }));
