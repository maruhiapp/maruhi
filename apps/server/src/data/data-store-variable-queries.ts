// The variable-side read queries of the data store (variables, variable
// meta statements, checkpoint snapshot reads) — assembled into
// DataStoreShape by dataStoreLayer in data-store.ts.

import { Effect } from "effect";

import type { CheckpointSnapshotEntryValue, CheckpointSnapshotValue } from "./data-plane.ts";
import {
  countsOf,
  nullableNumberColumn,
  numberColumn,
  storedVariableStatus,
  stringColumn,
  variableAnchorOf,
  variableStatementOf,
  VAR_MS_COLUMNS,
} from "./data-store-rows.ts";
import type { CheckpointValueEntryRow, VariableDigestEntryRow } from "./data-store.ts";

export const makeVariableQueries = (sql: SqlStorage) => ({
  findVariable: (environmentId: string, variableId: string) =>
    Effect.sync(() => {
      const row = sql
        .exec(
          `SELECT v.variable_id, v.name, v.latest_meta_version, v.latest_version, v.deleted_at,
                  ms.status
           FROM variables v
           JOIN variable_meta_statements ms
             ON ms.environment_id = v.environment_id
            AND ms.variable_id = v.variable_id
            AND ms.meta_version = v.latest_meta_version
           WHERE v.environment_id = ? AND v.variable_id = ?`,
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
        latestStatus: storedVariableStatus(stringColumn(row, "status")),
        deletedAtMs: nullableNumberColumn(row, "deleted_at"),
      };
    }),
  variableMetaAnchor: (environmentId: string, variableId: string, metaVersion: number) =>
    Effect.sync(() =>
      variableAnchorOf(
        sql
          .exec(
            `SELECT signed_bytes_hash_hex, name, status, layout_version, var_type, required,
                    description, max_age_days
             FROM variable_meta_statements
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
          `SELECT ms.variable_id, ${VAR_MS_COLUMNS}
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
  // The active side of deletedVariableStatements (the metadata-only
  // mode — §12-7): the latest statements only. Values and DEKs are not
  // selected (never distributed, so never touched). The statements of
  // declared variables are included too (the latest form of every
  // non-deleted variable — status carries the discrimination)
  activeVariableStatements: (environmentId: string) =>
    Effect.sync(() =>
      sql
        .exec(
          `SELECT ms.variable_id, ${VAR_MS_COLUMNS}
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
  // The latest statements of declared variables (the bundled material
  // of a value-bearing pull — §12-7; they never appear in
  // latestVersions because no value or version exists: the JOIN
  // naturally excludes the rows with latest_version 0)
  declaredVariableStatements: (environmentId: string) =>
    Effect.sync(() =>
      sql
        .exec(
          `SELECT ms.variable_id, ${VAR_MS_COLUMNS}
           FROM variables v
           JOIN variable_meta_statements ms
             ON ms.environment_id = v.environment_id
            AND ms.variable_id = v.variable_id
            AND ms.meta_version = v.latest_meta_version
           WHERE v.environment_id = ? AND v.deleted_at IS NULL AND ms.status = 'declared'
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
  // The recompute input of variables_digest (§12-5 (7)): the latest
  // form of every variable, tombstones included. The canonical order
  // (byte-ascending variable_id) is established internally by crypto's
  // computeVariablesDigest, so the order is not canonicalized here
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
        .map((row): VariableDigestEntryRow => ({
          variableId: stringColumn(row, "variable_id"),
          // declared naturally rides along as an entry's status value
          // (CRYPTO_SPEC §4.3 — the canonical form and encoder are
          // unchanged)
          status: storedVariableStatus(stringColumn(row, "status")),
          metaVersion: numberColumn(row, "meta_version"),
          metaSigHashHex: stringColumn(row, "signed_bytes_hash_hex"),
        })),
    ),
  // The recompute input of a checkpoint values_digest (§6.4): each
  // active variable's latest version and stored value_signed_bytes
  // hash. The canonical order (byte-ascending variable_id) is
  // established internally by crypto's computeEnvValuesDigest, so the
  // order is not canonicalized here
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
  // The distributed checkpoint snapshot (§12-7 — the stored rows
  // themselves)
  checkpointSnapshot: (environmentId: string) =>
    Effect.sync((): CheckpointSnapshotValue | null => {
      const row = sql
        .exec(
          "SELECT chain_seq, entry_hash_hex FROM environment_checkpoints WHERE environment_id = ?",
          environmentId,
        )
        .toArray()[0];
      if (row === undefined) {
        return null;
      }
      const values = sql
        .exec(
          `SELECT variable_id, version, value_sig_hash_hex
           FROM checkpoint_snapshot_values
           WHERE environment_id = ? ORDER BY variable_id`,
          environmentId,
        )
        .toArray()
        .map((value): CheckpointSnapshotEntryValue => ({
          variableId: stringColumn(value, "variable_id"),
          version: numberColumn(value, "version"),
          valueSigHashHex: stringColumn(value, "value_sig_hash_hex"),
        }));
      return {
        chainSeq: numberColumn(row, "chain_seq"),
        entryHashHex: stringColumn(row, "entry_hash_hex"),
        values,
      };
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
        .map((row) => ({
          variableId: stringColumn(row, "variable_id"),
          name: stringColumn(row, "name"),
        })),
    ),
});
