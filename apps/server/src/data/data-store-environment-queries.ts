// The environment-side read queries of the data store (environments,
// environment meta statements, environment manifests) — assembled into
// DataStoreShape by dataStoreLayer in data-store.ts.

import { Effect } from "effect";

import {
  columnValue,
  countsOf,
  environmentAnchorOf,
  MS_COLUMNS,
  nullableNumberColumn,
  numberColumn,
  statementOf,
  storedSuite,
  stringColumn,
} from "./data-store-rows.ts";

export const makeEnvironmentQueries = (sql: SqlStorage) => ({
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
  // Deleted environments are also listed with their deleted statement
  // (the detection material for a denied deletion / unauthorized
  // revival — §12-4; the client discriminates by the statement's
  // status)
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
      environmentAnchorOf(
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
  // Distribution (§12-2) does not select signed_bytes_hash_hex = never
  // distributes it (a verifier recomputes it themselves — the same
  // discipline as statement distribution)
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
