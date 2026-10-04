// The version-side read queries of the data store (bulk pulls, version
// history / range / anchor, the ciphertext-bytes meter) — assembled into
// DataStoreShape by dataStoreLayer in data-store.ts.

import { Effect } from "effect";

import type { PulledVariableValue } from "./data-plane.ts";
import {
  columnValue,
  numberColumn,
  statementColumns,
  storedSuite,
  storedVariableStatus,
  stringColumn,
  variableStatementV2Fields,
  type StoredRow,
} from "./data-store-rows.ts";
import type { StoredVersionMeta } from "./data-store.ts";

/**
 * A variable_versions row's distributed value columns (§12-7 — shared by the
 * bulk pull and the version value range). signed_bytes_hash_hex is never
 * selected = never distributed (AUTH_SPEC §12-2).
 */
function pulledValueColumns(row: StoredRow, variableId: string): PulledVariableValue {
  return {
    variableId,
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
  };
}

export const makeVersionQueries = (sql: SqlStorage) => ({
  // Distribution (§12-7) returns the stored signature block and the
  // writer / author as-is (never re-derived from the current member
  // set — verifiability of past data by a since-deleted writer /
  // author). signed_bytes_hash_hex is not selected on either values or
  // statements = never distributed (AUTH_SPEC §12-2)
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
                  ms.author_key_fingerprint AS ms_author_key_fingerprint,
                  ms.layout_version AS ms_layout_version, ms.var_type AS ms_var_type,
                  ms.required AS ms_required, ms.description AS ms_description,
                  ms.max_age_days AS ms_max_age_days
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
          ...pulledValueColumns(row, stringColumn(row, "variable_id")),
          // The statement part reads the ms_* aliased columns as-is
          // (statementColumns's prefix). The environment ID is the
          // WHERE-clause argument; the variable ID is the row's value
          statement: {
            environmentId,
            variableId: stringColumn(row, "variable_id"),
            ...statementColumns(row, "ms_", storedVariableStatus),
            ...variableStatementV2Fields(row, "ms_"),
          },
        })),
    ),
  versionHistory: (environmentId: string, variableId: string) =>
    Effect.sync(() =>
      sql
        .exec(
          `SELECT version, epoch, writer_user_id, writer_key_fingerprint, created_at
           FROM variable_versions
           WHERE environment_id = ? AND variable_id = ?
           ORDER BY version`,
          environmentId,
          variableId,
        )
        .toArray()
        .map((row): StoredVersionMeta => ({
          version: numberColumn(row, "version"),
          epoch: numberColumn(row, "epoch"),
          writerUserId: stringColumn(row, "writer_user_id"),
          writerKeyFingerprintHex: stringColumn(row, "writer_key_fingerprint"),
          pushedAtMs: numberColumn(row, "created_at"),
        })),
    ),
  versionRange: (environmentId: string, variableId: string, fromVersion: number, limit: number) =>
    Effect.sync(() =>
      sql
        .exec(
          `SELECT version, suite, epoch, nonce_hex, ciphertext_hex, prev_value_sig_hash_hex,
                  chain_head_hash_hex, chain_head_seq, signature_hex,
                  writer_user_id, writer_key_fingerprint
           FROM variable_versions
           WHERE environment_id = ? AND variable_id = ? AND version >= ?
           ORDER BY version
           LIMIT ?`,
          environmentId,
          variableId,
          fromVersion,
          limit,
        )
        .toArray()
        .map((row) => pulledValueColumns(row, variableId)),
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
  // The §12-8 meter: version ciphertexts plus the sealed values of
  // pending proposals (hex columns — two characters per byte), so a
  // project cannot park ciphertext outside the cap in proposals
  totalCiphertextBytes: Effect.sync(() => {
    const row = sql
      .exec(
        `SELECT (SELECT COALESCE(SUM(ciphertext_bytes), 0) FROM variable_versions)
              + (SELECT COALESCE(SUM(length(ciphertext_hex)), 0) / 2 FROM rotation_proposal_wraps)
              AS total`,
      )
      .toArray()[0];
    return row === undefined ? 0 : numberColumn(row, "total");
  }),
});
