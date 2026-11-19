// The head-attestation reads and the per-member fixed window of the
// data store (AUTH_SPEC §16-1) — assembled into DataStoreShape by
// dataStoreLayer in data-store.ts.

import type { KeyFingerprintHex, UserId } from "@maruhi/core";
import { decodeKeyFingerprintHex, decodeUserId } from "@maruhi/core";
import { Effect } from "effect";

import { ATTESTATION_WINDOW_MS } from "../policy.ts";
import { columnValue, numberColumn, storedSuite, stringColumn } from "./data-store-rows.ts";
import type { StoredHeadAttestation } from "./data-store.ts";

/**
 * Reads and the fixed window of head attestations (AUTH_SPEC §16-1).
 * The window's semantics (separation of judgment and consumption;
 * expired = counting from 0) are identical to the lease window's — only
 * the key became per-member.
 */
export const makeAttestationQueries = (sql: SqlStorage) => ({
  headAttestationSeq: (attesterUserId: UserId, keyFingerprintHex: KeyFingerprintHex) =>
    Effect.sync(() => {
      const row = sql
        .exec(
          "SELECT chain_head_seq FROM head_attestations WHERE attester_user_id = ? AND attester_key_fingerprint = ?",
          attesterUserId,
          keyFingerprintHex,
        )
        .toArray()[0];
      return row === undefined ? null : numberColumn(row, "chain_head_seq");
    }),
  listHeadAttestations: Effect.sync(() =>
    sql
      .exec(
        `SELECT attester_user_id, suite, chain_head_seq, chain_head_hash_hex,
                signature_hex, attester_key_fingerprint
         FROM head_attestations ORDER BY attester_user_id, attester_key_fingerprint`,
      )
      .toArray()
      .map((row): StoredHeadAttestation => ({
        attesterUserId: decodeUserId(stringColumn(row, "attester_user_id")),
        suite: storedSuite(columnValue(row, "suite")),
        chainHeadSeq: numberColumn(row, "chain_head_seq"),
        chainHeadHashHex: stringColumn(row, "chain_head_hash_hex"),
        signatureHex: stringColumn(row, "signature_hex"),
        attesterKeyFingerprintHex: decodeKeyFingerprintHex(
          stringColumn(row, "attester_key_fingerprint"),
        ),
      })),
  ),
  checkAttestationWindow: (attesterUserId: UserId, limit: number, nowMs: number) =>
    Effect.sync(() => {
      const current = attestationWindowRow(sql, attesterUserId, nowMs);
      if (current === null || current.count < limit) {
        return { allowed: true, retryAfterSeconds: 0 };
      }
      return {
        allowed: false,
        retryAfterSeconds: Math.ceil((ATTESTATION_WINDOW_MS - current.elapsed) / 1000),
      };
    }),
  recordAttestationWindowUse: (attesterUserId: UserId, nowMs: number) => {
    if (attestationWindowRow(sql, attesterUserId, nowMs) === null) {
      sql.exec(
        `INSERT INTO attestation_windows (attester_user_id, window_start, count) VALUES (?, ?, 1)
         ON CONFLICT(attester_user_id) DO UPDATE
           SET window_start = excluded.window_start, count = 1`,
        attesterUserId,
        nowMs,
      );
      return;
    }
    sql.exec(
      "UPDATE attestation_windows SET count = count + 1 WHERE attester_user_id = ?",
      attesterUserId,
    );
  },
});

/** The live row of the attestation window (same "live window" definition as the lease window's leaseWindowRow). */
function attestationWindowRow(
  sql: SqlStorage,
  attesterUserId: UserId,
  nowMs: number,
): { readonly count: number; readonly elapsed: number } | null {
  const row = sql
    .exec(
      "SELECT window_start, count FROM attestation_windows WHERE attester_user_id = ?",
      attesterUserId,
    )
    .toArray()[0];
  if (row === undefined) {
    return null;
  }
  const elapsed = nowMs - numberColumn(row, "window_start");
  if (elapsed >= ATTESTATION_WINDOW_MS || elapsed < 0) {
    return null;
  }
  return { count: numberColumn(row, "count"), elapsed };
}
