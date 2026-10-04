// The wrap- and lease-side queries of the data store (dek_wraps reads,
// lease fixed windows, lease bindings, the mirror-state check) —
// assembled into DataStoreShape by dataStoreLayer in data-store.ts.

import { Effect } from "effect";

import { LEASE_WINDOW_MS } from "../policy.ts";
import type { WireSuite } from "./data-plane.ts";
import { columnValue, numberColumn, storedSuite, stringColumn } from "./data-store-rows.ts";
import type { LeaseWindowKind } from "./data-store.ts";

export const makeWrapQueries = (sql: SqlStorage) => ({
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
  listWrapSlots: (environmentId: string, epoch: number, recipientUserId: string) =>
    Effect.sync(() =>
      sql
        .exec(
          "SELECT recipient_class, recipient_enc_pub_hex FROM dek_wraps WHERE environment_id = ? AND epoch = ? AND recipient_user_id = ? ORDER BY recipient_enc_pub_hex",
          environmentId,
          epoch,
          recipientUserId,
        )
        .toArray()
        .map((row) => ({
          recipientClass: stringColumn(row, "recipient_class"),
          recipientEncPubHex: stringColumn(row, "recipient_enc_pub_hex"),
        })),
    ),
  wrapStoredRecipient: (
    environmentId: string,
    epoch: number,
    recipientUserId: string,
    recipientEncPubHex: string,
  ) =>
    Effect.sync(() => {
      const row = sql
        .exec(
          "SELECT recipient_class, recipient_enc_pub_hex FROM dek_wraps WHERE environment_id = ? AND epoch = ? AND recipient_user_id = ? AND recipient_enc_pub_hex = ? LIMIT 1",
          environmentId,
          epoch,
          recipientUserId,
          recipientEncPubHex,
        )
        .toArray()[0];
      return row === undefined
        ? null
        : {
            recipientClass: stringColumn(row, "recipient_class"),
            recipientEncPubHex: stringColumn(row, "recipient_enc_pub_hex"),
          };
    }),
  // Distribution is to the recipient only (§12-6). A server-class row
  // cannot be looked up by user_id because the identifier shapes do
  // not intersect, but the class condition is stated explicitly to pin
  // the boundary
  listWrapsForRecipient: (environmentId: string, recipientUserId: string) =>
    Effect.sync(() =>
      selectWrapRows(sql, {
        environmentId,
        recipientClass: "member",
        recipientUserId,
        extraColumns:
          "recipient_enc_pub_hex, signature_hex, signer_user_id, signer_key_fingerprint",
      }).map((row) => ({
        ...wrapBodyOf(row),
        recipientEncPubHex: stringColumn(row, "recipient_enc_pub_hex"),
        signatureHex: stringColumn(row, "signature_hex"),
        signerUserId: stringColumn(row, "signer_user_id"),
        signerKeyFingerprintHex: stringColumn(row, "signer_key_fingerprint"),
      })),
    ),
  // Narrowing by FP as well keeps an environment that went through
  // revocation → re-grant under a different key from grabbing a row
  // addressed to the old server key that the current key cannot unwrap
  // (an unwrap failure is indistinguishable from a poisoned wrap and
  // would muddy the 503's reason)
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
      // An expired window, a first request, and a clock rewind all mean
      // "count from 0" = always allowed
      if (current === null || current.count < limit) {
        return { allowed: true, retryAfterSeconds: 0 };
      }
      return {
        allowed: false,
        retryAfterSeconds: Math.ceil((LEASE_WINDOW_MS - current.elapsed) / 1000),
      };
    }),
  isMirrorSync: () => sql.exec("SELECT 1 FROM mirror_state WHERE id = 1").toArray().length > 0,
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
    // Placing the GC first keeps an expired leftover of the same key
    // from blocking a new binding's record via a primary-key conflict
    // (the query side already ignores it via the expires_at condition)
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
 * The row of the currently-live fixed window (expired, first request,
 * or a clock rewind → null = count from 0). The single place where
 * judgment and consumption share the same "live window" definition.
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
 * The common SELECT of wrap rows (only the columns differ between
 * distribution and lease material). Ordered by ascending epoch.
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
 * The common part of a wrap row. `storedSuite` makes an unknown suite a
 * defect (a value the v1 write path cannot produce; it is never
 * silently distributed or re-wrapped as v1 — the same discipline as
 * the §13-5 recovery blob).
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
