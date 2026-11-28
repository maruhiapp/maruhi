import type { EnvironmentId, KeyFingerprintHex, UserId } from "@maruhi/core";
import { Effect } from "effect";

import { LEASE_WINDOW_MS } from "../policy.ts";
import type { WireSuite } from "./data-plane.ts";
import {
  columnValue,
  keyFingerprintColumn,
  numberColumn,
  storedSuite,
  stringColumn,
  userIdColumn,
} from "./data-store-rows.ts";
import type { LeaseWindowKind } from "./data-store.ts";

export const makeWrapQueries = (sql: SqlStorage) => ({
  countWrapsForEpoch: (environmentId: EnvironmentId, epoch: number) =>
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
  listWrapSlots: (
    environmentId: EnvironmentId,
    epoch: number,
    recipientUserId: UserId | KeyFingerprintHex,
  ) =>
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
    environmentId: EnvironmentId,
    epoch: number,
    recipientUserId: UserId | KeyFingerprintHex,
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
  listWrapsForRecipient: (
    environmentId: EnvironmentId,
    recipientUserId: UserId | KeyFingerprintHex,
  ) =>
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
        signerUserId: userIdColumn(row, "signer_user_id"),
        signerKeyFingerprintHex: keyFingerprintColumn(row, "signer_key_fingerprint"),
      })),
    ),
  listServerWraps: (environmentId: EnvironmentId, serverKeyFingerprintHex: KeyFingerprintHex) =>
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

function selectWrapRows(
  sql: SqlStorage,
  query: {
    readonly environmentId: EnvironmentId;
    readonly recipientClass: "member" | "server";
    readonly recipientUserId: UserId | KeyFingerprintHex;
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
