// Repository of the device registry and device-add requests
// (AUTH_SPEC §13-11 — 2026-09-19 DK K3).
//
// - An advisory ledger: where display labels, token associations, and
//   request public keys live. Never an input to verification or
//   authorization (the source of truth is each project's chain). No
//   audit events (same discipline as §6's token listing — device
//   additions and revocations are recorded as the chain's mirror rows)
// - Drizzle types and queries stay inside this file (within the
//   db.package boundary). The public shapes are domain types and Effect
//   only
// - Request rows carry no state column (a row = an unconsumed request;
//   expired rows are hidden on reads and opportunistically deleted on
//   create / list — design record dk-design.md §8 K3-8). The rate window
//   uses key_wrap_windows with kind `device-request`
//   (KeyWrapRepo.consumeWindow — no extra fixed-window implementation)

import type { KeyFingerprintHex, UserId } from "@maruhi/core";
import { and, count, eq, gt, lte, sql } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Effect } from "effect";

import { tryD1 } from "./errors.ts";
import { deviceAddRequests, devices } from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

// D1 access goes through the shared tryD1 adapter (errors.ts —
// ADR-0006). Every method pipes `Effect.orDie` at its boundary: the
// public repository types keep an empty error channel because the
// handlers turning D1FailureError into typed errors belong to other
// lanes. An unexpected D1 failure stays a defect = a 500, as before.
// Only domain-level branches are returned as values

/** One registry row (§13-11). */
export interface DeviceRecord {
  readonly keyFingerprintHex: KeyFingerprintHex;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly label: string;
  readonly tokenId: string | null;
  readonly createdAtMs: number;
}

/** One device-add request row (only unexpired ones are returned). */
export interface DeviceAddRequestRecord {
  readonly keyFingerprintHex: KeyFingerprintHex;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly label: string;
  readonly expiresAtMs: number;
}

export interface DeviceRepoShape {
  readonly list: (userId: UserId) => Effect.Effect<readonly DeviceRecord[]>;
  /**
   * Register in the registry / update the display label (upsert). A new
   * row enters only when under `limit` (a conditional INSERT — concurrent
   * registrations observing the same under-limit cannot exceed it).
   * Updating an existing row does not count toward the cap. Return value
   * false = cap refusal.
   */
  readonly upsert: (input: {
    readonly userId: UserId;
    readonly keyFingerprintHex: KeyFingerprintHex;
    readonly encPubHex: string;
    readonly sigPubHex: string;
    readonly label: string;
    readonly tokenId: string | null;
    readonly limit: number;
    readonly nowMs: number;
  }) => Effect.Effect<boolean>;
  /** Return value = whether a row actually disappeared (false → the caller's uniform 404). */
  readonly remove: (userId: UserId, keyFingerprintHex: KeyFingerprintHex) => Effect.Effect<boolean>;
  /**
   * Create an add request. An unexpired request for the same FP =
   * `request-exists`; an existing registry row = `device-registered`
   * (§13-11's 409s). An expired request for the same FP is replaced.
   */
  readonly requestCreate: (input: {
    readonly userId: UserId;
    readonly keyFingerprintHex: KeyFingerprintHex;
    readonly encPubHex: string;
    readonly sigPubHex: string;
    readonly label: string;
    readonly nowMs: number;
    readonly ttlMs: number;
  }) => Effect.Effect<"created" | "request-exists" | "device-registered">;
  /** Unexpired requests only. */
  readonly requestList: (
    userId: UserId,
    nowMs: number,
  ) => Effect.Effect<readonly DeviceAddRequestRecord[]>;
  readonly requestFind: (
    userId: UserId,
    keyFingerprintHex: KeyFingerprintHex,
    nowMs: number,
  ) => Effect.Effect<DeviceAddRequestRecord | null>;
  /** Return value = whether a row actually disappeared (expired rows can be removed too — doubles as cleanup). */
  readonly requestCancel: (
    userId: UserId,
    keyFingerprintHex: KeyFingerprintHex,
  ) => Effect.Effect<boolean>;
  /** Opportunistic deletion of expired requests (that user only — call before create / list). */
  readonly requestSweep: (userId: UserId, nowMs: number) => Effect.Effect<void>;
}

export class DeviceRepo extends Context.Service<DeviceRepo, DeviceRepoShape>()("DeviceRepo") {}

const toRequest = (row: {
  readonly keyFingerprintHex: KeyFingerprintHex;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly label: string;
  readonly expiresAt: number;
}): DeviceAddRequestRecord => ({
  keyFingerprintHex: row.keyFingerprintHex,
  encPubHex: row.encPubHex,
  sigPubHex: row.sigPubHex,
  label: row.label,
  expiresAtMs: row.expiresAt,
});

export function makeDeviceRepo(db: Db): DeviceRepoShape {
  return {
    list: (userId) =>
      tryD1(async () => {
        const rows = await db
          .select()
          .from(devices)
          .where(eq(devices.userId, userId))
          .orderBy(devices.createdAt, devices.keyFingerprintHex);
        return rows.map((row): DeviceRecord => ({
          keyFingerprintHex: row.keyFingerprintHex,
          encPubHex: row.encPubHex,
          sigPubHex: row.sigPubHex,
          label: row.label,
          tokenId: row.tokenId,
          createdAtMs: row.createdAt,
        }));
      }).pipe(Effect.orDie),
    upsert: ({ userId, keyFingerprintHex, encPubHex, sigPubHex, label, tokenId, limit, nowMs }) =>
      tryD1(async () => {
        // A single capped INSERT … SELECT … ON CONFLICT DO UPDATE
        // statement (same shape as TokenRepo — concurrent registrations
        // cannot overrun). If a row for the same (user, FP) exists, only
        // the label and token id are updated (the public keys are the
        // same key pair when the FP matches = immutable). Existing rows
        // do not count toward the cap (updates pass on the WHERE's OR
        // side). Concurrent first PUTs to the same FP split into one
        // INSERT and one primary-key conflict → DO UPDATE; both end up
        // an idempotent 204
        const upserted = await db
          .insert(devices)
          .select(
            db
              .select({
                userId: sql<UserId>`${userId}`.as("user_id"),
                keyFingerprintHex: sql<KeyFingerprintHex>`${keyFingerprintHex}`.as(
                  "key_fingerprint_hex",
                ),
                encPubHex: sql<string>`${encPubHex}`.as("enc_pub_hex"),
                sigPubHex: sql<string>`${sigPubHex}`.as("sig_pub_hex"),
                label: sql<string>`${label}`.as("label"),
                tokenId: sql<string | null>`${tokenId}`.as("token_id"),
                createdAt: sql<number>`${nowMs}`.as("created_at"),
              })
              .from(sql`(select 1)`)
              .where(
                sql`(select count(*) from ${devices} where ${devices.userId} = ${userId}) < ${limit}
                  or exists(select 1 from ${devices} where ${devices.userId} = ${userId}
                            and ${devices.keyFingerprintHex} = ${keyFingerprintHex})`,
              ),
          )
          .onConflictDoUpdate({
            target: [devices.userId, devices.keyFingerprintHex],
            set: { label, tokenId },
          })
          .returning({ fp: devices.keyFingerprintHex });
        return upserted.length === 1;
      }).pipe(Effect.orDie),
    remove: (userId, keyFingerprintHex) =>
      tryD1(async () => {
        const deleted = await db
          .delete(devices)
          .where(and(eq(devices.userId, userId), eq(devices.keyFingerprintHex, keyFingerprintHex)))
          .returning({ fp: devices.keyFingerprintHex });
        return deleted.length === 1;
      }).pipe(Effect.orDie),
    requestCreate: ({ userId, keyFingerprintHex, encPubHex, sigPubHex, label, nowMs, ttlMs }) =>
      tryD1(async () => {
        const registered = await db
          .select({ n: count() })
          .from(devices)
          .where(and(eq(devices.userId, userId), eq(devices.keyFingerprintHex, keyFingerprintHex)))
          .get();
        if ((registered?.n ?? 0) > 0) {
          return "device-registered";
        }
        // An unexpired same-FP row conflicts; an expired one is replaced
        // (ON CONFLICT … WHERE expires_at <= now)
        const rows = await db
          .insert(deviceAddRequests)
          .values({
            userId,
            keyFingerprintHex,
            encPubHex,
            sigPubHex,
            label,
            createdAt: nowMs,
            expiresAt: nowMs + ttlMs,
          })
          .onConflictDoUpdate({
            target: [deviceAddRequests.userId, deviceAddRequests.keyFingerprintHex],
            set: {
              encPubHex,
              sigPubHex,
              label,
              createdAt: nowMs,
              expiresAt: nowMs + ttlMs,
            },
            setWhere: sql`${deviceAddRequests.expiresAt} <= ${nowMs}`,
          })
          .returning({ fp: deviceAddRequests.keyFingerprintHex });
        return rows.length === 1 ? "created" : "request-exists";
      }).pipe(Effect.orDie),
    requestList: (userId, nowMs) =>
      tryD1(async () => {
        const rows = await db
          .select()
          .from(deviceAddRequests)
          .where(and(eq(deviceAddRequests.userId, userId), gt(deviceAddRequests.expiresAt, nowMs)))
          .orderBy(deviceAddRequests.createdAt, deviceAddRequests.keyFingerprintHex);
        return rows.map(toRequest);
      }).pipe(Effect.orDie),
    requestFind: (userId, keyFingerprintHex, nowMs) =>
      tryD1(async () => {
        const row = await db
          .select()
          .from(deviceAddRequests)
          .where(
            and(
              eq(deviceAddRequests.userId, userId),
              eq(deviceAddRequests.keyFingerprintHex, keyFingerprintHex),
              gt(deviceAddRequests.expiresAt, nowMs),
            ),
          )
          .get();
        return row === undefined ? null : toRequest(row);
      }).pipe(Effect.orDie),
    requestCancel: (userId, keyFingerprintHex) =>
      tryD1(async () => {
        const deleted = await db
          .delete(deviceAddRequests)
          .where(
            and(
              eq(deviceAddRequests.userId, userId),
              eq(deviceAddRequests.keyFingerprintHex, keyFingerprintHex),
            ),
          )
          .returning({ fp: deviceAddRequests.keyFingerprintHex });
        return deleted.length === 1;
      }).pipe(Effect.orDie),
    requestSweep: (userId, nowMs) =>
      tryD1(async () => {
        await db
          .delete(deviceAddRequests)
          .where(
            and(eq(deviceAddRequests.userId, userId), lte(deviceAddRequests.expiresAt, nowMs)),
          );
      }).pipe(Effect.orDie),
  };
}
