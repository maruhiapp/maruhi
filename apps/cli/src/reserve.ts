// The reserve key (CRYPTO_SPEC §3 / §8 — 2026-09-19 DK; design
// record dk-design.md §9 K4-1 / K4-2).
//
// Of the key pairs shaped like a device key, the reserve key is the
// one whose private half is **kept out of everyday devices and only
// in the ledger (§8)**. On the chain it is an ordinary device key
// registered via `add_device` (cap (owner, all)) and it receives DEK
// wraps. This CLI holds the reserve key's secret **only inside the
// process memory** of a sealing (code / passkey / guardians), a
// restore, or a ledger change — it is written neither to the
// keychain nor to agent memory (§8.5's prohibitions, K4-1).
//
// Types close the storage path (K4-1 a-5): the reserve key travels
// as {@link ReserveKeys} (brand `reserve`), and keychain storage
// (session.ts's `storeMasterKeyAndReport`) accepts only a device
// key's `MasterKeys`. Code that tries to store a reserve key is a
// type error.
//
// The reserve key's **public** side (FP, public keys, cap) goes into
// the local own-devices record (own-devices.ts — provenance
// "reserve"), the material the first-sync device registration
// (device-sync.ts) uses to `add_device` to each project (K4-3).

import { ALL_SCOPE, type EncryptionKeyPair, type SigningKeyPair } from "@maruhi/crypto";
import { Effect } from "effect";

import { cliError, type CliError } from "./errors.ts";
import type { CliIo } from "./io.ts";
import { generateKeyRecord } from "./key-record.ts";
import type { StoredMasterKey } from "./keychain.ts";
import { logNote, logWarning } from "./notice.ts";
import { type OwnDeviceEntry, OwnDeviceStore } from "./own-devices.ts";
import { type CliSession, importMasterKeys } from "./session.ts";

/**
 * The reserve key, imported and ready to use, held in memory only. The brand
 * keeps it out of every keychain-storing function (those take `MasterKeys`).
 */
export interface ReserveKeys {
  readonly reserve: true;
  readonly record: StoredMasterKey;
  readonly encKeyPair: EncryptionKeyPair;
  readonly sigKeyPair: SigningKeyPair;
  readonly fingerprintHex: string;
}

/** Loads a record decrypted from the ledger (or a generated record) as the reserve key. */
function reserveKeysFromRecord(record: StoredMasterKey): Effect.Effect<ReserveKeys, CliError> {
  return importMasterKeys(record).pipe(
    Effect.mapError(() =>
      cliError(
        "The reserve-key record cannot be loaded (unknown suite or corrupt). Update maruhi to the latest version and re-run",
      ),
    ),
    Effect.map((keys): ReserveKeys => ({
      reserve: true,
      record: keys.record,
      encKeyPair: keys.encKeyPair,
      sigKeyPair: keys.sigKeyPair,
      fingerprintHex: keys.fingerprintHex,
    })),
  );
}

/**
 * Generates a fresh reserve key (memory only — the caller seals it into the ledger).
 * The record carries the reserve-key mark (`kind: "reserve"` — CRYPTO_SPEC §8, DK K16):
 * the one positive fact that a ledger key is a reserve key.
 */
export function generateReserveKeys(): Effect.Effect<ReserveKeys, CliError> {
  return Effect.flatMap(generateKeyRecord(), (record) =>
    reserveKeysFromRecord({ ...record, kind: "reserve" }),
  );
}

/** Whether the key opened from the ledger carries the mark this CLI wrote when generating it as a reserve key (DK K16-6). */
export function isMarkedReserve(reserve: ReserveKeys): boolean {
  return reserve.record.kind === "reserve";
}

/** The own-devices row for a reserve key (cap (owner, all) — CRYPTO_SPEC §3). */
function reserveEntryOf(reserve: ReserveKeys, nowMs: number): OwnDeviceEntry {
  return {
    keyFingerprintHex: reserve.fingerprintHex,
    encPubHex: reserve.record.encPubHex,
    sigPubHex: reserve.record.sigPubHex,
    roleCap: "owner",
    scope: ALL_SCOPE,
    source: "reserve",
    label: "reserve",
    addedByFingerprintHex: null,
    observedProjectId: null,
    recordedAtMs: nowMs,
    revokedAtMs: null,
  };
}

/**
 * Records the reserve key's public side locally (K4-3 (1)). A write failure is
 * reported as a typed failure: without the record the reserve key never reaches
 * the project chains, so the caller must not report the sealing as complete.
 */
export function recordReserveLocally(
  session: CliSession,
  reserve: ReserveKeys,
): Effect.Effect<void, CliError, OwnDeviceStore> {
  return Effect.flatMap(OwnDeviceStore, (store) =>
    store.record(session.origin, session.userId, reserveEntryOf(reserve, Date.now())),
  );
}

/** The locally recorded reserve keys (not revoked), newest first. */
export function recordedReserves(
  session: CliSession,
): Effect.Effect<readonly OwnDeviceEntry[], CliError, OwnDeviceStore> {
  return Effect.gen(function* () {
    const store = yield* OwnDeviceStore;
    const loaded = yield* store.load(session.origin, session.userId);
    if (loaded.state !== "loaded") {
      return [];
    }
    return loaded.devices
      .filter((device) => device.source === "reserve" && device.revokedAtMs === null)
      .toSorted((a, b) => b.recordedAtMs - a.recordedAtMs);
  });
}

/**
 * When the ledger's key is found to be revoked and this device has
 * it recorded as reserve, attach the revocation mark (DK K14-4
 * 4-g). No row = do nothing. A write failure does not fail the
 * command — it becomes a Warning.
 */
export function markRevokedReserveRecord(
  session: CliSession,
  fingerprintHex: string,
): Effect.Effect<void, never, OwnDeviceStore | CliIo> {
  return Effect.gen(function* () {
    const store = yield* OwnDeviceStore;
    const loaded = yield* store.load(session.origin, session.userId);
    const recorded =
      loaded.state === "loaded" &&
      loaded.devices.some(
        (row) =>
          row.keyFingerprintHex === fingerprintHex &&
          row.source === "reserve" &&
          row.revokedAtMs === null,
      );
    if (!recorded) {
      return;
    }
    yield* store.markRevoked(session.origin, session.userId, [fingerprintHex], Date.now());
    yield* logNote(
      `this machine had recorded ${fingerprintHex} as your reserve key; it is revoked, so the record now says so`,
    );
  }).pipe(
    Effect.catch((error) =>
      logWarning(
        `could not correct this machine's record of ${fingerprintHex} (${error.message}); check it with \`maruhi key show\``,
      ),
    ),
  );
}
