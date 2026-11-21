import { ALL_SCOPE, type EncryptionKeyPair, type SigningKeyPair } from "@maruhi/crypto";
import { Clock, Effect } from "effect";

import { cliError, type CliError } from "./errors.ts";
import type { CliIo } from "./io.ts";
import { generateKeyRecord } from "./key-record.ts";
import type { StoredMasterKey } from "./keychain.ts";
import { logNote, logWarning } from "./notice.ts";
import { type OwnDeviceEntry, OwnDeviceStore } from "./own-devices.ts";
import { type CliSession, importMasterKeys } from "./session.ts";

export interface ReserveKeys {
  readonly reserve: true;
  readonly record: StoredMasterKey;
  readonly encKeyPair: EncryptionKeyPair;
  readonly sigKeyPair: SigningKeyPair;
  readonly fingerprintHex: string;
}

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

export function generateReserveKeys(): Effect.Effect<ReserveKeys, CliError> {
  return Effect.flatMap(generateKeyRecord(), (record) =>
    reserveKeysFromRecord({ ...record, kind: "reserve" }),
  );
}

export function isMarkedReserve(reserve: ReserveKeys): boolean {
  return reserve.record.kind === "reserve";
}

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

export const recordReserveLocally = Effect.fn("reserve.recordReserveLocally")(function* (
  session: CliSession,
  reserve: ReserveKeys,
): Effect.fn.Return<void, CliError, OwnDeviceStore> {
  const store = yield* OwnDeviceStore;
  const nowMs = yield* Clock.currentTimeMillis;
  yield* store.record(session.origin, session.userId, reserveEntryOf(reserve, nowMs));
});

export const recordedReserves = Effect.fn("reserve.recordedReserves")(function* (
  session: CliSession,
): Effect.fn.Return<readonly OwnDeviceEntry[], CliError, OwnDeviceStore> {
  const store = yield* OwnDeviceStore;
  const loaded = yield* store.load(session.origin, session.userId);
  if (loaded.state !== "loaded") {
    return [];
  }
  return loaded.devices
    .filter((device) => device.source === "reserve" && device.revokedAtMs === null)
    .toSorted((a, b) => b.recordedAtMs - a.recordedAtMs);
});

export const markRevokedReserveRecord: (
  session: CliSession,
  fingerprintHex: string,
) => Effect.Effect<void, never, OwnDeviceStore | CliIo> = Effect.fn(
  "reserve.markRevokedReserveRecord",
)(
  function* (session: CliSession, fingerprintHex: string) {
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
    yield* store.markRevoked(
      session.origin,
      session.userId,
      [fingerprintHex],
      yield* Clock.currentTimeMillis,
    );
    yield* logNote(
      `this machine had recorded ${fingerprintHex} as your reserve key; it is revoked, so the record now says so`,
    );
  },
  (effect, session, fingerprintHex) =>
    effect.pipe(
      Effect.catch((error) =>
        logWarning(
          `could not correct this machine's record of ${fingerprintHex} (${error.message}); check it with \`maruhi key show\``,
        ),
      ),
    ),
);
