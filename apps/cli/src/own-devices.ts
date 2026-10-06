// Recording the provenance of my device keys (design record
// dk-design.md §9 K4-3 / K4-4 — DK-D's 3 conditions).
//
// The keys that first-sync device registration (device-sync.ts) may
// `add_device` to a new project are limited to 3: (1) a key I
// generated (the reserve key), (2) a key I approved via `device
// approve`, (3) a key observed as that person's device on a verified
// chain (AUTH_SPEC §13-11). This record holds those 3 provenances as
// **non-secret** configuration (public keys, FP, cap, provenance,
// time only. No secret key — compatible with the diskless
// invariant).
//
// The only writers are the 3 paths (sealing a reserve key, approve,
// observation on a verified chain); the response of the device
// registry (`GET /auth/devices` — a server declaration = advisory) is
// **neither a reader nor a writer** (if the registry were a source of
// truth, the server could insert a fake public key and make the CLI
// append a ghost device — DK-D). The negative in device-sync.test.ts
// pins this.
//
// Recording revocation (`revokedAtMs`): set on running `device
// revoke` and on observing my device's `revoke_device` on a verified
// chain. A marked row is never re-added (so first sync does not
// resurrect a compromised key or a four-eyes vote — CRYPTO_SPEC
// §6.2). Only re-approval (`device approve`) overwrites the row and
// clears the flag (an explicit operation).
//
// Storage is the same family as the fingerprint ledger (<config
// dir>/own-devices.json — per-user, cross-project). fail-open:
// absent = no record, corrupt = no record + a distinguishable
// warning. Overwriting a corrupt file is refused (same discipline as
// pins / the fingerprint ledger).

import { dirname, join } from "node:path";

import * as BunFileSystem from "@effect/platform-bun/BunFileSystem";
import type { DeviceCap, MemberScope, Role } from "@maruhi/crypto";
import { memberScopeOf, scopePayloadFieldsOf } from "@maruhi/crypto";
import { Context, Effect, Result, Schema, SchemaGetter } from "effect";

import { cliError, type CliError } from "./errors.ts";
import { floorRecordGet } from "./floor.ts";
import {
  Hex32,
  Hex64,
  type LedgerRead,
  PositiveInt,
  readJsonFile,
  recordKeysMatch,
  ScopeEnvironmentIds,
  writeJsonFileAtomic,
} from "./json-record.ts";
import { BOOK_KEY, originBookSchema } from "./origin-book.ts";

/** Where the record came from (the three DK-D conditions). */
export type OwnDeviceSource = "reserve" | "approved" | "observed";

/** One recorded key of the user's own (non-secret: public keys, cap, provenance). */
export interface OwnDeviceRecord {
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly roleCap: Role;
  readonly scope: MemberScope;
  readonly source: OwnDeviceSource;
  /** Display label chosen at `device add` / `approve` (this machine's copy — not the registry). */
  readonly label: string | null;
  /** The device that appended the `add_device` when observed on a chain (null for the first key / unknown). */
  readonly addedByFingerprintHex: string | null;
  /** The project the key was first observed on (observed rows only). */
  readonly observedProjectId: string | null;
  readonly recordedAtMs: number;
  /** Set when the key was revoked (by this machine or observed on a verified chain). Never re-added. */
  readonly revokedAtMs: number | null;
}

/** The record with its fingerprint (the map key). */
export interface OwnDeviceEntry extends OwnDeviceRecord {
  readonly keyFingerprintHex: string;
}

/** Load result (fail-open: `corrupt` is distinguishable from `missing`). */
export type OwnDevicesLookup =
  | { readonly state: "loaded"; readonly devices: readonly OwnDeviceEntry[] }
  | { readonly state: "missing" }
  | { readonly state: "corrupt" };

/** Load / record boundary for the own-devices file. */
export interface OwnDeviceStoreShape {
  readonly filePath: string;
  readonly load: (origin: string, userId: string) => Effect.Effect<OwnDevicesLookup, CliError>;
  /** Upsert one record (read-merge-write). A re-approval overwrites a revoked row. */
  readonly record: (
    origin: string,
    userId: string,
    entry: OwnDeviceEntry,
  ) => Effect.Effect<void, CliError>;
  /** Marks fingerprints revoked (rows that do not exist are created as revoked "observed" rows only when keys are given). */
  readonly markRevoked: (
    origin: string,
    userId: string,
    fingerprintsHex: readonly string[],
    nowMs: number,
  ) => Effect.Effect<void, CliError>;
}

export class OwnDeviceStore extends Context.Service<OwnDeviceStore, OwnDeviceStoreShape>()(
  "cli/OwnDeviceStore",
) {}

/** The record's location (same family as the config: <config.json's parent>/own-devices.json). */
export function ownDevicesPathOf(configPath: string): string {
  return join(dirname(configPath), "own-devices.json");
}

/** The cap a record declares (`add_device` payload — CRYPTO_SPEC §6.2). */
export function capOfRecord(record: OwnDeviceRecord): DeviceCap {
  return { roleCap: record.roleCap, scope: record.scope };
}

interface OwnDevicesFile {
  readonly v: 1;
  readonly known: Readonly<
    Record<string, Readonly<Record<string, Readonly<Record<string, OwnDeviceRecord>>>>>
  >;
}

const HEX_32 = /^[0-9a-f]{32}$/;
const ROLES = ["reader", "member", "admin", "owner"] as const;
const SOURCES = ["reserve", "approved", "observed"] as const;

// The entry as stored: the scope is the wire pair scopeKind +
// scopeEnvironmentIds (the §6.2 normalization field order — the all scope
// carries the empty list, checked structurally).
const WireEntrySchema = Schema.Struct({
  encPubHex: Hex64,
  sigPubHex: Hex64,
  roleCap: Schema.Literals(ROLES),
  scopeKind: Schema.Literals(["all", "listed"]),
  scopeEnvironmentIds: Schema.Array(Schema.String),
  source: Schema.Literals(SOURCES),
  label: Schema.NullOr(Schema.String),
  addedByFingerprintHex: Schema.NullOr(Hex32),
  observedProjectId: Schema.NullOr(Schema.String),
  recordedAtMs: PositiveInt,
  revokedAtMs: Schema.NullOr(PositiveInt),
}).check(
  Schema.makeFilter(
    (entry) =>
      entry.scopeKind !== "all" ||
      entry.scopeEnvironmentIds.length === 0 ||
      "an 'all' scope carries no environment ids",
  ),
);

// The entry as held: the scope is the derived MemberScope (the union
// member for `listed` carries the id-format / at most 256 / no
// duplicates rules of §6.2).
const DomainEntrySchema = Schema.Struct({
  encPubHex: Hex64,
  sigPubHex: Hex64,
  roleCap: Schema.Literals(ROLES),
  scope: Schema.Union([
    Schema.Struct({ kind: Schema.Literal("all") }),
    Schema.Struct({
      kind: Schema.Literal("listed"),
      environmentIds: ScopeEnvironmentIds,
    }),
  ]),
  source: Schema.Literals(SOURCES),
  label: Schema.NullOr(Schema.String),
  addedByFingerprintHex: Schema.NullOr(Hex32),
  observedProjectId: Schema.NullOr(Schema.String),
  recordedAtMs: PositiveInt,
  revokedAtMs: Schema.NullOr(PositiveInt),
});

// One codec: the wire pair ↔ the derived scope (memberScopeOf /
// scopePayloadFieldsOf — the same transform every scope-carrying payload uses).
const EntrySchema = WireEntrySchema.pipe(
  Schema.decodeTo(DomainEntrySchema, {
    decode: SchemaGetter.transform((wire: typeof WireEntrySchema.Type) => {
      const { scopeKind, scopeEnvironmentIds, ...rest } = wire;
      return { ...rest, scope: memberScopeOf({ scopeKind, scopeEnvironmentIds }) };
    }),
    encode: SchemaGetter.transform((domain: typeof DomainEntrySchema.Encoded) => {
      const { scope, ...rest } = domain;
      return { ...rest, ...scopePayloadFieldsOf(scope) };
    }),
  }),
);

/** Strict decoding (no partial reads — same as pins / the fingerprint ledger). */
const FileSchema = originBookSchema(
  1,
  Schema.Record(Schema.String, EntrySchema).check(recordKeysMatch(HEX_32)),
);

/** File-backed own-devices store at `path` (used by both production and tests). */
export function makeFileOwnDeviceStore(path: string): OwnDeviceStoreShape {
  const writeError = () =>
    cliError(
      `Cannot write the own-devices record (corrupt or an I/O failure): ${path} — inspect it, and if the modification was unintended, delete it and re-run`,
    );

  // Reads are fail-open at the ledger level: only NotFound is `missing`,
  // and an unreadable file (EACCES / EISDIR / EIO) is the `corrupt`
  // state, not an error — `load` callers (recordedReserves in reserve.ts
  // via `key show`, staleReserveFingerprints in key-recover.ts) treat
  // any non-`loaded` state as "no records" and degrade, while `merge`
  // refuses to write over it.
  const loadLedger = readJsonFile(path, FileSchema).pipe(
    Effect.orElseSucceed((): LedgerRead<OwnDevicesFile> => ({ state: "corrupt" })),
    Effect.provide(BunFileSystem.layer),
  );

  const merge = (
    origin: string,
    userId: string,
    apply: (devices: Readonly<Record<string, OwnDeviceRecord>>) => Record<string, OwnDeviceRecord>,
  ): Effect.Effect<void, CliError> =>
    Effect.gen(function* () {
      if (!BOOK_KEY.test(origin) || !BOOK_KEY.test(userId)) {
        return yield* Effect.fail(writeError());
      }
      const loaded = yield* loadLedger;
      if (loaded.state === "corrupt") {
        // Refuse overwriting a corrupt file (same discipline as pins / the fingerprint ledger)
        return yield* Effect.fail(writeError());
      }
      const base: OwnDevicesFile = loaded.state === "missing" ? { v: 1, known: {} } : loaded.file;
      const users = floorRecordGet(base.known, origin) ?? {};
      const devices = floorRecordGet(users, userId) ?? {};
      yield* writeJsonFileAtomic(path, FileSchema, {
        v: 1,
        known: { ...base.known, [origin]: { ...users, [userId]: apply(devices) } },
      });
    }).pipe(Effect.mapError(writeError), Effect.provide(BunFileSystem.layer));

  return {
    filePath: path,
    load: Effect.fn("own-devices.load")(function* (origin, userId): Effect.fn.Return<
      OwnDevicesLookup,
      CliError
    > {
      const loaded = yield* loadLedger;
      if (loaded.state === "missing") {
        return { state: "missing" };
      }
      if (loaded.state === "corrupt") {
        return { state: "corrupt" };
      }
      const users = floorRecordGet(loaded.file.known, origin);
      const devices = users === undefined ? undefined : floorRecordGet(users, userId);
      return {
        state: "loaded",
        devices: Object.entries(devices ?? {}).map(([keyFingerprintHex, record]) => ({
          keyFingerprintHex,
          ...record,
        })),
      };
    }),
    record: (origin, userId, entry) => {
      const { keyFingerprintHex, ...record } = entry;
      if (
        !HEX_32.test(keyFingerprintHex) ||
        Result.isFailure(Schema.encodeResult(EntrySchema)(record))
      ) {
        return Effect.fail(
          cliError("Cannot record the device: the key material is not in the expected form"),
        );
      }
      return merge(origin, userId, (devices) => ({ ...devices, [keyFingerprintHex]: record }));
    },
    markRevoked: (origin, userId, fingerprintsHex, nowMs) =>
      merge(origin, userId, (devices) => {
        const next = { ...devices };
        for (const fingerprintHex of fingerprintsHex) {
          const existing = floorRecordGet(devices, fingerprintHex);
          if (existing !== undefined && existing.revokedAtMs === null) {
            next[fingerprintHex] = { ...existing, revokedAtMs: nowMs };
          }
        }
        return next;
      }),
  };
}
