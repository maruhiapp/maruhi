import { dirname, join } from "node:path";

import * as BunFileSystem from "@effect/platform-bun/BunFileSystem";
import { decodeEnvironmentId, type UserId } from "@maruhi/core";
import type { DeviceCap, MemberScope, Role } from "@maruhi/crypto";
import { memberScopeOf } from "@maruhi/crypto";
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

export type OwnDeviceSource = "reserve" | "approved" | "observed";

export interface OwnDeviceRecord {
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly roleCap: Role;
  readonly scope: MemberScope;
  readonly source: OwnDeviceSource;
  readonly label: string | null;
  readonly addedByFingerprintHex: string | null;
  readonly observedProjectId: string | null;
  readonly recordedAtMs: number;
  readonly revokedAtMs: number | null;
}

export interface OwnDeviceEntry extends OwnDeviceRecord {
  readonly keyFingerprintHex: string;
}

export type OwnDevicesLookup =
  | { readonly state: "loaded"; readonly devices: readonly OwnDeviceEntry[] }
  | { readonly state: "missing" }
  | { readonly state: "corrupt" };

export interface OwnDeviceStoreShape {
  readonly filePath: string;
  readonly load: (origin: string, userId: UserId) => Effect.Effect<OwnDevicesLookup, CliError>;
  readonly record: (
    origin: string,
    userId: UserId,
    entry: OwnDeviceEntry,
  ) => Effect.Effect<void, CliError>;
  readonly markRevoked: (
    origin: string,
    userId: UserId,
    fingerprintsHex: readonly string[],
    nowMs: number,
  ) => Effect.Effect<void, CliError>;
}

export class OwnDeviceStore extends Context.Service<OwnDeviceStore, OwnDeviceStoreShape>()(
  "cli/OwnDeviceStore",
) {}

export function ownDevicesPathOf(configPath: string): string {
  return join(dirname(configPath), "own-devices.json");
}

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

const entryKeyFields = {
  encPubHex: Hex64,
  sigPubHex: Hex64,
  roleCap: Schema.Literals(ROLES),
};
const entryRecordFields = {
  source: Schema.Literals(SOURCES),
  label: Schema.NullOr(Schema.String),
  addedByFingerprintHex: Schema.NullOr(Hex32),
  observedProjectId: Schema.NullOr(Schema.String),
  recordedAtMs: PositiveInt,
  revokedAtMs: Schema.NullOr(PositiveInt),
};

const WireEntrySchema = Schema.Struct({
  ...entryKeyFields,
  scopeKind: Schema.Literals(["all", "listed"]),
  scopeEnvironmentIds: Schema.Array(Schema.String),
  ...entryRecordFields,
}).check(
  Schema.makeFilter(
    (entry) =>
      entry.scopeKind !== "all" ||
      entry.scopeEnvironmentIds.length === 0 ||
      "an 'all' scope carries no environment ids",
  ),
);

const DomainEntrySchema = Schema.Struct({
  ...entryKeyFields,
  scope: Schema.Union([
    Schema.Struct({ kind: Schema.Literal("all") }),
    Schema.Struct({
      kind: Schema.Literal("listed"),
      environmentIds: ScopeEnvironmentIds,
    }),
  ]),
  ...entryRecordFields,
});

const EntrySchema = WireEntrySchema.pipe(
  Schema.decodeTo(DomainEntrySchema, {
    decode: SchemaGetter.transform((wire: typeof WireEntrySchema.Type) => {
      const { scopeKind, scopeEnvironmentIds, ...rest } = wire;
      return {
        ...rest,
        scope: memberScopeOf({
          scopeKind,
          scopeEnvironmentIds: scopeEnvironmentIds.map(decodeEnvironmentId),
        }),
      };
    }),
    encode: SchemaGetter.transform((domain: typeof DomainEntrySchema.Encoded) => {
      const { scope, ...rest } = domain;
      return {
        ...rest,
        ...(scope.kind === "all"
          ? { scopeKind: "all" as const, scopeEnvironmentIds: [] as readonly string[] }
          : { scopeKind: "listed" as const, scopeEnvironmentIds: [...scope.environmentIds] }),
      };
    }),
  }),
);

const FileSchema = originBookSchema(
  1,
  Schema.Record(Schema.String, EntrySchema).check(recordKeysMatch(HEX_32)),
);

export function makeFileOwnDeviceStore(path: string): OwnDeviceStoreShape {
  const writeError = () =>
    cliError(
      `Cannot write the own-devices record (corrupt or an I/O failure): ${path} — inspect it, and if the modification was unintended, delete it and re-run`,
    );

  const loadLedger = readJsonFile(path, FileSchema).pipe(
    Effect.orElseSucceed((): LedgerRead<OwnDevicesFile> => ({ state: "corrupt" })),
    Effect.provide(BunFileSystem.layer),
  );

  const merge = (
    origin: string,
    userId: UserId,
    apply: (devices: Readonly<Record<string, OwnDeviceRecord>>) => Record<string, OwnDeviceRecord>,
  ): Effect.Effect<void, CliError> =>
    Effect.gen(function* () {
      if (!BOOK_KEY.test(origin) || !BOOK_KEY.test(userId)) {
        return yield* Effect.fail(writeError());
      }
      const loaded = yield* loadLedger;
      if (loaded.state === "corrupt") {
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
