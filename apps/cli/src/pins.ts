import { dirname, join } from "node:path";

import * as BunFileSystem from "@effect/platform-bun/BunFileSystem";
import { type EnvironmentId, type ProjectId, type UserId, UserIdSchema } from "@maruhi/core";
import type { ScopeKind } from "@maruhi/crypto";
import { Clock, Context, Effect, Schema } from "effect";

import { cliError, type CliError } from "./errors.ts";
import { floorRecordGet } from "./floor.ts";
import { GITHUB_LOGIN } from "./invite-link.ts";
import {
  Hex32,
  Hex64,
  PositiveInt,
  readJsonFile,
  recordKeysMatch,
  ScopeEnvironmentIds,
  writeJsonFileAtomic,
} from "./json-record.ts";

export interface InviteAnchor {
  readonly headSeq: number;
  readonly headHashHex: string;
  readonly inviterUserId: UserId;
  readonly inviterKeyFingerprintHex: string;
  readonly inviterSigPubHex: string;
  readonly verifiedAtSeq: number | null;
}

export interface IssuedInvitePin {
  readonly linkPubHex: string;
  readonly role: "reader" | "member" | "admin";
  readonly scopeKind: ScopeKind;
  readonly scopeEnvironmentIds: readonly EnvironmentId[];
  readonly expiresAtMs: number;
  readonly expectedGithubLogin: string | null;
}

export interface InvitePins {
  readonly v: 1;
  readonly anchor: InviteAnchor | null;
  readonly issued: Readonly<Record<string, IssuedInvitePin>>;
}

export interface PinsLoadResult {
  readonly pins: InvitePins | null;
  readonly state: "loaded" | "missing" | "corrupt";
}

export interface PinStoreShape {
  readonly load: (projectId: ProjectId) => Effect.Effect<PinsLoadResult, CliError>;
  readonly saveAnchor: (
    projectId: ProjectId,
    anchor: InviteAnchor,
  ) => Effect.Effect<void, CliError>;
  readonly saveIssuedPin: (
    projectId: ProjectId,
    inviteId: string,
    pin: IssuedInvitePin,
  ) => Effect.Effect<void, CliError>;
}

export class PinStore extends Context.Service<PinStore, PinStoreShape>()("cli/PinStore") {}

export function pinsDirOf(configPath: string): string {
  return join(dirname(configPath), "invites");
}

const ISSUED_PIN_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;

const INVITE_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

const InviteAnchorSchema = Schema.Struct({
  headSeq: PositiveInt,
  headHashHex: Hex64,
  inviterUserId: UserIdSchema.check(Schema.isPattern(/^.{1,1024}$/s)),
  inviterKeyFingerprintHex: Hex32,
  inviterSigPubHex: Hex64,
  verifiedAtSeq: Schema.NullOr(PositiveInt),
});

const IssuedPinSchema = Schema.Struct({
  linkPubHex: Hex64,
  role: Schema.Literals(["reader", "member", "admin"]),
  scopeKind: Schema.Literals(["all", "listed"]),
  scopeEnvironmentIds: ScopeEnvironmentIds,
  expiresAtMs: PositiveInt,
  expectedGithubLogin: Schema.NullOr(Schema.String.check(Schema.isPattern(GITHUB_LOGIN))),
}).check(
  Schema.makeFilter(
    (pin) =>
      pin.scopeKind !== "all" ||
      pin.scopeEnvironmentIds.length === 0 ||
      "an 'all' scope carries no environment ids",
  ),
);

const PinsFileSchema = Schema.Struct({
  v: Schema.Literal(1),
  anchor: Schema.NullOr(InviteAnchorSchema),
  issued: Schema.Record(Schema.String, IssuedPinSchema).check(recordKeysMatch(INVITE_ID)),
});

export function issuedPinOf(
  pins: InvitePins | null,
  inviteId: string,
): IssuedInvitePin | undefined {
  return pins === null ? undefined : floorRecordGet(pins.issued, inviteId);
}

const mintLoadedFile = (file: (typeof PinsFileSchema)["Type"]): InvitePins => ({
  ...file,
  anchor: file.anchor === null ? null : file.anchor,
});

export function makeFilePinStore(dir: string): PinStoreShape {
  const pathOf = (projectId: ProjectId) => join(dir, `${projectId}.json`);
  const writeError = (projectId: ProjectId) =>
    cliError(
      `Cannot write the invite-pin file (corrupt or an I/O failure): ${pathOf(projectId)} — inspect it, and if the modification was unintended, delete it and re-run`,
    );

  const merge = (
    projectId: ProjectId,
    apply: (pins: InvitePins) => InvitePins,
  ): Effect.Effect<void, CliError> =>
    Effect.gen(function* () {
      const loaded = yield* readJsonFile(pathOf(projectId), PinsFileSchema);
      if (loaded.state === "corrupt") {
        return yield* Effect.fail(writeError(projectId));
      }
      const base: InvitePins =
        loaded.state === "missing"
          ? { v: 1, anchor: null, issued: {} }
          : mintLoadedFile(loaded.file);
      yield* writeJsonFileAtomic(pathOf(projectId), PinsFileSchema, apply(base));
    }).pipe(
      Effect.mapError(() => writeError(projectId)),
      Effect.provide(BunFileSystem.layer),
    );

  const load = (projectId: ProjectId) =>
    readJsonFile(pathOf(projectId), PinsFileSchema).pipe(
      Effect.map((loaded): PinsLoadResult => {
        switch (loaded.state) {
          case "missing":
            return { pins: null, state: "missing" };
          case "corrupt":
            return { pins: null, state: "corrupt" };
          case "loaded":
            return { pins: mintLoadedFile(loaded.file), state: "loaded" };
        }
      }),
      Effect.mapError(() => cliError(`Cannot read the invite-pin file: ${pathOf(projectId)}`)),
      Effect.provide(BunFileSystem.layer),
    );

  return {
    load,
    saveAnchor: (projectId, anchor) => merge(projectId, (pins) => ({ ...pins, anchor })),
    saveIssuedPin: (projectId, inviteId, pin) => {
      if (!INVITE_ID.test(inviteId)) {
        return Effect.fail(
          cliError(
            "Cannot save the issuance pin because the invite id in the server response is not in the expected form",
          ),
        );
      }
      return Effect.flatMap(Clock.currentTimeMillis, (now) =>
        merge(projectId, (pins) => {
          const kept = Object.entries(pins.issued).filter(
            ([, existing]) => existing.expiresAtMs + ISSUED_PIN_RETENTION_MS > now,
          );
          return { ...pins, issued: { ...Object.fromEntries(kept), [inviteId]: pin } };
        }),
      );
    },
  };
}
