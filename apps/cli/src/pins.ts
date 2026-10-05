// The persistence layer of invite non-secret pinning (CRYPTO_SPEC
// §6.3 out-of-band anchor (a) and its inviter-side counterpart =
// the issue-time pin).
//
// - **Acceptor-side anchor**: the genesis the invite link's
//   fragment carries (= projectId, which the filename doubles as),
//   the inviter's verified head (hash + seq), the inviter's user_id
//   + key FP. Pinned at accept time; the sync-time mechanical
//   collation (context.ts) checks "head containment + inviter FP
//   membership match" (§6.3 (a) / §6.5).
// - **Issuer-side pin**: what `invite create` records — invite id →
//   (link_pub, role, expiry, destination login). At member add
//   time it collates against the list response (a server
//   declaration) to mechanically detect row substitution and role
//   misdeclaration (the defense symmetric to the acceptor-side
//   anchor). member add from a different device has no pin and
//   degrades to the ceremony's display check only (SHOULD).
//
// The contents are only public keys, hashes, sequence numbers,
// user_id, FP, role, and login — no plaintext values, key material,
// or link-key seeds (compatible with the diskless invariant).
// Storage is the same family as the floor (<config
// dir>/invites/<projectId>.json). Writes are temp + rename
// read-merge-write (same discipline as the floor).
//
// fail-open: a missing file is "no pin", corruption is "no pin + a
// distinguishable warning" (the caller emits it). An attacker who
// can erase local state is outside the pins' remit (reduces to
// §14.3-3's non-guarantee — the same boundary as the floor).

import { dirname, join } from "node:path";

import * as BunFileSystem from "@effect/platform-bun/BunFileSystem";
import type { ScopeKind } from "@maruhi/crypto";
import { Context, Effect, Schema } from "effect";

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

/** The acceptor-side invite-link anchor (§6.3 (a)). */
export interface InviteAnchor {
  readonly headSeq: number;
  readonly headHashHex: string;
  readonly inviterUserId: string;
  /** The user key FP (16-byte hex, 32 chars — §3). */
  readonly inviterKeyFingerprintHex: string;
  /** The inviter's sig public key (the link's `is=`). Collated against the on-chain key in addition to the FP at first sync. */
  readonly inviterSigPubHex: string;
  /** My view's head seq at the time the first mechanical collation succeeded (not yet collated = null). */
  readonly verifiedAtSeq: number | null;
}

/** The issuer-side pin (invite id → the content settled at issue time. IV revision — link public key + destination login). */
export interface IssuedInvitePin {
  /** The link public key (hex 64). Collated against the row's link_pub of the server declaration (SHOULD). */
  readonly linkPubHex: string;
  readonly role: "reader" | "member" | "admin";
  /** The scope to be granted (2026-09-15 ES K4 — extra collation material of the same standing as role. The source of truth is the issue signature). */
  readonly scopeKind: ScopeKind;
  readonly scopeEnvironmentIds: readonly string[];
  readonly expiresAtMs: number;
  /**
   * The destination's GitHub login (`invite create --github` —
   * the backing source's check target. Kept only at hand: never
   * written to the server, audit, or chain). Unspecified = null.
   */
  readonly expectedGithubLogin: string | null;
}

/** The pin file for one project (invites/<projectId>.json). */
export interface InvitePins {
  readonly v: 1;
  readonly anchor: InviteAnchor | null;
  /** The key is the invite id. */
  readonly issued: Readonly<Record<string, IssuedInvitePin>>;
}

/** The load result (fail-open — the caller emits a state-specific warning). */
export interface PinsLoadResult {
  readonly pins: InvitePins | null;
  readonly state: "loaded" | "missing" | "corrupt";
}

/** Load / merge boundary for the invite pin files. */
export interface PinStoreShape {
  readonly load: (projectId: string) => Effect.Effect<PinsLoadResult, CliError>;
  /** Saves the anchor (read-merge-write. Existing issued pins are kept). */
  readonly saveAnchor: (projectId: string, anchor: InviteAnchor) => Effect.Effect<void, CliError>;
  /** Appends an issued pin (read-merge-write + sweeping rows long past their expiry). */
  readonly saveIssuedPin: (
    projectId: string,
    inviteId: string,
    pin: IssuedInvitePin,
  ) => Effect.Effect<void, CliError>;
}

export class PinStore extends Context.Service<PinStore, PinStoreShape>()("cli/PinStore") {}

/** The pins directory (a location of the same family as the config: <config.json's parent>/invites). */
export function pinsDirOf(configPath: string): string {
  return join(dirname(configPath), "invites");
}

/**
 * The issued pin's retention window: rows past this much time
 * after expiry are swept. An accepted invite's add_member is
 * possible even after expiry (the expiry binds only acceptance —
 * AUTH_SPEC §15-1), so it is not deleted at the expiry itself. A
 * member add past the window degrades to pinless (display check
 * only).
 */
const ISSUED_PIN_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;

// The invite id is server-issued (ULID) but does not depend on
// the format (the same posture as AUTH_SPEC §11-1's ID-format
// independence). Banning a leading `_` structurally excludes
// `__proto__` (floor.ts's record-key discipline). The reading side
// uses floorRecordGet
const INVITE_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

const InviteAnchorSchema = Schema.Struct({
  headSeq: PositiveInt,
  headHashHex: Hex64,
  inviterUserId: Schema.String.check(Schema.isPattern(/^.{1,1024}$/s)),
  inviterKeyFingerprintHex: Hex32,
  inviterSigPubHex: Hex64,
  verifiedAtSeq: Schema.NullOr(PositiveInt),
});

const IssuedPinSchema = Schema.Struct({
  linkPubHex: Hex64,
  role: Schema.Literals(["reader", "member", "admin"]),
  // The scope pair's structural rules are CRYPTO_SPEC §6.2's (kind's
  // closed set, at most 256 ids, no duplicates, id format — the
  // listed/all split is the struct-level check below)
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

/** Reads an issued pin (own-property — floor.ts's discipline). */
export function issuedPinOf(
  pins: InvitePins | null,
  inviteId: string,
): IssuedInvitePin | undefined {
  return pins === null ? undefined : floorRecordGet(pins.issued, inviteId);
}

/** File-backed pin store at `dir` (used by both production and tests). */
export function makeFilePinStore(dir: string): PinStoreShape {
  const pathOf = (projectId: string) => join(dir, `${projectId}.json`);
  const writeError = (projectId: string) =>
    cliError(
      `Cannot write the invite-pin file (corrupt or an I/O failure): ${pathOf(projectId)} — inspect it, and if the modification was unintended, delete it and re-run`,
    );

  const load = (projectId: string) =>
    readJsonFile(pathOf(projectId), PinsFileSchema).pipe(
      Effect.map((loaded): PinsLoadResult => {
        switch (loaded.state) {
          case "missing":
            return { pins: null, state: "missing" };
          case "corrupt":
            return { pins: null, state: "corrupt" };
          case "loaded":
            return { pins: loaded.file, state: "loaded" };
        }
      }),
      // Only missing (NotFound) **alone** folds into "none". EACCES
      // / EISDIR etc. are a "could not read the existing pins"
      // failure — folding them into "none" makes merge rebuild the
      // existing file from empty and silently lose the verified
      // anchor and the issued pins (same discipline as config.ts's
      // reading)
      Effect.mapError(() => cliError(`Cannot read the invite-pin file: ${pathOf(projectId)}`)),
      Effect.provide(BunFileSystem.layer),
    );

  const merge = (
    projectId: string,
    apply: (pins: InvitePins) => InvitePins,
  ): Effect.Effect<void, CliError> =>
    Effect.gen(function* () {
      const loaded = yield* readJsonFile(pathOf(projectId), PinsFileSchema);
      if (loaded.state === "corrupt") {
        // Writing onto a corrupt file is refused (same
        // discipline as the floor's "a write failure is never
        // fail-open"). Rebuilding from empty would let the
        // verified anchor be silently lost via one corruption +
        // the next write and become indistinguishable from
        // "there never was an anchor" (§6.3 (a)'s detection
        // itself depends on the anchor)
        return yield* Effect.fail(writeError(projectId));
      }
      const base: InvitePins =
        loaded.state === "missing" ? { v: 1, anchor: null, issued: {} } : loaded.file;
      yield* writeJsonFileAtomic(pathOf(projectId), PinsFileSchema, apply(base));
    }).pipe(
      Effect.mapError(() => writeError(projectId)),
      Effect.provide(BunFileSystem.layer),
    );

  return {
    load,
    saveAnchor: (projectId, anchor) => merge(projectId, (pins) => ({ ...pins, anchor })),
    saveIssuedPin: (projectId, inviteId, pin) => {
      // Writing an out-of-format id makes the next load wholly corrupt (strict decoding), so refuse beforehand
      if (!INVITE_ID.test(inviteId)) {
        return Effect.fail(
          cliError(
            "Cannot save the issuance pin because the invite id in the server response is not in the expected form",
          ),
        );
      }
      return merge(projectId, (pins) => {
        const now = Date.now();
        const kept = Object.entries(pins.issued).filter(
          ([, existing]) => existing.expiresAtMs + ISSUED_PIN_RETENTION_MS > now,
        );
        return { ...pins, issued: { ...Object.fromEntries(kept), [inviteId]: pin } };
      });
    },
  };
}
