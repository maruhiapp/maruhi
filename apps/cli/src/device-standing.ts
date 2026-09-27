// The standing of a device key on the chain (DK K13-1 — design
// record dk-design.md §18).
//
// One place answers "what is this key on this project": active,
// revoked (the target of an applied `revoke_device` addressed to
// it), absent, or unsyncable. `device add` (branching on an
// existing key, checking completion, expiry, `--replace` display),
// `device list`, and `ownDeviceOrFail` (the revocation branch) use
// the same predicate.
//
// The pure function `keyStandingIn` only applies to an
// already-verified chain (`device list` and `key recover`
// registrations do not double the sync). `keyStandingsOf` syncs
// each project of the project list (server declaration — for
// discovery) at the keyless pre-stage and calls the pure
// function; a list/sync failure does not drop the command and
// folds into facts (tamper signals ride on `evidence`). It does
// not produce wording (the reporting side does — K12-10).
//
// Whether a ledger key is a reserve key is decided by the
// reserve-key mark in the ledger's contents (CRYPTO_SPEC §8 — DK
// K16). The only thing the chain says about a ledger key is
// "whether it is revoked" (`ledgerKeyVerdictOf`).

import type { ChainDevice, ChainMember } from "@maruhi/crypto";
import { Effect, Result } from "effect";

import type { MaruhiClient } from "./api.ts";
import { type CliServices, openMetadataProject, type ProjectContextBase } from "./context.ts";
import { revokedFingerprintsOf } from "./device-key.ts";
import type { CliError } from "./errors.ts";
import { fetchProjectMemberships } from "./project-list.ts";
import { compareCodePoints } from "./scope.ts";
import type { CliSession } from "./session.ts";
import type { VerifiedProject } from "./sync.ts";

/** A key's standing on a verified chain (excludes sync success/failure). */
export type ChainKeyStanding =
  | {
      readonly kind: "active";
      readonly member: ChainMember;
      readonly device: ChainDevice;
    }
  | { readonly kind: "revoked" }
  | { readonly kind: "absent" };

/**
 * The standing of `fingerprintHex` for `userId` on one verified chain. A key that
 * is active wins over an earlier revocation (it can only be active again as a
 * new registration, which the chain would show).
 */
export function keyStandingIn(
  verified: VerifiedProject,
  userId: string,
  fingerprintHex: string,
): ChainKeyStanding {
  const member = verified.state.members.get(userId);
  const device = member?.devices.get(fingerprintHex);
  if (member !== undefined && device !== undefined) {
    return { kind: "active", member, device };
  }
  return revokedFingerprintsOf(verified, userId).has(fingerprintHex)
    ? { kind: "revoked" }
    : { kind: "absent" };
}

/** The standing on one project (when unsyncable, that fact — not confused with "absent"). */
export type KeyStanding =
  | (Extract<ChainKeyStanding, { readonly kind: "active" }> & {
      readonly context: ProjectContextBase;
    })
  | Exclude<ChainKeyStanding, { readonly kind: "active" }>
  | {
      readonly kind: "unsynced";
      readonly message: string;
      /** A contradiction in signed data (a chain-verification failure etc. — a tamper signal). */
      readonly evidence: boolean;
    };

/** Syncs one project (the keyless front half) and derives the key's standing on it. */
export function keyStandingOnProject(input: {
  readonly session: CliSession;
  readonly projectId: string;
  readonly fingerprintHex: string;
}): Effect.Effect<KeyStanding, never, CliServices> {
  return Effect.map(
    Effect.result(openMetadataProject({ server: input.session.origin, project: input.projectId })),
    (synced) => standingFrom(synced, input.session, input.fingerprintHex),
  );
}

/** The standing across every project of the list (`listFailure` when it cannot be fetched). */
export interface KeyStandings {
  readonly projects: readonly { readonly projectId: string; readonly standing: KeyStanding }[];
  /** The failure of fetching the project list (null = fetched). On failure `projects` is empty. */
  readonly listFailure: string | null;
}

/**
 * The key's standing on every project the server lists for the caller (server-
 * reported — discovery only). Never fails: a list failure and each sync failure
 * are carried as facts.
 */
export function keyStandingsOf(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly fingerprintHex: string;
}): Effect.Effect<KeyStandings, never, CliServices> {
  return Effect.gen(function* () {
    const listed = yield* Effect.result(fetchProjectMemberships(input.client));
    if (Result.isFailure(listed)) {
      return { projects: [], listFailure: listed.failure.message };
    }
    const projectIds = listed.success.map((row) => row.projectId).toSorted(compareCodePoints);
    const projects: KeyStandings["projects"][number][] = [];
    for (const projectId of projectIds) {
      const synced = yield* Effect.result(
        openMetadataProject({ server: input.session.origin, project: projectId }),
      );
      projects.push({
        projectId,
        standing: standingFrom(synced, input.session, input.fingerprintHex),
      });
    }
    return { projects, listFailure: null };
  });
}

/** From one sync's result (success / failure), produces one key's standing (when unsyncable, that fact). */
function standingFrom(
  synced: Result.Result<ProjectContextBase, CliError>,
  session: CliSession,
  fingerprintHex: string,
): KeyStanding {
  if (Result.isFailure(synced)) {
    return {
      kind: "unsynced",
      message: synced.failure.message,
      evidence: synced.failure.evidence === true,
    };
  }
  const context = synced.success;
  const standing = keyStandingIn(context.verified, session.userId, fingerprintHex);
  return standing.kind === "active" ? { ...standing, context } : standing;
}

/** The projects by standing (the material for reporting and branching). */
export interface StandingGroups {
  readonly active: readonly {
    readonly projectId: string;
    readonly standing: Extract<KeyStanding, { readonly kind: "active" }>;
  }[];
  readonly revoked: readonly string[];
  readonly absent: readonly string[];
  readonly unsynced: readonly {
    readonly projectId: string;
    readonly message: string;
    readonly evidence: boolean;
  }[];
}

export function groupStandings(standings: KeyStandings): StandingGroups {
  const groups = {
    active: [] as StandingGroups["active"][number][],
    revoked: [] as string[],
    absent: [] as string[],
    unsynced: [] as StandingGroups["unsynced"][number][],
  };
  for (const { projectId, standing } of standings.projects) {
    if (standing.kind === "active") {
      groups.active.push({ projectId, standing });
    } else if (standing.kind === "unsynced") {
      groups.unsynced.push({ projectId, message: standing.message, evidence: standing.evidence });
    } else {
      groups[standing.kind].push(projectId);
    }
  }
  return groups;
}

/**
 * What the chain says about a key opened from the ledger (DK
 * K16): whether it is a reserve key is decided by the mark in
 * the ledger's contents (CRYPTO_SPEC §8); the only thing the
 * chain says is "whether it is revoked anywhere". A revoked
 * reserve key does not work as a ledger key (when the user
 * revoked the reserve key with `device revoke`). It does not
 * produce wording (K12-10).
 */
export type ReserveVerdict =
  | {
      readonly kind: "revoked";
      readonly projectIds: readonly string[];
      /** Projects where it is not revoked (where it is still actively listed). */
      readonly activeProjectIds: readonly string[];
    }
  | {
      readonly kind: "usable";
      /**
       * 同期できず確かめられなかったプロジェクト(そこで失効していても見えない)。止めはしない
       * (DK K16-6)が、報告側が Note で名指す。
       */
      readonly uncheckedProjectIds: readonly string[];
      /** プロジェクト一覧の取得の失敗(null = 取れた)。取れなければどこも確かめていない。 */
      readonly listFailure: string | null;
    };

export function reserveVerdictOf(standings: KeyStandings): ReserveVerdict {
  const groups = groupStandings(standings);
  return groups.revoked.length > 0
    ? {
        kind: "revoked",
        projectIds: groups.revoked,
        activeProjectIds: groups.active.map((entry) => entry.projectId),
      }
    : {
        kind: "usable",
        uncheckedProjectIds: groups.unsynced.map((entry) => entry.projectId),
        listFailure: standings.listFailure,
      };
}

/**
 * Checks whether the ledger key is revoked anywhere by syncing
 * every project the server lists (`key recovery`, the pre-stage
 * of a ledger change). `key recover` applies `reserveVerdictOf`
 * directly on the chain it opened for registration (no double
 * sync).
 */
export function ledgerKeyVerdictOf(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly fingerprintHex: string;
}): Effect.Effect<ReserveVerdict, never, CliServices> {
  return Effect.map(keyStandingsOf(input), reserveVerdictOf);
}
