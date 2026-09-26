// The standing of a device key on the chain (DK K13-1 — design record
// dk-design.md §18).
//
// One place answers "what is this key on this project": active (with
// provenance — added via `add_device` / the person's first key),
// revoked (the target of an applied `revoke_device` addressed to it),
// absent, or unsyncable. `device add` (branching on an existing key,
// checking completion, expiry, `--replace` display), `device list`,
// and `ownDeviceOrFail` (the revocation branch) use the same
// predicate.
//
// The pure function `keyStandingIn` only applies to an already-verified
// chain (`device list` and `key recover` registrations do not double
// the sync). `keyStandingsOf` syncs each project of the project list
// (server declaration — for discovery) at the keyless pre-stage and
// calls the pure function; a list/sync failure does not drop the
// command and folds into facts (tamper signals ride on `evidence`). It
// does not produce wording (the reporting side does — K12-10).
//
// The list is a server declaration and is not a completeness witness
// (DK K15 — design record §20). The reserve-key judgment adds, only in
// the stopping direction, this device's observation record (rows of
// own-devices.json of this server and this account that were observed
// as the first key on a verified chain) (`recorded-first-key`).

import type { ChainDevice, ChainMember } from "@maruhi/crypto";
import { Effect, Result } from "effect";

import type { MaruhiClient } from "./api.ts";
import { type CliServices, openMetadataProject, type ProjectContextBase } from "./context.ts";
import { deviceProvenanceOf, revokedFingerprintsOf, wasFirstKeyOf } from "./device-key.ts";
import type { CliError } from "./errors.ts";
import type { CliIo } from "./io.ts";
import { logNote } from "./notice.ts";
import { OwnDeviceStore } from "./own-devices.ts";
import { fetchProjectMemberships } from "./project-list.ts";
import { compareCodePoints } from "./scope.ts";
import type { CliSession } from "./session.ts";
import type { VerifiedProject } from "./sync.ts";

/** The standing of a key on a verified chain (does not include sync success/failure). */
export type ChainKeyStanding =
  | {
      readonly kind: "active";
      readonly member: ChainMember;
      readonly device: ChainDevice;
      /**
       * Was once that person's first key on this chain (genesis /
       * add_member) — either the current provenance is the first key
       * or the first key of a previous membership (including a key
       * that came back as `add_device` on a re-invite after
       * `remove_member` — DK K14-1 1-f).
       */
      readonly firstKey: boolean;
    }
  | {
      readonly kind: "revoked";
      /** Before the revocation, was once that person's first key on this chain (DK K14-18). */
      readonly firstKey: boolean;
    }
  | {
      readonly kind: "absent";
      /** In a previous membership, was once that person's first key on this chain (DK K14-18). */
      readonly firstKey: boolean;
    };

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
    const provenance = deviceProvenanceOf(verified, userId, device);
    const firstKey =
      provenance.addedByFingerprintHex === null || wasFirstKeyOf(verified, userId, device);
    return { kind: "active", member, device, firstKey };
  }
  // Revoked keys and keys of previous memberships also leave their public key in the binding history (keyHistory) (DK K14-18)
  const bound = (verified.keyHistory.get(userId) ?? []).find(
    (binding) => binding.keyFingerprintHex === fingerprintHex,
  );
  const firstKey = bound !== undefined && wasFirstKeyOf(verified, userId, bound);
  return revokedFingerprintsOf(verified, userId).has(fingerprintHex)
    ? { kind: "revoked", firstKey }
    : { kind: "absent", firstKey };
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
      /** A contradiction in signed data (e.g. chain verification failure — a tamper signal). */
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

/** The standing on every project of the list (`listFailure` when the list could not be fetched). */
export interface KeyStandings {
  readonly projects: readonly { readonly projectId: string; readonly standing: KeyStanding }[];
  /** Failure to fetch the project list (null = fetched). When it failed, `projects` is empty. */
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
  return Effect.map(
    keyStandingsForKeys({ ...input, fingerprintsHex: [input.fingerprintHex] }),
    (byKey) => byKey.get(input.fingerprintHex) ?? { projects: [], listFailure: null },
  );
}

/**
 * The standings of several keys over one pass: each listed project is synced
 * once and the pure `keyStandingIn` is applied per key (DK K14-16 — the same
 * shape as `device list`, which lists every device over one sync).
 */
function keyStandingsForKeys(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly fingerprintsHex: readonly string[];
}): Effect.Effect<ReadonlyMap<string, KeyStandings>, never, CliServices> {
  return Effect.gen(function* () {
    const fingerprints = [...new Set(input.fingerprintsHex)];
    const listed = yield* Effect.result(fetchProjectMemberships(input.client));
    if (Result.isFailure(listed)) {
      const failed: KeyStandings = { projects: [], listFailure: listed.failure.message };
      return new Map(fingerprints.map((fp) => [fp, failed]));
    }
    const projectIds = listed.success.map((row) => row.projectId).toSorted(compareCodePoints);
    const byKey = new Map(fingerprints.map((fp) => [fp, [] as KeyStandings["projects"][number][]]));
    for (const projectId of projectIds) {
      const synced = yield* Effect.result(
        openMetadataProject({ server: input.session.origin, project: projectId }),
      );
      for (const fp of fingerprints) {
        byKey.get(fp)?.push({ projectId, standing: standingFrom(synced, input.session, fp) });
      }
    }
    return new Map(
      [...byKey].map(([fp, projects]) => [fp, { projects, listFailure: null } as KeyStandings]),
    );
  });
}

/** Produces the standing of one key from one sync's result (success / failure) (the fact itself when unsyncable). */
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

/** Projects grouped by standing (material for reporting and branching). */
export interface StandingGroups {
  readonly active: readonly {
    readonly projectId: string;
    readonly standing: Extract<KeyStanding, { readonly kind: "active" }>;
  }[];
  readonly revoked: readonly string[];
  readonly absent: readonly string[];
  /**
   * Projects where this key was (once) that person's first key,
   * whatever the standing (active / revoked / absent) (DK K14-18 —
   * read by the reserve-key judgment. `device add`'s two-way choice
   * reads only `firstKey` of active standings).
   */
  readonly firstKeyProjects: readonly string[];
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
    firstKeyProjects: [] as string[],
    unsynced: [] as StandingGroups["unsynced"][number][],
  };
  for (const { projectId, standing } of standings.projects) {
    if (standing.kind !== "unsynced" && standing.firstKey) {
      groups.firstKeyProjects.push(projectId);
    }
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
 * Judgment of whether a key opened from the ledger works as a reserve
 * key (DK K14-2 — design record §19). A reserve key always arrives via
 * `add_device` (K4-30); a pre-DK device-key duplicate becomes the
 * person's first key (genesis / `add_member`). The first matching item
 * from the top: anywhere at all was the first key (including a former
 * first key under a revoked/absent standing — K14-18) → `first-key`
 * (even with projects that cannot be synced — one positive fact
 * suffices) / the current chain does not show it, but this device's
 * observation record has it as a first key → `recorded-first-key`
 * (fills a project the server hid from the list — DK K15-1. Before
 * `revoked`: even if revoked on every visible project, it does not go
 * through the revocation gate) / revoked somewhere → `revoked` /
 * projects that cannot be synced or an unfetchable list → `unchecked`
 * / not active anywhere → `nowhere` / every active place is of
 * `add_device` provenance → `added` (the only one that may be recorded
 * as a reserve key). It does not produce wording (the reporting side
 * — K12-10).
 */
export type ReserveVerdict =
  | { readonly kind: "first-key"; readonly projectIds: readonly string[] }
  | {
      readonly kind: "recorded-first-key";
      /** The project this device observed as the first key (the `observedProjectId` of the observation row). */
      readonly projectId: string;
    }
  | {
      readonly kind: "revoked";
      readonly projectIds: readonly string[];
      /** Projects where it is not revoked (where it is still actively listed). */
      readonly activeProjectIds: readonly string[];
    }
  | {
      readonly kind: "unchecked";
      readonly projectIds: readonly string[];
      /** Failure to fetch the project list (null = fetched). */
      readonly listFailure: string | null;
    }
  | { readonly kind: "nowhere" }
  | { readonly kind: "added"; readonly projectIds: readonly string[] };

/** Facts that stop it (the chain's first key, this device's witness, revocation) — even marked, it is not treated as a reserve key. */
export function stopsLedgerKey(
  verdict: ReserveVerdict,
): verdict is Extract<
  ReserveVerdict,
  { readonly kind: "first-key" | "recorded-first-key" | "revoked" }
> {
  return (
    verdict.kind === "first-key" ||
    verdict.kind === "recorded-first-key" ||
    verdict.kind === "revoked"
  );
}

export function reserveVerdictOf(
  groups: StandingGroups,
  listFailure: string | null,
  /** The project where this device's observation record has this key as the first key (`recordedFirstKeysOf`). */
  recordedFirstKey: string | null,
): ReserveVerdict {
  if (groups.firstKeyProjects.length > 0) {
    return { kind: "first-key", projectIds: groups.firstKeyProjects };
  }
  if (recordedFirstKey !== null) {
    return { kind: "recorded-first-key", projectId: recordedFirstKey };
  }
  const activeProjectIds = groups.active.map((entry) => entry.projectId);
  if (groups.revoked.length > 0) {
    return { kind: "revoked", projectIds: groups.revoked, activeProjectIds };
  }
  if (groups.unsynced.length > 0 || listFailure !== null) {
    return {
      kind: "unchecked",
      projectIds: groups.unsynced.map((entry) => entry.projectId),
      listFailure,
    };
  }
  if (activeProjectIds.length === 0) {
    return { kind: "nowhere" };
  }
  return { kind: "added", projectIds: activeProjectIds };
}

/** The reserve-key judgment and its material (groups, the range that could not be checked). */
export interface LedgerKeyCheck {
  readonly verdict: ReserveVerdict;
  readonly groups: StandingGroups;
  /** The "range that could not be checked", independent of the verdict's value (null = everything checked — read by the revocation gate. K14-14). */
  readonly unchecked: Extract<ReserveVerdict, { readonly kind: "unchecked" }> | null;
}

/** Builds the reserve-key judgment from one key's standings (pure function). */
function ledgerKeyCheckFrom(
  standings: KeyStandings,
  recordedFirstKey: string | null,
): LedgerKeyCheck {
  const groups = groupStandings(standings);
  const unchecked =
    groups.unsynced.length > 0 || standings.listFailure !== null
      ? {
          kind: "unchecked" as const,
          projectIds: groups.unsynced.map((entry) => entry.projectId),
          listFailure: standings.listFailure,
        }
      : null;
  return {
    verdict: reserveVerdictOf(groups, standings.listFailure, recordedFirstKey),
    groups,
    unchecked,
  };
}

/**
 * The "was a first key" entries in this device's observation record
 * (DK K15-1 / K15-6): among this server's and this account's records,
 * rows with provenance `observed` and no provenance device (the first
 * key of `deviceProvenanceOf`) that carry the observed project — the
 * only writer is an observation of a verified chain (and the K14
 * correction). Revocation marks are not consulted (having been the
 * first key stays true after revocation). FP → project. Used only in
 * the stopping direction: empty when the record is absent, corrupt,
 * or unreadable (the K14 judgment stays as-is — the unreadable
 * failure is a Note).
 */
export function recordedFirstKeysOf(
  session: CliSession,
): Effect.Effect<ReadonlyMap<string, string>, never, OwnDeviceStore | CliIo> {
  return Effect.gen(function* () {
    const store = yield* OwnDeviceStore;
    const loaded = yield* store.load(session.origin, session.userId);
    const witnesses = new Map<string, string>();
    if (loaded.state !== "loaded") {
      return witnesses;
    }
    for (const row of loaded.devices) {
      if (
        row.source === "observed" &&
        row.addedByFingerprintHex === null &&
        row.observedProjectId !== null
      ) {
        witnesses.set(row.keyFingerprintHex, row.observedProjectId);
      }
    }
    return witnesses;
  }).pipe(
    Effect.catch((error) =>
      logNote(
        `could not read this machine's own-devices record (${error.message}); the key is checked on the project chains only`,
      ).pipe(Effect.as(new Map<string, string>())),
    ),
  );
}

/**
 * Judges the reserve key (and the old reserve key to be revoked) by
 * syncing once each project the server lists (DK K14-4 4-f / K14-16 —
 * the entry shared by `key recovery`, the pre-stage of a ledger
 * change, and the revocation gate). `key recover` applies
 * `reserveVerdictOf` directly on the chain it opened for
 * registration.
 */
export function ledgerKeyChecksOf(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly fingerprintsHex: readonly string[];
}): Effect.Effect<ReadonlyMap<string, LedgerKeyCheck>, never, CliServices> {
  return Effect.gen(function* () {
    const byKey = yield* keyStandingsForKeys(input);
    const recorded = yield* recordedFirstKeysOf(input.session);
    return new Map(
      [...byKey].map(([fp, standings]) => [
        fp,
        ledgerKeyCheckFrom(standings, recorded.get(fp) ?? null),
      ]),
    );
  });
}

/** `ledgerKeyChecksOf` for a single key. */
export function ledgerKeyVerdictOf(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly fingerprintHex: string;
}): Effect.Effect<LedgerKeyCheck, never, CliServices> {
  return Effect.map(
    ledgerKeyChecksOf({ ...input, fingerprintsHex: [input.fingerprintHex] }),
    (checks) =>
      checks.get(input.fingerprintHex) ??
      ledgerKeyCheckFrom({ projects: [], listFailure: null }, null),
  );
}
