import { type ProjectId, type UserId } from "@maruhi/core";
import type { ChainDevice, ChainMember } from "@maruhi/crypto";
import { Effect, Result } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { VerifiedProject } from "./chain-sync.ts";
import type { CliServices } from "./cli.ts";
import { openMetadataProject, type ProjectContextBase } from "./context.ts";
import { revokedFingerprintsOf } from "./device-key.ts";
import type { CliError } from "./errors.ts";
import { fetchProjectMemberships } from "./project.package/index.ts";
import { compareCodePoints } from "./scope.ts";
import type { CliSession } from "./session.ts";

export type ChainKeyStanding =
  | {
      readonly kind: "active";
      readonly member: ChainMember;
      readonly device: ChainDevice;
    }
  | { readonly kind: "revoked" }
  | { readonly kind: "absent" };

export function keyStandingIn(
  verified: VerifiedProject,
  userId: UserId,
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

export type KeyStanding =
  | (Extract<ChainKeyStanding, { readonly kind: "active" }> & {
      readonly context: ProjectContextBase;
    })
  | Exclude<ChainKeyStanding, { readonly kind: "active" }>
  | {
      readonly kind: "unsynced";
      readonly message: string;
      readonly evidence: boolean;
    };

export function keyStandingOnProject(input: {
  readonly session: CliSession;
  readonly projectId: ProjectId;
  readonly fingerprintHex: string;
}): Effect.Effect<KeyStanding, never, CliServices> {
  return Effect.map(
    Effect.result(openMetadataProject({ server: input.session.origin, project: input.projectId })),
    (synced) => standingFrom(synced, input.session, input.fingerprintHex),
  );
}

export interface KeyStandings {
  readonly projects: readonly { readonly projectId: ProjectId; readonly standing: KeyStanding }[];
  readonly listFailure: string | null;
}

export const keyStandingsOf = Effect.fn("device-standing.keyStandingsOf")(function* (input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly fingerprintHex: string;
}): Effect.fn.Return<KeyStandings, never, CliServices> {
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

export interface StandingGroups {
  readonly active: readonly {
    readonly projectId: ProjectId;
    readonly standing: Extract<KeyStanding, { readonly kind: "active" }>;
  }[];
  readonly revoked: readonly ProjectId[];
  readonly absent: readonly ProjectId[];
  readonly unsynced: readonly {
    readonly projectId: ProjectId;
    readonly message: string;
    readonly evidence: boolean;
  }[];
}

export function groupStandings(standings: KeyStandings): StandingGroups {
  const groups = {
    active: [] as StandingGroups["active"][number][],
    revoked: [] as StandingGroups["revoked"][number][],
    absent: [] as StandingGroups["absent"][number][],
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

export type ReserveVerdict =
  | {
      readonly kind: "revoked";
      readonly projectIds: readonly ProjectId[];
      readonly activeProjectIds: readonly ProjectId[];
    }
  | {
      readonly kind: "usable";
      readonly uncheckedProjectIds: readonly ProjectId[];
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

export function ledgerKeyVerdictOf(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly fingerprintHex: string;
}): Effect.Effect<ReserveVerdict, never, CliServices> {
  return Effect.map(keyStandingsOf(input), reserveVerdictOf);
}
