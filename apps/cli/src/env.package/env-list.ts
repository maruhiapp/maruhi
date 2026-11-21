import type { EnvironmentListSchema } from "@maruhi/api-schema";
import type { EnvironmentId, UserId } from "@maruhi/core";
import type { ChainDevice, ChainMember, EnvironmentChainState, MemberScope } from "@maruhi/crypto";
import { effectivePermissionOf, scopeIncludesEnvironment } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "../api.ts";
import type { VerifiedProject } from "../chain-sync.ts";
import { displayText } from "../display.ts";
import { cliError, type CliError, evidenceError } from "../errors.ts";
import { toCliError } from "../failure.ts";
import type { VerifiedEnvironmentStatement } from "../floor-check.ts";
import { compareCodePoints } from "../scope.ts";
import { serverDisclosures, serverKeysDisclosing } from "../server-disclosure.ts";
import { verifyEnvironmentStatement } from "../values-verify.ts";
import { pullWithBoundedResync } from "../values.ts";

export type EnvironmentStatus = "active" | "deleted";

function environmentStatusOf(environment: EnvironmentChainState): EnvironmentStatus {
  return environment.deletedAtSeq === null ? "active" : "deleted";
}

export interface EnvironmentListRow {
  readonly environmentId: EnvironmentId;
  readonly name: string | null;
  readonly status: EnvironmentStatus;
  readonly currentEpoch: number;
  readonly inScope: boolean;
  readonly disclosedToServerKeyFingerprintsHex: readonly string[];
}

export type ScopeBasis = "device" | "member";

export interface EnvironmentList {
  readonly rows: readonly EnvironmentListRow[];
  readonly scopeBasis: ScopeBasis;
  readonly memberBasisReason: string | null;
  readonly headSeq: number;
}

type ListWire = typeof EnvironmentListSchema.Type;
type ListedStatement = ListWire["environments"][number]["statement"];

interface JoinedEnvironment {
  readonly environmentId: EnvironmentId;
  readonly statement: VerifiedEnvironmentStatement | null;
  readonly chain: EnvironmentChainState;
}

const verifyListing = Effect.fn("env-list.verifyListing")(function* (
  view: VerifiedProject,
  wire: ListWire,
  resynced: boolean,
): Effect.fn.Return<
  | { readonly kind: "ok"; readonly value: readonly JoinedEnvironment[] }
  | { readonly kind: "future" },
  CliError
> {
  const listed = yield* indexListing(wire);
  if ([...listed.keys()].some((environmentId) => !view.state.environments.has(environmentId))) {
    return { kind: "future" } as const;
  }
  const joined: JoinedEnvironment[] = [];
  for (const [environmentId, chainEnvironment] of view.state.environments) {
    const statement = yield* joinedStatement(
      view,
      environmentId,
      chainEnvironment,
      listed.get(environmentId),
      resynced,
    );
    if (statement === "future") {
      return { kind: "future" } as const;
    }
    joined.push({
      environmentId,
      statement,
      chain: chainEnvironment,
    });
  }
  return { kind: "ok", value: joined } as const;
});

function indexListing(
  wire: ListWire,
): Effect.Effect<ReadonlyMap<EnvironmentId, ListedStatement>, CliError> {
  const listed = new Map<EnvironmentId, ListedStatement>();
  for (const entry of wire.environments) {
    if (listed.has(entry.environmentId)) {
      return Effect.fail(
        evidenceError(
          `The environment list carries environment ${displayText(entry.environmentId)} twice (an inconsistent server response)`,
        ),
      );
    }
    listed.set(entry.environmentId, entry.statement);
  }
  return Effect.succeed(listed);
}

const joinedStatement = Effect.fn("env-list.joinedStatement")(function* (
  view: VerifiedProject,
  environmentId: EnvironmentId,
  chainEnvironment: EnvironmentChainState,
  statement: ListedStatement | undefined,
  resynced: boolean,
): Effect.fn.Return<VerifiedEnvironmentStatement | null | "future", CliError> {
  if (statement === undefined) {
    if (chainEnvironment.deletedAtSeq !== null) {
      return null;
    }
    if (!resynced) {
      return "future";
    }
    return yield* Effect.fail(
      evidenceError(
        `The environment list omits environment ${displayText(environmentId)}, which the verified chain created (create_environment at seq ${chainEnvironment.createdAtSeq}) and has not deleted — the server withholds a live environment it must list`,
      ),
    );
  }
  const outcome = yield* Effect.promise(() =>
    verifyEnvironmentStatement(view, environmentId, statement),
  );
  if (outcome.kind === "rejected") {
    return yield* Effect.fail(
      outcome.evidence ? evidenceError(outcome.message) : cliError(outcome.message),
    );
  }
  return outcome.kind === "future" ? "future" : outcome.value;
});

function scopeOf(
  member: ChainMember,
  ownKeyFingerprintHex: string | null,
): { readonly scope: MemberScope; readonly basis: ScopeBasis; readonly reason: string | null } {
  if (ownKeyFingerprintHex === null) {
    return {
      scope: member.scope,
      basis: "member",
      reason: "this machine has no usable device key",
    };
  }
  const device: ChainDevice | undefined = member.devices.get(ownKeyFingerprintHex);
  if (device === undefined) {
    return {
      scope: member.scope,
      basis: "member",
      reason: "this machine's key is not a registered device on this project's chain",
    };
  }
  return { scope: effectivePermissionOf(member, device).scope, basis: "device", reason: null };
}

export const envListOp = Effect.fn("env-list.envListOp")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly userId: UserId;
  readonly ownKeyFingerprintHex: string | null;
}): Effect.fn.Return<EnvironmentList, CliError> {
  if (!input.verified.state.members.has(input.userId)) {
    return yield* Effect.fail(cliError("You are not a chain-derived member of this project"));
  }
  const { view, value: joined } = yield* pullWithBoundedResync({
    verified: input.verified,
    resync: input.resync,
    fetch: input.client.environments
      .list({ params: { projectId: input.verified.projectId } })
      .pipe(Effect.mapError(toCliError)),
    verify: (current, wire) => verifyListing(current, wire, current !== input.verified),
    accept: () => Effect.void,
    divergedMessage:
      "The environment list still names a chain head or an environment the verified chain does not have after a resync (evidence of a fork or a forged listing)",
  });
  const member = view.state.members.get(input.userId);
  if (member === undefined) {
    return yield* Effect.fail(cliError("You are not a chain-derived member of this project"));
  }
  const scope = scopeOf(member, input.ownKeyFingerprintHex);
  const disclosures = serverDisclosures(view);
  const rows = joined
    .map((environment): EnvironmentListRow => {
      const status = environmentStatusOf(environment.chain);
      return {
        environmentId: environment.environmentId,
        name: environment.statement?.name ?? null,
        status,
        currentEpoch: environment.chain.currentEpoch,
        inScope:
          status === "active" && scopeIncludesEnvironment(scope.scope, environment.environmentId),
        disclosedToServerKeyFingerprintsHex: serverKeysDisclosing(
          disclosures,
          environment.environmentId,
        ),
      };
    })
    .toSorted((a, b) => compareCodePoints(a.environmentId, b.environmentId));
  return {
    rows,
    scopeBasis: scope.basis,
    memberBasisReason: scope.reason,
    headSeq: view.state.headSeq,
  };
});

export function shownEnvironmentRows(
  list: EnvironmentList,
  all: boolean,
): readonly EnvironmentListRow[] {
  return all ? list.rows : list.rows.filter((row) => row.status === "active");
}

export function envListJson(list: EnvironmentList, all: boolean): string {
  return JSON.stringify(
    {
      scopeBasis: list.scopeBasis,
      environments: shownEnvironmentRows(list, all).map((row) => ({
        environmentId: row.environmentId,
        name: row.name,
        status: row.status,
        currentEpoch: row.currentEpoch,
        inScope: row.inScope,
        disclosedToServerKeyFingerprintsHex: row.disclosedToServerKeyFingerprintsHex,
      })),
    },
    null,
    2,
  );
}

export function formatEnvListRow(row: EnvironmentListRow): string {
  const disclosed = row.disclosedToServerKeyFingerprintsHex.length > 0 ? "yes" : "no";
  return `${displayText(row.environmentId)}\t${row.name === null ? "-" : displayText(row.name)}\t${row.status}\tepoch=${row.currentEpoch}\tin-scope=${row.inScope ? "yes" : "no"}\tdisclosed-to-server=${disclosed}`;
}
