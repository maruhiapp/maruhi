// `maruhi env list` — the project's environments: ID, display name, status,
// current epoch, and whether the caller's effective scope covers each one
// (zero values — a metadata read, so no agent gate and no master key is
// required).
//
// Where each fact comes from:
//   - The **set** of environments is the verified chain's create_environment
//     entries (complete and verified — every environment is created on the
//     chain, and the chain never forgets one, even after a deletion — §6.2)
//   - The **status** is chain-derived too: an environment whose
//     delete_environment entry is on the verified chain is deleted
//     (CRYPTO_SPEC §6.2 / §6.3 — the server cannot hide or undo it)
//   - The **name** of a live environment comes from its latest signed
//     statement in the environment list, verified against the chain
//     (signature, author's role and scope at its declared head — the same
//     verification as pull). A deleted environment has no name: nothing of
//     it is distributed any more (AUTH_SPEC §12-7)
//   - The **epoch** is chain-derived (the server's advisory currentEpoch is
//     not read)
//   - **In scope** is the caller's effective scope (member scope ∩ this
//     machine's device cap — §6.2); without a usable device key it falls
//     back to the member scope and says so
//
// Fail-closed: a live chain environment missing from the list, a deleted
// one present in it (a resurrection), an ID listed twice, or a statement
// that fails verification is an error — nothing is silently skipped. A
// statement declaring a chain head beyond this run's view (or a listed ID
// the view has not seen created yet) re-syncs once.

import type { ChainDevice, ChainMember, EnvironmentChainState, MemberScope } from "@maruhi/crypto";
import { effectivePermissionOf, scopeIncludesEnvironment } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { VerifiedProject } from "./chain-sync.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError, evidenceError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import type { VerifiedEnvironmentStatement } from "./floor-check.ts";
import { compareCodePoints } from "./scope.ts";
import { verifyEnvironmentStatement } from "./values-verify.ts";
import { pullWithBoundedResync } from "./values.ts";

/** An environment's lifecycle status. */
export type EnvironmentStatus = "active" | "deleted";

/**
 * The one place an environment's status is derived: the verified chain
 * (a deletion is the chain op delete_environment — CRYPTO_SPEC §6.2).
 */
function environmentStatusOf(environment: EnvironmentChainState): EnvironmentStatus {
  return environment.deletedAtSeq === null ? "active" : "deleted";
}

/** One listed environment (the verified chain's set, with a live environment's verified name). */
export interface EnvironmentListRow {
  readonly environmentId: string;
  /** The verified statement's display name; null for a deleted environment (none is distributed — §12-7). */
  readonly name: string | null;
  readonly status: EnvironmentStatus;
  /** The chain-derived current epoch. */
  readonly currentEpoch: number;
  /** Whether the caller's scope (see `scopeBasis`) covers the environment (never for a deleted one — a deletion leaves no permission in it). */
  readonly inScope: boolean;
}

/** Which scope `inScope` was judged against. */
export type ScopeBasis = "device" | "member";

export interface EnvironmentList {
  /** Every environment the chain created, ID ascending (deleted ones included). */
  readonly rows: readonly EnvironmentListRow[];
  readonly scopeBasis: ScopeBasis;
  /** Why the basis is the member scope (null when it is the device's effective scope). */
  readonly memberBasisReason: string | null;
  /** The verified chain head the listing was judged at. */
  readonly headSeq: number;
}

type ListWire = Effect.Success<ReturnType<MaruhiClient["environments"]["list"]>>;
type ListedStatement = ListWire["environments"][number]["statement"];

/** One chain environment joined with its verified listed statement (null = deleted on the chain). */
interface JoinedEnvironment {
  readonly environmentId: string;
  readonly statement: VerifiedEnvironmentStatement | null;
  readonly chain: EnvironmentChainState;
}

/**
 * Joins the verified chain's environment set with the listed statements: a
 * live environment must be listed and its statement must verify; a deleted
 * one must not be listed (verifyEnvironmentStatement refuses a chain-deleted
 * environment as a resurrection). `future` = a statement declares a head
 * beyond the view, or a listed ID was not created in the view yet (both
 * resolved by the one bounded resync).
 */
const verifyListing = Effect.fn("env-list.verifyListing")(function* (
  view: VerifiedProject,
  wire: ListWire,
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
    );
    if (statement === "future") {
      return { kind: "future" } as const;
    }
    joined.push({ environmentId, statement, chain: chainEnvironment });
  }
  return { kind: "ok", value: joined } as const;
});

/** The listed statements by environment ID (an ID listed twice is an inconsistent response). */
function indexListing(
  wire: ListWire,
): Effect.Effect<ReadonlyMap<string, ListedStatement>, CliError> {
  const listed = new Map<string, ListedStatement>();
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

/**
 * One chain environment's verified statement: a live one must be listed
 * and verify; an unlisted deleted one has none (null). A listed deleted one
 * is refused by verifyEnvironmentStatement (a resurrection).
 */
const joinedStatement = Effect.fn("env-list.joinedStatement")(function* (
  view: VerifiedProject,
  environmentId: string,
  chainEnvironment: EnvironmentChainState,
  statement: ListedStatement | undefined,
): Effect.fn.Return<VerifiedEnvironmentStatement | null | "future", CliError> {
  if (statement === undefined) {
    if (chainEnvironment.deletedAtSeq !== null) {
      return null;
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

/** The scope `inScope` is judged against: this machine's device (effective) or, failing that, the member's own. */
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

/**
 * Lists the project's environments (see the module header for where each
 * fact comes from). `ownKeyFingerprintHex` is this machine's device key
 * fingerprint, or null when no device key is available (a keyless run).
 */
export const envListOp = Effect.fn("env-list.envListOp")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly userId: string;
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
    verify: verifyListing,
    // The listing is not a floor input (it only reads)
    accept: () => Effect.void,
    divergedMessage:
      "The environment list still names a chain head or an environment the verified chain does not have after a resync (evidence of a fork or a forged listing)",
  });
  // The membership is re-read on the (possibly advanced) view
  const member = view.state.members.get(input.userId);
  if (member === undefined) {
    return yield* Effect.fail(cliError("You are not a chain-derived member of this project"));
  }
  const scope = scopeOf(member, input.ownKeyFingerprintHex);
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

/** The rows a run shows: deleted environments only with `--all`. */
export function shownEnvironmentRows(
  list: EnvironmentList,
  all: boolean,
): readonly EnvironmentListRow[] {
  return all ? list.rows : list.rows.filter((row) => row.status === "active");
}

/** One `--json` document (machine-readable — for agents / scripts. Zero values). */
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
      })),
    },
    null,
    2,
  );
}

/** The human-readable row (ID, name, status, epoch, scope; the name is neutralized; a deleted environment has no name — "-"). */
export function formatEnvListRow(row: EnvironmentListRow): string {
  return `${displayText(row.environmentId)}\t${row.name === null ? "-" : displayText(row.name)}\t${row.status}\tepoch=${row.currentEpoch}\tin-scope=${row.inScope ? "yes" : "no"}`;
}
