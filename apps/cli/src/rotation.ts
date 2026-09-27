// `maruhi rotation list|dismiss` (AUDIT_SPEC §4.1 / §6 / §7).
//
// - list: fetches and displays the server's derived view
//   (currently active rotation.recommended − resolved). Display
//   names are not trusted to the server's declaration; they are
//   resolved from the verified meta statements (a deleted
//   variable's tombstone — §4.2's "deleted keeps the last active
//   name") (AUDIT_SPEC §7's TCB discipline). An environment that
//   cannot be resolved (a verified deletion etc.) is displayed as
//   its identifier
// - dismiss: the withdrawal operation (the server generates
//   rotation.dismissed — admin). A flag is also resolved by
//   rotating the upstream credential + push (no re-encryption
//   marker needed) (§4.1-5) — dismiss is the explicit declaration
//   "accept the risk without rotating", and the only resolution
//   path for a deleted variable (which cannot be pushed)
//
// The flag set is only non-secret metadata (identifiers, basis
// kinds, targets); plaintext values and key material never pass
// through this module.

import { RotationFlagNotFoundError } from "@maruhi/api-schema";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { CliServices, ProjectContextBase } from "./context.ts";
import { floorHandleFor } from "./context.ts";
import { countNoun, displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import { logNote } from "./notice.ts";
import { pullVerifiedEnvironmentMetadata } from "./values.ts";

/** One flag of the derived view (the received form of api-schema's RotationFlagSchema). */
interface RotationFlagView {
  readonly environmentId: string;
  readonly variableId: string;
  readonly basis: "read" | "readable";
  readonly targetUserId?: string;
  readonly targetServerKeyFingerprintHex?: string;
  readonly recommendedAtMs: number;
  readonly triggerChainSeq: number;
  /**
   * AUDIT_SPEC §3.3's trigger (2026-09-14 ES. `revoke_device` is
   * 2026-09-19 DK K3's device-revocation variant — a mechanical
   * follow of the wire type. The CLI's 5th sweep kind is K4).
   */
  readonly trigger: "remove_member" | "change_role" | "revoke_server" | "revoke_device";
}

/** Fetches the flag view (the shared entry of display, count reporting, and dismiss-target resolution). */
function fetchRotationFlags(
  client: MaruhiClient,
  projectId: string,
): Effect.Effect<readonly RotationFlagView[], CliError> {
  return client.rotation.flags({ params: { projectId } }).pipe(
    Effect.mapError(toCliError),
    Effect.map((response) => response.flags),
  );
}

/** The variable-name resolution result (only verified-statement-derived — unresolvable = null). */
export type NameIndex = ReadonlyMap<string, string>;

/**
 * For each environment appearing in the list, fetches the
 * verified metadata (active + tombstone) and builds a variableId
 * → display name index. An environment whose fetch/verification
 * fails (a verified deletion etc.) has no index = degrades to
 * identifier display (with a warning — the display is SHOULD and
 * does not stop the listing itself). Shared with `maruhi audit`'s
 * display-name resolution (same TCB discipline — AUDIT_SPEC §7).
 */
export function resolveNames(
  context: ProjectContextBase,
  environmentIds: readonly string[],
): Effect.Effect<ReadonlyMap<string, NameIndex>, never, CliServices> {
  return Effect.gen(function* () {
    const byEnvironment = new Map<string, NameIndex>();
    for (const environmentId of environmentIds) {
      const attempted = yield* Effect.gen(function* () {
        const floorHandle = yield* floorHandleFor(context, environmentId);
        return yield* pullVerifiedEnvironmentMetadata({
          client: context.client,
          verified: context.verified,
          environmentId,
          resync: context.resync,
          floor: floorHandle,
        });
      }).pipe(
        Effect.map((metadata) => ({ kind: "ok", metadata }) as const),
        Effect.catch((error) =>
          Effect.succeed({ kind: "failed", message: error.message } as const),
        ),
      );
      if (attempted.kind === "failed") {
        yield* logNote(
          `could not fetch verified metadata for environment ${displayText(environmentId)} (${attempted.message}) — variables are shown by identifier only`,
        );
        continue;
      }
      const names = new Map<string, string>();
      for (const statement of attempted.metadata.variables) {
        names.set(statement.variableId, statement.name);
      }
      for (const tombstone of attempted.metadata.tombstones) {
        names.set(tombstone.variableId, tombstone.name);
      }
      byEnvironment.set(environmentId, names);
    }
    return byEnvironment;
  });
}

function describeTarget(flag: RotationFlagView): string {
  if (flag.targetUserId !== undefined) {
    // The change_role variant (demotion / scope shrinking —
    // AUDIT_SPEC §4.1) is not a deletion, so distinguish it by
    // trigger
    const prefix =
      flag.trigger === "change_role"
        ? "member (role/scope changed)"
        : flag.trigger === "revoke_device"
          ? "member (device revoked)"
          : "member";
    return `${prefix}:${displayText(flag.targetUserId)}`;
  }
  if (flag.targetServerKeyFingerprintHex !== undefined) {
    return `server:${flag.targetServerKeyFingerprintHex}`;
  }
  return "unknown";
}

function describeBasis(basis: "read" | "readable"): string {
  return basis === "read" ? "read (confirmed fetch)" : "readable (fetch was possible)";
}

/** `maruhi rotation list`: displays the currently active flags (all members — class 1). */
export function rotationListOp(
  context: ProjectContextBase,
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const flags = yield* fetchRotationFlags(context.client, context.projectId);
    if (flags.length === 0) {
      yield* io.log("No rotation flags are currently active");
      return 0;
    }
    const environmentIds = [...new Set(flags.map((flag) => flag.environmentId))].toSorted();
    const names = yield* resolveNames(context, environmentIds);
    yield* io.log(
      `Rotation flags: ${countNoun(flags.length, "active flag")} (upstream credential rotation recommended — AUDIT_SPEC §4.1)`,
    );
    for (const environmentId of environmentIds) {
      yield* io.log(`Environment ${displayText(environmentId)}:`);
      const index = names.get(environmentId);
      // Display order is detection time → (for the same time
      // within one sweep) a stable sort by variableId. The audit
      // seq does not go on the wire (AUDIT_SPEC §7 — non-leakage
      // of the ordinal)
      const rows = flags
        .filter((flag) => flag.environmentId === environmentId)
        .toSorted(
          (a, b) =>
            a.recommendedAtMs - b.recommendedAtMs || a.variableId.localeCompare(b.variableId),
        );
      for (const flag of rows) {
        const name = index?.get(flag.variableId);
        const label =
          name === undefined
            ? displayText(flag.variableId)
            : `${displayText(name)} (${displayText(flag.variableId)})`;
        yield* io.log(
          `  ${label}\tbasis=${describeBasis(flag.basis)}\ttarget=${describeTarget(flag)}\ttrigger seq=${flag.triggerChainSeq}`,
        );
      }
    }
    yield* io.log(
      "To resolve: rotate the upstream credential and save the new value with `maruhi push` (the mandated re-encryption alone does not resolve a flag). For pairs that cannot be pushed (e.g. deleted variables), dismiss the flag with `maruhi rotation dismiss` as an explicit acceptance of risk (admin)",
    );
    return 0;
  });
}

/** The result of dismiss's target resolution. */
interface DismissTargets {
  readonly targets: readonly { readonly environmentId: string; readonly variableId: string }[];
}

/**
 * `--all`'s target resolution: folds the currently active flags
 * (with `--env`, only that environment) into pairs (multiple
 * flags of the same pair — e.g. re-deletion — count as one
 * pair).
 */
function resolveAllTargets(input: {
  readonly client: MaruhiClient;
  readonly projectId: string;
  readonly environmentId: string | null;
}): Effect.Effect<DismissTargets, CliError> {
  return Effect.gen(function* () {
    const flags = yield* fetchRotationFlags(input.client, input.projectId);
    const scoped =
      input.environmentId === null
        ? flags
        : flags.filter((flag) => flag.environmentId === input.environmentId);
    const seen = new Set<string>();
    const targets: { environmentId: string; variableId: string }[] = [];
    for (const flag of scoped) {
      const key = `${flag.environmentId} ${flag.variableId}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      targets.push({ environmentId: flag.environmentId, variableId: flag.variableId });
    }
    if (targets.length === 0) {
      return yield* Effect.fail(
        cliError(
          input.environmentId === null
            ? "No rotation flags are currently active (nothing to dismiss)"
            : "No rotation flags are currently active in the specified environment (nothing to dismiss)",
        ),
      );
    }
    return { targets };
  });
}

/** The dismiss request's form (the part settled **without communication** — decided from the arguments alone). */
export type DismissRequest =
  | { readonly kind: "all"; readonly environmentId: string | null }
  | { readonly kind: "single"; readonly environmentId: string; readonly variableId: string };

/**
 * Interprets `maruhi rotation dismiss`'s request. Checks needing
 * no network (a contradiction between `--all` and a variable id,
 * a missing target) fail here — placed after the prior sync, the
 * guidance would hide behind a connection error and waste a
 * round trip.
 */
export function parseDismissRequest(input: {
  readonly all: boolean;
  readonly environmentId: string | null;
  readonly variableId: string | null;
}): Effect.Effect<DismissRequest, CliError> {
  if (input.all) {
    if (input.variableId !== null) {
      return Effect.fail(
        cliError("--all cannot be combined with a variableId (use one or the other)"),
      );
    }
    return Effect.succeed({ kind: "all", environmentId: input.environmentId });
  }
  if (input.environmentId === null || input.variableId === null) {
    return Effect.fail(
      cliError(
        "Specify what to dismiss: `maruhi rotation dismiss <variableId> --env <environmentId>` (or --all for every flag)",
      ),
    );
  }
  return Effect.succeed({
    kind: "single",
    environmentId: input.environmentId,
    variableId: input.variableId,
  });
}

/**
 * `maruhi rotation dismiss`'s target resolution: `--all` is
 * every currently active flag (with `--env`, only that
 * environment); an individual spec is the single pair (--env,
 * variableId).
 */
export function resolveDismissTargets(input: {
  readonly client: MaruhiClient;
  readonly projectId: string;
  readonly request: DismissRequest;
}): Effect.Effect<DismissTargets, CliError> {
  if (input.request.kind === "all") {
    return resolveAllTargets({
      client: input.client,
      projectId: input.projectId,
      environmentId: input.request.environmentId,
    });
  }
  const { environmentId, variableId } = input.request;
  return Effect.succeed({ targets: [{ environmentId, variableId }] });
}

/** `maruhi rotation dismiss`: executes the withdrawal (admin — the server checks the authority). */
export function rotationDismissOp(input: {
  readonly client: MaruhiClient;
  readonly projectId: string;
  readonly targets: readonly { readonly environmentId: string; readonly variableId: string }[];
}): Effect.Effect<number, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* input.client.rotation
      .dismiss({ params: { projectId: input.projectId }, payload: { targets: input.targets } })
      .pipe(
        Effect.catch((error) =>
          Effect.fail(
            error instanceof RotationFlagNotFoundError
              ? cliError(
                  `No active flag for variable ${displayText(error.variableId)} in environment ${displayText(error.environmentId)} (the dismissal was aborted as a whole — check the current targets with \`maruhi rotation list\`)`,
                )
              : toCliError(error),
          ),
        ),
      );
    yield* io.log(
      `Dismissed ${countNoun(input.targets.length, "rotation flag")} (rotation.dismissed — recorded in the audit log)`,
    );
    return 0;
  });
}

/**
 * The flag-count report at remove / revoke completion (ruling
 * B2 — guidance). Counts the currently active flags addressed to
 * the target (the removed user_id / the revoked server-key FP)
 * and shows it. A fetch failure does not change the command's
 * outcome (a SHOULD display).
 */
export function reportRotationFlagCount(input: {
  readonly client: MaruhiClient;
  readonly projectId: string;
  readonly target:
    | { readonly kind: "member"; readonly userId: string }
    | { readonly kind: "server"; readonly fingerprintHex: string };
}): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const flags = yield* fetchRotationFlags(input.client, input.projectId).pipe(
      Effect.catch((error) =>
        Effect.gen(function* () {
          yield* logNote(
            `failed to fetch rotation flags (${error.message}) — check with \`maruhi rotation list\``,
          );
          return null;
        }),
      ),
    );
    if (flags === null) {
      return;
    }
    const count = flags.filter((flag) =>
      input.target.kind === "member"
        ? flag.targetUserId === input.target.userId
        : flag.targetServerKeyFingerprintHex === input.target.fingerprintHex,
    ).length;
    if (count === 0) {
      return;
    }
    yield* io.log(
      `Rotation flags: ${countNoun(count, "active flag")} targeting the removed party (encryption cannot revoke already-read values — rotating the upstream credentials is recommended. See \`maruhi rotation list\`)`,
    );
  });
}
