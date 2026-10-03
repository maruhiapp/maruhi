// `maruhi audit` (discipline: see commands/index.ts).

import {
  AUDIT_ROW_ID_PATTERN,
  DEFAULT_AUDIT_EVENTS_PAGE_LIMIT,
  MAX_AUDIT_EVENTS_PAGE_LIMIT,
} from "@maruhi/api-schema";
import { isEnvironmentId, isVariableId } from "@maruhi/core";
import { Effect } from "effect";
import { Command, Flag } from "effect/cli";

import { auditReconcileOp } from "../audit-reconcile.ts";
import {
  type AuditListFilters,
  type AuditPageOptions,
  auditInvitesOp,
  auditListOp,
  auditSelfOp,
  auditVerifyOp,
} from "../audit.ts";
import { openMetadataProject, openSession } from "../context.ts";
import { CliError, usageError } from "../errors.ts";
import { projectFlags, serverOnlyFlags, singleFlag, singleValued } from "./flags.ts";
import { ENV_FLAG_SHAPE_MESSAGE } from "./shared.ts";

/** audit's pagination flag (shared by list / invites / self). */
const auditPageFlags = () => ({
  limit: Flag.Int("limit").pipe(
    Flag.withDescription(
      `Page size (1-${MAX_AUDIT_EVENTS_PAGE_LIMIT}; default ${DEFAULT_AUDIT_EVENTS_PAGE_LIMIT})`,
    ),
    Flag.atMost(1),
    Flag.map((values) => values[0]),
  ),
  before: singleValued(
    "before",
    "Show rows older than this row id (pass the value printed by the continuation hint at the end of the previous page)",
  ),
});

/**
 * The declaration shared by `maruhi audit` (the parent) and `maruhi audit
 * list`. To keep **bare `audit` = list** (the current spec), the parent
 * command itself carries this declaration and handler (measured: a
 * handler-carrying parent + withSubcommands runs the handler on the bare
 * parent, and only the child runs when a subcommand is given).
 */
export const auditListConfig = {
  ...projectFlags(),
  ...auditPageFlags(),
  event: singleValued(
    "event",
    "Filter by event kind (e.g. var.version_pushed / chain.member_added)",
  ),
  actor: singleValued("actor", "Filter by actor user ID (below admin, only your own)"),
  target: singleValued("target", "Filter by target user ID"),
  env: singleValued("env", "Filter by environment ID"),
  var: singleValued("var", "Filter by variable ID (also matches var.read rows that list it)"),
  expandReads: singleFlag(
    "expand-reads",
    "Print the variables listed by var.read rows, one line per variable (default: a count per row)",
  ),
};

export const auditInvitesConfig = { ...projectFlags(), ...auditPageFlags() };

// self takes no project account-wide (no --project on the declaration =
// Unknown flag)
export const auditSelfConfig = { ...serverOnlyFlags(), ...auditPageFlags() };

export const auditVerifyConfig = { ...projectFlags() };

export const auditReconcileConfig = { ...projectFlags() };

/** Unspecified is allowed; when given, only an integer in [1, max] passes. */
function outsideIntRange(value: number | undefined, max: number): boolean {
  if (value === undefined) {
    return false;
  }
  return !Number.isInteger(value) || value < 1 || value > max;
}

function parseAuditPage(
  limit: number | undefined,
  before: string | undefined,
): Effect.Effect<AuditPageOptions, CliError> {
  if (outsideIntRange(limit, MAX_AUDIT_EVENTS_PAGE_LIMIT)) {
    return Effect.fail(
      usageError(
        `--limit must be an integer between 1 and ${MAX_AUDIT_EVENTS_PAGE_LIMIT} (the AUDIT_SPEC §7 cap)`,
      ),
    );
  }
  // The cursor is a row id (AUDIT_SPEC §5.1 row_id — the format is shared
  // with api-schema's Schema). Pass the value the previous page's trailing
  // "To continue:" guidance showed, as-is
  if (before !== undefined && !AUDIT_ROW_ID_PATTERN.test(before)) {
    return Effect.fail(
      usageError(
        "--before must be a row id (32 lowercase hex chars — the value printed by the continuation hint at the end of the previous page)",
      ),
    );
  }
  return Effect.succeed({ limit: limit ?? null, before: before ?? null });
}

interface AuditFilterFlags {
  readonly event: string | undefined;
  readonly actor: string | undefined;
  readonly target: string | undefined;
  readonly env: string | undefined;
  readonly var: string | undefined;
}

/** Unspecified is allowed; when given, only non-empty within max chars passes. */
function boundedFlagValue(value: string | undefined, max: number): boolean {
  return value === undefined || (value.length > 0 && value.length <= max);
}

/** The first misspelling among the filter flags (null when none). */
function auditFilterProblem(values: AuditFilterFlags): string | null {
  if (!boundedFlagValue(values.event, 64)) {
    return "--event must be an event name (area.verb — e.g. var.version_pushed)";
  }
  if (!boundedFlagValue(values.actor, 1024)) {
    return "--actor must be a user_id";
  }
  if (!boundedFlagValue(values.target, 1024)) {
    return "--target must be a user_id";
  }
  if (values.env !== undefined && !isEnvironmentId(values.env)) {
    return ENV_FLAG_SHAPE_MESSAGE;
  }
  if (values.var !== undefined && !isVariableId(values.var)) {
    return "--var is not a valid variableId";
  }
  return null;
}

/** Checking list's filter flags (the format is checked before any network). */
function parseAuditFilters(values: AuditFilterFlags): Effect.Effect<AuditListFilters, CliError> {
  const problem = auditFilterProblem(values);
  if (problem !== null) {
    return Effect.fail(usageError(problem));
  }
  return Effect.succeed({
    event: values.event ?? null,
    actorUserId: values.actor ?? null,
    targetUserId: values.target ?? null,
    environmentId: values.env ?? null,
    variableId: values.var ?? null,
  });
}

export function makeAuditCommands(onExitCode: (code: number) => void) {
  /**
   * audit list's body (shared by bare `maruhi audit` and `maruhi audit
   * list`). The master key is not required (audit rows are non-secret
   * metadata — the same keyless class as rotation list). The visibility
   * class and the invite.* authority axis are enforced server-side.
   */
  const runAuditList = (values: {
    readonly server?: string | undefined;
    readonly project?: string | undefined;
    readonly limit?: number | undefined;
    readonly before?: string | undefined;
    readonly event?: string | undefined;
    readonly actor?: string | undefined;
    readonly target?: string | undefined;
    readonly env?: string | undefined;
    readonly var?: string | undefined;
    readonly expandReads?: boolean | undefined;
  }) =>
    Effect.gen(function* () {
      const page = yield* parseAuditPage(values.limit, values.before);
      const filters = yield* parseAuditFilters({
        event: values.event,
        actor: values.actor,
        target: values.target,
        env: values.env,
        var: values.var,
      });
      const context = yield* openMetadataProject({
        server: values.server,
        project: values.project,
      });
      onExitCode(
        yield* auditListOp(context, page, filters, { expandReads: values.expandReads ?? false }),
      );
    });

  const auditList = Command.make("list", auditListConfig, runAuditList).pipe(
    Command.withDescription(
      "List audit events, cross-checking chain.* mirror rows against the verified chain",
    ),
  );

  const auditInvites = Command.make("invites", auditInvitesConfig, (values) =>
    Effect.gen(function* () {
      const page = yield* parseAuditPage(values.limit, values.before);
      const context = yield* openMetadataProject({
        server: values.server,
        project: values.project,
      });
      onExitCode(yield* auditInvitesOp(context, page));
    }),
  ).pipe(Command.withDescription("List invite.* audit events (admin only)"));

  const auditSelf = Command.make("self", auditSelfConfig, (values) =>
    Effect.gen(function* () {
      const page = yield* parseAuditPage(values.limit, values.before);
      const context = yield* openSession(values.server);
      onExitCode(yield* auditSelfOp(context, page));
    }),
  ).pipe(Command.withDescription("List the audit events of your own account"));

  const auditVerify = Command.make("verify", auditVerifyConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openMetadataProject({
        server: values.server,
        project: values.project,
      });
      onExitCode(yield* auditVerifyOp(context));
    }),
  ).pipe(
    Command.withDescription(
      "Verify that audit mirror rows match the chain one-to-one (detects missing, forged, or altered rows)",
    ),
  );

  const auditReconcile = Command.make("reconcile", auditReconcileConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openMetadataProject({
        server: values.server,
        project: values.project,
      });
      onExitCode(yield* auditReconcileOp(context));
    }),
  ).pipe(
    Command.withDescription(
      "Recompute the audit-head hash column and reconcile notarized checkpoints (effective admin only)",
    ),
  );

  // **bare `maruhi audit` = list** (keeping the current spec — stage 3's
  // ruling). The parent itself carries list's declaration and handler
  // (measured: a handler-carrying parent + withSubcommands runs the
  // handler on the bare parent, and only the child runs when a subcommand
  // is given. An unknown subcommand is UnknownSubcommand = exit 2)
  const audit = Command.make("audit", auditListConfig, runAuditList).pipe(
    Command.withDescription(
      "View and verify audit events (list / invites / self / verify / reconcile). Bare `maruhi audit` runs list",
    ),
    Command.withSubcommands([auditList, auditInvites, auditSelf, auditVerify, auditReconcile]),
  );

  return audit;
}
