// `maruhi member` (discipline: see commands/index.ts).

import { type EnvironmentId, type UserId } from "@maruhi/core";
import { type Role } from "@maruhi/crypto";
import { Effect } from "effect";
import { Argument, Command } from "effect/cli";

import {
  NonBlank,
  NonBlankUserId,
  projectFlags,
  proposalFlags,
  rejectCombinedScopeFlags,
  scopeEnvFlag,
  singleFlag,
  singleValued,
} from "../commands/flags.ts";
import {
  openMetadataProject,
  openProject,
  reportRotationChecklist,
  sweepRotateFor,
} from "../commands/lazy.ts";
import {
  loadIdentityBacking,
  parseGithubLoginFlag,
  proposalInputOf,
  reportMemberAdd,
  reportProposed,
  reportRoleChangeFulfilment,
  reportSweepOutcome,
} from "../commands/shared.ts";
import type { CliServices, CommonFlags } from "../context.ts";
import { displayText } from "../display.ts";
import { CliError, usageError } from "../errors.ts";
import { parseUserFingerprintFlag } from "../fingerprint-flag.ts";
import { CliIo, type CliIoShape } from "../io.ts";
import { formatMemberListRow, memberListJson, memberListRows } from "../member-list.ts";
import { logNote } from "../notice.ts";
import { PinStore } from "../pins.ts";
import { describeScope, scopeFromFlags } from "../scope.ts";
import type { ChangeRoleRequest } from "./member-change-role.ts";
import type { MemberOpOutcome } from "./member.ts";

/** The role grantable to a member (CRYPTO_SPEC §6.2). */
const MEMBER_ROLES = ["reader", "member", "admin", "owner"] as const;

function isMemberRole(value: string | undefined): value is Role {
  return MEMBER_ROLES.some((known) => known === value);
}

/** @public */
export const memberAddConfig = {
  ...projectFlags(),
  ...proposalFlags(),
  github: singleValued(
    "github",
    "GitHub login of the acceptor (their acceptance key is checked against that account's signing keys; overrides the login recorded at `maruhi invite create --github`)",
  ),
  "expect-fingerprint": singleValued(
    "expect-fingerprint",
    "Acceptor's key fingerprint noted out of band (32 hex chars; replaces the interactive check)",
  ),
  // Since the declaration is add-only, "omittable when exactly one accepted row exists" is expressed by atMost(1)
  "invite-id": Argument.String("invite-id").pipe(
    Argument.withDescription(
      "Invite ID to add (may be omitted when exactly one invite is accepted)",
    ),
    Argument.withSchema(NonBlank),
    Argument.atMost(1),
    Argument.map((values) => values[0]),
  ),
};

/** The target user_id of remove / change-role (required, non-empty). */
const memberTargetArgument = () =>
  Argument.String("user-id").pipe(
    Argument.withDescription("Target user ID (see `maruhi member list`)"),
    Argument.withSchema(NonBlankUserId),
  );

/** @public */
export const memberRemoveConfig = {
  ...projectFlags(),
  ...proposalFlags(),
  "user-id": memberTargetArgument(),
};

/** @public */
export const memberChangeRoleConfig = {
  ...projectFlags(),
  ...proposalFlags(),
  role: singleValued(
    "role",
    `New role (${MEMBER_ROLES.join(" | ")}; omitted = keep the current role)`,
  ),
  env: scopeEnvFlag(
    "Environment in the new scope (repeatable; replaces the whole scope; omitted = keep the current scope)",
  ),
  "all-envs": singleFlag(
    "all-envs",
    "Set the scope to all environments (including ones created later); `--role owner` always implies it",
  ),
  "no-envs": singleFlag(
    "no-envs",
    "Set the scope to no environment at all (an empty listed scope — the member keeps only metadata access)",
  ),
  "user-id": memberTargetArgument(),
};

/** @public */
export const memberListConfig = {
  ...projectFlags(),
  json: singleFlag("json", "Print the members as JSON (user id, role, scope, key fingerprint)"),
};

/** `maruhi member add [invite-id]` (§6.5's mutual confirmation + add_member + the backfill). */
const memberAddCommand = Effect.fn("member-command.memberAddCommand")(function* (
  flags: CommonFlags & {
    readonly invite?: string | undefined;
    readonly github?: string | undefined;
    readonly expectFingerprint?: string | undefined;
    readonly expires?: string | undefined;
  },
): Effect.fn.Return<number, CliError, CliServices> {
  const { memberAddOp } = yield* Effect.promise(() =>
    import("./member-add.ts").then((m) => ({ memberAddOp: m.memberAddOp })),
  );

  const io = yield* CliIo;
  const expectFingerprintHex = yield* parseUserFingerprintFlag(
    "--expect-fingerprint",
    flags.expectFingerprint,
  );
  const githubLogin = yield* parseGithubLoginFlag("--github", flags.github);
  const proposal = yield* proposalInputOf(flags.expires);
  const identityBacking = yield* loadIdentityBacking;
  const context = yield* openProject(flags);
  const store = yield* PinStore;
  const loaded = yield* store.load(context.projectId);
  const outcome = yield* memberAddOp({
    client: context.client,
    verified: context.verified,
    inviteId: flags.invite ?? null,
    expectFingerprintHex,
    githubLogin,
    identityBacking,
    pins: loaded.pins,
    signerUserId: context.session.userId,
    origin: context.session.origin,
    signingKeyPair: context.masterKeys.sigKeyPair,
    recipient: context.recipient,
    resync: context.resync,
    proposal,
  });
  if (outcome.kind === "proposed") {
    const code = yield* reportProposed(io, outcome.proposal);
    yield* logNote(
      "the invite stays accepted until the proposal is applied; the completing approver distributes the DEK wraps to the new member (AUTH_SPEC §12-6)",
    );
    return code;
  }
  return yield* reportMemberAdd(io, outcome.summary);
});

/** `maruhi member remove <user-id>` (§7 — accompanied by the forced rotation of every environment). */
const memberRemoveCommand = Effect.fn("member-command.memberRemoveCommand")(function* (
  flags: CommonFlags & { readonly target: UserId; readonly expires?: string | undefined },
): Effect.fn.Return<number, CliError, CliServices> {
  const { memberRemoveOp } = yield* Effect.promise(() =>
    import("./member-remove.ts").then((m) => ({ memberRemoveOp: m.memberRemoveOp })),
  );

  const io = yield* CliIo;
  const proposal = yield* proposalInputOf(flags.expires);
  // A convergent command: the always-on warning of unconverged duties is suppressed (its own sweep report carries it)
  const context = yield* openProject(flags, { quietMandateWarning: true });
  const outcome = yield* memberRemoveOp({
    client: context.client,
    verified: context.verified,
    targetUserId: flags.target,
    signerUserId: context.session.userId,
    signingKeyPair: context.masterKeys.sigKeyPair,
    resync: context.resync,
    rotateWith: (reason) => sweepRotateFor(context, reason),
    proposal,
  });
  // Proposing a self-remove (K6-N′): a proposal is not an application, but the consequence is shown to the person before asking an approver
  if (outcome.kind === "proposed" && flags.target === context.session.userId) {
    yield* logNote(
      "this proposal removes you — once an owner approves it, you lose access to the project",
    );
  }
  return yield* unlessProposed(io, outcome, (summary) =>
    Effect.gen(function* () {
      if (summary.appended) {
        yield* io.log(
          `Appended remove_member to the chain (target=${displayText(summary.targetUserId)}). Forcing a rotation of every environment in the target's scope (CRYPTO_SPEC §7)`,
        );
      } else {
        yield* io.log(
          "The target was already removed — skipping the append and resuming the rotation of every environment in the target's scope (crash recovery)",
        );
      }
      const exitCode = yield* reportSweepOutcome(summary, {
        rerunCommand: "`maruhi member remove`",
        alreadyRotatedBasis: "the mandate entry",
      });
      if (exitCode === 0) {
        yield* io.log(
          "Done: the member removal and the rotation of every environment in the target's scope completed",
        );
      }
      // The needs-rotation-flag count and route (AUDIT_SPEC §4.1. A
      // rotation only distributes a new DEK — an already-read value
      // itself cannot be un-read)
      yield* reportRotationChecklist({
        context,
        target: { kind: "member", userId: summary.targetUserId },
      });
      return exitCode;
    }),
  );
});

/** If it became a proposal (K6-A), report and exit 0; if applied, continue to the aftermath report. */
function unlessProposed<S>(
  io: CliIoShape,
  outcome: MemberOpOutcome<S>,
  applied: (summary: S) => Effect.Effect<number, CliError, CliServices>,
): Effect.Effect<number, CliError, CliServices> {
  return outcome.kind === "proposed"
    ? reportProposed(io, outcome.proposal)
    : applied(outcome.summary);
}

/**
 * `maruhi member change-role <user-id> [--role <r>] [--env <id>]…
 * [--all-envs]`: the full replacement of (role, scope) (CRYPTO_SPEC
 * §6.2). An omission is kept as-is (design record K4-A). The widened part
 * is backfilled; the demoted / narrowed part carries §7's rotation duty.
 */
const memberChangeRoleCommand = Effect.fn("member-command.memberChangeRoleCommand")(function* (
  flags: Omit<CommonFlags, "env"> & {
    readonly target: UserId;
    readonly role?: string | undefined;
    readonly env: readonly EnvironmentId[];
    readonly allEnvs: boolean;
    readonly noEnvs: boolean;
    readonly expires?: string | undefined;
  },
): Effect.fn.Return<number, CliError, CliServices> {
  const { memberChangeRoleOp } = yield* Effect.promise(() =>
    import("./member-change-role.ts").then((m) => ({ memberChangeRoleOp: m.memberChangeRoleOp })),
  );

  const io = yield* CliIo;
  const request = yield* parseChangeRoleRequest(flags);
  const proposal = yield* proposalInputOf(flags.expires);
  // A convergent command: the always-on warning of unconverged duties is suppressed (the demotion / narrowing sweep report carries it)
  const context = yield* openProject(
    { server: flags.server, project: flags.project },
    { quietMandateWarning: true },
  );
  const outcome = yield* memberChangeRoleOp({
    client: context.client,
    verified: context.verified,
    targetUserId: flags.target,
    request,
    signerUserId: context.session.userId,
    signingKeyPair: context.masterKeys.sigKeyPair,
    recipient: context.recipient,
    resync: context.resync,
    rotateWith: (reason) => sweepRotateFor(context, reason),
    proposal,
  });
  return yield* unlessProposed(io, outcome, (summary) =>
    Effect.gen(function* () {
      yield* io.log(
        summary.appended
          ? `Appended change_role to the chain (target=${displayText(summary.targetUserId)}, role=${summary.newRole}, scope=${describeScope(summary.newScope)})`
          : "The target already has the specified role and scope — nothing was appended (resuming any pending backfill / rotation)",
      );
      const exitCode = yield* reportRoleChangeFulfilment(
        io,
        summary,
        "`maruhi member change-role` with the same flags",
      );
      if (summary.sweep !== null) {
        // A demotion / narrowing raised flags of the change_role trigger
        // (AUDIT_SPEC §4.1) — the leaver checklist for the narrowed part
        yield* reportRotationChecklist({
          context,
          target: { kind: "member", userId: summary.targetUserId, trigger: "change_role" },
        });
      }
      return exitCode;
    }),
  );
});

/**
 * change-role's input: at least one of `--role` / `--env`… / `--all-envs`
 * (an omission is kept as-is — design record K4-A). A malformed format
 * drops as usage (2) before any communication. A combination of the
 * scope flags was already refused by the command's validate rule.
 */
const parseChangeRoleRequest = Effect.fn("member-command.parseChangeRoleRequest")(
  function* (flags: {
    readonly role?: string | undefined;
    readonly env: readonly EnvironmentId[];
    readonly allEnvs: boolean;
    readonly noEnvs: boolean;
  }): Effect.fn.Return<ChangeRoleRequest, CliError> {
    if (flags.role !== undefined && !isMemberRole(flags.role)) {
      return yield* Effect.fail(usageError(`--role must be one of ${MEMBER_ROLES.join(" | ")}`));
    }
    const newScope = yield* scopeFromFlags({
      env: flags.env,
      allEnvs: flags.allEnvs,
      noEnvs: flags.noEnvs,
    });
    if (flags.role === undefined && newScope === null) {
      return yield* Effect.fail(
        usageError(
          `Specify what to change: --role (${MEMBER_ROLES.join(" | ")}) and/or the scope (--env <id>…, --all-envs or --no-envs)`,
        ),
      );
    }
    return { newRole: flags.role ?? null, newScope };
  },
);

/**
 * `maruhi member list [--json]`: the verified chain's members (user id,
 * role, scope, key FPs). Zero values, so the agent-gate
 * (ensureValueDisplayAllowed) is not applied (design record ruling M /
 * K4-E — the same permissive side as `maruhi schema`). The master key is
 * not required either (the same keyless class as project verify).
 */
const memberListCommand = Effect.fn("member-command.memberListCommand")(function* (
  flags: CommonFlags & { readonly json: boolean },
): Effect.fn.Return<void, CliError, CliServices> {
  const io = yield* CliIo;
  const context = yield* openMetadataProject(flags);
  const rows = memberListRows(context.verified);
  if (flags.json) {
    yield* io.log(memberListJson(rows));
    return;
  }
  yield* io.log(
    `Members (${rows.length}) — verified chain head seq=${context.verified.state.headSeq}:`,
  );
  for (const row of rows) {
    yield* io.log(`  ${formatMemberListRow(row)}`);
  }
});

/** @public */
export function makeMemberCommands(onExitCode: (code: number) => void) {
  const memberAdd = Command.make(
    "add",
    memberAddConfig,
    Effect.fn("member-command.memberAdd")(function* (values) {
      onExitCode(
        yield* memberAddCommand({
          server: values.server,
          project: values.project,
          invite: values["invite-id"],
          github: values.github,
          expectFingerprint: values["expect-fingerprint"],
          expires: values.expires,
        }),
      );
    }),
  ).pipe(
    Command.withDescription(
      "Add an accepted invitee as a member (mutual fingerprint confirmation, then key distribution)",
    ),
  );

  const memberRemove = Command.make(
    "remove",
    memberRemoveConfig,
    Effect.fn("member-command.memberRemove")(function* (values) {
      onExitCode(
        yield* memberRemoveCommand({
          server: values.server,
          project: values.project,
          target: values["user-id"],
          expires: values.expires,
        }),
      );
    }),
  ).pipe(
    Command.withDescription(
      "Remove a member and force-rotate every environment in the member's scope",
    ),
  );

  const memberChangeRole = Command.make(
    "change-role",
    memberChangeRoleConfig,
    Effect.fn("member-command.memberChangeRole")(function* (values) {
      onExitCode(
        yield* memberChangeRoleCommand({
          server: values.server,
          project: values.project,
          target: values["user-id"],
          role: values.role,
          env: values.env,
          allEnvs: values["all-envs"],
          noEnvs: values["no-envs"],
          expires: values.expires,
        }),
      );
    }),
  ).pipe(
    Command.withDescription(
      "Change a member's role and/or environment scope (demotion and scope narrowing force a rotation)",
    ),
    Command.validate((values) => rejectCombinedScopeFlags(values)),
  );

  const memberList = Command.make("list", memberListConfig, (values) =>
    memberListCommand({ server: values.server, project: values.project, json: values.json }),
  ).pipe(
    Command.withDescription("List the verified members with their role, scope and key fingerprint"),
  );

  const member = Command.make("member").pipe(
    Command.withDescription("Manage members (add / remove / change-role / list)"),
    Command.withSubcommands([memberAdd, memberRemove, memberChangeRole, memberList]),
  );

  return member;
}
