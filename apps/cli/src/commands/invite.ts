// `maruhi invite` (discipline: see commands/index.ts).

import { type EnvironmentId } from "@maruhi/core";
import { ALL_SCOPE } from "@maruhi/crypto";
import { Clock, Effect, Redacted } from "effect";
import { Argument, Command } from "effect/cli";

import { identityBackingOf } from "../config.ts";
import type { CliServices, CommonFlags } from "../context.ts";
import { CliError, usageError } from "../errors.ts";
import { parseUserFingerprintFlag } from "../fingerprint-flag.ts";
import { inviteCreateOp } from "../invite-create.ts";
import {
  type InviteInputRejection,
  type InviteLinkData,
  type InviteRole,
  parseInviteAcceptInput,
} from "../invite-link.ts";
import { inviteListOp, inviteRevokeOp } from "../invite-list.ts";
import { PinStore } from "../pins.ts";
import { scopeFromFlags } from "../scope.ts";
import { NonBlank, projectFlags, scopeEnvFlag, singleFlag, singleValued } from "./flags.ts";
import { loadIdentityBacking, parseGithubLoginFlag } from "./shared.ts";

/** The role an invite can grant (an owner is never granted via an invite — AUTH_SPEC §15-1). */
const INVITE_ROLES = ["reader", "member", "admin"] as const;

function isInviteRole(value: string | undefined): value is InviteRole {
  return INVITE_ROLES.some((known) => known === value);
}

export const inviteCreateConfig = {
  ...projectFlags(),
  role: singleValued("role", `Role to grant (required — ${INVITE_ROLES.join(" | ")})`),
  env: scopeEnvFlag(
    "Environment the invitee may access (repeatable; omitted = all environments, including ones created later)",
  ),
  "no-envs": singleFlag(
    "no-envs",
    "Grant no environment at all (an empty listed scope: the member sees names only; widen later with `maruhi member change-role --env`)",
  ),
  github: singleValued(
    "github",
    "GitHub login of the invitee (at `maruhi member add` their acceptance key is checked against that account's signing keys, so no 12-word call is needed)",
  ),
};

export const inviteAcceptConfig = {
  server: singleValued("server", "Server URL (defaults to config server)"),
  from: singleValued(
    "from",
    "GitHub login you expect the invite from (checked against the link and that account's signing keys; replaces the interactive confirmation)",
  ),
  "inviter-fingerprint": singleValued(
    "inviter-fingerprint",
    "Inviter's key fingerprint noted out of band (32 hex chars; checked against the link instead of the interactive ceremony)",
  ),
  // An invite link embeds the link-key seed = not a mere displayable
  // string. It is received as `Argument.Redacted` and passed to
  // invite-link.ts's interpretation boundary still Redacted (only the
  // existing boundary unwraps it). The link carries the project ID (v2 —
  // the raw-token path is gone), so it takes no --project
  target: Argument.Redacted("target").pipe(
    Argument.withDescription("Invite link (quote the link so the shell does not interpret it)"),
  ),
};

export const inviteListConfig = { ...projectFlags() };

export const inviteRevokeConfig = {
  ...projectFlags(),
  "invite-id": Argument.String("invite-id").pipe(
    Argument.withDescription("Invite ID to revoke (see `maruhi invite list`)"),
    Argument.withSchema(NonBlank),
  ),
};

/** `maruhi invite create --role <r> [--env <id>]… [--github <login>]` (§15-2 issuance + §15-3 link assembly). */
const inviteCreateCommand = Effect.fn("commands-invite.inviteCreateCommand")(function* (
  flags: Omit<CommonFlags, "env"> & {
    readonly role?: string | undefined;
    readonly env: readonly EnvironmentId[];
    readonly noEnvs: boolean;
    readonly github?: string | undefined;
  },
): Effect.fn.Return<void, CliError, CliServices> {
  const { openProject } = yield* Effect.promise(() =>
    import("../context.ts").then((m) => ({ openProject: m.openProject })),
  );

  if (!isInviteRole(flags.role)) {
    return yield* Effect.fail(
      usageError(
        `Specify --role (${INVITE_ROLES.join(" | ")} — owner cannot be granted via an invite. AUTH_SPEC §15-1)`,
      ),
    );
  }
  // scope: `--env` repetition = listed (ascending, duplicates refused),
  // `--no-envs` = listed{}, omitted = all (ruling K — no `--all-envs`)
  const scope =
    (yield* scopeFromFlags({ env: flags.env, allEnvs: false, noEnvs: flags.noEnvs })) ?? ALL_SCOPE;
  const expectedGithubLogin = yield* parseGithubLoginFlag("--github", flags.github);
  const identityBacking = yield* loadIdentityBacking;
  // The issuance signature (CRYPTO_SPEC §6.5) is made with the inviter's chain sig key = requires the master key
  const context = yield* openProject({ server: flags.server, project: flags.project });
  // The link's `il` (§15-3): a display snapshot of my GitHub login
  // (/auth/me). Unfetchable still lets the issuance succeed (the
  // acceptor just falls back to the ceremony)
  const inviterLogin =
    identityBacking === "none"
      ? null
      : yield* context.client.auth.me({}).pipe(
          Effect.map((me) => me.providerLogin ?? null),
          Effect.orElseSucceed(() => null),
        );
  yield* inviteCreateOp({
    client: context.client,
    verified: context.verified,
    origin: context.origin,
    role: flags.role,
    scope,
    sessionUserId: context.session.userId,
    masterKeys: context.masterKeys,
    expectedGithubLogin,
    inviterLogin,
  });
});

/** An `invite accept` input-rejection reason → the usage wording. */
function acceptInputRejectionMessage(reason: InviteInputRejection): string {
  if (reason === "unsupported-version") {
    return "This invite link's format version is not supported. Ask the inviter to issue a new link with the current maruhi CLI (`maruhi invite create`), or update your CLI if it is older than theirs";
  }
  if (reason === "missing-or-invalid-fragment-params") {
    return "The invite link's fragment (after #) is incomplete or invalid. Check that the link was copied without truncation (a broken link cannot be accepted without its issuance statement)";
  }
  return "Specify an invite link (…/invite#v=2&…). Quote the link so the shell does not interpret it";
}

/**
 * Resolving `invite accept`'s input (the link). The input arrives from
 * the argument layer still as `Redacted` (a link embeds the link-key
 * seed). The syntax interpretation is left to invite-link.ts's boundary —
 * it is not unwrapped here.
 */
function resolveAcceptLink(
  rawTarget: Redacted.Redacted<string>,
): Effect.Effect<InviteLinkData, CliError> {
  const parsed = parseInviteAcceptInput(rawTarget);
  if (parsed.kind === "rejected") {
    return Effect.fail(usageError(acceptInputRejectionMessage(parsed.reason)));
  }
  return Effect.succeed(parsed.link);
}

/** `maruhi invite accept <link>` (§15-3 / CRYPTO_SPEC §6.3 (a) / §6.5). */
const inviteAcceptCommand = Effect.fn("commands-invite.inviteAcceptCommand")(function* (flags: {
  readonly server?: string | undefined;
  readonly target: Redacted.Redacted<string>;
  readonly from?: string | undefined;
  readonly inviterFingerprint?: string | undefined;
}): Effect.fn.Return<void, CliError, CliServices> {
  const { openSession } = yield* Effect.promise(() =>
    import("../context.ts").then((m) => ({ openSession: m.openSession })),
  );
  const { inviteAcceptOp } = yield* Effect.promise(() =>
    import("../invite-accept.ts").then((m) => ({ inviteAcceptOp: m.inviteAcceptOp })),
  );
  const { keyGenerateOp } = yield* Effect.promise(() =>
    import("../keygen.ts").then((m) => ({ keyGenerateOp: m.keyGenerateOp })),
  );

  const link = yield* resolveAcceptLink(flags.target);
  const expectedFromLogin = yield* parseGithubLoginFlag("--from", flags.from);
  const expectInviterFingerprintHex = yield* parseUserFingerprintFlag(
    "--inviter-fingerprint",
    flags.inviterFingerprint,
  );
  const context = yield* openSession(flags.server);
  const identityBacking = identityBackingOf(context.config);
  yield* inviteAcceptOp({
    client: context.client,
    session: context.session,
    link,
    expectInviterFingerprintHex,
    expectedFromLogin,
    identityBacking,
    keyGenerate: keyGenerateOp({
      session: context.session,
      client: context.client,
      identityBacking,
      newIdentity: false,
    }),
  });
});

/** `maruhi invite list` (§6.5 independent verification of the acceptance blocks + the issuance-pin cross-check). */
const inviteListCommand = Effect.fn("commands-invite.inviteListCommand")(function* (
  flags: CommonFlags,
): Effect.fn.Return<number, CliError, CliServices> {
  const { openMetadataProject } = yield* Effect.promise(() =>
    import("../context.ts").then((m) => ({ openMetadataProject: m.openMetadataProject })),
  );

  const context = yield* openMetadataProject(flags);
  const store = yield* PinStore;
  const loaded = yield* store.load(context.projectId);
  const summary = yield* inviteListOp({
    client: context.client,
    verified: context.verified,
    pins: loaded.pins,
    nowMs: yield* Clock.currentTimeMillis,
  });
  // A signature-verification failure or a pin mismatch is not "a
  // successful read" but a detection of evidence — never 0 (a script can
  // use it as a health check)
  return summary.integrityFailures > 0 ? 1 : 0;
});

export function makeInviteCommands(onExitCode: (code: number) => void) {
  const inviteCreate = Command.make("create", inviteCreateConfig, (values) =>
    inviteCreateCommand({
      server: values.server,
      project: values.project,
      role: values.role,
      env: values.env,
      noEnvs: values["no-envs"],
      github: values.github,
    }),
  ).pipe(Command.withDescription("Issue an invite and build the invite link"));

  const inviteAccept = Command.make("accept", inviteAcceptConfig, (values) =>
    inviteAcceptCommand({
      server: values.server,
      target: values.target,
      from: values.from,
      inviterFingerprint: values["inviter-fingerprint"],
    }),
  ).pipe(Command.withDescription("Accept an invite link"));

  const inviteList = Command.make(
    "list",
    inviteListConfig,
    Effect.fn("commands-invite.inviteList")(function* (values) {
      onExitCode(yield* inviteListCommand(values));
    }),
  ).pipe(
    Command.withDescription(
      "List invites, independently verifying acceptance blocks and issuance pins",
    ),
  );

  const inviteRevoke = Command.make(
    "revoke",
    inviteRevokeConfig,
    Effect.fn("commands-invite.inviteRevoke")(function* (values) {
      const { openMetadataProject } = yield* Effect.promise(() =>
        import("../context.ts").then((m) => ({ openMetadataProject: m.openMetadataProject })),
      );

      const context = yield* openMetadataProject(values);
      yield* inviteRevokeOp({
        client: context.client,
        verified: context.verified,
        inviteId: values["invite-id"],
      });
    }),
  ).pipe(Command.withDescription("Revoke an invite"));

  const invite = Command.make("invite").pipe(
    Command.withDescription("Manage invites (create / accept / list / revoke)"),
    Command.withSubcommands([inviteCreate, inviteAccept, inviteList, inviteRevoke]),
  );

  return invite;
}
