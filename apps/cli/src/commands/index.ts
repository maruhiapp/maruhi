// The `effect/cli` argument layer (ADR-0016 decision 1 — stage 1:
// pull / run / env create, stage 2: env rotate / diff, server, invite,
// member, stage 3: push, config, key, project, rotation, audit, login,
// logout). The entry is cli.ts's runCli.
//
// `env` / `server` / `invite` / `member` are **true nested subcommands**
// (ADR-0016 decision 6): since the declaration is split per operation, no
// hand-rolled mechanism is needed to refuse "an option that does not apply
// to that operation". The property "a flag the operation lacks is a usage
// error (exit 2)" is upheld by the declaration + teardown (pinned by
// effect-cli.test.ts).
//
// The discipline (ADR-0016's decisions):
// 1. **Never write a hand-rolled scan for argument checks**. Everything is
//    expressed by declarations — a duplicated flag = `Flag.atMost(1)`
//    (**put it on booleans too**), an empty / whitespace-only value =
//    `Flag.withSchema`, a required run target = `Argument.atLeast(1)` /
//    `Argument.filter`
// 2. **Never surface a typed-in value in diagnostics**. The wording is
//    reassembled by `CliOutput.Formatter` (cli-formatter.ts)
// 3. **The exit code lives on the error type** (`Runtime.errorExitCode` —
//    errors.ts). The sole exception `ShowHelp` is re-read as 2 in the
//    teardown (cli-teardown.ts)
// 4. **Built-in global flags are narrowed to `--help` / `--version`
//    only**. By default `--wizard` / `--completions` / `--log-level` grow
//    onto every command, and `maruhi pull --wizard` **actually launches an
//    interactive wizard** (measured)
// 5. **Never read `process.*` directly**. argv and terminal presence go
//    through the `Stdio` service
// 6. **stdout is for the command's output only**. The command body's
//    output is `CliIo.log`; help and diagnostics go to `Console` (=
//    `CliIo.logError` = stderr)

import { Command, Param } from "effect/cli";

import { type CommandSpec } from "../cli-formatter.ts";
import { agentConfig, agentStatusConfig, makeAgentCommands } from "./agent.ts";
import {
  approvalApproveConfig,
  approvalListConfig,
  approvalShowConfig,
  approvalWithdrawConfig,
  makeApprovalCommands,
} from "./approval.ts";
import {
  auditInvitesConfig,
  auditListConfig,
  auditReconcileConfig,
  auditSelfConfig,
  auditVerifyConfig,
  makeAuditCommands,
} from "./audit.ts";
import { syncApplyConfig, syncInitConfig, syncPlanConfig, makeSyncCommands } from "./sync.ts";
import { ciRotateConfig, ciRunConfig, ciSyncConfig, makeCiCommands } from "./ci.ts";
import { configGetConfig, configSetConfig, makeConfigCommands } from "./config.ts";
import {
  deviceAddConfig,
  deviceApproveConfig,
  deviceListConfig,
  deviceRevokeConfig,
  makeDeviceCommands,
} from "./device.ts";
import { envCreateConfig, envDiffConfig, envRotateConfig, makeEnvCommands } from "./env.ts";
import { specOf } from "./flags.ts";
import {
  guardianAddConfig,
  guardianApproveConfig,
  guardianListConfig,
  guardianRemoveConfig,
  guardianWardsConfig,
  makeGuardianCommands,
} from "./guardian.ts";
import {
  inviteAcceptConfig,
  inviteCreateConfig,
  inviteListConfig,
  inviteRevokeConfig,
  makeInviteCommands,
} from "./invite.ts";
import {
  keyGenerateConfig,
  keyPublishConfig,
  keyRecoverConfig,
  keyRecoveryConfig,
  keyReserveRotateConfig,
  keySealListConfig,
  keySealPasskeyConfig,
  keySealRemoveConfig,
  keyShowConfig,
  makeKeyCommands,
} from "./key.ts";
import { loginConfig, logoutConfig, makeLoginLogoutCommands } from "./login-logout.ts";
import { mcpConfig, makeMcpCommand } from "./mcp.ts";
import {
  memberAddConfig,
  memberChangeRoleConfig,
  memberListConfig,
  memberRemoveConfig,
  makeMemberCommands,
} from "./member.ts";
import { mirrorMarkConfig, mirrorPromoteConfig } from "./mirror-write.ts";
import { mirrorStatusConfig, mirrorSyncConfig, makeMirrorCommands } from "./mirror.ts";
import {
  projectAnchorConfig,
  projectCheckpointConfig,
  projectExportConfig,
  projectInitConfig,
  projectListConfig,
  projectPolicyApprovalsConfig,
  projectVerifyConfig,
  makeProjectCommands,
} from "./project.ts";
import { proxyAcceptConfig, proxyRunConfig, makeProxyCommands } from "./proxy.ts";
import { pullConfig, runConfig, makePullRunCommands } from "./pull-run.ts";
import { PUSH_STDIN_HINT, pushConfig, makePushCommand } from "./push.ts";
import {
  rotationAcceptConfig,
  rotationDismissConfig,
  rotationListConfig,
  rotationProposalsConfig,
  rotationRejectConfig,
  makeRotationCommands,
} from "./rotation.ts";
import {
  schemaExportConfig,
  schemaImportConfig,
  schemaLintConfig,
  schemaSetConfig,
  schemaShowConfig,
  schemaVerifySnapshotConfig,
  makeSchemaCommands,
} from "./schema.ts";
import { serverGrantConfig, serverRevokeConfig, makeServerCommands } from "./server.ts";
import { tokenListConfig, tokenRevokeConfig, makeTokenCommands } from "./token.ts";
import {
  varHistoryConfig,
  varRmConfig,
  varRollbackConfig,
  varRotateConfig,
  makeVarCommands,
} from "./var.ts";

/**
 * The nesting stage (group) → the subcommand name → the declaration.
 * **This table is the single source** — COMMAND_SPECS (the dispatch keys
 * and the diagnostics' declaration / subcommand lists) is derived from
 * it. Holding the parents' stages as a hand-written copy would leave only
 * the dispatch and diagnostics stale when a subcommand is added.
 * makeRootCommand's `Command.make(name)` uses the same spelling as this
 * key (a disagreement falls in effect-cli.test.ts's conformity check).
 */
const GROUP_CONFIGS: Readonly<
  Record<string, Readonly<Record<string, Readonly<Record<string, Param.Any>>>>>
> = {
  env: { create: envCreateConfig, rotate: envRotateConfig, diff: envDiffConfig },
  server: { grant: serverGrantConfig, revoke: serverRevokeConfig },
  mirror: {
    sync: mirrorSyncConfig,
    status: mirrorStatusConfig,
    mark: mirrorMarkConfig,
    promote: mirrorPromoteConfig,
  },
  invite: {
    create: inviteCreateConfig,
    accept: inviteAcceptConfig,
    list: inviteListConfig,
    revoke: inviteRevokeConfig,
  },
  member: {
    add: memberAddConfig,
    remove: memberRemoveConfig,
    "change-role": memberChangeRoleConfig,
    list: memberListConfig,
  },
  approval: {
    list: approvalListConfig,
    show: approvalShowConfig,
    approve: approvalApproveConfig,
    withdraw: approvalWithdrawConfig,
  },
  key: {
    generate: keyGenerateConfig,
    show: keyShowConfig,
    publish: keyPublishConfig,
    recover: keyRecoverConfig,
    recovery: keyRecoveryConfig,
  },
  "key seal": {
    passkey: keySealPasskeyConfig,
    list: keySealListConfig,
    remove: keySealRemoveConfig,
  },
  "key reserve": { rotate: keyReserveRotateConfig },
  device: {
    add: deviceAddConfig,
    approve: deviceApproveConfig,
    list: deviceListConfig,
    revoke: deviceRevokeConfig,
  },
  token: { list: tokenListConfig, revoke: tokenRevokeConfig },
  guardian: {
    add: guardianAddConfig,
    approve: guardianApproveConfig,
    list: guardianListConfig,
    remove: guardianRemoveConfig,
    wards: guardianWardsConfig,
  },
  project: {
    init: projectInitConfig,
    list: projectListConfig,
    verify: projectVerifyConfig,
    anchor: projectAnchorConfig,
    checkpoint: projectCheckpointConfig,
    export: projectExportConfig,
  },
  "project policy": { approvals: projectPolicyApprovalsConfig },
  ci: { run: ciRunConfig, sync: ciSyncConfig, rotate: ciRotateConfig },
  agent: { status: agentStatusConfig },
  rotation: {
    list: rotationListConfig,
    dismiss: rotationDismissConfig,
    proposals: rotationProposalsConfig,
    accept: rotationAcceptConfig,
    reject: rotationRejectConfig,
  },
  audit: {
    list: auditListConfig,
    invites: auditInvitesConfig,
    self: auditSelfConfig,
    verify: auditVerifyConfig,
    reconcile: auditReconcileConfig,
  },
  config: { get: configGetConfig, set: configSetConfig },
  schema: {
    set: schemaSetConfig,
    import: schemaImportConfig,
    export: schemaExportConfig,
    "verify-snapshot": schemaVerifySnapshotConfig,
    lint: schemaLintConfig,
  },
  var: {
    rm: varRmConfig,
    history: varHistoryConfig,
    rollback: varRollbackConfig,
    rotate: varRotateConfig,
  },
  sync: { plan: syncPlanConfig, apply: syncApplyConfig, init: syncInitConfig },
  proxy: { run: proxyRunConfig, accept: proxyAcceptConfig },
};

/**
 * The groups whose parent stage itself carries a declaration (and a
 * handler). Only audit, which keeps bare `maruhi audit` = list — feeding
 * it into COMMAND_SPECS' parent entry so diagnostics (`audit --bogus`'s
 * undeclared flag) can also be assembled from the parent stage's
 * declaration.
 */
const GROUP_PARENT_CONFIGS: Readonly<Record<string, Readonly<Record<string, Param.Any>>>> = {
  audit: auditListConfig,
  schema: schemaShowConfig,
  // Bare `maruhi agent -- <cmd>` starts a session. Only `status` is a subcommand
  agent: agentConfig,
};

/**
 * commandKey → the diagnostics' declaration. Keys are the same as what
 * runCli's dispatch returns. A nested stage holds subcommands, which the
 * unknown-subcommand diagnostic uses to print "the list of possible
 * operations" (cli-formatter.ts).
 */
/**
 * The diagnostic key of the root (the `maruhi` stage). When
 * `ShowHelp.commandPath` has 1 stage, `commandPath.slice(1).join(" ")`
 * becomes an empty string, so it matches that spelling. Used for an
 * unknown command's (`maruhi bogus`) diagnostic to print "the list of
 * possible commands" (cli-formatter.ts's unknownSubcommandMessage).
 */
export const ROOT_SPEC_KEY = "";

const LEAF_AND_GROUP_SPECS: Readonly<Record<string, CommandSpec>> = {
  login: specOf(loginConfig),
  logout: specOf(logoutConfig),
  pull: specOf(pullConfig),
  run: specOf(runConfig),
  push: { ...specOf(pushConfig), strayHint: PUSH_STDIN_HINT },
  mcp: specOf(mcpConfig),
  ...Object.fromEntries(
    Object.entries(GROUP_CONFIGS).flatMap(([group, subcommands]) => [
      [
        group,
        {
          // A stage whose parent itself carries a declaration (audit) uses it for diagnostics too
          ...(GROUP_PARENT_CONFIGS[group] === undefined
            ? { flags: [], positionals: [] }
            : specOf(GROUP_PARENT_CONFIGS[group])),
          subcommands: [
            ...Object.keys(subcommands),
            // A nested group (`key seal`) counts as its parent's (`key`) possible operations
            ...Object.keys(GROUP_CONFIGS)
              .filter((other) => other.startsWith(`${group} `))
              .map((other) => other.slice(group.length + 1)),
          ],
        },
      ],
      ...Object.entries(subcommands).map(([name, config]) => [`${group} ${name}`, specOf(config)]),
    ]),
  ),
};

export const COMMAND_SPECS: Readonly<Record<string, CommandSpec>> = {
  ...LEAF_AND_GROUP_SPECS,
  // The root stage (the single-stage list). The unknown-command diagnostic prints "the possible commands
  [ROOT_SPEC_KEY]: {
    flags: [],
    positionals: [],
    subcommands: [
      ...new Set(Object.keys(LEAF_AND_GROUP_SPECS).map((key) => key.split(" ")[0] ?? key)),
    ],
  },
};

export function makeRootCommand(onExitCode: (code: number) => void) {
  const { login, logout } = makeLoginLogoutCommands();
  const { pull, run } = makePullRunCommands(onExitCode);
  const push = makePushCommand();
  const agent = makeAgentCommands(onExitCode);
  const ci = makeCiCommands(onExitCode);
  const env = makeEnvCommands(onExitCode);
  const server = makeServerCommands(onExitCode);
  const mirror = makeMirrorCommands();
  const invite = makeInviteCommands(onExitCode);
  const member = makeMemberCommands(onExitCode);
  const approval = makeApprovalCommands(onExitCode);
  const key = makeKeyCommands(onExitCode);
  const device = makeDeviceCommands(onExitCode);
  const token = makeTokenCommands();
  const guardian = makeGuardianCommands();
  const project = makeProjectCommands(onExitCode);
  const rotation = makeRotationCommands(onExitCode);
  const audit = makeAuditCommands(onExitCode);
  const config = makeConfigCommands();
  const schema = makeSchemaCommands();
  const mcp = makeMcpCommand();
  const varGroup = makeVarCommands();
  const sync = makeSyncCommands();
  const proxy = makeProxyCommands(onExitCode);

  return Command.make("maruhi").pipe(
    // The product's one-liner sits at the top of bare `maruhi` / `maruhi --help` (ruling F)
    Command.withDescription(
      "Diskless secrets manager: values are encrypted end-to-end and decrypted only in memory, never written to disk",
    ),
    Command.withSubcommands([
      login,
      logout,
      pull,
      run,
      push,
      agent,
      ci,
      env,
      server,
      mirror,
      invite,
      member,
      approval,
      key,
      device,
      token,
      guardian,
      project,
      rotation,
      audit,
      config,
      schema,
      mcp,
      varGroup,
      sync,
      proxy,
    ]),
  );
}
