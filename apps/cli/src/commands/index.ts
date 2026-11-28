import { Command, Param } from "effect/cli";

import {
  approvalApproveConfig,
  approvalListConfig,
  approvalShowConfig,
  approvalWithdrawConfig,
  makeApprovalCommands,
} from "../approval.package/command.ts";
import {
  auditInvitesConfig,
  auditListConfig,
  auditReconcileConfig,
  auditSelfConfig,
  auditVerifyConfig,
  makeAuditCommands,
} from "../audit.package/command.ts";
import {
  ciRotateConfig,
  ciRunConfig,
  ciSyncConfig,
  makeCiCommands,
} from "../ci.package/command.ts";
import type { CommandSpec } from "../cli-formatter.ts";
import {
  deviceAddConfig,
  deviceApproveConfig,
  deviceListConfig,
  deviceRevokeConfig,
  makeDeviceCommands,
} from "../device.package/command.ts";
import {
  envCreateConfig,
  envDiffConfig,
  envListConfig,
  envRenameConfig,
  envRmConfig,
  envRotateConfig,
  makeEnvCommands,
} from "../env.package/command.ts";
import {
  guardianAddConfig,
  guardianApproveConfig,
  guardianListConfig,
  guardianRemoveConfig,
  guardianWardsConfig,
  makeGuardianCommands,
} from "../guardian.package/command.ts";
import {
  inviteAcceptConfig,
  inviteCreateConfig,
  inviteListConfig,
  inviteRevokeConfig,
  makeInviteCommands,
} from "../invite.package/command.ts";
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
} from "../key.package/command.ts";
import {
  memberAddConfig,
  memberChangeRoleConfig,
  memberListConfig,
  memberRemoveConfig,
  makeMemberCommands,
} from "../member.package/command.ts";
import {
  mirrorMarkConfig,
  mirrorPromoteConfig,
  mirrorStatusConfig,
  mirrorSyncConfig,
  makeMirrorCommands,
} from "../mirror.package/command.ts";
import {
  projectAnchorConfig,
  projectCheckpointConfig,
  projectExportConfig,
  projectInitConfig,
  projectListConfig,
  projectPolicyApprovalsConfig,
  projectPolicySchemaConfig,
  projectVerifyConfig,
  makeProjectCommands,
} from "../project.package/command.ts";
import { proxyAcceptConfig, proxyRunConfig, makeProxyCommands } from "../proxy.package/command.ts";
import { pushConfig, makePushCommand } from "../push.package/command.ts";
import {
  schemaExportConfig,
  schemaImportConfig,
  schemaLintConfig,
  schemaSetConfig,
  schemaShowConfig,
  schemaVerifySnapshotConfig,
  makeSchemaCommands,
} from "../schema.package/command.ts";
import {
  serverGrantConfig,
  serverRevokeConfig,
  makeServerCommands,
} from "../server.package/command.ts";
import {
  syncApplyConfig,
  syncInitConfig,
  syncPlanConfig,
  makeSyncCommands,
} from "../sync.package/command.ts";
import {
  varHistoryConfig,
  varRmConfig,
  varRollbackConfig,
  varRotateConfig,
  makeVarCommands,
} from "../var.package/command.ts";
import { agentConfig, agentStatusConfig, makeAgentCommands } from "./agent.ts";
import { configGetConfig, configSetConfig, makeConfigCommands } from "./config.ts";
import { specOf } from "./flags.ts";
import { loginConfig, logoutConfig, makeLoginLogoutCommands } from "./login-logout.ts";
import { mcpConfig, makeMcpCommand } from "./mcp.ts";
import { pullConfig, runConfig, makePullRunCommands } from "./pull-run.ts";
import {
  rotationAcceptConfig,
  rotationDismissConfig,
  rotationListConfig,
  rotationProposalsConfig,
  rotationRejectConfig,
  makeRotationCommands,
} from "./rotation.ts";
import { tokenListConfig, tokenRevokeConfig, makeTokenCommands } from "./token.ts";

const GROUP_CONFIGS: Readonly<
  Record<string, Readonly<Record<string, Readonly<Record<string, Param.Any>>>>>
> = {
  env: {
    create: envCreateConfig,
    list: envListConfig,
    rename: envRenameConfig,
    rm: envRmConfig,
    rotate: envRotateConfig,
    diff: envDiffConfig,
  },
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
  "project policy": { approvals: projectPolicyApprovalsConfig, schema: projectPolicySchemaConfig },
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

const GROUP_PARENT_CONFIGS: Readonly<Record<string, Readonly<Record<string, Param.Any>>>> = {
  audit: auditListConfig,
  schema: schemaShowConfig,
  agent: agentConfig,
};

export const ROOT_SPEC_KEY = "";

const PUSH_STDIN_HINT =
  '. Values are read from stdin (example: `printf %s "$SECRET" | maruhi push API_KEY`)';

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
          ...(GROUP_PARENT_CONFIGS[group] === undefined
            ? { flags: [], positionals: [] }
            : specOf(GROUP_PARENT_CONFIGS[group])),
          subcommands: [
            ...Object.keys(subcommands),
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
