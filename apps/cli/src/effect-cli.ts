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

import { readFile } from "node:fs/promises";
import { hostname } from "node:os";

import {
  AUDIT_ROW_ID_PATTERN,
  DEFAULT_AUDIT_EVENTS_PAGE_LIMIT,
  DEFAULT_TOKEN_TTL_DAYS,
  MAX_AUDIT_EVENTS_PAGE_LIMIT,
  MAX_TOKEN_NAME_LENGTH,
  MAX_TOKEN_TTL_DAYS,
  PASSKEY_LABEL_PATTERN,
} from "@maruhi/api-schema";
import { type EnvironmentId, isEnvironmentId, isProjectId, isVariableId } from "@maruhi/core";
import {
  ALL_SCOPE,
  APPROVAL_TARGET_OPS,
  type ApprovalTargetOp,
  type GuardianMode,
  type MetaVarType,
  type Role,
  MAX_META_MAX_AGE_DAYS,
} from "@maruhi/crypto";
import {
  Cause,
  Console,
  Duration,
  Effect,
  Exit,
  FileSystem,
  Layer,
  Path,
  Redacted,
  Schema,
  Stdio,
  Terminal,
} from "effect";
import {
  Argument,
  CliConfig,
  CliError as EffectCliError,
  Command,
  Flag,
  GlobalFlag,
  Param,
} from "effect/cli";
import type { HttpClient } from "effect/http";
import { ChildProcessSpawner } from "effect/process";

import { ensureValueDisplayAllowed } from "./agent-gate.ts";
import { ensurePlainRunAllowed } from "./agent-gate.ts";
import { AGENT_COMMAND_REQUIRED, agentOp, agentStatusOp, parseKeyTtl } from "./agent.ts";
import { buildRepositoryAnchor, formatRepositoryAnchor } from "./anchor.ts";
import { BODY_TIMEOUT, makeApiClient, type MaruhiClient } from "./api.ts";
import { approveProposalOp, type Fulfilment } from "./approval-approve.ts";
import {
  DEFAULT_POLICY_OPS,
  describeInnerOperation,
  describeInnerOperationLines,
  describeKeyReuse,
  describePolicy,
  describeUnresolvedRef,
  isApprovalTargetOp,
  keyReuseOf,
  parseProposalExpiry,
  type ProposalView,
  proposalViewOf,
  proposalViews,
  resolveProposalRef,
  voteEligibility,
} from "./approval-rules.ts";
import {
  type PolicyRequest,
  type ProposalInput,
  type ProposedSummary,
  setApprovalPolicyOp,
  withdrawProposalOp,
} from "./approval.ts";
import { auditReconcileOp } from "./audit-reconcile.ts";
import {
  type AuditListFilters,
  auditInvitesOp,
  auditListOp,
  type AuditPageOptions,
  auditSelfOp,
  auditVerifyOp,
} from "./audit.ts";
import {
  ANCHOR_REFRESH_PROPOSAL,
  ANCHOR_STALE_AFTER_ROTATION,
  checkpointProposal,
  issueCheckpoint,
} from "./checkpoint.ts";
import { ciRotateOp, describeProposal, MAX_PROPOSAL_DAYS } from "./ci-rotate.ts";
import { ciRunOp } from "./ci-run.ts";
import {
  type CommandSpec,
  formatterLayer,
  NON_BLANK_MESSAGE,
  PASSKEY_LABEL_MESSAGE,
} from "./cli-formatter.ts";
import { maruhiTeardown } from "./cli-teardown.ts";
import {
  asConfigKey,
  asIdentityBacking,
  type CliConfig as MaruhiCliConfig,
  CONFIG_KEYS,
  ConfigFileCorruptError,
  type ConfigKey,
  ConfigStore,
  IDENTITY_BACKINGS,
  type IdentityBacking,
  identityBackingOf,
} from "./config.ts";
import type {
  CliServices,
  CommonFlags,
  EnvironmentContext,
  ProjectContext,
  SessionContext,
} from "./context.ts";
import {
  checkInviteAnchor,
  commitVerifiedHead,
  floorHandleFor,
  loadCheckedFloor,
  openEnvironment,
  openMetadataEnvironment,
  openMetadataEnvironmentPair,
  openMetadataProject,
  openProject,
  openSession,
  openSessionWith,
  reconcileGossip,
  resolveMirrorOrigin,
  resolveProjectId,
  withMirrorFallback,
} from "./context.ts";
import { reportOwnDeviceGapFills } from "./device-gaps.ts";
import {
  deviceAddOp,
  deviceApproveOp,
  deviceListOp,
  deviceRevokeOp,
  type DeviceRevokeSummary,
  parseApproveRef,
  type ProjectRevokeOutcome,
  parseCapRole,
  reportApproveOutcomes,
} from "./device.ts";
import {
  countNoun,
  displayText,
  formatPulledLine,
  formatUtcMinutes,
  logWarnings,
  showValues,
} from "./display.ts";
import { envCreateOp } from "./env-create.ts";
import { envDiffOp, reportEnvironmentDiff } from "./env-diff.ts";
import { envRotateOp } from "./env-rotate.ts";
import { CliError, cliError, usageError } from "./errors.ts";
import { internalErrorKind, isNoAnswer, toCliError } from "./failure.ts";
import { parseFingerprintFlag, parseUserFingerprintFlag } from "./fingerprint-flag.ts";
import type { FloorHandle } from "./floor-check.ts";
import { FloorStore } from "./floor.ts";
import {
  guardianAddOp,
  guardianApproveOp,
  guardianListOp,
  guardianRemoveOp,
  guardianWardsOp,
} from "./guardian.ts";
import {
  GITHUB_LOGIN,
  type InviteInputRejection,
  type InviteLinkData,
  type InviteRole,
  parseInviteAcceptInput,
} from "./invite-link.ts";
import { inviteAcceptOp, inviteCreateOp, inviteListOp, inviteRevokeOp } from "./invite.ts";
import { CliIo, type CliIoShape } from "./io.ts";
import { keyPublishOp } from "./key-publish.ts";
import { keyRecoverOp, keyRecoveryOp, keyReserveRotateOp } from "./key-recover.ts";
import { Keychain, tokenEntryName } from "./keychain.ts";
import { keyGenerateOp, keyShowOp } from "./keygen.ts";
import { loadLeasePolicy } from "./lease-policy.ts";
import { openLedgerReserveForChange } from "./ledger-open.ts";
import { loginOp, logoutOp } from "./login.ts";
import { notePastDueValues } from "./max-age.ts";
import { mcpServeOp } from "./mcp.ts";
import {
  type ChangeRoleRequest,
  formatMemberListRow,
  type MemberAddSummary,
  memberAddOp,
  memberChangeRoleOp,
  memberListJson,
  memberListRows,
  type MemberOpOutcome,
  memberRemoveOp,
  type RoleChangeFulfilment,
} from "./member.ts";
import {
  describeMirrorStatus,
  describeMirrorSync,
  headOnChain,
  mirrorStatusOp,
  mirrorSyncOp,
  replicaVerdict,
} from "./mirror.ts";
import { formatNotice, logNote, logWarning, NoticeLedger } from "./notice.ts";
import { listPasskeysOp, removePasskeyOp, sealPasskeyOp } from "./passkey.ts";
import { PinStore } from "./pins.ts";
import { describeExport, projectExportOp } from "./project-export.ts";
import { projectInitOp } from "./project-init.ts";
import { projectListOp } from "./project-list.ts";
import {
  acceptProxyConfig,
  ensurePlainRunOfBrokeredProjectAllowed,
  ensureProxyConfigAccepted,
  markProjectBrokered,
} from "./proxy-accept.ts";
import {
  checkProxyConfigProject,
  DEFAULT_PROXY_CONFIG_PATH,
  type LoadedProxyConfig,
  loadProxyConfig,
  loadProxyConfigIfPresent,
} from "./proxy-config.ts";
import { describeProxyConfig, proxyRunOp } from "./proxy-run.ts";
import { type PulledVariables, pullVariables } from "./pull.ts";
import { normalizeStdinValue, pushVariable } from "./push.ts";
import {
  DEFAULT_ROTATE_CONFIG_PATH,
  loadRotateConfig,
  configNamesProject as rotateConfigNamesProject,
} from "./rotate-config.ts";
import { SqlRunner } from "./rotate-connector.ts";
import {
  describeAcceptance,
  findProposal,
  rotationAcceptOp,
  rotationProposalsOp,
  rotationRejectOp,
} from "./rotation-proposals.ts";
import { reportRotation } from "./rotation-report.ts";
import type { SweepOutcome } from "./rotation-sweep.ts";
import { describeUnconvergedMandate, resolveUnconvergedMandates } from "./rotation-sweep.ts";
import {
  fetchRotationProposals,
  parseDismissRequest,
  reportRotationChecklist,
  resolveDismissTargets,
  rotationDismissOp,
  rotationListOp,
} from "./rotation.ts";
import {
  enforceDeclaredPresence,
  ProcessRunner,
  RUN_COMMAND_REQUIRED,
  runOp,
  typeAdvisoryWarnings,
} from "./run.ts";
import { ensureImportCeremonyAllowed, schemaImportOp } from "./schema-import.ts";
import { scanPaths, schemaLintOp } from "./schema-lint.ts";
import { schemaExportOp, schemaVerifySnapshotOp } from "./schema-snapshot.ts";
import {
  ensureEntropyAcknowledged,
  type FieldUpdate,
  type SchemaFieldUpdates,
  schemaSetOp,
  type SchemaSetSummary,
  schemaShowOp,
} from "./schema.ts";
import { describeScope, scopeFromFlags } from "./scope.ts";
import { serverGrantOp } from "./server-grant.ts";
import { REVOKE_ROTATION_REASON, type RevokeSummary, serverRevokeOp } from "./server-revoke.ts";
import { loadMasterKeys, normalizeHttpOrigin, resolveServerOrigin } from "./session.ts";
import { sweepRotateFor } from "./sweep-rotate.ts";
import { ciSyncOp } from "./sync-ci.ts";
import {
  checkConfigProject,
  DEFAULT_SYNC_CONFIG_PATH,
  loadSyncConfig,
  requireSyncTarget,
} from "./sync-config.ts";
import { syncInitOp } from "./sync-init.ts";
import { syncApplyOp, syncPlanOp } from "./sync-plan.ts";
import {
  decidePushSync,
  loadPushSyncConfig,
  type PushSyncSetup,
  syncAfterPush,
} from "./sync-push.ts";
import { advanceReceiptsAfterRotation, checkRotateConfigProject } from "./sync-rotate.ts";
import { syncProject, type VerifiedProject } from "./sync.ts";
import { tokenListOp, tokenRevokeOp } from "./token.ts";
import { formatVarHistory, varHistoryJson, varHistoryOp, varRollbackOp } from "./var-history.ts";
import { varRmOp } from "./var-rm.ts";
import {
  describeFinalization,
  describeRotation,
  logRotationWarnings,
  rotateDeps,
  RotateSeams,
  varFinalizeOp,
  varRotateOp,
} from "./var-rotate.ts";
import { CLI_VERSION } from "./version.ts";

/** The guidance attached to a run that forgot `--` (there is exactly one way to pass the run target). */
const RUN_TERMINATOR_HINT =
  ". Write the command to run after `--` (example: `maruhi run -- printenv MY_VAR`)";

/* -------------------------------------------------------------------------- */
/* Declarations (checks ride on Effect's mechanisms — no hand-rolled scan) */
/* -------------------------------------------------------------------------- */

/**
 * A string that accepts no empty / whitespace-only value. Blocks the
 * accident of `maruhi push API_KEY --env "$ENV"` silently writing into the
 * default environment when ENV is unset.
 */
const NonBlank = Schema.String.check(Schema.isPattern(/\S/, { message: NON_BLANK_MESSAGE }));

/**
 * One value-taking option. `atMost(1)` expresses **the refusal of a
 * duplicated flag** in the declaration (effect's default is first-wins,
 * silently). The accident shape `maruhi pull --no-show $FLAGS` that would
 * display every secret is blocked here. With `noUncheckedIndexedAccess:
 * true` the result is `string | undefined` = meshes directly with
 * context.ts's {@link CommonFlags} (no Option conversion).
 */
function singleValued(name: string, description: string) {
  return Flag.String(name).pipe(
    Flag.withDescription(description),
    Flag.withSchema(NonBlank),
    Flag.atMost(1),
    Flag.map((values) => values[0]),
  );
}

/**
 * One boolean option. **A boolean also needs `atMost(1)`**: a raw
 * `Flag.Boolean` resolves duplicates silently, and **the result changes
 * with the order typed** (measured: `--show --no-show` is `true` under
 * first-wins, `--no-show --show` is `false`). The shape where `--show`
 * sneaks into `$FLAGS` of `maruhi pull --no-show $FLAGS` (ef7cba1) must
 * not depend on the order.
 */
function singleFlag(name: string, description: string) {
  return Flag.Boolean(name).pipe(
    Flag.withDescription(description),
    Flag.atMost(1),
    Flag.map((values) => values[0] ?? false),
  );
}

/**
 * A hidden flag for testing (one value). Appears in neither help nor
 * typo candidates. `Flag.withHidden` removes it from help and completion
 * (rc.113+). The diagnostics listing (specOf) also walks the leaf's
 * `hidden` to exclude it — never popularize an internal spelling.
 */
function hiddenIntegerValued(name: string, description: string) {
  return Flag.Int(name).pipe(
    Flag.withDescription(description),
    Flag.withHidden,
    Flag.atMost(1),
    Flag.map((values) => values[0]),
  );
}

/**
 * Whether that declaration is a hidden leaf (`Param.Single`). A wrapper
 * (Map / Variadic / Transform / Optional) carries its child in `param`, so
 * walk to the leaf to judge.
 */
function isHiddenParam(param: Param.Any): boolean {
  let current: unknown = param;
  while (typeof current === "object" && current !== null) {
    if (Param.isSingle(current as Param.Any)) {
      return (current as { hidden: boolean }).hidden;
    }
    current = (current as { param?: unknown }).param;
  }
  return false;
}

/**
 * Derive the diagnostics' command declaration from **the command
 * definition itself**. A hand-written copy would leave only the
 * diagnostics stale when a flag is added. `Param` is a public type
 * carrying `kind` (`"flag"` / `"argument"`), so they can be sorted
 * straight off the declaration listing. The name uses the object key (=
 * the spelling typed). A hidden declaration is not listed (never
 * popularize an internal spelling).
 */
function specOf(config: Readonly<Record<string, Param.Any>>): CommandSpec {
  const flags: string[] = [];
  const positionals: string[] = [];
  for (const [name, param] of Object.entries(config)) {
    if (isHiddenParam(param)) {
      continue;
    }
    (param.kind === "flag" ? flags : positionals).push(name);
  }
  return { flags, positionals };
}

/* -------------------------------------------------------------------------- */
/* Command definitions                                                        */
/* -------------------------------------------------------------------------- */

/** The common flags an environment command takes (same names as context.ts's CommonFlags). */
const commonFlags = () => ({
  ...projectFlags(),
  env: singleValued("env", "Environment ID (default: the `defaultEnvironment` setting)"),
});

/** The common flags a project-level command takes (no env). */
const projectFlags = () => ({
  server: singleValued("server", "Server URL (defaults to config server)"),
  project: singleValued("project", "Project ID (default: the `defaultProject` setting)"),
});

/** The common flags a session-level command takes (neither project nor env). */
const serverOnlyFlags = () => ({
  server: singleValued("server", "Server URL (defaults to config server)"),
});

/** `--mirror <url>` (PF2 — AUTH_SPEC §11-7): the read-only replica a read falls back to when the server is unreachable. */
const mirrorFlag = () => ({
  mirror: singleValued(
    "mirror",
    "Mirror URL to read from when the server is unreachable (default: the `mirror` setting; reads only, announced on stderr)",
  ),
});

const pullConfig = {
  ...commonFlags(),
  ...mirrorFlag(),
  show: singleFlag("show", "Print the values (interactive terminals only)"),
};

/** The declaration of the run target (after `--`) shared by `run` / `ci run`. */
const runCommandArgument = () =>
  // Everything after `--` lands here (empty strings are kept too).
  // `atLeast(1)` drops "a run with no run target" and `filter` drops "a
  // run target that is an empty string" (the unset shape of `maruhi run --
  // "$CMD"`). Both are declarations, and a second-or-later empty string is
  // **kept as a child-process argument**. On rc.117 an atLeast of 0 becomes
  // `MissingArgument`. The wording mapping lives in cli-formatter.ts (only
  // the command argument is RUN_COMMAND_REQUIRED)
  Argument.String("command").pipe(
    Argument.withDescription("The command to run, written after `--` (passed to the child as-is)"),
    Argument.atLeast(1),
    Argument.filter(
      (command) => (command[0] ?? "").trim() !== "",
      () => RUN_COMMAND_REQUIRED,
    ),
  );

const runConfig = {
  ...commonFlags(),
  ...mirrorFlag(),
  plain: singleFlag(
    "plain",
    `Inject the real values even when ${DEFAULT_PROXY_CONFIG_PATH} is present (allowed only to a person at an interactive terminal; without the config, run always injects the real values)`,
  ),
  command: runCommandArgument(),
};

/**
 * `maruhi agent -- <command>` (KL2 — agent.ts). Same "only what follows
 * `--` is the run target" declaration as run. Carries no flags (it touches
 * neither the server nor keys — it just spawns the child and prepares the
 * holder).
 */
const agentConfig = {
  "key-ttl": singleValued(
    "key-ttl",
    "Forget this device's key this long after it is stored (e.g. 30m, 2h); the token stays. Default: keep it until the command exits",
  ),
  command: Argument.String("command").pipe(
    Argument.withDescription(
      "The command to run inside the agent session, written after `--` (usually a shell)",
    ),
    Argument.atLeast(1),
    Argument.filter(
      (command) => (command[0] ?? "").trim() !== "",
      () => AGENT_COMMAND_REQUIRED,
    ),
  ),
};

/** `maruhi agent status`: no flags (session presence is decided by the environment variable). */
const agentStatusConfig = {};

/**
 * `maruhi ci run`'s declaration: unlike an ordinary run it reads no
 * config file, so server / project / env are **mandatory as flags**. On
 * the declaration they are optional (singleValued), and a missing one is
 * diagnosed by the body side with the CI-specific fix ("write the flag",
 * not "set it in config").
 */
const ciRunConfig = {
  server: singleValued("server", "Server URL (required; CI mode reads no config file)"),
  project: singleValued("project", "Project ID, which is the pinned genesis hash (required)"),
  env: singleValued("env", "Environment ID to lease (required)"),
  audience: singleValued("audience", "OIDC audience to request (default: the server origin)"),
  mirror: singleValued(
    "mirror",
    "Mirror URL to lease from when the server is unreachable (a second OIDC token is requested for the mirror's audience unless --audience is given)",
  ),
  anchor: singleValued(
    "anchor",
    "Path to the committed repository anchor file (generate it with `maruhi project anchor`)",
  ),
  command: runCommandArgument(),
};

/**
 * `maruhi ci sync <target>`'s declaration (SY2 stage 2 — ruling D): like
 * `ci run` it reads no config file (server / project are mandatory flags).
 * There is no `--env` since the sync config's target decides the
 * environment. `--yes` is the same word as the local apply.
 */
const ciSyncConfig = {
  server: singleValued("server", "Server URL (required; CI mode reads no config file)"),
  project: singleValued("project", "Project ID, which is the pinned genesis hash (required)"),
  audience: singleValued("audience", "OIDC audience to request (default: the server origin)"),
  mirror: singleValued(
    "mirror",
    "Mirror URL to lease from when the server is unreachable (a second OIDC token is requested for the mirror's audience unless --audience is given)",
  ),
  anchor: singleValued(
    "anchor",
    "Path to the committed repository anchor file (generate it with `maruhi project anchor`)",
  ),
  config: singleValued(
    "config",
    `Path to the sync config committed in the repository (default: ${DEFAULT_SYNC_CONFIG_PATH})`,
  ),
  yes: singleFlag(
    "yes",
    "Write to a production target (without it, a production target only shows the plan)",
  ),
  target: Argument.String("target").pipe(
    Argument.withDescription("Target name from the sync config (a key under `targets`)"),
    Argument.withSchema(NonBlank),
  ),
};

/** `maruhi ci rotate <NAME>` (a sealed value proposal from a CI job — PF7b). */
const ciRotateConfig = {
  server: singleValued("server", "Server URL (required; CI mode reads no config file)"),
  project: singleValued("project", "Project ID, which is the pinned genesis hash (required)"),
  env: singleValued("env", "Environment ID of the variable to rotate (required)"),
  audience: singleValued("audience", "OIDC audience to request (default: the server origin)"),
  anchor: singleValued(
    "anchor",
    "Path to the committed repository anchor file (generate it with `maruhi project anchor`)",
  ),
  "rotate-config": singleValued(
    "rotate-config",
    `Path to the rotation config naming the connector and admin credential of each variable (default: ${DEFAULT_ROTATE_CONFIG_PATH} in the working directory)`,
  ),
  "expires-in": Flag.Int("expires-in").pipe(
    Flag.withDescription(
      `Days the proposal waits for a member before it expires (1 to ${MAX_PROPOSAL_DAYS}; default 7)`,
    ),
    Flag.atMost(1),
    Flag.map((values) => values[0]),
  ),
  name: Argument.String("name").pipe(
    Argument.withDescription(
      "Variable name to rotate (the rule's variable, or the access key id an AWS rule pairs with it)",
    ),
    Argument.withSchema(NonBlank),
  ),
};

/**
 * `maruhi push`'s specific fix, attached to its extra positional
 * arguments. `maruhi push API_KEY "$SECRET"` is the most likely
 * misspelling. The refused argument's content is never shown (it may be
 * plaintext), so "the value comes via stdin" is always attached instead —
 * otherwise there is no way to fix it (cli-formatter.ts's strayHint).
 */
const PUSH_STDIN_HINT =
  '. Values are read from stdin (example: `printf %s "$SECRET" | maruhi push API_KEY`)';

const pushConfig = {
  ...commonFlags(),
  config: singleValued(
    "config",
    `Path to the sync config whose "onPush" targets are synced after the push (default: ${DEFAULT_SYNC_CONFIG_PATH} in the working directory, when it exists and names this project)`,
  ),
  "no-sync": singleFlag(
    "no-sync",
    "Skip the sync after the push (the default sync config is not read; run `maruhi sync apply` once after several pushes)",
  ),
  name: Argument.String("name").pipe(
    Argument.withDescription(
      "Variable name (the display name; becomes the environment variable name)",
    ),
    Argument.withSchema(NonBlank),
  ),
};

/** The config key's positional argument (shared by config's subcommands). */
const configKeyArgument = () =>
  Argument.String("key").pipe(
    Argument.withDescription(`Config key (${CONFIG_KEYS.join(" | ")})`),
    Argument.withSchema(NonBlank),
  );

const configGetConfig = {
  key: configKeyArgument(),
};

const configSetConfig = {
  key: configKeyArgument(),
  // An empty / whitespace-only value is refused by the declaration
  // (NonBlank): blocks the accident where the unset shape of `config set
  // defaultProject "$PROJ"` overwrites the existing config with an empty
  // value and reports success
  value: Argument.String("value").pipe(
    Argument.withDescription("Value to set"),
    Argument.withSchema(NonBlank),
  ),
};

const rotationListConfig = {
  ...projectFlags(),
  "fail-on-due": singleFlag(
    "fail-on-due",
    "Exit with code 3 when a value is past the max age its schema declares (a CI cron turns it into a failed build or an issue; see also --due-within)",
  ),
  "due-within": Flag.Int("due-within").pipe(
    Flag.withDescription(
      "With --fail-on-due: also fail when a value comes due within this many days (default 0 = only values already past their max age)",
    ),
    Flag.atMost(1),
    Flag.map((values) => values[0]),
  ),
  "fail-on-flags": singleFlag(
    "fail-on-flags",
    "Exit with code 3 while any rotation flag is active (a credential a departed party could read has not been rotated or dismissed)",
  ),
  "fail-on-pending": singleFlag(
    "fail-on-pending",
    "Exit with code 3 while a sealed proposal minted by a CI job awaits a member (with --due-within, the ones expiring inside the window are counted in the message); needs a member's token",
  ),
};

const rotationDismissConfig = {
  ...projectFlags(),
  env: singleValued(
    "env",
    "Environment ID of the flag to dismiss (with --all, narrows the dismissal to that environment)",
  ),
  all: singleFlag("all", "Dismiss every currently-active flag (an explicit acceptance of risk)"),
  // Not taken on a --all run. atMost(1) expresses "omitted under --all" in the declaration
  variable: Argument.String("variable").pipe(
    Argument.withDescription("Variable ID to dismiss (omit with --all)"),
    Argument.withSchema(NonBlank),
    Argument.atMost(1),
    Argument.map((values) => values[0]),
  ),
};

const rotationProposalsConfig = {
  ...projectFlags(),
  env: singleValued("env", "Only the proposals of this environment"),
};

const rotationAcceptConfig = {
  ...projectFlags(),
  yes: singleFlag(
    "yes",
    "Skip the confirmation (the only non-interactive path; the pushes are signed by you)",
  ),
  id: Argument.String("id").pipe(
    Argument.withDescription(
      "Proposal id from `maruhi rotation proposals` (a unique prefix of 8+ characters works)",
    ),
    Argument.withSchema(NonBlank),
  ),
};

const rotationRejectConfig = {
  ...projectFlags(),
  id: Argument.String("id").pipe(
    Argument.withDescription(
      "Proposal id from `maruhi rotation proposals` (a unique prefix of 8+ characters works)",
    ),
    Argument.withSchema(NonBlank),
  ),
};

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
const auditListConfig = {
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

const auditInvitesConfig = { ...projectFlags(), ...auditPageFlags() };

// self takes no project account-wide (no --project on the declaration =
// Unknown flag)
const auditSelfConfig = { ...serverOnlyFlags(), ...auditPageFlags() };

const auditVerifyConfig = { ...projectFlags() };

const auditReconcileConfig = { ...projectFlags() };

const loginConfig = {
  ...serverOnlyFlags(),
  "token-name": singleValued(
    "token-name",
    "Token name (signing in again with the same name rotates the token; default: cli:<hostname>)",
  ),
  "token-ttl-days": Flag.Int("token-ttl-days").pipe(
    Flag.withDescription(
      `Token lifetime in days (1-${MAX_TOKEN_TTL_DAYS}; default ${DEFAULT_TOKEN_TTL_DAYS}). For unattended use on runtimes without lease support`,
    ),
    Flag.atMost(1),
    Flag.map((values) => values[0]),
  ),
  "show-token": singleFlag(
    "show-token",
    "Print the issued token once, to provision MARUHI_TOKEN on a runtime without lease support (interactive terminals only)",
  ),
  "poll-interval": hiddenIntegerValued(
    "poll-interval",
    "Minimum approval polling interval in seconds (for tests)",
  ),
};

const logoutConfig = serverOnlyFlags();

const keyGenerateConfig = {
  ...serverOnlyFlags(),
  "new-identity": singleFlag(
    "new-identity",
    "Create a new identity even though your account already has a reserve key in the recovery ledger (only when every device and every recovery path is lost)",
  ),
};
const keyShowConfig = serverOnlyFlags();
const keyPublishConfig = {
  ...serverOnlyFlags(),
  gh: singleFlag(
    "gh",
    "Add the key to your GitHub account through the gh CLI (`gh ssh-key add --type signing`) instead of printing it",
  ),
};
const keyRecoverConfig = {
  ...serverOnlyFlags(),
  handoff: singleFlag(
    "handoff",
    "Open the reserve key by approval from your guardians instead of a recovery code",
  ),
  passkey: singleFlag(
    "passkey",
    "Open the reserve key with a passkey registered by `maruhi key seal passkey` instead of a recovery code",
  ),
  resume: singleFlag(
    "resume",
    "Keep the device key already on this machine and only register it on the projects where it is still missing (re-run after an interrupted recovery)",
  ),
};
/** The passkey's label (the ledger's display name — the api-schema acceptance shape is checked early on the declaration side). */
const PasskeyLabel = Schema.String.check(
  Schema.isPattern(PASSKEY_LABEL_PATTERN, { message: PASSKEY_LABEL_MESSAGE }),
);
const keySealPasskeyConfig = {
  ...serverOnlyFlags(),
  passkey: singleFlag(
    "passkey",
    "Open the ledger with an already registered passkey instead of the recovery code",
  ),
  label: Flag.String("label").pipe(
    Flag.withDescription(
      "Display name for this passkey in `maruhi key seal list` (1 to 64 characters)",
    ),
    Flag.withSchema(PasskeyLabel),
    Flag.atMost(1),
    Flag.map((values) => values[0]),
  ),
};
const keySealListConfig = serverOnlyFlags();
const keySealRemoveConfig = {
  ...serverOnlyFlags(),
  "wrap-id": Argument.String("wrap-id").pipe(
    Argument.withDescription("Passkey wrap ID (see `maruhi key seal list`)"),
    Argument.withSchema(NonBlank),
  ),
};
const keyRecoveryConfig = {
  ...serverOnlyFlags(),
  passkey: singleFlag(
    "passkey",
    "Open the existing ledger with a passkey instead of the current recovery code",
  ),
  replace: singleFlag(
    "replace",
    "Replace the reserve key with a new one without opening the ledger (when the recovery code is lost or may be compromised); the reserve keys recorded on this machine are revoked on every project the server lists for you once those chains confirm each is not a device key",
  ),
};
const keyReserveRotateConfig = {
  ...serverOnlyFlags(),
  passkey: singleFlag(
    "passkey",
    "Open the current ledger with a passkey instead of the recovery code",
  ),
};
const guardianApproveConfig = {
  ...serverOnlyFlags(),
  code: Argument.String("code").pipe(
    Argument.withDescription(
      "Handoff code shown by `maruhi key recover --handoff` on the requesting device",
    ),
    Argument.withSchema(NonBlank),
  ),
};

const deviceAddConfig = {
  ...serverOnlyFlags(),
  label: singleValued(
    "label",
    "Display name for this device in the device registry (default: the hostname)",
  ),
  replace: singleFlag(
    "replace",
    "Generate a new key even though this machine already has one, replacing the old key in this keychain once the new key's request is created (for a device that was revoked, or a copy of another device's key)",
  ),
};
const deviceApproveConfig = {
  ...serverOnlyFlags(),
  project: singleValued(
    "project",
    "Register the device on this project only (default: every project you belong to)",
  ),
  cap: singleValued(
    "cap",
    "Role cap for the new device: owner (default, no bound), admin, member or reader",
  ),
  env: scopeEnvFlag(
    "Environment the device may hold keys for (repeatable; default: all environments)",
  ),
  "all-envs": singleFlag("all-envs", "Let the device hold keys for every environment (default)"),
  "no-envs": singleFlag("no-envs", "Let the device hold no environment keys (a vote-only device)"),
  ref: Argument.String("fp-or-words").pipe(
    Argument.withDescription(
      "The new device's full 32-character fingerprint, or its 12 words, as shown by `maruhi device add`",
    ),
    Argument.withSchema(NonBlank),
  ),
};
const deviceListConfig = {
  ...serverOnlyFlags(),
  project: singleValued(
    "project",
    "Show only this project's chain (default: every project you belong to)",
  ),
};
const deviceRevokeConfig = {
  ...serverOnlyFlags(),
  project: singleValued(
    "project",
    "Revoke on this project only (default: every project you belong to)",
  ),
  user: singleValued(
    "user",
    "Revoke another member's device (admin/owner; devices are named by fingerprint)",
  ),
  yes: singleFlag("yes", "Skip the confirmation prompt"),
  "revoke-token": singleFlag(
    "revoke-token",
    "Also revoke the API tokens the registry associates with the revoked devices",
  ),
  ref: Argument.String("ref").pipe(
    Argument.withDescription(
      "Fingerprint prefix (at least 8 hex characters) or, for your own devices, the registry label (repeatable)",
    ),
    Argument.withSchema(NonBlank),
    Argument.atLeast(1),
  ),
};
const tokenListConfig = serverOnlyFlags();
const tokenRevokeConfig = {
  ...serverOnlyFlags(),
  "token-id": Argument.String("token-id").pipe(
    Argument.withDescription("Token id as shown by `maruhi token list`"),
    Argument.withSchema(NonBlank),
  ),
};

/** The guardian group's approval scheme (CRYPTO_SPEC §8.3). */
const GUARDIAN_MODES = ["any", "all"] as const;

function isGuardianMode(value: string | undefined): value is GuardianMode {
  return GUARDIAN_MODES.some((known) => known === value);
}

const guardianAddConfig = {
  ...projectFlags(),
  mode: singleValued(
    "mode",
    "Approval mode: any (one guardian is enough) or all (every guardian must approve)",
  ),
  "user-id": Argument.String("user-id").pipe(
    Argument.withDescription("User ID of a guardian (a member of the project; repeatable)"),
    Argument.withSchema(NonBlank),
    Argument.atLeast(1),
  ),
};
const guardianListConfig = { ...projectFlags() };
const guardianRemoveConfig = {
  ...serverOnlyFlags(),
  "group-id": Argument.String("group-id").pipe(
    Argument.withDescription("Guardian group ID (see `maruhi guardian list`)"),
    Argument.withSchema(NonBlank),
  ),
};
const guardianWardsConfig = serverOnlyFlags();

const projectInitConfig = {
  ...serverOnlyFlags(),
  org: singleValued(
    "org",
    "Org to create the project in (needed only when you belong to multiple orgs)",
  ),
};

const projectListConfig = { ...serverOnlyFlags() };

const projectVerifyConfig = {
  ...serverOnlyFlags(),
  project: singleValued("project", "Project ID (default: the `defaultProject` setting)"),
};

const projectAnchorConfig = {
  ...serverOnlyFlags(),
  project: singleValued("project", "Project ID (default: the `defaultProject` setting)"),
};

const projectCheckpointConfig = {
  ...serverOnlyFlags(),
  project: singleValued("project", "Project ID (default: the `defaultProject` setting)"),
};

const projectExportConfig = {
  ...serverOnlyFlags(),
  project: singleValued("project", "Project ID (default: the `defaultProject` setting)"),
  out: singleValued(
    "out",
    "Path of the snapshot file to write (refused if it exists); the identities companion is written as <out>.identities.json",
  ),
};

/** The environment ID positional (shared by env's subcommands. The key is the spelling typed). */
const environmentIdArgument = (name: string, description: string) =>
  Argument.String(name).pipe(Argument.withDescription(description), Argument.withSchema(NonBlank));

const envCreateConfig = {
  ...projectFlags(),
  name: singleValued("name", "Display name (defaults to the environment ID)"),
  // The key is **the spelling typed** (specOf uses it as the diagnostic name as-is)
  "environment-id": environmentIdArgument("environment-id", "Environment ID (e.g. dev / prod)"),
};

const envRotateConfig = {
  ...projectFlags(),
  reason: singleValued(
    "reason",
    "Rotation reason (required when creating a new epoch; recorded on the chain)",
  ),
  "new-epoch": singleFlag(
    "new-epoch",
    "Always create a new epoch, even when incomplete re-encryption could be resumed instead",
  ),
  // The sync receipt advances only when given (no implicit discovery of
  // the default path — rotate can be run from outside a repository and the
  // config is cwd-dependent)
  config: singleValued(
    "config",
    `Path to the sync config committed in the repository; when given, the receipts of the targets synced from this environment advance to the re-encrypted versions (no default: without it, receipts are left alone)`,
  ),
  "environment-id": environmentIdArgument("environment-id", "Environment ID (e.g. dev / prod)"),
};

const envDiffConfig = {
  ...projectFlags(),
  "environment-id": environmentIdArgument("environment-id", "First environment ID to compare"),
  // Declared **required** since it is a diff-only subcommand (a missing one is MissingArgument)
  "other-environment-id": environmentIdArgument(
    "other-environment-id",
    "Second environment ID to compare",
  ),
};

/**
 * The expiry flag taken by commands that can become proposals under
 * four-eyes (CRYPTO_SPEC §6.2 — K6). Never read on an operation the
 * policy doesn't target (a direct append).
 */
const proposalFlags = () => ({
  expires: singleValued(
    "expires",
    "How long the proposal stays approvable when the four-eyes policy turns this into a proposal (e.g. 7d, 48h; default 7d, at most 30d)",
  ),
});

const serverGrantConfig = {
  ...projectFlags(),
  ...proposalFlags(),
  environments: singleValued(
    "environments",
    "Comma-separated environment IDs to disclose (required; environments are always explicit)",
  ),
  "lease-policy": singleValued(
    "lease-policy",
    "Path to a workload lease-policy JSON file (defaults to no lease path)",
  ),
  "expect-fingerprint": singleValued(
    "expect-fingerprint",
    "Server key fingerprint noted out of band (32 hex chars; replaces the interactive check)",
  ),
  "key-from": singleValued(
    "key-from",
    "URL of the deployment whose server key to grant, such as a mirror (its /auth/config supplies the key; the grant is appended on the server and reaches the mirror by replication). Default: the server itself",
  ),
};

/** `maruhi mirror sync` / `status`: the server (session + export) and the mirror (its own session + the pages). */
const mirrorStatusConfig = {
  ...projectFlags(),
  mirror: singleValued("mirror", "Mirror URL (default: the `mirror` setting)"),
};

const mirrorSyncConfig = {
  ...mirrorStatusConfig,
  force: singleFlag(
    "force",
    "Replicate even though the mirror is marked as a mirror of another server",
  ),
};

/** `maruhi mirror mark`: --server is the mirror deployment, --source the deployment it mirrors. */
const mirrorMarkConfig = {
  ...projectFlags(),
  source: singleValued("source", "URL of the deployment this project mirrors (required)"),
  force: singleFlag(
    "force",
    "Mark even though this project's chain is not part of the source's (a mirror that can never be synced)",
  ),
};

const mirrorPromoteConfig = {
  ...projectFlags(),
  force: singleFlag(
    "force",
    "Promote even though the source still answers (two writable copies of the project — a split you accept)",
  ),
};

const serverRevokeConfig = {
  ...projectFlags(),
  ...proposalFlags(),
  fingerprint: singleValued(
    "fingerprint",
    "Server key fingerprint to revoke (may be omitted when exactly one grant is active)",
  ),
};

/** The role an invite can grant (an owner is never granted via an invite — AUTH_SPEC §15-1). */
const INVITE_ROLES = ["reader", "member", "admin"] as const;

function isInviteRole(value: string | undefined): value is InviteRole {
  return INVITE_ROLES.some((known) => known === value);
}

/** `--env <id>` (repeatable) — the scope of invite / change-role (CRYPTO_SPEC §6.2 — 2026-09-15 ES K4). */
function scopeEnvFlag(description: string) {
  return Flag.String("env").pipe(
    Flag.withDescription(description),
    Flag.withSchema(NonBlank),
    // Express repetition in the declaration (0 or more — atLeast(0) gives readonly string[])
    Flag.atLeast(0),
  );
}

const inviteCreateConfig = {
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

const inviteAcceptConfig = {
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

const inviteListConfig = { ...projectFlags() };

const inviteRevokeConfig = {
  ...projectFlags(),
  "invite-id": Argument.String("invite-id").pipe(
    Argument.withDescription("Invite ID to revoke (see `maruhi invite list`)"),
    Argument.withSchema(NonBlank),
  ),
};

/** The role grantable to a member (CRYPTO_SPEC §6.2). */
const MEMBER_ROLES = ["reader", "member", "admin", "owner"] as const;

function isMemberRole(value: string | undefined): value is Role {
  return MEMBER_ROLES.some((known) => known === value);
}

const memberAddConfig = {
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
    Argument.withSchema(NonBlank),
  );

const memberRemoveConfig = {
  ...projectFlags(),
  ...proposalFlags(),
  "user-id": memberTargetArgument(),
};

const memberChangeRoleConfig = {
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

const memberListConfig = {
  ...projectFlags(),
  json: singleFlag("json", "Print the members as JSON (user id, role, scope, key fingerprint)"),
};

/** The proposal id positional (`maruhi approval show / approve / withdraw` — approval item 23). */
const proposalIdArgument = () =>
  Argument.String("proposal-id").pipe(
    Argument.withDescription(
      "Proposal id (the propose entry's hash; a unique prefix of at least 8 hex digits, or #<seq> of the propose entry — see `maruhi approval list`)",
    ),
    Argument.withSchema(NonBlank),
  );

const approvalListConfig = {
  ...projectFlags(),
  json: singleFlag(
    "json",
    "Print the policy and the pending proposals as JSON (votes recounted under the current policy)",
  ),
};

const approvalShowConfig = { ...projectFlags(), "proposal-id": proposalIdArgument() };

const approvalApproveConfig = { ...projectFlags(), "proposal-id": proposalIdArgument() };

const approvalWithdrawConfig = { ...projectFlags(), "proposal-id": proposalIdArgument() };

const projectPolicyApprovalsConfig = {
  ...projectFlags(),
  ...proposalFlags(),
  required: singleValued(
    "required",
    "Enable (or change) the four-eyes policy: number of distinct owner approvals an operation needs (at least 2; the project must have at least that many owners)",
  ),
  ops: singleValued(
    "ops",
    `Comma-separated operations that need approval (${APPROVAL_TARGET_OPS.join(" | ")}; default ${DEFAULT_POLICY_OPS.join(",")} — add_member is left out because adding an owner always needs approval, and other invites are already protected by the acceptance ceremony)`,
  ),
  off: singleFlag(
    "off",
    "Turn the policy off (while a policy is active, this itself needs the approvals)",
  ),
};

/** `maruhi schema` (display — the bare parent doubles as show. Same shape as audit). */
const schemaShowConfig = { ...commonFlags() };

/**
 * `maruhi mcp` (PF5 — the MCP server over stdio). The same flags as
 * `maruhi schema`: the host config pins the project (and the default
 * environment) the way a human would on the command line (pf5-design.md
 * ruling M4).
 */
const mcpConfig = { ...commonFlags() };

/**
 * `maruhi proxy run -- <command>` (PF4 — credential brokering): `run`'s
 * flags plus the proxy config path and a per-request log switch. The run
 * target is declared exactly like `run`'s.
 */
const proxyRunConfig = {
  ...commonFlags(),
  config: singleValued(
    "config",
    `Path to the proxy config committed in the repository (default: ${DEFAULT_PROXY_CONFIG_PATH})`,
  ),
  verbose: singleFlag(
    "verbose",
    "Print one line per request the proxy handles (method, host, path, and the variables substituted — never a value)",
  ),
  listen: singleValued(
    "listen",
    "Bind the proxy to host[:port] instead of the loopback, so a sandbox or container can reach it (every request still needs the run's proxy credential)",
  ),
  advertise: singleValued(
    "advertise",
    "The host[:port] the command is told to use for the proxy when it differs from the bound address (for example host.docker.internal from a container)",
  ),
  command: runCommandArgument(),
};

const proxyAcceptConfig = {
  config: singleValued(
    "config",
    `Path to the proxy config to accept (default: ${DEFAULT_PROXY_CONFIG_PATH})`,
  ),
  project: singleValued(
    "project",
    "The project the config is for (default: the config's `project`, else the default project)",
  ),
};

/** The `--type` closed set (CRYPTO_SPEC §4.2 — ruling CT) + `none` for an explicit clear. */
const SCHEMA_TYPES = ["string", "number", "boolean", "url"] as const;

const schemaSetConfig = {
  ...commonFlags(),
  type: singleValued(
    "type",
    `Declared value type (${SCHEMA_TYPES.join(" | ")}; \`none\` clears it back to unspecified)`,
  ),
  required: singleFlag(
    "required",
    "Declare the variable as required (`maruhi run` fails fast while it has no value)",
  ),
  optional: singleFlag("optional", "Declare the variable as not required"),
  description: singleValued(
    "description",
    "Human-readable description (plaintext metadata visible to the server — never put secret values here)",
  ),
  "clear-description": singleFlag(
    "clear-description",
    "Clear the description (explicit — an empty --description value is rejected as a likely unset shell variable)",
  ),
  "max-age": singleValued(
    "max-age",
    "Days within which a value should be replaced after its push (1 to 3650), or `none` to clear it; `maruhi rotation list` shows values past their max age",
  ),
  "allow-high-entropy": singleFlag(
    "allow-high-entropy",
    "Proceed without confirmation when the name or description contains a secret-like high-entropy string (fail-closed otherwise)",
  ),
  name: Argument.String("name").pipe(
    Argument.withDescription(
      "Variable name (created as a declared variable when it does not exist)",
    ),
    Argument.withSchema(NonBlank),
  ),
};

/** `maruhi schema import <file>` (bootstrap — design doc §1-3). */
const schemaImportConfig = {
  ...commonFlags(),
  file: Argument.String("file").pipe(
    Argument.withDescription(
      "Path to a .env or .env.example file to read locally (values are observed for type inference only; never sent unless you explicitly choose to push one)",
    ),
    Argument.withSchema(NonBlank),
  ),
};

/** `maruhi schema export` (producing the derived snapshot — design doc §1-6). */
const schemaExportConfig = { ...commonFlags() };

/** `maruhi schema verify-snapshot <file>` (the CI divergence check — design doc §1-6). */
const schemaVerifySnapshotConfig = {
  ...commonFlags(),
  file: Argument.String("file").pipe(
    Argument.withDescription(
      "Path to the committed snapshot file (generate with `maruhi schema export`)",
    ),
    Argument.withSchema(NonBlank),
  ),
};

/** `maruhi schema lint [paths...]` (matching against the code contract — design doc §1-7). */
const schemaLintConfig = {
  ...commonFlags(),
  ignore: Flag.String("ignore").pipe(
    Flag.withDescription(
      "Environment-variable name to exclude from the undeclared check (repeatable; for runtime variables not managed by maruhi, e.g. NODE_ENV)",
    ),
    Flag.withSchema(NonBlank),
    // Express repetition in the declaration (0 or more — atLeast(0) gives readonly string[])
    Flag.atLeast(0),
  ),
  paths: Argument.String("path").pipe(
    Argument.withDescription("File or directory to scan for environment-variable references"),
    Argument.atLeast(1),
  ),
};

/** `maruhi var rm <NAME>` (deleting a variable — AUTH_SPEC §12-5). */
const varRmConfig = {
  ...commonFlags(),
  force: singleFlag(
    "force",
    "Skip the interactive confirmation (the only non-interactive path; deletion is permanent)",
  ),
  name: Argument.String("name").pipe(
    Argument.withDescription("Variable name to delete (declared or active)"),
    Argument.withSchema(NonBlank),
  ),
};

/** `maruhi var history <NAME>` (the version history — AUTH_SPEC §12-7, 2026-09-27 VH). */
const varHistoryConfig = {
  ...commonFlags(),
  json: singleFlag(
    "json",
    "Print the history as JSON (server-declared metadata: version, epoch, writer, time, lineage, flag count)",
  ),
  name: Argument.String("name").pipe(
    Argument.withDescription("Variable name whose version history to show"),
    Argument.withSchema(NonBlank),
  ),
};

/** `maruhi var rollback <NAME> --to <VERSION>` (restoring an old value as a new version — VH). */
const varRollbackConfig = {
  ...commonFlags(),
  to: Flag.Int("to").pipe(
    Flag.withDescription(
      "The version whose value to restore (see `maruhi var history`); pushed as a new version",
    ),
    Flag.atMost(1),
    Flag.map((values) => values[0]),
  ),
  force: singleFlag("force", "Skip the interactive confirmation (the only non-interactive path)"),
  config: singleValued(
    "config",
    `Path to the sync config whose "onPush" targets are synced after the rollback (default: ${DEFAULT_SYNC_CONFIG_PATH} in the working directory, when it exists and names this project)`,
  ),
  "no-sync": singleFlag(
    "no-sync",
    "Skip the sync after the rollback (the default sync config is not read)",
  ),
  name: Argument.String("name").pipe(
    Argument.withDescription("Variable name to roll back"),
    Argument.withSchema(NonBlank),
  ),
};

/** `maruhi var rotate <NAME> [--finalize]` (upstream rotation through a connector — PF6). */
const varRotateConfig = {
  ...commonFlags(),
  finalize: singleFlag(
    "finalize",
    "Invalidate the credential the previous version held (after the new value is deployed) instead of rotating",
  ),
  previous: Flag.Int("previous").pipe(
    Flag.withDescription(
      "With --finalize: the version that held the credential to invalidate (default: the one before the current version)",
    ),
    Flag.atMost(1),
    Flag.map((values) => values[0]),
  ),
  yes: singleFlag(
    "yes",
    "Skip the confirmation of a step that invalidates a credential (the only non-interactive path)",
  ),
  "rotate-config": singleValued(
    "rotate-config",
    `Path to the rotation config naming the connector and admin credential of each variable (default: ${DEFAULT_ROTATE_CONFIG_PATH} in the working directory)`,
  ),
  config: singleValued(
    "config",
    `Path to the sync config whose "onPush" targets are synced after the rotation (default: ${DEFAULT_SYNC_CONFIG_PATH} in the working directory, when it exists and names this project)`,
  ),
  "no-sync": singleFlag(
    "no-sync",
    "Skip the sync after the rotation (the default sync config is not read)",
  ),
  name: Argument.String("name").pipe(
    Argument.withDescription(
      "Variable name to rotate (the rule's variable, or the access key id an AWS rule pairs with it)",
    ),
    Argument.withSchema(NonBlank),
  ),
};

/**
 * The declarations of `maruhi sync plan` / `apply` (SY2 stage 1). The
 * environment is decided not by a flag but by the repository config (the
 * `maruhi.sync.json` targets), so there is no `--env`. `--project` exists
 * but is checked against the config's `project` when present.
 */
const syncTargetArgument = () =>
  Argument.String("target").pipe(
    Argument.withDescription("Target name from the sync config (a key under `targets`)"),
    Argument.withSchema(NonBlank),
  );

const syncCommonFlags = () => ({
  ...projectFlags(),
  config: singleValued(
    "config",
    `Path to the sync config committed in the repository (default: ${DEFAULT_SYNC_CONFIG_PATH})`,
  ),
});

const syncPlanConfig = {
  ...syncCommonFlags(),
  target: syncTargetArgument(),
};

const syncApplyConfig = {
  ...syncCommonFlags(),
  yes: singleFlag(
    "yes",
    "Apply to a production target (without it, a production target only shows the plan)",
  ),
  target: syncTargetArgument(),
};

/**
 * `maruhi sync init <target>`'s declaration (SY2 stage 2 — ruling F):
 * touches neither network nor files; assembles the config JSON from the
 * flags and prints it to stdout.
 */
const syncInitConfig = {
  preset: singleValued(
    "preset",
    "Deploy target kind: vercel, cloudflare-workers, netlify, or github-actions (required)",
  ),
  driver: singleValued(
    "driver",
    "How to reach the target: exec (the installed vendor CLI; default when the preset has one; the only driver for github-actions) or http (the vendor API with a token stored in maruhi; the only driver for netlify)",
  ),
  env: singleValued("env", "maruhi environment ID to copy from (required)"),
  receipts: singleValued(
    "receipts",
    "maruhi environment ID that stores the receipts (required; create it with `maruhi env create`)",
  ),
  project: singleValued("project", "Project ID to pin the config to (optional)"),
  variables: singleValued("variables", 'Comma-separated variable names to copy (default: "all")'),
  exclude: singleValued(
    "exclude",
    'Comma-separated names to leave out (only with the default "all")',
  ),
  production: singleFlag(
    "production",
    "Mark the target as production (apply then needs --yes; the default follows the preset)",
  ),
  cwd: singleValued(
    "cwd",
    "exec driver: directory to run the vendor CLI in, relative to the config",
  ),
  command: singleValued(
    "command",
    "exec driver: path of the installed vendor CLI (default: on PATH)",
  ),
  "token-env": singleValued(
    "token-env",
    "http driver: maruhi environment ID that holds the vendor's token",
  ),
  "token-name": singleValued(
    "token-name",
    "http driver: name of the maruhi variable that holds the vendor's token",
  ),
  "on-push": singleValued(
    "on-push",
    "Sync after every `maruhi push` to the environment: apply (from this machine) or workflow (trigger the repository's workflow with gh so CI syncs); needs --project",
  ),
  workflow: singleValued(
    "workflow",
    "With --on-push workflow: the workflow file that runs `maruhi ci sync` (for example maruhi-sync.yml)",
  ),
  option: Flag.String("option").pipe(
    Flag.withDescription(
      "Preset option as key=value (repeatable; for example environment=production, name=my-worker)",
    ),
    Flag.withSchema(NonBlank),
    Flag.atMost(64),
  ),
  target: syncTargetArgument(),
};

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

/**
 * Settles the command list `maruhi run` executes (**only what follows
 * `--`**). The parser merges the positional arguments before and after
 * `--` into one array (measured: upstream's `parseArgs` produces
 * `[...result.arguments, ...afterEndOfOptions]`). So on the declaration
 * alone, `maruhi run stray -- printenv` would disguise as running `stray`.
 * As the implementation of ADR-0016 decision 8 (`--` is required, judged
 * by reading `Stdio.args`), it also checks **that the count after `--`
 * matches**.
 *
 * The count is derived from **the array the parser resolved and argv's
 * position** (never a copy of the declaration — it would silently drift
 * when a value-taking flag is added). The contents never appear in
 * diagnostics.
 */
function commandAfterTerminator(
  parsed: readonly string[],
): Effect.Effect<readonly string[], CliError, Stdio.Stdio> {
  return Effect.gen(function* () {
    const stdio = yield* Stdio.Stdio;
    const argv = yield* stdio.args;
    const terminator = argv.indexOf("--");
    // On the no-`--` branch, the variadic arguments stay as extra
    // positional arguments (`--env prod`'s `prod` was eaten as the flag's
    // value)
    const stray = terminator < 0 ? parsed.length : parsed.length - (argv.length - terminator - 1);
    if (stray > 0) {
      return yield* Effect.fail(
        usageError(
          `Unexpected extra arguments (${stray}; contents not shown — they may contain plaintext values). \`maruhi run\` takes no positional arguments before \`--\`${RUN_TERMINATOR_HINT}`,
        ),
      );
    }
    return parsed;
  });
}

/**
 * `maruhi env create <id>`'s body (the composite request — §12-4).
 */
function envCreateCommand(
  flags: CommonFlags & { readonly name?: string | undefined },
  environmentId: string,
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const context = yield* openProject(flags);
    const floor = yield* floorHandleFor(context, environmentId);
    const created = yield* envCreateOp({
      client: context.client,
      verified: context.verified,
      environmentId,
      name: flags.name ?? environmentId,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
      resync: context.resync,
      floor,
    });
    yield* io.log(
      // The member count is the size of **the wrap set actually
      // registered** (when rebuilt under a CAS retry, it may disagree with
      // the run-start view's member count)
      `Created environment ${environmentId} (epoch=${created.currentEpoch}, DEK wrapped for ${countNoun(created.memberCount, "current member")})`,
    );
  });
}

/** Format validation of an environment ID passed as a positional (**the given value itself never appears in the error**). */
function requireEnvironmentId(
  value: string,
  example: string,
): Effect.Effect<EnvironmentId, CliError> {
  return isEnvironmentId(value)
    ? Effect.succeed(value)
    : Effect.fail(
        usageError(
          `Invalid environment ID (must start with an alphanumeric character, followed by up to 63 alphanumerics, _ or -. Example: ${example})`,
        ),
      );
}

/** The environment ID's shape (the wording for the --env flag. The given value itself never appears in the error). */
const ENV_FLAG_SHAPE_MESSAGE =
  "Invalid environment ID for --env (must start with an alphanumeric character, followed by up to 63 alphanumerics, _ or -)";

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

/**
 * The length check of `--token-name` (**the given value itself never
 * appears in the error**). The bound reads the same constant as
 * `@maruhi/api-schema`'s declaration (transcribing the number onto the
 * CLI side would keep refusing under a stale bound when the declaration
 * is relaxed).
 */
function requireTokenName(value: string | undefined): Effect.Effect<string, CliError> {
  const name = value ?? `cli:${hostname()}`;
  return name.length > MAX_TOKEN_NAME_LENGTH
    ? Effect.fail(usageError(`--token-name must be at most ${MAX_TOKEN_NAME_LENGTH} characters`))
    : Effect.succeed(name);
}

/**
 * The range check of `--token-ttl-days` (AUTH_SPEC §6). The bound and
 * default read the same constants as `@maruhi/api-schema`'s declaration
 * (same reason as requireTokenName: a misspelling drops before the
 * browser approval completes). An omitted one is returned as undefined,
 * left to the server-side default (90 days).
 */
function requireTokenTtlDays(
  value: number | undefined,
): Effect.Effect<number | undefined, CliError> {
  if (value === undefined) {
    return Effect.succeed(undefined);
  }
  return value < 1 || value > MAX_TOKEN_TTL_DAYS
    ? Effect.fail(usageError(`--token-ttl-days must be between 1 and ${MAX_TOKEN_TTL_DAYS}`))
    : Effect.succeed(value);
}

/**
 * `maruhi schema` (display)'s body (shared between bare `maruhi schema`
 * and the parent handler — same shape as audit). **The keyless class**
 * (openMetadataEnvironment — a metadata-only pull) and **agent-gate does
 * not apply (the permissive side — design doc §1-1)**: the output carries
 * zero values (names, types, descriptions, required, status only), and
 * ADR-0016 decision 7's two-layer gate applies only to "value-displaying"
 * commands. Running as-is in an agent environment is this feature's main
 * use (not being on the deny-list is pinned by a test).
 */
function runSchemaShow(values: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly env?: string | undefined;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const context = yield* openMetadataEnvironment(values);
    yield* schemaShowOp({
      client: context.client,
      verified: context.verified,
      environmentId: context.environmentId,
      resync: context.resync,
      floor: context.floorHandle,
    });
  });
}

/** Interpreting `--type` (unspecified = keep, `none` = an explicit clear. **The given value itself never appears in the error**). */
function parseSchemaTypeFlag(
  value: string | undefined,
): Effect.Effect<FieldUpdate<MetaVarType>, CliError> {
  if (value === undefined) {
    return Effect.succeed({ kind: "keep" });
  }
  if (value === "none") {
    return Effect.succeed({ kind: "set", value: "" });
  }
  if ((SCHEMA_TYPES as readonly string[]).includes(value)) {
    return Effect.succeed({ kind: "set", value: value as MetaVarType });
  }
  return Effect.fail(
    usageError(`--type must be one of ${SCHEMA_TYPES.join(" | ")} (or \`none\` to clear it)`),
  );
}

/** Interpreting `--max-age` (unspecified = keep, `none` = clear, else a day count 1..3650). The given text never appears in the error. */
function parseMaxAgeFlag(
  value: string | undefined,
): Effect.Effect<FieldUpdate<number | null>, CliError> {
  if (value === undefined) {
    return Effect.succeed({ kind: "keep" });
  }
  if (value === "none") {
    return Effect.succeed({ kind: "set", value: null });
  }
  const days = /^[1-9][0-9]{0,3}$/.test(value) ? Number(value) : Number.NaN;
  return Number.isInteger(days) && days >= 1 && days <= MAX_META_MAX_AGE_DAYS
    ? Effect.succeed({ kind: "set", value: days })
    : Effect.fail(
        usageError(
          `--max-age must be a number of days from 1 to ${MAX_META_MAX_AGE_DAYS} (or \`none\` to clear it)`,
        ),
      );
}

/**
 * Interpreting `schema set`'s column specifications (partial update §1-2
 * — unspecified = keep, only an explicit flag returns to empty). A
 * contradictory specification (--required and --optional etc.) is a usage
 * error.
 */
function parseSchemaFieldUpdates(values: {
  readonly type?: string | undefined;
  readonly required: boolean;
  readonly optional: boolean;
  readonly description?: string | undefined;
  readonly "clear-description": boolean;
  readonly "max-age"?: string | undefined;
}): Effect.Effect<SchemaFieldUpdates, CliError> {
  return Effect.gen(function* () {
    const varType = yield* parseSchemaTypeFlag(values.type);
    const maxAgeDays = yield* parseMaxAgeFlag(values["max-age"]);
    if (values.required && values.optional) {
      return yield* Effect.fail(
        usageError("--required and --optional are mutually exclusive (specify at most one)"),
      );
    }
    const required: FieldUpdate<boolean> = values.required
      ? { kind: "set", value: true }
      : values.optional
        ? { kind: "set", value: false }
        : { kind: "keep" };
    if (values.description !== undefined && values["clear-description"]) {
      return yield* Effect.fail(
        usageError("--description and --clear-description are mutually exclusive"),
      );
    }
    const description: FieldUpdate<string> = values["clear-description"]
      ? { kind: "set", value: "" }
      : values.description !== undefined
        ? { kind: "set", value: values.description }
        : { kind: "keep" };
    return { varType, required, description, maxAgeDays };
  });
}

/** `schema set`'s success report (the type is displayed as a declaration — the word "verified" is never used, §14.3). */
function schemaSetReport(name: string, summary: SchemaSetSummary): string {
  const typeShown = summary.schema.varType === "" ? "-" : summary.schema.varType;
  const maxAge =
    summary.schema.maxAgeDays === null ? "" : `, max-age=${summary.schema.maxAgeDays}d`;
  if (summary.created) {
    return `Declared ${displayText(name)} (type=${typeShown}, required=${summary.schema.required}${maxAge}) — no value yet. Set the first value with: \`printf %s "$VALUE" | maruhi push ${displayText(name)}\``;
  }
  return `Updated the schema of ${displayText(name)} (type=${typeShown}, required=${summary.schema.required}${maxAge}, metaVersion=${summary.metaVersion})`;
}

/** Validating a config key passed as a positional (**the given value itself never appears in the error**). */
/* -------------------------------------------------------------------------- */
/* Mirrors (PF2 — AUTH_SPEC §11-7; the operations live in mirror.ts)          */
/* -------------------------------------------------------------------------- */

/** The mirror's session and the project of `mirror sync` / `status` (the server session is opened separately). */
function openMirrorTarget(flags: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly mirror?: string | undefined;
}) {
  return Effect.gen(function* () {
    const config = yield* (yield* ConfigStore).load;
    const projectId = yield* resolveProjectId(flags.project, config);
    const serverOrigin = yield* resolveServerOrigin(flags.server, config);
    const mirrorOrigin = yield* resolveMirrorOrigin(flags.mirror, config);
    if (mirrorOrigin === null) {
      return yield* Effect.fail(
        cliError(
          "No mirror URL. Pass --mirror <url> or set it with `maruhi config set mirror <url>`",
        ),
      );
    }
    // By string here (a cron's "current" tick stays the status reads
    // — H-9); the mark, where a self-mirror would be created, and the
    // promotion compare deployments by server key fingerprint (C-13)
    if (mirrorOrigin === serverOrigin) {
      return yield* Effect.fail(
        usageError("The mirror URL is the server URL itself (pass the mirror deployment's URL)"),
      );
    }
    const mirror = yield* openSession(mirrorOrigin, "mirror");
    return { mirror, mirrorOrigin, projectId };
  });
}

/**
 * Whether two origins publish one server key: equal strings, or equal
 * fingerprints from their public `/auth/config` (a deployment answers
 * under its workers.dev hostname and its custom domain alike — ruling C
 * revision, round 5). The fingerprint is self-reported, so equality only
 * ever refuses (a mirror of itself) or names a way out — never lifts a
 * guard (round 6). Without a fingerprint on either side the strings
 * decide; a config that does not answer within the probe's bound counts
 * as no fingerprint.
 */
function sameDeployment(a: string, b: string): Effect.Effect<boolean, never, CliServices> {
  if (a === b) {
    return Effect.succeed(true);
  }
  return Effect.gen(function* () {
    const [fingerprintA, fingerprintB] = yield* Effect.all(
      [deploymentFingerprint(a), deploymentFingerprint(b)],
      { concurrency: 2 },
    );
    return fingerprintA !== null && fingerprintA === fingerprintB;
  });
}

/** The server key fingerprint a deployment publishes (null = none, or no answer within the probe's bound). */
function deploymentFingerprint(origin: string): Effect.Effect<string | null, never, CliServices> {
  return Effect.gen(function* () {
    const client = yield* makeApiClient({ baseUrl: origin, timeout: PROMOTE_PROBE_TIMEOUT });
    return yield* client.auth.authConfig({}).pipe(
      Effect.map((config) => config.serverKeyFingerprintHex ?? null),
      Effect.catch(() => Effect.succeed(null)),
    );
  });
}

/** The server's verified view (the same keyless prologue as `project export`). */
function verifiedServerView(serverFlag: string | undefined, projectId: string) {
  return Effect.gen(function* () {
    const source = yield* openSession(serverFlag);
    const verified = yield* verifiedViewOf(source, projectId);
    return { source, verified };
  });
}

/**
 * The server's verified view from an open session: the same keyless
 * prologue as `project verify` — the floor check, the invite anchor and
 * the head gossip, which advances the local floor to the verified head
 * once every check passes (ruling H revision, round 7: a sync whose view
 * left the floor behind took the view on every tick, forever).
 */
function verifiedViewOf(source: SessionContext, projectId: string) {
  return Effect.gen(function* () {
    const synced = yield* syncProject(source.client, projectId);
    const checked = yield* loadCheckedFloor(
      projectId,
      synced,
      syncProject(source.client, projectId),
    );
    yield* checkInviteAnchor(projectId, checked.verified);
    return yield* reconcileGossip(
      projectId,
      checked.verified,
      syncProject(source.client, projectId),
    );
  });
}

/**
 * `maruhi mirror sync`: the export's pages uploaded to the mirror in
 * order. The two sessions are opened first (the server's for the export,
 * the mirror's for the pages); the server's chain is fetched and verified
 * only when something is uploaded — a cron's "current" tick is the two
 * status reads (ruling H revision, round 4).
 */
function mirrorSyncCommand(flags: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly mirror?: string | undefined;
  readonly force?: boolean | undefined;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const target = yield* openMirrorTarget(flags);
    const source = yield* openSession(flags.server);
    // The pages go through the mirror under the body bound on their
    // headers (a full page on a slow uplink is not "did not answer" — H-10);
    // the status reads keep the usual bound (H-12)
    const pages = yield* makeApiClient({
      baseUrl: target.mirrorOrigin,
      token: target.mirror.session.token,
      timeout: BODY_TIMEOUT,
    });
    const floor = yield* (yield* FloorStore).load(target.projectId);
    const result = yield* mirrorSyncOp({
      source: source.client,
      mirror: target.mirror.client,
      pages,
      projectId: target.projectId,
      sourceOrigin: source.origin,
      mirrorOrigin: target.mirrorOrigin,
      ...(flags.force === true ? { force: true } : {}),
      floorHead: floor.floor?.chainHead ?? null,
      verified: verifiedViewOf(source, target.projectId),
    });
    for (const line of describeMirrorSync(result, target.projectId, target.mirrorOrigin)) {
      yield* io.log(line);
    }
    // A replica behind the view taken before the export, past the one
    // taken after the commit, or off either's chain is evidence against
    // the server, reported above; the sync fails so a cron notices (ruling
    // H revision, rounds 8 and 9)
    const verdict =
      result.kind === "replicated"
        ? replicaVerdict(result.committed, result.viewBefore, result.verified)
        : null;
    if (verdict !== null) {
      return yield* Effect.fail(
        cliError(
          `The replica ${target.mirrorOrigin} now holds is ${verdict} — against ${source.origin} and against the mirror`,
        ),
      );
    }
  });
}

/**
 * `maruhi mirror status`: the server's verified head and the mirror's,
 * side by side. The one command for "is my mirror usable" must answer
 * while the server is down: a server that does not answer leaves the
 * mirror's head alone on the report (announced), any other failure of the
 * server side fails as usual.
 */
function mirrorStatusCommand(flags: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly mirror?: string | undefined;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const target = yield* openMirrorTarget(flags);
    const status = yield* mirrorStatusOp({
      client: target.mirror.client,
      projectId: target.projectId,
    });
    const verified = yield* verifiedServerView(flags.server, target.projectId).pipe(
      Effect.map((view) => view.verified),
      Effect.catch((error: CliError) =>
        error.unreachable === true
          ? Effect.gen(function* () {
              yield* io.logError(`${error.message}. Reporting the mirror's head alone`);
              return null;
            })
          : Effect.fail(error),
      ),
    );
    for (const line of describeMirrorStatus(status, verified, target.mirrorOrigin)) {
      yield* io.log(line);
    }
  });
}

/** `maruhi mirror mark --server <mirror> --source <server>`: the owner marks the project read-only there. */
function mirrorMarkCommand(flags: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly source?: string | undefined;
  readonly force?: boolean | undefined;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    if (flags.source === undefined) {
      return yield* Effect.fail(
        usageError("mirror mark requires --source <url> (the deployment this project mirrors)"),
      );
    }
    const sourceOrigin = yield* normalizeHttpOrigin(flags.source, "the --source URL");
    const context = yield* openSession(flags.server);
    if (yield* sameDeployment(sourceOrigin, context.origin)) {
      return yield* Effect.fail(
        usageError(
          sourceOrigin === context.origin
            ? "--source is the server itself (run this against the mirror deployment with --server <mirror url>)"
            : "--source publishes this server's key fingerprint: it is this deployment under another hostname (run this against the mirror deployment with --server <mirror url>), or another deployment sharing one SERVER_ENC_KEY_IKM — one key per deployment; generate a distinct IKM for the mirror first",
        ),
      );
    }
    const projectId = yield* resolveProjectId(flags.project, context.config);
    // A project whose chain is not part of the source's (a former primary
    // that advanced past the fork) can never be synced: every replica is
    // refused as not an extension, and there is no way out but another
    // promotion. Refused here, before the mark (ruling C revision, round 3)
    if (flags.force !== true) {
      yield* ensureMarkable(context, sourceOrigin, projectId);
    }
    yield* context.client.mirror
      .mark({ params: { projectId }, payload: { sourceOrigin } })
      .pipe(Effect.mapError(toCliError));
    yield* io.log(
      `Marked project ${projectId} on ${context.origin} as a mirror of ${sourceOrigin}: it refuses writes from now on and serves reads and leases. Keep it current with \`maruhi mirror sync --server ${sourceOrigin} --mirror ${context.origin}\`; members fall back to it with \`maruhi config set mirror ${context.origin}\``,
    );
  });
}

/**
 * The mark's precondition: the two chains are one chain — the project's
 * head here is an entry of the source's verified chain (equal, or behind
 * it), or the source's head is an entry of this project's (this project
 * is ahead: the planned failover's freeze, whose last sync brings the
 * difference over — ruling C revision, round 8). Only a fork is refused.
 * Both views are plain verified chains (no floor: the floor is per
 * project, and a mirror behind the local floor is the normal state of the
 * copy about to be synced). The source's view needs a session there;
 * without one, or when the source does not answer, the mark proceeds with
 * a warning (the first sync tells).
 */
function ensureMarkable(
  context: SessionContext,
  sourceOrigin: string,
  projectId: string,
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const here = yield* syncProject(context.client, projectId);
    const source = yield* openSessionWith(context.config, sourceOrigin, "server").pipe(
      Effect.flatMap((session) =>
        Effect.all({
          view: syncProject(session.client, projectId),
          mark: session.client.mirror
            .status({ params: { projectId } })
            .pipe(Effect.mapError(toCliError)),
        }),
      ),
      Effect.catch((error: CliError) =>
        Effect.as(
          logWarning(
            `the source's chain and mark could not be read (${error.message}); marking without the check that this project's chain is part of it and that the source is a primary — the first \`maruhi mirror sync\` tells`,
          ),
          null,
        ),
      ),
    );
    if (source === null) {
      return;
    }
    // The source's own mark decides whether the sync the mark leads to can
    // run at all (ruling C revision, round 9): a mirror of a third origin
    // is no source (the star), and a writable source takes no page
    if (source.mark.mirror && source.mark.sourceOrigin !== context.origin) {
      return yield* Effect.fail(
        cliError(
          `${sourceOrigin} holds this project as a mirror of ${source.mark.sourceOrigin ?? "another deployment"}: mirrors sync from the primary, so this project is marked against it (\`maruhi mirror mark --server ${context.origin} --source ${source.mark.sourceOrigin ?? "<primary url>"}\`), or pass --force to mark it against ${sourceOrigin} anyway`,
        ),
      );
    }
    if (onChain(headOfView(here), source.view)) {
      return;
    }
    const ahead = countNoun(here.state.headSeq - source.view.state.headSeq, "chain entry");
    if (!onChain(headOfView(source.view), here)) {
      return yield* Effect.fail(
        cliError(
          `This project's chain (seq ${here.state.headSeq}, head ${here.state.headHashHex}) and ${sourceOrigin}'s (seq ${source.view.state.headSeq}, head ${source.view.state.headHashHex}) are not one chain: neither head is an entry of the other. Marked as a mirror it could never be synced (every replica would be refused as not an extension). It was written to after the fork — export it away, or pass --force to mark it anyway`,
        ),
      );
    }
    if (!source.mark.mirror) {
      return yield* Effect.fail(
        cliError(
          `${sourceOrigin} holds this project writable, and this project holds ${ahead} it lacks (seq ${here.state.headSeq} against ${source.view.state.headSeq}): no sync brings them into a writable deployment (a replication writes into a marked mirror only). If this project is the primary, mark ${sourceOrigin} as a mirror of it instead (\`maruhi mirror mark --server ${sourceOrigin} --source ${context.origin}\`) and sync from here; if ${sourceOrigin} is the primary, those entries were written here after the fork — export them away. --force marks anyway and abandons them`,
        ),
      );
    }
    yield* logNote(
      `this project holds ${ahead} that ${sourceOrigin} lacks (seq ${here.state.headSeq} against ${source.view.state.headSeq}): after the mark, bring them over with \`maruhi mirror sync --server ${context.origin} --mirror ${sourceOrigin}\` before promoting ${sourceOrigin} (the planned failover's last sync)`,
    );
  });
}

function headOfView(view: VerifiedProject): {
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
} {
  return { chainHeadSeq: view.state.headSeq, chainHeadHashHex: view.state.headHashHex };
}

const onChain = headOnChain;

/** How long the promotion waits for the source to answer its probe (a black-holed source must not hold a failover). */
const PROMOTE_PROBE_TIMEOUT = Duration.seconds(10);

/**
 * `maruhi mirror promote --server <mirror>`: the owner unmarks the mirror;
 * it accepts writes again. The source is probed first (its public
 * `/auth/config`): a source that still answers means two writable copies
 * after the promotion, so it is refused unless `--force` (ruling C
 * revision — a split brain is an owner's explicit decision).
 */
function mirrorPromoteCommand(flags: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly force?: boolean | undefined;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const context = yield* openSession(flags.server);
    const projectId = yield* resolveProjectId(flags.project, context.config);
    const status = yield* context.client.mirror
      .status({ params: { projectId } })
      .pipe(Effect.mapError(toCliError));
    const guard =
      status.sourceOrigin !== undefined
        ? yield* promotionGuard(
            context,
            projectId,
            status.sourceOrigin,
            status,
            flags.force === true,
          )
        : { leftBehind: null, mirrorChain: null };
    const { leftBehind, mirrorChain } = guard;
    yield* context.client.mirror
      .unmark({ params: { projectId } })
      .pipe(Effect.mapError(toCliError));
    yield* io.log(
      `Promoted project ${projectId} on ${context.origin}: it accepts writes again. Members point at it with \`maruhi config set server ${context.origin}\`. A former primary that comes back is a stale server: it can never be replicated over this chain — mark it as a mirror of this one while its chain has not advanced past the fork, otherwise export it away`,
    );
    if (leftBehind !== null) {
      yield* io.log(leftBehind);
    }
    for (const line of yield* keyFollowUps(
      context.client,
      context.origin,
      projectId,
      mirrorChain,
    )) {
      yield* io.log(line);
    }
  });
}

/**
 * The promotion's guard on what the source holds: fails with the refusal,
 * else says what stays on a frozen source and hands on the mirror's chain
 * when the guard fetched it (a frozen source behind this mirror is judged
 * on it — a strict prefix holds nothing the mirror lacks, anything else is
 * a fork; ruling C revision, round 8).
 */
function promotionGuard(
  context: SessionContext,
  projectId: string,
  sourceOrigin: string,
  status: {
    readonly head: SourceHead;
    readonly lastSync?: { readonly auditMaxSeq: number } | undefined;
  },
  forced: boolean,
): Effect.Effect<
  { readonly leftBehind: string | null; readonly mirrorChain: VerifiedProject | null },
  CliError,
  CliServices
> {
  return Effect.gen(function* () {
    const source = yield* sourceState(context.config, sourceOrigin, projectId, context.origin);
    const frozenAt =
      typeof source === "string" ? null : "frozenAt" in source ? source.frozenAt : null;
    const mirrorChain =
      frozenAt !== null && frozenAt.chainHeadSeq < status.head.chainHeadSeq
        ? yield* syncProject(context.client, projectId)
        : null;
    const refusal = promotionRefusal(
      source,
      sourceOrigin,
      status.head,
      context.origin,
      mirrorChain,
    );
    if (refusal !== null) {
      // --force promotes anyway, but says what it abandons (round 9)
      if (!forced) {
        return yield* Effect.fail(cliError(refusal));
      }
      yield* logWarning(`promoting with --force. ${refusal}`);
    }
    return {
      leftBehind: frozenAt === null ? null : rowsLeftBehind(frozenAt, sourceOrigin, status),
      mirrorChain,
    };
  });
}

/**
 * What stays on the frozen source after the promotion (ruling C revision,
 * rounds 8 and 9): its audit rows past the mirror's last replication —
 * counted only when the frozen head is the mirror's and a replication is
 * recorded (positions of one log; a re-point clears the record), else
 * said to be uncountable from here. null = nothing to say (none, or the
 * source's marks are not shown to this session).
 */
function rowsLeftBehind(
  frozenAt: SourceHead,
  sourceOrigin: string,
  mirror: {
    readonly head: SourceHead;
    readonly lastSync?: { readonly auditMaxSeq: number } | undefined;
  },
): string | null {
  if (frozenAt.auditMaxSeq === undefined) {
    return null;
  }
  const keep = `a promoted copy takes no page, so they can never be brought over — keep them with \`maruhi project export --server ${sourceOrigin}\``;
  if (mirror.lastSync === undefined || frozenAt.chainHeadHashHex !== mirror.head.chainHeadHashHex) {
    return `The audit rows the frozen source ${sourceOrigin} wrote since the last replication (the reads and leases it served) cannot be counted from here: ${keep}`;
  }
  const rows = frozenAt.auditMaxSeq - mirror.lastSync.auditMaxSeq;
  return rows > 0
    ? `${countNoun(rows, "audit row")} stay on the frozen source ${sourceOrigin} (the reads and leases it served since the last replication): ${keep}`
    : null;
}

/**
 * Why a promotion is refused for what the source holds (null = it goes
 * through): a writable source and an unread mark are split brains, a
 * frozen source whose head the mirror lacks loses its last writes (round
 * 7), a source frozen for another origin moved; `--force` skips all four.
 */
function promotionRefusal(
  source: SourceState,
  sourceOrigin: string,
  mirrorHead: { readonly chainHeadSeq: number; readonly chainHeadHashHex: string },
  thisOrigin: string,
  mirrorChain: VerifiedProject | null,
): string | null {
  if (source === "writable") {
    return `The source ${sourceOrigin} still answers and holds this project writable: promoting ${thisOrigin} now leaves two writable copies (a split brain). The planned order: mark the source as a mirror of ${thisOrigin} (\`maruhi mirror mark --server ${sourceOrigin} --source ${thisOrigin}\` — it freezes), bring its last writes over (\`maruhi mirror sync --server ${sourceOrigin} --mirror ${thisOrigin}\`), then promote; or take the source down. Pass --force to promote anyway`;
  }
  if (source === "answers") {
    return `The source ${sourceOrigin} still answers, and its mark could not be read from this machine (no session for it here, or it refused the read): promoting ${thisOrigin} now may leave two writable copies (a split brain). Log in there (\`maruhi login --server ${sourceOrigin}\`) so the promotion can read whether it is frozen, follow the planned order (mark the source as a mirror of ${thisOrigin}, one last \`maruhi mirror sync\`, then promote), or pass --force to promote anyway`;
  }
  if (source === "gone") {
    return null;
  }
  if ("frozenAt" in source) {
    return frozenRefusal(source.frozenAt, sourceOrigin, mirrorHead, thisOrigin, mirrorChain);
  }
  return source.sameKey
    ? `The source ${sourceOrigin} holds this project as a mirror of ${source.movedTo}, which publishes this server's key fingerprint. If that is this deployment under another hostname, promote it under that name (\`maruhi mirror promote --server ${source.movedTo}\` — the source is frozen for it); if it is another deployment sharing one SERVER_ENC_KEY_IKM, that is the misconfiguration to fix first (one key per deployment); or pass --force to promote anyway`
    : `The source ${sourceOrigin} holds this project as a mirror of ${source.movedTo}, not of ${thisOrigin}: the project's primary moved there, and promoting this copy would leave two writable copies (a split brain). Re-point this mirror at it (\`maruhi mirror mark --server ${thisOrigin} --source ${source.movedTo}\`) and sync from there; or pass --force to promote anyway`;
}

/**
 * Why a promotion over a frozen source is refused (null = it goes through):
 * the planned order's last sync did not happen — the source holds chain
 * entries this mirror lacks, which a promotion makes unreachable forever
 * (ruling C revision, round 7); or the source, behind the mirror (restored
 * from an older backup, then frozen), is not on the mirror's chain — a
 * fork, which no sync repairs (round 8). A source behind the mirror on its
 * chain holds nothing the mirror lacks.
 */
function frozenRefusal(
  frozenAt: SourceHead,
  sourceOrigin: string,
  mirrorHead: { readonly chainHeadSeq: number; readonly chainHeadHashHex: string },
  thisOrigin: string,
  mirrorChain: VerifiedProject | null,
): string | null {
  if (frozenAt.chainHeadHashHex === mirrorHead.chainHeadHashHex) {
    return null;
  }
  if (frozenAt.chainHeadSeq < mirrorHead.chainHeadSeq) {
    return mirrorChain !== null && onChain(frozenAt, mirrorChain)
      ? null
      : `The source ${sourceOrigin} is frozen at chain seq ${frozenAt.chainHeadSeq} (head ${frozenAt.chainHeadHashHex}), which is not an entry of this mirror's chain (seq ${mirrorHead.chainHeadSeq}, head ${mirrorHead.chainHeadHashHex}): the two copies forked, and a promotion would bury the fork. Run \`maruhi project verify\` against both and decide which chain is the project's; --force promotes this copy anyway`;
  }
  return `The source ${sourceOrigin} is frozen at chain seq ${frozenAt.chainHeadSeq} (head ${frozenAt.chainHeadHashHex}) but this mirror holds seq ${mirrorHead.chainHeadSeq} (head ${mirrorHead.chainHeadHashHex}): its last writes have not been brought over. Run \`maruhi mirror sync --server ${sourceOrigin} --mirror ${thisOrigin}\` first; or pass --force to promote without them`;
}

/** The frozen source's head as its status reports it (the audit seq to admins and owners only). */
interface SourceHead {
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
  readonly auditMaxSeq?: number | undefined;
}

/** What the source holds; `movedTo` = it is a mirror of another deployment (the primary moved there). */
type SourceState =
  | { readonly frozenAt: SourceHead }
  | "writable"
  | "answers"
  | "gone"
  | { readonly movedTo: string; readonly sameKey: boolean };

/**
 * What the source holds (ruling C revision, round 3): `frozen` = it is
 * already a mirror of **this** deployment — by server key fingerprint, so
 * a deployment under another hostname is still this one (round 5) — the
 * honest path, promoted without a probe; `movedTo` = it is a mirror of
 * another deployment (the primary moved there; promoting this copy is a
 * split brain — round 4); `writable` = its mark says it holds the project
 * as a primary; `answers` = its mark could not be read (no session for it
 * here, or a refusal) but its public `/auth/config` answers (any HTTP
 * answer counts); `gone` = nothing answers.
 */
function sourceState(
  config: MaruhiCliConfig,
  sourceOrigin: string,
  projectId: string,
  thisOrigin: string,
): Effect.Effect<SourceState, never, CliServices> {
  return Effect.gen(function* () {
    const marked = yield* openSessionWith(config, sourceOrigin, "server").pipe(
      Effect.flatMap((source) =>
        source.client.mirror.status({ params: { projectId } }).pipe(
          Effect.flatMap((status): Effect.Effect<SourceState | null, never, CliServices> => {
            if (!status.mirror) {
              return Effect.succeed("writable");
            }
            if (status.sourceOrigin === undefined) {
              return Effect.succeed(null);
            }
            const movedTo = status.sourceOrigin;
            if (movedTo === thisOrigin) {
              return Effect.succeed({ frozenAt: status.head });
            }
            // A fingerprint match never lifts the guard (it is self-reported
            // and shared by deployments cloned from one secrets set — round
            // 6); it only names the honest way out
            return Effect.map(sameDeployment(movedTo, thisOrigin), (same) => ({
              movedTo,
              sameKey: same,
            }));
          }),
        ),
      ),
      Effect.catch(() => Effect.succeed(null)),
    );
    if (marked !== null) {
      return marked;
    }
    return (yield* sourceAnswers(sourceOrigin)) ? "answers" : "gone";
  });
}

/**
 * After a promotion: the other server keys the chain grants (each with
 * the environments its grant covers — the one to revoke and rotate if that
 * deployment was compromised), and whether this deployment's own key is
 * granted (CI leases need it). From the verified chain and this server's
 * public key; never a guess at a fingerprint (ruling F revision, round 3).
 */
function keyFollowUps(
  client: MaruhiClient,
  origin: string,
  projectId: string,
  prefetched: VerifiedProject | null = null,
): Effect.Effect<readonly string[], CliError, CliServices> {
  return Effect.gen(function* () {
    const verified = prefetched ?? (yield* syncProject(client, projectId));
    const own = yield* client.auth.authConfig({}).pipe(
      Effect.map((config) => config.serverKeyFingerprintHex ?? null),
      Effect.catch(() => Effect.succeed(null)),
    );
    const lines: string[] = [];
    for (const grant of [...verified.state.serverGrants.values()].toSorted((a, b) =>
      a.serverKeyFingerprintHex < b.serverKeyFingerprintHex ? -1 : 1,
    )) {
      if (grant.serverKeyFingerprintHex === own) {
        continue;
      }
      lines.push(
        `Another server key is granted on this chain: ${grant.serverKeyFingerprintHex} (environments ${grant.scopeEnvironmentIds.map(displayText).join(", ")}). If that deployment was compromised rather than lost, revoke it (\`maruhi server revoke ${grant.serverKeyFingerprintHex}\`) and rotate those environments (\`maruhi env rotate\`) — the promotion retires nothing`,
      );
    }
    if (own !== null && !verified.state.serverGrants.has(own)) {
      lines.push(
        `This deployment's server key (${own}) is not granted on the chain: CI leases are not issued here until an owner runs \`maruhi server grant --server ${origin}\``,
      );
    }
    return lines;
  });
}

/** Whether the source deployment answers its public auth config within the probe's bound (an error of any kind = it does not). */
function sourceAnswers(sourceOrigin: string): Effect.Effect<boolean, never, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const client = yield* makeApiClient({ baseUrl: sourceOrigin, timeout: PROMOTE_PROBE_TIMEOUT });
    return yield* client.auth.authConfig({}).pipe(
      Effect.map(() => true),
      // Any HTTP answer counts, even an error; only no answer at all does not
      Effect.catch((error) => Effect.succeed(!isNoAnswer(error))),
    );
  });
}

/**
 * After `config set mirror`: a fallback that needs a login while the server
 * is down is no fallback (ruling E revision), so the member is told now when
 * no session for the mirror is in the keychain.
 */
function noteMirrorSession(raw: string): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const origin = yield* normalizeHttpOrigin(raw, "the mirror URL", {
      fix: "mirror in your config",
    });
    const keychain = yield* Keychain;
    if ((yield* keychain.get(tokenEntryName(origin))) === null) {
      yield* logWarning(
        `no session for ${origin} is stored: run \`maruhi login --server ${origin}\` now, while the server is up — a fallback read uses the mirror's own credential, and a login is not possible once the server is the reason you need the mirror. Rehearse it with \`maruhi pull --server ${origin}\``,
      );
    }
  });
}

function requireConfigKey(value: string): Effect.Effect<ConfigKey, CliError> {
  const key = asConfigKey(value);
  return key === null
    ? Effect.fail(usageError(`Unknown config key (${CONFIG_KEYS.join(" | ")})`))
    : Effect.succeed(key);
}

/** Format check of the flag taking a GitHub login (`--github` / `--from`) (unspecified = null). */
function parseGithubLoginFlag(
  flagName: string,
  value: string | undefined,
): Effect.Effect<string | null, CliError> {
  if (value === undefined) {
    return Effect.succeed(null);
  }
  return GITHUB_LOGIN.test(value)
    ? Effect.succeed(value)
    : Effect.fail(
        usageError(
          `${flagName} must be a GitHub login (1 to 39 letters, digits, or hyphens; no leading, trailing, or doubled hyphen)`,
        ),
      );
}

/** The backing-source setting (CRYPTO_SPEC §6.5 — unset = github-signing-keys). */
const loadIdentityBacking: Effect.Effect<IdentityBacking, CliError, ConfigStore> = Effect.gen(
  function* () {
    const store = yield* ConfigStore;
    return identityBackingOf(yield* store.load);
  },
);

/** `maruhi project verify`: chain verification + floor / anchor checks + state display. */
function projectVerify(
  serverFlag: string | undefined,
  projectFlag: string | undefined,
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const context = yield* openSession(serverFlag);
    const projectId = yield* resolveProjectId(projectFlag, context.config);
    const synced = yield* syncProject(context.client, projectId);
    // The chain-floor check (§6.3 rule (a)) is also part of verify
    const checked = (yield* loadCheckedFloor(
      projectId,
      synced,
      syncProject(context.client, projectId),
    )).verified;
    // The mechanical matching of the invite-link anchor (§6.3 (a) / §6.5) is also part of verify
    yield* checkInviteAnchor(projectId, checked);
    // Matching against other members' head claims (§6.3 head gossip /
    // §6.6) is also part of verify (a contradictory claim = hard evidence
    // of a split view → abort and preserve the evidence). No submission
    // happens (verify is a read command that does not require the master
    // key). The floor head's advance happens inside reconcileGossip after
    // every check passes, same as attachProject
    const verified = yield* reconcileGossip(
      projectId,
      checked,
      syncProject(context.client, projectId),
    );
    yield* io.log(`Chain verification OK (head seq=${verified.state.headSeq})`);
    yield* io.log(`head: ${verified.state.headHashHex}`);
    // The scope column (2026-09-15 ES K4 — ruling M). The same row format as `maruhi member list`
    yield* io.log(`Members (${verified.state.members.size}):`);
    for (const row of memberListRows(verified)) {
      yield* io.log(`  ${formatMemberListRow(row)}`);
    }
    for (const [environmentId, environment] of verified.state.environments) {
      yield* io.log(
        `Environment ${environmentId}: epoch=${environment.currentEpoch} (created at seq=${environment.createdAtSeq})`,
      );
    }
    // The unconverged rotation duties (§7 — chain-derived, verified
    // deletions excluded) are also part of verify (the always-on warning —
    // rotation-sweep.ts — detail display. With zero candidates it settles
    // with no communication). A deleted environment's verification failure
    // is only the caveat "could not be confirmed" — verify itself counts
    // as successful (the chain verification is done)
    const pending = yield* resolveUnconvergedMandates({ client: context.client, verified });
    if (pending === null) {
      return;
    }
    if (pending.length === 0) {
      yield* io.log("Rotation mandates: none unconverged (CRYPTO_SPEC §7)");
      return;
    }
    for (const mandate of pending) {
      yield* io.logError(
        `Unconverged rotation mandate: ${describeUnconvergedMandate(verified, mandate)} (holders of the old DEK may still be able to read current values)`,
      );
    }
  });
}

/**
 * §7: a duty environment outside the performer's scope cannot be rotated
 * — a note, not a failure (the always-on warning keeps displaying it, and
 * an env rotate by a member whose scope covers it converges it).
 */
function warnOutOfScopeMandates(outOfScope: readonly string[]): Effect.Effect<void, never, CliIo> {
  if (outOfScope.length === 0) {
    return Effect.void;
  }
  const one = outOfScope.length === 1;
  return logWarning(
    `${countNoun(outOfScope.length, "environment")} with a pending rotation mandate ${one ? "is" : "are"} outside your scope and cannot be rotated by you (${outOfScope.map(displayText).join(", ")}) — a member whose scope includes ${one ? "it" : "them"} converges ${one ? "it" : "them"} with \`maruhi env rotate <environment> --new-epoch --reason <text>\``,
  );
}

/**
 * The proposal of issuance trigger (iii) (CRYPTO_SPEC §6.3): when a pull /
 * push success detects staleness of the baseline checkpoint (over 7 days,
 * or never issued = over 7 days since genesis), emit the proposal **as a
 * 1-line Note**. A failed proposal judgment never overturns the command
 * body's success (the proposal is a SHOULD attachment). On push, the
 * anchor-update proposal is bundled into the end of the same line (DP5
 * ruling C — never split into 2 lines).
 */
function proposeCheckpointRefresh(
  context: Pick<ProjectContext, "client" | "verified" | "session">,
  options: { readonly includeAnchor: boolean },
): Effect.Effect<void, never, CliServices> {
  return Effect.gen(function* () {
    const proposal = yield* checkpointProposal({
      client: context.client,
      verified: context.verified,
      signerUserId: context.session.userId,
      nowMs: Date.now(),
    });
    if (proposal === null) {
      return;
    }
    yield* logNote(options.includeAnchor ? `${proposal}. ${ANCHOR_REFRESH_PROPOSAL}` : proposal);
  }).pipe(Effect.catch(() => Effect.void));
}

/** `maruhi env rotate <id> [--reason <text>] [--new-epoch]` (§7 / §12-4). */
function envRotateCommand(
  flags: CommonFlags & {
    readonly reason?: string | undefined;
    readonly newEpoch?: boolean | undefined;
    readonly config?: string | undefined;
  },
  environmentId: EnvironmentId,
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    // The sync config (M1) is read **before any network**: detecting a
    // broken file or another project's config is never placed behind the
    // epoch advance (failing after advancing would make the rotation look
    // failed over a cleanup omission)
    const syncConfig = flags.config === undefined ? null : yield* loadSyncConfig(flags.config);
    // Opened as an environment context to use the environment floor (§6.3)
    // (the environment is fixed by the positional). Being a convergent
    // command, the always-on warning of unconverged duties is suppressed
    // (this command's own rotation report conveys the same fact —
    // context.ts's OpenProjectOptions)
    const context = yield* openEnvironment(
      { ...flags, env: environmentId },
      { quietMandateWarning: true },
    );
    if (syncConfig !== null) {
      yield* checkRotateConfigProject(syncConfig, context.projectId);
    }
    const summary = yield* envRotateOp({
      client: context.client,
      verified: context.verified,
      environmentId,
      recipient: context.recipient,
      // Unspecified (undefined) and an empty string are passed as
      // **distinct values**: an empty `--reason` is dropped by the
      // declaration (NonBlank) with exit 2, so an undefined reaching here
      // is only a run **without `--reason` itself** (env-rotate's
      // checkReasonLength stays as a defense line)
      reason: flags.reason,
      forceNewEpoch: flags.newEpoch === true,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
      resync: context.resync,
      floor: context.floorHandle,
    });
    // "Was a new epoch requested" is fixed by the launch-time flag
    // (--reason is required only on the path that creates a new epoch —
    // env-rotate.ts's requireReason)
    const code = yield* reportRotation(
      environmentId,
      summary,
      flags.newEpoch === true || flags.reason !== undefined,
    );
    if (summary.mode === "rotated") {
      // The anchor-update proposal (CRYPTO_SPEC §6.3 (b)): an advanced
      // epoch = the committed anchor's epoch floor went stale. Emitted
      // **before** the cleanup: even when the cleanup fails on evidence,
      // the fact the epoch advanced and the anchor's staleness do not
      // change
      yield* logNote(ANCHOR_STALE_AFTER_ROTATION);
    }
    if (syncConfig !== null) {
      // Cleanup: the receipt advances to the new version only for the
      // accepted re-encryptions. A failure stays a warning and the exit
      // code remains the rotation's report (sync-rotate.ts). When the
      // receipt environment is the rotated environment itself, the same
      // floor handle is reused (never open two handles on one
      // environment)
      const receiptsFloor =
        syncConfig.receiptsEnvironment === environmentId
          ? context.floorHandle
          : yield* floorHandleFor(context, syncConfig.receiptsEnvironment);
      yield* advanceReceiptsAfterRotation({
        client: context.client,
        // The rotation advanced the chain: the cleanup starts from the
        // resynced verified view (checked to be an extension of
        // openEnvironment's view). A resync communication failure is
        // folded into a warning inside the cleanup
        verified: context.verified,
        recipient: context.recipient,
        resync: context.resync,
        config: syncConfig,
        environmentId,
        written: summary.written,
        receiptsFloor,
        writerUserId: context.session.userId,
        signingKey: context.masterKeys.sigKeyPair.privateKey,
        now: () => new Date(),
      });
    }
    return code;
  });
}

/**
 * `maruhi env diff <a> <b>`: compares the two environments' **variable
 * name sets** (values are neither fetched nor decrypted). A difference
 * leaves the exit code 0: "a difference exists" is a **report content** of
 * a successful run, not a run failure — mixing it into 1 would make it
 * indistinguishable from a verification failure / floor violation (=
 * evidence of a malicious server) or a communication failure.
 */
function envDiffCommand(
  flags: CommonFlags,
  environmentId: EnvironmentId,
  otherEnvironmentId: EnvironmentId,
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    // The prologue (chain sync + §6.3 verification) runs exactly once. The
    // master key is not required (nothing is decrypted — context.ts's
    // openMetadataProjectWith)
    const context = yield* openMetadataEnvironmentPair(flags, environmentId, otherEnvironmentId);
    const diff = yield* envDiffOp({
      client: context.client,
      verified: context.verified,
      resync: context.resync,
      first: { environmentId: context.first.environmentId, floor: context.first.floorHandle },
      second: { environmentId: context.second.environmentId, floor: context.second.floorHandle },
      // No environment-level meta floor is built (no values were read),
      // but the **chain floor's head** advances the same as pull / push.
      // Recording happens per pull (envDiffOp)
      commitHead: (verified) => commitVerifiedHead(context.projectId, verified),
    });
    yield* reportEnvironmentDiff(diff);
  });
}

/**
 * Resolving `maruhi ci run`'s required flags: never falls back to the
 * config file (a CI runner has no persistent config, and pinning the
 * genesis belongs to the workflow YAML's review). The diagnostic also
 * says "write the flag", not "set it in config".
 */
function requireCiFlag(
  value: string | undefined,
  flag: string,
  command: "ci run" | "ci sync" | "ci rotate" = "ci run",
): Effect.Effect<string, CliError> {
  if (value !== undefined) {
    return Effect.succeed(value);
  }
  // `ci sync` has no `--env` (the sync config's target decides the
  // environment), so the fix is stated per command
  const guidance = {
    "ci run": `ci run requires ${flag} (CI mode reads no config file — pass --server, --project, and --env explicitly in the workflow)`,
    "ci sync": `ci sync requires ${flag} (CI mode reads no config file except the sync config — pass --server and --project explicitly in the workflow; the environment comes from the target)`,
    "ci rotate": `ci rotate requires ${flag} (CI mode reads no config file except the rotation config — pass --server, --project, and --env explicitly in the workflow)`,
  };
  return Effect.fail(usageError(guidance[command]));
}

/** `maruhi sync init`'s required flags (a misspelling = 2). */
function requireInitFlag(value: string | undefined, flag: string): Effect.Effect<string, CliError> {
  return value === undefined
    ? Effect.fail(usageError(`sync init requires ${flag} (pass --preset, --env, and --receipts)`))
    : Effect.succeed(value);
}

/** The lease target of a CI read: the server, or the mirror on the retry. */
interface CiTarget {
  readonly origin: string;
  readonly audience: string;
}

/**
 * The CI read's fallback (PF2 — AUTH_SPEC §11-7 ruling E): when the server
 * is unreachable and `--mirror` names a replica, the lease is requested
 * there instead, with an OIDC token for the mirror's audience unless
 * --audience was given (the mirror's own grant names its audience). Never
 * on an answer of the server (a 404 or a 401 is not retried)
 */
function withCiMirrorFallback<A>(
  values: { readonly mirror?: string | undefined; readonly audience?: string | undefined },
  primary: CiTarget,
  attempt: (target: CiTarget) => Effect.Effect<A, CliError, CliServices>,
): Effect.Effect<A, CliError, CliServices> {
  return Effect.gen(function* () {
    if (values.mirror === undefined) {
      return yield* attempt(primary);
    }
    const mirror = yield* normalizeHttpOrigin(values.mirror, "the mirror URL");
    if (mirror === primary.origin) {
      return yield* Effect.fail(
        usageError("--mirror is the server URL itself (pass the mirror deployment's URL)"),
      );
    }
    return yield* attempt(primary).pipe(
      Effect.catch((error: CliError) =>
        error.unreachable === true
          ? Effect.gen(function* () {
              const io = yield* CliIo;
              yield* io.logError(
                `${error.message}. Retrying against the mirror ${mirror} (a read-only replica that may be behind the server)`,
              );
              return yield* attempt({ origin: mirror, audience: values.audience ?? mirror });
            })
          : Effect.fail(error),
      ),
    );
  });
}

/** `maruhi ci run -- <cmd>`'s body (verification lives in ci-run.ts / lease-client.ts). */
function ciRunCommand(values: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly env?: string | undefined;
  readonly audience?: string | undefined;
  readonly mirror?: string | undefined;
  readonly anchor?: string | undefined;
  readonly command: readonly string[];
}): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    // Every format check precedes network / key generation (the same discipline as the existing commands)
    const origin = yield* normalizeHttpOrigin(
      yield* requireCiFlag(values.server, "--server"),
      "the server URL",
    );
    const projectFlag = yield* requireCiFlag(values.project, "--project");
    if (!isProjectId(projectFlag)) {
      return yield* Effect.fail(
        usageError("Invalid project ID for --project (the genesis hash — 64 hex digits)"),
      );
    }
    const envFlag = yield* requireCiFlag(values.env, "--env");
    if (!isEnvironmentId(envFlag)) {
      return yield* Effect.fail(usageError(ENV_FLAG_SHAPE_MESSAGE));
    }
    // audience's default is the server's normalized origin (AUTH_SPEC §14-1's recommended value)
    return yield* withCiMirrorFallback(
      values,
      { origin, audience: values.audience ?? origin },
      (target) =>
        ciRunOp({
          origin: target.origin,
          projectId: projectFlag,
          environmentId: envFlag,
          audience: target.audience,
          anchorPath: values.anchor,
          command: values.command,
        }),
    );
  });
}

/** `maruhi ci sync <target>`'s body (the lease and the sync live in sync-ci.ts). */
function ciSyncCommand(values: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly audience?: string | undefined;
  readonly mirror?: string | undefined;
  readonly anchor?: string | undefined;
  readonly config?: string | undefined;
  readonly yes: boolean;
  readonly target: string;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    // The format checks and the config read precede network / key
    // generation (the same discipline as ci run). There is no `--env`: the
    // sync config's target decides the environment
    const origin = yield* normalizeHttpOrigin(
      yield* requireCiFlag(values.server, "--server", "ci sync"),
      "the server URL",
    );
    const projectFlag = yield* requireCiFlag(values.project, "--project", "ci sync");
    if (!isProjectId(projectFlag)) {
      return yield* Effect.fail(
        usageError("Invalid project ID for --project (the genesis hash — 64 hex digits)"),
      );
    }
    const config = yield* loadSyncConfig(values.config ?? DEFAULT_SYNC_CONFIG_PATH);
    const target = yield* requireSyncTarget(config, values.target);
    yield* checkConfigProject(config, projectFlag);
    yield* withCiMirrorFallback(values, { origin, audience: values.audience ?? origin }, (where) =>
      ciSyncOp({
        origin: where.origin,
        projectId: projectFlag,
        audience: where.audience,
        anchorPath: values.anchor,
        target,
        yes: values.yes,
      }),
    );
  });
}

/** `maruhi ci rotate <NAME>`'s body (the lease, the connector, and the sealed proposal live in ci-rotate.ts). */
/** The coordinates of `maruhi ci rotate` (every format check before the config read and the network). */
function ciRotateCoordinates(values: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly env?: string | undefined;
  readonly "expires-in"?: number | undefined;
}): Effect.Effect<
  {
    readonly origin: string;
    readonly projectId: string;
    readonly environmentId: EnvironmentId;
    readonly expiresInDays: number;
  },
  CliError
> {
  return Effect.gen(function* () {
    const origin = yield* normalizeHttpOrigin(
      yield* requireCiFlag(values.server, "--server", "ci rotate"),
      "the server URL",
    );
    const projectId = yield* requireCiFlag(values.project, "--project", "ci rotate");
    if (!isProjectId(projectId)) {
      return yield* Effect.fail(
        usageError("Invalid project ID for --project (the genesis hash — 64 hex digits)"),
      );
    }
    const environmentId = yield* requireCiFlag(values.env, "--env", "ci rotate");
    if (!isEnvironmentId(environmentId)) {
      return yield* Effect.fail(usageError(ENV_FLAG_SHAPE_MESSAGE));
    }
    const expiresInDays = values["expires-in"] ?? 7;
    if (
      !Number.isInteger(expiresInDays) ||
      expiresInDays < 1 ||
      expiresInDays > MAX_PROPOSAL_DAYS
    ) {
      return yield* Effect.fail(
        usageError(`--expires-in must be a number of days from 1 to ${MAX_PROPOSAL_DAYS}`),
      );
    }
    return { origin, projectId, environmentId, expiresInDays };
  });
}

/** `maruhi ci rotate <NAME>`'s body (the lease, the connector, and the sealed proposal live in ci-rotate.ts). */
function ciRotateCommand(values: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly env?: string | undefined;
  readonly audience?: string | undefined;
  readonly anchor?: string | undefined;
  readonly "rotate-config"?: string | undefined;
  readonly "expires-in"?: number | undefined;
  readonly name: string;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const coordinates = yield* ciRotateCoordinates(values);
    // The config is read before any network / key generation (the same
    // discipline as ci run)
    const rotateConfigPath = values["rotate-config"] ?? DEFAULT_ROTATE_CONFIG_PATH;
    const rotateConfig = yield* loadRotateConfig(rotateConfigPath);
    if (!rotateConfigNamesProject(rotateConfig, coordinates.projectId)) {
      return yield* Effect.fail(
        usageError(
          `The rotation config ${displayText(rotateConfigPath)} belongs to a different project (its \`project\` does not match --project)`,
        ),
      );
    }
    const result = yield* ciRotateOp({
      ...coordinates,
      audience: values.audience ?? coordinates.origin,
      anchorPath: values.anchor,
      name: values.name,
      config: rotateConfig,
      configPath: rotateConfigPath,
      deps: rotateDeps(yield* RotateSeams, yield* SqlRunner, (yield* ProcessRunner).captureScript),
    });
    yield* logRotationWarnings(result.warnings);
    for (const line of describeProposal(result, coordinates.environmentId)) {
      yield* io.log(line);
    }
  });
}

/**
 * Interpreting `--environments dev,prod` (mandatory on grant — the
 * minimal-disclosure default is environments are explicitly listed.
 * session-22 §2's ruling). An empty element is refused as a misspelling.
 */
function parseEnvironmentsFlag(
  value: string | undefined,
): Effect.Effect<readonly EnvironmentId[], CliError> {
  if (value === undefined) {
    return Effect.fail(
      usageError(
        "grant requires --environments (list the environments to disclose, comma-separated — e.g. --environments dev,prod)",
      ),
    );
  }
  const ids = value.split(",").map((part) => part.trim());
  if (ids.length === 0 || ids.some((id) => id.length === 0)) {
    return Effect.fail(
      usageError(
        "--environments is malformed (comma-separated environment IDs; empty items are not allowed)",
      ),
    );
  }
  const invalid = ids.filter((id) => !isEnvironmentId(id));
  if (invalid.length > 0) {
    return Effect.fail(
      usageError(
        "--environments contains malformed environment IDs (each must start with an alphanumeric character, followed by up to 63 alphanumerics, _ or -)",
      ),
    );
  }
  return Effect.succeed(ids as readonly EnvironmentId[]);
}

/** `maruhi server grant --environments <ids> [--lease-policy <file>]` (§9 / §12-6). */
/**
 * Four-eyes (K6-K): `--expires <duration>` → the proposal's expiry and
 * clock. Never read on an operation the policy doesn't target, but a
 * malformed format drops as usage (2) before any communication.
 */
function proposalInputOf(expires: string | undefined): Effect.Effect<ProposalInput, CliError> {
  const parsed = parseProposalExpiry(expires);
  if (!parsed.ok) {
    return Effect.fail(usageError(parsed.message));
  }
  const nowMs = Date.now();
  return Effect.succeed({ nowMs, expiresAtMs: nowMs + parsed.lifetimeMs });
}

/** The wording of a proposal's remaining vote count ("needs N more owner approval(s)" — ruling P8). */
function describeNeeded(view: ProposalView): string {
  if (view.needed === null) {
    return "the policy is off, so it cannot be approved (withdraw it)";
  }
  const more = view.needed + 1;
  return `needs ${countNoun(more, "more owner approval")} (${view.votes} of ${view.required} recounted so far)`;
}

/**
 * Reporting that it was proposed (or was already proposed) (K6-A — a
 * shape never mistaken for "appended"). States that nothing was applied
 * and who does what next.
 */
function reportProposed(
  io: CliIoShape,
  proposal: ProposedSummary,
): Effect.Effect<number, never, CliIo> {
  return Effect.gen(function* () {
    const view = proposal.view;
    const id = view.proposal.proposalHashHex;
    if (proposal.kind === "proposed") {
      yield* io.log(
        `Proposed ${describeInnerOperation(view.proposal.inner)} (proposal ${id.slice(0, 12)}…, seq=${view.proposal.proposalSeq}; expires ${formatUtcMinutes(view.proposal.expiresAtMs)}) — the four-eyes policy requires approval, so nothing has been applied yet`,
      );
    } else {
      yield* io.log(
        `The same operation is already proposed (proposal ${id.slice(0, 12)}…, seq=${view.proposal.proposalSeq}, by ${displayText(view.proposal.proposerUserId)}; expires ${formatUtcMinutes(view.proposal.expiresAtMs)}) — nothing new was proposed and nothing has been applied`,
      );
    }
    yield* io.log(`  proposal id: ${id}`);
    yield* io.log(
      `  ${describeNeeded(view)}. Another owner runs \`maruhi approval approve ${id.slice(0, 12)}\`; the approver whose approval completes it runs the follow-up rotation / key distribution (CRYPTO_SPEC §7). \`maruhi approval list\` shows the status`,
    );
    return 0;
  });
}

/** The deployment whose server key `server grant --key-from` grants (a mirror — AUTH_SPEC §11-7 ruling F). */
interface GrantKeySource {
  readonly origin: string;
  readonly client: MaruhiClient;
}

/**
 * The client whose `/auth/config` supplies the key (`--key-from`; null = the
 * server itself). The endpoint is unauthenticated, so a tokenless client
 * reads it; naming the server itself is the default spelled out.
 */
function grantKeySource(
  keyOrigin: string | null,
  serverOrigin: string,
): Effect.Effect<GrantKeySource | null, CliError, CliServices> {
  return Effect.gen(function* () {
    if (keyOrigin === null) {
      return null;
    }
    if (keyOrigin === serverOrigin) {
      yield* logNote("--key-from names the server itself; granting its own key");
      return null;
    }
    return { origin: keyOrigin, client: yield* makeApiClient({ baseUrl: keyOrigin }) };
  });
}

/** After a grant of another deployment's key: how the grant reaches it. */
function noteGrantKeySource(keySource: GrantKeySource | null) {
  return keySource === null
    ? Effect.void
    : logNote(
        `the grant and the wraps reach ${keySource.origin} with the next \`maruhi mirror sync\` (a mirror accepts no write of its own)`,
      );
}

function serverGrantCommand(
  flags: CommonFlags & {
    readonly environments?: string | undefined;
    readonly leasePolicyPath?: string | undefined;
    readonly expectFingerprint?: string | undefined;
    readonly expires?: string | undefined;
    readonly keyFrom?: string | undefined;
  },
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const environmentIds = yield* parseEnvironmentsFlag(flags.environments);
    const leasePolicy = yield* loadLeasePolicy(flags.leasePolicyPath);
    const expectFingerprintHex = yield* parseFingerprintFlag(
      "--expect-fingerprint",
      flags.expectFingerprint,
    );
    const proposal = yield* proposalInputOf(flags.expires);
    // The key of another deployment (a mirror — AUTH_SPEC §11-7 ruling F);
    // the URL's format check precedes any network
    const keyOrigin =
      flags.keyFrom === undefined
        ? null
        : yield* normalizeHttpOrigin(flags.keyFrom, "the --key-from URL");
    const context = yield* openProject(flags);
    const keySource = yield* grantKeySource(keyOrigin, context.origin);
    const outcome = yield* serverGrantOp({
      client: context.client,
      ...(keySource === null ? {} : { keySource: keySource.client }),
      verified: context.verified,
      environmentIds,
      leasePolicy,
      expectFingerprintHex,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
      recipient: context.recipient,
      resync: context.resync,
      proposal,
    });
    if (outcome.kind === "proposed") {
      return yield* reportProposed(io, outcome.proposal);
    }
    const summary = outcome.summary;
    const policyNote =
      summary.leasePolicyCount === 0
        ? "no lease path (lease_policy is empty)"
        : `lease_policy has ${countNoun(summary.leasePolicyCount, "element")}`;
    const keyNote = keySource === null ? "" : ` (the key of ${keySource.origin})`;
    yield* io.log(
      `Done: disclosure to server key ${summary.serverKeyFingerprintHex}${keyNote} is active (scope=${summary.scopeEnvironmentIds.join(", ")}, ${policyNote}). Backfill: ${summary.registered} newly registered, ${summary.alreadyRegistered} already registered`,
    );
    yield* noteGrantKeySource(keySource);
    // §9: always indicate that it is being disclosed (the revocation path is also guided on the spot)
    yield* logNote(
      "the epoch DEKs of environments in the disclosure scope are disclosed to the server (CRYPTO_SPEC §9). To withdraw, run `maruhi server revoke` (it forces a rotation of every environment — §7)",
    );
    return 0;
  });
}

/** `maruhi server revoke [--fingerprint <hex>]` (§7 / §9). */
function serverRevokeCommand(
  flags: CommonFlags & {
    readonly fingerprint?: string | undefined;
    readonly expires?: string | undefined;
  },
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const fingerprintHex = yield* parseFingerprintFlag("--fingerprint", flags.fingerprint);
    const proposal = yield* proposalInputOf(flags.expires);
    // A convergent command: the always-on warning of unconverged duties is suppressed (its own sweep report carries it)
    const context = yield* openProject(flags, { quietMandateWarning: true });
    // One environment's rotation (reusing envRotateOp — sweepRotateFor)
    const outcome = yield* serverRevokeOp({
      client: context.client,
      verified: context.verified,
      fingerprintHex,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
      resync: context.resync,
      rotate: sweepRotateFor(context, REVOKE_ROTATION_REASON),
      proposal,
    });
    if (outcome.kind === "proposed") {
      return yield* reportProposed(io, outcome.proposal);
    }
    const summary = outcome.summary;
    yield* reportRevokeAppend(io, summary);
    const exitCode = yield* reportSweepOutcome(summary, {
      rerunCommand: "`maruhi server revoke`",
      alreadyRotatedBasis: "the revocation",
    });
    if (exitCode === 0) {
      yield* io.log("Done: the revocation and the rotation of every environment completed");
    }
    // The needs-rotation-flag count and route (the revoke variant of AUDIT_SPEC §4.1)
    if (summary.serverKeyFingerprintHex !== null) {
      yield* reportRotationChecklist({
        context,
        target: { kind: "server", fingerprintHex: summary.serverKeyFingerprintHex },
      });
    }
    return exitCode;
  });
}

/** Reporting revoke's append result (the sweep's shared part is carried by reportSweepOutcome). */
function reportRevokeAppend(io: CliIoShape, summary: RevokeSummary): Effect.Effect<void, CliError> {
  if (summary.appended) {
    return io.log(
      `Appended revoke_server to the chain (FP=${summary.serverKeyFingerprintHex ?? ""}). Forcing a rotation of every environment (§7)`,
    );
  }
  if (summary.serverKeyFingerprintHex !== null) {
    // The target grant existed, but the CAS-conflict resync found it
    // already revoked (a concurrent revoke). The fact that someone revoked
    // the same key is operationally significant, so it is made explicit
    return io.log(
      `The targeted grant (FP=${summary.serverKeyFingerprintHex}) was already revoked by a concurrent run — skipping the append and proceeding to rotate every environment (§7)`,
    );
  }
  return io.log(
    "No active grant — resuming the post-revocation rotation of every environment from where it left off (crash recovery)",
  );
}

/** `maruhi invite create --role <r> [--env <id>]… [--github <login>]` (§15-2 issuance + §15-3 link assembly). */
function inviteCreateCommand(
  flags: Omit<CommonFlags, "env"> & {
    readonly role?: string | undefined;
    readonly env: readonly string[];
    readonly noEnvs: boolean;
    readonly github?: string | undefined;
  },
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
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
      (yield* scopeFromFlags({ env: flags.env, allEnvs: false, noEnvs: flags.noEnvs })) ??
      ALL_SCOPE;
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
            Effect.catch(() => Effect.succeed(null)),
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
}

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
function inviteAcceptCommand(flags: {
  readonly server?: string | undefined;
  readonly target: Redacted.Redacted<string>;
  readonly from?: string | undefined;
  readonly inviterFingerprint?: string | undefined;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
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
}

/** `maruhi invite list` (§6.5 independent verification of the acceptance blocks + the issuance-pin cross-check). */
function inviteListCommand(flags: CommonFlags): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const context = yield* openMetadataProject(flags);
    const store = yield* PinStore;
    const loaded = yield* store.load(context.projectId);
    const summary = yield* inviteListOp({
      client: context.client,
      verified: context.verified,
      pins: loaded.pins,
      nowMs: Date.now(),
    });
    // A signature-verification failure or a pin mismatch is not "a
    // successful read" but a detection of evidence — never 0 (a script can
    // use it as a health check)
    return summary.integrityFailures > 0 ? 1 : 0;
  });
}

/** `maruhi device revoke`'s report (the per-project revoked FPs and the sweep — K4-7 / K4-8). */
function reportDeviceRevoke(
  summary: DeviceRevokeSummary,
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    let exitCode = 0;
    for (const project of summary.projects) {
      if (project.skipped === null && (yield* reportRevokedProject(project)) !== 0) {
        exitCode = 1;
      }
    }
    return exitCode;
  });
}

/** Reporting one project's revocation result (exit code: an append failure, a sweep failure, a rotate failure = 1). */
function reportRevokedProject(
  project: ProjectRevokeOutcome,
): Effect.Effect<number, CliError, CliServices> {
  const label = displayText(project.projectId);
  return Effect.gen(function* () {
    const io = yield* CliIo;
    if (project.failed !== null) {
      yield* logWarning(`${label}: revocation failed — ${project.failed}`);
      return 1;
    }
    yield* io.log(
      `${label}: revoked ${project.revoked.length === 0 ? "nothing (already revoked)" : project.revoked.join(", ")}`,
    );
    if (project.sweepFailed !== null) {
      // The revocation is on the chain. What remains is only fulfilling the duty (the always-on warning keeps displaying it)
      yield* logWarning(
        `${label}: the rotation sweep after the revocation failed — ${project.sweepFailed}. The revocation itself is on the chain; the mandate stays listed as unconverged until \`maruhi env rotate <environment> --new-epoch --reason <text>\` is run for the affected environments`,
      );
      return 1;
    }
    if (project.sweep === null) {
      if (project.revoked.length > 0) {
        yield* logNote(
          `${label}: the rotation mandated by the revocation was not run from this device (it cannot sign here any more, or nothing is mandated). It stays listed as an unconverged mandate until another device rotates`,
        );
      }
      return 0;
    }
    return yield* reportSweepOutcome(project.sweep, {
      rerunCommand: "`maruhi env rotate <environment> --new-epoch --reason <text>`",
      alreadyRotatedBasis: "the revocation",
    });
  });
}

/**
 * Reporting the sweep result (the §7 all-environment scan) and deriving
 * the exit code (shared by server revoke / member remove / change-role).
 * `alreadyRotatedBasis` phrases "past which point an epoch was confirmed
 * rotated" (revoke = the revocation, member = the duty entry). The report
 * shape and §7's "never silently skip a failed rotate" discipline are
 * kept in one place — held twice, only one would get fixed.
 */
function reportSweepOutcome(
  sweep: SweepOutcome & {
    readonly skippedDeleted: readonly string[];
    readonly outOfScope?: readonly string[];
  },
  options: { readonly rerunCommand: string; readonly alreadyRotatedBasis: string },
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* warnOutOfScopeMandates(sweep.outOfScope ?? []);
    if (sweep.skippedDeleted.length > 0) {
      yield* io.log(
        `Skipped deleted environments (signed deletion statements verified): ${sweep.skippedDeleted.join(", ")}`,
      );
    }
    if (sweep.alreadyRotated.length > 0) {
      yield* io.log(
        `Already rotated (epoch newer than ${options.alreadyRotatedBasis}, no incomplete re-encryption confirmed): ${sweep.alreadyRotated.join(", ")}`,
      );
    }
    let exitCode = 0;
    for (const item of sweep.rotated) {
      const code = yield* reportRotation(
        item.environmentId as EnvironmentId,
        item.summary,
        item.forcedNewEpoch,
      );
      if (code !== 0) {
        exitCode = 1;
      }
    }
    for (const failure of sweep.failed) {
      // §7: never silently skip a rotate refusal of an environment
      // believed active (never make selective rotation blocking by a
      // malicious server invisible)
      yield* logWarning(
        `rotation of environment ${displayText(failure.environmentId)} failed: ${failure.message} — resolve the cause and re-run ${options.rerunCommand} to resume (if the environment was deleted, check for a verified deletion statement)`,
      );
      exitCode = 1;
    }
    if (sweep.rotated.some((item) => item.summary.mode === "rotated")) {
      // The anchor-update proposal — emitted as one line across the whole sweep
      yield* logNote(ANCHOR_STALE_AFTER_ROTATION);
    }
    return exitCode;
  });
}

/** `maruhi member add [invite-id]` (§6.5's mutual confirmation + add_member + the backfill). */
function memberAddCommand(
  flags: CommonFlags & {
    readonly invite?: string | undefined;
    readonly github?: string | undefined;
    readonly expectFingerprint?: string | undefined;
    readonly expires?: string | undefined;
  },
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
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
}

/** member add's result report and exit code (a backfill failure = a partial completion). */
function reportMemberAdd(
  io: CliIoShape,
  summary: Pick<MemberAddSummary, "registered" | "alreadyRegistered" | "repaired" | "failed"> & {
    readonly targetUserId: string;
    readonly role: Role | null;
  },
): Effect.Effect<number, CliError, CliIo> {
  return Effect.gen(function* () {
    const repaired =
      summary.repaired > 0 ? `, ${countNoun(summary.repaired, "old-key wrap")} repaired` : "";
    yield* io.log(
      `Added member ${displayText(summary.targetUserId)}${summary.role === null ? "" : ` (role=${summary.role})`}. Backfill: ${summary.registered} newly registered, ${summary.alreadyRegistered} already registered${repaired}`,
    );
    if (summary.failed.length === 0) {
      yield* io.log(
        "Done: DEK wraps for every environment in the member's scope × every epoch were distributed to the new member (CRYPTO_SPEC §7). Have the new member run `maruhi pull` and confirm they can decrypt",
      );
      return 0;
    }
    for (const failure of summary.failed) {
      yield* logWarning(
        `backfill for environment ${displayText(failure.environmentId)} failed: ${failure.message} — resolve the cause and re-run \`maruhi member add\` to resume (409 converges as already-registered)`,
      );
    }
    return 1;
  });
}

/** `maruhi member remove <user-id>` (§7 — accompanied by the forced rotation of every environment). */
function memberRemoveCommand(
  flags: CommonFlags & { readonly target: string; readonly expires?: string | undefined },
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
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
}

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
function memberChangeRoleCommand(
  flags: Omit<CommonFlags, "env"> & {
    readonly target: string;
    readonly role?: string | undefined;
    readonly env: readonly string[];
    readonly allEnvs: boolean;
    readonly noEnvs: boolean;
    readonly expires?: string | undefined;
  },
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
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
}

/** Reporting change-role's post-application stage (shared by the direct append and the approver's fulfillment [approval approve]). */
function reportRoleChangeFulfilment(
  io: CliIoShape,
  summary: RoleChangeFulfilment,
  rerunCommand: string,
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const backfillCode = yield* reportScopeBackfill(io, summary, rerunCommand);
    if (summary.sweep === null) {
      yield* io.log(
        backfillCode === 0
          ? "Done: the role / scope was changed (no rotation mandate)"
          : "The role / scope was changed, but the backfill is incomplete",
      );
      return backfillCode;
    }
    yield* reportChangeRoleMandates(io, summary);
    const sweepCode = yield* reportSweepOutcome(summary.sweep, {
      rerunCommand,
      alreadyRotatedBasis: "the mandate entry",
    });
    const exitCode = backfillCode === 0 && sweepCode === 0 ? 0 : 1;
    if (exitCode === 0) {
      yield* io.log("Done: the change and the rotation of the affected environments completed");
    }
    return exitCode;
  });
}

/**
 * change-role's input: at least one of `--role` / `--env`… / `--all-envs`
 * (an omission is kept as-is — design record K4-A). A malformed format
 * drops as usage (2) before any communication.
 */
function parseChangeRoleRequest(flags: {
  readonly role?: string | undefined;
  readonly env: readonly string[];
  readonly allEnvs: boolean;
  readonly noEnvs: boolean;
}): Effect.Effect<ChangeRoleRequest, CliError> {
  return Effect.gen(function* () {
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
  });
}

/** Reporting change-role's widening backfill (a failure = a partial completion → 1). */
function reportScopeBackfill(
  io: CliIoShape,
  summary: RoleChangeFulfilment,
  rerunCommand: string,
): Effect.Effect<number, never, CliIo> {
  return Effect.gen(function* () {
    // The note of the widenings remaining outside scope is emitted even
    // when no backfill exists within my scope (Cursor Bugbot's catch: the
    // main path is a listed admin re-running after someone else's
    // widening)
    if (summary.widenedOutOfScopeEnvironmentIds.length > 0) {
      yield* logWarning(
        `${countNoun(summary.widenedOutOfScopeEnvironmentIds.length, "environment")} widened earlier for this member (${summary.widenedOutOfScopeEnvironmentIds.map(displayText).join(", ")}) ${summary.widenedOutOfScopeEnvironmentIds.length === 1 ? "is" : "are"} outside your scope, so you cannot backfill ${summary.widenedOutOfScopeEnvironmentIds.length === 1 ? "it" : "them"} — a member whose scope includes ${summary.widenedOutOfScopeEnvironmentIds.length === 1 ? "it" : "them"} re-runs \`maruhi member change-role\` with the member's current scope to resume`,
      );
    }
    if (summary.backfill === null) {
      return 0;
    }
    yield* io.log(
      `${countNoun(summary.widenedEnvironmentIds.length, "environment")} added to the member's scope (${summary.widenedEnvironmentIds.map(displayText).join(", ")}) — backfilled every epoch's DEK to the target (AUTH_SPEC §12-6): ${summary.backfill.registered} newly registered, ${summary.backfill.alreadyRegistered} already registered`,
    );
    for (const failure of summary.backfill.failed) {
      yield* logWarning(
        `backfill for environment ${displayText(failure.environmentId)} failed: ${failure.message} — resolve the cause and re-run ${rerunCommand} to resume (409 converges as already-registered)`,
      );
    }
    return summary.backfill.failed.length === 0 ? 0 : 1;
  });
}

/** The explanation line of change-role's duties (demotion / narrowing) (the sweep report's preamble). */
function reportChangeRoleMandates(
  io: CliIoShape,
  summary: RoleChangeFulfilment,
): Effect.Effect<void, never> {
  return Effect.gen(function* () {
    if (summary.demoted) {
      yield* io.log(
        "Demotion below member forces a rotation of every environment in the target's scope (CRYPTO_SPEC §7 — epoch-anchor soundness)",
      );
    }
    if (summary.narrowedEnvironmentIds.length > 0) {
      yield* io.log(
        `Scope narrowed by ${countNoun(summary.narrowedEnvironmentIds.length, "environment")} (${summary.narrowedEnvironmentIds.map(displayText).join(", ")}) — forcing a rotation of those environments (CRYPTO_SPEC §7 — the target keeps their old DEKs)`,
      );
    }
  });
}

/**
 * `maruhi member list [--json]`: the verified chain's members (user id,
 * role, scope, key FPs). Zero values, so the agent-gate
 * (ensureValueDisplayAllowed) is not applied (design record ruling M /
 * K4-E — the same permissive side as `maruhi schema`). The master key is
 * not required either (the same keyless class as project verify).
 */
function memberListCommand(
  flags: CommonFlags & { readonly json: boolean },
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
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
}

/* -------------------------------------------------------------------------- */
/* Four-eyes (CRYPTO_SPEC §6.2 — PF1 K6): approval list / show / approve / withdraw, */
/* project policy approvals. Zero values, so the agent-gate is not applied (design record K6-E) */
/* -------------------------------------------------------------------------- */

/** The summary line of one proposal (`approval list`). */
function formatProposalRow(view: ProposalView): string {
  const p = view.proposal;
  const votes = view.required === null ? "policy off" : `${view.votes}/${view.required} approvals`;
  const flags = [
    ...(view.expired ? ["EXPIRED"] : []),
    ...(!view.target ? ["NOT-A-TARGET"] : []),
    ...(view.target && !view.expired && view.needed === 0 ? ["READY"] : []),
  ];
  return `${p.proposalHashHex.slice(0, 12)}…\tseq=${p.proposalSeq}\tby ${displayText(p.proposerUserId)}\t${describeInnerOperation(p.inner)}\t${votes}\texpires ${formatUtcMinutes(p.expiresAtMs)}${flags.length === 0 ? "" : `\t[${flags.join(", ")}]`}`;
}

/** One `--json` document (machine-readable — K6-O. Zero values). */
function approvalListJson(
  policy: Parameters<typeof describePolicy>[0],
  views: readonly ProposalView[],
): string {
  return JSON.stringify(
    {
      policy:
        policy === null
          ? null
          : { requiredApprovals: policy.requiredApprovals, ops: [...policy.ops].toSorted() },
      proposals: views.map((view) => ({
        id: view.proposal.proposalHashHex,
        seq: view.proposal.proposalSeq,
        proposerUserId: view.proposal.proposerUserId,
        proposerRoleAtProposal: view.proposal.proposerRoleAtProposal,
        inner: view.proposal.inner,
        expiresAtMs: view.proposal.expiresAtMs,
        expired: view.expired,
        target: view.target,
        required: view.required,
        votes: view.votes,
        voters: view.voters,
        needed: view.needed,
        eligibleApprovers: view.eligibleApprovers,
      })),
    },
    null,
    2,
  );
}

/**
 * The guidance for an already-satisfied pending proposal (K5-L / K6 —
 * after the `required_approvals` reduction): the next approve completes
 * it — only a not-yet-voted owner can complete it.
 */
function readyNote(view: ProposalView): string | null {
  if (!view.target || view.expired || view.needed !== 0) {
    return null;
  }
  const eligible =
    view.eligibleApprovers.length === 0
      ? "no current owner is left who has not voted — the proposal cannot be completed as is (add an owner, or withdraw it)"
      : `an owner who has not voted yet completes it: ${view.eligibleApprovers.map(displayText).join(", ")} (owners who already voted get duplicate-approval)`;
  return `${view.proposal.proposalHashHex.slice(0, 12)}… already has enough recounted approvals under the current policy — the next approve applies it; ${eligible}`;
}

/** `maruhi approval list [--json]` (the verified chain's pending — K5-M. Vote counts are re-tallied). */
function approvalListCommand(
  flags: CommonFlags & { readonly json: boolean },
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const context = yield* openMetadataProject(flags);
    const views = proposalViews(context.verified, Date.now());
    if (flags.json) {
      yield* io.log(approvalListJson(context.verified.state.approvalPolicy, views));
      return;
    }
    yield* io.log(`Four-eyes policy: ${describePolicy(context.verified.state.approvalPolicy)}`);
    yield* io.log(
      `Pending proposals (${views.length}) — verified chain head seq=${context.verified.state.headSeq}:`,
    );
    for (const view of views) {
      yield* io.log(`  ${formatProposalRow(view)}`);
    }
    for (const view of views) {
      const note = readyNote(view);
      if (note !== null) {
        yield* logNote(note);
      }
    }
  });
}

/** `maruhi approval show <id>` (the proposer, the inner op, the expiry, the voters, whether I can approve). */
function approvalShowCommand(
  flags: CommonFlags & { readonly ref: string },
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const context = yield* openMetadataProject(flags);
    const resolution = resolveProposalRef(context.verified, flags.ref);
    if (resolution.kind !== "pending") {
      return yield* Effect.fail(cliError(describeUnresolvedRef(resolution)));
    }
    const view = proposalViewOf(context.verified, resolution.proposal, Date.now());
    for (const line of proposalDetailLines(view)) {
      yield* io.log(line);
    }
    // The approver-side key-FP re-registration warning (K6-I′ — same predicate and wording as the proposer-side K6-I)
    if (view.proposal.inner.op === "add_member") {
      for (const reuse of keyReuseOf(context.verified, view.proposal.inner.payload)) {
        yield* logWarning(describeKeyReuse("the proposed member's key", reuse));
      }
    }
    // A vote's eligibility is the signing device's effective role (DK
    // K4). On a keyless run (MARUHI_TOKEN) no device is determined, so
    // only that is stated (show stays a key-free command)
    const localKeys = yield* loadMasterKeys(context.session).pipe(
      Effect.catch(() => Effect.succeed(null)),
    );
    yield* io.log(
      eligibilityLine(
        context.verified,
        context.session.userId,
        localKeys === null ? null : localKeys.fingerprintHex,
        view,
      ),
    );
    const note = readyNote(view);
    if (note !== null) {
      yield* logNote(note);
    }
  });
}

/** `approval show`'s detail lines (the proposer, the inner op, the expiry, the votes — a pure function). */
function proposalDetailLines(view: ProposalView): readonly string[] {
  const p = view.proposal;
  const lapsed = p.approvals.filter((vote) => !view.voters.includes(vote.userId));
  const proposerNote =
    p.proposerRoleAtProposal === "owner"
      ? " — counts as one approval"
      : " — does not count as an approval";
  return [
    `Proposal ${p.proposalHashHex}`,
    `  proposed at seq: ${p.proposalSeq}`,
    `  proposer:        ${displayText(p.proposerUserId)} (as ${p.proposerRoleAtProposal}${proposerNote})`,
    `  operation:       ${p.inner.op}`,
    ...describeInnerOperationLines(p.inner).map((line) => `    ${line}`),
    `  expires:         ${formatUtcMinutes(p.expiresAtMs)}${view.expired ? " (EXPIRED by this machine's clock)" : ""}`,
    `  approvals:       ${view.required === null ? "policy off" : `${view.votes} of ${view.required} required`} (recounted — signers: ${view.voters.length === 0 ? "none" : view.voters.map(displayText).join(", ")})`,
    ...(lapsed.length === 0
      ? []
      : [
          `  lapsed votes:    ${lapsed.map((vote) => displayText(vote.userId)).join(", ")} (no longer an owner with the same key — not counted; they may approve again after being re-added with a new key)`,
        ]),
    ...(view.target
      ? []
      : [
          "  status:          not a target of the current policy (approval-not-required) — withdraw it; the operation can be run directly",
        ]),
  ];
}

/** The "can you approve" line (including K5-L's guidance). */
function eligibilityLine(
  verified: Parameters<typeof voteEligibility>[0],
  userId: string,
  deviceFingerprintHex: string | null,
  view: ProposalView,
): string {
  if (deviceFingerprintHex === null) {
    return "  you:             cannot tell — no device key is loaded on this machine (approving needs the key of one of your registered devices)";
  }
  const eligibility = voteEligibility(verified, userId, deviceFingerprintHex, view);
  if (!eligibility.ok) {
    return `  you:             cannot approve — ${eligibility.message}`;
  }
  const command = `\`maruhi approval approve ${view.proposal.proposalHashHex.slice(0, 12)}\``;
  if (eligibility.completes) {
    return `  you:             can approve — your approval completes it and applies the operation (you become the fulfiller of its rotation / key distribution — CRYPTO_SPEC §7): ${command}`;
  }
  const afterMine = {
    ...view,
    votes: view.votes + 1,
    needed: view.needed === null ? null : Math.max(0, view.needed - 1),
  };
  return `  you:             can approve — after yours it still ${describeNeeded(afterMine)}: ${command}`;
}

/** Reporting the sweep part of the approver's fulfillment (remove / revoke) (preamble → sweep → the completion line). */
function reportFulfilledSweep(
  io: CliIoShape,
  input: {
    readonly intro: string;
    readonly sweep: SweepOutcome & { readonly skippedDeleted: readonly string[] };
    readonly rerunCommand: string;
    readonly alreadyRotatedBasis: string;
    readonly done: string;
  },
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    yield* io.log(input.intro);
    const code = yield* reportSweepOutcome(input.sweep, {
      rerunCommand: input.rerunCommand,
      alreadyRotatedBasis: input.alreadyRotatedBasis,
    });
    if (code === 0) {
      yield* io.log(input.done);
    }
    return code;
  });
}

/** Reporting the approver's fulfillment (approval item 22) and the exit code (per inner op kind). */
const FULFILMENT_REPORTERS: {
  readonly [K in Fulfilment["kind"]]: (
    io: CliIoShape,
    fulfilment: Extract<Fulfilment, { readonly kind: K }>,
  ) => Effect.Effect<number, CliError, CliServices>;
} = {
  none: (io) =>
    io.log("Done: the policy change was applied (no follow-up obligation)").pipe(Effect.as(0)),
  "member-rotation": (io, fulfilment) =>
    fulfilment.sweep === null
      ? io.log("Done: applied (no rotation mandate for the target)").pipe(Effect.as(0))
      : reportFulfilledSweep(io, {
          intro:
            "Forcing a rotation of every environment in the removed member's scope (CRYPTO_SPEC §7 — you completed the removal, so you fulfil its mandate)",
          sweep: fulfilment.sweep,
          rerunCommand: `\`maruhi member remove ${displayText(fulfilment.targetUserId)}\``,
          alreadyRotatedBasis: "the mandate entry",
          done: "Done: the removal and the rotation of the affected environments completed",
        }),
  "member-backfill": (io, fulfilment) =>
    reportMemberAdd(io, {
      targetUserId: fulfilment.targetUserId,
      role: null,
      ...fulfilment.backfill,
    }),
  "role-change": (io, fulfilment) =>
    reportRoleChangeFulfilment(
      io,
      fulfilment.change,
      `\`maruhi member change-role ${displayText(fulfilment.targetUserId)}\` with the member's current role and scope`,
    ),
  "server-backfill": (io, fulfilment) =>
    Effect.gen(function* () {
      yield* io.log(
        `Done: disclosure to server key ${fulfilment.serverKeyFingerprintHex} is active (scope=${fulfilment.scopeEnvironmentIds.join(", ")}). Backfill: ${fulfilment.registered} newly registered, ${fulfilment.alreadyRegistered} already registered`,
      );
      yield* logNote(
        "the epoch DEKs of environments in the disclosure scope are disclosed to the server (CRYPTO_SPEC §9). To withdraw, run `maruhi server revoke` (it forces a rotation of every environment — §7)",
      );
      return 0;
    }),
  "server-rotation": (io, fulfilment) =>
    reportFulfilledSweep(io, {
      intro: `Revoked server key ${fulfilment.serverKeyFingerprintHex}. Forcing a rotation of every environment (§7 — you completed the revocation, so you fulfil its mandate)`,
      sweep: fulfilment.sweep,
      rerunCommand: "`maruhi server revoke`",
      alreadyRotatedBasis: "the revocation",
      done: "Done: the revocation and the rotation of every environment completed",
    }),
};

function reportFulfilment(
  io: CliIoShape,
  fulfilment: Fulfilment,
): Effect.Effect<number, CliError, CliServices> {
  // An exhaustive Record narrows the argument type per kind (Extract), but the shared call site calls it with the wide type
  const report = FULFILMENT_REPORTERS[fulfilment.kind] as (
    io: CliIoShape,
    fulfilment: Fulfilment,
  ) => Effect.Effect<number, CliError, CliServices>;
  return report(io, fulfilment);
}

/** `maruhi approval approve <id>` (sign → fulfill if complete — K6-B / approval item 22). */
function approvalApproveCommand(
  flags: CommonFlags & { readonly ref: string },
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    // The completion-time sweep report carries the unconverged duties, so the always-on warning is suppressed (same as a convergent command)
    const context = yield* openProject(flags, { quietMandateWarning: true });
    const outcome = yield* approveProposalOp({
      client: context.client,
      verified: context.verified,
      ref: flags.ref,
      signerUserId: context.session.userId,
      signerFingerprintHex: context.masterKeys.fingerprintHex,
      signingKeyPair: context.masterKeys.sigKeyPair,
      recipient: context.recipient,
      resync: context.resync,
      rotateWith: (reason) => sweepRotateFor(context, reason),
      nowMs: Date.now(),
    });
    switch (outcome.kind) {
      case "recorded":
        yield* io.log(
          `Recorded your approval of ${describeInnerOperation(outcome.view.proposal.inner)} (proposal ${outcome.view.proposal.proposalHashHex.slice(0, 12)}…). It still ${describeNeeded(outcome.view)} — nothing has been applied yet`,
        );
        return 0;
      case "completed-by-other":
        yield* io.log(
          `This proposal was already completed by another owner's approval at seq=${outcome.completedAtSeq} — your approval was not needed. That owner's CLI fulfils the follow-up rotation / key distribution (CRYPTO_SPEC §7); any unconverged mandate stays visible in \`maruhi project verify\``,
        );
        return 0;
      case "withdrawn-concurrently":
        return yield* Effect.fail(
          cliError("The proposal was withdrawn concurrently — nothing to approve"),
        );
      case "applied":
        return yield* reportFulfilment(io, outcome.fulfilment);
    }
  });
}

/** `maruhi approval withdraw <id>` (the proposer or an owner — K6-L). */
function approvalWithdrawCommand(
  flags: CommonFlags & { readonly ref: string },
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const context = yield* openProject(flags);
    const summary = yield* withdrawProposalOp({
      client: context.client,
      verified: context.verified,
      ref: flags.ref,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
      resync: context.resync,
    });
    if (summary.closedByOtherOwner) {
      yield* logNote(
        `withdrawing a proposal made by ${displayText(summary.proposerUserId)} (owners may close any proposal)`,
      );
    }
    yield* io.log(
      `Withdrew proposal ${summary.proposalHashHex.slice(0, 12)}… (seq=${summary.proposalSeq}) — nothing was applied`,
    );
  });
}

/** Parsing `--ops a,b` (a closed set — a typo is a usage error. Ascending, no duplicates). */
function parsePolicyOps(
  text: string | undefined,
): Effect.Effect<readonly ApprovalTargetOp[], CliError> {
  if (text === undefined) {
    return Effect.succeed(DEFAULT_POLICY_OPS);
  }
  const ops: ApprovalTargetOp[] = [];
  for (const raw of text.split(",")) {
    const op = raw.trim();
    if (!isApprovalTargetOp(op)) {
      return Effect.fail(
        usageError(
          `--ops must list operations from ${APPROVAL_TARGET_OPS.join(" | ")} (comma-separated)`,
        ),
      );
    }
    if (!ops.includes(op)) {
      ops.push(op);
    }
  }
  return Effect.succeed(ops.toSorted());
}

/** `--required N` / `--off` → the policy request (neither = null = display only). */
function parsePolicyRequest(flags: {
  readonly required?: string | undefined;
  readonly ops?: string | undefined;
  readonly off: boolean;
}): Effect.Effect<PolicyRequest | null, CliError> {
  return Effect.gen(function* () {
    if (flags.off) {
      if (flags.required !== undefined || flags.ops !== undefined) {
        return yield* Effect.fail(usageError("--off cannot be combined with --required / --ops"));
      }
      return { kind: "off" } as const;
    }
    if (flags.required === undefined) {
      if (flags.ops !== undefined) {
        return yield* Effect.fail(usageError("--ops requires --required <n>"));
      }
      return null;
    }
    const required = Number(flags.required);
    if (!Number.isInteger(required) || required < 2 || required > 64) {
      return yield* Effect.fail(
        usageError("--required must be an integer of at least 2 (CRYPTO_SPEC §6.2)"),
      );
    }
    const ops = yield* parsePolicyOps(flags.ops);
    return { kind: "on", requiredApprovals: required, ops } as const;
  });
}

/**
 * `maruhi project policy approvals [--required N [--ops …]] [--off]`
 * (approval item 17 / K6-H): no flags = display the current policy
 * (keyless). Enable / change / off are an owner's signature. While the
 * policy is enabled, set_approval_policy itself is a four-eyes target, so
 * it becomes a proposal (CRYPTO_SPEC §6.2).
 */
function projectPolicyApprovalsCommand(
  flags: CommonFlags & {
    readonly required?: string | undefined;
    readonly ops?: string | undefined;
    readonly off: boolean;
    readonly expires?: string | undefined;
  },
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const request = yield* parsePolicyRequest(flags);
    const proposal = yield* proposalInputOf(flags.expires);
    if (request === null) {
      const context = yield* openMetadataProject(flags);
      yield* io.log(`Four-eyes policy: ${describePolicy(context.verified.state.approvalPolicy)}`);
      const owners = [...context.verified.state.members.values()].filter((m) => m.role === "owner");
      yield* io.log(
        `Owners (${owners.length}): ${owners.map((m) => displayText(m.userId)).join(", ")}`,
      );
      return 0;
    }
    const context = yield* openProject(flags);
    const outcome = yield* setApprovalPolicyOp({
      client: context.client,
      verified: context.verified,
      request,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
      resync: context.resync,
      proposal,
    });
    if (outcome.kind === "unchanged") {
      yield* io.log(
        request.kind === "off"
          ? "The four-eyes policy is already off — nothing to do"
          : "The four-eyes policy already has these settings — nothing to do",
      );
      return 0;
    }
    if (outcome.kind === "proposed") {
      const code = yield* reportProposed(io, outcome.proposal);
      yield* warnPolicyAvailability(context.verified, request);
      return code;
    }
    yield* io.log(
      request.kind === "off"
        ? `Appended set_approval_policy to the chain (seq=${outcome.headSeq}): the four-eyes policy is now off`
        : `Appended set_approval_policy to the chain (seq=${outcome.headSeq}): ${describePolicy({ requiredApprovals: request.requiredApprovals, ops: request.ops })}`,
    );
    yield* warnPolicyAvailability(context.verified, request);
    return 0;
  });
}

/**
 * The guidance of the enablement's operational prerequisites (the owner
 * selection (i) of approval item 17 — kept as guidance, never a prompt):
 * owner ≥ required + 1, and every owner's recovery registration.
 */
function warnPolicyAvailability(
  verified: Parameters<typeof proposalViews>[0],
  request: PolicyRequest,
): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    if (request.kind === "off") {
      return;
    }
    const owners = [...verified.state.members.values()].filter((m) => m.role === "owner").length;
    if (owners <= request.requiredApprovals) {
      yield* logWarning(
        `the project has ${countNoun(owners, "owner")} and the policy requires ${request.requiredApprovals} approvals: if one owner becomes unavailable (lost key, left the team), owner additions, removals and policy changes can no longer reach the quorum and the admin plane locks up (data access keeps working). Keep at least ${request.requiredApprovals + 1} owners`,
      );
    }
    yield* logNote(
      "make sure every owner has a recovery registered (`maruhi key recovery` or a guardian group) — under the four-eyes policy a lost owner key cannot be replaced without the quorum",
    );
  });
}

/**
 * The command body. Since the handler can only return `Effect<void>`
 * (`Command.runWith` discards the value), the child process's exit code is
 * carried out via `onExitCode`.
 */
/**
 * `maruhi sync`'s shared prologue: config → target → project (matching
 * the config's `project` against the flag) → the floor handles of the
 * sync-source / receipt environments. The config is read exactly once
 * here. The project prologue happens once (never compare two verified
 * views that disagree by opening two environments separately — same
 * reason as env diff).
 */
function openSyncTarget(values: {
  readonly server: string | undefined;
  readonly project: string | undefined;
  readonly config: string | undefined;
  readonly target: string;
}) {
  return Effect.gen(function* () {
    // The config is read before any network (a broken file's detection is never placed behind a round trip)
    const config = yield* loadSyncConfig(values.config ?? DEFAULT_SYNC_CONFIG_PATH);
    const target = yield* requireSyncTarget(config, values.target);
    yield* checkConfigProject(config, values.project);
    const context = yield* openProject({
      server: values.server,
      project: values.project ?? config.projectId,
    });
    const sourceFloor = yield* floorHandleFor(context, target.environment);
    const receiptsFloor = yield* floorHandleFor(context, config.receiptsEnvironment);
    // The http driver's integration-token environment. When it equals
    // the sync-source / receipt environment, **the same floor handle** is
    // used (holding two handles on one environment would leave the
    // receipt's push unaware of the floor the token's pull advanced)
    const tokenFloor =
      target.driver.kind !== "http"
        ? null
        : target.driver.token.environment === target.environment
          ? sourceFloor
          : target.driver.token.environment === config.receiptsEnvironment
            ? receiptsFloor
            : yield* floorHandleFor(context, target.driver.token.environment);
    return { config, target, context, sourceFloor, receiptsFloor, tokenFloor };
  });
}

/**
 * The verified pull every run shape shares: decrypt the environment, show
 * the pull's warnings, the presence fail-fast (design doc §1-4 — rulings CT /
 * CU: a required = true declared in the verified set fails with a typed
 * error before any child starts), the advisory type check (§14.3-7 — a
 * mismatch warns only).
 */
function pullForRun(
  context: EnvironmentContext,
): Effect.Effect<PulledVariables, CliError, CliServices> {
  return Effect.gen(function* () {
    const pulled = yield* pullVariables({
      client: context.client,
      verified: context.verified,
      environmentId: context.environmentId,
      recipient: context.recipient,
      resync: context.resync,
      floor: context.floorHandle,
    });
    yield* logWarnings(pulled.warnings);
    yield* enforceDeclaredPresence(pulled.declared);
    yield* logWarnings(typeAdvisoryWarnings(pulled.variables));
    // The point-of-use nudge (PF7a): one note when a value just pulled is
    // past the max age its schema declares (never changes the outcome)
    yield* notePastDueValues({
      client: context.client,
      projectId: context.projectId,
      environmentId: context.environmentId,
      variables: pulled.variables,
    });
    return pulled;
  });
}

/**
 * The brokered run shared by `maruhi proxy run` and by `maruhi run` when
 * the repository has a proxy config: project check → environment →
 * verified pull → presence fail-fast → type advisory → proxy-run.ts.
 */
function brokeredRun(input: {
  readonly command: readonly string[];
  readonly flags: CommonFlags;
  readonly loaded: LoadedProxyConfig;
  readonly configPath: string;
  readonly verbose: boolean;
  readonly listen?: string | undefined;
  readonly advertise?: string | undefined;
}): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const { config } = input.loaded;
    yield* checkProxyConfigProject(config, input.flags.project);
    // A config is applied only once a person accepted its content on this
    // machine **for this project** (pf4-design.md §21 R-8 / R-24 — an agent
    // cannot accept its own rules, nor point another project's accepted
    // rules at this one). Checked before any network when the project is
    // known without it, and again against the project the prologue resolved
    const accepted = (projectId: string) =>
      ensureProxyConfigAccepted({
        path: input.configPath,
        content: input.loaded.content,
        projectId,
      });
    const early =
      input.flags.project ?? config.projectId ?? (yield* (yield* ConfigStore).load).defaultProject;
    if (early !== undefined) {
      yield* accepted(early);
    }
    // The read may be retried against the configured mirror (PF2); the proxy then starts once
    const { context, pulled } = yield* withMirrorFallback(input.flags, (flags) =>
      Effect.gen(function* () {
        const opened = yield* openEnvironment({
          ...flags,
          project: flags.project ?? config.projectId,
        });
        if (opened.projectId !== early) {
          yield* accepted(opened.projectId);
        }
        // From now on plain `run` without a config is gated for this project (R-13)
        yield* markProjectBrokered({ projectId: opened.projectId, configPath: input.configPath });
        return { context: opened, pulled: yield* pullForRun(opened) };
      }),
    );
    return yield* proxyRunOp({
      command: input.command,
      config,
      configPath: input.configPath,
      environmentId: context.environmentId,
      variables: pulled.variables,
      verbose: input.verbose,
      listen: input.listen,
      advertise: input.advertise,
    });
  });
}

/** `--previous` rides only with `--finalize` and names a version (checked before any network). */
function checkPreviousFlag(values: {
  readonly previous: number | undefined;
  readonly finalize: boolean;
}): Effect.Effect<void, CliError> {
  if (values.previous === undefined) {
    return Effect.void;
  }
  if (!values.finalize) {
    return Effect.fail(usageError("--previous applies to --finalize only"));
  }
  return values.previous < 1
    ? Effect.fail(usageError("--previous must be a positive version number"))
    : Effect.void;
}

/** `maruhi var rotate <name> --finalize`: invalidates the previous credential and reports. */
function runVarFinalize(
  input: Parameters<typeof varFinalizeOp>[0],
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const result = yield* varFinalizeOp(input);
    yield* logRotationWarnings(result.warnings);
    for (const line of describeFinalization(result, input.context.environmentId)) {
      yield* io.log(line);
    }
  });
}

/** `maruhi var rotate <name>`: the rotation, its report, the checkpoint proposal, and the onPush sync. */
function runVarRotate(
  input: Parameters<typeof varRotateOp>[0],
  syncSetup: PushSyncSetup | null,
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const { context } = input;
    const syncDecision =
      syncSetup === null
        ? null
        : yield* decidePushSync(syncSetup, {
            projectId: context.projectId,
            environmentId: context.environmentId,
            name: input.name,
          });
    const result = yield* varRotateOp(input);
    yield* logRotationWarnings(result.warnings);
    for (const line of describeRotation(result, context.environmentId)) {
      yield* io.log(line);
    }
    yield* proposeCheckpointRefresh(context, { includeAnchor: true });
    if (syncSetup !== null && syncDecision !== null) {
      yield* syncAfterPush({ context, setup: syncSetup, decision: syncDecision });
    }
  });
}

function makeRootCommand(onExitCode: (code: number) => void) {
  const pull = Command.make("pull", pullConfig, (values) =>
    Effect.gen(function* () {
      const io = yield* CliIo;
      // The value-display refusal is the command entry = checked **before
      // decryption** (never decrypt the whole environment first and then
      // refuse = never build decrypted plaintext at all). The same check
      // also exists in the post-decryption showValues — that one is a
      // defense line (display.ts)
      if (values.show) {
        yield* ensureValueDisplayAllowed;
      }
      // The read (the prologue and the pull) may be retried against the
      // configured mirror when the server is unreachable (PF2)
      const { context, pulled } = yield* withMirrorFallback(values, (flags) =>
        Effect.gen(function* () {
          const opened = yield* openEnvironment(flags);
          const read: PulledVariables = yield* pullVariables({
            client: opened.client,
            verified: opened.verified,
            environmentId: opened.environmentId,
            recipient: opened.recipient,
            resync: opened.resync,
            floor: opened.floorHandle,
            // Filling the missing epochs of my other devices (DK K11-4 — pull
            // only; a registration the mirror would refuse, so not on the
            // fallback read)
            ...(flags.mirrorOf === undefined
              ? { fillOwnDeviceGaps: { signingKeyPair: opened.masterKeys.sigKeyPair } }
              : {}),
          });
          return { context: opened, pulled: read };
        }),
      );
      yield* logWarnings(pulled.warnings);
      yield* reportOwnDeviceGapFills({
        projectId: context.projectId,
        environmentId: context.environmentId,
        fills: pulled.ownDeviceGapFills,
      });
      yield* io.log(
        `Sync and verification OK: ${countNoun(pulled.variables.length, "variable")} (environment ${context.environmentId})`,
      );
      for (const variable of pulled.variables) {
        yield* io.log(formatPulledLine(variable));
      }
      // declared (valueless declarations — §4.2 layout v2) are listed as
      // metadata rows (no value or version exists. The schema's detail is
      // `maruhi schema`)
      for (const declared of pulled.declared) {
        yield* io.log(`${displayText(declared.name)}\t(declared — no value set)`);
      }
      // The point-of-use nudge (PF7a): values past their declared max age
      yield* notePastDueValues({
        client: context.client,
        projectId: context.projectId,
        environmentId: context.environmentId,
        variables: pulled.variables,
      });
      if (values.show) {
        yield* showValues(pulled.variables);
      }
      // Issuance trigger (iii) (CRYPTO_SPEC §6.3): detecting the baseline
      // checkpoint's staleness on a successful pull. Proposal only (never
      // auto-issued)
      yield* proposeCheckpointRefresh(context, { includeAnchor: false });
    }),
  ).pipe(
    Command.withDescription(
      "Verify the project and environment, decrypt the values in memory, and list the variables (names, versions, and sizes; values only with --show)",
    ),
  );

  const run = Command.make("run", runConfig, (values) =>
    Effect.gen(function* () {
      const { command: parsed, plain, ...flags } = values;
      // Drops before communication / decryption (at the command body's head)
      const command = yield* commandAfterTerminator(parsed);
      // The repository's proxy config, when present, decides what the child
      // receives (ADR-0016 decision 7 revision 2 — pf4-design.md §20): the
      // same brokering as `proxy run`. `--plain` keeps the real-value shape,
      // only for a person at a terminal. Read before any network
      const proxyConfig = yield* loadProxyConfigIfPresent(DEFAULT_PROXY_CONFIG_PATH);
      if (proxyConfig !== null && !plain) {
        onExitCode(
          yield* brokeredRun({
            command,
            flags,
            loaded: proxyConfig,
            configPath: DEFAULT_PROXY_CONFIG_PATH,
            verbose: false,
          }),
        );
        return;
      }
      if (proxyConfig !== null) {
        yield* ensurePlainRunAllowed;
        yield* logNote(
          `--plain: injecting the real values; ${DEFAULT_PROXY_CONFIG_PATH} is not applied to this run`,
        );
      } else if (plain) {
        yield* logNote(
          `--plain has no effect: no ${DEFAULT_PROXY_CONFIG_PATH} in the working directory`,
        );
      }
      // The read may be retried against the configured mirror when the
      // server is unreachable (PF2); the command then runs once
      const pulled = yield* withMirrorFallback(flags, (read) =>
        Effect.gen(function* () {
          const context = yield* openEnvironment(read);
          if (proxyConfig === null) {
            // A project brokered on this machine: the real values only to a
            // person at a terminal (deleting the config or changing directory
            // is not a way around the rules — pf4-design.md §21 R-13)
            yield* ensurePlainRunOfBrokeredProjectAllowed(context.projectId);
          }
          return yield* pullForRun(context);
        }),
      );
      // Environment-variable names go through verified statements (§4.2 /
      // §12-7). The execution-control variable-name denylist (run.ts) is a
      // defense layer applied to the verified name
      onExitCode(yield* runOp({ command, variables: pulled.variables }));
    }),
  ).pipe(
    Command.withDescription(
      `Decrypt the environment and run a command with the values injected as environment variables (memory only). When ${DEFAULT_PROXY_CONFIG_PATH} is present its brokering rules apply (as \`maruhi proxy run\`); --plain injects the real values instead, for a person at a terminal. Write the command after \`--\``,
    ),
  );

  const agentStatus = Command.make("status", agentStatusConfig, () => agentStatusOp()).pipe(
    Command.withDescription(
      "Show what the current agent session holds (entry names only, never values)",
    ),
  );

  const agent = Command.make("agent", agentConfig, (values) =>
    Effect.gen(function* () {
      // A path with neither communication nor keys, but the `--` discipline is the same as run's (a misspelling drops first)
      const command = yield* commandAfterTerminator(values.command);
      const keyTtl =
        values["key-ttl"] === undefined
          ? undefined
          : { ms: yield* parseKeyTtl(values["key-ttl"]), text: values["key-ttl"] };
      onExitCode(yield* agentOp({ command, keyTtl }));
    }),
  ).pipe(
    Command.withDescription(
      "Hold the token and this device's key in memory for the lifetime of a command, for machines without an OS keychain (ssh-agent style; nothing is written to disk). Write the command after `--`; `agent status` shows what the session holds",
    ),
    Command.withSubcommands([agentStatus]),
  );

  const push = Command.make("push", pushConfig, (values) =>
    Effect.gen(function* () {
      const io = yield* CliIo;
      // The sync config is read **before any network**: detecting a broken
      // file or an explicitly-given other project's config is never placed
      // behind the push (same as SY2 stage 2 2b's ruling B)
      const syncSetup = yield* loadPushSyncConfig({
        config: values.config,
        noSync: values["no-sync"],
      });
      const context = yield* openEnvironment(values);
      // The cleanup's contents are decided **before** the push (a
      // disagreement with the explicitly-given config's `project` is a
      // misspelling = 2, and the push is not sent)
      const syncDecision =
        syncSetup === null
          ? null
          : yield* decidePushSync(syncSetup, {
              projectId: context.projectId,
              environmentId: context.environmentId,
              name: values.name,
            });
      // stdin is the origin where plaintext enters as raw bytes. Wrapped
      // here and flows only as a Redacted from now on (unwrapped only at
      // push.ts's encryption boundary)
      const value = Redacted.make(normalizeStdinValue(yield* io.readStdin), {
        label: "variable-value",
      });
      const pushed = yield* pushVariable({
        client: context.client,
        environmentId: context.environmentId,
        recipient: context.recipient,
        name: values.name,
        value,
        verified: context.verified,
        resync: context.resync,
        // The value signature (§4.1) / the creation-time statement author
        // signature (§4.2): writer / author = my internal user_id, key =
        // the master sig key
        writerUserId: context.session.userId,
        signingKey: context.masterKeys.sigKeyPair.privateKey,
        floor: context.floorHandle,
      });
      yield* logWarnings(pushed.warnings);
      yield* io.log(
        `Pushed ${displayText(values.name)} (version=${pushed.version}, epoch=${pushed.epoch})`,
      );
      // Issuance trigger (iii) (CRYPTO_SPEC §6.3): detecting the baseline
      // checkpoint's staleness on a successful push. The anchor-update
      // proposal rides the same route (the ruling is
      // docs/notes/session-35.md)
      yield* proposeCheckpointRefresh(context, { includeAnchor: true });
      if (syncSetup !== null && syncDecision !== null) {
        // Cleanup: apply directly to targets carrying `onPush`, or launch
        // CI. A failure stays a warning and the exit code stays push's
        // (only the evidence fails — sync-push.ts)
        yield* syncAfterPush({ context, setup: syncSetup, decision: syncDecision });
      }
    }),
  ).pipe(
    Command.withDescription(
      "Encrypt a value read from stdin and push it to the environment (one trailing newline is stripped), then sync the deploy targets whose config asks for it",
    ),
  );

  const login = Command.make("login", loginConfig, (values) =>
    Effect.gen(function* () {
      // Checked **before any communication**. The bound is shared with
      // api-schema (MAX_TOKEN_NAME_LENGTH). Without it, a too-long name
      // surfaces as start's encode failure (a diagnostic confusingly close
      // to a connection failure)
      const tokenName = yield* requireTokenName(values["token-name"]);
      const expiresInDays = yield* requireTokenTtlDays(values["token-ttl-days"]);
      // --show-token prints the issued PAT's raw value to the terminal
      // (AUTH_SPEC §6's "one place of terminal display at issuance" —
      // ruling CK). The displayability is judged by the same fail-closed
      // two-layer gate as value display (ADR-0016 decision 7), **before
      // any communication**: on an environment where it is refused, a
      // completed browser approval would revoke only the old token through
      // a same-name rotation and end with no new raw value obtained (the
      // worst failure shape — just breaking the CI token to be replaced)
      if (values["show-token"]) {
        yield* ensureValueDisplayAllowed;
      }
      const store = yield* ConfigStore;
      const config = yield* store.load;
      const origin = yield* resolveServerOrigin(values.server, config);
      const minIntervalSeconds = values["poll-interval"];
      yield* loginOp({
        origin,
        tokenName,
        showToken: values["show-token"],
        // The default-name judgment uses the resolved actual name
        // (explicitly passing cli:<hostname> also counts as the default
        // name — the branch keys on the fact that a plain re-login becomes
        // a same-name rotation. Ruling CM)
        tokenNameIsDefault: tokenName === `cli:${hostname()}`,
        ...(expiresInDays === undefined ? {} : { expiresInDays }),
        ...(minIntervalSeconds === undefined ? {} : { minIntervalSeconds }),
      });
    }),
  ).pipe(
    Command.withDescription(
      "Sign in by approving a request in your browser, and store the token in the OS keychain (or in the current `maruhi agent` session)",
    ),
  );

  const logout = Command.make("logout", logoutConfig, (values) =>
    Effect.gen(function* () {
      const store = yield* ConfigStore;
      const config = yield* store.load;
      const origin = yield* resolveServerOrigin(values.server, config);
      yield* logoutOp({ origin });
    }),
  ).pipe(
    Command.withDescription(
      "Revoke this machine's token and remove it from the OS keychain (or from the current `maruhi agent` session)",
    ),
  );

  const rotationList = Command.make("list", rotationListConfig, (values) =>
    Effect.gen(function* () {
      const dueWithin = values["due-within"];
      if (
        dueWithin !== undefined &&
        (dueWithin < 0 || (!values["fail-on-due"] && !values["fail-on-pending"]))
      ) {
        return yield* Effect.fail(
          usageError(
            dueWithin < 0
              ? "--due-within must be a number of days (0 or more)"
              : "--due-within applies to --fail-on-due / --fail-on-pending only",
          ),
        );
      }
      const context = yield* openMetadataProject(values);
      onExitCode(
        yield* rotationListOp(context, {
          failOnDue: values["fail-on-due"],
          dueWithinDays: dueWithin,
          failOnFlags: values["fail-on-flags"],
          failOnPending: values["fail-on-pending"],
        }),
      );
    }),
  ).pipe(
    Command.withDescription(
      "List the currently active rotation flags and the values past their max age (--fail-on-due / --fail-on-flags make a CI cron out of it)",
    ),
  );

  const rotationDismiss = Command.make("dismiss", rotationDismissConfig, (values) =>
    Effect.gen(function* () {
      // The targets' format is checked before any network
      const environmentId = values.env;
      if (environmentId !== undefined && !isEnvironmentId(environmentId)) {
        return yield* Effect.fail(usageError(ENV_FLAG_SHAPE_MESSAGE));
      }
      const variableId = values.variable;
      if (variableId !== undefined && !isVariableId(variableId)) {
        return yield* Effect.fail(
          usageError("Invalid variableId (see `maruhi rotation list` for the current targets)"),
        );
      }
      // The request's shape (an --all / variable-id contradiction, a missing target) is settled before communication too
      const request = yield* parseDismissRequest({
        all: values.all,
        environmentId: environmentId ?? null,
        variableId: variableId ?? null,
      });
      const context = yield* openMetadataProject({
        server: values.server,
        project: values.project,
      });
      const resolved = yield* resolveDismissTargets({
        client: context.client,
        projectId: context.projectId,
        request,
      });
      onExitCode(
        yield* rotationDismissOp({
          client: context.client,
          projectId: context.projectId,
          targets: resolved.targets,
        }),
      );
    }),
  ).pipe(
    Command.withDescription(
      "Dismiss rotation flags without rotating (an explicit acceptance of risk; admin only)",
    ),
  );

  // Neither list nor dismiss requires the master key (the flags are
  // non-secret metadata, and the name resolution is only reading verified
  // statements — the same keyless class as project verify). dismiss's
  // authority (admin or above × admin scope) is enforced server-side
  const rotationProposals = Command.make(
    "proposals",
    rotationProposalsConfig,
    (values): Effect.Effect<void, CliError, CliServices> =>
      Effect.gen(function* () {
        const environmentId = values.env;
        if (environmentId !== undefined && !isEnvironmentId(environmentId)) {
          return yield* Effect.fail(usageError(ENV_FLAG_SHAPE_MESSAGE));
        }
        const context = yield* openMetadataProject(values);
        yield* rotationProposalsOp(context, { environmentId });
      }),
  ).pipe(
    Command.withDescription(
      "List the sealed proposals CI jobs minted and nobody has accepted or rejected yet (no value is opened)",
    ),
  );

  const rotationAccept = Command.make(
    "accept",
    rotationAcceptConfig,
    (values): Effect.Effect<void, CliError, CliServices> =>
      Effect.gen(function* () {
        const io = yield* CliIo;
        // The proposal decides the environment: it is looked up through a
        // keyless project context first, then the environment context (the
        // device key) is opened for its environment
        const lookup = yield* openMetadataProject(values);
        const proposal = yield* findProposal(
          yield* fetchRotationProposals(lookup.client, lookup.projectId),
          values.id,
        );
        const context = yield* openEnvironment({ ...values, env: proposal.environmentId });
        const result = yield* rotationAcceptOp({ context, proposal, yes: values.yes });
        yield* logRotationWarnings(result.warnings);
        for (const line of describeAcceptance(result, context.environmentId)) {
          yield* io.log(line);
        }
        yield* proposeCheckpointRefresh(context, { includeAnchor: true });
      }),
  ).pipe(
    Command.withDescription(
      "Open the sealed values a CI job proposed to this device and push them as new versions signed by you (the previous credential stays valid until --finalize). Never displays a value",
    ),
  );

  const rotationReject = Command.make(
    "reject",
    rotationRejectConfig,
    (values): Effect.Effect<void, CliError, CliServices> =>
      Effect.gen(function* () {
        const context = yield* openMetadataProject(values);
        const proposal = yield* findProposal(
          yield* fetchRotationProposals(context.client, context.projectId),
          values.id,
        );
        yield* rotationRejectOp({ context, proposal });
      }),
  ).pipe(
    Command.withDescription(
      "Drop a sealed proposal without pushing it (the credential the job created at the issuer is named so you can retire it)",
    ),
  );

  const rotation = Command.make("rotation").pipe(
    Command.withDescription(
      "Manage rotation flags and sealed proposals (list / dismiss / proposals / accept / reject)",
    ),
    Command.withSubcommands([
      rotationList,
      rotationDismiss,
      rotationProposals,
      rotationAccept,
      rotationReject,
    ]),
  );

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

  const keyGenerate = Command.make("generate", keyGenerateConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openSession(values.server);
      yield* keyGenerateOp({
        session: context.session,
        client: context.client,
        identityBacking: identityBackingOf(context.config),
        newIdentity: values["new-identity"],
      });
    }),
  ).pipe(
    Command.withDescription(
      "Generate this device's key and store it in the OS keychain (or in the current `maruhi agent` session); the first time, also create the reserve key and seal it with a recovery code",
    ),
  );

  const keyShow = Command.make("show", keyShowConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openSession(values.server);
      yield* keyShowOp({ session: context.session, client: context.client });
    }),
  ).pipe(
    Command.withDescription(
      "Print this device's public keys and fingerprint, and the reserve key fingerprint (never the private keys)",
    ),
  );

  const keyPublish = Command.make("publish", keyPublishConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openSession(values.server);
      yield* keyPublishOp({ session: context.session, viaGh: values.gh });
    }),
  ).pipe(
    Command.withDescription(
      "Print your signing public key as an OpenSSH line to register on GitHub as a signing key (--gh adds it through the gh CLI)",
    ),
  );

  const keyRecover = Command.make("recover", keyRecoverConfig, (values) =>
    Effect.gen(function* () {
      // A misspelling drops before the session resolution (network)
      if (values.handoff && values.passkey) {
        return yield* Effect.fail(usageError("Choose one of --handoff and --passkey"));
      }
      const context = yield* openSession(values.server);
      yield* keyRecoverOp({
        session: context.session,
        client: context.client,
        via: values.handoff ? "handoff" : values.passkey ? "passkey" : "code",
        resume: values.resume,
      });
    }),
  ).pipe(
    Command.withDescription(
      "Recover on a new machine: open the reserve key (recovery code, --passkey, or --handoff via your guardians), then register a new device key for this machine with it",
    ),
  );

  const keySealPasskey = Command.make("passkey", keySealPasskeyConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openSession(values.server);
      const reserve = yield* openLedgerReserveForChange({
        session: context.session,
        client: context.client,
        via: values.passkey ? "passkey" : "code",
        command: "maruhi key seal passkey",
      });
      yield* sealPasskeyOp({
        session: context.session,
        client: context.client,
        reserve,
        ...(values.label === undefined ? {} : { label: values.label }),
      });
    }),
  ).pipe(
    Command.withDescription(
      "Seal the reserve key to a new passkey via a page served on localhost (opens the ledger first with the recovery code or --passkey)",
    ),
  );

  const keySealList = Command.make("list", keySealListConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openSession(values.server);
      yield* listPasskeysOp({ client: context.client });
    }),
  ).pipe(Command.withDescription("List the passkeys your reserve key is sealed to"));

  const keySealRemove = Command.make("remove", keySealRemoveConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openSession(values.server);
      yield* removePasskeyOp({ client: context.client, wrapId: values["wrap-id"] });
    }),
  ).pipe(Command.withDescription("Remove a passkey wrap from the recovery ledger"));

  const keySeal = Command.make("seal").pipe(
    Command.withDescription("Seal the reserve key to a passkey (passkey / list / remove)"),
    Command.withSubcommands([keySealPasskey, keySealList, keySealRemove]),
  );

  const keyReserveRotate = Command.make("rotate", keyReserveRotateConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openSession(values.server);
      onExitCode(
        yield* keyReserveRotateOp({
          session: context.session,
          client: context.client,
          via: values.passkey ? "passkey" : "code",
        }),
      );
    }),
  ).pipe(
    Command.withDescription(
      "Replace the reserve key: create a new one, seal it with a new recovery code, register it on every project and revoke the old one",
    ),
  );

  const keyReserve = Command.make("reserve").pipe(
    Command.withDescription("Manage the reserve key (rotate)"),
    Command.withSubcommands([keyReserveRotate]),
  );

  const keyRecovery = Command.make("recovery", keyRecoveryConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openSession(values.server);
      onExitCode(
        yield* keyRecoveryOp({
          session: context.session,
          client: context.client,
          via: values.passkey ? "passkey" : "code",
          replace: values.replace,
        }),
      );
    }),
  ).pipe(
    Command.withDescription(
      "Create the reserve key and its recovery code (first time), replace a ledger key that cannot serve as your reserve key, or reissue the recovery code",
    ),
  );

  const key = Command.make("key").pipe(
    Command.withDescription(
      "Manage this device's key and your reserve key (generate / show / publish / recover / recovery / seal / reserve)",
    ),
    Command.withSubcommands([
      keyGenerate,
      keyShow,
      keyPublish,
      keyRecover,
      keyRecovery,
      keySeal,
      keyReserve,
    ]),
  );

  const guardianAdd = Command.make("add", guardianAddConfig, (values) =>
    Effect.gen(function* () {
      if (!isGuardianMode(values.mode)) {
        return yield* Effect.fail(usageError(`Specify --mode (${GUARDIAN_MODES.join(" | ")})`));
      }
      yield* guardianAddOp({
        flags: values,
        mode: values.mode,
        userIds: values["user-id"],
        openReserve: (session, client) =>
          openLedgerReserveForChange({
            session,
            client,
            via: "code",
            command: "maruhi guardian add …",
          }),
      });
    }),
  ).pipe(
    Command.withDescription(
      "Designate project members as guardians who can approve restoring your reserve key (opens the ledger with the recovery code first)",
    ),
  );

  const guardianApprove = Command.make("approve", guardianApproveConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openSession(values.server);
      yield* guardianApproveOp({
        session: context.session,
        client: context.client,
        code: values.code,
      });
    }),
  ).pipe(
    Command.withDescription(
      "Approve a reserve-key handoff request as one of the requester's guardians (the code comes from `maruhi key recover --handoff` on the requesting device)",
    ),
  );

  const guardianList = Command.make("list", guardianListConfig, (values) =>
    guardianListOp({ flags: values }),
  ).pipe(
    Command.withDescription(
      "List your guardian groups (with --project, flag guardians whose key changed)",
    ),
  );

  const guardianRemove = Command.make("remove", guardianRemoveConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openSession(values.server);
      yield* guardianRemoveOp({
        session: context.session,
        client: context.client,
        groupId: values["group-id"],
      });
    }),
  ).pipe(Command.withDescription("Remove a guardian group"));

  const guardianWards = Command.make("wards", guardianWardsConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openSession(values.server);
      yield* guardianWardsOp({ session: context.session, client: context.client });
    }),
  ).pipe(Command.withDescription("List the people who made you one of their guardians"));

  const guardian = Command.make("guardian").pipe(
    Command.withDescription(
      "Manage guardians for reserve-key recovery (add / approve / list / remove / wards)",
    ),
    Command.withSubcommands([
      guardianAdd,
      guardianApprove,
      guardianList,
      guardianRemove,
      guardianWards,
    ]),
  );

  const deviceAdd = Command.make("add", deviceAddConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openSession(values.server);
      yield* deviceAddOp({
        session: context.session,
        client: context.client,
        label: values.label ?? hostname(),
        replace: values.replace,
      });
    }),
  ).pipe(
    Command.withDescription(
      "Register this machine as a new device: generate its key, print the fingerprint to approve from a registered device, and wait for the approval",
    ),
  );

  const deviceApprove = Command.make("approve", deviceApproveConfig, (values) =>
    Effect.gen(function* () {
      const ref = yield* parseApproveRef(values.ref);
      const roleCap = yield* parseCapRole(values.cap);
      const scope =
        (yield* scopeFromFlags({
          env: values.env,
          allEnvs: values["all-envs"],
          noEnvs: values["no-envs"],
        })) ?? ALL_SCOPE;
      const context = yield* openSession(values.server);
      const outcomes = yield* deviceApproveOp({
        session: context.session,
        client: context.client,
        ref,
        cap: { roleCap, scope },
        project: values.project,
      });
      onExitCode(yield* reportApproveOutcomes(outcomes));
    }),
  ).pipe(
    Command.withDescription(
      "Approve a device-add request from this (registered) device: adds the device key to your projects' chains and backfills its DEK wraps",
    ),
  );

  const deviceList = Command.make("list", deviceListConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openSession(values.server);
      yield* deviceListOp({
        session: context.session,
        client: context.client,
        project: values.project,
      });
    }),
  ).pipe(
    Command.withDescription(
      "List your device keys: what each project's chain holds, with registry labels (server-reported) and this machine's records",
    ),
  );

  const deviceRevoke = Command.make("revoke", deviceRevokeConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openSession(values.server);
      const summary = yield* deviceRevokeOp({
        session: context.session,
        client: context.client,
        refs: values.ref,
        user: values.user,
        project: values.project,
        yes: values.yes,
        revokeToken: values["revoke-token"],
      });
      onExitCode(yield* reportDeviceRevoke(summary));
    }),
  ).pipe(
    Command.withDescription(
      "Revoke device keys (a lost or retired device) on every project and rotate the environments they could open",
    ),
  );

  const device = Command.make("device").pipe(
    Command.withDescription("Manage your device keys (add / approve / list / revoke)"),
    Command.withSubcommands([deviceAdd, deviceApprove, deviceList, deviceRevoke]),
  );

  const tokenList = Command.make("list", tokenListConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openSession(values.server);
      yield* tokenListOp({ client: context.client });
    }),
  ).pipe(Command.withDescription("List your API tokens (ids, names, scopes, expiry)"));

  const tokenRevoke = Command.make("revoke", tokenRevokeConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openSession(values.server);
      yield* tokenRevokeOp({ client: context.client, tokenId: values["token-id"] });
    }),
  ).pipe(Command.withDescription("Revoke one of your API tokens by id"));

  const token = Command.make("token").pipe(
    Command.withDescription("Manage your API tokens (list / revoke)"),
    Command.withSubcommands([tokenList, tokenRevoke]),
  );

  const projectInit = Command.make("init", projectInitConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openSession(values.server);
      const masterKeys = yield* loadMasterKeys(context.session);
      yield* projectInitOp({
        client: context.client,
        session: context.session,
        masterKeys,
        ...(values.org === undefined ? {} : { orgFlag: values.org }),
      });
    }),
  ).pipe(Command.withDescription("Create a project (signs and submits the genesis entry)"));

  const projectList = Command.make("list", projectListConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openSession(values.server);
      yield* projectListOp({ client: context.client });
    }),
  ).pipe(
    Command.withDescription("List the projects you are a member of (as reported by the server)"),
  );

  const projectExport = Command.make("export", projectExportConfig, (values) =>
    Effect.gen(function* () {
      const io = yield* CliIo;
      if (values.out === undefined) {
        return yield* Effect.fail(
          usageError("project export requires --out <file> (the snapshot file to write)"),
        );
      }
      // The same keyless prologue as verify (chain sync + the floor
      // check): the export is cross-checked against this verified view
      const context = yield* openSession(values.server);
      const projectId = yield* resolveProjectId(values.project, context.config);
      const synced = yield* syncProject(context.client, projectId);
      const verified = (yield* loadCheckedFloor(
        projectId,
        synced,
        syncProject(context.client, projectId),
      )).verified;
      const result = yield* projectExportOp({
        client: context.client,
        projectId,
        verified,
        outPath: values.out,
      });
      for (const line of describeExport(result, verified)) {
        yield* io.log(line);
      }
    }),
  ).pipe(
    Command.withDescription(
      "Export the whole project (chain, ciphertexts, wraps, statements, audit log) as a snapshot file for import into another maruhi deployment (owner only)",
    ),
  );

  const projectVerifyCommand = Command.make("verify", projectVerifyConfig, (values) =>
    projectVerify(values.server, values.project),
  ).pipe(
    Command.withDescription(
      "Verify the chain, the local floor, and the invite anchor, then print the project state",
    ),
  );

  const projectAnchor = Command.make("anchor", projectAnchorConfig, (values) =>
    Effect.gen(function* () {
      const io = yield* CliIo;
      // The prologue is the same keyless class as verify (chain sync +
      // §6.3 checks + floor + the invite anchor's mechanical matching) —
      // the anchor is built only from the verified view
      const context = yield* openMetadataProject({
        server: values.server,
        project: values.project,
      });
      // stdout is only the command's output (the anchor JSON) (decision
      // 9): a redirect can commit it into a repository as-is. The content
      // is non-secret (hashes, serials, epoch numbers only — anchor.ts)
      yield* io.log(formatRepositoryAnchor(buildRepositoryAnchor(context.verified)).trimEnd());
    }),
  ).pipe(
    Command.withDescription(
      "Print the repository anchor as JSON to stdout (commit it and pass it to `ci run --anchor`)",
    ),
  );

  const projectPolicyApprovals = Command.make("approvals", projectPolicyApprovalsConfig, (values) =>
    Effect.gen(function* () {
      onExitCode(
        yield* projectPolicyApprovalsCommand({
          server: values.server,
          project: values.project,
          required: values.required,
          ops: values.ops,
          off: values.off,
          expires: values.expires,
        }),
      );
    }),
  ).pipe(
    Command.withDescription(
      "Show or set the four-eyes approval policy (owner approvals required for sensitive operations); no flags = show",
    ),
  );

  const projectPolicy = Command.make("policy").pipe(
    Command.withDescription("Project policies (approvals)"),
    Command.withSubcommands([projectPolicyApprovals]),
  );

  const projectCheckpoint = Command.make("checkpoint", projectCheckpointConfig, (values) =>
    Effect.gen(function* () {
      const io = yield* CliIo;
      // Issuance accompanies a chain append (an Ed25519 signature), so it
      // requires the master key. Building the verified view (the verified
      // pull of every environment) is the checkpoint's material itself —
      // the value fetches are correctly recorded as var.read (an explicit
      // operation)
      const context = yield* openProject({ server: values.server, project: values.project });
      // The environment-floor handle is resolved ahead (keeps issueCheckpoint's R at CliIo)
      const floors = new Map<string, FloorHandle>();
      for (const environmentId of context.verified.state.environments.keys()) {
        floors.set(environmentId, yield* floorHandleFor(context, environmentId));
      }
      const summary = yield* issueCheckpoint({
        client: context.client,
        verified: context.verified,
        resync: context.resync,
        environmentIds: "all",
        signerUserId: context.session.userId,
        signingKeyPair: context.masterKeys.sigKeyPair,
        floorFor: (environmentId) => {
          const handle = floors.get(environmentId);
          return handle === undefined
            ? Effect.fail(
                cliError(`No floor handle for environment ${displayText(environmentId)} — re-run`),
              )
            : Effect.succeed(handle);
        },
      });
      yield* logWarnings(summary.warnings);
      yield* io.log(
        `Checkpoint accepted at chain seq ${summary.headSeq}, covering ${countNoun(summary.environmentIds.length, "environment")}${summary.attestedAuditHead ? " (audit head attested)" : ""}`,
      );
      if (summary.skippedEnvironmentIds.length > 0) {
        yield* logWarning(
          `${countNoun(summary.skippedEnvironmentIds.length, "environment")} could not be covered (${summary.skippedEnvironmentIds.map(displayText).join(", ")}). Re-run \`maruhi project checkpoint\` later to cover them`,
        );
      }
    }),
  ).pipe(
    Command.withDescription(
      "Notarize the verified data state (and, with effective admin permission, the audit head) onto the chain",
    ),
  );

  const project = Command.make("project").pipe(
    Command.withDescription(
      "Manage projects (init / list / verify / anchor / checkpoint / policy)",
    ),
    Command.withSubcommands([
      projectInit,
      projectList,
      projectVerifyCommand,
      projectAnchor,
      projectCheckpoint,
      projectExport,
      projectPolicy,
    ]),
  );

  const ciRun = Command.make("run", ciRunConfig, (values) =>
    Effect.gen(function* () {
      const { command: parsed, ...flags } = values;
      // Drops before communication / key generation (at the command body's head) (the same `--` discipline as run)
      const command = yield* commandAfterTerminator(parsed);
      onExitCode(yield* ciRunCommand({ ...flags, command }));
    }),
  ).pipe(
    Command.withDescription(
      "Lease the environment via OIDC (no sign-in, no keychain), verify it, and run a command with the values injected. Write the command after `--`",
    ),
  );

  const ciSync = Command.make("sync", ciSyncConfig, (values) => ciSyncCommand(values)).pipe(
    Command.withDescription(
      "Lease the target's environment via OIDC (no sign-in, no keychain) and write every selected variable to the deploy target through its driver. Keeps no receipt and deletes nothing; a production target needs --yes",
    ),
  );

  const ciRotate = Command.make("rotate", ciRotateConfig, (values) => ciRotateCommand(values)).pipe(
    Command.withDescription(
      "Lease the environment via OIDC, create a new credential at the issuer through the rule's connector, and store it as a sealed proposal for a member to accept (no signing key in CI). Never displays a value",
    ),
  );

  const ci = Command.make("ci").pipe(
    Command.withDescription("Commands for CI jobs (run / sync / rotate)"),
    Command.withSubcommands([ciRun, ciSync, ciRotate]),
  );

  const configGet = Command.make("get", configGetConfig, (values) =>
    Effect.gen(function* () {
      const io = yield* CliIo;
      const store = yield* ConfigStore;
      const configKey = yield* requireConfigKey(values.key);
      const config = yield* store.load;
      // stdout is only the command's output (the value): `V=$(maruhi
      // config get server)` captures nothing besides the value (decision 9)
      yield* io.log(config[configKey] ?? "");
    }),
  ).pipe(Command.withDescription("Print one non-secret setting to stdout"));

  const configSet = Command.make("set", configSetConfig, (values) =>
    Effect.gen(function* () {
      const io = yield* CliIo;
      const store = yield* ConfigStore;
      const configKey = yield* requireConfigKey(values.key);
      // A key holding a closed-set value is checked at declaration (a typo is never silently stored)
      if (configKey === "identityBacking" && asIdentityBacking(values.value) === null) {
        return yield* Effect.fail(
          usageError(`identityBacking must be one of: ${IDENTITY_BACKINGS.join(" | ")}`),
        );
      }
      // A broken config file is recreatable via set (it holds only
      // non-secrets so it may be discarded — never make it unrecoverable
      // from inside the CLI). But since it loses the existing config, it is
      // never swallowed silently — a warning is emitted. Recreatable is
      // **content corruption** only: a read failure itself (EACCES /
      // EISDIR / EIO etc.) would silently replace an existing config that
      // merely could not be read, so it fails as-is
      const config = yield* store.load.pipe(
        Effect.catch((error) =>
          error instanceof ConfigFileCorruptError
            ? Effect.gen(function* () {
                yield* logWarning(
                  `${toCliError(error).message} — discarding the existing config and recreating it with only this key`,
                );
                return {};
              })
            : Effect.fail(error),
        ),
      );
      yield* store.save({ ...config, [configKey]: values.value });
      yield* io.log(`Set ${configKey}`);
      if (configKey === "mirror") {
        yield* noteMirrorSession(values.value);
      }
    }),
  ).pipe(Command.withDescription("Set one non-secret setting"));

  const config = Command.make("config").pipe(
    Command.withDescription(
      "Manage non-secret settings (get / set). Secrets are never stored here",
    ),
    Command.withSubcommands([configGet, configSet]),
  );

  const schemaSet = Command.make("set", schemaSetConfig, (values) =>
    Effect.gen(function* () {
      const io = yield* CliIo;
      // Interpreting the column specifications precedes the network
      // (partial update §1-2 — unspecified = keep, only an explicit flag
      // returns to empty)
      const updates = yield* parseSchemaFieldUpdates(values);
      // The entropy warning (ruling CW — fail-closed) is judged before communication / signing
      yield* ensureEntropyAcknowledged({
        fields: [
          { field: "name", text: values.name },
          ...(updates.description.kind === "set"
            ? [{ field: "description" as const, text: updates.description.value }]
            : []),
        ],
        allowHighEntropy: values["allow-high-entropy"],
      });
      const context = yield* openEnvironment(values);
      const summary = yield* schemaSetOp({
        client: context.client,
        verified: context.verified,
        environmentId: context.environmentId,
        name: values.name,
        updates,
        resync: context.resync,
        floor: context.floorHandle,
        authorUserId: context.session.userId,
        signingKey: context.masterKeys.sigKeyPair.privateKey,
      });
      yield* logWarnings(summary.warnings);
      yield* io.log(schemaSetReport(values.name, summary));
    }),
  ).pipe(
    Command.withDescription(
      "Set a variable's schema fields (type / required / description / max age) as a partial update. A missing name is created as a declared variable without a value. A declaration cannot be deleted from the CLI yet; downgrade a mistaken one with --optional so `maruhi run` proceeds",
    ),
  );

  const schemaImport = Command.make("import", schemaImportConfig, (values) =>
    Effect.gen(function* () {
      // The ceremony gate (the ceremony-family deny archetype of ADR-0016
      // decision 7) is judged **before any communication or file read**:
      // the per-variable interactive approval is the ceremony's core, and
      // no bulk --yes exists. Both layers — known-agent detection and the
      // non-interactive terminal — stop here (the judgment material goes
      // through the Stdio / AgentProfileRef services)
      yield* ensureImportCeremonyAllowed;
      const { file, ...flags } = values;
      // The file is read only on the client side (a value is wrapped in
      // Redacted right after parseEnvFile reads it — env-file.ts). When
      // unreadable, only the path is reported — never the content or the
      // OS error detail
      const content = yield* Effect.tryPromise({
        try: () => readFile(file, "utf8"),
        catch: () =>
          cliError(`Could not read ${displayText(file)} (check the path and permissions)`),
      });
      const context = yield* openEnvironment(flags);
      const summary = yield* schemaImportOp({
        client: context.client,
        verified: context.verified,
        environmentId: context.environmentId,
        resync: context.resync,
        floor: context.floorHandle,
        authorUserId: context.session.userId,
        signingKey: context.masterKeys.sigKeyPair.privateKey,
        recipient: context.recipient,
        filePath: file,
        content,
      });
      if (summary.deletionOffered && !summary.deleted) {
        yield* logNote(
          `${displayText(file)} was kept. Once every variable it lists is declared, its last job is done — the signed schema (\`maruhi schema\`) becomes the source of truth`,
        );
      }
    }),
  ).pipe(
    Command.withDescription(
      "Import schema candidates from a .env or .env.example file with interactive per-variable approval (declares names without sending values; optionally pushes a value per variable)",
    ),
  );

  // export / verify-snapshot / lint share schema (display)'s
  // read-only, zero-value, keyless class (openMetadataEnvironment — works
  // under a MARUHI_TOKEN session = runnable from a user's CI). The
  // agent-gate does not apply (the permissive side — ADR-0016 decision
  // 7's scope is "value-displaying" commands only. Pinned by a test)
  const schemaExport = Command.make("export", schemaExportConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openMetadataEnvironment(values);
      yield* schemaExportOp({
        client: context.client,
        verified: context.verified,
        environmentId: context.environmentId,
        resync: context.resync,
        floor: context.floorHandle,
      });
    }),
  ).pipe(
    Command.withDescription(
      "Print the environment's schema snapshot (a JSON Schema subset) to stdout. Commit it and check it in CI with `schema verify-snapshot`; the store stays the source of truth",
    ),
  );

  const schemaVerifySnapshot = Command.make(
    "verify-snapshot",
    schemaVerifySnapshotConfig,
    (values) =>
      Effect.gen(function* () {
        const { file, ...flags } = values;
        // The file is read before any network (a wrong path drops before a
        // round trip). Only the path is reported — never the content or
        // the OS error detail (same discipline as schema import)
        const fileContent = yield* Effect.tryPromise({
          try: () => readFile(file, "utf8"),
          catch: () =>
            cliError(`Could not read ${displayText(file)} (check the path and permissions)`),
        });
        const context = yield* openMetadataEnvironment(flags);
        yield* schemaVerifySnapshotOp({
          client: context.client,
          verified: context.verified,
          environmentId: context.environmentId,
          resync: context.resync,
          floor: context.floorHandle,
          filePath: file,
          fileContent,
        });
      }),
  ).pipe(
    Command.withDescription(
      "Verify a committed schema snapshot against the store and fail on any divergence (for CI; the store is the source of truth)",
    ),
  );

  const schemaLint = Command.make("lint", schemaLintConfig, (values) =>
    Effect.gen(function* () {
      // The scan precedes the network (a wrong path / an unreadable tree drops before a round trip)
      const scan = yield* scanPaths(values.paths);
      const context = yield* openMetadataEnvironment(values);
      yield* schemaLintOp({
        client: context.client,
        verified: context.verified,
        environmentId: context.environmentId,
        resync: context.resync,
        floor: context.floorHandle,
        scan,
        ignore: values.ignore,
      });
    }),
  ).pipe(
    Command.withDescription(
      "Cross-check environment-variable references in source code against the declared schema (best-effort static scan; names only)",
    ),
  );

  // `maruhi mcp` — the value-free schema over MCP (PF5). Keyless like
  // `maruhi schema`, and the agent-gate does not apply: it is the
  // agent-facing surface by construction and serves no values
  // (pf5-design.md rulings M3 / M7)
  const mcp = Command.make("mcp", mcpConfig, mcpServeOp).pipe(
    Command.withDescription(
      "Serve the value-free schema to AI agents over the Model Context Protocol (stdio). Never serves values",
    ),
  );

  // **bare `maruhi schema` = display** (design doc §1-1 — a handler-carrying parent like audit)
  const schema = Command.make("schema", schemaShowConfig, runSchemaShow).pipe(
    Command.withDescription(
      "Show the environment's declared variable schema (names, types, required, status, descriptions; no values). Bare `maruhi schema` shows; `schema set` writes",
    ),
    Command.withSubcommands([
      schemaSet,
      schemaImport,
      schemaExport,
      schemaVerifySnapshot,
      schemaLint,
    ]),
  );

  const varRm = Command.make("rm", varRmConfig, (values) =>
    Effect.gen(function* () {
      const io = yield* CliIo;
      const context = yield* openEnvironment(values);
      const summary = yield* varRmOp({
        client: context.client,
        verified: context.verified,
        environmentId: context.environmentId,
        name: values.name,
        force: values.force,
        resync: context.resync,
        floor: context.floorHandle,
        authorUserId: context.session.userId,
        signingKey: context.masterKeys.sigKeyPair.privateKey,
      });
      yield* logWarnings(summary.warnings);
      const consequence =
        summary.previousStatus === "active"
          ? "its value (every stored version) was deleted"
          : "it had no value (declared only)";
      yield* io.log(
        `Deleted ${displayText(values.name)} (${consequence}; metaVersion=${summary.metaVersion}). Deletion is terminal — the variable cannot be restored, though the name can be reused by a new variable`,
      );
    }),
  ).pipe(
    Command.withDescription(
      "Delete a variable and all of its values permanently (asks for confirmation unless --force). Works for declared and active variables",
    ),
  );

  const varHistory = Command.make("history", varHistoryConfig, (values) =>
    Effect.gen(function* () {
      const io = yield* CliIo;
      // Metadata only (§12-7): keyless, scope-agnostic, no value is read —
      // the agent gate does not apply (zero values — the permissive side)
      const context = yield* openMetadataEnvironment(values);
      const result = yield* varHistoryOp({
        client: context.client,
        verified: context.verified,
        environmentId: context.environmentId,
        name: values.name,
        resync: context.resync,
        floor: context.floorHandle,
      });
      yield* logWarnings(result.warnings);
      if (values.json) {
        yield* io.log(varHistoryJson(result, context.environmentId));
        return;
      }
      for (const line of formatVarHistory(result, context.environmentId)) {
        yield* io.log(line);
      }
    }),
  ).pipe(
    Command.withDescription(
      "Show a variable's version history (metadata only: version, epoch, writer, time, rollbacks, rotation-flag exposure — never a value)",
    ),
  );

  const varRollback = Command.make("rollback", varRollbackConfig, (values) =>
    Effect.gen(function* () {
      const io = yield* CliIo;
      const toVersion = values.to;
      if (toVersion === undefined || toVersion < 1) {
        return yield* Effect.fail(
          usageError(
            "--to <version> is required and must be a positive version number (see `maruhi var history <name>`)",
          ),
        );
      }
      // The sync config is read before any network (same order as push)
      const syncSetup = yield* loadPushSyncConfig({
        config: values.config,
        noSync: values["no-sync"],
      });
      const context = yield* openEnvironment(values);
      const syncDecision =
        syncSetup === null
          ? null
          : yield* decidePushSync(syncSetup, {
              projectId: context.projectId,
              environmentId: context.environmentId,
              name: values.name,
            });
      const result = yield* varRollbackOp({
        client: context.client,
        verified: context.verified,
        environmentId: context.environmentId,
        recipient: context.recipient,
        name: values.name,
        toVersion,
        force: values.force,
        resync: context.resync,
        floor: context.floorHandle,
        writerUserId: context.session.userId,
        signingKey: context.masterKeys.sigKeyPair.privateKey,
      });
      yield* logWarnings(result.warnings);
      yield* io.log(
        `Rolled back ${displayText(result.name)} to the value of version ${result.toVersion} (new version=${result.pushed.version}, epoch=${result.pushed.epoch}; was version ${result.fromVersion})`,
      );
      if (result.flagsIfCurrent > 0) {
        yield* logNote(
          `The restored value was readable by the subject of ${countNoun(result.flagsIfCurrent, "rotation flag")} — see \`maruhi rotation list\``,
        );
      }
      yield* proposeCheckpointRefresh(context, { includeAnchor: true });
      if (syncSetup !== null && syncDecision !== null) {
        yield* syncAfterPush({ context, setup: syncSetup, decision: syncDecision });
      }
    }),
  ).pipe(
    Command.withDescription(
      "Restore a previous version's value as a new version (verifies the old version against the latest first; asks for confirmation unless --force). Never displays the value",
    ),
  );

  const varRotate = Command.make("rotate", varRotateConfig, (values) =>
    Effect.gen(function* () {
      yield* checkPreviousFlag(values);
      // Both configs are read before any network: a broken or absent rotation
      // config is a usage problem, not something to find after a pull
      const rotateConfigPath = values["rotate-config"] ?? DEFAULT_ROTATE_CONFIG_PATH;
      const rotateConfig = yield* loadRotateConfig(rotateConfigPath);
      const syncSetup = values.finalize
        ? null
        : yield* loadPushSyncConfig({ config: values.config, noSync: values["no-sync"] });
      const context = yield* openEnvironment(values);
      if (!rotateConfigNamesProject(rotateConfig, context.projectId)) {
        return yield* Effect.fail(
          usageError(
            `The rotation config ${displayText(rotateConfigPath)} belongs to a different project (its \`project\` does not match)`,
          ),
        );
      }
      const shared = {
        context,
        config: rotateConfig,
        configPath: rotateConfigPath,
        name: values.name,
        yes: values.yes,
        deps: rotateDeps(
          yield* RotateSeams,
          yield* SqlRunner,
          (yield* ProcessRunner).captureScript,
        ),
      };
      if (values.finalize) {
        return yield* runVarFinalize({ ...shared, previousVersion: values.previous ?? null });
      }
      yield* runVarRotate(shared, syncSetup);
    }),
  ).pipe(
    Command.withDescription(
      "Create a new credential at the issuer through the rule's connector and push it as a new version; the previous credential stays valid until --finalize. Never displays a value",
    ),
  );

  const varGroup = Command.make("var").pipe(
    Command.withDescription(
      "Manage variables (rm, history, rollback, rotate). push / pull / run operate on values directly",
    ),
    Command.withSubcommands([varRm, varHistory, varRollback, varRotate]),
  );

  const envCreate = Command.make("create", envCreateConfig, (values) =>
    Effect.gen(function* () {
      // The format is an additional check after the declaration (NonBlank). Seen before the network
      const environmentId = yield* requireEnvironmentId(
        values["environment-id"],
        "`maruhi env create dev`",
      );
      yield* envCreateCommand(values, environmentId);
    }),
  ).pipe(Command.withDescription("Create an environment"));

  const envRotate = Command.make("rotate", envRotateConfig, (values) =>
    Effect.gen(function* () {
      const environmentId = yield* requireEnvironmentId(
        values["environment-id"],
        "`maruhi env rotate dev`",
      );
      const { reason, "new-epoch": newEpoch, config: syncConfig, ...flags } = values;
      onExitCode(
        yield* envRotateCommand({ ...flags, reason, newEpoch, config: syncConfig }, environmentId),
      );
    }),
  ).pipe(
    Command.withDescription(
      "Rotate the environment's epoch DEK, or resume an incomplete re-encryption",
    ),
  );

  const envDiff = Command.make("diff", envDiffConfig, (values) =>
    Effect.gen(function* () {
      const environmentId = yield* requireEnvironmentId(
        values["environment-id"],
        "`maruhi env diff dev prod`",
      );
      const otherEnvironmentId = yield* requireEnvironmentId(
        values["other-environment-id"],
        "`maruhi env diff dev prod`",
      );
      if (otherEnvironmentId === environmentId) {
        // Comparing an environment with itself is always empty = the
        // request itself is a misspelling. The given values are not shown
        // (a positional could carry a value)
        return yield* Effect.fail(
          usageError(
            "The same environment ID was written twice. Specify two different environments to compare",
          ),
        );
      }
      yield* envDiffCommand(values, environmentId, otherEnvironmentId);
    }),
  ).pipe(
    Command.withDescription(
      "Compare the variable-name sets of two environments (names only; no values)",
    ),
  );

  // The nested subcommands remove the need to hand-write the refusal of
  // "an option that does not apply to that operation"
  const env = Command.make("env").pipe(
    Command.withDescription("Manage environments (create / rotate / diff)"),
    Command.withSubcommands([envCreate, envRotate, envDiff]),
  );

  const serverGrant = Command.make("grant", serverGrantConfig, (values) =>
    Effect.gen(function* () {
      onExitCode(
        yield* serverGrantCommand({
          server: values.server,
          project: values.project,
          environments: values.environments,
          leasePolicyPath: values["lease-policy"],
          expectFingerprint: values["expect-fingerprint"],
          expires: values.expires,
          keyFrom: values["key-from"],
        }),
      );
    }),
  ).pipe(
    Command.withDescription(
      "Disclose the epoch DEKs of selected environments to the server (selective disclosure)",
    ),
  );

  const serverRevoke = Command.make("revoke", serverRevokeConfig, (values) =>
    Effect.gen(function* () {
      onExitCode(
        yield* serverRevokeCommand({
          server: values.server,
          project: values.project,
          fingerprint: values.fingerprint,
          expires: values.expires,
        }),
      );
    }),
  ).pipe(Command.withDescription("Revoke a server disclosure and force-rotate every environment"));

  const server = Command.make("server").pipe(
    Command.withDescription("Manage selective disclosure to the server (grant / revoke)"),
    Command.withSubcommands([serverGrant, serverRevoke]),
  );

  const mirrorSync = Command.make("sync", mirrorSyncConfig, (values) =>
    mirrorSyncCommand(values),
  ).pipe(
    Command.withDescription(
      "Replicate the project from the server to the mirror (the export's pages uploaded in order; the mirror accepts only a replica that extends what it holds). From a cron: MARUHI_TOKEN / MARUHI_TOKEN_ORIGIN for the server, MARUHI_MIRROR_TOKEN for the mirror",
    ),
  );

  const mirrorStatus = Command.make("status", mirrorStatusConfig, (values) =>
    mirrorStatusCommand(values),
  ).pipe(
    Command.withDescription(
      "Show the server's verified chain head and the mirror's side by side, with the last replication",
    ),
  );

  const mirrorMark = Command.make("mark", mirrorMarkConfig, (values) =>
    mirrorMarkCommand(values),
  ).pipe(
    Command.withDescription(
      "Mark the project on this server (--server names the mirror deployment) as a read-only mirror of --source; writes are refused there from then on (owner only)",
    ),
  );

  const mirrorPromote = Command.make("promote", mirrorPromoteConfig, (values) =>
    mirrorPromoteCommand(values),
  ).pipe(
    Command.withDescription(
      "Remove the mirror mark on this server (--server names the mirror deployment): the project accepts writes again and becomes the primary (owner only)",
    ),
  );

  const mirror = Command.make("mirror").pipe(
    Command.withDescription(
      "Manage a read replica of the project in another deployment (sync / status / mark / promote)",
    ),
    Command.withSubcommands([mirrorSync, mirrorStatus, mirrorMark, mirrorPromote]),
  );

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

  const inviteList = Command.make("list", inviteListConfig, (values) =>
    Effect.gen(function* () {
      onExitCode(yield* inviteListCommand(values));
    }),
  ).pipe(
    Command.withDescription(
      "List invites, independently verifying acceptance blocks and issuance pins",
    ),
  );

  const inviteRevoke = Command.make("revoke", inviteRevokeConfig, (values) =>
    Effect.gen(function* () {
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

  const memberAdd = Command.make("add", memberAddConfig, (values) =>
    Effect.gen(function* () {
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

  const memberRemove = Command.make("remove", memberRemoveConfig, (values) =>
    Effect.gen(function* () {
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

  const memberChangeRole = Command.make("change-role", memberChangeRoleConfig, (values) =>
    Effect.gen(function* () {
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

  const approvalList = Command.make("list", approvalListConfig, (values) =>
    approvalListCommand({ server: values.server, project: values.project, json: values.json }),
  ).pipe(
    Command.withDescription(
      "List the pending four-eyes proposals (votes recounted under the current policy)",
    ),
  );

  const approvalShow = Command.make("show", approvalShowConfig, (values) =>
    approvalShowCommand({
      server: values.server,
      project: values.project,
      ref: values["proposal-id"],
    }),
  ).pipe(
    Command.withDescription(
      "Show a pending proposal (proposer, operation, expiry, voters, whether you can approve it)",
    ),
  );

  const approvalApprove = Command.make("approve", approvalApproveConfig, (values) =>
    Effect.gen(function* () {
      onExitCode(
        yield* approvalApproveCommand({
          server: values.server,
          project: values.project,
          ref: values["proposal-id"],
        }),
      );
    }),
  ).pipe(
    Command.withDescription(
      "Approve a pending proposal as an owner; the approval that reaches the quorum applies it and runs the follow-up rotation / key distribution",
    ),
  );

  const approvalWithdraw = Command.make("withdraw", approvalWithdrawConfig, (values) =>
    approvalWithdrawCommand({
      server: values.server,
      project: values.project,
      ref: values["proposal-id"],
    }),
  ).pipe(Command.withDescription("Withdraw a pending proposal (as its proposer or an owner)"));

  const approval = Command.make("approval").pipe(
    Command.withDescription("Four-eyes proposals (list / show / approve / withdraw)"),
    Command.withSubcommands([approvalList, approvalShow, approvalApprove, approvalWithdraw]),
  );

  const syncPlan = Command.make("plan", syncPlanConfig, (values) =>
    Effect.gen(function* () {
      const opened = yield* openSyncTarget(values);
      yield* syncPlanOp({
        client: opened.context.client,
        verified: opened.context.verified,
        recipient: opened.context.recipient,
        resync: opened.context.resync,
        target: opened.target,
        sourceFloor: opened.sourceFloor,
        receiptsEnvironment: opened.config.receiptsEnvironment as EnvironmentId,
        receiptsFloor: opened.receiptsFloor,
      });
    }),
  ).pipe(
    Command.withDescription(
      "Show which variables an apply would write to or delete from a deploy target, by name and version (the values are not decrypted, and nothing is read back from the target)",
    ),
  );

  const syncApply = Command.make("apply", syncApplyConfig, (values) =>
    Effect.gen(function* () {
      const opened = yield* openSyncTarget(values);
      yield* syncApplyOp({
        client: opened.context.client,
        verified: opened.context.verified,
        recipient: opened.context.recipient,
        resync: opened.context.resync,
        target: opened.target,
        sourceFloor: opened.sourceFloor,
        receiptsEnvironment: opened.config.receiptsEnvironment as EnvironmentId,
        receiptsFloor: opened.receiptsFloor,
        // The receipt's signature (§4.1): writer = my internal user_id, key = the master sig key
        writerUserId: opened.context.session.userId,
        signingKey: opened.context.masterKeys.sigKeyPair.privateKey,
        yes: values.yes,
        now: () => new Date(),
        tokenFloor: opened.tokenFloor,
      });
    }),
  ).pipe(
    Command.withDescription(
      "Decrypt the target's variables in memory and write the changed ones to the deploy target through its driver (the installed vendor CLI on stdin, or the vendor API with a token stored in maruhi), then record what was delivered in the receipt. A production target needs --yes",
    ),
  );

  const syncInit = Command.make("init", syncInitConfig, (values) =>
    Effect.gen(function* () {
      const preset = yield* requireInitFlag(values.preset, "--preset");
      const environment = yield* requireInitFlag(values.env, "--env");
      const receipts = yield* requireInitFlag(values.receipts, "--receipts");
      yield* syncInitOp({
        target: values.target,
        preset,
        driver: values.driver,
        environment,
        receipts,
        project: values.project,
        variables: values.variables,
        exclude: values.exclude,
        production: values.production,
        cwd: values.cwd,
        command: values.command,
        tokenEnvironment: values["token-env"],
        tokenName: values["token-name"],
        onPush: values["on-push"],
        workflow: values.workflow,
        options: values.option,
      });
    }),
  ).pipe(
    Command.withDescription(
      "Print a sync config for one deploy target as JSON to stdout (commit it as maruhi.sync.json). Reads nothing and contacts no server",
    ),
  );

  // `maruhi proxy run` (PF4 — pf4-design.md). The same prologue as run
  // (config → environment → verified pull → presence fail-fast → type
  // advisory); what differs is what the child receives (proxy-run.ts)
  const proxyRun = Command.make("run", proxyRunConfig, (values) =>
    Effect.gen(function* () {
      const { command: parsed, config: configFlag, verbose, listen, advertise, ...flags } = values;
      // Drops before communication / decryption (at the command body's head)
      const command = yield* commandAfterTerminator(parsed);
      // The config is read before any network (a broken file is reported first)
      const configPath = configFlag ?? DEFAULT_PROXY_CONFIG_PATH;
      const proxyConfig = yield* loadProxyConfig(configPath);
      onExitCode(
        yield* brokeredRun({
          command,
          flags,
          loaded: proxyConfig,
          configPath,
          verbose,
          listen,
          advertise,
        }),
      );
    }),
  ).pipe(
    Command.withDescription(
      "Run a command behind a local credential-brokering proxy: brokered variables arrive as placeholders and the real values are substituted only in requests to the hosts the proxy config allows. Write the command after `--`",
    ),
  );

  // `maruhi proxy accept` (pf4-design.md §21 R-8 / R-14): a person at a
  // terminal records the config's content as accepted on this machine —
  // the explicit act the brokering rules need before they apply (the
  // direnv model). Reads the file, contacts no server
  const proxyAccept = Command.make("accept", proxyAcceptConfig, (values) =>
    Effect.gen(function* () {
      const configPath = values.config ?? DEFAULT_PROXY_CONFIG_PATH;
      const loaded = yield* loadProxyConfig(configPath);
      // The project the rules are for: the flag, the config's `project`, or
      // the default project — resolved without any network (the mark it
      // arms is per project, R-18)
      yield* checkProxyConfigProject(loaded.config, values.project);
      const projectId =
        values.project ??
        loaded.config.projectId ??
        (yield* (yield* ConfigStore).load).defaultProject;
      if (projectId === undefined) {
        return yield* Effect.fail(
          usageError(
            "Cannot tell which project the proxy config is for: pass --project <id>, set `project` in the config, or set a default project (`maruhi config set defaultProject <id>`)",
          ),
        );
      }
      if (!isProjectId(projectId)) {
        return yield* Effect.fail(usageError("Invalid project ID (64 hex digits)"));
      }
      const outcome = yield* acceptProxyConfig({
        path: configPath,
        content: loaded.content,
        projectId,
      });
      yield* logNote(
        outcome === "unchanged"
          ? `${configPath} is already accepted on this machine with this content for this project; nothing changed`
          : `${configPath} accepted on this machine for project ${projectId} (${outcome === "changed" ? "replaces the content accepted before" : outcome === "project added" ? "the same content was already accepted for another project" : "first use"}): ${describeProxyConfig(loaded.config)}. A change to the file will need \`maruhi proxy accept\` again`,
      );
    }),
  ).pipe(
    Command.withDescription(
      "Accept the proxy config on this machine so its rules apply to `maruhi run` and `maruhi proxy run` (a person at a terminal; a new or changed file is refused until accepted). Reads the file and contacts no server",
    ),
  );

  const proxy = Command.make("proxy").pipe(
    Command.withDescription(
      "Credential brokering for AI agents and other programs: run a command that never holds the real values (run), after a person accepted the repository's proxy config on this machine (accept)",
    ),
    Command.withSubcommands([proxyRun, proxyAccept]),
  );

  const sync = Command.make("sync").pipe(
    Command.withDescription(
      "Copy variables to deploy targets (init / plan / apply) through the installed vendor CLI or the vendor API. Targets are declared in the sync config committed in the repository",
    ),
    Command.withSubcommands([syncInit, syncPlan, syncApply]),
  );

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

/* -------------------------------------------------------------------------- */
/* Runner                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Of the Effect environments the argument layer uses, the ones **maruhi
 * never uses**. Files, the terminal, and child processes are carried by
 * maruhi's own services (ConfigStore / CliIo.promptLine / ProcessRunner).
 * Passing implementations to the argument layer would leave room for
 * undeclared interaction/output paths (Prompt / wizard) to move, so a
 * **dying implementation** is placed here (same reason as decision 5).
 */
const unusedEnvironment = Layer.mergeAll(
  FileSystem.layerNoop({}),
  Path.layer,
  Layer.succeed(
    Terminal.Terminal,
    Terminal.make({
      columns: Effect.succeed(80),
      rows: Effect.succeed(24),
      readInput: Effect.die(
        "the argument layer must not read interactive input (interaction goes through CliIo.promptLine)",
      ),
      readLine: Effect.die(
        "the argument layer must not read interactive input (interaction goes through CliIo.promptLine)",
      ),
      display: () => Effect.void,
    }),
  ),
  Layer.succeed(
    ChildProcessSpawner.ChildProcessSpawner,
    ChildProcessSpawner.make(() =>
      Effect.die("child processes are spawned only through ProcessRunner (run.ts)"),
    ),
  ),
);

/**
 * The destination of help / diagnostics. **Every method** is bent toward
 * `CliIo.logError` (= stderr) (decision 9). A partial override of just
 * log / error would open a hole where a future upstream render method
 * passes through to the real stdout. Since `Console`'s methods are
 * synchronous (`void`), lines are accumulated here and flushed to `CliIo`
 * after the run (never interrupt an Effect via `runSync`).
 */
function collectingConsole(lines: string[]): Console.Console {
  const collect = (...args: ReadonlyArray<unknown>) => {
    lines.push(args.join(" "));
  };
  return {
    assert: collect,
    clear: collect,
    count: collect,
    countReset: collect,
    debug: collect,
    dir: collect,
    dirxml: collect,
    error: collect,
    group: collect,
    groupCollapsed: collect,
    groupEnd: collect,
    info: collect,
    log: collect,
    table: collect,
    time: collect,
    timeEnd: collect,
    timeLog: collect,
    trace: collect,
    warn: collect,
  };
}

/**
 * Re-mounts argv onto `Stdio`. runCli takes argv as an argument (a test
 * swaps argv per run), so the `Stdio.args` the `--` judgment
 * (`commandAfterTerminator`) reads is **the same array**. Production's
 * `Stdio.args` is `process.argv.slice(2)` = what bin.ts passes to runCli,
 * so the value never changes — only the source is unified.
 */
function withArgs(stdio: Stdio.Stdio, argv: readonly string[]): Stdio.Stdio {
  return Stdio.make({ ...stdio, args: Effect.succeed([...argv]) });
}

/** Puts a run failure into one line of maruhi vocabulary (never pass through an upstream English sentence raw). */
function reportFailure(io: CliIoShape, cause: Cause.Cause<unknown>): Effect.Effect<void> {
  const failure: unknown = Cause.squash(cause);
  // ShowHelp was already rendered by the effect side via Formatter (Console → stderr)
  if (failure instanceof EffectCliError.ShowHelp) {
    return Effect.void;
  }
  if (failure instanceof CliError) {
    return io.logError(formatNotice("error", failure.message, io.colorEnabled()));
  }
  // A defect (a bug) or an upstream unknown error. **The message is never
  // shown**: it could arrive embedding a typed-in value (`Invalid value:
  // <plaintext>`), so control-character neutralization alone cannot keep
  // the discipline (never surface a typed-in value in diagnostics). Never
  // swallowed silently (CLAUDE.md) — only the type's name is attached
  // (failure.ts's internalErrorKind — the same shape as cli.ts's defect
  // path)
  return io.logError(
    formatNotice("error", `internal error (${internalErrorKind(failure)})`, io.colorEnabled()),
  );
}

/**
 * Runs one of the migrated commands (`pull` / `run` / `env create`) through
 * `effect/cli` and returns the process exit code.
 *
 * `commandKey` is the **resolved command stage** decided by runCli's
 * dispatch, used as the diagnostics' destination (which declaration to
 * name).
 */
export async function runEffectCli(
  commandKey: string,
  argv: readonly string[],
  layer: Layer.Layer<CliServices>,
): Promise<number> {
  const diagnostics: string[] = [];
  let commandExitCode = 0;
  const root = makeRootCommand((code) => {
    commandExitCode = code;
  });
  // Decides only the amount of help (a run with an explicit `--help` gets
  // the full text; a misspelling gets a 1-line usage — decision 3). Never
  // used for any argument **check**. What follows `--` is **the child
  // process's arguments**, so it is not inspected: `maruhi run stray --
  // cmd -h`'s `-h` belongs to cmd, not a help request to maruhi
  const terminator = argv.indexOf("--");
  const ownArgs = terminator < 0 ? argv : argv.slice(0, terminator);
  // **Bare `maruhi` (no arguments) is treated as a help request** (the
  // stage-3 ruling — ADR-0016 appendix): usage + the command list with
  // exit 0. The destination is stderr (decision 9: stdout is for the
  // command's output only — the same treatment as `maruhi --help`). A
  // bare **subcommand stage** (`maruhi env` alone) is not covered: that
  // is a misspelling (exit 2), and the teardown tells them apart
  const bareRoot = ownArgs.length === 0;
  const helpRequested = bareRoot || ownArgs.includes("--help") || ownArgs.includes("-h");
  const versionRequested = ownArgs.includes("--version") || ownArgs.includes("-v");
  // The teardown's discrimination material (cli-teardown.ts): without an
  // explicit help / version, an errors-empty ShowHelp (a bare parent
  // command) is a misspelling (2)
  const infoRequested = helpRequested || versionRequested;

  const program = Effect.gen(function* () {
    const io = yield* CliIo;
    const stdio = yield* Stdio.Stdio;
    const exit = yield* Command.runWith(root, { version: CLI_VERSION })([...argv]).pipe(
      Effect.provideService(Stdio.Stdio, withArgs(stdio, argv)),
      Effect.provideService(Console.Console, collectingConsole(diagnostics)),
      // Color applies only to stderr's prefixes and help headings (notice.ts — judged via CliIo)
      Effect.provide(formatterLayer(commandKey, COMMAND_SPECS, helpRequested, io.colorEnabled())),
      // Built-in global flags are only --help / --version (decision 5)
      Effect.provide(CliConfig.layer({ builtIns: [GlobalFlag.Help, GlobalFlag.Version] })),
      Effect.provide(unusedEnvironment),
      Effect.exit,
    );
    for (const line of diagnostics) {
      // Only `--version`'s output is **the command's output** (stdout).
      // `V=$(maruhi --version)` is a legitimate script use, a different
      // role than help / diagnostics (stderr). A failed run (when written
      // alongside a misspelling) stays on stderr. A run where `--help` is
      // also given makes upstream's Help win = the collected lines are the
      // help body, so they are not flushed to stdout
      yield* versionRequested && !helpRequested && Exit.isSuccess(exit)
        ? io.log(line)
        : io.logError(line);
    }
    if (Exit.isFailure(exit)) {
      yield* reportFailure(io, exit.cause);
    }
    return exit;
  });

  const exit = await Effect.runPromise(
    program.pipe(
      // An identical-worded Note / Warning fires once per run (notice.ts — the ledger is per-run)
      Effect.provideService(NoticeLedger, new Set<string>()),
      Effect.provide(layer),
    ),
  );

  let exitCode = 0;
  // Production and tests go through the same teardown (never build a
  // shape where ShowHelp's exit 1 → 2 re-read works on only one side —
  // cli-teardown.ts)
  maruhiTeardown(infoRequested)(exit, (code) => {
    exitCode = code;
  });
  // `maruhi run` inherits the child process's exit code. Since
  // `Command.runWith` discards the handler's return value, only a
  // successful run's exit code is carried out (not an error, so it cannot
  // ride Runtime.errorExitCode)
  return exitCode === 0 ? commandExitCode : exitCode;
}
