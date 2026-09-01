// `effect/unstable/cli` の引数層(ADR-0016 — 第 1 段階: pull / run /
// env create、第 2 段階: env rotate / diff、server、invite、member、
// 第 3 段階: push、config、key、project、rotation、audit、login、logout)。
// **移行は完了し、gunshi は廃止済み**(決定 1)。エントリは cli.ts の runCli。
//
// `env` / `server` / `invite` / `member` は**真の入れ子サブコマンド**
// (ADR-0016 決定 6): gunshi の 1 段制約のために操作を位置引数にしていた結果
// 必要だった「その操作に適用されないオプション」の拒否機構(*_ACTION_FLAGS /
// optionRestrictedTo / actionFlagRejection / withoutPositionals)は、宣言が
// 操作ごとに分かれることで機構ごと不要になった。「その操作に無いフラグは
// usage エラー(exit 2)」の性質は宣言 + teardown が保つ
// (effect-cli.test.ts が固定する)。
//
// 規律(ADR-0016 の決定):
//
// 1. **引数の検査に自前の走査を書かない**。すべて宣言で表す —
//    重複指定 = `Flag.atMost(1)`(**boolean にも付ける**)、空 / 空白だけの値 =
//    `Flag.withSchema`、実行対象の必須 = `Argument.atLeast(1)` / `Argument.filter`
// 2. **打たれた値を診断に出さない**。文面は `CliOutput.Formatter`
//    (cli-formatter.ts)で組み直す
// 3. **終了コードはエラー型が持つ**(`Runtime.errorExitCode` — errors.ts)。
//    唯一の例外 `ShowHelp` は teardown で 2 へ読み替える(cli-teardown.ts)
// 4. **組み込みグローバルフラグは `--help` / `--version` だけ**に絞る。既定では
//    `--wizard` / `--completions` / `--log-level` が全コマンドへ生え、
//    `maruhi pull --wizard` は**対話ウィザードが実際に起動する**(実測)
// 5. **`process.*` を直に読まない**。argv も端末の有無も `Stdio` サービス経由
// 6. **stdout はコマンドの出力だけ**。コマンド本体の出力は `CliIo.log`、
//    ヘルプ・診断は `Console`(= `CliIo.logError` = stderr)へ分ける

import { hostname } from "node:os";

import {
  AUDIT_ROW_ID_PATTERN,
  DEFAULT_AUDIT_EVENTS_PAGE_LIMIT,
  DEFAULT_TOKEN_TTL_DAYS,
  MAX_AUDIT_EVENTS_PAGE_LIMIT,
  MAX_TOKEN_NAME_LENGTH,
  MAX_TOKEN_TTL_DAYS,
} from "@maruhi/api-schema";
import { type EnvironmentId, isEnvironmentId, isProjectId, isVariableId } from "@maruhi/core";
import type { MetaVarType, Role } from "@maruhi/crypto";
import {
  Cause,
  Console,
  Effect,
  Exit,
  FileSystem,
  Layer,
  Option,
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
  Primitive,
} from "effect/unstable/cli";
import { ChildProcessSpawner } from "effect/unstable/process";

import { ensureValueDisplayAllowed } from "./agent-gate.ts";
import { buildRepositoryAnchor, formatRepositoryAnchor } from "./anchor.ts";
import { auditReconcileOp } from "./audit-reconcile.ts";
import {
  type AuditListFilters,
  auditInvitesOp,
  auditListOp,
  type AuditPageOptions,
  auditSelfOp,
  auditVerifyOp,
} from "./audit.ts";
import { ANCHOR_REFRESH_PROPOSAL, checkpointProposal, issueCheckpoint } from "./checkpoint.ts";
import { ciRunOp } from "./ci-run.ts";
import { type CommandSpec, formatterLayer, NON_BLANK_MESSAGE } from "./cli-formatter.ts";
import { maruhiTeardown } from "./cli-teardown.ts";
import {
  asConfigKey,
  CONFIG_KEYS,
  ConfigFileCorruptError,
  type ConfigKey,
  ConfigStore,
} from "./config.ts";
import type { CliServices, CommonFlags, ProjectContext } from "./context.ts";
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
  reconcileGossip,
  resolveProjectId,
} from "./context.ts";
import { countNoun, displayText, formatPulledLine, logWarnings, showValues } from "./display.ts";
import { envCreateOp } from "./env-create.ts";
import { envDiffOp, reportEnvironmentDiff } from "./env-diff.ts";
import { envRotateOp } from "./env-rotate.ts";
import { CliError, cliError, usageError } from "./errors.ts";
import { internalErrorKind, toCliError } from "./failure.ts";
import { parseFingerprintFlag, parseUserFingerprintFlag } from "./fingerprint-flag.ts";
import type { FloorHandle } from "./floor-check.ts";
import {
  type InviteInputRejection,
  type InviteRole,
  parseInviteAcceptInput,
} from "./invite-link.ts";
import {
  type AcceptTarget,
  inviteAcceptOp,
  inviteCreateOp,
  inviteListOp,
  inviteRevokeOp,
} from "./invite.ts";
import { CliIo, type CliIoShape } from "./io.ts";
import { keyGenerateOp, keyShowOp } from "./keygen.ts";
import { loadLeasePolicy } from "./lease-policy.ts";
import { loginOp, logoutOp } from "./login.ts";
import {
  MEMBER_REMOVED_ROTATION_REASON,
  type MemberAddSummary,
  memberAddOp,
  memberChangeRoleOp,
  memberRemoveOp,
  ROLE_DEMOTED_ROTATION_REASON,
} from "./member.ts";
import { PinStore } from "./pins.ts";
import { projectInitOp } from "./project-init.ts";
import { projectListOp } from "./project-list.ts";
import { type PulledVariables, pullVariables } from "./pull.ts";
import { normalizeStdinValue, pushVariable } from "./push.ts";
import { issueRecoveryCodeOp, recoverMasterKeyOp } from "./recovery.ts";
import { reportRotation } from "./rotation-report.ts";
import type { SweepOutcome } from "./rotation-sweep.ts";
import { describeUnconvergedMandate, resolveUnconvergedMandates } from "./rotation-sweep.ts";
import {
  parseDismissRequest,
  reportRotationFlagCount,
  resolveDismissTargets,
  rotationDismissOp,
  rotationListOp,
} from "./rotation.ts";
import {
  enforceDeclaredPresence,
  RUN_COMMAND_REQUIRED,
  runOp,
  typeAdvisoryWarnings,
} from "./run.ts";
import {
  ensureEntropyAcknowledged,
  type FieldUpdate,
  type SchemaFieldUpdates,
  schemaSetOp,
  type SchemaSetSummary,
  schemaShowOp,
} from "./schema.ts";
import { serverGrantOp } from "./server-grant.ts";
import { REVOKE_ROTATION_REASON, type RevokeSummary, serverRevokeOp } from "./server-revoke.ts";
import { loadMasterKeys, normalizeHttpOrigin, resolveServerOrigin } from "./session.ts";
import { sweepRotateFor } from "./sweep-rotate.ts";
import { syncProject } from "./sync.ts";
import { CLI_VERSION } from "./version.ts";

/** `--` を書き忘れた実行に添える案内(実行対象の渡し方は 1 つだけ)。 */
const RUN_TERMINATOR_HINT =
  ". Write the command to run after `--` (example: maruhi run -- printenv MY_VAR)";

/* -------------------------------------------------------------------------- */
/* 宣言(検査は Effect の機構に載せる — 自前の走査を書かない)                 */
/* -------------------------------------------------------------------------- */

/**
 * 空・空白だけの値を受け付けない文字列。
 *
 * gunshi では自前の走査(args.ts の emptyOptionValueRejection)だったものが、
 * Schema の宣言 1 つになる。`maruhi push API_KEY --env "$ENV"` で ENV が
 * 未設定のとき、既定環境へ黙って書き込む事故を塞ぐ。
 */
const NonBlank = Schema.String.check(Schema.isPattern(/\S/, { message: NON_BLANK_MESSAGE }));

/**
 * 値を取るオプション 1 つ。
 *
 * `atMost(1)` が**重複指定の拒否**(gunshi: last-wins で沈黙 /
 * effect: first-wins で沈黙)を宣言で表す。`maruhi pull --no-show $FLAGS` が
 * 全シークレットを表示していた事故(ef7cba1)と同じ形をここで塞ぐ。
 *
 * `noUncheckedIndexedAccess: true` なので結果は `string | undefined` =
 * context.ts の {@link CommonFlags} とそのまま噛み合う(Option へ変換しない)。
 */
function singleValued(name: string, description: string) {
  return Flag.string(name).pipe(
    Flag.withDescription(description),
    Flag.withSchema(NonBlank),
    Flag.atMost(1),
    Flag.map((values) => values[0]),
  );
}

/**
 * boolean オプション 1 つ。
 *
 * **boolean にも `atMost(1)` が要る**: 素の `Flag.boolean` は重複を沈黙で解決し、
 * **打った順で結果が変わる**(実測: `--show --no-show` は first-wins で `true`、
 * `--no-show --show` は `false`)。`maruhi pull --no-show $FLAGS` の `$FLAGS` に
 * `--show` が混ざる形(ef7cba1)は順序に依存させてはいけない。
 */
function singleFlag(name: string, description: string) {
  return Flag.boolean(name).pipe(
    Flag.withDescription(description),
    Flag.atMost(1),
    Flag.map((values) => values[0] ?? false),
  );
}

/**
 * テスト用の隠しフラグ(値 1 つ)。ヘルプにも打ち間違いの候補にも出さない。
 *
 * `Flag` には hidden コンビネータが**無い**が、`Param.Single` は
 * `hidden: boolean` を持ち `Param.makeSingle` が受ける(実測: ヘルプの描画と
 * 上流の typo 候補の両方が hidden を除外する)。診断の一覧(specOf)からも
 * 除外する — 内部向けの綴りを広めない(gunshi 時代の hidden と同じ扱い)。
 */
function hiddenSingle<A>(name: string, description: string, primitive: Primitive.Primitive<A>) {
  return Param.makeSingle({
    kind: Param.flagKind,
    name,
    primitiveType: primitive,
    description: Option.some(description),
    hidden: true,
  });
}

function hiddenIntegerValued(name: string, description: string) {
  return hiddenSingle(name, description, Primitive.integer).pipe(
    Flag.atMost(1),
    Flag.map((values) => values[0]),
  );
}

/**
 * その宣言は hidden な葉(`Param.Single`)か。ラッパ(Map / Variadic /
 * Transform / Optional)は子を `param` に持つので、葉まで辿って判定する。
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
 * 診断用のコマンド宣言を、**コマンド定義そのもの**から導く。
 *
 * 手書きの写しを持つと、フラグを足したときに診断だけ古いまま残る。`Param` は
 * 公開型として `kind`(`"flag"` / `"argument"`)を持つので、宣言の並びから
 * そのまま仕分けできる。名前はオブジェクトのキー(= 打つときの綴り)を使う。
 * hidden な宣言は一覧に出さない(内部向けの綴りを広めない)。
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
/* コマンド定義                                                                */
/* -------------------------------------------------------------------------- */

/** 環境系コマンドが取る共通フラグ(context.ts の CommonFlags と同じ名前)。 */
const commonFlags = () => ({
  ...projectFlags(),
  env: singleValued("env", "Environment ID (defaults to config defaultEnvironment)"),
});

/** プロジェクト水準のコマンドが取る共通フラグ(env は取らない)。 */
const projectFlags = () => ({
  server: singleValued("server", "Server URL (defaults to config server)"),
  project: singleValued("project", "Project ID (defaults to config defaultProject)"),
});

/** セッション水準のコマンドが取る共通フラグ(project も env も取らない)。 */
const serverOnlyFlags = () => ({
  server: singleValued("server", "Server URL (defaults to config server)"),
});

const pullConfig = {
  ...commonFlags(),
  show: singleFlag(
    "show",
    "Print values to the terminal (only allowed on an interactive terminal)",
  ),
};

/** `run` / `ci run` 共通の実行対象(`--` の後ろ)の宣言。 */
const runCommandArgument = () =>
  // `--` の後ろはここに入る(空文字列も保持される)。`atLeast(1)` が
  // 「実行対象のない実行」を、`filter` が「実行対象が空文字列」
  // (`maruhi run -- "$CMD"` の未設定形)を落とす。どちらも宣言で、
  // 2 つ目以降の空文字列は**子プロセスの引数として保つ**
  Argument.string("command").pipe(
    Argument.withDescription("The command to run, written after `--` (passed to the child as-is)"),
    Argument.atLeast(1),
    Argument.filter(
      (command) => (command[0] ?? "").trim() !== "",
      () => RUN_COMMAND_REQUIRED,
    ),
  );

const runConfig = {
  ...commonFlags(),
  command: runCommandArgument(),
};

/**
 * `maruhi ci run` の宣言(session-25 §1 / §2): 通常の run と違い config
 * ファイルを読まないため、server / project / env は**フラグで必須**。宣言上は
 * optional(singleValued)にし、欠落の診断は本体側で CI 特有の直し方
 * (「config へ」ではなく「フラグを書く」)を言う。
 */
const ciRunConfig = {
  server: singleValued("server", "Server URL (required — CI mode reads no config file)"),
  project: singleValued(
    "project",
    "Project ID = the pinned genesis hash (required — CRYPTO_SPEC §9.1 verification duty (1))",
  ),
  env: singleValued("env", "Environment ID to lease (required)"),
  audience: singleValued(
    "audience",
    "OIDC audience to request (defaults to the server origin — AUTH_SPEC §14-1)",
  ),
  anchor: singleValued(
    "anchor",
    "Path to the committed repository anchor file (generate with `maruhi project anchor` — CRYPTO_SPEC §6.3)",
  ),
  command: runCommandArgument(),
};

/**
 * `maruhi push` の余分な位置引数に添える固有の直し方(第 3 段階 ①)。
 *
 * `maruhi push API_KEY "$SECRET"` は最も起こりやすい書き間違い。拒否した引数の
 * 中身は出さない(平文でありうる)ので、代わりに「値は stdin から」を必ず
 * 添える — でないと直しようがない(cli-formatter.ts の strayHint)。
 */
const PUSH_STDIN_HINT =
  '. Values are read from stdin (example: printf %s "$SECRET" | maruhi push API_KEY)';

const pushConfig = {
  ...commonFlags(),
  name: Argument.string("name").pipe(
    Argument.withDescription("Variable name (the display name; becomes the env var name)"),
    Argument.withSchema(NonBlank),
  ),
};

/** 設定キーの位置引数(config のサブコマンド共通)。 */
const configKeyArgument = () =>
  Argument.string("key").pipe(
    Argument.withDescription(`Config key (${CONFIG_KEYS.join(" | ")})`),
    Argument.withSchema(NonBlank),
  );

const configGetConfig = {
  key: configKeyArgument(),
};

const configSetConfig = {
  key: configKeyArgument(),
  // 空 / 空白だけの値は宣言(NonBlank)で拒否する: `config set defaultProject
  // "$PROJ"` の未設定形が既存の設定を空で上書きして成功を報告する事故を塞ぐ
  // (gunshi 時代は args.ts の emptyPositionalRejection が受け持っていた)
  value: Argument.string("value").pipe(
    Argument.withDescription("Value to set"),
    Argument.withSchema(NonBlank),
  ),
};

const rotationListConfig = { ...projectFlags() };

const rotationDismissConfig = {
  ...projectFlags(),
  env: singleValued(
    "env",
    "Environment ID of the flag to dismiss (with --all, narrows the dismissal to that environment)",
  ),
  all: singleFlag("all", "Dismiss every currently-active flag (an explicit acceptance of risk)"),
  // gunshi では optional な 2 つ目の位置引数だった(--all の実行では取らない)。
  // atMost(1) が「--all なら省略」を宣言で表す
  variable: Argument.string("variable").pipe(
    Argument.withDescription("variableId to dismiss (omit when using --all)"),
    Argument.withSchema(NonBlank),
    Argument.atMost(1),
    Argument.map((values) => values[0]),
  ),
};

/** audit のページ指定フラグ(list / invites / self 共通)。 */
const auditPageFlags = () => ({
  limit: Flag.integer("limit").pipe(
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
 * `maruhi audit`(親)と `maruhi audit list` が共有する宣言。**bare `audit` =
 * list**(現行仕様)を保つため、親コマンド自身がこの宣言とハンドラを持つ
 * (実測: ハンドラ付き親 + withSubcommands で、bare 親はハンドラを実行し、
 * サブコマンド指定時は子だけが走る)。
 */
const auditListConfig = {
  ...projectFlags(),
  ...auditPageFlags(),
  event: singleValued(
    "event",
    "Filter by event kind (e.g. var.version_pushed / chain.member_added)",
  ),
  actor: singleValued(
    "actor",
    "Filter by actor user_id (below admin, only your own user_id — AUDIT_SPEC §6)",
  ),
  target: singleValued("target", "Filter by target user_id"),
  env: singleValued("env", "Filter by environment ID"),
  var: singleValued("var", "Filter by variableId"),
};

const auditInvitesConfig = { ...projectFlags(), ...auditPageFlags() };

// self はアカウント全域でプロジェクトを取らない(--project は宣言に無い =
// Unknown flag。gunshi 時代の AUDIT_ACTION_FLAGS の置き換え)
const auditSelfConfig = { ...serverOnlyFlags(), ...auditPageFlags() };

const auditVerifyConfig = { ...projectFlags() };

const auditReconcileConfig = { ...projectFlags() };

const loginConfig = {
  ...serverOnlyFlags(),
  "token-name": singleValued(
    "token-name",
    "Token name (re-login with the same name rotates the token; default: cli:<hostname>)",
  ),
  "token-ttl-days": Flag.integer("token-ttl-days").pipe(
    Flag.withDescription(
      `Token lifetime in days (1-${MAX_TOKEN_TTL_DAYS}; default ${DEFAULT_TOKEN_TTL_DAYS}). For unattended use on runtimes without lease support`,
    ),
    Flag.atMost(1),
    Flag.map((values) => values[0]),
  ),
  "show-token": singleFlag(
    "show-token",
    "Print the issued token once (to provision MARUHI_TOKEN on runtimes without lease support). Interactive terminals only",
  ),
  "poll-interval": hiddenIntegerValued(
    "poll-interval",
    "Minimum approval polling interval in seconds (for tests)",
  ),
};

const logoutConfig = serverOnlyFlags();

const keyGenerateConfig = serverOnlyFlags();
const keyShowConfig = serverOnlyFlags();
const keyRecoverConfig = serverOnlyFlags();
const keyRecoveryConfig = serverOnlyFlags();

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
  project: singleValued("project", "Project ID to verify (defaults to config defaultProject)"),
};

const projectAnchorConfig = {
  ...serverOnlyFlags(),
  project: singleValued("project", "Project ID to anchor (defaults to config defaultProject)"),
};

const projectCheckpointConfig = {
  ...serverOnlyFlags(),
  project: singleValued("project", "Project ID to checkpoint (defaults to config defaultProject)"),
};

/** 環境 ID の位置引数(env のサブコマンド共通。キーは打つときの綴り)。 */
const environmentIdArgument = (name: string, description: string) =>
  Argument.string(name).pipe(Argument.withDescription(description), Argument.withSchema(NonBlank));

const envCreateConfig = {
  ...projectFlags(),
  name: singleValued("name", "Display name (defaults to the environment ID)"),
  // キーは**打つときの綴り**にする(specOf が診断名としてそのまま使う)
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
  // 移行専用(session-27 §14 PR-M1): マニフェスト導入前に作成された環境の
  // manifest_version 1 初期化。許容するのは**欠落**のみで、配布された
  // マニフェストの検証は緩和しない(manifest.ts)
  "init-manifest": singleFlag(
    "init-manifest",
    "Initialize the environment manifest (only for environments created before manifests existed; tolerates a missing manifest for this one rotation). Run this for every environment before upgrading CI — workloads cannot initialize a manifest themselves",
  ),
  "environment-id": environmentIdArgument("environment-id", "Environment ID (e.g. dev / prod)"),
};

const envDiffConfig = {
  ...projectFlags(),
  "environment-id": environmentIdArgument("environment-id", "First environment ID to compare"),
  // gunshi では 1 段制約のため optional な 3 つ目の位置引数だったが、diff 専用の
  // サブコマンドになったので**必須**として宣言できる(欠落は MissingArgument)
  "other-environment-id": environmentIdArgument(
    "other-environment-id",
    "Second environment ID to compare",
  ),
};

const serverGrantConfig = {
  ...projectFlags(),
  environments: singleValued(
    "environments",
    "Comma-separated environment IDs to disclose (required — least disclosure, environments are explicit)",
  ),
  "lease-policy": singleValued(
    "lease-policy",
    "Path to a workload lease-policy JSON file (defaults to no lease path)",
  ),
  "expect-fingerprint": singleValued(
    "expect-fingerprint",
    "Server key fingerprint noted out of band (32 hex chars; replaces the interactive check)",
  ),
};

const serverRevokeConfig = {
  ...projectFlags(),
  fingerprint: singleValued(
    "fingerprint",
    "Server key fingerprint to revoke (may be omitted when exactly one grant is active)",
  ),
};

/** 招待で付与できる role(owner は招待経由で付与しない — AUTH_SPEC §15-1)。 */
const INVITE_ROLES = ["reader", "member", "admin"] as const;

function isInviteRole(value: string | undefined): value is InviteRole {
  return INVITE_ROLES.some((known) => known === value);
}

const inviteCreateConfig = {
  ...projectFlags(),
  role: singleValued("role", `Role to grant (required — ${INVITE_ROLES.join(" | ")})`),
};

const inviteAcceptConfig = {
  server: singleValued("server", "Server URL (defaults to config server)"),
  project: singleValued(
    "project",
    "Project ID (only required when accepting with a raw token — a link carries it)",
  ),
  "inviter-fingerprint": singleValued(
    "inviter-fingerprint",
    "Inviter's key fingerprint noted out of band (32 hex chars; checked against the link's if= instead of the interactive ceremony)",
  ),
  // 招待リンクはトークン生値を内包する = ただの表示可能文字列ではない。
  // `Argument.redacted` で受け、Redacted のまま invite-link.ts の解釈境界へ
  // 渡す(PR #74 の申し送り — 剥がすのは既存の境界だけ)
  target: Argument.redacted("target").pipe(
    Argument.withDescription(
      "Invite link or token (quote the link so the shell does not interpret it)",
    ),
  ),
};

const inviteListConfig = { ...projectFlags() };

const inviteRevokeConfig = {
  ...projectFlags(),
  "invite-id": Argument.string("invite-id").pipe(
    Argument.withDescription("Invite id to revoke (see maruhi invite list)"),
    Argument.withSchema(NonBlank),
  ),
};

/** メンバーに付与できる role(CRYPTO_SPEC §6.2)。 */
const MEMBER_ROLES = ["reader", "member", "admin", "owner"] as const;

function isMemberRole(value: string | undefined): value is Role {
  return MEMBER_ROLES.some((known) => known === value);
}

const memberAddConfig = {
  ...projectFlags(),
  "expect-fingerprint": singleValued(
    "expect-fingerprint",
    "Acceptor's key fingerprint noted out of band (32 hex chars; replaces the interactive check)",
  ),
  // gunshi では 1 段制約のため optional な共有位置引数(target)だったもの。
  // add 専用の宣言になったので「受諾済みが 1 件なら省略可」を atMost(1) で表す
  "invite-id": Argument.string("invite-id").pipe(
    Argument.withDescription("Invite id to add (may be omitted when exactly one is accepted)"),
    Argument.withSchema(NonBlank),
    Argument.atMost(1),
    Argument.map((values) => values[0]),
  ),
};

/** remove / change-role の対象 user_id(必須・非空)。 */
const memberTargetArgument = () =>
  Argument.string("user-id").pipe(
    Argument.withDescription("Target user_id (see the member list in maruhi project verify)"),
    Argument.withSchema(NonBlank),
  );

const memberRemoveConfig = {
  ...projectFlags(),
  "user-id": memberTargetArgument(),
};

const memberChangeRoleConfig = {
  ...projectFlags(),
  role: singleValued("role", `New role (required — ${MEMBER_ROLES.join(" | ")})`),
  "user-id": memberTargetArgument(),
};

/** `maruhi schema`(表示 — bare 親が show を兼ねる。audit と同じ型)。 */
const schemaShowConfig = { ...commonFlags() };

/** `--type` の閉集合(CRYPTO_SPEC §4.2 — 裁定 CT)+ 明示クリアの `none`。 */
const SCHEMA_TYPES = ["string", "number", "boolean", "url"] as const;

const schemaSetConfig = {
  ...commonFlags(),
  type: singleValued(
    "type",
    `Declared value type (${SCHEMA_TYPES.join(" | ")}; \`none\` clears it back to unspecified)`,
  ),
  required: singleFlag(
    "required",
    "Declare the variable as required (maruhi run fails fast while it has no value)",
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
  "allow-high-entropy": singleFlag(
    "allow-high-entropy",
    "Proceed without confirmation when the name or description contains a secret-like high-entropy string (fail-closed otherwise)",
  ),
  name: Argument.string("name").pipe(
    Argument.withDescription(
      "Variable name (created as a declared variable when it does not exist)",
    ),
    Argument.withSchema(NonBlank),
  ),
};

/**
 * 入れ子の段(グループ)→ サブコマンド名 → 宣言。**この表が唯一の出所**で、
 * COMMAND_SPECS(振り分けのキーと診断の宣言・サブコマンド一覧)をここから
 * 導く — 親の段を手書きの写しで持つと、サブコマンドを足したときに振り分けと
 * 診断だけ古いまま残る。makeRootCommand の `Command.make(名前)` はこのキーと
 * 同じ綴りを使う(食い違いは effect-cli.test.ts の適合検査で落ちる)。
 */
const GROUP_CONFIGS: Readonly<
  Record<string, Readonly<Record<string, Readonly<Record<string, Param.Any>>>>>
> = {
  env: { create: envCreateConfig, rotate: envRotateConfig, diff: envDiffConfig },
  server: { grant: serverGrantConfig, revoke: serverRevokeConfig },
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
  },
  key: {
    generate: keyGenerateConfig,
    show: keyShowConfig,
    recover: keyRecoverConfig,
    recovery: keyRecoveryConfig,
  },
  project: {
    init: projectInitConfig,
    list: projectListConfig,
    verify: projectVerifyConfig,
    anchor: projectAnchorConfig,
    checkpoint: projectCheckpointConfig,
  },
  ci: { run: ciRunConfig },
  rotation: { list: rotationListConfig, dismiss: rotationDismissConfig },
  audit: {
    list: auditListConfig,
    invites: auditInvitesConfig,
    self: auditSelfConfig,
    verify: auditVerifyConfig,
    reconcile: auditReconcileConfig,
  },
  config: { get: configGetConfig, set: configSetConfig },
  schema: { set: schemaSetConfig },
};

/**
 * 親の段自身が宣言(とハンドラ)を持つグループ。bare `maruhi audit` = list を
 * 保つ audit だけで、診断(`audit --bogus` の未宣言フラグ)も親の段の宣言で
 * 組めるよう COMMAND_SPECS の親エントリへ流し込む。
 */
const GROUP_PARENT_CONFIGS: Readonly<Record<string, Readonly<Record<string, Param.Any>>>> = {
  audit: auditListConfig,
  schema: schemaShowConfig,
};

/**
 * commandKey → 診断用の宣言。キーは runCli の振り分けが返すものと同じ。
 * 入れ子の段は subcommands を持ち、不明なサブコマンドの診断が「取りうる
 * 操作の一覧」を出すのに使う(cli-formatter.ts)。
 */
/**
 * root(`maruhi` 段)の診断キー。`ShowHelp.commandPath` が 1 段のとき
 * `commandPath.slice(1).join(" ")` は空文字列になるので、その綴りに合わせる。
 * 未知のコマンド(`maruhi bogus`)の診断が「取りうるコマンドの一覧」を
 * 出すために使う(cli-formatter.ts の unknownSubcommandMessage)。
 */
export const ROOT_SPEC_KEY = "";

const LEAF_AND_GROUP_SPECS: Readonly<Record<string, CommandSpec>> = {
  login: specOf(loginConfig),
  logout: specOf(logoutConfig),
  pull: specOf(pullConfig),
  run: specOf(runConfig),
  push: { ...specOf(pushConfig), strayHint: PUSH_STDIN_HINT },
  ...Object.fromEntries(
    Object.entries(GROUP_CONFIGS).flatMap(([group, subcommands]) => [
      [
        group,
        {
          // 親自身が宣言を持つ段(audit)は、その宣言を診断にも使う
          ...(GROUP_PARENT_CONFIGS[group] === undefined
            ? { flags: [], positionals: [] }
            : specOf(GROUP_PARENT_CONFIGS[group])),
          subcommands: Object.keys(subcommands),
        },
      ],
      ...Object.entries(subcommands).map(([name, config]) => [`${group} ${name}`, specOf(config)]),
    ]),
  ),
};

export const COMMAND_SPECS: Readonly<Record<string, CommandSpec>> = {
  ...LEAF_AND_GROUP_SPECS,
  // root 段(1 段の一覧)。未知のコマンドの診断が「取りうるコマンド」を出す
  [ROOT_SPEC_KEY]: {
    flags: [],
    positionals: [],
    subcommands: [
      ...new Set(Object.keys(LEAF_AND_GROUP_SPECS).map((key) => key.split(" ")[0] ?? key)),
    ],
  },
};

/**
 * `maruhi run` が実行するコマンド列を確定する(**`--` の後ろだけ**)。
 *
 * パーサは `--` の前後の位置引数を 1 つの配列にまとめる(実測: 上流の
 * `parseArgs` が `[...result.arguments, ...afterEndOfOptions]`)。したがって
 * 宣言だけでは `maruhi run stray -- printenv` が `stray` の実行に化ける。
 * ADR-0016 決定 8(`--` を必須とし、判定は `Stdio.args` を読む)の実装として、
 * **`--` の後ろの個数と一致すること**まで見る。
 *
 * 個数は**パーサが解決した配列と argv の位置**から出す(宣言の写しを持たない
 * — 値を取るフラグを足したときに黙ってずれる)。中身は診断に出さない。
 */
function commandAfterTerminator(
  parsed: readonly string[],
): Effect.Effect<readonly string[], CliError, Stdio.Stdio> {
  return Effect.gen(function* () {
    const stdio = yield* Stdio.Stdio;
    const argv = yield* stdio.args;
    const terminator = argv.indexOf("--");
    // `--` が無い分岐では、可変長引数がそのまま余分な位置引数になる
    // (`--env prod` の `prod` はフラグの値として食べられている)
    const stray = terminator < 0 ? parsed.length : parsed.length - (argv.length - terminator - 1);
    if (stray > 0) {
      return yield* Effect.fail(
        usageError(
          `Unexpected extra arguments (${stray}; contents not shown — they may contain plaintext values). maruhi run takes no positional arguments before \`--\`${RUN_TERMINATOR_HINT}`,
        ),
      );
    }
    return parsed;
  });
}

/**
 * `maruhi env create <id>` の本体(複合リクエスト — §12-4)。
 *
 * 第 1 段階の移行中は gunshi 側の env コマンド(cli.ts)も同じ本体を呼んで
 * いたが、第 2 段階で env がまるごと移ったので共有は解消した。
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
      // メンバー数は**実際に登録したラップ集合**の大きさ(CAS リトライで作り
      // 直した場合、コマンド開始時のビューのメンバー数とは食い違いうる)
      `Created environment ${environmentId} (epoch=${created.currentEpoch}, DEK wrapped for ${countNoun(created.memberCount, "current member")})`,
    );
  });
}

/** 位置引数で受けた環境 ID の形式検証(**指定値そのものはエラーに出さない**)。 */
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

/** 環境 ID の形(--env フラグ用の文面。指定値そのものはエラーに出さない)。 */
const ENV_FLAG_SHAPE_MESSAGE =
  "Invalid environment ID for --env (must start with an alphanumeric character, followed by up to 63 alphanumerics, _ or -)";

/** 未指定は許容し、指定時は [1, max] の整数のみ通す。 */
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
  // カーソルは行 id(AUDIT_SPEC §5.1 row_id — 形式は api-schema の Schema と
  // 共有)。前ページ末尾の「To continue:」案内が示す値をそのまま渡す
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

/** 未指定は許容し、指定時は非空かつ max 文字以内のみ通す。 */
function boundedFlagValue(value: string | undefined, max: number): boolean {
  return value === undefined || (value.length > 0 && value.length <= max);
}

/** フィルタフラグの最初の書き方の誤り(なければ null)。 */
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

/** list のフィルタフラグの検査(形式はネットワークより先に見る)。 */
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
 * `--token-name` の長さ検査(**指定値そのものはエラーに出さない**)。
 *
 * 上限は `@maruhi/api-schema` の宣言と同じ定数を見る(CLI 側に数字を写すと、
 * 宣言を緩めたときにこちらだけ古い上限で拒否し続ける)。
 */
function requireTokenName(value: string | undefined): Effect.Effect<string, CliError> {
  const name = value ?? `cli:${hostname()}`;
  return name.length > MAX_TOKEN_NAME_LENGTH
    ? Effect.fail(usageError(`--token-name must be at most ${MAX_TOKEN_NAME_LENGTH} characters`))
    : Effect.succeed(name);
}

/**
 * `--token-ttl-days` の範囲検査(AUTH_SPEC §6 — W3a)。上限・既定は
 * `@maruhi/api-schema` の宣言と同じ定数を見る(requireTokenName と同じ理由:
 * 書き方の誤りはブラウザ承認の完走より前に落とす)。省略は undefined のまま
 * 返し、サーバー側の既定(90 日)に委ねる。
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
 * `maruhi schema`(表示)の本体(bare `maruhi schema` と親ハンドラが共有 —
 * audit と同じ型)。**鍵なしクラス**(openMetadataEnvironment — メタデータ
 * のみ pull)で、**agent-gate は適用しない(許可側 — 設計文書 §1-1)**:
 * 出力は値ゼロ(名前・型・説明・必須・状態のみ)であり、ADR-0016 決定 7 の
 * 2 層ゲートの適用対象は「値を表示する系」に限られる。エージェント環境で
 * そのまま動くことが本機能の主用途(deny-list に含めないことはテストで固定)。
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

/** `--type` の解釈(未指定 = keep・`none` = 明示クリア。**指定値そのものはエラーに出さない**)。 */
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

/**
 * `schema set` の欄指定の解釈(部分更新 §1-2 — 未指定 = keep、空へ戻すのは
 * 明示フラグのみ)。矛盾する指定(--required と --optional 等)は usage エラー。
 */
function parseSchemaFieldUpdates(values: {
  readonly type?: string | undefined;
  readonly required: boolean;
  readonly optional: boolean;
  readonly description?: string | undefined;
  readonly "clear-description": boolean;
}): Effect.Effect<SchemaFieldUpdates, CliError> {
  return Effect.gen(function* () {
    const varType = yield* parseSchemaTypeFlag(values.type);
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
    return { varType, required, description };
  });
}

/** `schema set` の成功報告(型は宣言として表示 — 「verified」の語を使わない §14.3)。 */
function schemaSetReport(name: string, summary: SchemaSetSummary): string {
  const typeShown = summary.schema.varType === "" ? "-" : summary.schema.varType;
  if (summary.created) {
    return `Declared ${displayText(name)} (type=${typeShown}, required=${summary.schema.required}) — no value yet. Set the first value with: printf %s "$VALUE" | maruhi push ${displayText(name)}`;
  }
  return `Updated the schema of ${displayText(name)} (type=${typeShown}, required=${summary.schema.required}, metaVersion=${summary.metaVersion})`;
}

/** 位置引数で受けた設定キーの検証(**指定値そのものはエラーに出さない**)。 */
function requireConfigKey(value: string): Effect.Effect<ConfigKey, CliError> {
  const key = asConfigKey(value);
  return key === null
    ? Effect.fail(usageError(`Unknown config key (${CONFIG_KEYS.join(" | ")})`))
    : Effect.succeed(key);
}

/** `maruhi project verify`: チェーン検証 + 床・アンカー検査 + 状態表示。 */
function projectVerify(
  serverFlag: string | undefined,
  projectFlag: string | undefined,
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const context = yield* openSession(serverFlag);
    const projectId = yield* resolveProjectId(projectFlag, context.config);
    const synced = yield* syncProject(context.client, projectId);
    // チェーン床の検査(§6.3 規則 (a))も verify の一部
    const checked = (yield* loadCheckedFloor(
      projectId,
      synced,
      syncProject(context.client, projectId),
    )).verified;
    // 招待リンクアンカーの機械照合(§6.3 (a) / §6.5)も verify の一部
    yield* checkInviteAnchor(projectId, checked);
    // 他メンバーのヘッド申告との照合(§6.3 ヘッドゴシップ / §6.6)も verify の
    // 一部(矛盾申告 = split view の硬い証拠で中断・証拠保存)。提出は行わない
    // (verify は master 鍵を要求しない読み取りコマンド)。床ヘッドの前進は
    // attachProject と同じく reconcileGossip の中で全検査通過後に行う
    const verified = yield* reconcileGossip(
      projectId,
      checked,
      syncProject(context.client, projectId),
    );
    yield* io.log(`Chain verification OK (head seq=${verified.state.headSeq})`);
    yield* io.log(`head: ${verified.state.headHashHex}`);
    yield* io.log(`Members (${verified.state.members.size}):`);
    for (const member of verified.state.members.values()) {
      yield* io.log(
        `  ${displayText(member.userId)}\t${member.role}\tfp=${member.keyFingerprintHex}`,
      );
    }
    for (const [environmentId, environment] of verified.state.environments) {
      yield* io.log(
        `Environment ${environmentId}: epoch=${environment.currentEpoch} (created at seq=${environment.createdAtSeq})`,
      );
    }
    // 未収束のローテーション義務(§7 — チェーン導出 + 検証済み削除の除外)も
    // verify の一部(常時警告 — rotation-sweep.ts — の詳細表示。候補ゼロなら
    // 通信なしで確定する)。削除済み環境の検証失敗は「確定できません」の注意
    // だけで verify 自体は成功扱い(チェーン検証は済んでいる — Cursor bot 指摘)
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
 * 発行契機 (iii) の提案(CRYPTO_SPEC §6.3): pull / push の成功後に基準
 * チェックポイントの鮮度(7 日超・未発行)を検出したら提案行を出す。提案の
 * 判定失敗でコマンド本体の成功を覆さない(提案は SHOULD の付随)。push では
 * アンカー更新の提案(session-25 §8)を同じ導線に同梱する。
 */
function proposeCheckpointRefresh(
  context: Pick<ProjectContext, "client" | "verified" | "session">,
  options: { readonly includeAnchor: boolean },
): Effect.Effect<void, never, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const proposal = yield* checkpointProposal({
      client: context.client,
      verified: context.verified,
      signerUserId: context.session.userId,
      nowMs: Date.now(),
    });
    if (proposal === null) {
      return;
    }
    yield* io.logError(proposal);
    if (options.includeAnchor) {
      yield* io.logError(`Note: ${ANCHOR_REFRESH_PROPOSAL}`);
    }
  }).pipe(Effect.catch(() => Effect.void));
}

/** `maruhi env rotate <id> [--reason <text>] [--new-epoch]`(§7 / §12-4)。 */
function envRotateCommand(
  flags: CommonFlags & {
    readonly reason?: string | undefined;
    readonly newEpoch?: boolean | undefined;
    readonly initManifest?: boolean | undefined;
  },
  environmentId: EnvironmentId,
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    // 環境床(§6.3)を使うため環境コンテキストで開く(環境は位置引数で確定)。
    // 収束系コマンドなので未収束義務の常時警告は抑制する(このコマンド自身の
    // ローテーション報告が同じ事実を伝える — context.ts の OpenProjectOptions)
    const context = yield* openEnvironment(
      { ...flags, env: environmentId },
      { quietMandateWarning: true },
    );
    const summary = yield* envRotateOp({
      client: context.client,
      verified: context.verified,
      environmentId,
      recipient: context.recipient,
      // 未指定(undefined)と空文字列は**別物**として渡す: 空の `--reason` は
      // 宣言(NonBlank)が exit 2 で落とすので、ここへ来る undefined は
      // **`--reason` 自体が無い**実行だけ(env-rotate の checkReasonLength は
      // 防衛線として残る)
      reason: flags.reason,
      forceNewEpoch: flags.newEpoch === true,
      initManifest: flags.initManifest === true,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
      resync: context.resync,
      floor: context.floorHandle,
    });
    // 「新しいエポックを要求したか」は起動時のフラグで決まる(--reason は
    // 新エポックを作る経路でのみ必須 — env-rotate.ts の requireReason)
    const code = yield* reportRotation(
      environmentId,
      summary,
      flags.newEpoch === true || flags.reason !== undefined,
    );
    if (summary.mode === "rotated") {
      // アンカー更新の提案(session-25 §8 / CRYPTO_SPEC §6.3 (b)): エポックが
      // 進んだ = コミット済みアンカーのエポック床が古くなった
      const io = yield* CliIo;
      yield* io.logError(`Note: ${ANCHOR_REFRESH_PROPOSAL}`);
    }
    return code;
  });
}

/**
 * `maruhi env diff <a> <b>`: 2 環境の**変数名の集合**を比較する(値は取得も
 * 復号もしない)。差分があっても終了コードは 0 のまま: 「差分あり」は成功した
 * 実行の**報告内容**であって実行の失敗ではなく、1 に混ぜると検証失敗・床違反
 * (= サーバー不正の証拠)や通信失敗と区別できなくなる。
 */
function envDiffCommand(
  flags: CommonFlags,
  environmentId: EnvironmentId,
  otherEnvironmentId: EnvironmentId,
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    // 前段(チェーン同期 + §6.3 検証)は 1 回だけ。master 鍵は要求しない
    // (復号しないため — context.ts の openMetadataProjectWith)
    const context = yield* openMetadataEnvironmentPair(flags, environmentId, otherEnvironmentId);
    const diff = yield* envDiffOp({
      client: context.client,
      verified: context.verified,
      resync: context.resync,
      first: { environmentId: context.first.environmentId, floor: context.first.floorHandle },
      second: { environmentId: context.second.environmentId, floor: context.second.floorHandle },
      // 環境のメタ水準の床は作らない(値を読んでいないため)が、**チェーン床の
      // ヘッド**は pull / push と同じく前進させる。記録は pull ごと(envDiffOp)
      commitHead: (verified) => commitVerifiedHead(context.projectId, verified),
    });
    yield* reportEnvironmentDiff(diff);
  });
}

/**
 * `maruhi ci run` の必須フラグの解決(session-25 §2): config ファイルへ
 * フォールバックしない(CI ランナーに永続 config は無く、genesis 固定は
 * ワークフロー YAML のレビューに置く)。診断も「config を設定する」ではなく
 * 「フラグを書く」を言う。
 */
function requireCiFlag(value: string | undefined, flag: string): Effect.Effect<string, CliError> {
  return value === undefined
    ? Effect.fail(
        usageError(
          `ci run requires ${flag} (CI mode reads no config file — pass --server, --project, and --env explicitly in the workflow)`,
        ),
      )
    : Effect.succeed(value);
}

/** `maruhi ci run -- <cmd>` の本体(検証は ci-run.ts / lease-client.ts)。 */
function ciRunCommand(values: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly env?: string | undefined;
  readonly audience?: string | undefined;
  readonly anchor?: string | undefined;
  readonly command: readonly string[];
}): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    // 形式検証はすべてネットワーク・鍵生成より先(既存コマンドと同じ規律)
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
    return yield* ciRunOp({
      origin,
      projectId: projectFlag,
      environmentId: envFlag,
      // audience の既定はサーバーの正規化 origin(AUTH_SPEC §14-1 の推奨値)
      audience: values.audience ?? origin,
      anchorPath: values.anchor,
      command: values.command,
    });
  });
}

/**
 * `--environments dev,prod` の解釈(grant では必須 — 最小開示の既定として
 * 環境は明示指定。session-22 §2 の裁定)。空要素は書き間違いとして拒否する。
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

/** `maruhi server grant --environments <ids> [--lease-policy <file>]`(§9 / §12-6)。 */
function serverGrantCommand(
  flags: CommonFlags & {
    readonly environments?: string | undefined;
    readonly leasePolicyPath?: string | undefined;
    readonly expectFingerprint?: string | undefined;
  },
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const environmentIds = yield* parseEnvironmentsFlag(flags.environments);
    const leasePolicy = yield* loadLeasePolicy(flags.leasePolicyPath);
    const expectFingerprintHex = yield* parseFingerprintFlag(
      "--expect-fingerprint",
      flags.expectFingerprint,
    );
    const context = yield* openProject(flags);
    const summary = yield* serverGrantOp({
      client: context.client,
      verified: context.verified,
      environmentIds,
      leasePolicy,
      expectFingerprintHex,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
      recipient: context.recipient,
      resync: context.resync,
    });
    const policyNote =
      summary.leasePolicyCount === 0
        ? "no lease path (lease_policy is empty)"
        : `lease_policy has ${countNoun(summary.leasePolicyCount, "element")}`;
    yield* io.log(
      `Done: disclosure to server key ${summary.serverKeyFingerprintHex} is active (scope=${summary.scopeEnvironmentIds.join(", ")}, ${policyNote}). Backfill: ${summary.registered} newly registered, ${summary.alreadyRegistered} already registered`,
    );
    // §9: 開示中であることを常時明示する(失効経路もその場で案内する)
    yield* io.log(
      "Note: the epoch DEKs of environments in the disclosure scope are disclosed to the server (CRYPTO_SPEC §9). To withdraw, run maruhi server revoke (it forces a rotation of every environment — §7)",
    );
  });
}

/** `maruhi server revoke [--fingerprint <hex>]`(§7 / §9)。 */
function serverRevokeCommand(
  flags: CommonFlags & { readonly fingerprint?: string | undefined },
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const fingerprintHex = yield* parseFingerprintFlag("--fingerprint", flags.fingerprint);
    // 収束系コマンド: 未収束義務の常時警告は抑制(自分の sweep 報告が担う)
    const context = yield* openProject(flags, { quietMandateWarning: true });
    // 1 環境のローテーション(PR-1 の envRotateOp の再利用 — sweepRotateFor)
    const summary = yield* serverRevokeOp({
      client: context.client,
      verified: context.verified,
      fingerprintHex,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
      resync: context.resync,
      rotate: sweepRotateFor(context, REVOKE_ROTATION_REASON),
    });
    yield* reportRevokeAppend(io, summary);
    const exitCode = yield* reportSweepOutcome(summary, {
      rerunCommand: "maruhi server revoke",
      alreadyRotatedBasis: "the revocation",
    });
    if (exitCode === 0) {
      yield* io.log("Done: the revocation and the rotation of every environment completed");
    }
    // 要ローテーションフラグの件数と導線(B2 — AUDIT_SPEC §4.1 の revoke 変種)
    if (summary.serverKeyFingerprintHex !== null) {
      yield* reportRotationFlagCount({
        client: context.client,
        projectId: context.projectId,
        target: { kind: "server", fingerprintHex: summary.serverKeyFingerprintHex },
      });
    }
    return exitCode;
  });
}

/** revoke の追記結果の報告(sweep 共通部分は reportSweepOutcome が受け持つ)。 */
function reportRevokeAppend(io: CliIoShape, summary: RevokeSummary): Effect.Effect<void, CliError> {
  if (summary.appended) {
    return io.log(
      `Appended revoke_server to the chain (FP=${summary.serverKeyFingerprintHex ?? ""}). Forcing a rotation of every environment (§7)`,
    );
  }
  if (summary.serverKeyFingerprintHex !== null) {
    // 対象の grant はあったが、CAS 競合の再同期で既に失効済みと判明した
    // (並行 revoke)。誰かが同じ鍵を失効させた事実は運用上重要なので明示する
    return io.log(
      `The targeted grant (FP=${summary.serverKeyFingerprintHex}) was already revoked by a concurrent run — skipping the append and proceeding to rotate every environment (§7)`,
    );
  }
  return io.log(
    "No active grant — resuming the post-revocation rotation of every environment from where it left off (crash recovery)",
  );
}

/** `maruhi invite create --role <r>`(§15-2 発行 + §15-3 リンク組み立て)。 */
function inviteCreateCommand(
  flags: CommonFlags & { readonly role?: string | undefined },
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    if (!isInviteRole(flags.role)) {
      return yield* Effect.fail(
        usageError(
          `Specify --role (${INVITE_ROLES.join(" | ")} — owner cannot be granted via an invite. AUTH_SPEC §15-1)`,
        ),
      );
    }
    // リンク材料(ヘッド・自分の FP)はチェーン導出 — master 鍵は不要
    const context = yield* openMetadataProject(flags);
    yield* inviteCreateOp({
      client: context.client,
      verified: context.verified,
      origin: context.origin,
      role: flags.role,
      sessionUserId: context.session.userId,
    });
  });
}

/** `invite accept` の入力拒否理由 → usage 文言。 */
function acceptInputRejectionMessage(reason: InviteInputRejection): string {
  if (reason === "unsupported-version") {
    return "This invite link's format version is not supported (update the maruhi CLI)";
  }
  if (reason === "missing-or-invalid-fragment-params") {
    return "The invite link's fragment (after #) is incomplete or invalid. Check that the link was copied without truncation (a broken link cannot be accepted without its anchor)";
  }
  return "Specify an invite link (…/invite#v=1&…) or an invite token (maruhi_inv_…). Quote the link so the shell does not interpret it";
}

/**
 * `invite accept` の入力(リンク | トークン + --project)の解決。
 *
 * 入力は引数層から `Redacted` のまま届く(リンクはトークン生値を内包する)。
 * 構文解釈は invite-link.ts の境界に任せ、ここでは剥がさない。
 */
function resolveAcceptTarget(
  rawTarget: Redacted.Redacted<string>,
  projectFlag: string | undefined,
): Effect.Effect<AcceptTarget, CliError> {
  const parsed = parseInviteAcceptInput(rawTarget);
  if (parsed.kind === "rejected") {
    return Effect.fail(usageError(acceptInputRejectionMessage(parsed.reason)));
  }
  if (parsed.kind === "token") {
    // 受諾署名(CRYPTO_SPEC §6.5)は project_id を署名対象に含むため、リンク
    // なしの受諾にはプロジェクト ID の帯域外供給が必須(config の
    // defaultProject へはフォールバックしない — 別プロジェクトへの署名を
    // 黙って作らない)
    if (projectFlag === undefined) {
      return Effect.fail(
        usageError(
          "Accepting with a raw token requires --project <project ID> (the acceptance signature binds the project ID — CRYPTO_SPEC §6.5). Not needed when accepting with an invite link",
        ),
      );
    }
    if (!isProjectId(projectFlag)) {
      return Effect.fail(usageError("Invalid project ID (64 hex digits)"));
    }
    return Effect.succeed({ kind: "token", token: parsed.token, projectId: projectFlag });
  }
  if (projectFlag !== undefined && projectFlag !== parsed.link.projectId) {
    return Effect.fail(
      usageError(
        "--project does not match the link's p (project ID). --project is not needed when accepting with a link",
      ),
    );
  }
  return Effect.succeed({ kind: "link", link: parsed.link });
}

/** `maruhi invite accept <link|token>`(§15-3 / CRYPTO_SPEC §6.3 (a) / §6.5)。 */
function inviteAcceptCommand(flags: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly target: Redacted.Redacted<string>;
  readonly inviterFingerprint?: string | undefined;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const target = yield* resolveAcceptTarget(flags.target, flags.project);
    const expectInviterFingerprintHex = yield* parseUserFingerprintFlag(
      "--inviter-fingerprint",
      flags.inviterFingerprint,
    );
    const context = yield* openSession(flags.server);
    yield* inviteAcceptOp({
      client: context.client,
      session: context.session,
      target,
      expectInviterFingerprintHex,
      keyGenerate: keyGenerateOp({ session: context.session, client: context.client }),
    });
  });
}

/** `maruhi invite list`(受諾ブロックの §6.5 独立検証 + 発行ピン突合)。 */
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
    // 署名検証失敗・ピン不一致は「読み取りの成功」ではなく証拠の検出 — 0 に
    // しない(スクリプトが健全性チェックとして使える)
    return summary.integrityFailures > 0 ? 1 : 0;
  });
}

/**
 * sweep 結果(§7 の全環境走査)の報告と終了コードの導出(server revoke /
 * member remove / change-role 共通)。
 *
 * `alreadyRotatedBasis` は「どの時点より後のエポックなら回転済みと確認したか」
 * の言い分け(revoke = 失効・member = 義務エントリ)。報告の形と §7 の
 * 「rotate の失敗を黙ってスキップしない」規律は 1 か所に保つ — 二重に持つと
 * 片方だけ直る。
 */
function reportSweepOutcome(
  sweep: SweepOutcome & { readonly skippedDeleted: readonly string[] },
  options: { readonly rerunCommand: string; readonly alreadyRotatedBasis: string },
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
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
      // §7: active と信じる環境の rotate 拒否を黙ってスキップしない(悪意サーバーに
      // よる選択的なローテーション阻止を不可視にしない)
      yield* io.logError(
        `Warning: rotation of environment ${displayText(failure.environmentId)} failed: ${failure.message} — resolve the cause and re-run ${options.rerunCommand} to resume (if the environment was deleted, check for a verified deletion statement)`,
      );
      exitCode = 1;
    }
    if (sweep.rotated.some((item) => item.summary.mode === "rotated")) {
      // アンカー更新の提案(session-25 §8)— sweep 全体で 1 行だけ出す
      yield* io.logError(`Note: ${ANCHOR_REFRESH_PROPOSAL}`);
    }
    return exitCode;
  });
}

/** `maruhi member add [invite-id]`(§6.5 の相互確認 + add_member + バックフィル)。 */
function memberAddCommand(
  flags: CommonFlags & {
    readonly invite?: string | undefined;
    readonly expectFingerprint?: string | undefined;
  },
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const expectFingerprintHex = yield* parseUserFingerprintFlag(
      "--expect-fingerprint",
      flags.expectFingerprint,
    );
    const context = yield* openProject(flags);
    const store = yield* PinStore;
    const loaded = yield* store.load(context.projectId);
    const summary = yield* memberAddOp({
      client: context.client,
      verified: context.verified,
      inviteId: flags.invite ?? null,
      expectFingerprintHex,
      pins: loaded.pins,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
      recipient: context.recipient,
      resync: context.resync,
    });
    return yield* reportMemberAdd(io, summary);
  });
}

/** member add の結果報告と終了コード(バックフィル失敗 = 部分完了)。 */
function reportMemberAdd(
  io: CliIoShape,
  summary: MemberAddSummary,
): Effect.Effect<number, CliError> {
  return Effect.gen(function* () {
    const repaired =
      summary.repaired > 0 ? `, ${countNoun(summary.repaired, "old-key wrap")} repaired` : "";
    yield* io.log(
      `Added member ${displayText(summary.targetUserId)} (role=${summary.role}). Backfill: ${summary.registered} newly registered, ${summary.alreadyRegistered} already registered${repaired}`,
    );
    if (summary.failed.length === 0) {
      yield* io.log(
        "Done: DEK wraps for every environment × every epoch were distributed to the new member (CRYPTO_SPEC §7). Have the new member run maruhi pull and confirm they can decrypt",
      );
      return 0;
    }
    for (const failure of summary.failed) {
      yield* io.logError(
        `Warning: backfill for environment ${displayText(failure.environmentId)} failed: ${failure.message} — resolve the cause and re-run maruhi member add to resume (409 converges as already-registered)`,
      );
    }
    return 1;
  });
}

/** `maruhi member remove <user-id>`(§7 — 全環境の強制ローテーションを伴う)。 */
function memberRemoveCommand(
  flags: CommonFlags & { readonly target: string },
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    // 収束系コマンド: 未収束義務の常時警告は抑制(自分の sweep 報告が担う)
    const context = yield* openProject(flags, { quietMandateWarning: true });
    const summary = yield* memberRemoveOp({
      client: context.client,
      verified: context.verified,
      targetUserId: flags.target,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
      resync: context.resync,
      rotate: sweepRotateFor(context, MEMBER_REMOVED_ROTATION_REASON),
    });
    if (summary.appended) {
      yield* io.log(
        `Appended remove_member to the chain (target=${displayText(summary.targetUserId)}). Forcing a rotation of every environment (CRYPTO_SPEC §7)`,
      );
    } else {
      yield* io.log(
        "The target was already removed — skipping the append and resuming the rotation of every environment (crash recovery)",
      );
    }
    const exitCode = yield* reportSweepOutcome(summary, {
      rerunCommand: "maruhi member remove",
      alreadyRotatedBasis: "the mandate entry",
    });
    if (exitCode === 0) {
      yield* io.log("Done: the member removal and the rotation of every environment completed");
    }
    // 要ローテーションフラグの件数と導線(B2 — AUDIT_SPEC §4.1。ローテーションは
    // 新しい DEK を配るだけで、既読の値そのものは取り消せない)
    yield* reportRotationFlagCount({
      client: context.client,
      projectId: context.projectId,
      target: { kind: "member", userId: summary.targetUserId },
    });
    return exitCode;
  });
}

/** `maruhi member change-role <user-id> --role <r>`(降格は §7 のローテーション義務)。 */
function memberChangeRoleCommand(
  flags: CommonFlags & { readonly target: string; readonly role?: string | undefined },
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    if (!isMemberRole(flags.role)) {
      return yield* Effect.fail(usageError(`Specify --role (${MEMBER_ROLES.join(" | ")})`));
    }
    // 収束系コマンド: 未収束義務の常時警告は抑制(降格の sweep 報告が担う)
    const context = yield* openProject(flags, { quietMandateWarning: true });
    const summary = yield* memberChangeRoleOp({
      client: context.client,
      verified: context.verified,
      targetUserId: flags.target,
      newRole: flags.role,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
      resync: context.resync,
      rotate: sweepRotateFor(context, ROLE_DEMOTED_ROTATION_REASON),
    });
    if (summary.appended) {
      yield* io.log(
        `Appended change_role to the chain (target=${displayText(summary.targetUserId)}, role=${summary.newRole})`,
      );
    } else {
      yield* io.log("The target already has the specified role — nothing was appended");
    }
    if (summary.sweep === null) {
      yield* io.log("Done: the role was changed (no rotation mandate)");
      return 0;
    }
    yield* io.log(
      "Demotion below member forces a rotation of every environment (CRYPTO_SPEC §7 — epoch-anchor soundness)",
    );
    const exitCode = yield* reportSweepOutcome(summary.sweep, {
      rerunCommand: "maruhi member change-role",
      alreadyRotatedBasis: "the mandate entry",
    });
    if (exitCode === 0) {
      yield* io.log("Done: the demotion and the rotation of every environment completed");
    }
    return exitCode;
  });
}

/**
 * コマンド本体。ハンドラは `Effect<void>` しか返せない(`Command.runWith` が
 * 値を捨てる)ので、子プロセスの終了コードは `onExitCode` で持ち出す。
 */
function makeRootCommand(onExitCode: (code: number) => void) {
  const pull = Command.make("pull", pullConfig, (values) =>
    Effect.gen(function* () {
      const io = yield* CliIo;
      // 値の表示拒否はコマンド入口 = **復号前**に検査する(環境全体を復号して
      // から拒否しない = 復号された平文をそもそも作らない)。復号後の
      // showValues にも同じ検査があり、そちらは防衛線(display.ts)
      if (values.show) {
        yield* ensureValueDisplayAllowed;
      }
      const context = yield* openEnvironment(values);
      const pulled: PulledVariables = yield* pullVariables({
        client: context.client,
        verified: context.verified,
        environmentId: context.environmentId,
        recipient: context.recipient,
        resync: context.resync,
        floor: context.floorHandle,
      });
      yield* logWarnings(pulled.warnings);
      yield* io.log(
        `Sync and verification OK: ${countNoun(pulled.variables.length, "variable")} (environment ${context.environmentId})`,
      );
      for (const variable of pulled.variables) {
        yield* io.log(formatPulledLine(variable));
      }
      // declared(値なしの宣言 — §4.2 レイアウト v2)はメタデータ行として列挙
      // する(値・バージョンは存在しない。schema の詳細は `maruhi schema`)
      for (const declared of pulled.declared) {
        yield* io.log(`${displayText(declared.name)}\t(declared — no value set)`);
      }
      if (values.show) {
        yield* showValues(pulled.variables);
      }
      // 発行契機 (iii)(CRYPTO_SPEC §6.3): pull 成功時の基準チェックポイントの
      // 鮮度検出。提案のみ(自動発行しない)
      yield* proposeCheckpointRefresh(context, { includeAnchor: false });
    }),
  ).pipe(
    Command.withDescription(
      "Sync-check (§6.3) + distribution verification (§5.1) + decrypt, then print metadata",
    ),
  );

  const run = Command.make("run", runConfig, (values) =>
    Effect.gen(function* () {
      const { command: parsed, ...flags } = values;
      // 通信・復号より前(コマンド本体の先頭)で落とす
      const command = yield* commandAfterTerminator(parsed);
      const context = yield* openEnvironment(flags);
      const pulled = yield* pullVariables({
        client: context.client,
        verified: context.verified,
        environmentId: context.environmentId,
        recipient: context.recipient,
        resync: context.resync,
        floor: context.floorHandle,
      });
      yield* logWarnings(pulled.warnings);
      // presence fail-fast(設計文書 §1-4 — 裁定 CT / CU): required = true の
      // declared が検証済み集合にあれば、子プロセスを起動せず型付きエラー
      yield* enforceDeclaredPresence(pulled.declared);
      // type は advisory(§14.3-7)— 不一致は警告のみで実行続行
      yield* logWarnings(typeAdvisoryWarnings(pulled.variables));
      // 環境変数名は検証済みステートメント経由(§4.2 / §12-7)。実行制御系
      // 変数名 denylist(run.ts)は検証済み name に適用される防衛層
      onExitCode(yield* runOp({ command, variables: pulled.variables }));
    }),
  ).pipe(
    Command.withDescription(
      "pull + inject decrypted values into the child process environment (memory only) and run the command",
    ),
  );

  const push = Command.make("push", pushConfig, (values) =>
    Effect.gen(function* () {
      const io = yield* CliIo;
      const context = yield* openEnvironment(values);
      // stdin は平文が素の bytes で入ってくる起点。ここで包み、以降は
      // Redacted としてしか流さない(剥がすのは push.ts の暗号境界のみ)
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
        // 値署名(§4.1)/ 作成時のステートメント著者署名(§4.2):
        // writer / author = 自分の内部 user_id、鍵 = master sig 鍵
        writerUserId: context.session.userId,
        signingKey: context.masterKeys.sigKeyPair.privateKey,
        floor: context.floorHandle,
      });
      yield* logWarnings(pushed.warnings);
      yield* io.log(
        `Pushed ${displayText(values.name)} (version=${pushed.version}, epoch=${pushed.epoch})`,
      );
      // 発行契機 (iii)(CRYPTO_SPEC §6.3): push 成功時の基準チェックポイントの
      // 鮮度検出。アンカー更新の提案(session-25 §8)は同じ導線に同梱する
      // (裁定は docs/notes/session-35.md)
      yield* proposeCheckpointRefresh(context, { includeAnchor: true });
    }),
  ).pipe(
    Command.withDescription(
      "Encrypt the value read from stdin and push it (one trailing newline is stripped)",
    ),
  );

  const login = Command.make("login", loginConfig, (values) =>
    Effect.gen(function* () {
      // **どの通信よりも先**に見る。上限は api-schema と共有する
      // (MAX_TOKEN_NAME_LENGTH)。ここで見ないと、長すぎる名前は start の
      // encode 失敗(接続失敗と紛らわしい診断)として現れる
      const tokenName = yield* requireTokenName(values["token-name"]);
      const expiresInDays = yield* requireTokenTtlDays(values["token-ttl-days"]);
      // --show-token は発行した PAT の生値を端末へ出す(AUTH_SPEC §6 の
      // 「発行時の端末表示 1 箇所」— 裁定 CK)。表示可否は値表示と同じ
      // fail-closed の 2 層ゲート(ADR-0016 決定 7)で、**どの通信よりも前**に
      // 判定する: 拒否される環境でブラウザ承認を完走させると、同名ローテー
      // ションで旧トークンだけ失効し、新しい生値は得られないまま終わる
      // (置き換え対象の CI トークンを壊すだけの最悪の失敗形)
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
        // 既定名の判定は解決後の実名で行う(明示的に cli:<hostname> を渡した
        // 場合も既定名扱い — 素の再ログインが同名ローテーションになる事実で
        // 分岐する。裁定 CM / PR #108 Bugbot 指摘)
        tokenNameIsDefault: tokenName === `cli:${hostname()}`,
        ...(expiresInDays === undefined ? {} : { expiresInDays }),
        ...(minIntervalSeconds === undefined ? {} : { minIntervalSeconds }),
      });
    }),
  ).pipe(
    Command.withDescription(
      "Log in by approving the request in your browser, and store the maruhi token in the OS keychain",
    ),
  );

  const logout = Command.make("logout", logoutConfig, (values) =>
    Effect.gen(function* () {
      const store = yield* ConfigStore;
      const config = yield* store.load;
      const origin = yield* resolveServerOrigin(values.server, config);
      yield* logoutOp({ origin });
    }),
  ).pipe(Command.withDescription("Revoke this token and remove it from the OS keychain"));

  const rotationList = Command.make("list", rotationListConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openMetadataProject(values);
      onExitCode(yield* rotationListOp(context));
    }),
  ).pipe(Command.withDescription("List currently-active rotation flags (AUDIT_SPEC §4.1)"));

  const rotationDismiss = Command.make("dismiss", rotationDismissConfig, (values) =>
    Effect.gen(function* () {
      // 対象の形式はネットワークより先に検査する
      const environmentId = values.env;
      if (environmentId !== undefined && !isEnvironmentId(environmentId)) {
        return yield* Effect.fail(usageError(ENV_FLAG_SHAPE_MESSAGE));
      }
      const variableId = values.variable;
      if (variableId !== undefined && !isVariableId(variableId)) {
        return yield* Effect.fail(
          usageError("Invalid variableId (see maruhi rotation list for the current targets)"),
        );
      }
      // 要求の形(--all と変数 id の矛盾・対象の欠落)も通信より前に確定する
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
      "Dismiss rotation flags without rotating (an explicit acceptance of risk — admin)",
    ),
  );

  // list / dismiss とも master 鍵を要求しない(フラグは非機密メタデータで、
  // 名前解決も検証済みステートメントの読み取りのみ — project verify と同じ
  // 鍵なしクラス)。dismiss の権限(admin 以上 × admin スコープ)はサーバー側が
  // 強制する
  const rotation = Command.make("rotation").pipe(
    Command.withDescription("Manage rotation flags (list / dismiss — AUDIT_SPEC §4.1)"),
    Command.withSubcommands([rotationList, rotationDismiss]),
  );

  /**
   * audit list の本体(bare `maruhi audit` と `maruhi audit list` が共有する)。
   * master 鍵を要求しない(監査行は非機密メタデータ — rotation list と同じ
   * 鍵なしクラス)。可視性クラス・invite.* の権限軸はサーバー側が強制する。
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
      onExitCode(yield* auditListOp(context, page, filters));
    });

  const auditList = Command.make("list", auditListConfig, runAuditList).pipe(
    Command.withDescription(
      "List audit events, cross-checking chain.* mirror rows (AUDIT_SPEC §7)",
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
  ).pipe(Command.withDescription("List invite.* audit events (chain-role admin)"));

  const auditSelf = Command.make("self", auditSelfConfig, (values) =>
    Effect.gen(function* () {
      const page = yield* parseAuditPage(values.limit, values.before);
      const context = yield* openSession(values.server);
      onExitCode(yield* auditSelfOp(context, page));
    }),
  ).pipe(Command.withDescription("List your own account audit events (AUDIT_SPEC §3.1)"));

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
      "Verify the chain ↔ mirror bijection (detects missing / forged / altered rows)",
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
      "Recompute the audit-head hash column and reconcile notarized checkpoints (effective admin — AUDIT_SPEC §6)",
    ),
  );

  // **bare `maruhi audit` = list**(現行仕様の維持 — 第 3 段階の裁定)。
  // 親自身が list の宣言とハンドラを持つ(実測: ハンドラ付き親 +
  // withSubcommands で、bare 親はハンドラを実行し、サブコマンド指定時は
  // 子だけが走る。不明なサブコマンドは UnknownSubcommand で exit 2)
  const audit = Command.make("audit", auditListConfig, runAuditList).pipe(
    Command.withDescription(
      "View and verify audit events (list / invites / self / verify / reconcile — AUDIT_SPEC §7). Bare `maruhi audit` runs list",
    ),
    Command.withSubcommands([auditList, auditInvites, auditSelf, auditVerify, auditReconcile]),
  );

  const keyGenerate = Command.make("generate", keyGenerateConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openSession(values.server);
      yield* keyGenerateOp({ session: context.session, client: context.client });
    }),
  ).pipe(Command.withDescription("Generate the master keypair and store it in the OS keychain"));

  const keyShow = Command.make("show", keyShowConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openSession(values.server);
      yield* keyShowOp({ session: context.session, client: context.client });
    }),
  ).pipe(Command.withDescription("Print the public keys and fingerprint (never the private keys)"));

  const keyRecover = Command.make("recover", keyRecoverConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openSession(values.server);
      yield* recoverMasterKeyOp({ session: context.session, client: context.client });
    }),
  ).pipe(Command.withDescription("Restore the master key from a recovery code (CRYPTO_SPEC §8)"));

  const keyRecovery = Command.make("recovery", keyRecoveryConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openSession(values.server);
      const masterKeys = yield* loadMasterKeys(context.session);
      yield* issueRecoveryCodeOp({
        session: context.session,
        client: context.client,
        masterKeys,
      });
    }),
  ).pipe(Command.withDescription("Issue (or reissue) the recovery code (CRYPTO_SPEC §8)"));

  const key = Command.make("key").pipe(
    Command.withDescription(
      "Manage the master keypair (generate / show / recover / recovery — CRYPTO_SPEC §3 / §8)",
    ),
    Command.withSubcommands([keyGenerate, keyShow, keyRecover, keyRecovery]),
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
  ).pipe(
    Command.withDescription(
      "Create a project (sign and submit the genesis entry — AUTH_SPEC §11-3)",
    ),
  );

  const projectList = Command.make("list", projectListConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openSession(values.server);
      yield* projectListOp({ client: context.client });
    }),
  ).pipe(
    Command.withDescription(
      "List projects where you are a chain-derived member (server-reported — AUTH_SPEC §11-5)",
    ),
  );

  const projectVerifyCommand = Command.make("verify", projectVerifyConfig, (values) =>
    projectVerify(values.server, values.project),
  ).pipe(
    Command.withDescription(
      "Verify the chain, local floor, and invite anchor, then print the project state",
    ),
  );

  const projectAnchor = Command.make("anchor", projectAnchorConfig, (values) =>
    Effect.gen(function* () {
      const io = yield* CliIo;
      // 前段は verify と同じ鍵なしクラス(チェーン同期 + §6.3 検査 + 床 +
      // 招待アンカーの機械照合)— アンカーは検証済みビューからだけ作る
      const context = yield* openMetadataProject({
        server: values.server,
        project: values.project,
      });
      // stdout はコマンドの出力(アンカー JSON)だけ(決定 9): リダイレクトで
      // そのままリポジトリへコミットできる。内容は非機密(ハッシュ・連番・
      // エポック番号のみ — anchor.ts)
      yield* io.log(formatRepositoryAnchor(buildRepositoryAnchor(context.verified)).trimEnd());
    }),
  ).pipe(
    Command.withDescription(
      "Print the repository anchor JSON — commit it and pass to `ci run --anchor` (CRYPTO_SPEC §6.3)",
    ),
  );

  const projectCheckpoint = Command.make("checkpoint", projectCheckpointConfig, (values) =>
    Effect.gen(function* () {
      const io = yield* CliIo;
      // 発行はチェーン追記(Ed25519 署名)を伴うので master 鍵を要求する。
      // 検証済みビューの構築(全環境の検証済み pull)はチェックポイントの
      // 材料そのもの — 値の取得は var.read として正しく記録される(明示操作)
      const context = yield* openProject({ server: values.server, project: values.project });
      // 環境床ハンドルは先に解決しておく(issueCheckpoint の R を CliIo に保つ)
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
        yield* io.logError(
          `Warning: ${countNoun(summary.skippedEnvironmentIds.length, "environment")} could not be covered (${summary.skippedEnvironmentIds.map(displayText).join(", ")}). Re-run maruhi project checkpoint later to cover them`,
        );
      }
    }),
  ).pipe(
    Command.withDescription(
      "Notarize the verified data state (and, with effective admin permission, the audit head) onto the chain (CRYPTO_SPEC §6.3)",
    ),
  );

  const project = Command.make("project").pipe(
    Command.withDescription("Manage projects (init / list / verify / anchor / checkpoint)"),
    Command.withSubcommands([
      projectInit,
      projectList,
      projectVerifyCommand,
      projectAnchor,
      projectCheckpoint,
    ]),
  );

  const ciRun = Command.make("run", ciRunConfig, (values) =>
    Effect.gen(function* () {
      const { command: parsed, ...flags } = values;
      // 通信・鍵生成より前(コマンド本体の先頭)で落とす(run と同じ `--` 規律)
      const command = yield* commandAfterTerminator(parsed);
      onExitCode(yield* ciRunCommand({ ...flags, command }));
    }),
  ).pipe(
    Command.withDescription(
      "Lease the environment via OIDC (no login, no keychain), verify it, and run the command with injected values (CRYPTO_SPEC §9.1)",
    ),
  );

  const ci = Command.make("ci").pipe(
    Command.withDescription(
      "Workload-lease commands for CI jobs (run — CRYPTO_SPEC §9.1 / AUTH_SPEC §14)",
    ),
    Command.withSubcommands([ciRun]),
  );

  const configGet = Command.make("get", configGetConfig, (values) =>
    Effect.gen(function* () {
      const io = yield* CliIo;
      const store = yield* ConfigStore;
      const configKey = yield* requireConfigKey(values.key);
      const config = yield* store.load;
      // stdout はコマンドの出力(値)だけ: `V=$(maruhi config get server)` が
      // 値以外を捕まえない(決定 9)
      yield* io.log(config[configKey] ?? "");
    }),
  ).pipe(Command.withDescription("Print one non-secret config value"));

  const configSet = Command.make("set", configSetConfig, (values) =>
    Effect.gen(function* () {
      const io = yield* CliIo;
      const store = yield* ConfigStore;
      const configKey = yield* requireConfigKey(values.key);
      // 壊れた設定ファイルは set で作り直せるようにする(非機密のみの
      // ファイルなので破棄してよい — CLI 内から復旧不能にしない)。
      // ただし既存設定の喪失を伴うため、無言では飲まず警告を出す。
      // 作り直してよいのは**内容の破損**のみ(deepsec B2): 読み取り自体の失敗
      // (EACCES / EISDIR / EIO 等)は読めなかっただけの既存設定を黙って
      // 置換することになるため、そのまま失敗させる
      const config = yield* store.load.pipe(
        Effect.catch((error) =>
          error instanceof ConfigFileCorruptError
            ? Effect.gen(function* () {
                yield* io.logError(
                  `Warning: ${toCliError(error).message} — discarding the existing config and recreating it with only this key`,
                );
                return {};
              })
            : Effect.fail(error),
        ),
      );
      yield* store.save({ ...config, [configKey]: values.value });
      yield* io.log(`Set ${configKey}`);
    }),
  ).pipe(Command.withDescription("Set one non-secret config value"));

  const config = Command.make("config").pipe(
    Command.withDescription(
      "Manage non-secret settings (get / set); secrets are never stored here",
    ),
    Command.withSubcommands([configGet, configSet]),
  );

  const schemaSet = Command.make("set", schemaSetConfig, (values) =>
    Effect.gen(function* () {
      const io = yield* CliIo;
      // 欄指定の解釈はネットワークより先(部分更新 §1-2 — 未指定 = keep、
      // 空へ戻すのは明示フラグのみ)
      const updates = yield* parseSchemaFieldUpdates(values);
      // エントロピー警告(裁定 CW — fail-closed)は通信・署名より前に判定する
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
      "Set a variable's schema fields (type / required / description — a partial update). A missing name is created as a declared variable (no value)",
    ),
  );

  // **bare `maruhi schema` = 表示**(設計文書 §1-1 — audit と同じハンドラ付き親)
  const schema = Command.make("schema", schemaShowConfig, runSchemaShow).pipe(
    Command.withDescription(
      "Show the environment's declared variable schema (names / types / required / status / descriptions — no values). Bare `maruhi schema` shows; `schema set` writes",
    ),
    Command.withSubcommands([schemaSet]),
  );

  const envCreate = Command.make("create", envCreateConfig, (values) =>
    Effect.gen(function* () {
      // 形式は宣言(NonBlank)を通った後の追加検査。ネットワークより前に見る
      const environmentId = yield* requireEnvironmentId(
        values["environment-id"],
        "maruhi env create dev",
      );
      yield* envCreateCommand(values, environmentId);
    }),
  ).pipe(Command.withDescription("Create an environment (compound request — §12-4)"));

  const envRotate = Command.make("rotate", envRotateConfig, (values) =>
    Effect.gen(function* () {
      const environmentId = yield* requireEnvironmentId(
        values["environment-id"],
        "maruhi env rotate dev",
      );
      const { reason, "new-epoch": newEpoch, "init-manifest": initManifest, ...flags } = values;
      onExitCode(
        yield* envRotateCommand({ ...flags, reason, newEpoch, initManifest }, environmentId),
      );
    }),
  ).pipe(
    Command.withDescription(
      "Rotate the environment's epoch DEK, or resume incomplete re-encryption (§7)",
    ),
  );

  const envDiff = Command.make("diff", envDiffConfig, (values) =>
    Effect.gen(function* () {
      const environmentId = yield* requireEnvironmentId(
        values["environment-id"],
        "maruhi env diff dev prod",
      );
      const otherEnvironmentId = yield* requireEnvironmentId(
        values["other-environment-id"],
        "maruhi env diff dev prod",
      );
      if (otherEnvironmentId === environmentId) {
        // 同じ環境どうしの比較は必ず空になる = 要求そのものが書き間違い。
        // 指定値は出さない(位置引数には値が書かれうる)
        return yield* Effect.fail(
          usageError(
            "The same environment ID was written twice. Specify two different environments to compare",
          ),
        );
      }
      yield* envDiffCommand(values, environmentId, otherEnvironmentId);
    }),
  ).pipe(
    Command.withDescription("Compare the variable-name sets of two environments (names only)"),
  );

  // gunshi は 1 段(サブコマンド + positional の action)しか組めないため、
  // maruhi は create / rotate / diff を**位置引数**にしていた。その結果
  // 1 つの引数表に全操作のフラグが同居し、「その操作に適用されない
  // オプション」の拒否(cli.ts の ENV_ACTION_FLAGS / optionRestrictedTo)を
  // 自前で書く必要があった。入れ子のサブコマンドはその機構ごと不要にする
  const env = Command.make("env").pipe(
    Command.withDescription("Manage environments (create / rotate / diff)"),
    Command.withSubcommands([envCreate, envRotate, envDiff]),
  );

  const serverGrant = Command.make("grant", serverGrantConfig, (values) =>
    serverGrantCommand({
      server: values.server,
      project: values.project,
      environments: values.environments,
      leasePolicyPath: values["lease-policy"],
      expectFingerprint: values["expect-fingerprint"],
    }),
  ).pipe(
    Command.withDescription(
      "Disclose epoch DEKs of selected environments to the server (CRYPTO_SPEC §9)",
    ),
  );

  const serverRevoke = Command.make("revoke", serverRevokeConfig, (values) =>
    Effect.gen(function* () {
      onExitCode(
        yield* serverRevokeCommand({
          server: values.server,
          project: values.project,
          fingerprint: values.fingerprint,
        }),
      );
    }),
  ).pipe(
    Command.withDescription(
      "Revoke a server disclosure and force-rotate every environment (§7 / §9)",
    ),
  );

  const server = Command.make("server").pipe(
    Command.withDescription("Manage selective disclosure to the server (grant / revoke — §9)"),
    Command.withSubcommands([serverGrant, serverRevoke]),
  );

  const inviteCreate = Command.make("create", inviteCreateConfig, (values) =>
    inviteCreateCommand(values),
  ).pipe(Command.withDescription("Issue an invite and build the invite link (AUTH_SPEC §15)"));

  const inviteAccept = Command.make("accept", inviteAcceptConfig, (values) =>
    inviteAcceptCommand({
      server: values.server,
      project: values.project,
      target: values.target,
      inviterFingerprint: values["inviter-fingerprint"],
    }),
  ).pipe(Command.withDescription("Accept an invite link or token (§15-3 / CRYPTO_SPEC §6.5)"));

  const inviteList = Command.make("list", inviteListConfig, (values) =>
    Effect.gen(function* () {
      onExitCode(yield* inviteListCommand(values));
    }),
  ).pipe(
    Command.withDescription(
      "List invites, independently verifying acceptance blocks (§6.5) and issuance pins",
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
    Command.withDescription(
      "Manage invites (create / accept / list / revoke — AUTH_SPEC §15 / CRYPTO_SPEC §6.5)",
    ),
    Command.withSubcommands([inviteCreate, inviteAccept, inviteList, inviteRevoke]),
  );

  const memberAdd = Command.make("add", memberAddConfig, (values) =>
    Effect.gen(function* () {
      onExitCode(
        yield* memberAddCommand({
          server: values.server,
          project: values.project,
          invite: values["invite-id"],
          expectFingerprint: values["expect-fingerprint"],
        }),
      );
    }),
  ).pipe(
    Command.withDescription(
      "Add an accepted invitee as a member (mutual confirmation §6.5 + add_member + backfill)",
    ),
  );

  const memberRemove = Command.make("remove", memberRemoveConfig, (values) =>
    Effect.gen(function* () {
      onExitCode(
        yield* memberRemoveCommand({
          server: values.server,
          project: values.project,
          target: values["user-id"],
        }),
      );
    }),
  ).pipe(
    Command.withDescription("Remove a member and force-rotate every environment (CRYPTO_SPEC §7)"),
  );

  const memberChangeRole = Command.make("change-role", memberChangeRoleConfig, (values) =>
    Effect.gen(function* () {
      onExitCode(
        yield* memberChangeRoleCommand({
          server: values.server,
          project: values.project,
          target: values["user-id"],
          role: values.role,
        }),
      );
    }),
  ).pipe(
    Command.withDescription(
      "Change a member's role (demotion below member forces a rotation — §7)",
    ),
  );

  const member = Command.make("member").pipe(
    Command.withDescription(
      "Manage members (add / remove / change-role — CRYPTO_SPEC §6.2 / §6.5 / §7)",
    ),
    Command.withSubcommands([memberAdd, memberRemove, memberChangeRole]),
  );

  return Command.make("maruhi").pipe(
    Command.withSubcommands([
      login,
      logout,
      pull,
      run,
      push,
      ci,
      env,
      server,
      invite,
      member,
      key,
      project,
      rotation,
      audit,
      config,
      schema,
    ]),
  );
}

/* -------------------------------------------------------------------------- */
/* ランナー                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * 引数層が使う Effect の環境のうち、**maruhi が使わない**もの。
 *
 * ファイル・端末・子プロセスは maruhi 自身のサービス(ConfigStore /
 * CliIo.promptLine / ProcessRunner)が受け持つ。引数層へ実装を渡すと、
 * 宣言していない対話経路・出力経路(Prompt / wizard)が動く余地を残すので、
 * ここでは**死ぬ実装**を置く(決定 5 と同じ理由)。
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
 * ヘルプ・診断の宛先。**全メソッド**を `CliIo.logError`(= stderr)へ寄せる
 * (決定 9)。log / error だけの部分上書きだと、上流が描画メソッドを増やした
 * ときに実 stdout へ素通りする穴ができる。
 *
 * `Console` のメソッドは同期(`void`)なので、ここでは行を溜めて実行後に
 * `CliIo` へ流す(Effect を `runSync` で割り込ませない)。
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
 * argv を `Stdio` へ載せ替える。
 *
 * runCli は argv を引数で受け取る(テストが実行ごとに argv を差し替えるため)
 * ので、`--` の判定(`commandAfterTerminator`)が見る `Stdio.args` も**同じ
 * 配列**にする。本番の `Stdio.args` は `process.argv.slice(2)` = bin.ts が
 * runCli へ渡すものと同一なので、値は変わらず出所だけが 1 つになる。
 */
function withArgs(stdio: Stdio.Stdio, argv: readonly string[]): Stdio.Stdio {
  return Stdio.make({ ...stdio, args: Effect.succeed([...argv]) });
}

/** 実行の失敗を maruhi の語彙で 1 行にする(上流の英文を素通しにしない)。 */
function reportFailure(io: CliIoShape, cause: Cause.Cause<unknown>): Effect.Effect<void> {
  const failure: unknown = Cause.squash(cause);
  // ShowHelp は effect 側が Formatter 経由で描画済み(Console → stderr)
  if (failure instanceof EffectCliError.ShowHelp) {
    return Effect.void;
  }
  if (failure instanceof CliError) {
    return io.logError(`maruhi: ${failure.message}`);
  }
  // defect(バグ)や上流の未知エラー。**message は出さない**: 打たれた値を
  // 埋め込んだ文面(`Invalid value: <平文>`)でも到達しうるので、制御文字の
  // 中和だけでは規律(打たれた値を診断に出さない)を守れない。無言では飲まず
  // (CLAUDE.md)、型の名前だけを添える(failure.ts の internalErrorKind —
  // gunshi 側の defect 経路と同じ形)
  return io.logError(`maruhi: internal error (${internalErrorKind(failure)})`);
}

/**
 * Runs one of the migrated commands (`pull` / `run` / `env create`) through
 * `effect/unstable/cli` and returns the process exit code.
 *
 * `commandKey` は runCli の振り分けが決めた**解決済みのコマンド段**で、診断の
 * 宛先(どの宣言を名指しするか)に使う。
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
  // ヘルプの分量だけを決める(`--help` を明示した実行は全文、書き方の誤りに
  // 添えるのは使い方 1 行 — 決定 3)。引数の**検査**には一切使わない。
  // `--` の後ろは**子プロセスの引数**なので見ない: `maruhi run stray -- cmd -h`
  // の `-h` は cmd のもので、maruhi へのヘルプ要求ではない
  const terminator = argv.indexOf("--");
  const ownArgs = terminator < 0 ? argv : argv.slice(0, terminator);
  // **bare `maruhi`(引数なし)はヘルプ要求として扱う**(第 3 段階の裁定 —
  // ADR-0016 追記)。gunshi 時代の bare `maruhi` は使い方 + コマンド一覧を
  // exit 0 で出しており、これを維持する。出力先だけは stdout → stderr へ
  // 変わる(決定 9: stdout はコマンドの出力だけ — `maruhi --help` と同じ扱い)。
  // bare の**サブコマンド段**(`maruhi env` 単体)はこれに含めない: そちらは
  // gunshi 時代から書き方の誤り(exit 2)で、teardown が読み分ける
  const bareRoot = ownArgs.length === 0;
  const helpRequested = bareRoot || ownArgs.includes("--help") || ownArgs.includes("-h");
  const versionRequested = ownArgs.includes("--version") || ownArgs.includes("-v");
  // teardown の読み分け材料(cli-teardown.ts): ヘルプ・バージョンの明示が
  // なければ、errors 空の ShowHelp(親コマンド単体)は書き方の誤り(2)
  const infoRequested = helpRequested || versionRequested;

  const program = Effect.gen(function* () {
    const io = yield* CliIo;
    const stdio = yield* Stdio.Stdio;
    const exit = yield* Command.runWith(root, { version: CLI_VERSION })([...argv]).pipe(
      Effect.provideService(Stdio.Stdio, withArgs(stdio, argv)),
      Effect.provideService(Console.Console, collectingConsole(diagnostics)),
      Effect.provide(formatterLayer(commandKey, COMMAND_SPECS, helpRequested)),
      // 組み込みグローバルフラグは --help / --version だけ(決定 5)
      Effect.provide(CliConfig.layer({ builtIns: [GlobalFlag.Help, GlobalFlag.Version] })),
      Effect.provide(unusedEnvironment),
      Effect.exit,
    );
    for (const line of diagnostics) {
      // `--version` の出力だけは**コマンドの出力**(stdout)。`V=$(maruhi
      // --version)` はスクリプトの正当な使い方で、ヘルプ・診断(stderr)とは
      // 役割が違う。失敗した実行(書き方の誤りとの併記)は stderr のまま。
      // `--help` が併記された実行は上流で Help が勝つ = 集めた行はヘルプ本文
      // なので stdout へ流さない(レビュー第 3 巡の指摘)
      yield* versionRequested && !helpRequested && Exit.isSuccess(exit)
        ? io.log(line)
        : io.logError(line);
    }
    if (Exit.isFailure(exit)) {
      yield* reportFailure(io, exit.cause);
    }
    return exit;
  });

  const exit = await Effect.runPromise(program.pipe(Effect.provide(layer)));

  let exitCode = 0;
  // 本番もテストも同じ teardown を通す(ShowHelp の exit 1 → 2 の読み替えが
  // 片方でしか効かない形を作らない — cli-teardown.ts)
  maruhiTeardown(infoRequested)(exit, (code) => {
    exitCode = code;
  });
  // `maruhi run` は子プロセスの終了コードを引き継ぐ。`Command.runWith` は
  // ハンドラの返り値を捨てるため、成功した実行の終了コードだけは持ち出す
  // (エラーではないので Runtime.errorExitCode には載せられない)
  return exitCode === 0 ? commandExitCode : exitCode;
}
