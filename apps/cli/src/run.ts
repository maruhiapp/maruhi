// `maruhi run -- <cmd>`: values are passed only by in-memory injection
// into the child's environment variables (CLAUDE.md's diskless
// invariant). No intermediate path — file, temp file, socket — is
// created. run is allowed even when an agent is detected (it is not a
// value display but a sanctioned consumption path — the task ruling).
//
// The valueless schema's (§4.2 layout v2) fail-fast (design doc §1-4 —
// rulings CT / CU): presence is strict (a required = true declared →
// the child is **never started**, a typed error), types are lenient (an
// advisory check on the plaintext just before injection — a mismatch
// only warns and the run continues §14.3-7). **No error or warning
// wording ever includes the description** (never build an injection
// surface via the logs).

import { Context, Data, Effect, Redacted, Stdio } from "effect";

import { AgentProfileRef } from "./agent-gate.ts";
import { decodeValueText, displayText } from "./display.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { CliIo } from "./io.ts";
import { logNote } from "./notice.ts";
import type { DeclaredVariable, DecryptedVariable } from "./pull.ts";

/**
 * One driven vendor-CLI process (`maruhi sync` — sync-exec.ts). The value
 * travels only on the child's standard input; `command` carries names and
 * options, never a value.
 */
export interface ExecInput {
  readonly command: readonly string[];
  /** Working directory of the child (the vendor CLI resolves its project from it). */
  readonly cwd: string;
  /** Non-secret additions to the inherited environment (vendor telemetry off). */
  readonly extraEnv: Readonly<Record<string, string>>;
  /** Bytes written to the child's stdin, then closed (the only path a value takes). */
  readonly stdin: Redacted.Redacted<Uint8Array>;
}

/** Outcome of one driven process: the exit code and its captured output. */
export interface ExecOutcome {
  readonly exitCode: number;
  /**
   * Combined stdout + stderr of the child, whole and untruncated: cutting it
   * before redaction could leave a suffix of an echoed value that no longer
   * matches. Untrusted: it may echo the value, so callers must scrub it before
   * showing any of it, and only then trim it (sync-exec.ts's
   * scrubVendorOutput).
   */
  readonly output: string;
}

/**
 * One script of the `exec` rotation connector (rotate-connector.ts — PF8).
 * Unlike {@link ExecInput}, `extraEnv` **does** carry secrets: the current
 * credential, its companions and the admin inputs ride into the child's
 * environment by memory injection — the `maruhi run` shape, restricted to
 * the rule's variables. stdin is closed; stdout is the script's answer
 * (the new credential) and comes back as bytes; stderr is the script's
 * commentary and is shown only after scrubbing, only on failure.
 */
export interface CaptureInput {
  readonly command: readonly string[];
  readonly cwd: string;
  readonly extraEnv: Readonly<Record<string, string>>;
}

/** Outcome of one captured script (stdout as bytes — it is the credential, never decoded here). */
export interface CaptureOutcome {
  readonly exitCode: number;
  readonly stdout: Uint8Array;
  readonly stderr: string;
}

/** A captured script that maruhi stopped after it started (its stdout passed the cap) — distinct from a launch failure. */
export class ScriptStoppedError extends Data.TaggedError("ScriptStoppedError")<{
  readonly message: string;
}> {
  constructor(message: string) {
    super({ message });
  }
}

/**
 * A captured script that exited while a process it started kept writing
 * to its stdout: the answer cannot be told from that output (D-14). The
 * script's own exit code is carried — a 0 means the credential may exist
 * at the issuer.
 */
export class ScriptLeftoverError extends Data.TaggedError("ScriptLeftoverError")<{
  readonly exitCode: number;
  readonly message: string;
}> {
  constructor(exitCode: number, message: string) {
    super({ exitCode, message });
  }
}

/** The input of {@link ProcessRunnerShape.run}. */
export interface RunInput {
  readonly command: readonly string[];
  readonly extraEnv: Readonly<Record<string, string>>;
  /**
   * Keep the parent alive for the child's whole life: SIGINT is ignored by
   * the parent (the terminal delivers Ctrl+C to the child too, which owns
   * it) and SIGTERM / SIGHUP are forwarded (`maruhi proxy run` — the proxy
   * the child talks to lives in the parent). Default false = the parent
   * reacts to signals as usual.
   */
  readonly holdSignals?: boolean | undefined;
  /**
   * Run-output redaction (ROADMAP Phase 3 ⑤ — run.ts's `redactionFragments`).
   * When present, the child's stdout and stderr are received on pipes and
   * every occurrence of these byte fragments is replaced with `[redacted]`
   * before being relayed (byte domain, streaming). Absent = stdio inherited
   * (a human terminal).
   */
  readonly redact?: readonly Uint8Array[] | undefined;
}

/** Child-process boundary: inject values, inherit non-maruhi env + stdio. */
export interface ProcessRunnerShape {
  /** Runs `command`, merging `extraEnv` into the inherited environment. Returns the exit code. */
  readonly run: (input: RunInput) => Effect.Effect<number, CliError>;
  /**
   * Runs a vendor CLI with bytes on its stdin and its stdio captured
   * (`maruhi sync`). Fails with a typed error when the command cannot be
   * started (not installed / not on PATH) — never by fetching it.
   */
  readonly exec: (input: ExecInput) => Effect.Effect<ExecOutcome, CliError>;
  /**
   * Runs a script of the `exec` rotation connector with secrets in its
   * environment and its stdout captured as bytes (rotate-connector.ts —
   * PF8). Promise-shaped like the connectors' other seams (`SqlRunner`):
   * the connector frame lives in Promise land. A launch failure (not
   * found, cwd missing) rejects with a message that names only the
   * executable and the directory.
   */
  readonly captureScript: (input: CaptureInput) => Promise<CaptureOutcome>;
  /**
   * Runs the command of a `maruhi agent` session (agent.ts): stdio inherited,
   * the parent's environment passed through **unfiltered** plus `env`.
   * Unlike `run`, the MARUHI_* namespace is not stripped — `env` carries the
   * session handle (`MARUHI_AGENT_SOCK`), and the user's own settings
   * (config dir, token) must stay visible in the shell they are about to
   * work in. No value is injected here. While the child runs, SIGINT is
   * ignored by the parent (the child's shell owns Ctrl+C) and SIGTERM /
   * SIGHUP are forwarded to the child. Returns the exit code.
   */
  readonly runSession: (input: {
    readonly command: readonly string[];
    readonly env: Readonly<Record<string, string>>;
  }) => Effect.Effect<number, CliError>;
}

export class ProcessRunner extends Context.Service<ProcessRunner, ProcessRunnerShape>()(
  "cli/ProcessRunner",
) {}

const MARUHI_ENV_PREFIX = "MARUHI_";

// Execution-control environment variable names are refused for
// injection: a variable name is plaintext metadata unbound by the AAD,
// so a malicious server could swap name↔ciphertext pairs and decryption
// would still succeed. Since a legitimate secret injected under one of
// these names would hand the child process's code execution to it,
// the whole namespace is blocked.
// This list is a best-effort mitigation, not exhaustive — the root fix
// is cryptographically binding the names (a spec-side consideration).
// Comparison is done upper-cased (Windows environment variable names are
// case-insensitive)
const DENIED_ENV_NAMES = new Set([
  "PATH",
  "NODE_OPTIONS",
  "NODE_PATH",
  "NODE_EXTRA_CA_CERTS",
  "NODE_TLS_REJECT_UNAUTHORIZED",
  "NODE_REPL_EXTERNAL_MODULE",
  "SSLKEYLOGFILE",
  "BUN_OPTIONS",
  "BASH_ENV",
  "ENV",
  "IFS",
  "SHELL",
  "ZDOTDIR",
  // Names that can redirect what rc files / config directories point at:
  // swapping HOME makes bash / zsh / various tools read an attacker
  // path's rc / config
  "HOME",
  "USERPROFILE",
  "HOMEDRIVE",
  "HOMEPATH",
  "APPDATA",
  "LOCALAPPDATA",
  "XDG_CONFIG_HOME",
  "XDG_DATA_HOME",
  // bash/zsh variables that become command execution via prompt
  // evaluation (M2). PS1 / PS4 also become execution control via command
  // substitution / xtrace (SHELLOPTS=xtrace + PS4)
  "PROMPT_COMMAND",
  "PS0",
  "PS1",
  "PS4",
  "SHELLOPTS",
  "BASHOPTS",
  "PYTHONSTARTUP",
  "PYTHONPATH",
  "PYTHONHOME",
  "PYTHONUSERBASE",
  "PYTHONWARNINGS",
  "PYTHONBREAKPOINT",
  "PYTHONEXECUTABLE",
  "PYTHON",
  "NODE_GYP_FORCE_PYTHON",
  // Forcing interactive mode (M2): a REPL opens after the child exits and executes the input that follows
  "PYTHONINSPECT",
  "PERL5OPT",
  "PERL5LIB",
  "PERLLIB",
  "RUBYOPT",
  "RUBYLIB",
  "JAVA_TOOL_OPTIONS",
  "_JAVA_OPTIONS",
  "JDK_JAVA_OPTIONS",
  "CLASSPATH",
  "GCONV_PATH",
  // Windows's execution resolution (M2): PATHEXT is extension search,
  // COMSPEC is the shell itself, SYSTEMROOT / WINDIR can redirect the
  // resolution basis of system DLLs / executables
  "PATHEXT",
  "COMSPEC",
  "SYSTEMROOT",
  "WINDIR",
  // What gets launched when the child **starts another program**:
  // LESSOPEN / LESSCLOSE are executed as commands verbatim in `|cmd %s`
  // form, and PAGER family + EDITOR / VISUAL / BROWSER are spawned
  // directly by git, systemctl, and assorted CLIs
  "LESSOPEN",
  "LESSCLOSE",
  "PAGER",
  "MANPAGER",
  "EDITOR",
  "VISUAL",
  "BROWSER",
  // Stand-in programs for passphrase entry: ssh / sudo execute the target
  "SSH_ASKPASS",
  "SUDO_ASKPASS",
  // The interpreter's init hooks / module search. LUA_INIT runs arbitrary
  // Lua, and LUA_PATH / LUA_CPATH redirect require's search targets
  "LUA_INIT",
  "LUA_PATH",
  "LUA_CPATH",
  "PSMODULEPATH",
  // The search targets of glibc / loader behavior and auxiliary data.
  // GLIBC_TUNABLES changes behavior via tunables, and LOCPATH / NLSPATH /
  // TERMINFO / TERMCAP redirect the provenance of binary descriptors
  // (locales, terminal definitions) a process loads
  "GLIBC_TUNABLES",
  "MALLOC_CONF",
  "LOCPATH",
  "NLSPATH",
  "TERMINFO",
  "TERMINFO_DIRS",
  "TERMCAP",
  "CDPATH",
  // shell function autoload and TLS trust roots. The same execution /
  // trust boundary as the existing BASH_ENV / ZDOTDIR /
  // NODE_EXTRA_CA_CERTS
  "FPATH",
  "KSH_ENV",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
  "CURL_CA_BUNDLE",
  "REQUESTS_CA_BUNDLE",
  "AWS_CA_BUNDLE",
  "NPM_CONFIG_USERCONFIG",
  "NPM_CONFIG_GLOBALCONFIG",
  "NPM_CONFIG_SCRIPT_SHELL",
  "NPM_CONFIG_SHELL",
  "NPM_CONFIG_NODE_OPTIONS",
  "NPM_CONFIG_PREFIX",
  "NPM_CONFIG_CAFILE",
  "NPM_CONFIG_IGNORE_SCRIPTS",
  "NPM_CONFIG_NODE_GYP",
  "NPM_CONFIG_PYTHON",
  "NPM_CONFIG_INIT_MODULE",
  "NPM_CONFIG_EDITOR",
  "NPM_CONFIG_VIEWER",
  "NPM_CONFIG_STRICT_SSL",
  "NPM_CONFIG_CA",
  "NPM_CONFIG_GIT",
  "DOTNET_STARTUP_HOOKS",
  "GEM_HOME",
  "GEM_PATH",
  "HOSTALIASES",
]);
// A blanket prefix refusal of NODE_ / PYTHON_ / BUN_ is not taken:
// it would sweep up masses of legitimate non-execution-control
// variables (NODE_ENV / PYTHONDONTWRITEBYTECODE etc.) and the forced
// renames would break compatibility. Known execution-control names are
// added individually instead.
//
// `MARUHI_` alone is blocked by blanket prefix. This does not contradict
// the policy above because it is **a namespace maruhi itself reserves**:
// in principle no "legitimate variable" can be swept up (maruhi defines
// what this namespace means), and conversely letting even one through
// lets the injecting side decide the behavior of a nested `maruhi`. In
// fact `MARUHI_TOKEN` / `MARUHI_TOKEN_ORIGIN` are read by resolveSession
// **before** the keychain, so a malicious member who plants their own
// PAT in a variable of that name gets their victim's `maruhi pull`
// inside `maruhi run -- make deploy` authenticated as the attacker (the
// variable name is plaintext metadata unbound by the AAD = a
// co-member can choose it). Enumerating individual names would reopen
// the same hole the next time MARUHI_* grows
//
// NPM_CONFIG_ is not blanket-refused because it has legitimate
// secret / config injection uses (registry credentials / a private
// registry URL). Only the keys above that directly change execution /
// require / spawn / TLS trust are refused individually.
// NPM_CONFIG_REGISTRY changes where installs come from but is also the
// basic setting for a private registry, so it is allowed — whether an
// install script may run is the responsibility of the npm command being
// invoked
const DENIED_ENV_PREFIXES = ["LD_", "DYLD_", "GIT_", "CORECLR_", "COR_", MARUHI_ENV_PREFIX];

/** Whether `name` is an execution-control environment variable (the denylist above, upper-cased). */
export function isDeniedEnvName(name: string): boolean {
  const upper = name.toUpperCase();
  return DENIED_ENV_NAMES.has(upper) || DENIED_ENV_PREFIXES.some((p) => upper.startsWith(p));
}

/**
 * The environment passed to the child. The parent's general environment
 * is inherited, but maruhi's own control / credential namespace is not.
 *
 * A keychain-less / CI MARUHI_TOKEN is needed for run's session
 * resolution, but passed on to the child, dependent code could read a
 * PAT longer-lived and broader in scope than the injected values. The
 * upper-cased comparison exists because Windows environment variable
 * names are case-insensitive.
 */
export function buildChildEnvironment(
  inherited: Readonly<Record<string, string | undefined>>,
  extraEnv: Readonly<Record<string, string>>,
): Readonly<Record<string, string>> {
  const child: Record<string, string> = {};
  const copyAllowed = (name: string, value: string | undefined): void => {
    if (value !== undefined && !name.toUpperCase().startsWith(MARUHI_ENV_PREFIX)) {
      child[name] = value;
    }
  };
  for (const [name, value] of Object.entries(inherited)) {
    copyAllowed(name, value);
  }
  // extraEnv already refused MARUHI_* in buildInjectionEnv, but a future
  // caller that uses the ProcessRunner boundary directly must still not
  // pass the credential namespace through
  for (const [name, value] of Object.entries(extraEnv)) {
    copyAllowed(name, value);
  }
  return child;
}

// Injected environment variable names are limited to POSIX identifiers
// (structurally blocks injection paths containing special characters
// like bash function-import names. The denylist covers the
// execution-control names inside the identifier space)
export const SAFE_ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * Builds the env-var map to inject: variable display names become env names.
 * Names and values are validated for env-var safety (no `=`, no NUL, UTF-8,
 * no execution-control names); the error mentions only the variable name,
 * never the value.
 */
export function buildInjectionEnv(
  variables: readonly DecryptedVariable[],
): Effect.Effect<Readonly<Record<string, string>>, CliError> {
  return Effect.gen(function* () {
    const env: Record<string, string> = {};
    // Windows environment variable names are case-insensitive, so
    // allowing names differing only in case to coexist would silently
    // crush one side. Refuse as a collision
    const seenUpper = new Set<string>();
    for (const variable of variables) {
      const upper = variable.name.toUpperCase();
      if (seenUpper.has(upper)) {
        return yield* Effect.fail(
          cliError(
            `Variable names collide differing only by letter case (they become the same environment variable on Windows): ${displayText(variable.name)}`,
          ),
        );
      }
      seenUpper.add(upper);
      // Environment variable names are limited to POSIX identifiers
      // ([A-Za-z_][A-Za-z0-9_]*). This filters out not only `=` / NUL /
      // control characters but also bash function-import encoded names
      // (BASH_FUNC_x%% and x() forms — shellshock-family function
      // injection): a malicious member could create a variable of that
      // name and a victim running `maruhi run -- bash ...` would load
      // the attacker-defined function into the shell
      if (!SAFE_ENV_NAME.test(variable.name)) {
        return yield* Effect.fail(
          cliError(
            `The variable name cannot be injected as an environment variable (names may use only alphanumerics and _, starting with a letter or _): ${displayText(variable.name)}`,
          ),
        );
      }
      if (isDeniedEnvName(variable.name)) {
        return yield* Effect.fail(
          cliError(
            `Refusing to inject variable name ${displayText(variable.name)}: it is an execution-control environment variable (rename the variable)`,
          ),
        );
      }
      // Reason for unwrapping: injection into the child process's env
      // (this function's product). Unwrapped only at the last moment
      // before injection; the plaintext appears only in the returned env
      // map. Error messages carry only the variable name (none of the
      // three branches below includes the value)
      // The decoding policy is unified into display.ts (fatal — shared
      // with pull --show)
      const value = decodeValueText(Redacted.value(variable.value));
      if (value === null) {
        return yield* Effect.fail(
          cliError(
            `The value of variable ${displayText(variable.name)} is not valid UTF-8 (it cannot be injected as an environment variable)`,
          ),
        );
      }
      if (value.includes("\0")) {
        return yield* Effect.fail(
          cliError(
            `The value of variable ${displayText(variable.name)} contains NUL (it cannot be injected as an environment variable)`,
          ),
        );
      }
      env[variable.name] = value;
    }
    return env;
  });
}

/**
 * Message shown when `maruhi run` has no command after `--`. Shared by the
 * argument check at the CLI entry point and the guard in {@link runOp}.
 *
 * The wording lives in one place (so the two implementations cannot disagree).
 */
export const RUN_COMMAND_REQUIRED =
  "Specify the command to run after `--` (example: `maruhi run -- printenv MY_VAR`)";

/**
 * Presence fail-fast (design doc §1-4 — rulings CT / CU): when a
 * required = true declared variable exists in the verified set, exit
 * with a typed error **before starting the child process** (enumerating
 * the variable names. The judgment material is only signed statements +
 * manifest coverage — §14.2-8: independent of the server's claims). A
 * required = false declared is not injected and only noted (stderr).
 * Neither wording includes the description.
 */
export function enforceDeclaredPresence(
  declared: readonly DeclaredVariable[],
  /** The closing clause of what did not happen (run = the child was never started, sync = nothing was sent). */
  outcome = "The command was not started",
): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const missing = declared
      .filter((variable) => variable.required)
      .map((variable) => displayText(variable.name))
      .toSorted();
    if (missing.length > 0) {
      // The strict error of a child never started (presence — verified
      // statements only). Two recovery paths are spelled out: set the
      // value (activation), or when the declaration was mistaken lower
      // required via --optional (no command deletes a declaration yet)
      return yield* Effect.fail(
        cliError(
          `Required variables are declared but have no value yet (verified from signed statements — CRYPTO_SPEC §14.2): ${missing.join(", ")}. Set each value with \`maruhi push <NAME>\` (the first push of a declared variable activates it), or downgrade a mistaken declaration with \`maruhi schema set <NAME> --optional\`. ${outcome}`,
        ),
      );
    }
    const optional = declared
      .filter((variable) => !variable.required)
      .map((variable) => displayText(variable.name))
      .toSorted();
    if (optional.length > 0) {
      yield* logNote(
        `declared variables without values were not injected (declared as not required): ${optional.join(", ")}`,
      );
    }
  });
}

// The advisory type check's (§14.3-7) judgment. The declared type is a
// closed set (§4.2 — "" = unspecified is outside the check). The
// judgment touches only the in-memory plaintext just before injection
// and nothing but the result (boolean) leaves. number accepts decimal
// notation only (integer / fraction / exponent) (never counting
// Number()'s acceptance of "0x1f" / "Infinity" as a type match)
const NUMBER_TEXT = /^-?(?:\d+)(?:\.\d+)?(?:[eE][+-]?\d+)?$/;

function matchesDeclaredType(varType: "string" | "number" | "boolean" | "url", text: string) {
  switch (varType) {
    case "string":
      return true;
    case "number":
      return NUMBER_TEXT.test(text);
    case "boolean":
      return text === "true" || text === "false";
    case "url":
      return URL.canParse(text);
  }
}

/**
 * Advisory declared-type check at injection time (§14.3-7): mismatches are
 * warnings only and execution continues (type conformance is never verified —
 * the declaration is advisory). The wording carries only the variable
 * name and declared-type name (neither the value nor the description).
 * Invalid UTF-8 is silently passed through here (buildInjectionEnv turns
 * it into a strict error with the variable name — no double reporting).
 */
export function typeAdvisoryWarnings(variables: readonly DecryptedVariable[]): readonly string[] {
  const warnings: string[] = [];
  for (const variable of variables) {
    if (variable.varType === "") {
      continue;
    }
    // Reason for unwrapping: the advisory type check just before
    // injection (in memory only). Nothing but the judgment result
    // (boolean) leaves — the warning wording carries only the variable
    // name and declared-type name
    const text = decodeValueText(Redacted.value(variable.value));
    if (text !== null && !matchesDeclaredType(variable.varType, text)) {
      warnings.push(
        `The value of variable ${displayText(variable.name)} does not match its declared type "${variable.varType}" (the declaration is advisory — CRYPTO_SPEC §14.3; continuing)`,
      );
    }
  }
  return warnings;
}

/**
 * Run-output redaction (ROADMAP Phase 3 ⑤ — the trigger). The injected
 * values are known exactly, so the child's stdout / stderr can be scrubbed
 * by exact match when its output may land somewhere other than a human's
 * terminal. The trigger is **not** the value-display gate's: (1) a known
 * agent is detected (an agent that allocates a PTY has a terminal on
 * stdout, so without this layer `run -- printenv` stays open), or (2)
 * stdout **or** stderr is not a terminal (CI, a pipe, a redirect, an
 * unknown agent). stdin alone is not a trigger — a human heredoc-ing
 * `run` keeps the child's TTY. Returns the byte fragments to scrub
 * (undefined = no redaction: stdio is inherited). Residual: an unknown
 * agent on a PTY is caught by neither layer; the root fix is `proxy run`.
 */
export function redactionFragments(
  variables: readonly DecryptedVariable[],
  /** Further secrets to scrub (`proxy run`: the brokered values known at start). */
  extraSecrets: readonly Uint8Array[] = [],
): Effect.Effect<readonly Uint8Array[] | undefined, never, CliIo | Stdio.Stdio> {
  return Effect.gen(function* () {
    const agent = yield* AgentProfileRef;
    const io = yield* CliIo;
    const stdio = yield* Stdio.Stdio;
    const stdoutIsTerminal = yield* stdio.stdoutIsTerminal;
    const triggered = agent.isAgent || !stdoutIsTerminal || !io.stderrIsTerminal();
    if (!triggered || variables.length + extraSecrets.length === 0) {
      return undefined;
    }
    // Reason for unwrapping: the fragments are the search patterns of the
    // redaction itself (what the child's output is scrubbed of). They stay
    // inside the ProcessRunner boundary and never appear in any message
    return [...variables.map((variable) => Redacted.value(variable.value)), ...extraSecrets];
  });
}

/** `maruhi run`: inject decrypted variables into the child env and run the command. */
export function runOp(input: {
  readonly command: readonly string[];
  readonly variables: readonly DecryptedVariable[];
}): Effect.Effect<number, CliError, ProcessRunner | CliIo | Stdio.Stdio> {
  return Effect.gen(function* () {
    // An empty string cannot execute (`maruhi run -- "$CMD"` with CMD
    // unset arrives in this shape). "One argument is present" and
    // "there is a target to run" are different things
    if (input.command.length === 0 || (input.command[0] ?? "").trim() === "") {
      // A mistake in how it was written = a usage error (2). Same treatment as the entry-point check
      return yield* Effect.fail(usageError(RUN_COMMAND_REQUIRED));
    }
    const runner = yield* ProcessRunner;
    const extraEnv = yield* buildInjectionEnv(input.variables);
    return yield* runner.run({
      command: input.command,
      extraEnv,
      redact: yield* redactionFragments(input.variables),
    });
  });
}
