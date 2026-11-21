import { Context, Data, Effect, Redacted, Stdio } from "effect";

import { AgentProfileRef } from "./agent-gate.ts";
import { decodeValueText, displayText } from "./display.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { CliIo } from "./io.ts";
import { logNote } from "./notice.ts";
import type { DeclaredVariable, DecryptedVariable } from "./pull.ts";

export interface ExecInput {
  readonly command: readonly string[];
  readonly cwd: string;
  readonly extraEnv: Readonly<Record<string, string>>;
  readonly stdin: Redacted.Redacted<Uint8Array>;
}

export interface ExecOutcome {
  readonly exitCode: number;
  readonly output: string;
}

export interface CaptureInput {
  readonly command: readonly string[];
  readonly cwd: string;
  readonly extraEnv: Readonly<Record<string, string>>;
}

export interface CaptureOutcome {
  readonly exitCode: number;
  readonly stdout: Uint8Array;
  readonly stderr: string;
}

export class ScriptStoppedError extends Data.TaggedError("ScriptStoppedError")<{
  readonly message: string;
}> {
  constructor(message: string) {
    super({ message });
  }
}

export class ScriptLeftoverError extends Data.TaggedError("ScriptLeftoverError")<{
  readonly exitCode: number;
  readonly message: string;
}> {
  constructor(exitCode: number, message: string) {
    super({ exitCode, message });
  }
}

export interface RunInput {
  readonly command: readonly string[];
  readonly extraEnv: Readonly<Record<string, string>>;
  readonly holdSignals?: boolean | undefined;
  readonly redact?: readonly Uint8Array[] | undefined;
}

export interface ProcessRunnerShape {
  readonly run: (input: RunInput) => Effect.Effect<number, CliError>;
  readonly exec: (input: ExecInput) => Effect.Effect<ExecOutcome, CliError>;
  readonly captureScript: (input: CaptureInput) => Promise<CaptureOutcome>;
  readonly runSession: (input: {
    readonly command: readonly string[];
    readonly env: Readonly<Record<string, string>>;
  }) => Effect.Effect<number, CliError>;
}

export class ProcessRunner extends Context.Service<ProcessRunner, ProcessRunnerShape>()(
  "cli/ProcessRunner",
) {}

const MARUHI_ENV_PREFIX = "MARUHI_";

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
  "HOME",
  "USERPROFILE",
  "HOMEDRIVE",
  "HOMEPATH",
  "APPDATA",
  "LOCALAPPDATA",
  "XDG_CONFIG_HOME",
  "XDG_DATA_HOME",
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
  "PATHEXT",
  "COMSPEC",
  "SYSTEMROOT",
  "WINDIR",
  "LESSOPEN",
  "LESSCLOSE",
  "PAGER",
  "MANPAGER",
  "EDITOR",
  "VISUAL",
  "BROWSER",
  "SSH_ASKPASS",
  "SUDO_ASKPASS",
  "LUA_INIT",
  "LUA_PATH",
  "LUA_CPATH",
  "PSMODULEPATH",
  "GLIBC_TUNABLES",
  "MALLOC_CONF",
  "LOCPATH",
  "NLSPATH",
  "TERMINFO",
  "TERMINFO_DIRS",
  "TERMCAP",
  "CDPATH",
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
const DENIED_ENV_PREFIXES = ["LD_", "DYLD_", "GIT_", "CORECLR_", "COR_", MARUHI_ENV_PREFIX];

export function isDeniedEnvName(name: string): boolean {
  const upper = name.toUpperCase();
  return DENIED_ENV_NAMES.has(upper) || DENIED_ENV_PREFIXES.some((p) => upper.startsWith(p));
}

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
  for (const [name, value] of Object.entries(extraEnv)) {
    copyAllowed(name, value);
  }
  return child;
}

export const SAFE_ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

export const buildInjectionEnv = Effect.fn("run.buildInjectionEnv")(function* (
  variables: readonly DecryptedVariable[],
): Effect.fn.Return<Readonly<Record<string, string>>, CliError> {
  const env: Record<string, string> = {};
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

export const RUN_COMMAND_REQUIRED =
  "Specify the command to run after `--` (example: `maruhi run -- printenv MY_VAR`)";

export const enforceDeclaredPresence = Effect.fn("run.enforceDeclaredPresence")(function* (
  declared: readonly DeclaredVariable[],
  outcome = "The command was not started",
): Effect.fn.Return<void, CliError, CliIo> {
  const missing = declared
    .filter((variable) => variable.required)
    .map((variable) => displayText(variable.name))
    .toSorted();
  if (missing.length > 0) {
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

export function typeAdvisoryWarnings(variables: readonly DecryptedVariable[]): readonly string[] {
  const warnings: string[] = [];
  for (const variable of variables) {
    if (variable.varType === "") {
      continue;
    }
    const text = decodeValueText(Redacted.value(variable.value));
    if (text !== null && !matchesDeclaredType(variable.varType, text)) {
      warnings.push(
        `The value of variable ${displayText(variable.name)} does not match its declared type "${variable.varType}" (the declaration is advisory — CRYPTO_SPEC §14.3; continuing)`,
      );
    }
  }
  return warnings;
}

export const redactionFragments = Effect.fn("run.redactionFragments")(function* (
  variables: readonly DecryptedVariable[],
  extraSecrets: readonly Uint8Array[] = [],
): Effect.fn.Return<readonly Uint8Array[] | undefined, never, CliIo | Stdio.Stdio> {
  const agent = yield* AgentProfileRef;
  const io = yield* CliIo;
  const stdio = yield* Stdio.Stdio;
  const stdoutIsTerminal = yield* stdio.stdoutIsTerminal;
  const triggered = agent.isAgent || !stdoutIsTerminal || !io.stderrIsTerminal();
  if (!triggered || variables.length + extraSecrets.length === 0) {
    return undefined;
  }
  return [...variables.map((variable) => Redacted.value(variable.value)), ...extraSecrets];
});

export const runOp = Effect.fn("run.runOp")(function* (input: {
  readonly command: readonly string[];
  readonly variables: readonly DecryptedVariable[];
}): Effect.fn.Return<number, CliError, ProcessRunner | CliIo | Stdio.Stdio> {
  if (input.command.length === 0 || (input.command[0] ?? "").trim() === "") {
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
