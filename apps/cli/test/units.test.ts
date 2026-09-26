// Unit tests for details: keychain record codecs, run's injection checks,
// stdin normalization, the MARUHI_TOKEN env-var path, server URL resolution.
// (CLI login polling rules live in login.test.ts — AUTH_SPEC §4)

import {
  DataLimitExceededError,
  ProjectLimitError,
  ProjectNotFoundError,
  UnauthorizedError,
} from "@maruhi/api-schema";
import { Cause, Effect, Exit, Layer, Redacted, Schema, Stdio } from "effect";
import { HttpClientError, HttpClientRequest } from "effect/unstable/http";
import { afterEach, describe, expect, it } from "vitest";

import { AgentProfileRef } from "../src/agent-gate.ts";
import { runCli } from "../src/cli.ts";
import {
  decodeValueText,
  formatUtcDate,
  formatUtcMinutes,
  formatUtcSeconds,
  showValues,
} from "../src/display.ts";
import { toCliError } from "../src/failure.ts";
import { CliIo } from "../src/io.ts";
import {
  Keychain,
  masterKeyEntryName,
  parseStoredMasterKey,
  parseStoredToken,
  serializeStoredToken,
  tokenEntryName,
} from "../src/keychain.ts";
import type { DecryptedVariable } from "../src/pull.ts";
import { normalizeStdinValue } from "../src/push.ts";
import { buildChildEnvironment, buildInjectionEnv, ProcessRunner, runOp } from "../src/run.ts";
import {
  cryptoBackendUsable,
  resolveServerOrigin,
  storeMasterKeyGuarded,
  unsupportedCryptoCause,
  unsupportedCryptoMessage,
} from "../src/session.ts";
import { makeTestUser } from "./support/crypto.ts";
import { makeTestEnv, seedConfig } from "./support/env.ts";
import { MockServer, onRequest } from "./support/server.ts";

let servers: MockServer[] = [];

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

describe("total timestamp formatters", () => {
  it("degrades to an explicit display — no RangeError — for out-of-Date-range or non-finite input", () => {
    expect(formatUtcSeconds(0)).toBe("1970-01-01 00:00:00 UTC");
    expect(formatUtcMinutes(0)).toBe("1970-01-01 00:00 UTC");
    expect(formatUtcDate(0)).toBe("1970-01-01");
    // Even inside the Date range, years outside 0-9999 (where toISOString
    // returns an expanded-year form) silently shift a fixed slice — degrade explicitly instead
    expect(formatUtcSeconds(Date.UTC(9999, 11, 31, 23, 59, 59))).toBe("9999-12-31 23:59:59 UTC");
    for (const bad of [
      253_402_300_800_000, // year 10000
      -62_167_219_200_001, // year -1
      8_640_000_000_000_000,
      -1e300,
      Number.POSITIVE_INFINITY,
      Number.NaN,
    ]) {
      expect(formatUtcSeconds(bad)).toContain("invalid timestamp");
      expect(formatUtcMinutes(bad)).toContain("invalid timestamp");
      expect(formatUtcDate(bad)).toContain("invalid timestamp");
    }
  });
});

describe("keychain record codecs", () => {
  it("round-trips token / device key records and detects corruption", () => {
    const token = { token: "maruhi_pat_x", userId: "u1", tokenId: "t1" };
    const parsed = parseStoredToken(JSON.stringify(token));
    if (parsed === null) throw new Error("expected a parsed token record");
    // Always unwrap before comparing raw values (toEqual on wrapped values does not inspect the contents)
    expect(Redacted.value(parsed.token)).toBe("maruhi_pat_x");
    expect({ userId: parsed.userId, tokenId: parsed.tokenId }).toEqual({
      userId: "u1",
      tokenId: "t1",
    });
    // Round-trip against the storage side: serializeStoredToken → parseStoredToken
    // returns the raw value (if serialization wrote a redaction this fails here)
    const reparsed = parseStoredToken(serializeStoredToken(parsed));
    if (reparsed === null) throw new Error("expected a reparsed token record");
    expect(Redacted.value(reparsed.token)).toBe("maruhi_pat_x");
    expect(parseStoredToken("not json")).toBeNull();
    expect(parseStoredToken(JSON.stringify({ token: "x" }))).toBeNull();
    expect(parseStoredMasterKey(JSON.stringify({ suite: "maruhi/v1" }))).toBeNull();
  });

  it("keychain names are scoped by server origin (and userId)", () => {
    expect(tokenEntryName("https://a.example")).not.toBe(tokenEntryName("https://b.example"));
    expect(masterKeyEntryName("https://a.example", "u1")).not.toBe(
      masterKeyEntryName("https://a.example", "u2"),
    );
  });
});

describe("resolveServerOrigin", () => {
  it("resolves flag → config in order and normalizes to an origin", async () => {
    const origin = await Effect.runPromise(
      resolveServerOrigin("https://maruhi.example/some/path", {}),
    );
    expect(origin).toBe("https://maruhi.example");
    const fromConfig = await Effect.runPromise(
      resolveServerOrigin(undefined, { server: "http://localhost:8787" }),
    );
    expect(fromConfig).toBe("http://localhost:8787");
  });

  it("unset or malformed URLs are errors", async () => {
    const missing = await Effect.runPromiseExit(resolveServerOrigin(undefined, {}));
    expect(Exit.isFailure(missing)).toBe(true);
    const invalid = await Effect.runPromiseExit(resolveServerOrigin("not-a-url", {}));
    expect(Exit.isFailure(invalid)).toBe(true);
  });

  it("allows http: only for loopback (blocks plaintext sends)", async () => {
    const loopback = await Effect.runPromise(resolveServerOrigin("http://localhost:8787", {}));
    expect(loopback).toBe("http://localhost:8787");
    const remote = await Effect.runPromiseExit(resolveServerOrigin("http://maruhi.example", {}));
    expect(Exit.isFailure(remote)).toBe(true);
    expect(JSON.stringify(remote)).toContain("loopback");
  });
});

function variable(name: string, value: string | Uint8Array): DecryptedVariable {
  return {
    variableId: "v1",
    name,
    version: 1,
    epoch: 1,
    required: false,
    varType: "",
    value: Redacted.make(typeof value === "string" ? new TextEncoder().encode(value) : value, {
      label: "variable-value",
    }),
  };
}

describe("storeMasterKeyGuarded (save with overwrite detection)", () => {
  const ENTRY = masterKeyEntryName("https://maruhi.test", "user-1");

  /**
   * A Keychain simulating concurrent runs: `onSet` injects "another process
   * wrote before/after my write" situations. Since the OS keychain has no
   * conditional write, all that can be pinned is "detect last-writer-wins and fail"
   */
  const fakeKeychain = (input: {
    readonly initial?: string;
    readonly onSet?: (store: Map<string, string>) => void;
  }) => {
    const store = new Map<string, string>();
    if (input.initial !== undefined) {
      store.set(ENTRY, input.initial);
    }
    return {
      store,
      layer: Layer.succeed(Keychain, {
        kind: "os-keychain",
        get: (name: string) => Effect.sync(() => store.get(name) ?? null),
        set: (name: string, value: string) =>
          Effect.sync(() => {
            store.set(name, value);
            input.onSet?.(store);
          }),
        remove: (name: string) => Effect.sync(() => void store.delete(name)),
      }),
    };
  };

  it("can save into an empty entry", async () => {
    const keychain = fakeKeychain({});
    const exit = await Effect.runPromiseExit(
      storeMasterKeyGuarded(ENTRY, "record-mine").pipe(Effect.provide(keychain.layer)),
    );
    expect(Exit.isSuccess(exit)).toBe(true);
    expect(keychain.store.get(ENTRY)).toBe("record-mine");
  });

  it("does not overwrite a record that appeared between the check and the write", async () => {
    // The shape where another process wrote after ensureNoStoredMasterKey. A
    // plain set would silently erase the other's key as last-writer-wins
    const keychain = fakeKeychain({ initial: "record-other" });
    const exit = await Effect.runPromiseExit(
      storeMasterKeyGuarded(ENTRY, "record-mine").pipe(Effect.provide(keychain.layer)),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(JSON.stringify(exit)).toContain("at the same time");
    expect(keychain.store.get(ENTRY)).toBe("record-other");
  });

  it("fails when overwritten right after writing (does not proceed to recovery issuance)", async () => {
    // The shape where another process wrote right after my write. Detecting that
    // the read-back is not my record prevents registering a recovery blob for the discarded key
    const keychain = fakeKeychain({
      onSet: (store) => store.set(ENTRY, "record-other"),
    });
    const exit = await Effect.runPromiseExit(
      storeMasterKeyGuarded(ENTRY, "record-mine").pipe(Effect.provide(keychain.layer)),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(JSON.stringify(exit)).toContain("no recovery code was issued");
  });
});

describe("runOp", () => {
  /** A runner that never spawns the child process (so reaching spawn is observable). */
  const spawnedNothing = Layer.succeed(ProcessRunner, {
    run: () => Effect.succeed(0),
    exec: () => Effect.succeed({ exitCode: 0, output: "" }),
    runSession: () => Effect.succeed(0),
  });

  it("does not spawn a child process even for a whitespace-only command (same check as the entry point)", async () => {
    const exit = await Effect.runPromiseExit(
      runOp({ command: ["  "], variables: [] }).pipe(Effect.provide(spawnedNothing)),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(JSON.stringify(exit)).toContain("Specify the command to run after `--`");
  });

  it("does not spawn a child process for an empty-string command", async () => {
    // The same check as the entry point's argument validation (cli.ts) lives here
    // too (a defense line for direct callers). `[""]` is the "one element but not runnable" shape
    const exit = await Effect.runPromiseExit(
      runOp({ command: [""], variables: [] }).pipe(Effect.provide(spawnedNothing)),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(JSON.stringify(exit)).toContain("Specify the command to run after `--`");
    // Usage mistakes surface as the same usage error as the entry point (exit code 2)
    expect(JSON.stringify(exit)).toContain('"usage":true');
  });
});

describe("showValues (the post-decryption defense line)", () => {
  /** A CliIo that discards output (this check only observes "display is never reached"). */
  const silentIo = Layer.succeed(CliIo, {
    log: () => Effect.void,
    logError: () => Effect.void,
    readStdin: Effect.succeed(new Uint8Array(0)),
    promptLine: () => Effect.succeed(""),
    envVar: () => undefined,
    agentProfile: () => ({ isAgent: false }),
    stderrIsTerminal: () => true,
    colorEnabled: () => false,
    openBrowser: () => Effect.succeed(false),
  });

  const showOne = (input: {
    readonly agent?: { readonly isAgent: boolean; readonly name?: string };
    readonly stdinIsTerminal: boolean;
    readonly stdoutIsTerminal: boolean;
  }) =>
    Effect.runPromiseExit(
      showValues([variable("SECRET", "plaintext-value")]).pipe(
        Effect.provide(
          Layer.mergeAll(
            silentIo,
            Layer.succeed(AgentProfileRef, input.agent ?? { isAgent: false }),
            Stdio.layerTest({
              stdinIsTerminal: Effect.succeed(input.stdinIsTerminal),
              stdoutIsTerminal: Effect.succeed(input.stdoutIsTerminal),
            }),
          ),
        ),
      ),
    );

  it("does not display off-terminal even for a direct call that bypasses the entry check", async () => {
    // The main path is pull's entry point (before decryption). This defense line
    // keeps a future direct showValues caller from reaching display without the
    // entry check — pins **both layers using the same decision** (primary = TTY, secondary = agent detection)
    const piped = await showOne({ stdinIsTerminal: true, stdoutIsTerminal: false });
    expect(Exit.isFailure(piped)).toBe(true);
    expect(JSON.stringify(piped)).toContain("stdout is not an interactive terminal");
    expect(JSON.stringify(piped)).not.toContain("plaintext-value");

    const headless = await showOne({ stdinIsTerminal: false, stdoutIsTerminal: true });
    expect(Exit.isFailure(headless)).toBe(true);
    expect(JSON.stringify(headless)).toContain("stdin is not an interactive terminal");

    // The most common shape in CI / non-interactive shells = both non-terminal (pins all 3 branches)
    const detached = await showOne({ stdinIsTerminal: false, stdoutIsTerminal: false });
    expect(Exit.isFailure(detached)).toBe(true);
    expect(JSON.stringify(detached)).toContain(
      "neither stdin nor stdout is an interactive terminal",
    );
    expect(JSON.stringify(detached)).not.toContain("plaintext-value");

    const agent = await showOne({
      agent: { isAgent: true, name: "claude" },
      stdinIsTerminal: true,
      stdoutIsTerminal: true,
    });
    expect(Exit.isFailure(agent)).toBe(true);
    expect(JSON.stringify(agent)).toContain("AI agent environment was detected");
  });

  it("displays on a human interactive terminal (positive control that the checks are not vacuous)", async () => {
    const allowed = await showOne({ stdinIsTerminal: true, stdoutIsTerminal: true });
    expect(Exit.isSuccess(allowed)).toBe(true);
  });

  it("cannot forge a `NAME=value` line via a newline in the value", async () => {
    // Values can be written by co-editors. Streaming a newline verbatim would let
    // them fabricate a line for a nonexistent variable on screen (deceiving a user who copies from pull --show)
    const logs: string[] = [];
    const capturingIo = Layer.succeed(CliIo, {
      log: (line: string) => {
        logs.push(line);
        return Effect.void;
      },
      logError: () => Effect.void,
      readStdin: Effect.succeed(new Uint8Array(0)),
      promptLine: () => Effect.succeed(""),
      envVar: () => undefined,
      agentProfile: () => ({ isAgent: false }),
      stderrIsTerminal: () => true,
      colorEnabled: () => false,
      openBrowser: () => Effect.succeed(false),
    });
    const exit = await Effect.runPromiseExit(
      showValues([variable("SECRET", "x\nDATABASE_URL=postgres://attacker/")]).pipe(
        Effect.provide(
          Layer.mergeAll(
            capturingIo,
            Layer.succeed(AgentProfileRef, { isAgent: false }),
            Stdio.layerTest({
              stdinIsTerminal: Effect.succeed(true),
              stdoutIsTerminal: Effect.succeed(true),
            }),
          ),
        ),
      ),
    );
    expect(Exit.isSuccess(exit)).toBe(true);
    // A forged line never appears in `NAME=value` form (it carries a marker)
    expect(logs).not.toContain("DATABASE_URL=postgres://attacker/");
    expect(logs).toContain("| DATABASE_URL=postgres://attacker/");
  });

  it("a trailing newline does not add to the line count; it is only reported as present", async () => {
    // "a\nb\n" is 2 lines + a trailing newline. A naive split would fabricate an
    // empty third line and shift the reported count by one (the trailing newline is part of the value, so it is not dropped either)
    const logs: string[] = [];
    const capturingIo = Layer.succeed(CliIo, {
      log: (line: string) => {
        logs.push(line);
        return Effect.void;
      },
      logError: () => Effect.void,
      readStdin: Effect.succeed(new Uint8Array(0)),
      promptLine: () => Effect.succeed(""),
      envVar: () => undefined,
      agentProfile: () => ({ isAgent: false }),
      stderrIsTerminal: () => true,
      colorEnabled: () => false,
      openBrowser: () => Effect.succeed(false),
    });
    const exit = await Effect.runPromiseExit(
      showValues([variable("SECRET", "a\nb\n")]).pipe(
        Effect.provide(
          Layer.mergeAll(
            capturingIo,
            Layer.succeed(AgentProfileRef, { isAgent: false }),
            Stdio.layerTest({
              stdinIsTerminal: Effect.succeed(true),
              stdoutIsTerminal: Effect.succeed(true),
            }),
          ),
        ),
      ),
    );
    expect(Exit.isSuccess(exit)).toBe(true);
    expect(logs[0]).toContain("2-line value with a trailing newline");
    expect(logs).toEqual([logs[0], "| a", "| b"]);
  });

  it("neutralizes order-breaking characters even in displayed values (same treatment as the name side)", async () => {
    // Values are written by co-editors, so a malicious value could fake another
    // member's terminal display. Killing ANSI alone leaves bidi overrides and
    // zero-width chars — pin that the same list as the name side (displayText) neutralizes them (never add coverage to only one side)
    const logs: string[] = [];
    const errors: string[] = [];
    const capturingIo = Layer.succeed(CliIo, {
      log: (line: string) => {
        logs.push(line);
        return Effect.void;
      },
      logError: (line: string) => {
        errors.push(line);
        return Effect.void;
      },
      readStdin: Effect.succeed(new Uint8Array(0)),
      promptLine: () => Effect.succeed(""),
      envVar: () => undefined,
      agentProfile: () => ({ isAgent: false }),
      stderrIsTerminal: () => true,
      colorEnabled: () => false,
      openBrowser: () => Effect.succeed(false),
    });
    const exit = await Effect.runPromiseExit(
      showValues([variable("SECRET", "a\u202Eb\u200Bc\u2028d\u200Ce\nf")]).pipe(
        Effect.provide(
          Layer.mergeAll(
            capturingIo,
            Layer.succeed(AgentProfileRef, { isAgent: false }),
            Stdio.layerTest({
              stdinIsTerminal: Effect.succeed(true),
              stdoutIsTerminal: Effect.succeed(true),
            }),
          ),
        ),
      ),
    );
    expect(Exit.isSuccess(exit)).toBe(true);
    // ZWNJ (needed for some scripts) and newlines (legitimate values like PEMs)
    // are kept. A value containing newlines is printed with a marker on the second line onward (so the value side cannot forge a `NAME=value` line)
    expect(logs).toEqual([
      'SECRET= (a 2-line value; the leading "| " on each line below is a marker added by maruhi)',
      "| a\uFFFDb\uFFFDc\uFFFDd\u200Ce",
      "| f",
    ]);
    // Neutralization is not silent: name that the display differs from the actual
    // value (without putting the value itself in the warning)
    expect(errors.join("\n")).toContain("SECRET");
    expect(errors.join("\n")).toContain("do not match the actual values");
  });
});

describe("buildInjectionEnv", () => {
  it("validates names and values to build the env map", async () => {
    const env = await Effect.runPromise(
      buildInjectionEnv([variable("A", "1"), variable("B_2", "two")]),
    );
    expect(env).toEqual({ A: "1", B_2: "two" });
  });

  it("rejects names containing `=`, values containing NUL, and invalid UTF-8 (the error does not show the value)", async () => {
    const badName = await Effect.runPromiseExit(buildInjectionEnv([variable("A=B", "x")]));
    expect(Exit.isFailure(badName)).toBe(true);
    const nulName = await Effect.runPromiseExit(buildInjectionEnv([variable("A\0B", "x")]));
    expect(Exit.isFailure(nulName)).toBe(true);
    const withNul = await Effect.runPromiseExit(buildInjectionEnv([variable("SECRET_A", "a\0b")]));
    expect(Exit.isFailure(withNul)).toBe(true);
    expect(JSON.stringify(withNul)).not.toContain("a\\u0000b");
    const invalidUtf8 = await Effect.runPromiseExit(
      buildInjectionEnv([variable("SECRET_B", new Uint8Array([0xff, 0xfe]))]),
    );
    expect(Exit.isFailure(invalidUtf8)).toBe(true);
  });

  it("rejects bash function-import names (BASH_FUNC_x%% / x()) (shellshock family)", async () => {
    for (const name of ["BASH_FUNC_ls%%", "evil()", "a b", "my-secret", "1abc"]) {
      const exit = await Effect.runPromiseExit(buildInjectionEnv([variable(name, "x")]));
      expect(Exit.isFailure(exit)).toBe(true);
      expect(JSON.stringify(exit)).toContain("only alphanumerics and _");
    }
  });

  it("rejects name collisions that differ only in case (Windows case-insensitivity defense)", async () => {
    const exit = await Effect.runPromiseExit(
      buildInjectionEnv([variable("Secret_A", "x"), variable("SECRET_A", "y")]),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(JSON.stringify(exit)).toContain("differing only by letter case");
  });

  it("rejects injection into execution-control env var names (PATH / LD_* / NODE_OPTIONS etc.)", async () => {
    // "Path" defends against Windows case-insensitivity (compared after uppercasing)
    for (const name of [
      "PATH",
      "Path",
      "LD_PRELOAD",
      "DYLD_INSERT_LIBRARIES",
      "NODE_OPTIONS",
      "NODE_TLS_REJECT_UNAUTHORIZED",
      "SSLKEYLOGFILE",
      "BUN_OPTIONS",
    ]) {
      const exit = await Effect.runPromiseExit(buildInjectionEnv([variable(name, "x")]));
      expect(Exit.isFailure(exit)).toBe(true);
      expect(JSON.stringify(exit)).toContain("execution-control");
    }
  });

  it("also rejects injection into POSIX / Windows execution-control names", async () => {
    for (const name of [
      // POSIX: rc / config-directory substitution and prompt evaluation
      "HOME",
      "home", // defense against case-folded comparison (Windows case-insensitivity)
      "USERPROFILE",
      "XDG_CONFIG_HOME",
      "XDG_DATA_HOME",
      "PROMPT_COMMAND",
      "PS1",
      "PS4",
      "SHELLOPTS",
      "BASHOPTS",
      "NODE_REPL_EXTERNAL_MODULE",
      "PYTHONINSPECT",
      // Windows: substitution of execution resolution
      "PATHEXT",
      "COMSPEC",
      "SYSTEMROOT",
      "SystemRoot",
      "WINDIR",
    ]) {
      const exit = await Effect.runPromiseExit(buildInjectionEnv([variable(name, "x")]));
      expect(Exit.isFailure(exit)).toBe(true);
      expect(JSON.stringify(exit)).toContain("execution-control");
    }
  });

  it("also rejects injection into names that launch other programs", async () => {
    for (const name of [
      // Programs a child process would launch (pager / editor / browser / askpass)
      "LESSOPEN",
      "LESSCLOSE",
      "PAGER",
      "MANPAGER",
      "EDITOR",
      "VISUAL",
      "BROWSER",
      "SSH_ASKPASS",
      "SUDO_ASKPASS",
      // Interpreter init hooks and module search paths
      "LUA_INIT",
      "LUA_PATH",
      "LUA_CPATH",
      "PSModulePath", // defense against case-folded comparison (Windows case-insensitivity)
      // Loader / auxiliary-data search locations
      "GLIBC_TUNABLES",
      "MALLOC_CONF",
      "LOCPATH",
      "NLSPATH",
      "TERMINFO",
      "TERMCAP",
      // shell autoload / TLS trust / Python user-site
      "FPATH",
      "KSH_ENV",
      "SSL_CERT_FILE",
      "SSL_CERT_DIR",
      "CURL_CA_BUNDLE",
      "REQUESTS_CA_BUNDLE",
      "AWS_CA_BUNDLE",
      "PYTHONUSERBASE",
      "PYTHONWARNINGS",
      // Windows home/config, shell lookup, npm settings
      "HOMEDRIVE",
      "HOMEPATH",
      "APPDATA",
      "LOCALAPPDATA",
      "CDPATH",
      "TERMINFO_DIRS",
      "NPM_CONFIG_USERCONFIG",
      "NPM_CONFIG_GLOBALCONFIG",
      "npm_config_script_shell", // individual name + case-insensitive
      "NPM_CONFIG_SHELL",
      "NPM_CONFIG_NODE_OPTIONS",
      "NPM_CONFIG_PREFIX",
      "NPM_CONFIG_CAFILE",
      "NPM_CONFIG_IGNORE_SCRIPTS",
      "NPM_CONFIG_NODE_GYP",
      "npm_config_python",
      "NPM_CONFIG_INIT_MODULE",
      "NPM_CONFIG_EDITOR",
      "NPM_CONFIG_VIEWER",
      "NPM_CONFIG_STRICT_SSL",
      "NPM_CONFIG_CA",
      "NPM_CONFIG_GIT",
      // interpreter / runtime hooks that do not need an attacker-controlled rc file
      "PYTHONBREAKPOINT",
      "PYTHONEXECUTABLE",
      "PYTHON",
      "NODE_GYP_FORCE_PYTHON",
      "JDK_JAVA_OPTIONS",
      "DOTNET_STARTUP_HOOKS",
      "GEM_HOME",
      "GEM_PATH",
      "HOSTALIASES",
      "CORECLR_ENABLE_PROFILING",
      "COR_PROFILER_PATH",
    ]) {
      const exit = await Effect.runPromiseExit(buildInjectionEnv([variable(name, "x")]));
      expect(Exit.isFailure(exit)).toBe(true);
      expect(JSON.stringify(exit)).toContain("execution-control");
    }
    // Pins the ruling (M2) that no blanket prefix rejection was adopted: legitimate variables like NODE_ENV pass
    const allowed = await Effect.runPromise(
      buildInjectionEnv([
        variable("NODE_ENV", "production"),
        variable("BUN_INSTALL", "x"),
        // npm registry auth is a legitimate secret-injection use of maruhi run.
        // NPM_CONFIG_ as a whole is not rejected — only the execution-control keys above are denied individually
        variable("NPM_CONFIG__AUTH", "credential"),
        variable("NPM_CONFIG__AUTHTOKEN", "credential"),
        variable("NPM_CONFIG_REGISTRY", "https://registry.example"),
      ]),
    );
    expect(Object.keys(allowed).toSorted()).toEqual([
      "BUN_INSTALL",
      "NODE_ENV",
      "NPM_CONFIG_REGISTRY",
      "NPM_CONFIG__AUTH",
      "NPM_CONFIG__AUTHTOKEN",
    ]);
  });

  it("rejects injection into maruhi's own namespace (MARUHI_*)", async () => {
    // resolveSession checks MARUHI_TOKEN before the keychain, so a co-member who
    // can create a variable of this name could authenticate a nested `maruhi`
    // inside the victim's `maruhi run -- make deploy` as themselves. It is a
    // reserved namespace, so the whole prefix is blocked rather than individual names (adding more MARUHI_* later cannot reopen the hole)
    for (const name of [
      "MARUHI_TOKEN",
      "MARUHI_TOKEN_ORIGIN",
      "maruhi_token", // defense against case-folded comparison (Windows case-insensitivity)
      "MARUHI_FUTURE_KNOB", // unknown future MARUHI_* are covered by the prefix
    ]) {
      const exit = await Effect.runPromiseExit(buildInjectionEnv([variable(name, "x")]));
      expect(Exit.isFailure(exit)).toBe(true);
      expect(JSON.stringify(exit)).toContain("execution-control");
    }
    // Names outside the reserved namespace pass (names merely starting with MARUHI are not caught)
    const allowed = await Effect.runPromise(
      buildInjectionEnv([variable("MARUHISECRET", "x"), variable("APP_MARUHI_TOKEN", "y")]),
    );
    expect(Object.keys(allowed).toSorted()).toEqual(["APP_MARUHI_TOKEN", "MARUHISECRET"]);
  });
});

describe("buildChildEnvironment", () => {
  it("excludes MARUHI_* from the parent / extra env, case-insensitively", () => {
    expect(
      buildChildEnvironment(
        {
          PATH: "/usr/bin",
          MARUHI_TOKEN: "maruhi_pat_parent",
          maruhi_token_origin: "https://maruhi.test",
          MARUHI_FUTURE_AUTH: "reserved",
          APP_MARUHI_TOKEN: "application-value",
          UNDEFINED_VALUE: undefined,
        },
        {
          SECRET: "injected-value",
          MARUHI_TOKEN: "must-not-pass-even-from-extra-env",
        },
      ),
    ).toEqual({
      PATH: "/usr/bin",
      APP_MARUHI_TOKEN: "application-value",
      SECRET: "injected-value",
    });
  });
});

const decode = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

describe("decodeValueText (unified value-decoding policy)", () => {
  it("returns valid UTF-8 as-is (including newlines / tabs) and null for invalid UTF-8", () => {
    expect(decodeValueText(new TextEncoder().encode("multi\nline\tvalue"))).toBe(
      "multi\nline\tvalue",
    );
    // The fatal policy shared by --show / run: no substitution-character camouflage — the caller raises an explicit error
    expect(decodeValueText(new Uint8Array([0xff, 0xfe]))).toBeNull();
  });
});

describe("toCliError (terminal neutralization of server-sourced strings)", () => {
  it("guides a 401 to both possibilities — expired and revoked — and to re-login (AUTH_SPEC §6)", () => {
    // Expiry folds into the same 401 as revocation (the distinction never reaches
    // the wire), so the guidance names both possibilities and the next step (re-login)
    const rendered = toCliError(new UnauthorizedError());
    expect(rendered.message).toContain("expired or revoked");
    expect(rendered.message).toContain("maruhi login");
  });

  it("typed tenant-quota errors do not fall into opaque unknown; they guide the next step (AUTH_SPEC §11-3 / §12-8)", () => {
    // 429 ProjectLimit (org project-count cap — only on new init)
    const projectLimit = toCliError(new ProjectLimitError({ limit: 100 }));
    expect(projectLimit.message).not.toContain("Unexpected error");
    expect(projectLimit.message).toContain("maximum number of projects (100");
    expect(projectLimit.message).toContain("existing projects are unaffected");
    // 422 DataLimitExceeded project-storage-bytes (DO total-storage guard):
    // the guidance says delete / read still work under the refusal (exit path / freeing means)
    const storage = toCliError(
      new DataLimitExceededError({ resource: "project-storage-bytes", limit: 9_000_000_000 }),
    );
    expect(storage.message).toContain("storage guard");
    expect(storage.message).toContain("9000000000 bytes");
    expect(storage.message).toContain("reading values");
    expect(storage.message).toContain("deleting");
    // Other §12-8 quantity caps keep the conventional general form
    const generic = toCliError(new DataLimitExceededError({ resource: "variables", limit: 1000 }));
    expect(generic.message).toBe("Exceeds a server acceptance limit (variables limit 1000)");
  });

  it("neutralizes the error Schema's free-form string IDs", () => {
    // Schema.String fields unconstrained on the wire (a malicious server could embed ANSI / newlines)
    const notFound = toCliError(
      new ProjectNotFoundError({ projectId: "x\u001b[31mred\u001b[0m\nfake" }),
    );
    expect(notFound.message).not.toContain("\u001b");
    expect(notFound.message).not.toContain("\n");
    expect(notFound.message).toContain("x\uFFFD[31mred\uFFFD[0m\uFFFDfake");
  });

  it("an unknown error past all declared cases prints no message — only the type name is attached", () => {
    // All three typed-client failure kinds (declared errors / HttpClientError /
    // SchemaError) are already mapped, so only a true unknown reaches here.
    // message may contain fragments of the response body, so it is **not printed** rather than neutralized
    const unknown = toCliError(new Error("boom sk-live-SUPER-SECRET \u001b]0;pwned\u0007"));
    expect(unknown.message).toBe("Unexpected error (Error)");
    expect(unknown.message).not.toContain("sk-live-SUPER-SECRET");
    expect(unknown.message).not.toContain("\u001b");
  });

  it("connection failure is handled by its own mapping (never falls into unknown)", () => {
    // Why narrowing the unknown fallback does not erase the connection-failure
    // trail: transport-level failures are explained by name in the HttpClientError mapping
    const transport = new HttpClientError.HttpClientError({
      reason: new HttpClientError.TransportError({
        request: HttpClientRequest.get("https://maruhi.example/chain"),
        cause: new Error("connect ECONNREFUSED 127.0.0.1:9"),
      }),
    });
    const rendered = toCliError(transport);
    expect(rendered.message).toContain("Failed to connect to the server");
    expect(rendered.message).not.toContain("Unexpected error");
    // The lower cause's text (host, port, etc.) is not passed through
    expect(rendered.message).not.toContain("ECONNREFUSED");
  });

  it("a response schema mismatch shows only 'location and expectation' (never values)", async () => {
    // Upstream (effect rc.109) formatting shows only the expected type and
    // location. The response body can carry variable names and ciphertext, so **if the formatting ever includes values this test fails**
    const Payload = Schema.Struct({ version: Schema.Number });
    const exit = await Effect.runPromiseExit(
      Schema.decodeUnknownEffect(Payload)({ version: "sk-live-SUPER-SECRET" }),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    if (!Exit.isFailure(exit)) return;
    const rendered = toCliError(Cause.squash(exit.cause));
    expect(rendered.message).toContain("does not match the schema");
    expect(rendered.message).toContain("Expected number");
    expect(rendered.message).toContain('["version"]');
    expect(rendered.message).not.toContain("sk-live-SUPER-SECRET");
    // Request-encode failures flow through the same channel (the direction is not
    // visible from the type), so the guidance lists both directions. If it regresses to one-sided "server's fault" guidance this fails
    expect(rendered.message).toContain("values you provided");
    // Newlines are folded into one line before neutralizing (so replacement chars do not make it unreadable)
    expect(rendered.message).not.toContain("\uFFFD");
  });
});

describe("normalizeStdinValue", () => {
  it("removes only a single trailing newline (LF / CRLF)", () => {
    expect(decode(normalizeStdinValue(new TextEncoder().encode("v\n")))).toBe("v");
    expect(decode(normalizeStdinValue(new TextEncoder().encode("v\r\n")))).toBe("v");
    expect(decode(normalizeStdinValue(new TextEncoder().encode("v\n\n")))).toBe("v\n");
    expect(decode(normalizeStdinValue(new TextEncoder().encode("v")))).toBe("v");
  });
});

describe("cryptoBackendUsable", () => {
  it("is true in a working environment (never blames corruption on the environment)", async () => {
    // This check splits "the key is unreadable" into key vs. environment causes.
    // Returning false on a working environment turns even a genuinely broken
    // record's diagnosis into "environment unsupported — do not delete", making the only recovery step (deleting by hand) unreachable
    expect(await Effect.runPromise(cryptoBackendUsable())).toBe(true);
  });

  it("environment-caused shared wording does not contain 'what is intact' (it differs per path)", () => {
    // Only the keychain path can point to a stored key. recover / generate have
    // not stored anything yet, so shared wording written that far would point at something that does not exist
    expect(unsupportedCryptoCause).not.toContain("do not delete");
    expect(unsupportedCryptoCause).not.toContain("stored");
    // Only the keychain path's wording carries "do not delete it"
    expect(unsupportedCryptoMessage).toContain("do not delete it");
  });
});

describe("the MARUHI_TOKEN env-var path", () => {
  it("works without a keychain by resolving userId via /auth/me", async () => {
    const user = await makeTestUser("user-env-0001");
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", (request) => {
        expect(request.headers["authorization"]).toBe("Bearer maruhi_pat_env");
        return { status: 200, json: { userId: user.userId, orgs: [] } };
      }),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", server.origin);
    // key show requires session resolution + the device key. It errors for lack of
    // a device key, but verifies that session resolution (/auth/me) itself goes through
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("No device key on this machine");
  });

  it("pre-warns on stderr when expiry is within 14 days (ruling CL — the env-var path learns it from /auth/me self-disclosure)", async () => {
    const user = await makeTestUser("user-env-0001");
    const DAY_MS = 24 * 60 * 60 * 1000;
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", () => ({
        status: 200,
        json: { userId: user.userId, orgs: [], tokenExpiresAtMs: Date.now() + 5 * DAY_MS },
      })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", server.origin);
    await runCli(["key", "show"], env.layer);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Warning: the API token expires on");
    expect(errors).toContain("days left");
    expect(errors).toContain("--show-token");
  });

  it("does not warn when expiry is outside the window (env-var path)", async () => {
    const user = await makeTestUser("user-env-0001");
    const DAY_MS = 24 * 60 * 60 * 1000;
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", () => ({
        status: 200,
        json: { userId: user.userId, orgs: [], tokenExpiresAtMs: Date.now() + 60 * DAY_MS },
      })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", server.origin);
    await runCli(["key", "show"], env.layer);
    expect(env.errors.join("\n")).not.toContain("Warning: the API token expires");
  });

  it("the keychain path warns without network from the record's stored expiry; old records (no expiry) behave as before", async () => {
    const DAY_MS = 24 * 60 * 60 * 1000;
    const server = await MockServer.start([]);
    servers.push(server);

    const nearEnv = await makeTestEnv();
    await seedConfig(nearEnv, { server: server.origin });
    nearEnv.keychain.set(
      tokenEntryName(server.origin),
      JSON.stringify({
        token: "maruhi_pat_keychain",
        userId: "user-0001",
        tokenId: "tok_1",
        expiresAtMs: Date.now() + 3 * DAY_MS,
      }),
    );
    await runCli(["key", "show"], nearEnv.layer);
    const nearErrors = nearEnv.errors.join("\n");
    expect(nearErrors).toContain("Warning: the API token expires on");
    expect(nearErrors).toContain("Sign in again with `maruhi login`");
    // The warning needs no communication to decide (not a single request goes out)
    expect(server.requests).toHaveLength(0);

    // Old records written by pre-W3a logins (no expiresAtMs) work without a warning
    const legacyEnv = await makeTestEnv();
    await seedConfig(legacyEnv, { server: server.origin });
    legacyEnv.keychain.set(
      tokenEntryName(server.origin),
      JSON.stringify({ token: "maruhi_pat_keychain", userId: "user-0001", tokenId: "tok_1" }),
    );
    await runCli(["key", "show"], legacyEnv.layer);
    expect(legacyEnv.errors.join("\n")).not.toContain("Warning: the API token expires");
  });

  it("the env var takes precedence over the keychain", async () => {
    const user = await makeTestUser("user-env-0001");
    let presented = "";
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", (request) => {
        presented = String(request.headers["authorization"]);
        return { status: 200, json: { userId: user.userId, orgs: [] } };
      }),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.keychain.set(
      tokenEntryName(server.origin),
      JSON.stringify({ token: "maruhi_pat_keychain", userId: user.userId, tokenId: "tok_1" }),
    );
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", server.origin);
    await runCli(["key", "show"], env.layer);
    expect(presented).toBe("Bearer maruhi_pat_env");
  });

  it("fails with a guidance message when /auth/me returns 401", async () => {
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", () => ({ status: 401, json: { _tag: "Unauthorized" } })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", server.origin);
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Authentication with MARUHI_TOKEN failed");
    // The most likely cause of this 401 in an unattended environment is expiry
    // (W3a ruling CJ). The guidance goes as far as naming the fix — swapping the
    // env var (never regress to the `maruhi login`-alone keychain guidance)
    expect(errors).toContain("expired or revoked");
    expect(errors).toContain("update the MARUHI_TOKEN value");
  });

  it("treats a whitespace-only MARUHI_TOKEN as unset (no round trip with an empty token)", async () => {
    let hit = false;
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", () => {
        hit = true;
        return { status: 200, json: { userId: "u", orgs: [] } };
      }),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    // If the decision were not made on the trimmed value, we would send
    // `Bearer ` (empty) and land on a 401 with guidance for a different cause —
    // "may be expired or revoked" (session.ts's auth-failure wording)
    env.setEnvVar("MARUHI_TOKEN", " \n");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", server.origin);
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    expect(hit).toBe(false);
    expect(env.errors.join("\n")).toContain("Not logged in");
  });

  it("does not use MARUHI_TOKEN and guides when MARUHI_TOKEN_ORIGIN is unset", async () => {
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", () => ({ status: 200, json: { userId: "u", orgs: [] } })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "requires MARUHI_TOKEN_ORIGIN to name the target server origin",
    );
  });

  it("a malformed MARUHI_TOKEN_ORIGIN is an execution failure (1) that shows where to fix", async () => {
    let hit = false;
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", () => {
        hit = true;
        return { status: 200, json: { userId: "u", orgs: [] } };
      }),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    // An env-var value is not a command-line typo, so it is not usage (2) —
    // name the fix target (the env var) and exit with 1
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", "notaurl");
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    const text = env.errors.join("\n");
    expect(text).toContain("fix the MARUHI_TOKEN_ORIGIN env var");
    // The value itself is never echoed (a URL with embedded credentials is possible)
    expect(text).not.toContain("notaurl");
    expect(hit).toBe(false);
  });

  it("does not send the token when MARUHI_TOKEN_ORIGIN does not match the connection target", async () => {
    let hit = false;
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", () => {
        hit = true;
        return { status: 200, json: { userId: "u", orgs: [] } };
      }),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", "https://other.example");
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not match the connection target");
    // The token is never sent to the connection target
    expect(hit).toBe(false);
  });
});

describe("input validation and defect handling", () => {
  it("invalid project / environment IDs error early", async () => {
    const env = await makeTestEnv();
    await seedConfig(env, { server: "https://maruhi.example", defaultEnvironment: "dev" });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    // A usage mistake is a usage error (2). The supplied value itself is not echoed
    expect(await runCli(["pull", "--project", "not-hex"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Invalid project ID");
    expect(env.errors.join("\n")).not.toContain("not-hex");
    const env2 = await makeTestEnv();
    await seedConfig(env2, {
      server: "https://maruhi.example",
      defaultProject: "ab".repeat(32),
    });
    env2.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    // The environment ID format check runs before any network access (session resolution)
    expect(await runCli(["pull", "--env", "!bad"], env2.layer)).toBe(2);
    expect(env2.errors.join("\n")).toContain("Invalid environment ID");
    expect(env2.errors.join("\n")).not.toContain("!bad");
  });

  it("a config-sourced invalid ID is not a typo — it names the fix target and exits 1", async () => {
    const env = await makeTestEnv();
    // Nothing was typed on the command line, so reporting it as 2 (usage error)
    // would be "a usage error with nothing to fix"
    await seedConfig(env, { server: "https://maruhi.example", defaultProject: "not-hex" });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    expect(await runCli(["pull", "--env", "dev"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("fix defaultProject in your config");
  });

  it("a defect (bug-sourced throw) is reported as 1, not a usage error (2)", async () => {
    const env = await makeTestEnv();
    env.breakConfigLoadWithDefect();
    expect(await runCli(["config", "get", "server"], env.layer)).toBe(1);
    // Pin the "only the type name is attached" shape **strictly** (a partial
    // match would still pass after regressing to `internal error: <upstream message>` — the rule would lose its teeth)
    expect(env.errors.join("\n")).toContain("maruhi: internal error (Error)");
    // A defect's message is not shown — even wording embedding the typed value could reach here
    expect(env.errors.join("\n")).not.toContain("config load defect");
  });
});
