// Unit tests for run.ts: runOp, and the child environment `maruhi run`
// injects (buildInjectionEnv's checks and buildChildEnvironment).

import { Effect, Exit, Layer, Stdio } from "effect";
import { describe, expect, it } from "vitest";

import { CliIo } from "../src/io.ts";
import { buildChildEnvironment, buildInjectionEnv, ProcessRunner, runOp } from "../src/run.ts";
import { variable } from "./support/variable.ts";

describe("runOp", () => {
  /** A runner that never spawns the child process (so reaching spawn is observable). */
  const spawnedNothing = Layer.mergeAll(
    Layer.succeed(ProcessRunner, {
      run: () => Effect.succeed(0),
      exec: () => Effect.succeed({ exitCode: 0, output: "" }),
      captureScript: () => Promise.resolve({ exitCode: 0, stdout: new Uint8Array(0), stderr: "" }),
      runSession: () => Effect.succeed(0),
    }),
    // The run-output redaction's terminal evidence (run.ts) — a human terminal here
    Layer.succeed(CliIo, {
      log: () => Effect.void,
      logError: () => Effect.void,
      readStdin: Effect.succeed(new Uint8Array(0)),
      promptLine: () => Effect.succeed(""),
      envVar: () => undefined,
      agentProfile: () => ({ isAgent: false }),
      stderrIsTerminal: () => true,
      colorEnabled: () => false,
      openBrowser: () => Effect.succeed(false),
    }),
    Stdio.layerTest({
      stdinIsTerminal: Effect.succeed(true),
      stdoutIsTerminal: Effect.succeed(true),
    }),
  );

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
