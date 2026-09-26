// Service layer for tests: in-memory keychain, output-capturing CliIo,
// recording ProcessRunner, temp-dir config store, real-fetch HttpClient.
// The real keychain (Bun.secrets) doesn't exist in CI, so it is not wired in
// (per task instructions).

import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Effect, Layer, Redacted, Stdio } from "effect";
import { FetchHttpClient, HttpClient, HttpClientRequest } from "effect/unstable/http";

import { AgentProfileRef } from "../../src/agent-gate.ts";
import type { CliServices } from "../../src/cli.ts";
import { ConfigStore, makeFileConfigStore } from "../../src/config.ts";
import { CliError, cliError } from "../../src/errors.ts";
import { makeFileFloorStore } from "../../src/floor-log.ts";
import { floorDirOf, FloorStore } from "../../src/floor.ts";
import { type AgentProfile, CliIo } from "../../src/io.ts";
import {
  Keychain,
  masterKeyEntryName,
  type StoredMasterKey,
  serializeStoredMasterKey,
  serializeStoredToken,
  type StoredToken,
  tokenEntryName,
} from "../../src/keychain.ts";
import {
  FingerprintBook,
  fingerprintBookPathOf,
  makeFileFingerprintBook,
} from "../../src/known-fingerprints.ts";
import { makeFileOwnDeviceStore, OwnDeviceStore, ownDevicesPathOf } from "../../src/own-devices.ts";
import { makeFilePinStore, PinStore, pinsDirOf } from "../../src/pins.ts";
import { type ExecInput, type ExecOutcome, ProcessRunner } from "../../src/run.ts";
import type { TestUser } from "./crypto.ts";

/** One recorded child-process invocation. */
export interface RunnerCall {
  readonly command: readonly string[];
  readonly extraEnv: Readonly<Record<string, string>>;
}

/** One recorded vendor-CLI invocation (`maruhi sync` — stdin is what left maruhi). */
export interface ExecCall {
  readonly command: readonly string[];
  readonly cwd: string;
  readonly extraEnv: Readonly<Record<string, string>>;
  readonly stdin: Uint8Array;
}

/** One recorded `maruhi agent` session child (agent.ts — env carries the socket path). */
export interface SessionCall {
  readonly command: readonly string[];
  readonly env: Readonly<Record<string, string>>;
}

/** A fully in-memory test environment for driving `runCli`. */
export interface TestEnv {
  readonly layer: Layer.Layer<CliServices>;
  readonly keychain: Map<string, string>;
  readonly logs: string[];
  readonly errors: string[];
  readonly runnerCalls: RunnerCall[];
  /** Recorded vendor-CLI invocations (sync — argv / cwd / env / stdin). */
  readonly execCalls: ExecCall[];
  /** Recorded `maruhi agent` child launches (argv and the extra env vars passed). */
  readonly sessionCalls: SessionCall[];
  readonly configPath: string;
  /** Directory of the local floor (§6.3) (<configDir>/floor). */
  readonly floorDir: string;
  /** Directory of invite pins (§6.3 (a) anchor + issue pins) (<configDir>/invites). */
  readonly pinsDir: string;
  /** File path of the verified fingerprint book (KF) (<configDir>/known-fingerprints.json). */
  readonly fingerprintBookPath: string;
  /** Prompt strings shown via promptLine (for assertions). */
  readonly prompts: string[];
  /** URLs passed to openBrowser (for asserting login's auto-browser-launch branch). */
  readonly browserOpens: string[];
  setStdin(bytes: Uint8Array): void;
  /**
   * Fakes the terminal detection (`Stdio`). It is the **primary boundary** for
   * whether values may be displayed, so the default is "a human's interactive
   * terminal" = stdin / stdout / stderr are all terminals. Pass false to
   * reproduce pipes, redirects, CI, or unknown agents.
   */
  setTerminal(input: {
    readonly stdin?: boolean;
    readonly stdout?: boolean;
    readonly stderr?: boolean;
  }): void;
  /**
   * Queues the responses promptLine returns in order (failure once exhausted =
   * EOF equivalent). Functions are evaluated at response time (for answers
   * derived from already-printed logs — e.g. confirming a recovery code was
   * stored).
   */
  setPromptResponses(lines: readonly (string | (() => string))[]): void;
  setAgent(profile: AgentProfile): void;
  /** Color of the stderr prefix (notice.ts). Default is uncolored — so assertions can be plain strings. */
  setColor(enabled: boolean): void;
  setEnvVar(name: string, value: string | undefined): void;
  setRunnerExitCode(code: number): void;
  /**
   * Fakes the vendor CLI's outcome (default: exit 0, no output). Taken as a
   * function so the result can differ per call (e.g. fail only the Nth call).
   */
  setExecHandler(handler: (call: ExecCall, index: number) => ExecOutcome | CliError): void;
  /** Fakes whether openBrowser succeeds (default: succeeds). */
  setBrowserOpenSucceeds(succeeds: boolean): void;
  /**
   * Stands in for the browser in place of openBrowser (passkey — supplement 20
   * ruling J). The handler runs while the CLI is waiting for the page's POST,
   * so it can answer the passed URL via fetch. The return value is "did it
   * open". When set, takes precedence over setBrowserOpenSucceeds.
   */
  setBrowserOpenHandler(handler: (url: string) => Promise<boolean>): void;
  /**
   * Fakes the `maruhi agent` child (default: exit 0). The handler runs while
   * the child is alive = while the agent socket is listening, so it can connect
   * from here and assert the destination.
   */
  setSessionHandler(handler: (call: SessionCall) => Promise<number>): void;
  /** Makes keychain writes fail (for asserting login's revocation fallback). */
  failKeychainWrites(): void;
  /**
   * Fails only the floor commit of an accepted push (reads and pull commits
   * still pass). The floor is a SHOULD; used to pin down that detection does
   * not rely on the floor alone when it cannot be written.
   */
  failFloorPushCommits(): void;
  /**
   * Fails only intent (3-F) appends. journal-before-send is the only
   * fail-closed floor write (no send when persisting fails); used to pin down
   * a regression toward fail-open as "not a single request reaches the
   * server".
   */
  failFloorIntentAppends(): void;
  /** For testing the defect path: makes config load throw (a non-CliError). */
  breakConfigLoadWithDefect(): void;
  /**
   * Redirects the vendor API (`maruhi sync`'s http driver) targets to a fake
   * server. Production code only knows the preset fixed hosts
   * (`https://api.vercel.com` etc.) and offers no override point — the swap
   * happens at the HttpClient layer (the test boundary).
   */
  setVendorOrigin(host: string, origin: string): void;
}

/** The default `maruhi agent` child (does nothing, exits 0). */
function sessionExitsZero(): Promise<number> {
  return Promise.resolve(0);
}

/** The default vendor-CLI response (success, no output). */
function execSucceeds(): ExecOutcome {
  return { exitCode: 0, output: "" };
}

export async function makeTestEnv(): Promise<TestEnv> {
  const configDir = await mkdtemp(join(tmpdir(), "maruhi-cli-test-"));
  const configPath = join(configDir, "config.json");
  const keychain = new Map<string, string>();
  const logs: string[] = [];
  const errors: string[] = [];
  const runnerCalls: RunnerCall[] = [];
  const execCalls: ExecCall[] = [];
  let execHandler: (call: ExecCall, index: number) => ExecOutcome | CliError = execSucceeds;
  const envVars = new Map<string, string>();
  const prompts: string[] = [];
  const promptResponses: (string | (() => string))[] = [];
  const browserOpens: string[] = [];
  let browserOpenSucceeds = true;
  let browserOpenHandler: ((url: string) => Promise<boolean>) | null = null;
  const sessionCalls: SessionCall[] = [];
  let sessionHandler: (call: SessionCall) => Promise<number> = sessionExitsZero;
  let stdin: Uint8Array = new Uint8Array(0);
  let agent: AgentProfile = { isAgent: false };
  let colorEnabled = false;
  // Default is the "a human ran this at an interactive terminal" shape (the
  // only shape where displaying values is allowed)
  let stdinIsTerminal = true;
  let stdoutIsTerminal = true;
  let stderrIsTerminal = true;
  let runnerExitCode = 0;
  let keychainWritable = true;
  let floorPushCommittable = true;
  let floorIntentAppendable = true;
  let configLoadDefect = false;
  const vendorOrigins = new Map<string, string>();

  const fileStore = makeFileConfigStore(configPath);
  const floorDir = floorDirOf(configPath);
  const floorStore = makeFileFloorStore(floorDir);
  const pinsDir = pinsDirOf(configPath);
  const pinStore = makeFilePinStore(pinsDir);
  const fingerprintBookPath = fingerprintBookPathOf(configPath);
  const fingerprintBook = makeFileFingerprintBook(fingerprintBookPath);
  const layer = Layer.mergeAll(
    // argv is passed per run by runCli (effect-cli.ts remounts it onto Stdio).
    // What gets fixed here is terminal detection — the primary boundary for
    // whether values may be displayed (agent-gate.ts)
    Stdio.layerTest({
      stdinIsTerminal: Effect.sync(() => stdinIsTerminal),
      stdoutIsTerminal: Effect.sync(() => stdoutIsTerminal),
    }),
    // The secondary layer (known-agent detection result); in production
    // live.ts supplies it from std-env
    Layer.sync(AgentProfileRef, () => agent),
    Layer.succeed(PinStore, pinStore),
    Layer.succeed(FingerprintBook, fingerprintBook),
    Layer.succeed(OwnDeviceStore, makeFileOwnDeviceStore(ownDevicesPathOf(configPath))),
    Layer.succeed(FloorStore, {
      load: (projectId) => floorStore.load(projectId),
      commitHead: (projectId, head) => floorStore.commitHead(projectId, head),
      commitPull: (projectId, commit) => floorStore.commitPull(projectId, commit),
      commitPush: (projectId, commit) =>
        Effect.suspend(() =>
          floorPushCommittable
            ? floorStore.commitPush(projectId, commit)
            : Effect.fail(cliError("cannot write to the local floor (test injection)")),
        ),
      commitMetadata: (projectId, commit) => floorStore.commitMetadata(projectId, commit),
      commitManifest: (projectId, commit) =>
        Effect.suspend(() =>
          floorPushCommittable
            ? floorStore.commitManifest(projectId, commit)
            : Effect.fail(cliError("cannot write to the local floor (test injection)")),
        ),
      appendIntent: (projectId, intent) =>
        Effect.suspend(() =>
          floorIntentAppendable
            ? floorStore.appendIntent(projectId, intent)
            : Effect.fail(cliError("cannot write the intent to the local floor (test injection)")),
        ),
      resolveIntent: (projectId, intentId, outcome) =>
        floorStore.resolveIntent(projectId, intentId, outcome),
      loadAttestedHead: (projectId) => floorStore.loadAttestedHead(projectId),
      listProjectIds: () => floorStore.listProjectIds(),
      saveAttestedHead: (projectId, head) => floorStore.saveAttestedHead(projectId, head),
      appendAttestationEvidence: (projectId, evidence) =>
        floorStore.appendAttestationEvidence(projectId, evidence),
    }),
    Layer.succeed(Keychain, {
      kind: "os-keychain",
      get: (name) => Effect.sync(() => keychain.get(name) ?? null),
      set: (name, value) =>
        Effect.suspend(() => {
          if (!keychainWritable) {
            return Effect.fail(cliError("キーチェーンに書き込めません(テスト注入)")); // english-exempt: asserts literal text owned by apps/cli/test/login.test.ts
          }
          keychain.set(name, value);
          return Effect.void;
        }),
      remove: (name) =>
        Effect.sync(() => {
          keychain.delete(name);
        }),
    }),
    Layer.succeed(ConfigStore, {
      load: Effect.suspend(() => {
        if (configLoadDefect) {
          throw new Error("config load defect (test)");
        }
        return fileStore.load;
      }),
      save: (config) => fileStore.save(config),
    }),
    Layer.succeed(CliIo, {
      log: (line) =>
        Effect.sync(() => {
          logs.push(line);
        }),
      logError: (line) =>
        Effect.sync(() => {
          errors.push(line);
        }),
      readStdin: Effect.suspend(() => Effect.succeed(stdin)),
      promptLine: ({ prompt }) =>
        Effect.suspend(() => {
          prompts.push(prompt);
          const next = promptResponses.shift();
          return next === undefined
            ? Effect.fail(cliError("cannot read interactive input (test: response queue is empty)"))
            : Effect.succeed(typeof next === "function" ? next() : next);
        }),
      envVar: (name) => envVars.get(name),
      agentProfile: () => agent,
      stderrIsTerminal: () => stderrIsTerminal,
      colorEnabled: () => colorEnabled,
      openBrowser: (url) =>
        Effect.promise(async () => {
          browserOpens.push(url);
          if (browserOpenHandler !== null) {
            // The browser stand-in must POST to the page while the CLI is
            // waiting, so return "opened" without awaiting completion. The
            // handler's rejection is not swallowed (vitest would fail the test
            // as an unhandled rejection — don't wait out the 5-minute timeout).
            // openBrowser itself only reports launch success in production too
            void browserOpenHandler(url);
            return true;
          }
          return browserOpenSucceeds;
        }),
    }),
    Layer.succeed(ProcessRunner, {
      run: ({ command, extraEnv }) =>
        Effect.sync(() => {
          runnerCalls.push({ command, extraEnv });
          return runnerExitCode;
        }),
      exec: (input: ExecInput) =>
        Effect.suspend(() => {
          // Fake child process: records the bytes that arrived on stdin
          // (evidence for where the value went; in production live.ts this is
          // Bun.spawn's stdin)
          const call: ExecCall = {
            command: input.command,
            cwd: input.cwd,
            extraEnv: input.extraEnv,
            stdin: Redacted.value(input.stdin),
          };
          execCalls.push(call);
          const outcome = execHandler(call, execCalls.length - 1);
          // A faked spawn failure (unimplemented — live.ts's execStartFailure)
          // is returned as a typed error
          return outcome instanceof CliError ? Effect.fail(outcome) : Effect.succeed(outcome);
        }),
      runSession: ({ command, env }) =>
        Effect.tryPromise({
          try: () => {
            const call: SessionCall = { command, env };
            sessionCalls.push(call);
            return sessionHandler(call);
          },
          catch: () => cliError("cannot spawn the agent session child (test injection)"),
        }),
    }),
    // Real-fetch HttpClient; only the vendor APIs' fixed hosts are remapped to
    // the fake server (requests to the maruhi server already have the fake
    // origin)
    Layer.effect(
      HttpClient.HttpClient,
      Effect.map(HttpClient.HttpClient, (client) =>
        HttpClient.mapRequest(client, (request) => {
          for (const [host, origin] of vendorOrigins) {
            const prefix = `https://${host}`;
            if (request.url.startsWith(prefix)) {
              return HttpClientRequest.setUrl(
                request,
                `${origin}${request.url.slice(prefix.length)}`,
              );
            }
          }
          return request;
        }),
      ),
    ).pipe(Layer.provide(FetchHttpClient.layer)),
  );

  return {
    layer,
    keychain,
    logs,
    errors,
    runnerCalls,
    execCalls,
    sessionCalls,
    configPath,
    floorDir,
    pinsDir,
    fingerprintBookPath,
    prompts,
    browserOpens,
    setStdin(bytes) {
      stdin = bytes;
    },
    setTerminal({ stdin: isStdinTerminal, stdout: isStdoutTerminal, stderr: isStderrTerminal }) {
      stdinIsTerminal = isStdinTerminal ?? stdinIsTerminal;
      stdoutIsTerminal = isStdoutTerminal ?? stdoutIsTerminal;
      stderrIsTerminal = isStderrTerminal ?? stderrIsTerminal;
    },
    setPromptResponses(lines) {
      promptResponses.length = 0;
      promptResponses.push(...lines);
    },
    setAgent(profile) {
      agent = profile;
    },
    setColor(enabled) {
      colorEnabled = enabled;
    },
    setEnvVar(name, value) {
      if (value === undefined) {
        envVars.delete(name);
      } else {
        envVars.set(name, value);
      }
    },
    setRunnerExitCode(code) {
      runnerExitCode = code;
    },
    setExecHandler(handler) {
      execHandler = handler;
    },
    setBrowserOpenSucceeds(succeeds) {
      browserOpenSucceeds = succeeds;
    },
    setBrowserOpenHandler(handler) {
      browserOpenHandler = handler;
    },
    setSessionHandler(handler) {
      sessionHandler = handler;
    },
    failKeychainWrites() {
      keychainWritable = false;
    },
    failFloorPushCommits() {
      floorPushCommittable = false;
    },
    failFloorIntentAppends() {
      floorIntentAppendable = false;
    },
    breakConfigLoadWithDefect() {
      configLoadDefect = true;
    },
    setVendorOrigin(host, origin) {
      vendorOrigins.set(host, origin);
    },
  };
}

/** Seeds the keychain into a logged-in + master-key-stored state. */
export function seedSession(env: TestEnv, origin: string, user: TestUser): void {
  const token: StoredToken = {
    // Fixture shaped like the real server's format (maruhi_pat_ + Base62 random)
    token: Redacted.make("maruhi_pat_Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St9x123"),
    userId: user.userId,
    tokenId: "tok_0001",
  };
  const master: StoredMasterKey = {
    suite: "maruhi/v1",
    encPubHex: user.encPubHex,
    encSkHex: Redacted.make(user.encSkHex),
    sigPubHex: user.sigPubHex,
    sigSkSeedHex: Redacted.make(user.sigSkSeedHex),
  };
  // JSON.stringify(token) cannot be used — Redacted.toJSON() returns a redacted
  // string, producing a "seeded but cannot authenticate" test (the same trap as
  // production login.ts)
  env.keychain.set(tokenEntryName(origin), serializeStoredToken(token));
  // JSON.stringify cannot be used for the master key either (the secret side
  // would be stored redacted and become undecryptable)
  env.keychain.set(masterKeyEntryName(origin, user.userId), serializeStoredMasterKey(master));
}

/** Creates the state where config.json has server (+ any defaults) written. */
export async function seedConfig(
  env: TestEnv,
  config: Readonly<Record<string, string>>,
): Promise<void> {
  const { writeFile, mkdir } = await import("node:fs/promises");
  const { dirname } = await import("node:path");
  await mkdir(dirname(env.configPath), { recursive: true });
  await writeFile(env.configPath, JSON.stringify(config));
}
