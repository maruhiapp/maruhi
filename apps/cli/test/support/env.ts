import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { cryptoServicesLayer } from "@maruhi/core";
import { Effect, Layer, Redacted, Sink, Stdio, Stream } from "effect";
import { FetchHttpClient, HttpClient, HttpClientRequest } from "effect/http";

import { AgentProfileRef } from "../../src/agent-gate.ts";
import type { CliServices } from "../../src/cli.ts";
import { ConfigStore, makeFileConfigStore } from "../../src/config.ts";
import { SqlRunner, type SqlRunnerShape } from "../../src/connector.package/connector-sql.ts";
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
import {
  acceptedProxyConfigsPathOf,
  makeFileProxyAcceptStore,
  ProxyAcceptStore,
} from "../../src/proxy.package/proxy-accept.ts";
import { ProxySeams, type ProxySeamsShape } from "../../src/proxy.package/proxy-run.ts";
import {
  type CaptureInput,
  type CaptureOutcome,
  type ExecInput,
  type ExecOutcome,
  ProcessRunner,
} from "../../src/run.ts";
import type { TestUser } from "./crypto.ts";

export interface RunnerCall {
  readonly command: readonly string[];
  readonly extraEnv: Readonly<Record<string, string>>;
  readonly holdSignals: boolean;
  readonly redact: readonly Uint8Array[] | undefined;
}

export interface ExecCall {
  readonly command: readonly string[];
  readonly cwd: string;
  readonly extraEnv: Readonly<Record<string, string>>;
  readonly stdin: Uint8Array;
}

export type CaptureCall = CaptureInput;

export interface SessionCall {
  readonly command: readonly string[];
  readonly env: Readonly<Record<string, string>>;
}

export interface TestEnv {
  readonly layer: Layer.Layer<CliServices>;
  readonly keychain: Map<string, string>;
  readonly logs: string[];
  readonly errors: string[];
  readonly runnerCalls: RunnerCall[];
  readonly execCalls: ExecCall[];
  readonly sessionCalls: SessionCall[];
  readonly captureCalls: CaptureCall[];
  readonly configPath: string;
  readonly floorDir: string;
  readonly pinsDir: string;
  readonly fingerprintBookPath: string;
  readonly prompts: string[];
  readonly browserOpens: string[];
  readonly stdioOut: string[];
  setStdin(bytes: Uint8Array): void;
  setStdioIn(stream: Stream.Stream<Uint8Array>): void;
  setTerminal(input: {
    readonly stdin?: boolean;
    readonly stdout?: boolean;
    readonly stderr?: boolean;
  }): void;
  setPromptResponses(lines: readonly (string | (() => string))[]): void;
  setAgent(profile: AgentProfile): void;
  setColor(enabled: boolean): void;
  setEnvVar(name: string, value: string | undefined): void;
  setRunnerExitCode(code: number): void;
  setRunnerHandler(handler: (call: RunnerCall) => Promise<number>): void;
  setProxySeams(seams: ProxySeamsShape | null): void;
  setSqlRunner(runner: SqlRunnerShape): void;
  setExecHandler(handler: (call: ExecCall, index: number) => ExecOutcome | CliError): void;
  setCaptureHandler(handler: (call: CaptureCall, index: number) => CaptureOutcome): void;
  setBrowserOpenSucceeds(succeeds: boolean): void;
  setBrowserOpenHandler(handler: (url: string) => Promise<boolean>): void;
  setSessionHandler(handler: (call: SessionCall) => Promise<number>): void;
  failKeychainWrites(): void;
  failFloorPushCommits(): void;
  failFloorIntentAppends(): void;
  breakConfigLoadWithDefect(): void;
  setVendorOrigin(host: string, origin: string): void;
}

function sessionExitsZero(): Promise<number> {
  return Promise.resolve(0);
}

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
  const captureCalls: CaptureCall[] = [];
  let captureHandler: (call: CaptureCall, index: number) => CaptureOutcome = () => {
    throw new Error("cannot start the script (test injection)");
  };
  const envVars = new Map<string, string>();
  const prompts: string[] = [];
  const promptResponses: (string | (() => string))[] = [];
  const browserOpens: string[] = [];
  let browserOpenSucceeds = true;
  let browserOpenHandler: ((url: string) => Promise<boolean>) | null = null;
  const sessionCalls: SessionCall[] = [];
  let sessionHandler: (call: SessionCall) => Promise<number> = sessionExitsZero;
  let stdin: Uint8Array = new Uint8Array(0);
  let stdioIn: Stream.Stream<Uint8Array> = Stream.empty;
  const stdioOut: string[] = [];
  const stdoutDecoder = new TextDecoder();
  let agent: AgentProfile = { isAgent: false };
  let colorEnabled = false;
  let stdinIsTerminal = true;
  let stdoutIsTerminal = true;
  let stderrIsTerminal = true;
  let runnerExitCode = 0;
  let runnerHandler: ((call: RunnerCall) => Promise<number>) | null = null;
  let proxySeams: ProxySeamsShape | null = null;
  let sqlRunner: SqlRunnerShape = {
    execute: () => Promise.reject(new Error("no database client in tests (setSqlRunner)")),
    probe: () => Promise.reject(new Error("no database client in tests (setSqlRunner)")),
  };
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
    cryptoServicesLayer,
    Stdio.layerTest({
      stdinIsTerminal: Effect.sync(() => stdinIsTerminal),
      stdoutIsTerminal: Effect.sync(() => stdoutIsTerminal),
      stdin: Stream.suspend(() => stdioIn),
      stdout: () =>
        Sink.forEach((chunk: string | Uint8Array) =>
          Effect.sync(() => {
            stdioOut.push(
              typeof chunk === "string" ? chunk : stdoutDecoder.decode(chunk, { stream: true }),
            );
          }),
        ),
    }),
    Layer.sync(AgentProfileRef, () => agent),
    Layer.succeed(PinStore, pinStore),
    Layer.succeed(FingerprintBook, fingerprintBook),
    Layer.succeed(OwnDeviceStore, makeFileOwnDeviceStore(ownDevicesPathOf(configPath))),
    Layer.succeed(
      ProxyAcceptStore,
      makeFileProxyAcceptStore(acceptedProxyConfigsPathOf(configDir)),
    ),
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
            return Effect.fail(cliError("cannot write to the keychain (test injection)"));
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
            void browserOpenHandler(url);
            return true;
          }
          return browserOpenSucceeds;
        }),
    }),
    Layer.sync(ProxySeams, () => proxySeams),
    Layer.succeed(SqlRunner, {
      execute: (url, statements) => sqlRunner.execute(url, statements),
      probe: (url) => sqlRunner.probe(url),
    }),
    Layer.succeed(ProcessRunner, {
      run: ({ command, extraEnv, holdSignals, redact }) =>
        Effect.tryPromise({
          try: () => {
            const call: RunnerCall = {
              command,
              extraEnv,
              holdSignals: holdSignals === true,
              redact,
            };
            runnerCalls.push(call);
            return runnerHandler === null ? Promise.resolve(runnerExitCode) : runnerHandler(call);
          },
          catch: () => cliError("cannot spawn the run child (test injection)"),
        }),
      exec: (input: ExecInput) =>
        Effect.suspend(() => {
          const call: ExecCall = {
            command: input.command,
            cwd: input.cwd,
            extraEnv: input.extraEnv,
            stdin: Redacted.value(input.stdin),
          };
          execCalls.push(call);
          const outcome = execHandler(call, execCalls.length - 1);
          return outcome instanceof CliError ? Effect.fail(outcome) : Effect.succeed(outcome);
        }),
      captureScript: (input) => {
        const call: CaptureCall = {
          command: input.command,
          cwd: input.cwd,
          extraEnv: input.extraEnv,
        };
        captureCalls.push(call);
        try {
          return Promise.resolve(captureHandler(call, captureCalls.length - 1));
        } catch (error) {
          return Promise.reject(error);
        }
      },
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
    captureCalls,
    configPath,
    floorDir,
    pinsDir,
    fingerprintBookPath,
    prompts,
    browserOpens,
    stdioOut,
    setStdioIn(stream) {
      stdioIn = stream;
    },
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
    setRunnerHandler(handler) {
      runnerHandler = handler;
    },
    setProxySeams(seams) {
      proxySeams = seams;
    },
    setSqlRunner(runner) {
      sqlRunner = runner;
    },
    setExecHandler(handler) {
      execHandler = handler;
    },
    setCaptureHandler(handler) {
      captureHandler = handler;
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

export function seedSession(env: TestEnv, origin: string, user: TestUser): void {
  const token: StoredToken = {
    token: Redacted.make("maruhi_pat_Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St9x123"),
    userId: user.userId,
    tokenId: "tok_0001",
    expiresAtMs: 4_102_444_800_000,
  };
  const master: StoredMasterKey = {
    suite: "maruhi/v1",
    encPubHex: user.encPubHex,
    encSkHex: Redacted.make(user.encSkHex),
    sigPubHex: user.sigPubHex,
    sigSkSeedHex: Redacted.make(user.sigSkSeedHex),
  };
  env.keychain.set(tokenEntryName(origin), serializeStoredToken(token));
  env.keychain.set(masterKeyEntryName(origin, user.userId), serializeStoredMasterKey(master));
}

export async function seedConfig(
  env: TestEnv,
  config: Readonly<Record<string, string>>,
): Promise<void> {
  const { writeFile, mkdir } = await import("node:fs/promises");
  const { dirname } = await import("node:path");
  await mkdir(dirname(env.configPath), { recursive: true });
  await writeFile(env.configPath, JSON.stringify(config));
}
