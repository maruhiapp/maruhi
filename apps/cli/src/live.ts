import { writeSync } from "node:fs";
import { stat } from "node:fs/promises";
import { homedir, userInfo } from "node:os";

import * as BunStdio from "@effect/platform-bun/BunStdio";
import { cryptoServicesLayer, egressHttpClientLayer } from "@maruhi/core";
import { Duration, Effect, Layer, Redacted } from "effect";
import { agentInfo } from "std-env";

import { type AgentProfile, AgentProfileRef } from "./agent-gate.ts";
import { AGENT_SOCKET_ENV, makeAgentKeychain } from "./agent.ts";
import { makeStreamReplacer, scrubPatterns } from "./byte-replace.ts";
import type { CliServices } from "./cli.ts";
import { ConfigStore, defaultConfigPath, makeFileConfigStore } from "./config.ts";
import { SqlRunner, type SqlRunnerShape } from "./connector.package/index.ts";
import { cliError } from "./errors.ts";
import { makeFileFloorStore } from "./floor-log.ts";
import { floorDirOf, FloorStore } from "./floor.ts";
import { CliIo, type CliIoShape } from "./io.ts";
import { KEYCHAIN_SERVICE, Keychain, type KeychainShape } from "./keychain.ts";
import {
  FingerprintBook,
  fingerprintBookPathOf,
  makeFileFingerprintBook,
} from "./known-fingerprints.ts";
import { shouldUseColor } from "./notice.ts";
import { makeFileOwnDeviceStore, OwnDeviceStore, ownDevicesPathOf } from "./own-devices.ts";
import { makeFilePinStore, PinStore, pinsDirOf } from "./pins.ts";
import {
  acceptedProxyConfigsPathOf,
  makeFileProxyAcceptStore,
  ProxyAcceptStore,
} from "./proxy.package/index.ts";
import {
  buildChildEnvironment,
  type CaptureInput,
  type CaptureOutcome,
  ScriptLeftoverError,
  ScriptStoppedError,
  type ExecInput,
  type ExecOutcome,
  ProcessRunner,
  type ProcessRunnerShape,
} from "./run.ts";

const keychainUnavailable = () =>
  cliError(
    "Cannot access the OS keychain (tokens and keys cannot be stored in this environment). maruhi does not fall back to plaintext files — run `maruhi agent -- <shell>` to keep them in memory for that shell's lifetime, or pass a token via the MARUHI_TOKEN environment variable",
  );

const KEYCHAIN_TIMEOUT = Duration.seconds(30);

const keychainWriteTimedOut = () =>
  cliError(
    `Writing to the OS keychain timed out. The write cannot be cancelled and may still complete in the background — if a later command reports that a key or token already exists, that write did land. Check the stored state with \`maruhi key show\`, and remove a stale entry via your OS keychain manager (service: ${KEYCHAIN_SERVICE}) before retrying. maruhi does not fall back to plaintext files`,
  );
const keychainRemoveTimedOut = () =>
  cliError(
    `Removing from the OS keychain timed out. The removal cannot be cancelled and may still complete in the background — the entry may be gone even though this command failed. Check the stored state with \`maruhi key show\` (or your OS keychain manager, service: ${KEYCHAIN_SERVICE}) before retrying`,
  );

function keychainOp<T>(
  run: () => Promise<T>,
  onTimeout: () => ReturnType<typeof cliError> = keychainUnavailable,
): Effect.Effect<T, ReturnType<typeof cliError>> {
  return Effect.tryPromise({ try: run, catch: keychainUnavailable }).pipe(
    Effect.timeout(KEYCHAIN_TIMEOUT),
    Effect.catchTag("TimeoutError", () => Effect.fail(onTimeout())),
  );
}

function makeBunKeychain(): KeychainShape {
  return {
    kind: "os-keychain",
    get: (name) => keychainOp(() => Bun.secrets.get({ service: KEYCHAIN_SERVICE, name })),
    set: (name, value) =>
      keychainOp(
        () => Bun.secrets.set({ service: KEYCHAIN_SERVICE, name, value }),
        keychainWriteTimedOut,
      ),
    remove: (name) =>
      keychainOp(async () => {
        await Bun.secrets.delete({ service: KEYCHAIN_SERVICE, name });
      }, keychainRemoveTimedOut),
  };
}

async function execVendor(input: ExecInput): Promise<ExecOutcome> {
  const cwdStat = await stat(input.cwd).catch(() => null);
  if (cwdStat === null || !cwdStat.isDirectory()) {
    throw new CwdUnavailableError(input.cwd);
  }
  const stdin = Redacted.value(input.stdin);
  const child = Bun.spawn({
    cmd: [...input.command],
    cwd: input.cwd,
    env: buildChildEnvironment(process.env, input.extraEnv),
    stdin,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  return { exitCode, output: `${stdout}${stderr}` };
}

async function captureScript(input: CaptureInput): Promise<CaptureOutcome> {
  const child = await startScript(input);
  const name = input.command[0] ?? "";
  const timers: ReturnType<typeof setTimeout>[] = [];
  const watch: ScriptWatch = {
    exitedAtMs: null,
    postExitBytes: 0,
    stdoutClosedAtMs: null,
    leftover: false,
    stopped: false,
  };
  const out = (child.stdout as ReadableStream<Uint8Array>).getReader();
  const err = (child.stderr as ReadableStream<Uint8Array>).getReader();
  const stopPastCap = (bytes: Uint8Array | null) => {
    watch.stdoutClosedAtMs = Date.now();
    if (bytes === null && watch.exitedAtMs === null) {
      watch.stopped = true;
      child.kill();
      timers.push(setTimeout(() => child.kill("SIGKILL"), SCRIPT_GRACE_MS));
    }
    return bytes;
  };
  const exited = child.exited.then((code) => {
    watch.exitedAtMs = Date.now();
    timers.push(
      setTimeout(() => {
        watch.leftover = true;
        void out.cancel().catch(() => undefined);
        void err.cancel().catch(() => undefined);
      }, SCRIPT_GRACE_MS),
    );
    return code;
  });
  const [stdout, stderrBytes, exitCode] = await Promise.all([
    readBounded(out, MAX_SCRIPT_STREAM_BYTES, "cancel", (bytes) => {
      if (watch.exitedAtMs !== null) {
        watch.postExitBytes += bytes;
      }
    }).then(stopPastCap),
    readBounded(err, MAX_SCRIPT_STREAM_BYTES, "drain"),
    exited,
  ]).finally(() => {
    for (const timer of timers) {
      clearTimeout(timer);
    }
  });
  return judgeCapture(name, watch, { stdout, stderrBytes, exitCode });
}

async function startScript(input: CaptureInput): Promise<ReturnType<typeof Bun.spawn>> {
  const cwdStat = await stat(input.cwd).catch(() => null);
  if (cwdStat === null || !cwdStat.isDirectory()) {
    throw new Error(
      `the scripts' working directory does not exist or is not a directory (${input.cwd}) — fix the rule's cwd in the rotation config`,
    );
  }
  try {
    return Bun.spawn({
      cmd: [...input.command],
      cwd: input.cwd,
      env: buildChildEnvironment(process.env, input.extraEnv),
      stdin: new Uint8Array(0),
      stdout: "pipe",
      stderr: "pipe",
    });
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    throw new Error(
      `cannot start ${input.command[0] ?? ""}${code === undefined ? "" : ` (${code})`}: is it executable and on PATH, or a path relative to the rule's cwd?`,
      { cause: error },
    );
  }
}

interface ScriptWatch {
  exitedAtMs: number | null;
  postExitBytes: number;
  stdoutClosedAtMs: number | null;
  leftover: boolean;
  stopped: boolean;
}

function judgeCapture(
  name: string,
  watch: ScriptWatch,
  read: {
    readonly stdout: Uint8Array | null;
    readonly stderrBytes: Uint8Array | null;
    readonly exitCode: number;
  },
): CaptureOutcome {
  if (watch.stopped) {
    throw new ScriptStoppedError(
      `${name} wrote more than ${MAX_SCRIPT_STREAM_MIB} MiB to stdout (a credential is small; commentary belongs on stderr): it was stopped and nothing it wrote was read`,
    );
  }
  if (read.exitCode === 0 && leftoverWrote(watch, read.stdout)) {
    throw new ScriptLeftoverError(
      read.exitCode,
      `${name} exited (code ${read.exitCode}) while a process it started kept writing to its stdout: the answer cannot be told from that output. Redirect that process's output in the script (\`>/dev/null 2>&1\`)`,
    );
  }
  return {
    exitCode: read.exitCode,
    stdout: read.stdout ?? new Uint8Array(0),
    stderr: stderrText(read.stderrBytes, watch.leftover),
  };
}

function leftoverWrote(watch: ScriptWatch, stdout: Uint8Array | null): boolean {
  const closedAtOnce =
    watch.exitedAtMs !== null &&
    watch.stdoutClosedAtMs !== null &&
    watch.stdoutClosedAtMs - watch.exitedAtMs <= SCRIPT_SETTLE_MS;
  return watch.postExitBytes > 0 && (stdout === null || !closedAtOnce);
}

function stderrText(bytes: Uint8Array | null, leftover: boolean): string {
  const stderr =
    bytes === null
      ? `(the script wrote more than ${MAX_SCRIPT_STREAM_MIB} MiB to stderr; none of it is shown)`
      : new TextDecoder().decode(bytes);
  const held = leftover
    ? `\n(a process the script started still held its output ${SCRIPT_GRACE_MS / 1000} s after the script exited; what it wrote later was not read)`
    : "";
  return `${stderr}${held}`;
}

const SCRIPT_GRACE_MS = 3000;
const SCRIPT_SETTLE_MS = 200;

const MAX_SCRIPT_STREAM_MIB = 1;
const MAX_SCRIPT_STREAM_BYTES = MAX_SCRIPT_STREAM_MIB * 1024 * 1024;

async function readBounded(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  limit: number,
  pastLimit: "cancel" | "drain",
  onChunk?: (bytes: number) => void,
): Promise<Uint8Array | null> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    onChunk?.(value.byteLength);
    total += value.byteLength;
    if (total > limit) {
      if (pastLimit === "cancel") {
        await reader.cancel();
      } else {
        while (!(await reader.read()).done) {}
      }
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

class CwdUnavailableError extends Error {
  constructor(readonly cwd: string) {
    super("cwd unavailable");
  }
}

function execStartFailure(input: ExecInput, error: unknown): string {
  if (error instanceof CwdUnavailableError) {
    return `Cannot run ${input.command[0] ?? ""}: the target's working directory does not exist or is not a directory (${error.cwd}). Fix the target's cwd in the sync config`;
  }
  const code = (error as NodeJS.ErrnoException).code;
  return `Cannot start ${input.command[0] ?? ""}${code === undefined ? "" : ` (${code})`}: is it installed and on PATH, or named by a \`command\` in the sync config? maruhi never downloads a vendor CLI: install it and sign in with it, then retry`;
}

async function withSqlConnection(
  url: string,
  body: (sql: Bun.SQL) => Promise<void>,
): Promise<void> {
  const sql = new Bun.SQL(url, { max: 1 });
  try {
    await body(sql);
  } finally {
    await sql.close();
  }
}

function makeBunSqlRunner(): SqlRunnerShape {
  return {
    execute: (url, statements) =>
      withSqlConnection(url, async (sql) => {
        for (const statement of statements) {
          await sql.unsafe(statement);
        }
      }),
    probe: (url) =>
      withSqlConnection(url, async (sql) => {
        await sql.unsafe("SELECT 1");
      }),
  };
}

function makeBunProcessRunner(): ProcessRunnerShape {
  return {
    run: ({ command, extraEnv, holdSignals, redact }) =>
      Effect.tryPromise({
        try: async () => {
          const piped = redact !== undefined;
          const child = Bun.spawn({
            cmd: [...command],
            env: buildChildEnvironment(process.env, extraEnv),
            stdin: "inherit",
            stdout: piped ? "pipe" : "inherit",
            stderr: piped ? "pipe" : "inherit",
          });
          const relays = piped ? startRedactedRelay(child, redact) : null;
          const exitCode = holdSignals === true ? await holdingSignals(child) : await child.exited;
          if (relays !== null) {
            const grace = setTimeout(() => relays.abort(), RELAY_GRACE_MS);
            await relays.done;
            clearTimeout(grace);
          }
          return exitCode;
        },
        catch: () => cliError(`Cannot start the command: ${command[0] ?? ""}`),
      }),
    exec: (input) =>
      Effect.tryPromise({
        try: () => execVendor(input),
        catch: (error) => cliError(execStartFailure(input, error)),
      }),
    captureScript,
    runSession: ({ command, env }) =>
      Effect.tryPromise({
        try: () => runAgentSession(command, env),
        catch: () => cliError(`Cannot start the command: ${command[0] ?? ""}`),
      }),
  };
}

const ignoreInterrupt = (): void => {};

async function runAgentSession(
  command: readonly string[],
  env: Readonly<Record<string, string>>,
): Promise<number> {
  const child = Bun.spawn({
    cmd: [...command],
    env: { ...process.env, ...env },
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit",
  });
  return holdingSignals(child);
}

async function holdingSignals(child: {
  kill: (signal: NodeJS.Signals) => void;
  exited: Promise<number>;
}): Promise<number> {
  const forwardTerm = (): void => {
    child.kill("SIGTERM");
  };
  const forwardHup = (): void => {
    child.kill("SIGHUP");
  };
  process.on("SIGINT", ignoreInterrupt);
  process.on("SIGTERM", forwardTerm);
  process.on("SIGHUP", forwardHup);
  try {
    return await child.exited;
  } finally {
    process.off("SIGINT", ignoreInterrupt);
    process.off("SIGTERM", forwardTerm);
    process.off("SIGHUP", forwardHup);
  }
}

const REDACTED = "[redacted]";

type ChildStream = ReadableStream<Uint8Array> | number | undefined;

const RELAY_GRACE_MS = 500;

function startRedactedRelay(
  child: { stdout: ChildStream; stderr: ChildStream; kill: (signal: NodeJS.Signals) => void },
  fragments: readonly Uint8Array[],
): { readonly done: Promise<void>; readonly abort: () => void } {
  const patterns = scrubPatterns(fragments, REDACTED);
  const aborts: (() => void)[] = [];
  const relay = async (stream: ChildStream, fd: number): Promise<void> => {
    if (typeof stream !== "object") {
      return;
    }
    const reader = stream.getReader();
    let aborted = false;
    aborts.push(() => {
      aborted = true;
      void reader.cancel().catch(() => undefined);
    });
    const replacer = makeStreamReplacer(patterns);
    for (;;) {
      const { done, value } = await reader.read();
      if (done || aborted) {
        break;
      }
      if (!writeBytes(fd, replacer.push(value))) {
        aborted = true;
        void reader.cancel().catch(() => undefined);
        child.kill("SIGPIPE");
        return;
      }
    }
    if (!aborted) {
      writeBytes(fd, replacer.flush());
    }
  };
  return {
    done: Promise.all([relay(child.stdout, 1), relay(child.stderr, 2)]).then(() => undefined),
    abort: () => {
      for (const abort of aborts) {
        abort();
      }
    },
  };
}

class PromptInterruptedError extends Error {}

const ENTER_CHARS = new Set(["\r", "\n"]);
const ERASE_CHARS = new Set(["\u007f", "\b"]);
const CTRL_C = "\u0003";
const CTRL_D = "\u0004";
const ESCAPE = "\u001b";
const ESCAPE_END = /[A-Za-z~]/;

function endOutcome(ch: string): "done" | "interrupted" | null {
  if (ENTER_CHARS.has(ch)) {
    return "done";
  }
  if (ch === CTRL_C || ch === CTRL_D) {
    return "interrupted";
  }
  return null;
}

export function readHiddenLine(stdin: NodeJS.ReadStream): Promise<string> {
  return new Promise((resolve, reject) => {
    const wasRaw = stdin.isRaw;
    stdin.setRawMode(true);
    stdin.resume();
    let line = "";
    let inEscape = false;
    const cleanup = () => {
      stdin.off("data", onData);
      stdin.off("end", onEnd);
      stdin.off("error", onError);
      stdin.setRawMode(wasRaw);
      stdin.pause();
    };
    const finish = (outcome: "done" | "interrupted" | "eof") => {
      cleanup();
      process.stderr.write("\n");
      if (outcome === "done") {
        resolve(line);
      } else if (outcome === "interrupted") {
        reject(new PromptInterruptedError("interrupted"));
      } else {
        reject(new Error(outcome));
      }
    };
    const applyChar = (ch: string) => {
      if (ERASE_CHARS.has(ch)) {
        line = line.slice(0, -1);
      } else if (ch >= " ") {
        line += ch;
      }
    };
    const handleChar = (ch: string): boolean => {
      if (inEscape) {
        inEscape = !ESCAPE_END.test(ch);
        return false;
      }
      if (ch === ESCAPE) {
        inEscape = true;
        return false;
      }
      const outcome = endOutcome(ch);
      if (outcome !== null) {
        finish(outcome);
        return true;
      }
      applyChar(ch);
      return false;
    };
    const onData = (chunk: Buffer) => {
      for (const ch of chunk.toString("utf8")) {
        if (handleChar(ch)) {
          return;
        }
      }
    };
    const onEnd = () => finish("eof");
    const onError = () => finish("eof");
    stdin.on("data", onData);
    stdin.once("end", onEnd);
    stdin.once("error", onError);
  });
}

export function makeStdinLineReader(stdin: NodeJS.ReadStream): () => Promise<string> {
  let buffered = "";
  let ended = false;
  const takeLine = (): string | null => {
    const index = buffered.indexOf("\n");
    if (index < 0) {
      return null;
    }
    const line = buffered.slice(0, index);
    buffered = buffered.slice(index + 1);
    return line.endsWith("\r") ? line.slice(0, -1) : line;
  };
  const drainTail = (): string => {
    if (buffered.length === 0) {
      throw new Error("eof");
    }
    const rest = buffered;
    buffered = "";
    return rest;
  };
  const refill = async (): Promise<void> => {
    const chunk = await nextChunk(stdin);
    if (chunk === null) {
      ended = true;
    } else {
      buffered += chunk;
    }
  };
  return async () => {
    for (;;) {
      const line = takeLine();
      if (line !== null) {
        return line;
      }
      if (ended) {
        return drainTail();
      }
      await refill();
    }
  };
}

function nextChunk(stdin: NodeJS.ReadStream): Promise<string | null> {
  if (stdin.readableEnded) {
    return Promise.resolve(null);
  }
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      stdin.off("data", onData);
      stdin.off("end", onEnd);
      stdin.off("error", onError);
      stdin.pause();
    };
    const onData = (chunk: Buffer) => {
      cleanup();
      resolve(chunk.toString("utf8"));
    };
    const onEnd = () => {
      cleanup();
      resolve(null);
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    stdin.on("data", onData);
    stdin.once("end", onEnd);
    stdin.once("error", onError);
    stdin.resume();
  });
}

function detectAgentProfile(): AgentProfile {
  const name = agentInfo.name;
  return name === undefined ? { isAgent: false } : { isAgent: true, name };
}

function browserOpenCommand(url: string): readonly string[] {
  if (process.platform === "darwin") {
    return ["open", url];
  }
  if (process.platform === "win32") {
    return ["rundll32", "url.dll,FileProtocolHandler", url];
  }
  return ["xdg-open", url];
}

function openBrowserLive(url: string): Effect.Effect<boolean> {
  return Effect.tryPromise({
    try: async () => {
      const child = Bun.spawn({
        cmd: [...browserOpenCommand(url)],
        stdin: "ignore",
        stdout: "ignore",
        stderr: "ignore",
      });
      return (await child.exited) === 0;
    },
    catch: () => cliError("browser open failed"),
  }).pipe(Effect.catch(() => Effect.succeed(false)));
}

export function writeLine(fd: number, line: string): void {
  writeBytes(fd, Buffer.from(`${line}\n`));
}

function writeBytes(fd: number, buffer: Uint8Array): boolean {
  let offset = 0;
  while (offset < buffer.length) {
    try {
      offset += writeSync(fd, buffer, offset);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "EPIPE") {
        return false;
      }
      if (code !== "EAGAIN") {
        throw error;
      }
      Atomics.wait(EAGAIN_PAUSE, 0, 0, 1);
    }
  }
  return true;
}

const EAGAIN_PAUSE = new Int32Array(new SharedArrayBuffer(4));

function makeLiveIo(): CliIoShape {
  const readPipedLine = makeStdinLineReader(process.stdin);
  return {
    log: (line) => Effect.sync(() => writeLine(1, line)),
    logError: (line) => Effect.sync(() => writeLine(2, line)),
    readStdin: Effect.tryPromise({
      try: async () => {
        const chunks: Uint8Array[] = [];
        for await (const chunk of process.stdin) {
          chunks.push(chunk as Uint8Array);
        }
        const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
        const merged = new Uint8Array(total);
        let offset = 0;
        for (const chunk of chunks) {
          merged.set(chunk, offset);
          offset += chunk.length;
        }
        return merged;
      },
      catch: () => cliError("Cannot read stdin"),
    }),
    promptLine: ({ prompt, secret }) =>
      Effect.tryPromise({
        try: async () => {
          process.stderr.write(prompt);
          const stdin = process.stdin;
          if (secret === true && stdin.isTTY) {
            return await readHiddenLine(stdin);
          }
          return await readPipedLine();
        },
        catch: (error) =>
          cliError(
            error instanceof PromptInterruptedError
              ? "The input was interrupted"
              : "Cannot read interactive input (this operation cannot run in a non-interactive environment)",
          ),
      }),
    envVar: (name) => process.env[name],
    agentProfile: detectAgentProfile,
    stderrIsTerminal: () => process.stderr.isTTY === true,
    colorEnabled: () =>
      shouldUseColor({
        stderrIsTerminal: process.stderr.isTTY === true,
        envVar: (name) => process.env[name],
      }),
    openBrowser: openBrowserLive,
  };
}

function accountHomeDir(): string {
  try {
    return userInfo().homedir;
  } catch {
    return homedir();
  }
}

export function liveLayer(): Layer.Layer<CliServices> {
  const configPath = defaultConfigPath((name) => process.env[name]);
  const agentSocket = process.env[AGENT_SOCKET_ENV];
  const keychain =
    agentSocket !== undefined && agentSocket.length > 0
      ? makeAgentKeychain(agentSocket)
      : makeBunKeychain();
  return Layer.mergeAll(
    cryptoServicesLayer,
    BunStdio.layer,
    Layer.succeed(AgentProfileRef, detectAgentProfile()),
    Layer.succeed(Keychain, keychain),
    Layer.succeed(ConfigStore, makeFileConfigStore(configPath)),
    Layer.succeed(FloorStore, makeFileFloorStore(floorDirOf(configPath))),
    Layer.succeed(PinStore, makeFilePinStore(pinsDirOf(configPath))),
    Layer.succeed(FingerprintBook, makeFileFingerprintBook(fingerprintBookPathOf(configPath))),
    Layer.succeed(OwnDeviceStore, makeFileOwnDeviceStore(ownDevicesPathOf(configPath))),
    Layer.succeed(
      ProxyAcceptStore,
      makeFileProxyAcceptStore(acceptedProxyConfigsPathOf(accountHomeDir())),
    ),
    Layer.succeed(CliIo, makeLiveIo()),
    Layer.succeed(ProcessRunner, makeBunProcessRunner()),
    Layer.succeed(SqlRunner, makeBunSqlRunner()),
    egressHttpClientLayer(),
  );
}
