// The production service implementations (Bun runtime. ADR-0004: the CLI
// may use Bun-specific APIs).
//
// - Keychain = Bun.secrets (macOS Keychain / Linux libsecret / Windows
//   Credential Manager). On a keychain-less environment it guides with a
//   typed error; never falls back to a plaintext file (the diskless
//   invariant)
// - ProcessRunner = Bun.spawn (in-memory injection into environment
//   variables only; stdio is inherited)
// - Agent detection = std-env's agentInfo (ADR-0016 decision 7's
//   secondary layer. The first boundary is Stdio's TTY judgment)
// - Stdio = @effect/platform-bun (argv and terminal presence. Reading
//   `process.*` directly happens only inside this implementation = the
//   argument layer arrives via services)

import { writeSync } from "node:fs";
import { stat } from "node:fs/promises";
// Read submodules directly (a package's index pulls in BunRedis etc. and
// crashes on environments that cannot resolve the `bun` module — vitest
// running under Node)
import { homedir, userInfo } from "node:os";

import * as BunStdio from "@effect/platform-bun/BunStdio";
import { Duration, Effect, Layer, Redacted } from "effect";
import { FetchHttpClient } from "effect/http";
import { agentInfo } from "std-env";

import { type AgentProfile, AgentProfileRef } from "./agent-gate.ts";
import { AGENT_SOCKET_ENV, makeAgentKeychain } from "./agent.ts";
import { makeStreamReplacer, scrubPatterns } from "./byte-replace.ts";
import type { CliServices } from "./cli.ts";
import { ConfigStore, defaultConfigPath, makeFileConfigStore } from "./config.ts";
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
} from "./proxy-accept.ts";
import { SqlRunner, type SqlRunnerShape } from "./rotate-connector.ts";
import {
  buildChildEnvironment,
  type CaptureInput,
  type CaptureOutcome,
  type ExecInput,
  type ExecOutcome,
  ProcessRunner,
  type ProcessRunnerShape,
} from "./run.ts";

const keychainUnavailable = () =>
  cliError(
    "Cannot access the OS keychain (tokens and keys cannot be stored in this environment). maruhi does not fall back to plaintext files — run `maruhi agent -- <shell>` to keep them in memory for that shell's lifetime, or pass a token via the MARUHI_TOKEN environment variable",
  );

// On a keyring-daemon-less headless Linux, a Bun.secrets write was
// observed to block without answering. Leave room to wait for the
// keychain's unlock prompt (a user action), while a hang degrades to a
// guidance error
const KEYCHAIN_TIMEOUT = Duration.seconds(30);

// Wording dedicated to a mutating timeout: Effect's timeout cannot cancel
// an in-flight Bun.secrets.set / delete Promise, so the change may
// complete **after** the CLI reports the failure (set → the next run's
// "already exists" guard; delete → a key expected to still be there gone
// missing). Spell out that "it may have completed" and the confirm /
// recover procedure
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

/**
 * Driving a vendor CLI (`maruhi sync`'s exec driver — sync-exec.ts). The
 * value is **written to the child's stdin once and closed** (Bun closes
 * stdin only after writing an ArrayBufferView to the end — matching
 * Vercel CLI's "wait just 500 ms for the first chunk" read). stdout /
 * stderr are captured, not inherited: the vendor's output may contain
 * values, so it never flows to the terminal as-is (display is the
 * caller's after scrubbing). It is **not truncated here**: truncating
 * before redacting makes the latter half of a value sitting across the
 * cut match no fragment and leak. The display cap is applied by
 * sync-exec.ts after redaction.
 */
async function execVendor(input: ExecInput): Promise<ExecOutcome> {
  // A missing / non-directory cwd surfaces as spawn's ENOENT / ENOTDIR,
  // indistinguishable from a missing executable. Look first and name the
  // cause
  const cwdStat = await stat(input.cwd).catch(() => null);
  if (cwdStat === null || !cwdStat.isDirectory()) {
    throw new CwdUnavailableError(input.cwd);
  }
  // Reason for unwrapping: writing to the child process's stdin (the only
  // path by which a value leaves maruhi. argv carries names only —
  // sync-exec.ts's types guarantee it)
  const stdin = Redacted.value(input.stdin);
  const child = Bun.spawn({
    cmd: [...input.command],
    cwd: input.cwd,
    // The same discipline as run: inherit the parent's general environment, never pass MARUHI_*
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

/**
 * A script of the `exec` rotation connector (rotate-connector.ts — PF8):
 * secrets ride in the child's environment (the `maruhi run` shape — the
 * only path they take), stdin is closed, stdout comes back as bytes (the
 * new credential — never decoded or logged here), stderr as text for the
 * connector to scrub. A launch failure rejects with a message naming only
 * the executable and the directory.
 */
async function captureScript(input: CaptureInput): Promise<CaptureOutcome> {
  const cwdStat = await stat(input.cwd).catch(() => null);
  if (cwdStat === null || !cwdStat.isDirectory()) {
    throw new Error(
      `the scripts' working directory does not exist or is not a directory (${input.cwd}) — fix the rule's cwd in the rotation config`,
    );
  }
  let child: ReturnType<typeof Bun.spawn>;
  try {
    child = Bun.spawn({
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
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout as ReadableStream).bytes(),
    new Response(child.stderr as ReadableStream).text(),
    child.exited,
  ]);
  return { exitCode, stdout, stderr };
}

/** The vendor CLI's execution directory (the config's cwd) is missing or not a directory. */
class CwdUnavailableError extends Error {
  constructor(readonly cwd: string) {
    super("cwd unavailable");
  }
}

/** The launch-failure wording (carries no values — only the executable name, cwd, and the OS error code). */
function execStartFailure(input: ExecInput, error: unknown): string {
  if (error instanceof CwdUnavailableError) {
    return `Cannot run ${input.command[0] ?? ""}: the target's working directory does not exist or is not a directory (${error.cwd}). Fix the target's cwd in the sync config`;
  }
  const code = (error as NodeJS.ErrnoException).code;
  return `Cannot start ${input.command[0] ?? ""}${code === undefined ? "" : ` (${code})`}: is it installed and on PATH, or named by a \`command\` in the sync config? maruhi never downloads a vendor CLI: install it and sign in with it, then retry`;
}

/**
 * The database client of the `postgres` / `mysql` rotation connectors:
 * Bun's built-in SQL client (no dependency; the URL's scheme selects the
 * driver). One short-lived connection per call, closed whatever happened.
 * Statements are built by the connector from validated identifiers and
 * generated passwords (rotate-connector.ts); nothing here interpolates.
 */
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
          // Values are injected into the child's environment variables in
          // memory only (the diskless invariant). With `redact`, the
          // child's stdout / stderr come back on pipes and are scrubbed
          // before being relayed (run-output redaction — relayRedacted);
          // without it, a human terminal is inherited as before
          const piped = redact !== undefined;
          const child = Bun.spawn({
            cmd: [...command],
            // A keychain-less / CI MARUHI_TOKEN is for the parent's
            // session resolution only. Never pass a child a longer-lived
            // credential broader than the injected values
            env: buildChildEnvironment(process.env, extraEnv),
            stdin: "inherit",
            stdout: piped ? "pipe" : "inherit",
            stderr: piped ? "pipe" : "inherit",
          });
          const relays = piped ? startRedactedRelay(child, redact) : null;
          // `proxy run`: the parent must outlive the child (it is the
          // child's proxy) — the same signal shape as `maruhi agent`
          const exitCode = holdSignals === true ? await holdingSignals(child) : await child.exited;
          if (relays !== null) {
            // The pipes drain right after the child exits. A grandchild that
            // inherited them (a daemon the child left behind) must not pin
            // this process: after a short grace the readers are cancelled —
            // with inherited stdio the parent would have exited at once and
            // the daemon kept writing to the terminal; here its next write
            // fails instead (review finding pf4-design.md §19 C-1)
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
        // A launch failure (not installed, not on PATH, cwd missing).
        // Never go fetch it (only an installed CLI — integration-options.md
        // §3 supplement 16)
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

/** SIGINT's handling while the child is alive (do nothing = leave it to the child's interactive shell). */
const ignoreInterrupt = (): void => {};

/**
 * `maruhi agent`'s child (agent.ts). Unlike run, the parent's environment
 * is passed **unfiltered** (carrying `MARUHI_AGENT_SOCK` is this path's
 * whole purpose, and the user's settings [MARUHI_CONFIG_DIR etc.] must
 * also be visible to the shell they are about to work in. No value
 * injection).
 *
 * Signals: the terminal's Ctrl+C reaches the whole foreground process
 * group (agent and child). While a child that is an interactive shell
 * ignores SIGINT and stays alive, if agent died the shell would lose
 * where the keys are held. Like ssh-agent's `ssh-agent <command>`, the
 * agent side ignores SIGINT while the child is alive and forwards
 * SIGTERM / SIGHUP to the child (once the child finishes the agent does
 * too — cleanup is agent.ts's release). `process.*` is read only inside
 * this implementation (ADR-0016 decision 5).
 */
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

/**
 * Waits for `child` while the parent ignores SIGINT and forwards SIGTERM /
 * SIGHUP to it (`maruhi agent` and `maruhi proxy run` — parents whose job
 * is to outlive the child).
 */
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

/** What a scrubbed value becomes in the relayed output. */
const REDACTED = "[redacted]";

/**
 * Run-output redaction (ROADMAP Phase 3 ⑤; the trigger is run.ts's
 * `redactionFragments`). The child's stdout and stderr arrive on pipes
 * and are relayed to this process's fds **in the byte domain**: the
 * fragments (each value whole, each of its lines, the JSON-escaped forms
 * — byte-replace.ts's scrubPatterns, the `maruhi sync` rule) are
 * searched in the raw chunks and replaced with `[redacted]`; bytes that
 * match nothing pass through untouched, so binary output (`pg_dump -Fc`,
 * `tar czf -`) is not corrupted. A value straddling two chunks is caught
 * by the replacer's carry-over (longest fragment − 1 bytes, cut at a
 * newline when every fragment is single-line — live logs stay
 * line-by-line). Each stream is relayed independently with synchronous
 * writes (ordering within a stream is preserved; between the two
 * streams it is the same race any piped child has).
 *
 * Limits (stated in the docs): a value transformed by the child (base64,
 * a hash, a different encoding) is not caught — this is a second line of
 * defence; keeping values away from an agent is `proxy run`'s job.
 */
type ChildStream = ReadableStream<Uint8Array> | number | undefined;

/** How long after the child's exit its pipes may still deliver output (a grandchild's) before the relay stops. */
const RELAY_GRACE_MS = 500;

/**
 * Starts relaying the child's stdout / stderr through the redaction.
 * `done` settles when both pipes ended (or were aborted); `abort` cancels
 * the readers. When this process's own output is gone (EPIPE — `maruhi run
 * -- yes | head -1`), the child is sent SIGPIPE and that relay stops: the
 * pipe semantics a child has with inherited stdio.
 */
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
    // The replacer holds back only bytes that could still begin a match
    // (byte-replace.ts): output that resembles no value streams at once
    const replacer = makeStreamReplacer(patterns);
    for (;;) {
      const { done, value } = await reader.read();
      if (done || aborted) {
        break;
      }
      if (!writeBytes(fd, replacer.push(value))) {
        // Our reader is gone: close the child's side as a pipe would
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

/** An interruption of interactive input by Ctrl+C / Ctrl+D (distinguished from EOF and unreadability). */
class PromptInterruptedError extends Error {}

const ENTER_CHARS = new Set(["\r", "\n"]);
const ERASE_CHARS = new Set(["\u007f", "\b"]);
const CTRL_C = "\u0003";
const CTRL_D = "\u0004";
const ESCAPE = "\u001b";
// The terminator of a CSI-style escape sequence (a letter or ~). Never mix arrow-key fragments into the input
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

/**
 * Non-echoed input on a TTY (one secret line, e.g. a recovery code).
 * Reads one character at a time in raw mode and shows nothing on the
 * terminal. Backspace deletes the tail; Ctrl+C / Ctrl+D interrupt (under
 * raw mode even EOF arrives as a key press); escape sequences like the
 * arrow keys and other control characters are ignored (never silently
 * corrupt invisible input). Always settles even on stream end / error
 * (never hangs). Exported for tests.
 */
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
    // Erase removes one trailing character, other control characters (tabs etc.) are ignored, only printable characters are appended
    const applyChar = (ch: string) => {
      if (ERASE_CHARS.has(ch)) {
        line = line.slice(0, -1);
      } else if (ch >= " ") {
        line += ch;
      }
    };
    // Processes one character and returns whether the input terminated (finish already ran)
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

/**
 * The shared line reader for non-TTY (piped) input. The
 * create-and-close-a-readline-each-time shape discards the next
 * already-buffered line when it closes, so in a multi-prompt flow
 * (re-entering a recovery code etc.) the second line onward disappears.
 * Cut lines out of a single buffer that keeps the unconsumed part.
 * Exported for tests.
 */
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
  // A tail that ended without a newline (e.g. `printf`'s last line) is also returned as one line
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

/** Read stdin's next chunk (end is null; an error rejects). */
function nextChunk(stdin: NodeJS.ReadStream): Promise<string | null> {
  // 'end' fires only once: if the stream already ended after a previous
  // read removed its listeners, waiting for the event never resolves.
  // An already-ended stream is detected here
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

/**
 * Detecting an AI coding agent (the secondary layer).
 *
 * The detection rules are std-env's `agentInfo` (a table of environment
 * variables such as `CLAUDECODE` / `CURSOR_AGENT` / `GEMINI_CLI` /
 * `AI_AGENT`). `agentInfo` is a synchronous value evaluated once at
 * module initialization.
 */
function detectAgentProfile(): AgentProfile {
  const name = agentInfo.name;
  return name === undefined ? { isAgent: false } : { isAgent: true, name };
}

/** The command that opens the OS default browser (the URL is passed as an argument — no shell expansion). */
function browserOpenCommand(url: string): readonly string[] {
  if (process.platform === "darwin") {
    return ["open", url];
  }
  if (process.platform === "win32") {
    // Using cmd's builtin `start` would let cmd's own parser interpret
    // `&` `^` etc. inside the URL (spawn's quoting convention targets
    // Win32 argv and does not escape cmd metacharacters — a legitimate
    // verificationUrl gets cut at `&`, and from a hostile server it
    // becomes command injection). rundll32's FileProtocolHandler
    // dispatches to the default browser without passing through cmd
    return ["rundll32", "url.dll,FileProtocolHandler", url];
  }
  return ["xdg-open", url];
}

/**
 * Open a URL in the default browser (best effort). stdio is left
 * unconnected (never dirty the terminal's display). A launch failure
 * (missing command etc.) is false — the caller degrades to guidance for
 * opening the URL manually.
 */
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

/**
 * Synchronously write one line to an fd. `console.error` is not used:
 * when stderr is a terminal Bun colors **all** console.error output red
 * (measured `\e[0m\e[31m…\e[0m` — help bodies and Notes were all red).
 * `process.stderr.write` is not used either: it is asynchronous against
 * a pipe and bin.ts's `process.exit` clips the tail (measured: cut off
 * at line 7,401 of 50k). `writeSync` returns after completing on
 * terminal, pipe, or file alike.
 *
 * Writing to a pipe whose reader closed first (the lines past `maruhi
 * pull | head -1`) throws `EPIPE`. console.log was observed to drop this
 * silently, so do the same — the reader has already said it needs no
 * more, and there is nobody and no path to report it to (making it a
 * defect would end "a run whose reader was satisfied" in an internal
 * error). `EAGAIN` (a non-blocking fd) retries until written; a partial
 * write continues from where it left off. Any other write failure is
 * thrown as-is (never swallowed). Exported for tests.
 */
export function writeLine(fd: number, line: string): void {
  writeBytes(fd, Buffer.from(`${line}\n`));
}

/** The byte form of {@link writeLine} (the redacted relay of a child's output writes chunks, not lines). */
/**
 * Returns false when the reader has left (EPIPE) — the relayed child is then
 * told so. A non-blocking fd's EAGAIN waits a millisecond before retrying
 * (a tight loop would spin a core while the reader catches up).
 */
function writeBytes(fd: number, buffer: Uint8Array): boolean {
  let offset = 0;
  // A partial write (return value < remaining) continues from where it
  // left off, EAGAIN (a non-blocking fd) retries until written, and EPIPE
  // ends it because the reader has left
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

/** A shared cell `Atomics.wait` can sleep on (a synchronous millisecond pause). */
const EAGAIN_PAUSE = new Int32Array(new SharedArrayBuffer(4));

function makeLiveIo(): CliIoShape {
  // One line reader per process for non-TTY input (keeps unconsumed lines across prompts)
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
          // The prompt goes to stderr (the interaction survives stdout being piped)
          process.stderr.write(prompt);
          const stdin = process.stdin;
          if (secret === true && stdin.isTTY) {
            return await readHiddenLine(stdin);
          }
          // On non-TTY (piped input) there is no echo control to be had, so read as-is
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
    // Whether color is allowed (only stderr's prefixes — notice.ts). The
    // judgment material's `process.*` is read only inside this
    // implementation (ADR-0016 decision 5)
    colorEnabled: () =>
      shouldUseColor({
        stderrIsTerminal: process.stderr.isTTY === true,
        envVar: (name) => process.env[name],
      }),
    openBrowser: openBrowserLive,
  };
}

/** Production service layer for the maruhi CLI (Bun runtime). */
/**
 * The account's home directory from the system user database (getpwuid),
 * which no environment variable moves — the anchor of the acceptance
 * record (proxy-accept.ts, §21 R-23). `userInfo()` throws for a uid
 * without a passwd entry (some containers); `homedir()` ($HOME) is the
 * fallback there, stated in the record as the residual.
 */
function accountHomeDir(): string {
  try {
    return userInfo().homedir;
  } catch {
    return homedir();
  }
}

export function liveLayer(): Layer.Layer<CliServices> {
  const configPath = defaultConfigPath((name) => process.env[name]);
  // Inside a `maruhi agent` session (MARUHI_AGENT_SOCK present), use the
  // agent's memory instead of the OS keychain (KL2 — agent.ts). An
  // explicit environment variable = the user's explicit choice, so the
  // agent wins even when a keychain exists. MARUHI_TOKEN's precedence
  // (session.ts: env var → Keychain) is unchanged
  const agentSocket = process.env[AGENT_SOCKET_ENV];
  const keychain =
    agentSocket !== undefined && agentSocket.length > 0
      ? makeAgentKeychain(agentSocket)
      : makeBunKeychain();
  return Layer.mergeAll(
    // argv and terminal presence (the argument layer and the judgment material for value displayability)
    BunStdio.layer,
    // The secondary layer for value displayability (the first boundary is the Stdio TTY judgment above)
    Layer.succeed(AgentProfileRef, detectAgentProfile()),
    Layer.succeed(Keychain, keychain),
    Layer.succeed(ConfigStore, makeFileConfigStore(configPath)),
    // The local floor (§6.3) lives in the same non-sensitive family as the config (<config dir>/floor)
    Layer.succeed(FloorStore, makeFileFloorStore(floorDirOf(configPath))),
    // The invite anchors and issuance pins (§6.3 (a)) are the same family (<config dir>/invites)
    Layer.succeed(PinStore, makeFilePinStore(pinsDirOf(configPath))),
    // The verified-fingerprint ledger (KF) is the same family (<config dir>/known-fingerprints.json)
    Layer.succeed(FingerprintBook, makeFileFingerprintBook(fingerprintBookPathOf(configPath))),
    Layer.succeed(OwnDeviceStore, makeFileOwnDeviceStore(ownDevicesPathOf(configPath))),
    // The proxy configs a person accepted (pf4-design.md §21 R-8) live under the account's home from
    // the system user database — not the env-redirectable config dir (R-23)
    Layer.succeed(
      ProxyAcceptStore,
      makeFileProxyAcceptStore(acceptedProxyConfigsPathOf(accountHomeDir())),
    ),
    Layer.succeed(CliIo, makeLiveIo()),
    Layer.succeed(ProcessRunner, makeBunProcessRunner()),
    Layer.succeed(SqlRunner, makeBunSqlRunner()),
    FetchHttpClient.layer,
  );
}
