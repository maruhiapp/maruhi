// `maruhi agent` — in-session in-memory key holding (KL2; ssh-agent style).
//
// In environments without an OS keychain (Codespaces / devcontainer / WSL /
// bare Linux), holds the maruhi token and the master secret key **only in this
// process's memory**. `maruhi agent -- <command>` starts a child (usually a
// shell), and that child's and its descendants' maruhi read and write to this
// process over a unix domain socket. When the child ends it discards the
// memory, removes the socket, and exits with the child's exit code (the
// `ssh-agent <command>` form of ssh-agent — the detached, lingering form is
// not taken: an orphaned resident process leaks with no upper bound on its
// lifetime. It matches the same nested-shell shape as the KL1 recipe
// `dbus-run-session -- bash`).
//
// Design rulings (L2 + L3 of integration-options.md supplement 12):
// - Implemented **as a Keychain service substitution**. When
//   `MARUHI_AGENT_SOCK` is set, the live layer adopts {@link makeAgentKeychain}
//   instead of the OS keychain (live.ts). So login / key generate /
//   key recover / pull / run / push land on this memory unchanged —
//   "fetch → decrypt → into L2's memory" is wired without touching
//   recovery.ts. The existing constraints (the rate limit on recovery-blob
//   fetches, code entry only on a human interactive terminal) keep working
//   as-is
// - **Writes nothing to disk**: what is placed is only the socket (an inode,
//   not data). The socket is `agent.sock` (0600) inside an mkdtemp directory
//   (0700) under `$XDG_RUNTIME_DIR` (os.tmpdir() when unset). The permission
//   boundary is same-user — equal to the OS keychain (Secret Service is
//   likewise the same user's D-Bus); this layer has no stronger boundary
//   (a same-user process can also read this process's memory)
// - **Adds no cryptographic operations**: what flows over the socket is the
//   same record string as the Keychain service's. The path is local,
//   same-user, and never touches disk, so no sealing that the spec
//   (CRYPTO_SPEC) does not have is invented
// - **Lifetime = the child's lifespan**. No TTL flag (it would collide with
//   `key recover`'s fetch limit [5 per hour] and force re-restoration).
//   Revocation is exiting the shell (the memory vanishes with it) or
//   `maruhi logout` (removes it from the agent, revokes it on the server)
// - **Adds no agent-environment (ADR-0016 decision 7) gate**: the agent is a
//   holding mechanism, not a value-display path. The display and ceremony
//   gates stay on each command's side. By the existing rule that `maruhi run`
//   children receive no `MARUHI_*` (run.ts), `MARUHI_AGENT_SOCK` likewise
//   does not reach the child (same conclusion as decision 5)
//
// Protocol (one request per connection; newline-delimited JSON):
//   request  {"v":1,"op":"get"|"remove","name":"…"} / {"v":1,"op":"set","name":"…","value":"…"}
//            {"v":1,"op":"list"} (the held entry names — for `maruhi agent status`; values are not carried)
//   response {"ok":true,"value":"…"|null} / {"ok":true,"names":[…]} / {"ok":false,"error":"…"}
// A version-mismatched or malformed request gets `ok:false` (never silently reinterpreted).
//
// The socket is node:net (unix-socket listen / connect verified working on
// both Bun and Node). vitest (Node) can exercise server and client over a
// real socket. Decision inputs (environment variables) arrive via CliIo.

import type { Stats } from "node:fs";
import { chmod, lstat, mkdtemp, rm } from "node:fs/promises";
import { createConnection, createServer, type Server, type Socket } from "node:net";
import { platform, tmpdir } from "node:os";
import { join } from "node:path";

import { Effect } from "effect";

import { displayText } from "./display.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { CliIo } from "./io.ts";
import { isMasterKeyEntryName, type KeychainShape } from "./keychain.ts";
import { logWarning } from "./notice.ts";
import { ProcessRunner } from "./run.ts";

/** Environment variable that carries the agent socket path to the session's commands. */
export const AGENT_SOCKET_ENV = "MARUHI_AGENT_SOCK";

/** Wire protocol version (a mismatch is refused, never reinterpreted). */
const AGENT_PROTOCOL_VERSION = 1;

/**
 * Cap on one request / one response. What is carried is a keychain record
 * (token ≈ 200 B, master key ≈ 500 B), so there is headroom by orders of
 * magnitude. Without a cap a broken peer could eat memory away.
 */
const MAX_MESSAGE_BYTES = 64 * 1024;

/** Cap on connect / response wait (an unresponsive agent must not hang the CLI). */
const IO_TIMEOUT_MS = 5_000;

const SOCKET_FILE_NAME = "agent.sock";

/** One request to the agent (mirrors {@link KeychainShape}, plus `list` for status). */
export type AgentRequest =
  | { readonly v: 1; readonly op: "get" | "remove"; readonly name: string }
  | { readonly v: 1; readonly op: "set"; readonly name: string; readonly value: string }
  | { readonly v: 1; readonly op: "list" };

/** One response from the agent. */
export type AgentResponse =
  | { readonly ok: true; readonly value: string | null }
  | { readonly ok: true; readonly names: readonly string[] }
  | { readonly ok: false; readonly error: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Parses one request line; null when malformed or of another protocol version. */
export function parseAgentRequest(line: string): AgentRequest | null {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return null;
  }
  if (!isRecord(value) || value["v"] !== AGENT_PROTOCOL_VERSION) {
    return null;
  }
  if (value["op"] === "list") {
    return { v: 1, op: "list" };
  }
  const name = value["name"];
  if (typeof name !== "string" || name.length === 0) {
    return null;
  }
  const op = value["op"];
  if (op === "get" || op === "remove") {
    return { v: 1, op, name };
  }
  if (op === "set" && typeof value["value"] === "string") {
    return { v: 1, op, name, value: value["value"] };
  }
  return null;
}

/** Parses one response line; null when malformed. */
export function parseAgentResponse(line: string): AgentResponse | null {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return null;
  }
  if (!isRecord(value)) {
    return null;
  }
  if (value["ok"] === true && (typeof value["value"] === "string" || value["value"] === null)) {
    return { ok: true, value: value["value"] };
  }
  const names = value["names"];
  if (
    value["ok"] === true &&
    Array.isArray(names) &&
    names.every((name) => typeof name === "string")
  ) {
    return { ok: true, names: names as string[] };
  }
  if (value["ok"] === false && typeof value["error"] === "string") {
    return { ok: false, error: value["error"] };
  }
  return null;
}

/** Encodes a request as one line (the wire form). */
export function encodeAgentRequest(request: AgentRequest): string {
  return `${JSON.stringify(request)}\n`;
}

/** Encodes a response as one line (the wire form). */
function encodeAgentResponse(response: AgentResponse): string {
  return `${JSON.stringify(response)}\n`;
}

/**
 * Applies one request to the in-memory store. It is factored out as a pure
 * function so the semantics can be tested apart from socket concerns
 * (split arrivals, disconnects).
 */
export function handleAgentRequest(
  store: Map<string, string>,
  request: AgentRequest,
): AgentResponse {
  switch (request.op) {
    case "get":
      return { ok: true, value: store.get(request.name) ?? null };
    case "set":
      store.set(request.name, request.value);
      return { ok: true, value: null };
    case "remove":
      store.delete(request.name);
      return { ok: true, value: null };
    case "list":
      // Names only (`token::<origin>` / `master::<origin>::<userId>`); values are not carried
      return { ok: true, names: [...store.keys()] };
  }
}

/**
 * The holding store (`--key-ttl` — integration-options.md supplement 19-3
 * (c)). Only master-key entries are forgotten on expiry; the token stays (no
 * re-login needed — the key is re-fetched with `maruhi key recover`). The
 * deadline extends on every set (a re-fetched key gets a fresh deadline). The
 * clock is substitutable (tests).
 */
export interface AgentStore {
  /** Applies one request (sweep expired → apply → record the deadline). */
  readonly apply: (request: AgentRequest) => AgentResponse;
  /** Discards everything held. */
  readonly clear: () => void;
}

export interface AgentStoreOptions {
  /** Lifetime of master-key entries (ms). Unset = the child's lifespan (as before). */
  readonly keyTtlMs?: number | undefined;
  readonly now?: (() => number) | undefined;
}

export function makeAgentStore(options: AgentStoreOptions = {}): AgentStore {
  const records = new Map<string, string>();
  const expiries = new Map<string, number>();
  const now = options.now ?? Date.now;
  const sweep = (): void => {
    const at = now();
    for (const [name, expiresAt] of expiries) {
      if (expiresAt <= at) {
        records.delete(name);
        expiries.delete(name);
      }
    }
  };
  return {
    apply(request) {
      sweep();
      const response = handleAgentRequest(records, request);
      if (
        request.op === "set" &&
        options.keyTtlMs !== undefined &&
        isMasterKeyEntryName(request.name)
      ) {
        expiries.set(request.name, now() + options.keyTtlMs);
      } else if (request.op === "remove") {
        expiries.delete(request.name);
      }
      return response;
    },
    clear() {
      records.clear();
      expiries.clear();
    },
  };
}

/** The `--key-ttl` notation (a number + s / m / h; one unit). */
const KEY_TTL_PATTERN = /^(\d+)([smh])$/;
const KEY_TTL_UNIT_MS = { s: 1_000, m: 60_000, h: 3_600_000 } as const;

/** Reads a `--key-ttl` value into ms (a malformed or zero value is a usage error). */
export function parseKeyTtl(text: string): Effect.Effect<number, CliError> {
  const match = KEY_TTL_PATTERN.exec(text.trim());
  const amount = match === null ? 0 : Number(match[1]);
  const unit = match?.[2] as keyof typeof KEY_TTL_UNIT_MS | undefined;
  if (match === null || unit === undefined || !Number.isSafeInteger(amount) || amount <= 0) {
    return Effect.fail(
      usageError("Write --key-ttl as a number followed by s, m, or h (examples: 30m, 2h)"),
    );
  }
  return Effect.succeed(amount * KEY_TTL_UNIT_MS[unit]);
}

/* -------------------------------------------------------------------------- */
/* Server (the agent process side)                                            */
/* -------------------------------------------------------------------------- */

/** A running agent socket. */
export interface AgentServer {
  readonly socketPath: string;
  /** Stops listening, drops every held record, and removes the socket. */
  readonly close: () => Promise<void>;
}

/**
 * Handles one connection as one request, answers it, and closes it.
 *
 * A peer that stays silent without completing its request line is cut off at
 * {@link IO_TIMEOUT_MS}: without that, `server.close()` (which waits for every
 * connection to end) never returns and the agent stays after the child exits
 * (cleanup never runs, and the child's exit code is never returned).
 */
function serveConnection(store: AgentStore, socket: Socket): void {
  let buffered = "";
  let answered = false;
  const answer = (response: AgentResponse): void => {
    answered = true;
    socket.end(encodeAgentResponse(response));
  };
  socket.setEncoding("utf8");
  socket.setTimeout(IO_TIMEOUT_MS, () => {
    socket.destroy();
  });
  socket.on("data", (chunk: string) => {
    if (answered) {
      return;
    }
    buffered += chunk;
    if (Buffer.byteLength(buffered) > MAX_MESSAGE_BYTES) {
      answer({ ok: false, error: "request too large" });
      return;
    }
    const newline = buffered.indexOf("\n");
    if (newline < 0) {
      return;
    }
    const request = parseAgentRequest(buffered.slice(0, newline));
    answer(
      request === null
        ? { ok: false, error: "malformed request (protocol version mismatch?)" }
        : store.apply(request),
    );
  });
  // The peer's (CLI's) disconnect / write failure. There is nobody to report
  // to: what failed is the peer's request, and the peer reports its own
  // side's failure itself (makeAgentKeychain). The agent's stderr shares the
  // terminal with the child shell, so writing here would only dirty the
  // user's screen. It is not ignored — "the peer reports it" — so the
  // listener's only job is to close the connection
  socket.on("error", () => {
    socket.destroy();
  });
}

/**
 * Starts listening on `<dir>/agent.sock` (mode 0600) with an empty in-memory
 * store. `dir` must already exist and be private to the user (0700).
 */
export function startAgentServer(
  dir: string,
  options: AgentStoreOptions = {},
): Promise<AgentServer> {
  const socketPath = join(dir, SOCKET_FILE_NAME);
  const store = makeAgentStore(options);
  // The ledger of open connections. close severs these first, then waits on
  // server.close (server.close only waits for them to close naturally — it
  // never severs them)
  const connections = new Set<Socket>();
  const server: Server = createServer({ allowHalfOpen: false }, (socket) => {
    connections.add(socket);
    socket.once("close", () => {
      connections.delete(socket);
    });
    serveConnection(store, socket);
  });
  return new Promise<AgentServer>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => {
      server.off("error", reject);
      // Tighten right after listen (independent of umask). The directory is
      // 0700, so there is no window in which another user could connect
      chmod(socketPath, 0o600).then(
        () =>
          resolve({
            socketPath,
            close: () =>
              new Promise<void>((done) => {
                // Discard the held records first (later connections see an
                // empty store). JS strings cannot be zeroed, so dropping the
                // references is the most we can do
                store.clear();
                server.close(() => {
                  done();
                });
                // Sever without waiting: termination is decided by the
                // child's exit, and there is no obligation to complete
                // in-flight requests (the peer reports its own side's
                // failure itself)
                for (const socket of connections) {
                  socket.destroy();
                }
              }),
          }),
        (error: unknown) => {
          server.close();
          reject(error);
        },
      );
    });
  });
}

/* -------------------------------------------------------------------------- */
/* Client (the session's CLI side = the Keychain service implementation)    */
/* -------------------------------------------------------------------------- */

/** The connect succeeded but the conversation cannot be held (no answer, malformed answer, version mismatch). */
class AgentProtocolError extends Error {}

/** No socket or nobody is listening (the session has ended). */
class AgentGoneError extends Error {}

/** What the env var points to does not look like a socket our agent made (do not use it). */
class AgentSocketRejectedError extends Error {}

const GONE_CODES = new Set(["ENOENT", "ECONNREFUSED", "ENOTSOCK", "EACCES"]);

/**
 * Before connecting, distrust what the env var points to. Anyone can plant
 * `MARUHI_AGENT_SOCK` (devcontainer.json's remoteEnv, `.envrc`, a Makefile),
 * so trusting it blindly would write the token and master key's plaintext to
 * that destination. A socket our agent made always passes "is a socket ·
 * owned by you · 0600"; another user's, a world-accessible one, or a plain
 * file stops here (a same-user attacker cannot be stopped — the same
 * boundary as the OS keychain).
 */
async function assertTrustedSocket(socketPath: string): Promise<void> {
  const reason = socketRejectionReason(await lstatAgentSocket(socketPath));
  if (reason !== null) {
    throw new AgentSocketRejectedError(reason);
  }
}

/** Maps lstat failures into the same vocabulary as the connect side (gone / cannot talk). */
async function lstatAgentSocket(socketPath: string): Promise<Stats> {
  try {
    return await lstat(socketPath);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code ?? "lstat";
    // Same classification as the connect side: missing / unreachable (EACCES
    // etc.) is "the session has ended", everything else is the cannot-talk
    // side — so the same state does not become a different story by path
    throw GONE_CODES.has(code) ? new AgentGoneError(code) : new AgentProtocolError(code);
  }
}

/** The reason it must not be used (in user-facing words); null when fine. */
function socketRejectionReason(stat: Stats): string | null {
  if (!stat.isSocket()) {
    return "it is not a socket";
  }
  // Our uid comes from `process.getuid` (just the syscall). `os.userInfo()`
  // reads passwd, so in a container with only a numeric uid — precisely this
  // feature's target environment — it throws and would reject even a genuine
  // socket. On platforms without a uid (Windows has no getuid at all) the
  // ownership check is skipped — the agent's startup refuses win32, but when
  // only the env var is carried in, live.ts picks this implementation on any
  // OS, so this is reachable. Reading `process.*` here is not decision input
  // (terminal · agent — ADR-0016 decision 7) but owner identity, so it is
  // read here rather than via a service
  const uid = process.getuid?.() ?? -1;
  if (uid >= 0 && stat.uid !== uid) {
    return "it is not owned by you";
  }
  return (stat.mode & 0o077) === 0 ? null : "other users can access it";
}

async function sendAgentRequest(socketPath: string, request: AgentRequest): Promise<AgentResponse> {
  await assertTrustedSocket(socketPath);
  return new Promise((resolve, reject) => {
    let buffered = "";
    let settled = false;
    const socket = createConnection(socketPath);
    const settle = (outcome: () => void): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      outcome();
    };
    const timer = setTimeout(
      () => settle(() => reject(new AgentProtocolError("timeout"))),
      IO_TIMEOUT_MS,
    );
    socket.setEncoding("utf8");
    socket.once("connect", () => {
      socket.write(encodeAgentRequest(request));
    });
    socket.on("data", (chunk: string) => {
      buffered += chunk;
      if (Buffer.byteLength(buffered) > MAX_MESSAGE_BYTES) {
        settle(() => reject(new AgentProtocolError("response too large")));
        return;
      }
      const newline = buffered.indexOf("\n");
      if (newline < 0) {
        return;
      }
      const response = parseAgentResponse(buffered.slice(0, newline));
      settle(() =>
        response === null
          ? reject(new AgentProtocolError("malformed response"))
          : resolve(response),
      );
    });
    socket.once("error", (error: NodeJS.ErrnoException) => {
      settle(() =>
        reject(
          error.code !== undefined && GONE_CODES.has(error.code)
            ? new AgentGoneError(error.code)
            : new AgentProtocolError(error.code ?? "socket error"),
        ),
      );
    });
    // Closed before the response line (the agent died, etc.)
    socket.once("close", () => settle(() => reject(new AgentProtocolError("closed"))));
  });
}

const agentGoneMessage =
  `Cannot connect to the maruhi agent (${AGENT_SOCKET_ENV} points to a socket nobody is listening on). The agent session has ended — start a new one with \`maruhi agent -- <shell>\`, or unset ${AGENT_SOCKET_ENV} to use the OS keychain` as const;

const agentProtocolMessage =
  "The maruhi agent did not answer as expected (a different maruhi version may be running it). Exit the agent session and start a new one with `maruhi agent -- <shell>` using this version" as const;

function agentRequestError(error: unknown): CliError {
  if (error instanceof AgentGoneError) {
    return cliError(agentGoneMessage);
  }
  if (error instanceof AgentSocketRejectedError) {
    return cliError(
      `Refusing to use the agent socket named by ${AGENT_SOCKET_ENV}: ${error.message}. Unset ${AGENT_SOCKET_ENV}, or start a new session with \`maruhi agent -- <shell>\``,
    );
  }
  return cliError(agentProtocolMessage);
}

/**
 * Whether the agent the env var points to is alive (for the nesting check).
 * No socket / nobody listening is "the remains of an ended session" = fine
 * to start a new one. Other failures (an untrusted destination, a version
 * mismatch) are returned to the user with their reason.
 */
function probeAgent(socketPath: string): Effect.Effect<"live" | "gone", CliError> {
  return Effect.tryPromise({
    try: () => sendAgentRequest(socketPath, { v: 1, op: "list" }),
    catch: (error) => error,
  }).pipe(
    Effect.map((): "live" => "live"),
    Effect.catch((error) =>
      error instanceof AgentGoneError
        ? Effect.succeed("gone" as const)
        : Effect.fail(agentRequestError(error)),
    ),
  );
}

/** Sends one request, mapping even `ok:false` (the agent refused = version mismatch) into a typed failure. */
function askAgent(
  socketPath: string,
  request: AgentRequest,
): Effect.Effect<Exclude<AgentResponse, { readonly ok: false }>, CliError> {
  return Effect.tryPromise({
    try: () => sendAgentRequest(socketPath, request),
    catch: agentRequestError,
  }).pipe(
    Effect.flatMap((response) =>
      // A request the agent would refuse never leaves this implementation (only a version-mismatched agent)
      response.ok ? Effect.succeed(response) : Effect.fail(cliError(agentProtocolMessage)),
    ),
  );
}

/**
 * Keychain implementation backed by a running `maruhi agent`. Selected by the
 * production layer when {@link AGENT_SOCKET_ENV} is set (live.ts).
 */
export function makeAgentKeychain(socketPath: string): KeychainShape {
  const ask = (request: AgentRequest): Effect.Effect<string | null, CliError> =>
    askAgent(socketPath, request).pipe(
      Effect.flatMap((response) =>
        "value" in response
          ? Effect.succeed(response.value)
          : // A non-value response (names) cannot arrive for this request = a version-mismatched agent
            Effect.fail(cliError(agentProtocolMessage)),
      ),
    );
  return {
    kind: "agent",
    get: (name) => ask({ v: 1, op: "get", name }),
    set: (name, value) => Effect.asVoid(ask({ v: 1, op: "set", name, value })),
    remove: (name) => Effect.asVoid(ask({ v: 1, op: "remove", name })),
  };
}

/* -------------------------------------------------------------------------- */
/* Command body                                                             */
/* -------------------------------------------------------------------------- */

/** `maruhi agent` has nothing to run (a usage error). */
export const AGENT_COMMAND_REQUIRED =
  "Write the command to run inside the agent session after `--` (example: `maruhi agent -- bash`)";

/**
 * The parent of where the socket goes. `$XDG_RUNTIME_DIR` is ideal — a
 * per-user tmpfs (0700, removed at logout). Without it, os.tmpdir() — the
 * directory we make is itself 0700, so even a shared /tmp hides it from
 * other users.
 */
function socketBaseDir(envVar: (name: string) => string | undefined): string {
  const runtime = envVar("XDG_RUNTIME_DIR");
  return runtime !== undefined && runtime.length > 0 ? runtime : tmpdir();
}

/**
 * `maruhi agent -- <command>`: start the socket, run the command with
 * {@link AGENT_SOCKET_ENV} set, and tear everything down when it exits.
 * Returns the command's exit code.
 */
export function agentOp(input: {
  readonly command: readonly string[];
  /** `--key-ttl` (ms). Unset = the master key is held for the child's lifespan too. */
  readonly keyTtl?: { readonly ms: number; readonly text: string } | undefined;
}): Effect.Effect<number, CliError, CliIo | ProcessRunner> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const runner = yield* ProcessRunner;
    // Same as run: "there is one argument" and "there is something to run" are different things
    if (input.command.length === 0 || (input.command[0] ?? "").trim() === "") {
      return yield* Effect.fail(usageError(AGENT_COMMAND_REQUIRED));
    }
    if (platform() === "win32") {
      return yield* Effect.fail(
        cliError(
          "`maruhi agent` is not available on Windows (it needs a Unix domain socket). The Windows Credential Manager needs no setup — use it instead",
        ),
      );
    }
    // Nesting is refused: the outer agent already holds the keys, and an
    // inner one would only add an empty holding store and make "which one it
    // went into" unknowable. But **only a live agent** counts as nesting: if
    // the parent died first and only the shell remains (terminal
    // multiplexing, reparenting), the env var is a leftover, and "start a new
    // one" + "refuse nesting" would dead-end. Leftovers may be replaced
    const existing = io.envVar(AGENT_SOCKET_ENV);
    if (existing !== undefined && existing.length > 0) {
      const state = yield* probeAgent(existing);
      if (state === "live") {
        return yield* Effect.fail(
          cliError(
            `Already inside an agent session (${AGENT_SOCKET_ENV} points to a running agent). Nested agents are refused — use this session, or exit it first`,
          ),
        );
      }
      yield* logWarning(
        `${AGENT_SOCKET_ENV} pointed to an agent session that has already ended; starting a new one (the new value replaces it for this command's children)`,
      );
    }
    const dir = yield* Effect.tryPromise({
      try: () => mkdtemp(join(socketBaseDir(io.envVar), "maruhi-agent-")),
      catch: () =>
        cliError(
          "Cannot create a private directory for the agent socket (under XDG_RUNTIME_DIR, or the temp directory when it is unset)",
        ),
    });
    // Even when removal fails the session's result (the child's exit code)
    // is not thrown away: the directory is empty or holds only the socket's
    // inode (no values in it). Not swallowed silently — warned
    const removeDir = Effect.tryPromise({
      try: () => rm(dir, { recursive: true, force: true }),
      catch: () =>
        cliError(`could not remove the agent socket directory (${dir}) — remove it by hand`),
    }).pipe(Effect.catch((error) => logWarning(error.message)));
    return yield* Effect.acquireUseRelease(
      Effect.tryPromise({
        try: () => startAgentServer(dir, { keyTtlMs: input.keyTtl?.ms }),
        catch: (error) =>
          cliError(
            `Cannot listen on the agent socket${errnoSuffix(error)}. Nothing was stored; check that the directory is on a filesystem that supports Unix domain sockets`,
          ),
      }).pipe(Effect.onError(() => removeDir)),
      (server) =>
        Effect.gen(function* () {
          // The notice goes to stderr (does not dirty the child's stdout —
          // output does not interleave even under uses like
          // `maruhi agent -- make`)
          yield* io.logError(
            "Agent session started: tokens and keys you sign in with or recover here stay in memory only, and are discarded when the command exits",
          );
          if (input.keyTtl !== undefined) {
            yield* io.logError(
              `This device's key is forgotten ${input.keyTtl.text} after it is stored (--key-ttl); the token stays. When a command reports it is missing, register this shell again with \`maruhi device add\` (approve it from a device you have) and revoke the forgotten key with \`maruhi device revoke\``,
            );
          }
          return yield* runner.runSession({
            command: input.command,
            env: { [AGENT_SOCKET_ENV]: server.socketPath },
          });
        }),
      (server) => Effect.promise(() => server.close()).pipe(Effect.andThen(removeDir)),
    );
  });
}

/**
 * `maruhi agent status`: shows by name what this agent session is holding
 * (values are neither carried nor printed). Outside a session it fails, and
 * a stale `MARUHI_AGENT_SOCK` surfaces the client's session-ended message
 * as-is.
 */
export function agentStatusOp(): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const socketPath = io.envVar(AGENT_SOCKET_ENV);
    if (socketPath === undefined || socketPath.length === 0) {
      return yield* Effect.fail(
        cliError(
          `Not inside an agent session (${AGENT_SOCKET_ENV} is not set). Start one with \`maruhi agent -- <shell>\``,
        ),
      );
    }
    const response = yield* askAgent(socketPath, { v: 1, op: "list" });
    if (!("names" in response)) {
      return yield* Effect.fail(cliError(agentProtocolMessage));
    }
    // The path is one our own process made, but it arrives via an env var, so neutralize it before display
    yield* io.log(`socket:      ${displayText(socketPath)}`);
    if (response.names.length === 0) {
      yield* io.log("holding:     nothing yet (run `maruhi login` in this session)");
      return;
    }
    for (const name of response.names.toSorted()) {
      yield* io.log(describeEntryName(name));
    }
  });
}

/**
 * Renders an entry name (keychain.ts's tokenEntryName / masterKeyEntryName)
 * readable. origin and userId are server-supplied free strings, so they are
 * neutralized on output.
 */
function describeEntryName(name: string): string {
  const token = /^token::(.+)$/.exec(name);
  if (token !== null) {
    return `token:       ${displayText(token[1] ?? "")}`;
  }
  // The separator is the **last** `::` (an origin like `http://[::1]:8787`
  // can contain `::`; userId is a server-issued identifier without `::`)
  const master = /^master::(.+)::(.+)$/.exec(name);
  if (master !== null) {
    return `device key:  ${displayText(master[1] ?? "")} (user ${displayText(master[2] ?? "")})`;
  }
  return `entry:       ${displayText(name)}`;
}

function errnoSuffix(error: unknown): string {
  const code = (error as NodeJS.ErrnoException | null)?.code;
  return code === undefined ? "" : ` (${code})`;
}
