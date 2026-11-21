import type { Stats } from "node:fs";
import { chmod, lstat, mkdtemp, rm } from "node:fs/promises";
import { createConnection, createServer, type Server, type Socket } from "node:net";
import { platform, tmpdir } from "node:os";
import { join } from "node:path";

import { Data, Effect, Option, Predicate, Schema } from "effect";

import { displayText } from "./display.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { CliIo } from "./io.ts";
import { isMasterKeyEntryName, type KeychainShape } from "./keychain.ts";
import { logWarning } from "./notice.ts";
import { ProcessRunner } from "./run.ts";

export const AGENT_SOCKET_ENV = "MARUHI_AGENT_SOCK";

const AGENT_PROTOCOL_VERSION = 1;

const MAX_MESSAGE_BYTES = 64 * 1024;

const IO_TIMEOUT_MS = 5_000;

const SOCKET_FILE_NAME = "agent.sock";

const AgentRequestSchema = Schema.Union([
  Schema.Struct({
    v: Schema.Literal(AGENT_PROTOCOL_VERSION),
    op: Schema.Literals(["get", "remove"]),
    name: Schema.NonEmptyString,
  }),
  Schema.Struct({
    v: Schema.Literal(AGENT_PROTOCOL_VERSION),
    op: Schema.Literal("set"),
    name: Schema.NonEmptyString,
    value: Schema.String,
  }),
  Schema.Struct({ v: Schema.Literal(AGENT_PROTOCOL_VERSION), op: Schema.Literal("list") }),
]);
export type AgentRequest = typeof AgentRequestSchema.Type;

const AgentResponseSchema = Schema.Union([
  Schema.Struct({ ok: Schema.Literal(true), value: Schema.NullOr(Schema.String) }),
  Schema.Struct({ ok: Schema.Literal(true), names: Schema.Array(Schema.String) }),
  Schema.Struct({ ok: Schema.Literal(false), error: Schema.String }),
]);
export type AgentResponse = typeof AgentResponseSchema.Type;

const requestFromLine = Schema.fromJsonString(AgentRequestSchema);
const responseFromLine = Schema.fromJsonString(AgentResponseSchema);

export function parseAgentRequest(line: string): AgentRequest | null {
  return Option.getOrNull(Schema.decodeUnknownOption(requestFromLine)(line));
}

export function parseAgentResponse(line: string): AgentResponse | null {
  return Option.getOrNull(Schema.decodeUnknownOption(responseFromLine)(line));
}

export function encodeAgentRequest(request: AgentRequest): string {
  return `${JSON.stringify(request)}\n`;
}

function encodeAgentResponse(response: AgentResponse): string {
  return `${JSON.stringify(response)}\n`;
}

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
      return { ok: true, names: [...store.keys()] };
  }
}

export interface AgentStore {
  readonly apply: (request: AgentRequest) => AgentResponse;
  readonly clear: () => void;
}

export interface AgentStoreOptions {
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

const KEY_TTL_PATTERN = /^(\d+)([smh])$/;
const KEY_TTL_UNIT_MS = { s: 1_000, m: 60_000, h: 3_600_000 } as const;

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

export interface AgentServer {
  readonly socketPath: string;
  readonly close: () => Promise<void>;
}

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
  socket.on("error", () => {
    socket.destroy();
  });
}

export function startAgentServer(
  dir: string,
  options: AgentStoreOptions = {},
): Promise<AgentServer> {
  const socketPath = join(dir, SOCKET_FILE_NAME);
  const store = makeAgentStore(options);
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
      chmod(socketPath, 0o600).then(
        () =>
          resolve({
            socketPath,
            close: () =>
              new Promise<void>((done) => {
                store.clear();
                server.close(() => {
                  done();
                });
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

class AgentProtocolError extends Data.TaggedError("AgentProtocolError")<{
  readonly reason: string;
}> {}

class AgentGoneError extends Data.TaggedError("AgentGoneError")<{
  readonly reason: string;
}> {}

class AgentSocketRejectedError extends Data.TaggedError("AgentSocketRejectedError")<{
  readonly reason: string;
}> {}

const GONE_CODES = new Set(["ENOENT", "ECONNREFUSED", "ENOTSOCK", "EACCES"]);

function assertTrustedSocket(
  socketPath: string,
): Effect.Effect<void, AgentGoneError | AgentProtocolError | AgentSocketRejectedError> {
  return Effect.tryPromise({
    try: () => lstat(socketPath),
    catch: (error) => {
      const code =
        Predicate.hasProperty(error, "code") && Predicate.isString(error.code)
          ? error.code
          : "lstat";
      return GONE_CODES.has(code)
        ? new AgentGoneError({ reason: code })
        : new AgentProtocolError({ reason: code });
    },
  }).pipe(
    Effect.flatMap((stat) => {
      const reason = socketRejectionReason(stat);
      return reason === null ? Effect.void : Effect.fail(new AgentSocketRejectedError({ reason }));
    }),
  );
}

function socketRejectionReason(stat: Stats): string | null {
  if (!stat.isSocket()) {
    return "it is not a socket";
  }
  const uid = process.getuid?.() ?? -1;
  if (uid >= 0 && stat.uid !== uid) {
    return "it is not owned by you";
  }
  return (stat.mode & 0o077) === 0 ? null : "other users can access it";
}

export function sendAgentRequest(
  socketPath: string,
  request: AgentRequest,
): Effect.Effect<AgentResponse, AgentGoneError | AgentProtocolError | AgentSocketRejectedError> {
  const conversation = Effect.callback<AgentResponse, AgentGoneError | AgentProtocolError>(
    (resume) => {
      let buffered = "";
      const socket = createConnection(socketPath);
      const finish = (
        outcome: Effect.Effect<AgentResponse, AgentGoneError | AgentProtocolError>,
      ): void => {
        socket.destroy();
        resume(outcome);
      };
      socket.setEncoding("utf8");
      socket.once("connect", () => {
        socket.write(encodeAgentRequest(request));
      });
      socket.on("data", (chunk: string) => {
        buffered += chunk;
        if (Buffer.byteLength(buffered) > MAX_MESSAGE_BYTES) {
          finish(Effect.fail(new AgentProtocolError({ reason: "response too large" })));
          return;
        }
        const newline = buffered.indexOf("\n");
        if (newline < 0) {
          return;
        }
        const response = parseAgentResponse(buffered.slice(0, newline));
        finish(
          response === null
            ? Effect.fail(new AgentProtocolError({ reason: "malformed response" }))
            : Effect.succeed(response),
        );
      });
      socket.on("error", (error: NodeJS.ErrnoException) => {
        finish(
          Effect.fail(
            error.code !== undefined && GONE_CODES.has(error.code)
              ? new AgentGoneError({ reason: error.code })
              : new AgentProtocolError({ reason: error.code ?? "socket error" }),
          ),
        );
      });
      socket.once("close", () => finish(Effect.fail(new AgentProtocolError({ reason: "closed" }))));
      return Effect.sync(() => {
        socket.destroy();
      });
    },
  );
  return assertTrustedSocket(socketPath).pipe(
    Effect.andThen(
      conversation.pipe(
        Effect.timeout(IO_TIMEOUT_MS),
        Effect.catchTag("TimeoutError", () =>
          Effect.fail(new AgentProtocolError({ reason: "timeout" })),
        ),
      ),
    ),
  );
}

const agentGoneMessage =
  `Cannot connect to the maruhi agent (${AGENT_SOCKET_ENV} points to a socket nobody is listening on). The agent session has ended — start a new one with \`maruhi agent -- <shell>\`, or unset ${AGENT_SOCKET_ENV} to use the OS keychain` as const;

const agentProtocolMessage =
  "The maruhi agent did not answer as expected (a different maruhi version may be running it). Exit the agent session and start a new one with `maruhi agent -- <shell>` using this version" as const;

const agentErrorHandlers = {
  AgentSocketRejectedError: (error: AgentSocketRejectedError) =>
    Effect.fail(
      cliError(
        `Refusing to use the agent socket named by ${AGENT_SOCKET_ENV}: ${error.reason}. Unset ${AGENT_SOCKET_ENV}, or start a new session with \`maruhi agent -- <shell>\``,
      ),
    ),
  AgentProtocolError: () => Effect.fail(cliError(agentProtocolMessage)),
} as const;

function probeAgent(socketPath: string): Effect.Effect<"live" | "gone", CliError> {
  return sendAgentRequest(socketPath, { v: 1, op: "list" }).pipe(
    Effect.as("live" as const),
    Effect.catchTags({
      ...agentErrorHandlers,
      AgentGoneError: () => Effect.succeed("gone" as const),
    }),
  );
}

function askAgent(
  socketPath: string,
  request: AgentRequest,
): Effect.Effect<Exclude<AgentResponse, { readonly ok: false }>, CliError> {
  return sendAgentRequest(socketPath, request).pipe(
    Effect.catchTags({
      ...agentErrorHandlers,
      AgentGoneError: () => Effect.fail(cliError(agentGoneMessage)),
    }),
    Effect.flatMap((response) =>
      response.ok ? Effect.succeed(response) : Effect.fail(cliError(agentProtocolMessage)),
    ),
  );
}

export function makeAgentKeychain(socketPath: string): KeychainShape {
  const ask = (request: AgentRequest): Effect.Effect<string | null, CliError> =>
    askAgent(socketPath, request).pipe(
      Effect.flatMap((response) =>
        "value" in response
          ? Effect.succeed(response.value)
          : Effect.fail(cliError(agentProtocolMessage)),
      ),
    );
  return {
    kind: "agent",
    get: (name) => ask({ v: 1, op: "get", name }),
    set: (name, value) => Effect.asVoid(ask({ v: 1, op: "set", name, value })),
    remove: (name) => Effect.asVoid(ask({ v: 1, op: "remove", name })),
  };
}

export const AGENT_COMMAND_REQUIRED =
  "Write the command to run inside the agent session after `--` (example: `maruhi agent -- bash`)";

function runtimeBaseDir(envVar: (name: string) => string | undefined): string {
  const runtime = envVar("XDG_RUNTIME_DIR");
  return runtime !== undefined && runtime.length > 0 ? runtime : tmpdir();
}

export const privateRuntimeDir = Effect.fn("agent.privateRuntimeDir")(function* (input: {
  readonly envVar: (name: string) => string | undefined;
  readonly prefix: string;
  readonly purpose: string;
  readonly removeFailure: (dir: string) => string;
}): Effect.fn.Return<
  { readonly dir: string; readonly removeDir: Effect.Effect<void, never, CliIo> },
  CliError
> {
  const dir = yield* Effect.tryPromise({
    try: () => mkdtemp(join(runtimeBaseDir(input.envVar), input.prefix)),
    catch: () =>
      cliError(
        `Cannot create a private directory for ${input.purpose} (under XDG_RUNTIME_DIR, or the temp directory when it is unset)`,
      ),
  });
  const removeDir = Effect.tryPromise({
    try: () => rm(dir, { recursive: true, force: true }),
    catch: () => cliError(input.removeFailure(dir)),
  }).pipe(Effect.catch((error) => logWarning(error.message)));
  return { dir, removeDir };
});

export const agentOp = Effect.fn("agent.agentOp")(function* (input: {
  readonly command: readonly string[];
  readonly keyTtl?: { readonly ms: number; readonly text: string } | undefined;
}): Effect.fn.Return<number, CliError, CliIo | ProcessRunner> {
  const io = yield* CliIo;
  const runner = yield* ProcessRunner;
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
  const { dir, removeDir } = yield* privateRuntimeDir({
    envVar: io.envVar,
    prefix: "maruhi-agent-",
    purpose: "the agent socket",
    removeFailure: (path) =>
      `could not remove the agent socket directory (${path}) — remove it by hand`,
  });
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

export const agentStatusOp = Effect.fn("agent.agentStatusOp")(function* (): Effect.fn.Return<
  void,
  CliError,
  CliIo
> {
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
  yield* io.log(`socket:      ${displayText(socketPath)}`);
  if (response.names.length === 0) {
    yield* io.log("holding:     nothing yet (run `maruhi login` in this session)");
    return;
  }
  for (const name of response.names.toSorted()) {
    yield* io.log(describeEntryName(name));
  }
});

function describeEntryName(name: string): string {
  const token = /^token::(.+)$/.exec(name);
  if (token !== null) {
    return `token:       ${displayText(token[1] ?? "")}`;
  }
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
