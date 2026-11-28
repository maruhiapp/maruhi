import { chmod as setFileMode, mkdtemp, rename, rm, stat } from "node:fs/promises";
import { createServer, type Socket } from "node:net";
import { platform, tmpdir } from "node:os";
import { join } from "node:path";

import { wrapMasterSecret } from "@maruhi/crypto";
import { Cause, Duration, Effect, Exit, Fiber, Layer, Predicate, Redacted } from "effect";
import { TestClock } from "effect/testing";
import { afterEach, describe, expect, it } from "vite-plus/test";

import {
  AGENT_SOCKET_ENV,
  encodeAgentRequest,
  handleAgentRequest,
  makeAgentKeychain,
  makeAgentStore,
  parseAgentRequest,
  parseAgentResponse,
  sendAgentRequest,
  startAgentServer,
} from "../src/agent.ts";
import { runCli } from "../src/cli.ts";
import {
  Keychain,
  masterKeyEntryName,
  parseStoredMasterKey,
  serializeStoredMasterKey,
  type StoredMasterKey,
  tokenEntryName,
} from "../src/keychain.ts";
import { formatRecoveryCode } from "../src/reserve.package/recovery-code.ts";
import { buildChildEnvironment } from "../src/run.ts";
import { makeTestUser, type TestUser } from "./support/crypto.ts";
import { testUserId } from "./support/crypto.ts";
import { makeTestEnv, seedConfig } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

const describeSocket = platform() === "win32" ? describe.skip : describe;

let cleanups: (() => Promise<void>)[] = [];

afterEach(async () => {
  await Promise.all(cleanups.map((cleanup) => cleanup()));
  cleanups = [];
});

async function privateDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "maruhi-agent-test-"));
  cleanups.push(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

async function fileMode(path: string): Promise<number> {
  return (await stat(path)).mode & 0o777;
}

async function exists(path: string): Promise<boolean> {
  return stat(path).then(
    () => true,
    () => false,
  );
}

describe("agent protocol (newline-delimited JSON)", () => {
  it("request parsing: accepts get / set / remove by version and shape; anything else is null", () => {
    expect(parseAgentRequest('{"v":1,"op":"get","name":"token::x"}')).toEqual({
      v: 1,
      op: "get",
      name: "token::x",
    });
    expect(parseAgentRequest('{"v":1,"op":"set","name":"a","value":"b"}')).toEqual({
      v: 1,
      op: "set",
      name: "a",
      value: "b",
    });
    expect(parseAgentRequest('{"v":1,"op":"remove","name":"a"}')).toEqual({
      v: 1,
      op: "remove",
      name: "a",
    });
    expect(parseAgentRequest('{"v":2,"op":"get","name":"a"}')).toBeNull();
    expect(parseAgentRequest('{"op":"get","name":"a"}')).toBeNull();
    expect(parseAgentRequest('{"v":1,"op":"set","name":"a"}')).toBeNull();
    expect(parseAgentRequest('{"v":1,"op":"get","name":""}')).toBeNull();
    expect(parseAgentRequest('{"v":1,"op":"dump","name":"a"}')).toBeNull();
    expect(parseAgentRequest("not json")).toBeNull();
    expect(parseAgentRequest("[1]")).toBeNull();
    expect(parseAgentRequest('{"v":1,"op":"list"}')).toEqual({ v: 1, op: "list" });
    expect(parseAgentRequest('{"v":2,"op":"list"}')).toBeNull();
  });

  it("response parsing: accepts only ok/value and ok:false/error", () => {
    expect(parseAgentResponse('{"ok":true,"value":"x"}')).toEqual({ ok: true, value: "x" });
    expect(parseAgentResponse('{"ok":true,"value":null}')).toEqual({ ok: true, value: null });
    expect(parseAgentResponse('{"ok":false,"error":"nope"}')).toEqual({
      ok: false,
      error: "nope",
    });
    expect(parseAgentResponse('{"ok":true,"names":["a","b"]}')).toEqual({
      ok: true,
      names: ["a", "b"],
    });
    expect(parseAgentResponse('{"ok":true,"names":[1]}')).toBeNull();
    expect(parseAgentResponse('{"ok":true}')).toBeNull();
    expect(parseAgentResponse('{"ok":false}')).toBeNull();
    expect(parseAgentResponse("{")).toBeNull();
  });

  it("the wire form is one message per line (trailing newline)", () => {
    expect(encodeAgentRequest({ v: 1, op: "get", name: "a" })).toBe(
      '{"v":1,"op":"get","name":"a"}\n',
    );
  });

  it("storage semantics: absent reads null, set then reads back, remove then is gone", () => {
    const store = new Map<string, string>();
    expect(handleAgentRequest(store, { v: 1, op: "get", name: "a" })).toEqual({
      ok: true,
      value: null,
    });
    expect(handleAgentRequest(store, { v: 1, op: "set", name: "a", value: "1" })).toEqual({
      ok: true,
      value: null,
    });
    expect(handleAgentRequest(store, { v: 1, op: "get", name: "a" })).toEqual({
      ok: true,
      value: "1",
    });
    expect(handleAgentRequest(store, { v: 1, op: "remove", name: "a" })).toEqual({
      ok: true,
      value: null,
    });
    expect(handleAgentRequest(store, { v: 1, op: "get", name: "a" })).toEqual({
      ok: true,
      value: null,
    });
  });

  it("list returns only names (values are not carried)", () => {
    const store = new Map<string, string>([
      ["token::https://a", "secret-1"],
      ["master::https://a::u1", "secret-2"],
    ]);
    const listed = handleAgentRequest(store, { v: 1, op: "list" });
    expect(listed).toEqual({ ok: true, names: ["token::https://a", "master::https://a::u1"] });
    expect(JSON.stringify(listed)).not.toContain("secret");
  });

  it("--key-ttl: forgets only master-key entries on expiry, keeps tokens (set extends the deadline)", () => {
    let clock = 1_000;
    const store = makeAgentStore({ keyTtlMs: 100, now: () => clock });
    const token = tokenEntryName("https://a");
    const master = masterKeyEntryName("https://a", testUserId("u1"));
    store.apply({ v: 1, op: "set", name: token, value: "t" });
    store.apply({ v: 1, op: "set", name: master, value: "m" });
    clock = 1_099;
    expect(store.apply({ v: 1, op: "get", name: master })).toEqual({ ok: true, value: "m" });
    store.apply({ v: 1, op: "set", name: master, value: "m2" });
    clock = 1_150;
    expect(store.apply({ v: 1, op: "get", name: master })).toEqual({ ok: true, value: "m2" });
    clock = 1_198;
    expect(store.apply({ v: 1, op: "list" })).toEqual({ ok: true, names: [token, master] });
    clock = 1_199;
    expect(store.apply({ v: 1, op: "get", name: master })).toEqual({ ok: true, value: null });
    expect(store.apply({ v: 1, op: "get", name: token })).toEqual({ ok: true, value: "t" });
    expect(store.apply({ v: 1, op: "list" })).toEqual({ ok: true, names: [token] });
    const forever = makeAgentStore({ now: () => clock });
    forever.apply({ v: 1, op: "set", name: master, value: "m" });
    clock = Number.MAX_SAFE_INTEGER;
    expect(forever.apply({ v: 1, op: "get", name: master })).toEqual({ ok: true, value: "m" });
  });
});

describeSocket("agent server and client (real unix socket)", () => {
  it("round-trips get / set / remove as a Keychain implementation; the socket is 0600", async () => {
    const dir = await privateDir();
    const server = await startAgentServer(dir);
    cleanups.push(() => server.close());
    expect(server.socketPath).toBe(join(dir, "agent.sock"));
    expect(await fileMode(server.socketPath)).toBe(0o600);
    expect((await stat(server.socketPath)).isSocket()).toBe(true);

    const keychain = makeAgentKeychain(server.socketPath);
    expect(keychain.kind).toBe("agent");
    expect(await Effect.runPromise(keychain.get("token::x"))).toBeNull();
    await Effect.runPromise(keychain.set("token::x", '{"token":"maruhi_pat_a"}'));
    expect(await Effect.runPromise(keychain.get("token::x"))).toBe('{"token":"maruhi_pat_a"}');
    expect(await Effect.runPromise(keychain.get("master::x::u"))).toBeNull();
    await Effect.runPromise(keychain.remove("token::x"));
    expect(await Effect.runPromise(keychain.get("token::x"))).toBeNull();
  });

  it("rejects malformed requests and version mismatches with ok:false and closes the connection (no silent parsing)", async () => {
    const dir = await privateDir();
    const server = await startAgentServer(dir);
    cleanups.push(() => server.close());
    const { createConnection } = await import("node:net");
    const raw = (line: string): Promise<string> =>
      new Promise((resolve, reject) => {
        const socket = createConnection(server.socketPath);
        let buffered = "";
        socket.setEncoding("utf8");
        socket.once("connect", () => socket.write(line));
        socket.on("data", (chunk: string) => {
          buffered += chunk;
        });
        socket.once("close", () => resolve(buffered));
        socket.once("error", reject);
      });
    expect(parseAgentResponse((await raw('{"v":9,"op":"get","name":"a"}\n')).trim())).toEqual({
      ok: false,
      error: "malformed request (protocol version mismatch?)",
    });
    expect(parseAgentResponse((await raw("garbage\n")).trim())).toEqual({
      ok: false,
      error: "malformed request (protocol version mismatch?)",
    });
    const { createConnection: connect } = await import("node:net");
    const split = await new Promise<string>((resolve, reject) => {
      const socket = connect(server.socketPath);
      let buffered = "";
      socket.setEncoding("utf8");
      socket.once("connect", () => {
        socket.write('{"v":1,"op":"g');
        setTimeout(() => socket.write('et","name":"a"}\n'), 20);
      });
      socket.on("data", (chunk: string) => {
        buffered += chunk;
      });
      socket.once("close", () => resolve(buffered));
      socket.once("error", reject);
    });
    expect(parseAgentResponse(split.trim())).toEqual({ ok: true, value: null });
  });

  it("close drops the held contents and the socket stops listening (the client names the session as ended)", async () => {
    const dir = await privateDir();
    const server = await startAgentServer(dir);
    const keychain = makeAgentKeychain(server.socketPath);
    await Effect.runPromise(keychain.set("token::x", "v"));
    await server.close();
    const exit = await Effect.runPromiseExit(keychain.get("token::x"));
    expect(Exit.isFailure(exit)).toBe(true);
    const message = JSON.stringify(exit);
    expect(message).toContain("The agent session has ended");
    expect(message).toContain("maruhi agent -- <shell>");
  });

  it("close is not held up by a peer that stays connected without sending a request (cleanup runs)", async () => {
    const dir = await privateDir();
    const server = await startAgentServer(dir);
    const { createConnection } = await import("node:net");
    const idle = createConnection(server.socketPath);
    await new Promise<void>((resolve) => idle.once("connect", () => resolve()));
    const clientClosed = new Promise<void>((resolve) => idle.once("close", () => resolve()));
    const started = Date.now();
    await server.close();
    await Promise.race([
      clientClosed,
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("the idle client was not disconnected")), 2_000),
      ),
    ]);
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  it("a path with no socket gives the same ended message (stale MARUHI_AGENT_SOCK)", async () => {
    const dir = await privateDir();
    const keychain = makeAgentKeychain(join(dir, "gone.sock"));
    const exit = await Effect.runPromiseExit(keychain.get("token::x"));
    expect(JSON.stringify(exit)).toContain("The agent session has ended");
  });
});

interface ScriptedAgent {
  readonly socketPath: string;
  readonly received: Promise<string>;
  readonly disconnected: Promise<void>;
  readonly isDisconnected: () => boolean;
}

async function scriptedAgent(respond: (socket: Socket) => void): Promise<ScriptedAgent> {
  const socketPath = join(await privateDir(), "agent.sock");
  let onReceived: (line: string) => void = () => undefined;
  let onDisconnected: () => void = () => undefined;
  const received = new Promise<string>((resolve) => {
    onReceived = resolve;
  });
  const disconnected = new Promise<void>((resolve) => {
    onDisconnected = resolve;
  });
  let closed = false;
  const connections = new Set<Socket>();
  const server = createServer((socket) => {
    const first = connections.size === 0;
    connections.add(socket);
    let buffered = "";
    let answered = false;
    socket.setEncoding("utf8");
    socket.on("data", (chunk: string) => {
      buffered += chunk;
      const newline = buffered.indexOf("\n");
      if (answered || newline < 0) {
        return;
      }
      answered = true;
      if (first) {
        onReceived(buffered.slice(0, newline));
      }
      respond(socket);
    });
    socket.on("error", () => {
      socket.destroy();
    });
    socket.once("close", () => {
      if (first) {
        closed = true;
        onDisconnected();
      }
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => {
      server.off("error", reject);
      resolve();
    });
  });
  await setFileMode(socketPath, 0o600);
  cleanups.push(
    () =>
      new Promise<void>((resolve) => {
        for (const socket of connections) {
          socket.destroy();
        }
        server.close(() => resolve());
      }),
  );
  return { socketPath, received, disconnected, isDisconnected: () => closed };
}

function agentFailure(exit: Exit.Exit<unknown, unknown>): {
  readonly _tag: string;
  readonly reason: string;
} {
  if (!Exit.isFailure(exit)) {
    throw new Error("expected a failure exit");
  }
  const error = Cause.squash(exit.cause);
  if (!Predicate.hasProperty(error, "_tag") || !Predicate.hasProperty(error, "reason")) {
    throw new Error("expected a tagged agent error");
  }
  const { _tag: tag, reason } = error;
  if (!Predicate.isString(tag) || !Predicate.isString(reason)) {
    throw new Error("expected a tagged agent error");
  }
  return { _tag: tag, reason };
}

function failureMessage(exit: Exit.Exit<unknown, unknown>): string {
  if (!Exit.isFailure(exit)) {
    throw new Error("expected a failure exit");
  }
  const error = Cause.squash(exit.cause);
  if (!Predicate.hasProperty(error, "message") || !Predicate.isString(error.message)) {
    throw new Error("expected an error with a message");
  }
  return error.message;
}

const AGENT_PROTOCOL_MESSAGE =
  "The maruhi agent did not answer as expected (a different maruhi version may be running it). Exit the agent session and start a new one with `maruhi agent -- <shell>` using this version";

const AGENT_GONE_MESSAGE =
  "Cannot connect to the maruhi agent (MARUHI_AGENT_SOCK points to a socket nobody is listening on). The agent session has ended — start a new one with `maruhi agent -- <shell>`, or unset MARUHI_AGENT_SOCK to use the OS keychain";

function acrossTheTimeout<A, E>(
  agent: ScriptedAgent,
  effect: Effect.Effect<A, E>,
): Promise<{ readonly exit: Exit.Exit<A, E>; readonly heldBeforeLimit: boolean }> {
  return Effect.runPromise(
    Effect.gen(function* () {
      const fiber = yield* Effect.forkChild(Effect.exit(effect));
      yield* Effect.promise(() => agent.received);
      yield* TestClock.adjust(Duration.millis(4_999));
      yield* Effect.promise(() => new Promise<void>((resolve) => setTimeout(resolve, 20)));
      const heldBeforeLimit = fiber.pollUnsafe() === undefined && !agent.isDisconnected();
      yield* TestClock.adjust(Duration.millis(1));
      const exit = yield* Fiber.join(fiber);
      return { exit, heldBeforeLimit };
    }).pipe(Effect.provide(TestClock.layer())),
  );
}

describeSocket("agent client failures (real unix socket, sendAgentRequest)", () => {
  it("a silent agent times out at 5 s on the Effect clock, and the client severs the connection", async () => {
    const agent = await scriptedAgent(() => undefined);
    const { exit, heldBeforeLimit } = await acrossTheTimeout(
      agent,
      sendAgentRequest(agent.socketPath, { v: 1, op: "list" }),
    );
    expect(await agent.received).toBe('{"v":1,"op":"list"}');
    expect(heldBeforeLimit).toBe(true);
    expect(agentFailure(exit)).toEqual({ _tag: "AgentProtocolError", reason: "timeout" });
    await agent.disconnected;
    expect(agent.isDisconnected()).toBe(true);

    const viaKeychain = await scriptedAgent(() => undefined);
    const keychainRun = await acrossTheTimeout(
      viaKeychain,
      makeAgentKeychain(viaKeychain.socketPath).get("token::x"),
    );
    expect(keychainRun.heldBeforeLimit).toBe(true);
    expect(failureMessage(keychainRun.exit)).toBe(AGENT_PROTOCOL_MESSAGE);
    await viaKeychain.disconnected;
  });

  it("an agent that answers garbage and closes without a newline is classified as closed", async () => {
    const agent = await scriptedAgent((socket) => socket.end("garbage"));
    const exit = await Effect.runPromiseExit(
      sendAgentRequest(agent.socketPath, { v: 1, op: "get", name: "token::x" }),
    );
    expect(agentFailure(exit)).toEqual({ _tag: "AgentProtocolError", reason: "closed" });
    await agent.disconnected;
    const viaKeychain = await scriptedAgent((socket) => socket.end("garbage"));
    expect(
      failureMessage(
        await Effect.runPromiseExit(makeAgentKeychain(viaKeychain.socketPath).get("token::x")),
      ),
    ).toBe(AGENT_PROTOCOL_MESSAGE);
  });

  it("a complete but malformed response line is classified as a malformed response", async () => {
    const agent = await scriptedAgent((socket) => socket.end("garbage\n"));
    const exit = await Effect.runPromiseExit(
      sendAgentRequest(agent.socketPath, { v: 1, op: "get", name: "token::x" }),
    );
    expect(agentFailure(exit)).toEqual({
      _tag: "AgentProtocolError",
      reason: "malformed response",
    });
    const viaKeychain = await scriptedAgent((socket) => socket.end("garbage\n"));
    expect(
      failureMessage(
        await Effect.runPromiseExit(makeAgentKeychain(viaKeychain.socketPath).get("token::x")),
      ),
    ).toBe(AGENT_PROTOCOL_MESSAGE);
  });

  it("a response beyond the 64 KiB cap is refused as too large, and the client severs the connection", async () => {
    const oversized = "x".repeat(64 * 1024 + 1);
    const agent = await scriptedAgent((socket) => socket.write(oversized));
    const exit = await Effect.runPromiseExit(
      sendAgentRequest(agent.socketPath, { v: 1, op: "get", name: "token::x" }),
    );
    expect(agentFailure(exit)).toEqual({
      _tag: "AgentProtocolError",
      reason: "response too large",
    });
    await agent.disconnected;
    expect(agent.isDisconnected()).toBe(true);
    const viaKeychain = await scriptedAgent((socket) => socket.write(oversized));
    expect(
      failureMessage(
        await Effect.runPromiseExit(makeAgentKeychain(viaKeychain.socketPath).get("token::x")),
      ),
    ).toBe(AGENT_PROTOCOL_MESSAGE);
  });

  it("a trusted socket file nobody listens on fails the connect as ECONNREFUSED (the session has ended)", async () => {
    const dir = await privateDir();
    const server = await startAgentServer(dir);
    const orphan = join(dir, "orphan.sock");
    await rename(server.socketPath, orphan);
    await server.close();
    expect((await stat(orphan)).isSocket()).toBe(true);
    expect(await fileMode(orphan)).toBe(0o600);
    const exit = await Effect.runPromiseExit(sendAgentRequest(orphan, { v: 1, op: "list" }));
    expect(agentFailure(exit)).toEqual({ _tag: "AgentGoneError", reason: "ECONNREFUSED" });
    expect(
      failureMessage(await Effect.runPromiseExit(makeAgentKeychain(orphan).get("token::x"))),
    ).toBe(AGENT_GONE_MESSAGE);
  });
});

describeSocket("maruhi agent -- <command>", () => {
  it("passes MARUHI_AGENT_SOCK to the child, the agent listens only while the child lives, and the exit code is inherited", async () => {
    const env = await makeTestEnv();
    let socketPath = "";
    let seenInside: string | null = null;
    env.setSessionHandler(async (call) => {
      socketPath = call.env[AGENT_SOCKET_ENV] ?? "";
      const inside = makeAgentKeychain(socketPath);
      await Effect.runPromise(inside.set("token::https://maruhi.test", "record"));
      seenInside = await Effect.runPromise(inside.get("token::https://maruhi.test"));
      expect(await fileMode(socketPath)).toBe(0o600);
      expect(await fileMode(join(socketPath, ".."))).toBe(0o700);
      return 7;
    });
    expect(await runCli(["agent", "--", "bash", "-l"], env.layer)).toBe(7);
    expect(env.sessionCalls).toHaveLength(1);
    expect(env.sessionCalls[0]?.command).toEqual(["bash", "-l"]);
    expect(socketPath.endsWith("/agent.sock")).toBe(true);
    expect(seenInside).toBe("record");
    expect(await exists(socketPath)).toBe(false);
    expect(await exists(join(socketPath, ".."))).toBe(false);
    const after = await Effect.runPromiseExit(
      makeAgentKeychain(socketPath).get("token::https://maruhi.test"),
    );
    expect(Exit.isFailure(after)).toBe(true);
    expect(env.errors.join("\n")).toContain("stay in memory only");
    expect(env.logs).toEqual([]);
    expect(env.sessionCalls[0]?.env).toEqual({ [AGENT_SOCKET_ENV]: socketPath });
  });

  it("places the socket under XDG_RUNTIME_DIR when set", async () => {
    const env = await makeTestEnv();
    const runtime = await privateDir();
    env.setEnvVar("XDG_RUNTIME_DIR", runtime);
    let socketPath = "";
    env.setSessionHandler((call) => {
      socketPath = call.env[AGENT_SOCKET_ENV] ?? "";
      return Promise.resolve(0);
    });
    expect(await runCli(["agent", "--", "sh"], env.layer)).toBe(0);
    expect(socketPath.startsWith(`${runtime}/maruhi-agent-`)).toBe(true);
  });

  it("refuses nesting (MARUHI_AGENT_SOCK pointing at a live agent) and does not spawn the child", async () => {
    const dir = await privateDir();
    const outer = await startAgentServer(dir);
    cleanups.push(() => outer.close());
    const env = await makeTestEnv();
    env.setEnvVar(AGENT_SOCKET_ENV, outer.socketPath);
    expect(await runCli(["agent", "--", "sh"], env.layer)).toBe(1);
    expect(env.sessionCalls).toEqual([]);
    expect(env.errors.join("\n")).toContain("Already inside an agent session");
  });

  it("starts fresh when the session leftover (MARUHI_AGENT_SOCK pointing nowhere) is stale", async () => {
    const dir = await privateDir();
    const env = await makeTestEnv();
    env.setEnvVar(AGENT_SOCKET_ENV, join(dir, "agent.sock"));
    let socketPath = "";
    env.setSessionHandler((call) => {
      socketPath = call.env[AGENT_SOCKET_ENV] ?? "";
      return Promise.resolve(0);
    });
    expect(await runCli(["agent", "--", "sh"], env.layer)).toBe(0);
    expect(socketPath).not.toBe(join(dir, "agent.sock"));
    expect(socketPath.endsWith("/agent.sock")).toBe(true);
    expect(env.errors.join("\n")).toContain("has already ended; starting a new one");
  });

  it("distrusts what MARUHI_AGENT_SOCK points at: no plaintext to a non-socket or a world-accessible one", async () => {
    const { writeFile } = await import("node:fs/promises");
    const { chmod } = await import("node:fs/promises");
    const dir = await privateDir();
    const file = join(dir, "not-a-socket");
    await writeFile(file, "");
    const asFile = await Effect.runPromiseExit(makeAgentKeychain(file).set("token::x", "v"));
    expect(JSON.stringify(asFile)).toContain("it is not a socket");
    const server = await startAgentServer(dir);
    cleanups.push(() => server.close());
    await chmod(server.socketPath, 0o666);
    const loose = await Effect.runPromiseExit(makeAgentKeychain(server.socketPath).get("token::x"));
    expect(JSON.stringify(loose)).toContain("other users can access it");
    await chmod(server.socketPath, 0o600);
    expect(
      await Effect.runPromise(makeAgentKeychain(server.socketPath).get("token::x")),
    ).toBeNull();
  });

  it("no run target after `--` is a usage error (2)", async () => {
    const env = await makeTestEnv();
    expect(await runCli(["agent"], env.layer)).toBe(2);
    expect(await runCli(["agent", "--", ""], env.layer)).toBe(2);
    expect(await runCli(["agent", "sh", "--", "bash"], env.layer)).toBe(2);
    expect(env.sessionCalls).toEqual([]);
    expect(env.errors.join("\n")).toContain("after `--`");
  });

  it("--key-ttl accepts only number + s/m/h and prints guidance to stderr (format error is 2)", async () => {
    const env = await makeTestEnv();
    expect(await runCli(["agent", "--key-ttl", "90", "--", "bash"], env.layer)).toBe(2);
    expect(await runCli(["agent", "--key-ttl", "0m", "--", "bash"], env.layer)).toBe(2);
    expect(await runCli(["agent", "--key-ttl", "1d", "--", "bash"], env.layer)).toBe(2);
    expect(env.sessionCalls).toEqual([]);
    expect(env.errors.join("\n")).toContain("Write --key-ttl as a number followed by s, m, or h");
    expect(await runCli(["agent", "--key-ttl", "2h", "--", "bash"], env.layer)).toBe(0);
    expect(env.sessionCalls).toHaveLength(1);
    const ttlHint = env.errors.join("\n");
    expect(ttlHint).toContain("This device's key is forgotten 2h after it is stored");
    expect(ttlHint).toContain("`maruhi device add`");
    expect(ttlHint).toContain("`maruhi device revoke`");
    expect(ttlHint).not.toContain("`maruhi key recover`");
  });

  it("`agent -- status` runs the child command, not a subcommand (does not span `--`)", async () => {
    const env = await makeTestEnv();
    expect(await runCli(["agent", "--", "status"], env.layer)).toBe(0);
    expect(env.sessionCalls[0]?.command).toEqual(["status"]);
  });

  it("a `maruhi run` child does not get MARUHI_AGENT_SOCK (the existing rule that MARUHI_* is not passed)", () => {
    expect(
      buildChildEnvironment({ PATH: "/usr/bin", [AGENT_SOCKET_ENV]: "/run/x/agent.sock" }, {}),
    ).toEqual({ PATH: "/usr/bin" });
  });
});

describeSocket("maruhi agent status", () => {
  it("inside a session it lists held entry names and no values", async () => {
    const dir = await privateDir();
    const server = await startAgentServer(dir);
    cleanups.push(() => server.close());
    const agent = makeAgentKeychain(server.socketPath);
    await Effect.runPromise(agent.set(tokenEntryName("https://maruhi.test"), "maruhi_pat_secret"));
    await Effect.runPromise(
      agent.set(
        masterKeyEntryName("https://maruhi.test", testUserId("user-0001")),
        "master-secret",
      ),
    );
    const env = await makeTestEnv();
    env.setEnvVar(AGENT_SOCKET_ENV, server.socketPath);
    await Effect.runPromise(
      agent.set(
        masterKeyEntryName("http://[::1]:8787", testUserId("user-0002")),
        "master-secret-2",
      ),
    );
    expect(await runCli(["agent", "status"], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).toContain(`socket:      ${server.socketPath}`);
    expect(output).toContain("token:       https://maruhi.test");
    expect(output).toContain("device key:  https://maruhi.test (user user-0001)");
    expect(output).toContain("device key:  http://[::1]:8787 (user user-0002)");
    expect(output).not.toContain("secret");
  });

  it("on a broken master-key record, guides toward recreating the session rather than the keychain", async () => {
    const dir = await privateDir();
    const server = await startAgentServer(dir);
    cleanups.push(() => server.close());
    const agent = makeAgentKeychain(server.socketPath);
    await Effect.runPromise(
      agent.set(
        tokenEntryName("https://maruhi.test"),
        JSON.stringify({
          token: "maruhi_pat_stored",
          userId: "user-0001",
          tokenId: "tok_1",
          expiresAtMs: 4_102_444_800_000,
        }),
      ),
    );
    await Effect.runPromise(
      agent.set(
        masterKeyEntryName("https://maruhi.test", testUserId("user-0001")),
        JSON.stringify({
          suite: "maruhi/v1",
          encPubHex: "zz",
          encSkHex: "zz",
          sigPubHex: "zz",
          sigSkSeedHex: "zz",
        }),
      ),
    );
    const env = await makeTestEnv();
    await seedConfig(env, { server: "https://maruhi.test" });
    const layer = Layer.merge(env.layer, Layer.succeed(Keychain, agent));
    expect(await runCli(["key", "show"], layer)).toBe(1);
    const message = env.errors.join("\n");
    expect(message).toContain("held by this agent session");
    expect(message).toContain("re-run inside this session");
    expect(message).toContain(
      "only if you still have another device of yours or your recovery code",
    );
    expect(message).toContain("exit the session");
    expect(message).toContain("maruhi agent -- <shell>");
    expect(message).not.toContain("by hand");
    expect(message).not.toContain("OS keychain");
  });

  it("when empty, says so and suggests the next step", async () => {
    const dir = await privateDir();
    const server = await startAgentServer(dir);
    cleanups.push(() => server.close());
    const env = await makeTestEnv();
    env.setEnvVar(AGENT_SOCKET_ENV, server.socketPath);
    expect(await runCli(["agent", "status"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("nothing yet (run `maruhi login` in this session)");
  });

  it("fails outside a session, and reports a stale socket as an ended session", async () => {
    const env = await makeTestEnv();
    expect(await runCli(["agent", "status"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Not inside an agent session");
    const dir = await privateDir();
    env.setEnvVar(AGENT_SOCKET_ENV, join(dir, "gone.sock"));
    expect(await runCli(["agent", "status"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("The agent session has ended");
  });

  it("a wrong flag to status is a usage error (2)", async () => {
    const env = await makeTestEnv();
    expect(await runCli(["agent", "status", "--bogus"], env.layer)).toBe(2);
  });
});

function storedMasterRecord(user: TestUser): StoredMasterKey {
  return {
    suite: "maruhi/v1",
    encPubHex: user.encPubHex,
    encSkHex: Redacted.make(user.encSkHex),
    sigPubHex: user.sigPubHex,
    sigSkSeedHex: Redacted.make(user.sigSkSeedHex),
  };
}

async function wrappedBlobHandler(
  user: TestUser,
  secret: Uint8Array,
): Promise<{ handler: MockHandler; code: string }> {
  const record = storedMasterRecord(user);
  const wrapped = await wrapMasterSecret({
    recoverySecret: secret,
    userId: user.userId,
    masterSecretBlob: new TextEncoder().encode(serializeStoredMasterKey(record)),
  });
  if (!wrapped.ok) {
    throw new Error("test wrap failed");
  }
  const handler = onRequest("GET", "/auth/recovery", () => ({
    status: 200,
    json: {
      suite: "maruhi/v1",
      nonceHex: Buffer.from(wrapped.value.nonce).toString("hex"),
      ciphertextHex: Buffer.from(wrapped.value.ciphertext).toString("hex"),
      updatedAtMs: 1754006400000,
    },
  }));
  return { handler, code: Redacted.value(formatRecoveryCode(Redacted.make(secret))) };
}

describeSocket("key recover lands in memory inside an agent session", () => {
  it("the newly issued device key goes only into the agent; nothing remains in the test keychain", async () => {
    const user = await makeTestUser("user-agent-0001");
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { handler, code } = await wrappedBlobHandler(user, secret);
    const maruhi = await MockServer.start([
      handler,
      onRequest("GET", "/projects", () => ({ status: 200, json: { projects: [] } })),
    ]);
    cleanups.push(() => maruhi.close());

    const dir = await privateDir();
    const server = await startAgentServer(dir);
    cleanups.push(() => server.close());
    const agent = makeAgentKeychain(server.socketPath);
    await Effect.runPromise(
      agent.set(
        tokenEntryName(maruhi.origin),
        JSON.stringify({
          token: "maruhi_pat_stored",
          userId: user.userId,
          tokenId: "tok_1",
          expiresAtMs: 4_102_444_800_000,
        }),
      ),
    );

    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.setPromptResponses([code]);
    const layer = Layer.merge(env.layer, Layer.succeed(Keychain, agent));
    expect(await runCli(["key", "recover"], layer)).toBe(0);

    expect(env.keychain.size).toBe(0);
    const stored = await Effect.runPromise(
      agent.get(masterKeyEntryName(maruhi.origin, user.userId)),
    );
    const device = parseStoredMasterKey(stored ?? "");
    if (device === null) throw new Error("expected the new device key in the agent");
    expect(device.encPubHex).not.toBe(user.encPubHex);
    expect(serializeStoredMasterKey(device)).not.toBe(
      serializeStoredMasterKey(storedMasterRecord(user)),
    );
    expect(stored).not.toContain(user.encSkHex);
    expect(stored).not.toContain(user.sigSkSeedHex);
    const output = env.logs.join("\n");
    expect(output).toContain(
      "Generated this device's key and stored it in the maruhi agent's memory (this session only)",
    );
    const shown = env.logs.find((line) => line.startsWith("key fingerprint: "));
    expect(shown).toMatch(/^key fingerprint: [0-9a-f]{32}$/);
    expect(shown).not.toBe(`key fingerprint: ${user.fingerprintHex}`);
    expect(env.errors.join("\n")).toContain("the reserve key was discarded from memory");
    expect(output).not.toContain(user.encSkHex);
    expect(output).not.toContain(code);

    const status = onRequest("GET", "/auth/recovery/status", () => ({
      status: 200,
      json: { registered: true, updatedAtMs: 1754006400000 },
    }));
    const maruhi2 = await MockServer.start([status]);
    cleanups.push(() => maruhi2.close());
    await Effect.runPromise(
      agent.set(
        tokenEntryName(maruhi2.origin),
        JSON.stringify({
          token: "maruhi_pat_stored",
          userId: user.userId,
          tokenId: "tok_1",
          expiresAtMs: 4_102_444_800_000,
        }),
      ),
    );
    await Effect.runPromise(
      agent.set(masterKeyEntryName(maruhi2.origin, user.userId), stored ?? ""),
    );
    expect(await runCli(["key", "show", "--server", maruhi2.origin], layer)).toBe(0);
    const deviceFingerprint = shown?.slice("key fingerprint: ".length) ?? "";
    expect(env.logs.join("\n")).toContain(`device key fingerprint: ${deviceFingerprint}`);
  });
});
