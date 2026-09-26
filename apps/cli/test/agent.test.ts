// Tests for `maruhi agent` (KL2 — in-session memory key holding).
//
// - Protocol (newline-delimited JSON) parsing and rejection (version mismatch,
//   malformed requests)
// - Server and client (the Keychain implementation) round-trip over a real
//   unix socket (node:net — the same path under vitest's Node and production
//   Bun)
// - Permissions: directory 0700, socket 0600; the socket disappears after exit
// - `maruhi agent -- <cmd>`: the child gets MARUHI_AGENT_SOCK and the agent
//   listens only while it lives; the child's exit code is inherited. Nesting
//   is refused; no `--` is a usage error
// - Restore-path wiring: `key recover` lands in the agent's memory and the
//   success message names the right destination (reproduces recovery.test.ts's
//   restore case on the agent side)
// - A `maruhi run` child does NOT get MARUHI_AGENT_SOCK (corollary of the
//   existing rule)

import { mkdtemp, rm, stat } from "node:fs/promises";
import { platform, tmpdir } from "node:os";
import { join } from "node:path";

import { wrapMasterSecret } from "@maruhi/crypto";
import { Effect, Exit, Layer, Redacted } from "effect";
import { afterEach, describe, expect, it } from "vitest";

import {
  AGENT_SOCKET_ENV,
  encodeAgentRequest,
  handleAgentRequest,
  makeAgentKeychain,
  makeAgentStore,
  parseAgentRequest,
  parseAgentResponse,
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
import { formatRecoveryCode } from "../src/recovery-code.ts";
import { buildChildEnvironment } from "../src/run.ts";
import { makeTestUser, type TestUser } from "./support/crypto.ts";
import { makeTestEnv, seedConfig } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

// Unix domain sockets are a different thing on Windows (named pipes). The
// implementation already makes win32 an explicit error, so the socket-path
// tests don't run there
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
    // Version mismatches are not silently parsed
    expect(parseAgentRequest('{"v":2,"op":"get","name":"a"}')).toBeNull();
    expect(parseAgentRequest('{"op":"get","name":"a"}')).toBeNull();
    // set without value / empty name / unknown op / not JSON / an array
    expect(parseAgentRequest('{"v":1,"op":"set","name":"a"}')).toBeNull();
    expect(parseAgentRequest('{"v":1,"op":"get","name":""}')).toBeNull();
    expect(parseAgentRequest('{"v":1,"op":"dump","name":"a"}')).toBeNull();
    expect(parseAgentRequest("not json")).toBeNull();
    expect(parseAgentRequest("[1]")).toBeNull();
    // list takes no name (for status)
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
    const master = masterKeyEntryName("https://a", "u1");
    store.apply({ v: 1, op: "set", name: token, value: "t" });
    store.apply({ v: 1, op: "set", name: master, value: "m" });
    clock = 1_099;
    expect(store.apply({ v: 1, op: "get", name: master })).toEqual({ ok: true, value: "m" });
    // Re-setting (set) carries a fresh deadline
    store.apply({ v: 1, op: "set", name: master, value: "m2" });
    clock = 1_150;
    expect(store.apply({ v: 1, op: "get", name: master })).toEqual({ ok: true, value: "m2" });
    clock = 1_198;
    expect(store.apply({ v: 1, op: "list" })).toEqual({ ok: true, names: [token, master] });
    // Deadline reached (1099 + 100): the key is gone, the token remains (gone
    // from status's list too)
    clock = 1_199;
    expect(store.apply({ v: 1, op: "get", name: master })).toEqual({ ok: true, value: null });
    expect(store.apply({ v: 1, op: "get", name: token })).toEqual({ ok: true, value: "t" });
    expect(store.apply({ v: 1, op: "list" })).toEqual({ ok: true, names: [token] });
    // Without a TTL no deadline is attached
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
    // Other entries are independent
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
    // Responds once a full line has arrived even if it arrives split
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
    // A peer that stays silent without sending a line (broken / hostile client)
    const idle = createConnection(server.socketPath);
    await new Promise<void>((resolve) => idle.once("connect", () => resolve()));
    const clientClosed = new Promise<void>((resolve) => idle.once("close", () => resolve()));
    const started = Date.now();
    // server.close only waits for every connection to end naturally, so it
    // doesn't return unless they are cut (verify close itself cuts them, ahead
    // of the 5-second idle timeout)
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

describeSocket("maruhi agent -- <command>", () => {
  it("passes MARUHI_AGENT_SOCK to the child, the agent listens only while the child lives, and the exit code is inherited", async () => {
    const env = await makeTestEnv();
    let socketPath = "";
    let seenInside: string | null = null;
    env.setSessionHandler(async (call) => {
      socketPath = call.env[AGENT_SOCKET_ENV] ?? "";
      // Connect to the agent as the child would (in production the child's
      // maruhi chooses this path in live.ts)
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
    // Once the child exits, the socket and directory are gone and the memory
    // record is unreachable
    expect(await exists(socketPath)).toBe(false);
    expect(await exists(join(socketPath, ".."))).toBe(false);
    const after = await Effect.runPromiseExit(
      makeAgentKeychain(socketPath).get("token::https://maruhi.test"),
    );
    expect(Exit.isFailure(after)).toBe(true);
    // Guidance goes to stderr (doesn't dirty the child's stdout). No key
    // material is printed
    expect(env.errors.join("\n")).toContain("stay in memory only");
    expect(env.logs).toEqual([]);
    // The agent itself is handed to the child only via the env var (no parent
    // agent present)
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
    // The shape where the parent agent died first and only the shell remains —
    // "start a new one" and "refuse nesting" must not deadlock
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
    // A plain file (a destination someone swapped in)
    const file = join(dir, "not-a-socket");
    await writeFile(file, "");
    const asFile = await Effect.runPromiseExit(makeAgentKeychain(file).set("token::x", "v"));
    expect(JSON.stringify(asFile)).toContain("it is not a socket");
    // Even a real socket is refused if other users can touch it
    const server = await startAgentServer(dir);
    cleanups.push(() => server.close());
    await chmod(server.socketPath, 0o666);
    const loose = await Effect.runPromiseExit(makeAgentKeychain(server.socketPath).get("token::x"));
    expect(JSON.stringify(loose)).toContain("other users can access it");
    // Back to 0600 and it passes (the shape your own agent makes)
    await chmod(server.socketPath, 0o600);
    expect(
      await Effect.runPromise(makeAgentKeychain(server.socketPath).get("token::x")),
    ).toBeNull();
  });

  it("no run target after `--` is a usage error (2)", async () => {
    const env = await makeTestEnv();
    expect(await runCli(["agent"], env.layer)).toBe(2);
    expect(await runCli(["agent", "--", ""], env.layer)).toBe(2);
    // A positional argument before `--` is diagnosed the same as run
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
    // Path forward (K7-4): a vanished device key is re-registered as a new
    // device, and the forgotten key is revoked (not recovered)
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
      agent.set(masterKeyEntryName("https://maruhi.test", "user-0001"), "master-secret"),
    );
    const env = await makeTestEnv();
    env.setEnvVar(AGENT_SOCKET_ENV, server.socketPath);
    // An origin containing `::` (IPv6 loopback) must not break the delimiter
    await Effect.runPromise(
      agent.set(masterKeyEntryName("http://[::1]:8787", "user-0002"), "master-secret-2"),
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
        JSON.stringify({ token: "maruhi_pat_stored", userId: "user-0001", tokenId: "tok_1" }),
      ),
    );
    // The current shape is complete but the hex is broken = the corruption
    // side's guidance
    await Effect.runPromise(
      agent.set(
        masterKeyEntryName("https://maruhi.test", "user-0001"),
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
    // Since it cannot be made reversible: the ordering (re-enter without
    // exiting) and the condition (can only exit while the code exists)
    expect(message).toContain("re-run inside this session");
    expect(message).toContain(
      "only if you still have another device of yours or your recovery code",
    );
    expect(message).toContain("exit the session");
    expect(message).toContain("maruhi agent -- <shell>");
    // Does not print the OS-keychain procedure (which cannot be run here)
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

/* -------------------------------------------------------------------------- */
/* Restore-path wiring (supplement 12: fetch → decrypt → into L2 memory)       */
/* -------------------------------------------------------------------------- */

function storedMasterRecord(user: TestUser): StoredMasterKey {
  return {
    suite: "maruhi/v1",
    encPubHex: user.encPubHex,
    encSkHex: Redacted.make(user.encSkHex),
    sigPubHex: user.sigPubHex,
    sigSkSeedHex: Redacted.make(user.sigSkSeedHex),
  };
}

/** Builds a blob wrapped with a known secret and serves it at GET /auth/recovery (same shape as recovery.test.ts). */
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
    // DK: the reserve key B opened from the ledger is used only to issue the
    // device key and is not stored (§8.1). What gets stored is the new device
    // key — pin down that its destination is the agent's memory
    const user = await makeTestUser("user-agent-0001");
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { handler, code } = await wrappedBlobHandler(user, secret);
    const maruhi = await MockServer.start([
      handler,
      // The project list the restore tail scans (AUTH_SPEC §11-5) — empty
      onRequest("GET", "/projects", () => ({ status: 200, json: { projects: [] } })),
    ]);
    cleanups.push(() => maruhi.close());

    const dir = await privateDir();
    const server = await startAgentServer(dir);
    cleanups.push(() => server.close());
    const agent = makeAgentKeychain(server.socketPath);
    // Place the logged-in state on the agent side (in production `maruhi
    // login` writes via the same path)
    await Effect.runPromise(
      agent.set(
        tokenEntryName(maruhi.origin),
        JSON.stringify({ token: "maruhi_pat_stored", userId: user.userId, tokenId: "tok_1" }),
      ),
    );

    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    // Just the code (no projects, so no reserve-key confirmation appears — DK
    // K14-2's nowhere)
    env.setPromptResponses([code]);
    // Same swap live.ts does on MARUHI_AGENT_SOCK: only Keychain goes to the
    // agent implementation
    const layer = Layer.merge(env.layer, Layer.succeed(Keychain, agent));
    expect(await runCli(["key", "recover"], layer)).toBe(0);

    // The destination is the agent's memory. The test (OS-equivalent) keychain
    // has nothing
    expect(env.keychain.size).toBe(0);
    const stored = await Effect.runPromise(
      agent.get(masterKeyEntryName(maruhi.origin, user.userId)),
    );
    const device = parseStoredMasterKey(stored ?? "");
    if (device === null) throw new Error("expected the new device key in the agent");
    // What is stored is the new device key. The ledger's reserve key B is
    // stored nowhere
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

    // Later commands in the same session read the agent's key (key show)
    const status = onRequest("GET", "/auth/recovery/status", () => ({
      status: 200,
      json: { registered: true, updatedAtMs: 1754006400000 },
    }));
    const maruhi2 = await MockServer.start([status]);
    cleanups.push(() => maruhi2.close());
    await Effect.runPromise(
      agent.set(
        tokenEntryName(maruhi2.origin),
        JSON.stringify({ token: "maruhi_pat_stored", userId: user.userId, tokenId: "tok_1" }),
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
