// `maruhi agent`(KL2 — セッション内メモリ鍵保持)のテスト。
//
// - プロトコル(改行区切り JSON)の解釈と拒否(版違い・壊れた要求)
// - サーバーとクライアント(Keychain 実装)を実 unix ソケットで往復する
//   (node:net — vitest の Node でも本番の Bun でも同じ経路)
// - 権限: ディレクトリ 0700・ソケット 0600。終了後にソケットが消える
// - `maruhi agent -- <cmd>`: 子に MARUHI_AGENT_SOCK が渡り、その間だけ agent が
//   聞いている。子の終了コードを引き継ぐ。入れ子は拒否。`--` 無しは usage
// - 復元経路の配線: `key recover` の着地先が agent のメモリになり、成功文言が
//   保存先を正しく言う(recovery.test.ts の復元ケースを agent 側で再現)
// - `maruhi run` の子には MARUHI_AGENT_SOCK が渡らない(既存規則の帰結)

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

// unix ドメインソケットは Windows では別物(名前付きパイプ)。本体も win32 を
// 明示エラーにしているので、ソケット経路のテストはそこでは走らせない
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

describe("agent プロトコル(改行区切り JSON)", () => {
  it("要求の解釈: get / set / remove を版と形で受け付け、それ以外は null", () => {
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
    // 版違いは黙って解釈しない
    expect(parseAgentRequest('{"v":2,"op":"get","name":"a"}')).toBeNull();
    expect(parseAgentRequest('{"op":"get","name":"a"}')).toBeNull();
    // set に value が無い / 名前が空 / 未知の op / JSON でない / 配列
    expect(parseAgentRequest('{"v":1,"op":"set","name":"a"}')).toBeNull();
    expect(parseAgentRequest('{"v":1,"op":"get","name":""}')).toBeNull();
    expect(parseAgentRequest('{"v":1,"op":"list","name":"a"}')).toBeNull();
    expect(parseAgentRequest("not json")).toBeNull();
    expect(parseAgentRequest("[1]")).toBeNull();
  });

  it("応答の解釈: ok/value と ok:false/error だけを受け付ける", () => {
    expect(parseAgentResponse('{"ok":true,"value":"x"}')).toEqual({ ok: true, value: "x" });
    expect(parseAgentResponse('{"ok":true,"value":null}')).toEqual({ ok: true, value: null });
    expect(parseAgentResponse('{"ok":false,"error":"nope"}')).toEqual({
      ok: false,
      error: "nope",
    });
    expect(parseAgentResponse('{"ok":true}')).toBeNull();
    expect(parseAgentResponse('{"ok":false}')).toBeNull();
    expect(parseAgentResponse("{")).toBeNull();
  });

  it("ワイヤ形は 1 行 1 メッセージ(末尾に改行)", () => {
    expect(encodeAgentRequest({ v: 1, op: "get", name: "a" })).toBe(
      '{"v":1,"op":"get","name":"a"}\n',
    );
  });

  it("保持の意味論: 無ければ null、set の後は読め、remove の後は消える", () => {
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
});

describeSocket("agent サーバーとクライアント(実 unix ソケット)", () => {
  it("Keychain 実装として get / set / remove が往復し、ソケットは 0600", async () => {
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
    // 別のエントリは独立
    expect(await Effect.runPromise(keychain.get("master::x::u"))).toBeNull();
    await Effect.runPromise(keychain.remove("token::x"));
    expect(await Effect.runPromise(keychain.get("token::x"))).toBeNull();
  });

  it("壊れた要求・版違いは ok:false で拒み、接続は閉じる(黙って解釈しない)", async () => {
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
    // 分割到着でも 1 行が揃えば応答する
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

  it("close で保持内容を捨て、ソケットは聞かなくなる(クライアントは終了を名指しする)", async () => {
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

  it("ソケットの無いパスは同じ終了メッセージ(古い MARUHI_AGENT_SOCK)", async () => {
    const dir = await privateDir();
    const keychain = makeAgentKeychain(join(dir, "gone.sock"));
    const exit = await Effect.runPromiseExit(keychain.get("token::x"));
    expect(JSON.stringify(exit)).toContain("The agent session has ended");
  });
});

describeSocket("maruhi agent -- <command>", () => {
  it("子に MARUHI_AGENT_SOCK を渡し、子が生きている間だけ agent が聞き、終了コードを引き継ぐ", async () => {
    const env = await makeTestEnv();
    let socketPath = "";
    let seenInside: string | null = null;
    env.setSessionHandler(async (call) => {
      socketPath = call.env[AGENT_SOCKET_ENV] ?? "";
      // 子の立場で agent へ接続する(本番では子の maruhi が live.ts でこの経路を選ぶ)
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
    // 子が終わればソケットもディレクトリも消え、メモリの記録は届かない
    expect(await exists(socketPath)).toBe(false);
    expect(await exists(join(socketPath, ".."))).toBe(false);
    const after = await Effect.runPromiseExit(
      makeAgentKeychain(socketPath).get("token::https://maruhi.test"),
    );
    expect(Exit.isFailure(after)).toBe(true);
    // 案内は stderr(子の stdout を汚さない)。鍵素材は出ない
    expect(env.errors.join("\n")).toContain("stay in memory only");
    expect(env.logs).toEqual([]);
    // agent 自身は環境変数を通してのみ子へ渡す(親の agent は不在)
    expect(env.sessionCalls[0]?.env).toEqual({ [AGENT_SOCKET_ENV]: socketPath });
  });

  it("XDG_RUNTIME_DIR があればその下に置く", async () => {
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

  it("入れ子(既に MARUHI_AGENT_SOCK がある)は拒否し、子を起動しない", async () => {
    const env = await makeTestEnv();
    env.setEnvVar(AGENT_SOCKET_ENV, "/run/user/1000/maruhi-agent-x/agent.sock");
    expect(await runCli(["agent", "--", "sh"], env.layer)).toBe(1);
    expect(env.sessionCalls).toEqual([]);
    expect(env.errors.join("\n")).toContain("Already inside an agent session");
  });

  it("`--` の後ろに実行対象が無い形は書き方の誤り(2)", async () => {
    const env = await makeTestEnv();
    expect(await runCli(["agent"], env.layer)).toBe(2);
    expect(await runCli(["agent", "--", ""], env.layer)).toBe(2);
    // `--` の前に位置引数を置いた形も run と同じ診断
    expect(await runCli(["agent", "sh", "--", "bash"], env.layer)).toBe(2);
    expect(env.sessionCalls).toEqual([]);
    expect(env.errors.join("\n")).toContain("after `--`");
  });

  it("`maruhi run` の子には MARUHI_AGENT_SOCK が渡らない(MARUHI_* を渡さない既存規則)", () => {
    expect(
      buildChildEnvironment({ PATH: "/usr/bin", [AGENT_SOCKET_ENV]: "/run/x/agent.sock" }, {}),
    ).toEqual({ PATH: "/usr/bin" });
  });
});

/* -------------------------------------------------------------------------- */
/* 復元経路の配線(補足 12: 取得 → 復号 → L2 のメモリへ)                         */
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

/** 既知の secret でラップ済みブロブを作り、GET /auth/recovery で配る(recovery.test.ts と同形)。 */
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

describeSocket("key recover は agent セッションの中でメモリへ着地する", () => {
  it("復元した master 鍵は agent にだけ入り、テスト用キーチェーンには何も残らない", async () => {
    const user = await makeTestUser("user-agent-0001");
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { handler, code } = await wrappedBlobHandler(user, secret);
    const maruhi = await MockServer.start([handler]);
    cleanups.push(() => maruhi.close());

    const dir = await privateDir();
    const server = await startAgentServer(dir);
    cleanups.push(() => server.close());
    const agent = makeAgentKeychain(server.socketPath);
    // ログイン済み状態を agent 側に置く(本番では `maruhi login` が同じ経路で書く)
    await Effect.runPromise(
      agent.set(
        tokenEntryName(maruhi.origin),
        JSON.stringify({ token: "maruhi_pat_stored", userId: user.userId, tokenId: "tok_1" }),
      ),
    );

    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.setPromptResponses([code]);
    // live.ts が MARUHI_AGENT_SOCK で行う差し替えと同じ: Keychain だけ agent 実装へ
    const layer = Layer.merge(env.layer, Layer.succeed(Keychain, agent));
    expect(await runCli(["key", "recover"], layer)).toBe(0);

    // 着地先は agent のメモリ。テスト用(OS 相当)キーチェーンには何も無い
    expect(env.keychain.size).toBe(0);
    const stored = await Effect.runPromise(
      agent.get(masterKeyEntryName(maruhi.origin, user.userId)),
    );
    const restored = parseStoredMasterKey(stored ?? "");
    if (restored === null) throw new Error("expected the restored master key in the agent");
    expect(serializeStoredMasterKey(restored)).toBe(
      serializeStoredMasterKey(storedMasterRecord(user)),
    );
    const output = env.logs.join("\n");
    expect(output).toContain(
      "Restored the master key and stored it in the maruhi agent's memory (this session only)",
    );
    expect(output).toContain(`key fingerprint: ${user.fingerprintHex}`);
    expect(output).not.toContain(user.encSkHex);
    expect(output).not.toContain(code);

    // 同じセッションの後続コマンドは agent の鍵を読む(key show)
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
    expect(env.logs.join("\n")).toContain(`key fingerprint: ${user.fingerprintHex}`);
  });
});
