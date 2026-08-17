// リカバリーコードの発行・保存確認・復元・再発行のテスト(CRYPTO_SPEC §8 /
// AUTH_SPEC §13 のクライアント面)。ラップ・復号は実 crypto を使い、サーバーは
// ワイヤレベルモック(support/server.ts)。

import { unwrapMasterSecret, wrapMasterSecret } from "@maruhi/crypto";
import { Redacted } from "effect";
import { afterEach, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  masterKeyEntryName,
  parseStoredMasterKey,
  serializeStoredMasterKey,
  type StoredMasterKey,
  tokenEntryName,
} from "../src/keychain.ts";
import { formatRecoveryCode, parseRecoveryCode } from "../src/recovery-code.ts";
import { makeTestUser, type TestUser } from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

let servers: MockServer[] = [];

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

async function start(handlers: readonly MockHandler[]): Promise<MockServer> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  return server;
}

async function loggedInEnv(origin: string, userId: string): Promise<TestEnv> {
  const env = await makeTestEnv();
  await seedConfig(env, { server: origin });
  env.keychain.set(
    tokenEntryName(origin),
    JSON.stringify({ token: "maruhi_pat_stored", userId, tokenId: "tok_1" }),
  );
  return env;
}

function statusHandler(registered: boolean): MockHandler {
  return onRequest("GET", "/auth/recovery/status", () => ({
    status: 200,
    json: { registered, updatedAtMs: registered ? 1754006400000 : null },
  }));
}

interface PutBody {
  readonly suite: string;
  readonly nonceHex: string;
  readonly ciphertextHex: string;
}

function putHandler(record: (body: PutBody) => void): MockHandler {
  return onRequest("PUT", "/auth/recovery", (request) => {
    record(request.body as PutBody);
    return { status: 204 };
  });
}

// コードは鍵素材なので stderr(プロンプトと同じチャネル)にのみ表示される
function displayedCode(env: TestEnv): string {
  const line = env.errors.find((entry) => /^ {4}[A-Z2-7]{4}(-[A-Z2-7]{4}){12}$/.test(entry));
  if (line === undefined) {
    throw new Error("recovery code line not found in stderr output");
  }
  return line.trim();
}

function lastGroupOf(env: TestEnv): () => string {
  return () => {
    const groups = displayedCode(env).split("-");
    return groups[groups.length - 1] ?? "";
  };
}

/** 解釈結果を剥がして生バイトで突合するためのヘルパ(null はそのまま返す)。 */
function unwrapParsed(parsed: Redacted.Redacted<Uint8Array> | null): Uint8Array | null {
  return parsed === null ? null : Redacted.value(parsed);
}

function storedMasterRecord(user: TestUser): StoredMasterKey {
  return {
    suite: "maruhi/v1",
    encPubHex: user.encPubHex,
    encSkHex: Redacted.make(user.encSkHex),
    sigPubHex: user.sigPubHex,
    sigSkSeedHex: Redacted.make(user.sigSkSeedHex),
  };
}

describe("recovery-code の表現(Base32)", () => {
  it("roundtrip: 32 バイト → 13 グループ → 復元(小文字・空白・ハイフン差を吸収)", () => {
    for (let round = 0; round < 8; round += 1) {
      const secret = crypto.getRandomValues(new Uint8Array(32));
      // 生値の突合は剥がして行う(包んだままの toEqual は中身を見ない)
      const code = Redacted.value(formatRecoveryCode(Redacted.make(secret)));
      expect(code).toMatch(/^[A-Z2-7]{4}(-[A-Z2-7]{4}){12}$/);
      expect(unwrapParsed(parseRecoveryCode(code))).toEqual(secret);
      expect(unwrapParsed(parseRecoveryCode(code.toLowerCase().replaceAll("-", " ")))).toEqual(
        secret,
      );
    }
  });

  it("アルファベット外の文字・長さ違い・非ゼロ詰めを拒否する", () => {
    const secret = new Uint8Array(32).fill(7);
    const code = Redacted.value(formatRecoveryCode(Redacted.make(secret)));
    // 0 / 1 は Base32 アルファベット外(O / I への推測置換をしない)
    expect(parseRecoveryCode(code.replace(/^./, "0"))).toBeNull();
    expect(parseRecoveryCode(code.replace(/^./, "1"))).toBeNull();
    expect(parseRecoveryCode(code.slice(0, -1))).toBeNull();
    expect(parseRecoveryCode(`${code}A`)).toBeNull();
    // 末尾シンボルの下位ビット(ゼロ詰め領域)の破壊は拒否される
    const symbols = code.replaceAll("-", "");
    const tampered = `${symbols.slice(0, -1)}H`; // H = 7 → 下位ビット非ゼロ
    expect(parseRecoveryCode(tampered)).toBeNull();
  });
});

/**
 * 表示されたコードで登録済みラップを開き、直列化した master 鍵レコードを返す。
 *
 * 直列化して返す理由: `JSON.stringify(record)` は秘密側が伏字になるため、
 * レコード同士をそのまま比較すると「どんな鍵でも一致する」空の突合になる。
 */
async function unwrapWithDisplayedCode(
  env: TestEnv,
  body: PutBody | null,
  userId: string,
): Promise<string> {
  const secret = parseRecoveryCode(displayedCode(env));
  if (secret === null) throw new Error("expected a parsed recovery secret");
  const unwrapped = await unwrapMasterSecret({
    recoverySecret: Redacted.value(secret),
    userId,
    wrapped: {
      nonce: Uint8Array.from(Buffer.from(body?.nonceHex ?? "", "hex")),
      ciphertext: Uint8Array.from(Buffer.from(body?.ciphertextHex ?? "", "hex")),
    },
  });
  if (!unwrapped.ok) throw new Error("expected the recovery blob to unwrap");
  const record = parseStoredMasterKey(new TextDecoder().decode(unwrapped.value));
  if (record === null) throw new Error("expected a parsed master-key record");
  return serializeStoredMasterKey(record);
}

describe("maruhi key generate のリカバリー発行", () => {
  it("発行 → 登録 → 表示コードで実際に復号できる(roundtrip)+ 保存確認", async () => {
    let put: PutBody | null = null;
    const maruhi = await start([
      statusHandler(false),
      putHandler((body) => {
        put = body;
      }),
    ]);
    const env = await loggedInEnv(maruhi.origin, "user-0001");
    env.setPromptResponses([lastGroupOf(env)]);
    expect(await runCli(["key", "generate"], env.layer)).toBe(0);

    const body = put as PutBody | null;
    expect(body?.suite).toBe("maruhi/v1");
    expect(body?.nonceHex).toMatch(/^[0-9a-f]{24}$/);
    // 登録されたラップは、表示されたコードで復号でき、キーチェーンの
    // レコードと一致する(コードを失う前に壊れたラップを検出できる形)
    const blob = await unwrapWithDisplayedCode(env, body, "user-0001");
    expect(blob).toBe(env.keychain.get(masterKeyEntryName(maruhi.origin, "user-0001")));
    expect(env.errors.join("\n")).toContain("保存確認が完了しました");
    // 鍵素材(コード)はリダイレクトされうる stdout に出ない(レビュー①)
    expect(env.logs.join("\n")).not.toContain(displayedCode(env));
  });

  it("保存確認に 3 回失敗すると失敗するが、登録は残る旨を案内する", async () => {
    const maruhi = await start([statusHandler(false), putHandler(() => {})]);
    const env = await loggedInEnv(maruhi.origin, "user-0001");
    env.setPromptResponses(["XXXX", "YYYY", "ZZZZ"]);
    expect(await runCli(["key", "generate"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("保存確認に失敗しました");
    expect(errors).toContain("`maruhi key recovery`");
    // 鍵生成自体は成立している
    expect(env.keychain.get(masterKeyEntryName(maruhi.origin, "user-0001"))).toBeDefined();
  });

  it("AI エージェント環境では発行をスキップし、人間の端末を案内する", async () => {
    let putSeen = false;
    const maruhi = await start([
      statusHandler(false),
      putHandler(() => {
        putSeen = true;
      }),
    ]);
    const env = await loggedInEnv(maruhi.origin, "user-0001");
    env.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["key", "generate"], env.layer)).toBe(0);
    expect(putSeen).toBe(false);
    expect(env.logs.join("\n")).toContain("リカバリーコードの発行をスキップしました");
    expect(env.keychain.get(masterKeyEntryName(maruhi.origin, "user-0001"))).toBeDefined();
  });

  it("登録に失敗しても鍵生成は成立し、再発行コマンドを案内する", async () => {
    const maruhi = await start([
      statusHandler(false),
      onRequest("PUT", "/auth/recovery", () => ({ status: 500, bodyText: "boom" })),
    ]);
    const env = await loggedInEnv(maruhi.origin, "user-0001");
    expect(await runCli(["key", "generate"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("`maruhi key recovery` で改めて発行できます");
    expect(env.keychain.get(masterKeyEntryName(maruhi.origin, "user-0001"))).toBeDefined();
  });
});

describe("maruhi key recovery(発行・再発行)", () => {
  it("既登録なら置換であることを明示して再発行する", async () => {
    const user = await makeTestUser("user-0001");
    let put: PutBody | null = null;
    const maruhi = await start([
      statusHandler(true),
      putHandler((body) => {
        put = body;
      }),
    ]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    seedSession(env, maruhi.origin, user);
    env.setPromptResponses([lastGroupOf(env)]);
    expect(await runCli(["key", "recovery"], env.layer)).toBe(0);
    expect(put).not.toBeNull();
    expect(env.errors.join("\n")).toContain("これまでのリカバリーコードは無効になります");
  });

  it("AI エージェント環境では発行を拒否する", async () => {
    const user = await makeTestUser("user-0001");
    const maruhi = await start([statusHandler(false), putHandler(() => {})]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    seedSession(env, maruhi.origin, user);
    env.setAgent({ isAgent: true });
    expect(await runCli(["key", "recovery"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("AI エージェント環境");
  });
});

describe("maruhi key recover(復元)", () => {
  /** 既知の secret でラップ済みブロブを作り、GET /auth/recovery で配る。 */
  async function wrappedBlobHandler(
    user: TestUser,
    secret: Uint8Array,
  ): Promise<{ handler: MockHandler; code: string }> {
    const record = storedMasterRecord(user);
    const wrapped = await wrapMasterSecret({
      recoverySecret: secret,
      userId: user.userId,
      // JSON.stringify(record) は使えない — 秘密側が伏字でラップされ、
      // 「復号は成功するのに鍵が読めない」ブロブになる(本番の recovery.ts と同じ罠)
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

  it("正しいコードで master 鍵を復元し、FP を表示する", async () => {
    const user = await makeTestUser("user-0001");
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { handler, code } = await wrappedBlobHandler(user, secret);
    const maruhi = await start([handler]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    env.setPromptResponses([code.toLowerCase()]);
    expect(await runCli(["key", "recover"], env.layer)).toBe(0);
    const stored = env.keychain.get(masterKeyEntryName(maruhi.origin, user.userId));
    const restored = parseStoredMasterKey(stored ?? "");
    if (restored === null) throw new Error("expected a restored master-key record");
    // 秘密側は剥がして突合する(包んだままの toEqual は中身を見ない)
    expect(serializeStoredMasterKey(restored)).toBe(
      serializeStoredMasterKey(storedMasterRecord(user)),
    );
    const output = env.logs.join("\n");
    expect(output).toContain("master 鍵を復元し");
    expect(output).toContain(`key fingerprint: ${user.fingerprintHex}`);
    // 秘密鍵素材・コードを表示しない
    expect(output).not.toContain(user.encSkHex);
    expect(output).not.toContain(code);
  });

  it("未知スイートのブロブは行き止まりにせず、更新と再登録を案内する", async () => {
    // 別デバイスのより新しい maruhi が登録したブロブ。復号はできるが鍵素材は
    // 読めない — 「壊れています」ではないので、出口(更新する / 鍵の残る
    // デバイスで再登録する)を示す
    const user = await makeTestUser("user-0001");
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const future = { ...storedMasterRecord(user), suite: "maruhi/v2" };
    const wrapped = await wrapMasterSecret({
      recoverySecret: secret,
      userId: user.userId,
      masterSecretBlob: new TextEncoder().encode(serializeStoredMasterKey(future)),
    });
    if (!wrapped.ok) throw new Error("test wrap failed");
    const maruhi = await start([
      onRequest("GET", "/auth/recovery", () => ({
        status: 200,
        json: {
          suite: "maruhi/v1",
          nonceHex: Buffer.from(wrapped.value.nonce).toString("hex"),
          ciphertextHex: Buffer.from(wrapped.value.ciphertext).toString("hex"),
          updatedAtMs: 1754006400000,
        },
      })),
    ]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    env.setPromptResponses([Redacted.value(formatRecoveryCode(Redacted.make(secret)))]);
    expect(await runCli(["key", "recover"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("maruhi/v2");
    expect(errors).toContain("最新版へ更新");
    expect(errors).toContain("`maruhi key recovery`");
    // キーチェーンには何も書かない
    expect(env.keychain.get(masterKeyEntryName(maruhi.origin, user.userId))).toBeUndefined();
  });

  it("誤ったコードはローカルで再試行し、3 回で失敗する(取得は 1 回)", async () => {
    const user = await makeTestUser("user-0001");
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { handler } = await wrappedBlobHandler(user, secret);
    let fetches = 0;
    const counting: MockHandler = (request) => {
      if (request.method === "GET" && request.path === "/auth/recovery") {
        fetches += 1;
      }
      return null;
    };
    const maruhi = await start([counting, handler]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    const wrong = Redacted.value(formatRecoveryCode(Redacted.make(new Uint8Array(32).fill(1))));
    env.setPromptResponses([wrong, wrong, wrong]);
    expect(await runCli(["key", "recover"], env.layer)).toBe(1);
    expect(fetches).toBe(1);
    expect(env.errors.join("\n")).toContain("連続で失敗しました");
    expect(env.keychain.get(masterKeyEntryName(maruhi.origin, user.userId))).toBeUndefined();
  });

  it("AI エージェント環境ではコード入力を拒否する(発行側と対称の線引き)", async () => {
    const user = await makeTestUser("user-0001");
    let fetched = false;
    const maruhi = await start([
      onRequest("GET", "/auth/recovery", () => {
        fetched = true;
        return { status: 404, json: { _tag: "RecoveryWrapNotFound" } };
      }),
    ]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    env.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["key", "recover"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("リカバリーコードの入力を拒否しました");
    // ブロブ取得(要監視イベント)にも到達しない
    expect(fetched).toBe(false);
  });

  it("既に master 鍵があるデバイスでは上書きを拒否する", async () => {
    const user = await makeTestUser("user-0001");
    const maruhi = await start([]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    seedSession(env, maruhi.origin, user);
    expect(await runCli(["key", "recover"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("既にこのデバイスにあります");
  });

  it("未登録(404)は登録手順を案内する", async () => {
    const user = await makeTestUser("user-0001");
    const maruhi = await start([
      onRequest("GET", "/auth/recovery", () => ({
        status: 404,
        json: { _tag: "RecoveryWrapNotFound" },
      })),
    ]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    expect(await runCli(["key", "recover"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("リカバリーが未登録です");
  });

  it("レート制限(429)は再試行までの秒数を伝える", async () => {
    const user = await makeTestUser("user-0001");
    const maruhi = await start([
      onRequest("GET", "/auth/recovery", () => ({
        status: 429,
        json: { _tag: "RecoveryRateLimited", retryAfterSeconds: 1800 },
      })),
    ]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    expect(await runCli(["key", "recover"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("1800 秒後");
  });
});
