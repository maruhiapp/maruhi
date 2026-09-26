// リカバリーコードの発行・保存確認・復元・再発行のテスト(CRYPTO_SPEC §8 /
// AUTH_SPEC §13 のクライアント面 — 2026-09-19 DK: 台帳に封印されるのは端末鍵ではなく
// **予備鍵**)。ラップ・復号は実 crypto を使い、サーバーはワイヤレベルモック
// (support/server.ts)。

import { unwrapMasterSecret, wrapMasterSecret } from "@maruhi/crypto";
import { Effect, Redacted } from "effect";
import { afterEach, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  masterKeyEntryName,
  parseStoredMasterKey,
  serializeStoredMasterKey,
  type StoredMasterKey,
  tokenEntryName,
} from "../src/keychain.ts";
import {
  makeFileOwnDeviceStore,
  type OwnDeviceEntry,
  ownDevicesPathOf,
} from "../src/own-devices.ts";
import { formatRecoveryCode, parseRecoveryCode } from "../src/recovery-code.ts";
import { makeTestUser, type TestUser } from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { ledgerHandlerFor, storedMasterRecord, storedReserveRecord } from "./support/ledger.ts";
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

/** `GET /projects`(AUTH_SPEC §11-5): 復元の後段が走査するプロジェクト一覧(空)。 */
function noProjectsHandler(): MockHandler {
  return onRequest("GET", "/projects", () => ({ status: 200, json: { projects: [] } }));
}

/** own-devices.json に記録された(失効していない)予備鍵の行(公開側のみ)。 */
async function recordedReservesOf(
  env: TestEnv,
  origin: string,
  userId: string,
): Promise<readonly OwnDeviceEntry[]> {
  const loaded = await Effect.runPromise(
    makeFileOwnDeviceStore(ownDevicesPathOf(env.configPath)).load(origin, userId),
  );
  if (loaded.state !== "loaded") {
    return [];
  }
  return loaded.devices.filter(
    (device) => device.source === "reserve" && device.revokedAtMs === null,
  );
}

/** キーチェーンの端末鍵レコード(無ければ失敗)。 */
function storedDeviceRecord(env: TestEnv, origin: string, userId: string): StoredMasterKey {
  const record = parseStoredMasterKey(env.keychain.get(masterKeyEntryName(origin, userId)) ?? "");
  if (record === null) throw new Error("expected a device-key record in the keychain");
  return record;
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
 * 表示されたコードで登録済みラップを開き、中の鍵レコード(予備鍵)を返す。
 *
 * 突合は `serializeStoredMasterKey` で行うこと: `JSON.stringify(record)` は秘密側が
 * 伏字になるため、レコード同士をそのまま比較すると「どんな鍵でも一致する」空の
 * 突合になる。
 */
async function unwrapWithDisplayedCode(
  env: TestEnv,
  body: PutBody | null,
  userId: string,
): Promise<StoredMasterKey> {
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
  return record;
}

describe("予備鍵の印(CRYPTO_SPEC §8 — DK K16)", () => {
  const base = {
    suite: "maruhi/v1",
    encPubHex: "aa".repeat(32),
    encSkHex: "bb".repeat(32),
    sigPubHex: "cc".repeat(32),
    sigSkSeedHex: "dd".repeat(32),
  };

  it("印は読み取りと書き込みで運ばれ、無い記録には付かない", () => {
    const marked = parseStoredMasterKey(JSON.stringify({ ...base, kind: "reserve" }));
    expect(marked?.kind).toBe("reserve");
    expect(JSON.parse(serializeStoredMasterKey(marked ?? ({} as StoredMasterKey)))).toMatchObject({
      kind: "reserve",
    });
    const plain = parseStoredMasterKey(JSON.stringify(base));
    expect(plain?.kind).toBeUndefined();
    expect(
      JSON.parse(serializeStoredMasterKey(plain ?? ({} as StoredMasterKey))),
    ).not.toHaveProperty("kind");
  });

  it("知らない印の値は壊れたレコードとして読まない", () => {
    expect(parseStoredMasterKey(JSON.stringify({ ...base, kind: "device" }))).toBeNull();
  });

  it("キーチェーンに印のある鍵があれば、端末鍵として使わずに止まる", async () => {
    const user = await makeTestUser("user-0001");
    const env = await loggedInEnv("https://maruhi.test", user.userId);
    env.keychain.set(
      masterKeyEntryName("https://maruhi.test", user.userId),
      serializeStoredMasterKey(storedReserveRecord(user)),
    );
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      `is marked as a reserve key, which lives only in the recovery ledger and is never used as a device key. Remove that entry, then add this machine as a device (\`maruhi device add\`) or run \`maruhi key recover\``,
    );
  });
});

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
    expect(env.logs.join("\n")).toContain(
      "Generated this device's key and stored it in the OS keychain",
    );

    const body = put as PutBody | null;
    expect(body?.suite).toBe("maruhi/v1");
    expect(body?.nonceHex).toMatch(/^[0-9a-f]{24}$/);
    // 登録されたラップは、表示されたコードで復号でき、整形式の鍵レコード
    // (= 予備鍵)が入っている(コードを失う前に壊れたラップを検出できる形)
    const reserve = await unwrapWithDisplayedCode(env, body, "user-0001");
    expect(reserve.suite).toBe("maruhi/v1");
    expect(reserve.encPubHex).toMatch(/^[0-9a-f]{64}$/);
    // 生成した予備鍵は印を持ち(CRYPTO_SPEC §8 — DK K16)、キーチェーンの端末鍵は持たない
    expect(reserve.kind).toBe("reserve");
    // DK: 台帳の中身は端末鍵ではなく**別の**予備鍵(端末鍵の複製を封印しない)
    const device = storedDeviceRecord(env, maruhi.origin, "user-0001");
    expect(device.kind).toBeUndefined();
    expect(reserve.encPubHex).not.toBe(device.encPubHex);
    expect(serializeStoredMasterKey(reserve)).not.toBe(serializeStoredMasterKey(device));
    // 予備鍵の公開側は own-devices.json に出所 "reserve" で記録される(K4-3)
    const reserves = await recordedReservesOf(env, maruhi.origin, "user-0001");
    expect(reserves).toHaveLength(1);
    expect(reserves[0]?.encPubHex).toBe(reserve.encPubHex);
    expect(reserves[0]?.sigPubHex).toBe(reserve.sigPubHex);
    expect(env.errors.join("\n")).toContain(
      `created your reserve key (fingerprint ${reserves[0]?.keyFingerprintHex})`,
    );
    expect(env.errors.join("\n")).toContain("Save confirmation complete");
    // 鍵素材(コード)はリダイレクトされうる stdout に出ない
    expect(env.logs.join("\n")).not.toContain(displayedCode(env));
    // 予備鍵の秘密はキーチェーンへ書かれない
    expect([...env.keychain.values()].join("\n")).not.toContain(Redacted.value(reserve.encSkHex));
  });

  it("台帳の状態が取れなければ fail-closed で生成しない(--new-identity は例外)", async () => {
    // 最初は status に答えない(404)= サーバーが台帳の状態を答えない
    let statusAnswers = false;
    const status: MockHandler = (request) =>
      statusAnswers ? null : request.path === "/auth/recovery/status" ? { status: 404 } : null;
    const maruhi = await start([status, statusHandler(true), putHandler(() => {})]);
    const env = await loggedInEnv(maruhi.origin, "user-0001");
    expect(await runCli(["key", "generate"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Cannot check whether your account already has a recovery ledger",
    );
    expect(env.keychain.get(masterKeyEntryName(maruhi.origin, "user-0001"))).toBeUndefined();
    // 名指しの明示があれば台帳の有無を問わず生成する(台帳「あり」でも拒否しない。
    // 後段の封印が読む status には答えさせる = 置換として発行される)
    statusAnswers = true;
    env.setPromptResponses([lastGroupOf(env)]);
    expect(await runCli(["key", "generate", "--new-identity"], env.layer)).toBe(0);
    expect(env.keychain.get(masterKeyEntryName(maruhi.origin, "user-0001"))).toBeDefined();
    expect(env.errors.join("\n")).toContain("Replacing the existing recovery registration");
  });

  it("台帳が既にあるアカウントでは 2 台目として `maruhi device add` へ案内する", async () => {
    let putSeen = false;
    const maruhi = await start([
      statusHandler(true),
      putHandler(() => {
        putSeen = true;
      }),
    ]);
    const env = await loggedInEnv(maruhi.origin, "user-0001");
    expect(await runCli(["key", "generate"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("`maruhi device add`");
    expect(putSeen).toBe(false);
    expect(env.keychain.get(masterKeyEntryName(maruhi.origin, "user-0001"))).toBeUndefined();
  });

  it("保存確認に 3 回失敗すると失敗するが、登録は残る旨を案内する", async () => {
    const maruhi = await start([statusHandler(false), putHandler(() => {})]);
    const env = await loggedInEnv(maruhi.origin, "user-0001");
    env.setPromptResponses(["XXXX", "YYYY", "ZZZZ"]);
    expect(await runCli(["key", "generate"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Save confirmation failed");
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
    expect(env.logs.join("\n")).toContain(
      "Skipped creating the reserve key and its recovery code because this is an AI agent environment",
    );
    expect(env.keychain.get(masterKeyEntryName(maruhi.origin, "user-0001"))).toBeDefined();
    // 予備鍵は作られていない(記録も無い)
    expect(await recordedReservesOf(env, maruhi.origin, "user-0001")).toHaveLength(0);
  });

  it("登録に失敗しても鍵生成は成立し、再発行コマンドを案内する", async () => {
    const maruhi = await start([
      statusHandler(false),
      onRequest("PUT", "/auth/recovery", () => ({ status: 500, bodyText: "boom" })),
    ]);
    const env = await loggedInEnv(maruhi.origin, "user-0001");
    expect(await runCli(["key", "generate"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "the device key generation itself is complete; create the reserve key later with `maruhi key recovery`",
    );
    expect(env.keychain.get(masterKeyEntryName(maruhi.origin, "user-0001"))).toBeDefined();
    // 封印に失敗した予備鍵は記録しない(封印 → 記録の順序 — K4-1)
    expect(await recordedReservesOf(env, maruhi.origin, "user-0001")).toHaveLength(0);
  });
});

describe("maruhi key recovery(発行・再発行)", () => {
  it("未登録なら予備鍵を生成して初回封印する", async () => {
    const user = await makeTestUser("user-0001");
    let put: PutBody | null = null;
    const maruhi = await start([
      statusHandler(false),
      putHandler((body) => {
        put = body;
      }),
    ]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    seedSession(env, maruhi.origin, user);
    env.setPromptResponses([lastGroupOf(env)]);
    expect(await runCli(["key", "recovery"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("No reserve key is sealed yet — creating one");
    const reserve = await unwrapWithDisplayedCode(env, put as PutBody | null, user.userId);
    expect(reserve.encPubHex).not.toBe(user.encPubHex);
    const reserves = await recordedReservesOf(env, maruhi.origin, user.userId);
    expect(reserves.map((entry) => entry.encPubHex)).toEqual([reserve.encPubHex]);
    // 端末鍵はそのまま
    expect(storedDeviceRecord(env, maruhi.origin, user.userId).encPubHex).toBe(user.encPubHex);
  });

  it("既登録(予備鍵)なら台帳を開いてから置換であることを明示して再発行する", async () => {
    const user = await makeTestUser("user-0001");
    // 台帳の中身は端末鍵とは別の鍵 = 予備鍵(再発行の経路)
    const reserveUser = await makeTestUser("user-0001-reserve");
    const { handler, code } = await ledgerHandlerFor(
      storedReserveRecord(reserveUser),
      user.userId,
      crypto.getRandomValues(new Uint8Array(32)),
    );
    let put: PutBody | null = null;
    const maruhi = await start([
      statusHandler(true),
      handler,
      putHandler((body) => {
        put = body;
      }),
      // 台帳の鍵のチェーン上の判定(DK K14-4)が走査するプロジェクト一覧(空 = どこにも無い)
      noProjectsHandler(),
    ]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    seedSession(env, maruhi.origin, user);
    env.setPromptResponses([code, lastGroupOf(env)]);
    expect(await runCli(["key", "recovery"], env.layer)).toBe(0);
    expect(env.prompts[0]).toBe("Enter your recovery code: ");
    expect(put).not.toBeNull();
    const errors = env.errors.join("\n");
    expect(errors).toContain("previous recovery codes become invalid");
    expect(errors).toContain(
      `reissued the recovery code for your reserve key (fingerprint ${reserveUser.fingerprintHex}); the previous code no longer works`,
    );
    // 新しいコードで開くと**同じ**予備鍵が入っている(鍵は変えずコードだけ更新)
    const reserve = await unwrapWithDisplayedCode(env, put as PutBody | null, user.userId);
    expect(serializeStoredMasterKey(reserve)).toBe(
      serializeStoredMasterKey(storedReserveRecord(reserveUser)),
    );
    // 記録の復元(K4-2 の反例 2)
    const reserves = await recordedReservesOf(env, maruhi.origin, user.userId);
    expect(reserves.map((entry) => entry.keyFingerprintHex)).toEqual([reserveUser.fingerprintHex]);
    // 端末鍵はそのまま。予備鍵の秘密はキーチェーンへ書かれない
    expect(storedDeviceRecord(env, maruhi.origin, user.userId).encPubHex).toBe(user.encPubHex);
    expect([...env.keychain.values()].join("\n")).not.toContain(reserveUser.encSkHex);
  });

  it("台帳が端末鍵の複製(pre-DK)なら予備鍵を生成して分離する", async () => {
    const user = await makeTestUser("user-0001");
    const { handler, code } = await ledgerHandlerFor(
      storedMasterRecord(user),
      user.userId,
      crypto.getRandomValues(new Uint8Array(32)),
    );
    let put: PutBody | null = null;
    const maruhi = await start([
      statusHandler(true),
      handler,
      putHandler((body) => {
        put = body;
      }),
    ]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    seedSession(env, maruhi.origin, user);
    env.setPromptResponses([code, lastGroupOf(env)]);
    expect(await runCli(["key", "recovery"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain(
      `The recovery ledger holds a copy of this device's key (${user.fingerprintHex}) — an install from before device keys. Separating: creating a reserve key and sealing it instead`,
    );
    expect(env.errors.join("\n")).toContain("`maruhi device add --replace`");
    // 台帳には端末鍵ではない新しい予備鍵が入り、記録される
    const reserve = await unwrapWithDisplayedCode(env, put as PutBody | null, user.userId);
    expect(reserve.encPubHex).not.toBe(user.encPubHex);
    const reserves = await recordedReservesOf(env, maruhi.origin, user.userId);
    expect(reserves.map((entry) => entry.encPubHex)).toEqual([reserve.encPubHex]);
    expect(reserves[0]?.keyFingerprintHex).not.toBe(user.fingerprintHex);
    // 端末鍵はそのまま
    expect(storedDeviceRecord(env, maruhi.origin, user.userId).encPubHex).toBe(user.encPubHex);
  });

  it("--replace は台帳を開かずに置換する(コード紛失の逃げ道)", async () => {
    const user = await makeTestUser("user-0001");
    let fetched = false;
    let put: PutBody | null = null;
    const maruhi = await start([
      statusHandler(true),
      onRequest("GET", "/auth/recovery", () => {
        fetched = true;
        return { status: 404, json: { _tag: "RecoveryWrapNotFound" } };
      }),
      putHandler((body) => {
        put = body;
      }),
      noProjectsHandler(),
      onRequest("GET", "/auth/key-wraps", () => ({
        status: 200,
        json: {
          recoveryCode: { registered: true, updatedAtMs: 1754006400000 },
          passkeys: [],
          guardianGroups: [],
        },
      })),
    ]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    seedSession(env, maruhi.origin, user);
    env.setPromptResponses([lastGroupOf(env)]);
    expect(await runCli(["key", "recovery", "--replace"], env.layer)).toBe(0);
    expect(fetched).toBe(false);
    expect(put).not.toBeNull();
    const errors = env.errors.join("\n");
    expect(errors).toContain("replacing the recovery ledger without opening it");
    // 記録に旧予備鍵が無ければ失効できない旨を警告する(失効は記録に依る — K4-38)
    expect(errors).toContain(
      "no previous reserve key is recorded on this machine, so none was revoked",
    );
    // 台帳に行(パスキー / 保護者)が無ければ、無い行の削除も成立しない --passkey の案内も出さない
    expect(errors).not.toContain("seal the current reserve key are deleted");
    expect(errors).not.toContain("run `maruhi key recovery --passkey` instead");
    expect(await recordedReservesOf(env, maruhi.origin, user.userId)).toHaveLength(1);
    // --passkey は --replace と両立しない(台帳を開かないので)— 何も書かずに使い方エラー
    const before = env.errors.length;
    expect(await runCli(["key", "recovery", "--passkey", "--replace"], env.layer)).toBe(2);
    expect(env.errors.slice(before).join("\n")).toContain(
      "--passkey cannot be combined with --replace",
    );
  });

  it("--replace はパスキーの行があれば件数と --passkey の代替を書き込みの前に示し、その行を消す", async () => {
    const user = await makeTestUser("user-0001");
    const wrapId = "01JMKWRAP000000000000PASSK";
    const deleted: string[] = [];
    let put: PutBody | null = null;
    const maruhi = await start([
      statusHandler(true),
      putHandler((body) => {
        put = body;
      }),
      noProjectsHandler(),
      onRequest("GET", "/auth/key-wraps", () => ({
        status: 200,
        json: {
          recoveryCode: { registered: true, updatedAtMs: 1754006400000 },
          passkeys: [
            {
              wrapId,
              label: "yubikey",
              credentialIdHex: "ab".repeat(16),
              prfSaltHex: "22".repeat(32),
              updatedAtMs: 1754006400000,
            },
          ],
          guardianGroups: [],
        },
      })),
      onRequest("DELETE", `/auth/key-wraps/passkey/${wrapId}`, () => {
        deleted.push(wrapId);
        return { status: 204 };
      }),
    ]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    seedSession(env, maruhi.origin, user);
    env.setPromptResponses([lastGroupOf(env)]);
    expect(await runCli(["key", "recovery", "--replace"], env.layer), env.errors.join("\n")).toBe(
      0,
    );
    expect(put).not.toBeNull();
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      "1 passkey wrap and 0 guardian groups that seal the current reserve key are deleted. If you still have that passkey, stop here and run `maruhi key recovery --passkey` instead",
    );
    // 警告は書き込み(コード発行の表示)より前
    expect(errors.indexOf("replacing the recovery ledger")).toBeLessThan(
      errors.indexOf("Issued your recovery code"),
    );
    expect(deleted).toEqual([wrapId]);
    expect(errors).toContain("removed 1 passkey wrap and 0 guardian groups");
  });

  it("--replace は台帳の行の一覧が読めなくても置換を止めない(警告は一般形 + Note)", async () => {
    const user = await makeTestUser("user-0001");
    let put: PutBody | null = null;
    const maruhi = await start([
      statusHandler(true),
      putHandler((body) => {
        put = body;
      }),
      noProjectsHandler(),
      onRequest("GET", "/auth/key-wraps", () => ({ status: 500, json: { _tag: "Internal" } })),
    ]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    seedSession(env, maruhi.origin, user);
    env.setPromptResponses([lastGroupOf(env)]);
    // 末尾の台帳行の削除は同じ一覧に依るので飛ばし(Note)、コマンドは成功で終わる
    expect(await runCli(["key", "recovery", "--replace"], env.layer), env.errors.join("\n")).toBe(
      0,
    );
    expect(put).not.toBeNull();
    const errors = env.errors.join("\n");
    expect(errors).toContain("could not read the ledger's passkey wraps and guardian groups");
    expect(errors).toContain(
      "could not be listed, so any that sealed the previous reserve key were left in place",
    );
    expect(errors).toContain(
      "any passkey wraps and guardian groups that seal the current reserve key are deleted",
    );
    expect(await recordedReservesOf(env, maruhi.origin, user.userId)).toHaveLength(1);
  });

  it("AI エージェント環境では発行を拒否する", async () => {
    const user = await makeTestUser("user-0001");
    const maruhi = await start([statusHandler(false), putHandler(() => {})]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    seedSession(env, maruhi.origin, user);
    env.setAgent({ isAgent: true });
    expect(await runCli(["key", "recovery"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("AI agent environment");
  });

  it("stdin / stdout / stderr のどれかが非TTYなら発行前(登録・表示の前)に拒否する", async () => {
    for (const terminal of [
      { stdin: false, stdout: true, stderr: true },
      { stdin: true, stdout: false, stderr: true },
      { stdin: true, stdout: true, stderr: false },
    ]) {
      const user = await makeTestUser("user-0001");
      let putSeen = false;
      const maruhi = await start([
        // 台帳の有無の確認(鍵素材を運ばない)はゲートの前に走る
        statusHandler(false),
        putHandler(() => {
          putSeen = true;
        }),
      ]);
      const env = await loggedInEnv(maruhi.origin, user.userId);
      seedSession(env, maruhi.origin, user);
      env.setTerminal(terminal);
      expect(await runCli(["key", "recovery"], env.layer)).toBe(1);
      expect(env.errors.join("\n")).toContain("stdin, stdout, and stderr must all be terminals");
      // 鍵素材は登録も表示もされない
      expect(putSeen).toBe(false);
      expect(env.errors.some((line) => /^ {4}[A-Z2-7]{4}-/.test(line))).toBe(false);
      expect(env.prompts).toHaveLength(0);
      expect(await recordedReservesOf(env, maruhi.origin, user.userId)).toHaveLength(0);
    }
  });
});

describe("maruhi key recover(復元)", () => {
  /** `user` の鍵レコードを既知の secret でラップし、GET /auth/recovery で配る(予備鍵 B)。 */
  function wrappedBlobHandler(
    user: TestUser,
    secret: Uint8Array,
  ): Promise<{ handler: MockHandler; code: string }> {
    return ledgerHandlerFor(storedReserveRecord(user), user.userId, secret);
  }

  it("正しいコードで予備鍵を開き、新しい端末鍵を発行して予備鍵は捨てる", async () => {
    // 復元する人(セッション)と、台帳に封印された予備鍵 B は別の鍵
    const user = await makeTestUser("user-0001");
    const reserveUser = await makeTestUser("user-0001-reserve");
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { handler, code } = await ledgerHandlerFor(
      storedReserveRecord(reserveUser),
      user.userId,
      secret,
    );
    const maruhi = await start([handler, noProjectsHandler()]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    env.setPromptResponses([code.toLowerCase()]);
    expect(await runCli(["key", "recover"], env.layer)).toBe(0);
    // プロジェクトが無い = どのチェーンにも無い → 予備鍵かは問わない(DK K14-2 の nowhere)
    expect(env.prompts).toEqual(["Enter your recovery code: "]);
    // キーチェーンに入るのは**新しい端末鍵**であり、台帳の B ではない(§8.1)
    const device = storedDeviceRecord(env, maruhi.origin, user.userId);
    expect(device.encPubHex).not.toBe(reserveUser.encPubHex);
    expect(device.encPubHex).toMatch(/^[0-9a-f]{64}$/);
    expect(serializeStoredMasterKey(device)).not.toBe(
      serializeStoredMasterKey(storedReserveRecord(reserveUser)),
    );
    // B の秘密はどこにも保存されない
    const keychainDump = [...env.keychain.values()].join("\n");
    expect(keychainDump).not.toContain(reserveUser.encSkHex);
    expect(keychainDump).not.toContain(reserveUser.sigSkSeedHex);
    // 予備鍵の印がある鍵は、問わずに予備鍵として記録する(DK K16-6 — 判定の正例・反例は
    // device.test.ts の DK K14 / K16 の describe)
    expect(await recordedReservesOf(env, maruhi.origin, user.userId)).toHaveLength(1);
    const output = env.logs.join("\n");
    expect(output).toContain("Generated this device's key and stored it in the OS keychain");
    expect(output).toContain(
      `Opened key ${reserveUser.fingerprintHex} from the recovery ledger. It is used only to register this machine's new device key, then discarded`,
    );
    // 表示される FP は新しい端末鍵のもの(台帳の鍵の FP ではない)
    const shown = env.logs.find((line) => line.startsWith("key fingerprint: "));
    expect(shown).toBeDefined();
    expect(shown).toMatch(/^key fingerprint: [0-9a-f]{32}$/);
    expect(shown).not.toBe(`key fingerprint: ${reserveUser.fingerprintHex}`);
    expect(env.errors.join("\n")).toContain(
      "the reserve key was discarded from memory; it stays sealed in the recovery ledger only. This device now signs with its own key",
    );
    // 秘密鍵素材・コードを表示しない
    expect(output).not.toContain(reserveUser.encSkHex);
    expect(output).not.toContain(code);
    expect(env.errors.join("\n")).not.toContain(reserveUser.encSkHex);
  });

  it("予備鍵の印がある鍵は、どのチェーンにも無くても問わずに記録する(DK K16-6)", async () => {
    const user = await makeTestUser("user-0001");
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { handler, code } = await wrappedBlobHandler(user, secret);
    const maruhi = await start([handler, noProjectsHandler()]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    env.setPromptResponses([code]);
    expect(await runCli(["key", "recover"], env.layer)).toBe(0);
    expect(env.prompts).toEqual(["Enter your recovery code: "]);
    expect(await recordedReservesOf(env, maruhi.origin, user.userId)).toHaveLength(1);
    expect(env.errors.join("\n")).toContain(
      `Note: recorded ${user.fingerprintHex} on this machine as your reserve key (its ledger record carries the mark maruhi writes when it creates a reserve key)`,
    );
    // 新しい端末鍵は発行されている(台帳の鍵そのものは保存しない)
    expect(storedDeviceRecord(env, maruhi.origin, user.userId).encPubHex).not.toBe(user.encPubHex);
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
    expect(errors).toContain("update maruhi to the latest");
    expect(errors).toContain("`maruhi key recovery --replace`");
    // 未知スイートは「このコードでは復元できません」ではない(更新すれば
    // そのまま使える)。破損用の文言を混ぜると、使えるコードを捨てさせる
    expect(errors).not.toContain("This code cannot restore");
    expect(errors).toContain("do not discard");
    // キーチェーンには何も書かない
    expect(env.keychain.get(masterKeyEntryName(maruhi.origin, user.userId))).toBeUndefined();
  });

  it("解釈できないブロブは形で言い分け、再登録は別デバイスだと断る", async () => {
    // 復号は成功するが parse に落ちる 2 種類: 現行の形が揃っていて中身が壊れて
    // いるもの(再登録)と、形が違うもの(将来版かもしれない = 更新が先)
    const cases = [
      {
        blob: JSON.stringify({
          suite: "maruhi/v1",
          encPubHex: "",
          encSkHex: "",
          sigPubHex: "",
          sigSkSeedHex: "",
        }),
        expected: "seal a new reserve key by running `maruhi key recovery --replace`",
        notExpected: "update maruhi to the latest",
      },
      {
        blob: JSON.stringify({ suite: "maruhi/v2", keys: { enc: "aa" } }),
        expected: "update maruhi to the latest",
        notExpected: "This code cannot restore",
      },
      {
        // 形は現行のまま符号化だけ違う = parse は通り、hex の解釈で落ちる。
        // このフォークでは「壊れている」と「将来版の符号化」を観測で区別
        // できないので、断定して再登録(= コードの失効)へ送らない
        blob: JSON.stringify({
          suite: "maruhi/v1",
          encPubHex: "aa".repeat(32),
          encSkHex: "not-hex+/=",
          sigPubHex: "bb".repeat(32),
          sigSkSeedHex: "cc".repeat(32),
        }),
        expected: "do not discard",
        notExpected: "This code cannot restore",
      },
    ] as const;
    for (const testCase of cases) {
      const user = await makeTestUser("user-0001");
      const secret = crypto.getRandomValues(new Uint8Array(32));
      const wrapped = await wrapMasterSecret({
        recoverySecret: secret,
        userId: user.userId,
        masterSecretBlob: new TextEncoder().encode(testCase.blob),
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
      expect(errors).toContain(testCase.expected);
      expect(errors).not.toContain(testCase.notExpected);
    }
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
    expect(env.errors.join("\n")).toContain("failed repeatedly");
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
    expect(env.errors.join("\n")).toContain("Refused to read a recovery code");
    // ブロブ取得(要監視イベント)にも到達しない
    expect(fetched).toBe(false);
  });

  it("stdin / stdout / stderr のどれかが非TTYならブロブ取得前に拒否する", async () => {
    for (const terminal of [
      { stdin: false, stdout: true, stderr: true },
      { stdin: true, stdout: false, stderr: true },
      { stdin: true, stdout: true, stderr: false },
    ]) {
      const user = await makeTestUser("user-0001");
      let fetched = false;
      const maruhi = await start([
        onRequest("GET", "/auth/recovery", () => {
          fetched = true;
          return { status: 404, json: { _tag: "RecoveryWrapNotFound" } };
        }),
      ]);
      const env = await loggedInEnv(maruhi.origin, user.userId);
      env.setTerminal(terminal);
      expect(await runCli(["key", "recover"], env.layer)).toBe(1);
      expect(env.errors.join("\n")).toContain("stdin, stdout, and stderr must all be terminals");
      expect(fetched).toBe(false);
      expect(env.prompts).toHaveLength(0);
    }
  });

  it("既に端末鍵があるデバイスではサーバーに触れる前に拒否する", async () => {
    const user = await makeTestUser("user-0001");
    let reachedServer = false;
    const maruhi = await start([
      () => {
        reachedServer = true;
        return null;
      },
    ]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    seedSession(env, maruhi.origin, user);
    expect(await runCli(["key", "recover"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "A device key already exists on this machine, so there is nothing to recover here",
    );
    expect(reachedServer).toBe(false);
    expect(env.prompts).toHaveLength(0);
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
    expect(env.errors.join("\n")).toContain("No recovery code is registered for your account");
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
    expect(env.errors.join("\n")).toContain("after 1800 seconds");
  });
});
