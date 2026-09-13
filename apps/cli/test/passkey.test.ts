// パスキー PRF 経路(CRYPTO_SPEC §8.2 / AUTH_SPEC §13-7 — KL3 K5)の統合テスト:
// `maruhi key seal passkey` / `maruhi key recover --passkey` / `maruhi key seal list|remove`。
// ラップ・復号は実 crypto、サーバーはワイヤレベルモック、ブラウザは
// `setBrowserOpenHandler` でテストが務める(ページの代わりに PRF を POST する —
// integration-options.md 補足 20 裁定 J)。
//
// 固定する性質:
//  1. 登録は「PRF → KEK → ラップ → 最後に POST」で、台帳の行はテストベクターと同じ
//     `derivePasskeyKek` + master-wrap AAD(user_id / passkey-prf / wrap_id)で開ける
//  2. 復元は台帳のラップを 1 件取り、同じ PRF で復号してキーチェーンへ保存する。
//     ブロブ取得は儀式の前に 1 回だけ(複数登録は番号で選ぶ)
//  3. ゲート: エージェント環境・非端末・既存鍵あり・登録なし・上限はリスナーを立てる前に拒否
//  4. ページの理由コードは英語の案内に写り、台帳には何も書かれない

import { decodeHex, derivePasskeyKek, unwrapMasterBlob } from "@maruhi/crypto";
import { Redacted } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { masterKeyEntryName, serializeStoredMasterKey, tokenEntryName } from "../src/keychain.ts";
import type { PrfPagePost } from "../src/passkey-page.ts";
import { makeTestUser, type TestUser } from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

let owner: TestUser;
const servers: MockServer[] = [];

const PRF_HEX = "53ed1bf3f3a19eb2fda745bfcc680cc45739f1840514c10609a6863483fd260c";
const CREDENTIAL_HEX = "3cb8db37e0370e63a3849be601db91faf1306f83dcfb24c6428da106499921e2";
const WRAP_ID = "01JMKWRAP000000000000PASSK";
const OTHER_WRAP_ID = "01JMKWRAP000000000000THER0";

beforeAll(async () => {
  owner = await makeTestUser("user-owner-0001");
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

interface Started {
  readonly env: TestEnv;
  readonly server: MockServer;
}

async function start(handlers: readonly MockHandler[]): Promise<Started> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  await seedConfig(env, { server: server.origin });
  return { env, server };
}

function seedTokenOnly(env: TestEnv, origin: string): void {
  env.keychain.set(
    tokenEntryName(origin),
    JSON.stringify({ token: "maruhi_pat_stored", userId: owner.userId, tokenId: "tok_1" }),
  );
}

interface PasskeyRow {
  readonly wrapId: string;
  readonly label: string | null;
  readonly credentialIdHex: string;
  readonly prfSaltHex?: string;
  readonly updatedAtMs: number;
}

function statusHandler(passkeys: readonly PasskeyRow[]): MockHandler {
  return onRequest("GET", "/auth/key-wraps", () => ({
    status: 200,
    json: {
      recoveryCode: { registered: true, updatedAtMs: 1754006400000 },
      passkeys,
      guardianGroups: [],
    },
  }));
}

interface RegistrationBody {
  readonly wrapId: string;
  readonly wrap: {
    readonly suite: string;
    readonly nonceHex: string;
    readonly ciphertextHex: string;
  };
  readonly credentialIdHex: string;
  readonly prfSaltHex: string;
  readonly rpId: string;
  readonly label?: string;
}

function registerHandler(record: (body: RegistrationBody) => void): MockHandler {
  return onRequest("POST", "/auth/key-wraps/passkey", (request) => {
    const body = request.body as RegistrationBody;
    record(body);
    return { status: 200, json: { wrapId: body.wrapId } };
  });
}

function wrapHandler(wrapId: string, registration: RegistrationBody): MockHandler {
  return onRequest("GET", `/auth/key-wraps/passkey/${wrapId}`, () => ({
    status: 200,
    json: { ...registration, label: registration.label ?? null, updatedAtMs: 1754006400000 },
  }));
}

/** 端末(stderr)に表示された確認コード(利用者がページへ打ち込む値)。 */
function displayedCode(env: TestEnv): string {
  const line = env.errors.find((entry) =>
    entry.startsWith("Confirmation code (type it into the page): "),
  );
  const match = line === undefined ? null : /(\d{3}) (\d{3})$/.exec(line);
  if (match === null) {
    throw new Error("confirmation code line not found in stderr output");
  }
  return `${match[1]}${match[2]}`;
}

/** ブラウザ役: config.json を読み、端末のコードを添えて 1 POST を返す。 */
function browserPosting(
  env: TestEnv,
  respond: (config: unknown) => PrfPagePost,
  seen: { config?: unknown } = {},
  code: (env: TestEnv) => string = displayedCode,
): void {
  env.setBrowserOpenHandler(async (url) => {
    const config = await (await fetch(`${url}config.json`)).json();
    seen.config = config;
    const origin = new URL(url).origin;
    const response = await fetch(`${url}prf`, {
      method: "POST",
      headers: { "content-type": "application/json", origin },
      body: JSON.stringify({ code: code(env), ...respond(config) }),
    });
    return response.status === 204;
  });
}

const hex = (value: string): Uint8Array => {
  const bytes = decodeHex(value);
  if (bytes === null) throw new Error("hex");
  return bytes;
};

/** 台帳 / キーチェーンが持つ master 鍵レコード(seedSession と同じ形)。 */
function serializedRecord(): string {
  return serializeStoredMasterKey({
    suite: "maruhi/v1",
    encPubHex: owner.encPubHex,
    encSkHex: Redacted.make(owner.encSkHex),
    sigPubHex: owner.sigPubHex,
    sigSkSeedHex: Redacted.make(owner.sigSkSeedHex),
  });
}

async function registerOnce(label?: string): Promise<{
  readonly registration: RegistrationBody;
  readonly env: TestEnv;
}> {
  // クロージャで代入する値は TS が狭めるので、器に入れて受ける
  const captured: { body: RegistrationBody | null } = { body: null };
  const { env, server } = await start([
    statusHandler([]),
    registerHandler((body) => {
      captured.body = body;
    }),
  ]);
  seedSession(env, server.origin, owner);
  const seen: { config?: unknown } = {};
  browserPosting(env, () => ({ credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX }), seen);
  const argv = ["key", "seal", "passkey", ...(label === undefined ? [] : ["--label", label])];
  const code = await runCli(argv, env.layer);
  expect(code, env.errors.join("\n")).toBe(0);
  expect(seen.config).toMatchObject({
    mode: "register",
    rpId: "localhost",
    userName: `maruhi · ${new URL(server.origin).host}`,
    excludeCredentialIdsHex: [],
  });
  const registration = captured.body;
  if (registration === null) throw new Error("registration was not posted");
  // ページが使った salt と台帳へ送った salt は同じ値(食い違うと復元不能)
  expect(seen.config).toMatchObject({ prfSaltHex: registration.prfSaltHex });
  return { registration, env };
}

describe("maruhi key seal passkey(登録)", () => {
  it("PRF から KEK を導いて B をラップし、公開パラメータと共に台帳へ登録する(POST は最後)", async () => {
    const { registration, env } = await registerOnce("MacBook Touch ID");
    expect(registration.rpId).toBe("localhost");
    expect(registration.credentialIdHex).toBe(CREDENTIAL_HEX);
    expect(registration.prfSaltHex).toMatch(/^[0-9a-f]{64}$/);
    expect(registration.label).toBe("MacBook Touch ID");
    expect(registration.wrap.suite).toBe("maruhi/v1");
    // 台帳の行は、テストベクターと同じ経路(derivePasskeyKek + master-wrap AAD)で開ける
    const kek = await derivePasskeyKek(hex(PRF_HEX));
    if (!kek.ok) throw new Error("kek");
    const opened = await unwrapMasterBlob({
      kek: kek.value,
      wrapped: {
        nonce: hex(registration.wrap.nonceHex),
        ciphertext: hex(registration.wrap.ciphertextHex),
      },
      context: { userId: owner.userId, kind: "passkey-prf", wrapRef: registration.wrapId },
    });
    if (!opened.ok) throw new Error("unwrap failed");
    expect(new TextDecoder().decode(opened.value)).toBe(serializedRecord());
    // 別の wrap_id へ移植すると開けない(AAD の束縛)
    const moved = await unwrapMasterBlob({
      kek: kek.value,
      wrapped: {
        nonce: hex(registration.wrap.nonceHex),
        ciphertext: hex(registration.wrap.ciphertextHex),
      },
      context: { userId: owner.userId, kind: "passkey-prf", wrapRef: OTHER_WRAP_ID },
    });
    expect(moved.ok).toBe(false);
    expect(env.logs[0]).toBe(`Sealed the master key to a passkey (wrap ${registration.wrapId})`);
    expect(env.logs[1]).toBe(`key fingerprint: ${owner.fingerprintHex}`);
    const stderr = env.errors.join("\n");
    expect(stderr).toContain("Open this page in your browser");
    expect(stderr).toContain(env.browserOpens[0]);
    expect(stderr).not.toContain(PRF_HEX);
    expect(stderr).not.toContain(registration.wrap.ciphertextHex);
  });

  it("ラベル無しでは label を送らず、--label の受理形違いは usage エラー(exit 2)", async () => {
    const { registration } = await registerOnce();
    expect(registration.label).toBeUndefined();

    const { env, server } = await start([statusHandler([])]);
    seedSession(env, server.origin, owner);
    expect(await runCli(["key", "seal", "passkey", "--label", "bad‮label"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain(
      "Unacceptable value for flag --label (expected: 1 to 64 characters without control or bidirectional-formatting characters)",
    );
    expect(env.browserOpens).toEqual([]);
    expect(server.requests).toHaveLength(0);
  });

  it("既存の credential を excludeCredentials として渡し、上限(5 件)ではブラウザを開かずに拒否する", async () => {
    const rows = Array.from({ length: 4 }, (_, i) => ({
      wrapId: `01JMKWRAP0000000000000000${i}`,
      label: null,
      credentialIdHex: `0${i}`.repeat(8),
      updatedAtMs: 1754006400000,
    }));
    const { env, server } = await start([statusHandler(rows), registerHandler(() => {})]);
    seedSession(env, server.origin, owner);
    const seen: { config?: unknown } = {};
    browserPosting(env, () => ({ credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX }), seen);
    expect(await runCli(["key", "seal", "passkey"], env.layer)).toBe(0);
    expect(seen.config).toMatchObject({
      excludeCredentialIdsHex: rows.map((r) => r.credentialIdHex),
    });

    const full = await start([statusHandler([...rows, { ...rows[0]!, wrapId: WRAP_ID }])]);
    seedSession(full.env, full.server.origin, owner);
    expect(await runCli(["key", "seal", "passkey"], full.env.layer)).toBe(1);
    expect(full.env.errors.join("\n")).toContain(
      "You already have 5 passkeys registered (the limit)",
    );
    expect(full.env.browserOpens).toEqual([]);
  });

  it("確認コードが違う POST は受理されず(儀式も消費しない)、打ち直した正しいコードで通る", async () => {
    const captured: { body: RegistrationBody | null } = { body: null };
    const { env, server } = await start([
      statusHandler([]),
      registerHandler((body) => {
        captured.body = body;
      }),
    ]);
    seedSession(env, server.origin, owner);
    const statuses: number[] = [];
    env.setBrowserOpenHandler(async (url) => {
      const origin = new URL(url).origin;
      const send = async (code: string) => {
        const response = await fetch(`${url}prf`, {
          method: "POST",
          headers: { "content-type": "application/json", origin },
          body: JSON.stringify({ code, credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX }),
        });
        statuses.push(response.status);
      };
      // 別 UID の利用者がトークンを拾って偽の PRF を送る形 = コードを知らない
      await send("000000");
      await send(displayedCode(env));
      return true;
    });
    expect(await runCli(["key", "seal", "passkey"], env.layer), env.errors.join("\n")).toBe(0);
    expect(statuses).toEqual([404, 204]);
    expect(captured.body).not.toBeNull();
    expect(env.errors.join("\n")).toMatch(
      /Confirmation code \(type it into the page\): \d{3} \d{3}/,
    );
  });

  it("確認コードの総当たりは儀式ごと失敗し、台帳には何も書かれない", async () => {
    const { env, server } = await start([statusHandler([]), registerHandler(() => {})]);
    seedSession(env, server.origin, owner);
    env.setBrowserOpenHandler(async (url) => {
      const origin = new URL(url).origin;
      for (const code of ["000001", "000002", "000003", "000004", "000005"]) {
        await fetch(`${url}prf`, {
          method: "POST",
          headers: { "content-type": "application/json", origin },
          body: JSON.stringify({ code, credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX }),
        });
      }
      return true;
    });
    expect(await runCli(["key", "seal", "passkey"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "The confirmation code was rejected too many times, so the passkey step was cancelled. Either the code was mistyped, or another process on this machine is sending requests to the passkey page",
    );
    expect(server.requests.filter((r) => r.method === "POST")).toHaveLength(0);
  });

  it("ページの理由コードは案内に写り、台帳には何も書かれない", async () => {
    const cases: readonly [PrfPagePost, string][] = [
      [{ error: "not-allowed" }, "The passkey was not created"],
      [{ error: "already-registered" }, "This authenticator already holds a passkey"],
      [{ error: "prf-unsupported" }, "does not support the WebAuthn PRF extension"],
      [{ error: "unexpected" }, "The passkey step failed in the browser"],
    ];
    for (const [post, expected] of cases) {
      const { env, server } = await start([statusHandler([]), registerHandler(() => {})]);
      seedSession(env, server.origin, owner);
      browserPosting(env, () => post);
      expect(await runCli(["key", "seal", "passkey"], env.layer), expected).toBe(1);
      expect(env.errors.join("\n"), expected).toContain(expected);
      expect(
        server.requests.filter((r) => r.method === "POST"),
        expected,
      ).toHaveLength(0);
    }
  });

  it("エージェント環境・非端末・鍵なしの端末ではリスナーを立てる前に拒否する", async () => {
    const agent = await start([statusHandler([])]);
    seedSession(agent.env, agent.server.origin, owner);
    agent.env.setAgent({ isAgent: true, name: "Claude Code" });
    expect(await runCli(["key", "seal", "passkey"], agent.env.layer)).toBe(1);
    expect(agent.env.errors.join("\n")).toContain(
      "Refused to seal the master key to a passkey because an AI agent environment was detected",
    );
    expect(agent.env.browserOpens).toEqual([]);
    expect(agent.server.requests).toHaveLength(0);

    const piped = await start([statusHandler([])]);
    seedSession(piped.env, piped.server.origin, owner);
    piped.env.setTerminal({ stdout: false });
    expect(await runCli(["key", "seal", "passkey"], piped.env.layer)).toBe(1);
    expect(piped.env.errors.join("\n")).toContain(
      "Passkey sealing is only allowed on an interactive terminal",
    );
    expect(piped.env.browserOpens).toEqual([]);

    const noKey = await start([statusHandler([])]);
    seedTokenOnly(noKey.env, noKey.server.origin);
    expect(await runCli(["key", "seal", "passkey"], noKey.env.layer)).toBe(1);
    expect(noKey.env.errors.join("\n")).toContain("No master key on this device");
    expect(noKey.env.browserOpens).toEqual([]);
  });
});

/** status の passkey 行(新サーバー = 公開パラメータ prfSaltHex を運ぶ)。 */
function rowOf(registration: RegistrationBody, label: string | null = null): PasskeyRow {
  return {
    wrapId: registration.wrapId,
    label,
    credentialIdHex: registration.credentialIdHex,
    prfSaltHex: registration.prfSaltHex,
    updatedAtMs: 1,
  };
}

/** 旧サーバーの行(prfSaltHex を運ばない)。 */
function legacyRowOf(registration: RegistrationBody, label: string | null = null): PasskeyRow {
  const { prfSaltHex: _omitted, ...row } = rowOf(registration, label);
  return row;
}

const passkeyFetches = (server: MockServer) =>
  server.requests.filter(
    (r) => r.method === "GET" && r.path.startsWith("/auth/key-wraps/passkey/"),
  );

describe("maruhi key recover --passkey(復元 — status が salt を運ぶ本線)", () => {
  it("全 credential で儀式し、応答の credential の行だけをラップ取得して復号・保存する(取得は儀式の後)", async () => {
    const { registration } = await registerOnce();
    // 行ごとに別の salt(evalByCredential の対応を固定する — 同じ salt だと取り違えを検出できない)
    const other = {
      ...registration,
      wrapId: OTHER_WRAP_ID,
      credentialIdHex: "ff".repeat(16),
      prfSaltHex: "77".repeat(32),
    };
    const { env, server } = await start([
      statusHandler([rowOf(other, "YubiKey"), rowOf(registration, "Touch ID")]),
      wrapHandler(OTHER_WRAP_ID, other),
      wrapHandler(registration.wrapId, registration),
    ]);
    seedTokenOnly(env, server.origin);
    const seen: { config?: unknown; fetchesAtCeremony?: number } = {};
    browserPosting(
      env,
      () => {
        // 儀式の時点ではブロブをまだ取っていない(取り消しが窓を消費しない根拠)
        seen.fetchesAtCeremony = passkeyFetches(server).length;
        return { credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX };
      },
      seen,
    );
    const code = await runCli(["key", "recover", "--passkey"], env.layer);
    expect(code, env.errors.join("\n")).toBe(0);
    expect(seen.config).toEqual({
      mode: "recover",
      rpId: "localhost",
      credentials: [
        { credentialIdHex: other.credentialIdHex, prfSaltHex: other.prfSaltHex },
        { credentialIdHex: CREDENTIAL_HEX, prfSaltHex: registration.prfSaltHex },
      ],
    });
    expect(seen.fetchesAtCeremony).toBe(0);
    expect(env.prompts).toEqual([]);
    expect(passkeyFetches(server).map((r) => r.path)).toEqual([
      `/auth/key-wraps/passkey/${registration.wrapId}`,
    ]);
    expect(env.keychain.get(masterKeyEntryName(server.origin, owner.userId))).toBe(
      serializedRecord(),
    );
    expect(env.logs[0]).toBe(
      "Restored the master key via passkey and stored it in the OS keychain",
    );
    expect(env.logs[1]).toBe(`key fingerprint: ${owner.fingerprintHex}`);
    expect(env.errors.join("\n")).not.toContain(PRF_HEX);
  });

  it("取り消し・未登録の credential・違う PRF・行と食い違うラップでは復元せず、取り消しはブロブを取らない", async () => {
    const { registration } = await registerOnce();
    const cases: readonly [PrfPagePost, string, number][] = [
      [{ error: "not-allowed" }, "The passkey was not used", 0],
      [
        { credentialIdHex: "ab".repeat(8), prfHex: PRF_HEX },
        "is not registered for your account",
        0,
      ],
      [
        { credentialIdHex: CREDENTIAL_HEX, prfHex: "99".repeat(32) },
        "Cannot decrypt the wrapped master key with this passkey",
        1,
      ],
    ];
    for (const [post, expected, fetches] of cases) {
      const { env, server } = await start([
        statusHandler([rowOf(registration)]),
        wrapHandler(registration.wrapId, registration),
      ]);
      seedTokenOnly(env, server.origin);
      browserPosting(env, () => post);
      expect(await runCli(["key", "recover", "--passkey"], env.layer), expected).toBe(1);
      expect(env.errors.join("\n"), expected).toContain(expected);
      expect(passkeyFetches(server), expected).toHaveLength(fetches);
      expect(env.keychain.has(masterKeyEntryName(server.origin, owner.userId)), expected).toBe(
        false,
      );
    }
    // サーバーが行と食い違うラップ(別 credential の登録)を返したら fail-closed
    const swapped = { ...registration, credentialIdHex: "ab".repeat(8) };
    const { env, server } = await start([
      statusHandler([rowOf(registration)]),
      wrapHandler(registration.wrapId, swapped),
    ]);
    seedTokenOnly(env, server.origin);
    browserPosting(env, () => ({ credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX }));
    expect(await runCli(["key", "recover", "--passkey"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "The wrap fetched from the server belongs to a different passkey",
    );
    expect(env.keychain.has(masterKeyEntryName(server.origin, owner.userId))).toBe(false);
  });

  it("儀式の後のレート制限は案内になり、キーチェーンには何も残らない", async () => {
    const { registration } = await registerOnce();
    const { env, server } = await start([
      statusHandler([rowOf(registration)]),
      onRequest("GET", `/auth/key-wraps/passkey/${registration.wrapId}`, () => ({
        status: 429,
        json: { _tag: "KeyWrapRateLimited", window: "blob-fetch", retryAfterSeconds: 1200 },
      })),
    ]);
    seedTokenOnly(env, server.origin);
    browserPosting(env, () => ({ credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX }));
    expect(await runCli(["key", "recover", "--passkey"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "The key-wrap fetch limit was reached. Retry after 1200 seconds",
    );
    expect(env.keychain.has(masterKeyEntryName(server.origin, owner.userId))).toBe(false);
  });
});

describe("maruhi key recover --passkey(旧サーバー = status に salt が無いときのフォールバック)", () => {
  it("行を 1 つ選んでラップを先に取り、その salt で儀式する(複数なら番号で選ぶ)", async () => {
    const { registration } = await registerOnce();
    // 行ごとに別の salt(evalByCredential の対応を固定する — 同じ salt だと取り違えを検出できない)
    const other = {
      ...registration,
      wrapId: OTHER_WRAP_ID,
      credentialIdHex: "ff".repeat(16),
      prfSaltHex: "77".repeat(32),
    };
    const { env, server } = await start([
      statusHandler([legacyRowOf(other, "YubiKey"), legacyRowOf(registration, "Touch ID")]),
      wrapHandler(OTHER_WRAP_ID, other),
      wrapHandler(registration.wrapId, registration),
    ]);
    seedTokenOnly(env, server.origin);
    env.setPromptResponses(["2"]);
    const seen: { config?: unknown } = {};
    browserPosting(env, () => ({ credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX }), seen);
    expect(await runCli(["key", "recover", "--passkey"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.prompts[0]).toBe("Which passkey will you use? [1-2]: ");
    expect(env.errors.join("\n")).toContain(
      `1. ${OTHER_WRAP_ID}  YubiKey  credential ffffffffffffffff…`,
    );
    expect(seen.config).toEqual({
      mode: "recover",
      rpId: "localhost",
      credentials: [{ credentialIdHex: CREDENTIAL_HEX, prfSaltHex: registration.prfSaltHex }],
    });
    expect(passkeyFetches(server).map((r) => r.path)).toEqual([
      `/auth/key-wraps/passkey/${registration.wrapId}`,
    ]);
    expect(env.keychain.get(masterKeyEntryName(server.origin, owner.userId))).toBe(
      serializedRecord(),
    );

    // 1 件なら自動、番号が不正なら取り消し(ブラウザを開かない)
    const single = await start([
      statusHandler([legacyRowOf(registration)]),
      wrapHandler(registration.wrapId, registration),
    ]);
    seedTokenOnly(single.env, single.server.origin);
    browserPosting(single.env, () => ({ credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX }));
    expect(await runCli(["key", "recover", "--passkey"], single.env.layer)).toBe(0);
    expect(single.env.prompts).toEqual([]);

    const cancelled = await start([statusHandler([legacyRowOf(other), legacyRowOf(registration)])]);
    seedTokenOnly(cancelled.env, cancelled.server.origin);
    cancelled.env.setPromptResponses(["9"]);
    expect(await runCli(["key", "recover", "--passkey"], cancelled.env.layer)).toBe(1);
    expect(cancelled.env.errors.join("\n")).toContain(
      "The passkey recovery was cancelled (nothing was changed)",
    );
    expect(cancelled.env.browserOpens).toEqual([]);
  });

  it("ラップ取得のレート制限はブラウザを開く前に案内になる", async () => {
    const { registration } = await registerOnce();
    const { env, server } = await start([
      statusHandler([legacyRowOf(registration)]),
      onRequest("GET", `/auth/key-wraps/passkey/${registration.wrapId}`, () => ({
        status: 429,
        json: { _tag: "KeyWrapRateLimited", window: "blob-fetch", retryAfterSeconds: 1200 },
      })),
    ]);
    seedTokenOnly(env, server.origin);
    expect(await runCli(["key", "recover", "--passkey"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "The key-wrap fetch limit was reached. Retry after 1200 seconds",
    );
    expect(env.browserOpens).toEqual([]);
  });
});

describe("maruhi key recover --passkey(前提の拒否)", () => {
  it("登録なし・既存鍵あり・エージェント環境・非端末はリスナーを立てる前に拒否する", async () => {
    const none = await start([statusHandler([])]);
    seedTokenOnly(none.env, none.server.origin);
    expect(await runCli(["key", "recover", "--passkey"], none.env.layer)).toBe(1);
    expect(none.env.errors.join("\n")).toContain("No passkey is registered for your account");
    expect(none.env.browserOpens).toEqual([]);

    const row: PasskeyRow = {
      wrapId: WRAP_ID,
      label: null,
      credentialIdHex: CREDENTIAL_HEX,
      prfSaltHex: "22".repeat(32),
      updatedAtMs: 1,
    };
    const hasKey = await start([statusHandler([row])]);
    seedSession(hasKey.env, hasKey.server.origin, owner);
    expect(await runCli(["key", "recover", "--passkey"], hasKey.env.layer)).toBe(1);
    expect(hasKey.env.errors.join("\n")).toContain("A master key already exists on this device");
    expect(hasKey.env.browserOpens).toEqual([]);

    const agent = await start([statusHandler([row])]);
    seedTokenOnly(agent.env, agent.server.origin);
    agent.env.setAgent({ isAgent: true });
    expect(await runCli(["key", "recover", "--passkey"], agent.env.layer)).toBe(1);
    expect(agent.env.errors.join("\n")).toContain(
      "Refused to restore the master key with a passkey because an AI agent environment was detected",
    );
    expect(agent.server.requests).toHaveLength(0);

    const piped = await start([statusHandler([row])]);
    seedTokenOnly(piped.env, piped.server.origin);
    piped.env.setTerminal({ stdin: false });
    expect(await runCli(["key", "recover", "--passkey"], piped.env.layer)).toBe(1);
    expect(piped.env.errors.join("\n")).toContain(
      "Passkey recovery is only allowed on an interactive terminal",
    );
  });

  it("--handoff と --passkey の同時指定は usage エラー", async () => {
    const { env, server } = await start([]);
    seedTokenOnly(env, server.origin);
    expect(await runCli(["key", "recover", "--passkey", "--handoff"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Choose one of --handoff and --passkey");
  });
});

describe("儀式の 3 チャネル TTY ゲート(ADR-0016 決定 7)", () => {
  const CHANNELS = [
    { stdin: false, stdout: true, stderr: true },
    { stdin: true, stdout: false, stderr: true },
    { stdin: true, stdout: true, stderr: false },
  ] as const;
  const CEREMONIES = [
    { argv: ["key", "seal", "passkey"], noun: "Passkey sealing", seed: "key" },
    { argv: ["key", "recover", "--passkey"], noun: "Passkey recovery", seed: "token" },
    { argv: ["key", "seal", "remove", WRAP_ID], noun: "Passkey wrap removal", seed: "token" },
  ] as const;

  it("stdin / stdout / stderr のどれか 1 つでも端末でなければ、サーバーにもブラウザにも触れずに拒否する", async () => {
    for (const ceremony of CEREMONIES) {
      for (const terminal of CHANNELS) {
        const label = `${ceremony.argv.join(" ")} ${JSON.stringify(terminal)}`;
        const { env, server } = await start([
          statusHandler([
            { wrapId: WRAP_ID, label: null, credentialIdHex: CREDENTIAL_HEX, updatedAtMs: 1 },
          ]),
          onRequest("DELETE", `/auth/key-wraps/passkey/${WRAP_ID}`, () => ({ status: 204 })),
        ]);
        if (ceremony.seed === "key") {
          seedSession(env, server.origin, owner);
        } else {
          seedTokenOnly(env, server.origin);
        }
        env.setTerminal(terminal);
        browserPosting(env, () => ({ credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX }));
        expect(await runCli([...ceremony.argv], env.layer), label).toBe(1);
        expect(env.errors.join("\n"), label).toContain(
          `${ceremony.noun} is only allowed on an interactive terminal (stdin, stdout, and stderr must all be terminals; pipes, redirects, CI, and AI agents are refused)`,
        );
        expect(env.browserOpens, label).toEqual([]);
        expect(server.requests, label).toHaveLength(0);
        expect(env.keychain.has(masterKeyEntryName(server.origin, owner.userId)), label).toBe(
          ceremony.seed === "key",
        );
      }
    }
  });
});

describe("maruhi key seal list / remove", () => {
  it("list は台帳の公開パラメータだけを出し、remove は行を消す(端末ゲートつき)", async () => {
    const rows = [
      {
        wrapId: WRAP_ID,
        label: "Touch ID",
        credentialIdHex: CREDENTIAL_HEX,
        updatedAtMs: 1754006400000,
      },
      {
        wrapId: OTHER_WRAP_ID,
        label: null,
        credentialIdHex: "ff".repeat(16),
        updatedAtMs: 1754006460000,
      },
    ];
    const { env, server } = await start([
      statusHandler(rows),
      onRequest("DELETE", `/auth/key-wraps/passkey/${WRAP_ID}`, () => ({ status: 204 })),
      onRequest("DELETE", `/auth/key-wraps/passkey/${OTHER_WRAP_ID}`, () => ({
        status: 404,
        json: { _tag: "KeyWrapNotFound" },
      })),
    ]);
    seedTokenOnly(env, server.origin);
    expect(await runCli(["key", "seal", "list"], env.layer)).toBe(0);
    expect(env.logs).toEqual([
      `${WRAP_ID}  Touch ID  credential ${CREDENTIAL_HEX.slice(0, 16)}…  2025-08-01 00:00 UTC`,
      `${OTHER_WRAP_ID}  (no label)  credential ffffffffffffffff…  2025-08-01 00:01 UTC`,
    ]);

    env.logs.length = 0;
    expect(await runCli(["key", "seal", "remove", WRAP_ID], env.layer)).toBe(0);
    expect(env.logs).toEqual([`Removed passkey wrap ${WRAP_ID}`]);
    expect(env.errors.join("\n")).toContain("the passkey itself stays in your authenticator");

    expect(await runCli(["key", "seal", "remove", OTHER_WRAP_ID], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("No passkey wrap with that ID");

    env.setAgent({ isAgent: true });
    expect(await runCli(["key", "seal", "remove", WRAP_ID], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Refused to remove a passkey wrap because an AI agent environment was detected",
    );
    // list はゲートを掛けない(公開情報のみ)
    env.logs.length = 0;
    expect(await runCli(["key", "seal", "list"], env.layer)).toBe(0);
    expect(env.logs).toHaveLength(2);
  });

  it("登録が無ければ list はその旨を 1 行出す", async () => {
    const { env, server } = await start([statusHandler([])]);
    seedTokenOnly(env, server.origin);
    expect(await runCli(["key", "seal", "list"], env.layer)).toBe(0);
    expect(env.logs).toEqual([
      "No passkeys are registered (seal your key with `maruhi key seal passkey`)",
    ]);
  });
});
