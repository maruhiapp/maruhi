// パスキー PRF 経路(CRYPTO_SPEC §8.2 / AUTH_SPEC §13-7 — KL3 K5、2026-09-19 DK K4)の
// 統合テスト: `maruhi key seal passkey` / `maruhi key recover --passkey` /
// `maruhi key seal list|remove`。ラップ・復号は実 crypto、サーバーはワイヤレベル
// モック、ブラウザは `setBrowserOpenHandler` でテストが務める(ページの代わりに
// PRF を POST する — integration-options.md 補足 20 裁定 J)。
//
// 固定する性質:
//  1. 封印は「台帳の開封(コード / --passkey)→ PRF → KEK → ラップ → 最後に POST」で、
//     台帳の行はテストベクターと同じ `derivePasskeyKek` + master-wrap AAD(user_id /
//     passkey-prf / wrap_id)で開け、中身は**予備鍵**のレコード(端末鍵ではない)
//  2. 復元は台帳のラップを 1 件取り、同じ PRF で予備鍵を復号し、**新しい端末鍵**を
//     生成してキーチェーンへ保存する(予備鍵は保存しない — K4-1)。ブロブ取得は儀式の
//     前に 1 回だけ(複数登録は番号で選ぶ)
//  3. ゲート: エージェント環境・非端末・既存鍵あり・登録なし・上限はリスナーを立てる
//     前に拒否する(封印はまずリカバリーコードのゲートに当たる)
//  4. ページの理由コードは英語の案内に写り、台帳には何も書かれない
//  5. pre-DK の台帳(端末鍵の複製)には封印せず、`maruhi key recovery` へ誘導する

import { decodeHex, derivePasskeyKek, unwrapMasterBlob, wrapMasterSecret } from "@maruhi/crypto";
import { Redacted } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  masterKeyEntryName,
  parseStoredMasterKey,
  serializeStoredMasterKey,
  tokenEntryName,
} from "../src/keychain.ts";
import type { PrfPagePost } from "../src/passkey-page.ts";
import { formatRecoveryCode } from "../src/recovery-code.ts";
import { makeTestUser, type TestUser } from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

/** この端末の端末鍵(キーチェーンに seed する側)。 */
let owner: TestUser;
/** 台帳に封印されている予備鍵(キーチェーンには決して入らない側)。 */
let reserve: TestUser;
/** 予備鍵をリカバリーコードでラップした台帳(GET /auth/recovery)とそのコード。 */
let ledger: Ledger;
const servers: MockServer[] = [];

const PRF_HEX = "53ed1bf3f3a19eb2fda745bfcc680cc45739f1840514c10609a6863483fd260c";
const CREDENTIAL_HEX = "3cb8db37e0370e63a3849be601db91faf1306f83dcfb24c6428da106499921e2";
const WRAP_ID = "01JMKWRAP000000000000PASSK";
const OTHER_WRAP_ID = "01JMKWRAP000000000000THER0";

const RESERVE_QUESTION = "Type yes if it is your reserve key (anything else = no): ";
const RECOVERY_CODE_AGENT_REFUSAL =
  "Refused to read a recovery code because an AI agent environment was detected (the code is key material; run the recovery on a human interactive terminal)";
const RECOVERY_CODE_TERMINAL_REFUSAL =
  "Recovery-code entry is only allowed on an interactive terminal (stdin, stdout, and stderr must all be terminals; pipes, redirects, CI, and AI agents are refused)";
const DEVICE_KEY_EXISTS_REFUSAL =
  "A device key already exists on this machine, so there is nothing to recover here. To add this machine as another device of yours, run `maruhi device add` and approve it from a registered device; if an earlier `maruhi key recover` was interrupted before every project registered this device, re-run with --resume";
const NO_DEVICE_KEY_REFUSAL =
  "No device key on this machine. If you still have a device of yours, add this machine as a device: `maruhi device add` here, then `maruhi device approve` there. If no device is left, open the reserve key with `maruhi key recover` (recovery code), `maruhi key recover --passkey` (a registered passkey), or `maruhi key recover --handoff` (approvals from your guardians). If this is your first key, generate one with `maruhi key generate`";
const LEDGER_HOLDS_DEVICE_KEY_REFUSAL =
  "The recovery ledger holds a copy of this device's key (an install from before device keys), not a separate reserve key. Run `maruhi key recovery` first: it creates a reserve key, seals it with a new recovery code and replaces the ledger. Then re-run `maruhi key seal passkey`";

beforeAll(async () => {
  owner = await makeTestUser("user-owner-0001");
  reserve = await makeTestUser("user-owner-0001");
  ledger = await ledgerFor(reserve);
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
  readonly prfSaltHex: string;
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

/** 復元の後段(finishRecovery)が走査するプロジェクト一覧(§11-5)— 空。 */
const noMembershipsHandler: MockHandler = onRequest("GET", "/projects", () => ({
  status: 200,
  json: { projects: [] },
}));

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

/** 端末(stderr)に表示された最新の確認コード(儀式が 2 回続くときは後の方 — 開封 → 登録)。 */
function displayedCode(env: TestEnv): string {
  const line = env.errors.findLast((entry) =>
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

/** 鍵レコードの直列化(seedSession / 台帳と同じ形)。 */
function serializedRecordOf(user: TestUser): string {
  return serializeStoredMasterKey({
    suite: "maruhi/v1",
    encPubHex: user.encPubHex,
    encSkHex: Redacted.make(user.encSkHex),
    sigPubHex: user.sigPubHex,
    sigSkSeedHex: Redacted.make(user.sigSkSeedHex),
  });
}

/** 台帳に封印された予備鍵レコードの直列化(封印した行の中身はこれでなければならない)。 */
function serializedReserveRecord(): string {
  return serializedRecordOf(reserve);
}

interface Ledger {
  /** GET /auth/recovery(リカバリーコードでラップした B)。 */
  readonly handler: MockHandler;
  /** 台帳を開けるリカバリーコード(表示形)。 */
  readonly code: string;
}

/**
 * `user` のレコードを既知のリカバリーコードでラップし、GET /auth/recovery で配る
 * (recovery.test.ts と同じ組み立て)。AAD の user_id はセッションの利用者 = owner。
 */
async function ledgerFor(user: TestUser): Promise<Ledger> {
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const wrapped = await wrapMasterSecret({
    recoverySecret: secret,
    userId: owner.userId,
    // JSON.stringify は使えない — 秘密側が伏字でラップされる(本番の recovery.ts と同じ罠)
    masterSecretBlob: new TextEncoder().encode(serializedRecordOf(user)),
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

/** 端末鍵をキーチェーンへ、予備鍵を台帳へ置き、コード入力を 1 回分キューする。 */
function seedDeviceAndLedger(env: TestEnv, origin: string): void {
  seedSession(env, origin, owner);
  env.setPromptResponses([ledger.code]);
}

async function registerOnce(label?: string): Promise<{
  readonly registration: RegistrationBody;
  readonly env: TestEnv;
  readonly server: MockServer;
}> {
  // クロージャで代入する値は TS が狭めるので、器に入れて受ける
  const captured: { body: RegistrationBody | null } = { body: null };
  const { env, server } = await start([
    statusHandler([]),
    ledger.handler,
    registerHandler((body) => {
      captured.body = body;
    }),
  ]);
  seedDeviceAndLedger(env, server.origin);
  const seen: { config?: unknown } = {};
  browserPosting(env, () => ({ credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX }), seen);
  const argv = ["key", "seal", "passkey", ...(label === undefined ? [] : ["--label", label])];
  const code = await runCli(argv, env.layer);
  expect(code, env.errors.join("\n")).toBe(0);
  // 台帳の開封(コード入力)が儀式の前(ブラウザは開封の後に開く)
  expect(env.prompts).toEqual(["Enter your recovery code: "]);
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
  return { registration, env, server };
}

describe("maruhi key seal passkey(登録)", () => {
  it("台帳を開封してから PRF で KEK を導き、予備鍵 B をラップして台帳へ登録する(POST は最後)", async () => {
    const { registration, env, server } = await registerOnce("MacBook Touch ID");
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
    // 封印されるのは台帳から開いた**予備鍵**であり、キーチェーンの端末鍵ではない
    const sealed = new TextDecoder().decode(opened.value);
    expect(sealed).toBe(serializedReserveRecord());
    expect(sealed).not.toBe(serializedRecordOf(owner));
    expect(sealed).not.toContain(owner.encSkHex);
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
    expect(env.logs[0]).toBe(`Sealed the reserve key to a passkey (wrap ${registration.wrapId})`);
    expect(env.logs[1]).toBe(`reserve key fingerprint: ${reserve.fingerprintHex}`);
    const stderr = env.errors.join("\n");
    expect(stderr).toContain(
      `opened the reserve key (fingerprint ${reserve.fingerprintHex}) for this change`,
    );
    expect(stderr).toContain("Open this page in your browser");
    expect(stderr).toContain(env.browserOpens[0]);
    expect(stderr).not.toContain(PRF_HEX);
    expect(stderr).not.toContain(registration.wrap.ciphertextHex);
    expect(stderr).not.toContain(ledger.code);
    expect(stderr).not.toContain(reserve.encSkHex);
    // キーチェーンの端末鍵は触らない(予備鍵で置き換えない)
    expect(env.keychain.get(masterKeyEntryName(server.origin, owner.userId))).toBe(
      serializedRecordOf(owner),
    );
  });

  it("--passkey で台帳を開封して封印できる(開封の儀式 → 登録の儀式)", async () => {
    const { registration } = await registerOnce();
    const captured: { body: RegistrationBody | null } = { body: null };
    const { env, server } = await start([
      statusHandler([rowOf(registration, "Touch ID")]),
      wrapHandler(registration.wrapId, registration),
      registerHandler((body) => {
        captured.body = body;
      }),
    ]);
    seedSession(env, server.origin, owner);
    const modes: string[] = [];
    browserPosting(env, (config) => {
      modes.push((config as { mode: string }).mode);
      return { credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX };
    });
    const code = await runCli(["key", "seal", "passkey", "--passkey"], env.layer);
    expect(code, env.errors.join("\n")).toBe(0);
    expect(env.prompts).toEqual([]);
    expect(modes).toEqual(["recover", "register"]);
    expect(
      server.requests.filter((r) => r.method === "GET" && r.path === "/auth/recovery"),
    ).toEqual([]);
    const second = captured.body;
    if (second === null) throw new Error("registration was not posted");
    const kek = await derivePasskeyKek(hex(PRF_HEX));
    if (!kek.ok) throw new Error("kek");
    const opened = await unwrapMasterBlob({
      kek: kek.value,
      wrapped: { nonce: hex(second.wrap.nonceHex), ciphertext: hex(second.wrap.ciphertextHex) },
      context: { userId: owner.userId, kind: "passkey-prf", wrapRef: second.wrapId },
    });
    if (!opened.ok) throw new Error("unwrap failed");
    expect(new TextDecoder().decode(opened.value)).toBe(serializedReserveRecord());
    expect(env.logs[1]).toBe(`reserve key fingerprint: ${reserve.fingerprintHex}`);
  });

  it("ラベル無しでは label を送らず、--label の受理形違いは usage エラー(exit 2)", async () => {
    const { registration } = await registerOnce();
    expect(registration.label).toBeUndefined();

    const { env, server } = await start([statusHandler([]), ledger.handler]);
    seedDeviceAndLedger(env, server.origin);
    expect(await runCli(["key", "seal", "passkey", "--label", "bad‮label"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain(
      "Unacceptable value for flag --label (expected: 1 to 64 characters without control or bidirectional-formatting characters)",
    );
    expect(env.prompts).toEqual([]);
    expect(env.browserOpens).toEqual([]);
    expect(server.requests).toHaveLength(0);
  });

  it("既存の credential を excludeCredentials として渡し、上限(5 件)ではブラウザを開かずに拒否する", async () => {
    const rows = Array.from({ length: 4 }, (_, i) => ({
      wrapId: `01JMKWRAP0000000000000000${i}`,
      label: null,
      credentialIdHex: `0${i}`.repeat(8),
      prfSaltHex: `1${i}`.repeat(32),
      updatedAtMs: 1754006400000,
    }));
    const { env, server } = await start([
      statusHandler(rows),
      ledger.handler,
      registerHandler(() => {}),
    ]);
    seedDeviceAndLedger(env, server.origin);
    const seen: { config?: unknown } = {};
    browserPosting(env, () => ({ credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX }), seen);
    expect(await runCli(["key", "seal", "passkey"], env.layer), env.errors.join("\n")).toBe(0);
    expect(seen.config).toMatchObject({
      excludeCredentialIdsHex: rows.map((r) => r.credentialIdHex),
    });

    // 上限の判定は台帳の開封の後(開封は台帳変更の資格)、リスナーを立てる前
    const full = await start([
      statusHandler([...rows, { ...rows[0]!, wrapId: WRAP_ID }]),
      ledger.handler,
    ]);
    seedDeviceAndLedger(full.env, full.server.origin);
    expect(await runCli(["key", "seal", "passkey"], full.env.layer)).toBe(1);
    expect(full.env.errors.join("\n")).toContain(
      "You already have 5 passkeys registered (the limit)",
    );
    expect(full.env.prompts).toEqual(["Enter your recovery code: "]);
    expect(full.env.browserOpens).toEqual([]);
  });

  it("確認コードが違う POST は受理されず(儀式も消費しない)、打ち直した正しいコードで通る", async () => {
    const captured: { body: RegistrationBody | null } = { body: null };
    const { env, server } = await start([
      statusHandler([]),
      ledger.handler,
      registerHandler((body) => {
        captured.body = body;
      }),
    ]);
    seedDeviceAndLedger(env, server.origin);
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
    const { env, server } = await start([
      statusHandler([]),
      ledger.handler,
      registerHandler(() => {}),
    ]);
    seedDeviceAndLedger(env, server.origin);
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
      const { env, server } = await start([
        statusHandler([]),
        ledger.handler,
        registerHandler(() => {}),
      ]);
      seedDeviceAndLedger(env, server.origin);
      browserPosting(env, () => post);
      expect(await runCli(["key", "seal", "passkey"], env.layer), expected).toBe(1);
      expect(env.errors.join("\n"), expected).toContain(expected);
      expect(
        server.requests.filter((r) => r.method === "POST"),
        expected,
      ).toHaveLength(0);
    }
  });

  it("pre-DK の台帳(端末鍵の複製)には封印せず、`maruhi key recovery` へ誘導する", async () => {
    // 台帳 B = この端末の鍵そのもの → 封印すると端末鍵の複製が増えるだけなので拒否
    const preDk = await ledgerFor(owner);
    const { env, server } = await start([
      statusHandler([]),
      preDk.handler,
      registerHandler(() => {}),
    ]);
    seedSession(env, server.origin, owner);
    env.setPromptResponses([preDk.code]);
    browserPosting(env, () => ({ credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX }));
    expect(await runCli(["key", "seal", "passkey"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(LEDGER_HOLDS_DEVICE_KEY_REFUSAL);
    expect(env.browserOpens).toEqual([]);
    expect(server.requests.filter((r) => r.method === "POST")).toHaveLength(0);
  });

  it("エージェント環境・非端末・鍵なしの端末ではリスナーを立てる前に拒否する(まずコード入力のゲート)", async () => {
    const agent = await start([statusHandler([]), ledger.handler]);
    seedDeviceAndLedger(agent.env, agent.server.origin);
    agent.env.setAgent({ isAgent: true, name: "Claude Code" });
    expect(await runCli(["key", "seal", "passkey"], agent.env.layer)).toBe(1);
    expect(agent.env.errors.join("\n")).toContain(RECOVERY_CODE_AGENT_REFUSAL);
    expect(agent.env.prompts).toEqual([]);
    expect(agent.env.browserOpens).toEqual([]);
    expect(agent.server.requests).toHaveLength(0);

    const piped = await start([statusHandler([]), ledger.handler]);
    seedDeviceAndLedger(piped.env, piped.server.origin);
    piped.env.setTerminal({ stdout: false });
    expect(await runCli(["key", "seal", "passkey"], piped.env.layer)).toBe(1);
    expect(piped.env.errors.join("\n")).toContain(RECOVERY_CODE_TERMINAL_REFUSAL);
    expect(piped.env.prompts).toEqual([]);
    expect(piped.env.browserOpens).toEqual([]);
    expect(piped.server.requests).toHaveLength(0);

    // 端末鍵の読み込みが開封より先(鍵の無い端末に封印の資格は無い)
    const noKey = await start([statusHandler([]), ledger.handler]);
    seedTokenOnly(noKey.env, noKey.server.origin);
    noKey.env.setPromptResponses([ledger.code]);
    expect(await runCli(["key", "seal", "passkey"], noKey.env.layer)).toBe(1);
    expect(noKey.env.errors.join("\n")).toContain(NO_DEVICE_KEY_REFUSAL);
    expect(noKey.env.prompts).toEqual([]);
    expect(noKey.env.browserOpens).toEqual([]);
    expect(noKey.server.requests).toHaveLength(0);
  });
});

/** status の passkey 行(公開パラメータ prfSaltHex を運ぶ)。 */
function rowOf(registration: RegistrationBody, label: string | null = null): PasskeyRow {
  return {
    wrapId: registration.wrapId,
    label,
    credentialIdHex: registration.credentialIdHex,
    prfSaltHex: registration.prfSaltHex,
    updatedAtMs: 1,
  };
}

const passkeyFetches = (server: MockServer) =>
  server.requests.filter(
    (r) => r.method === "GET" && r.path.startsWith("/auth/key-wraps/passkey/"),
  );

describe("maruhi key recover --passkey(復元)", () => {
  it("全 credential で儀式し、応答の credential の行だけをラップ取得して予備鍵を開き、新しい端末鍵を保存する(取得は儀式の後)", async () => {
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
      noMembershipsHandler,
    ]);
    seedTokenOnly(env, server.origin);
    env.setPromptResponses(["yes"]);
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
    // 儀式の後の対話は「予備鍵か」の 1 問だけ(コード入力は無い)
    expect(env.prompts).toEqual([RESERVE_QUESTION]);
    expect(passkeyFetches(server).map((r) => r.path)).toEqual([
      `/auth/key-wraps/passkey/${registration.wrapId}`,
    ]);
    // 開いた予備鍵は保存されず、この端末の**新しい**端末鍵が生成・保存される(K4-1 / K4-10)
    const stored = env.keychain.get(masterKeyEntryName(server.origin, owner.userId));
    expect(stored).toBeDefined();
    expect(stored).not.toBe(serializedReserveRecord());
    expect(stored).not.toContain(reserve.encSkHex);
    expect(stored).not.toContain(reserve.sigSkSeedHex);
    expect(stored).not.toContain(reserve.encPubHex);
    const device = parseStoredMasterKey(stored ?? "");
    if (device === null) throw new Error("expected a well-formed device-key record");
    expect(device.suite).toBe("maruhi/v1");
    expect(device.encPubHex).toMatch(/^[0-9a-f]{64}$/);
    expect(device.sigPubHex).toMatch(/^[0-9a-f]{64}$/);
    expect(env.logs[0]).toBe("Generated this device's key and stored it in the OS keychain");
    expect(env.logs[1]).toMatch(/^key fingerprint: [0-9a-f]{32}$/);
    expect(env.logs[1]).not.toBe(`key fingerprint: ${reserve.fingerprintHex}`);
    expect(env.logs[2]).toBe(
      `Opened key ${reserve.fingerprintHex} from the recovery ledger. It is used only to register this machine's new device key, then discarded`,
    );
    expect(
      server.requests.filter((r) => r.method === "GET" && r.path === "/projects"),
    ).toHaveLength(1);
    const stderr = env.errors.join("\n");
    expect(stderr).toContain(
      "the reserve key was discarded from memory; it stays sealed in the recovery ledger only. This device now signs with its own key",
    );
    expect(stderr).not.toContain(PRF_HEX);
    expect(stderr).not.toContain(reserve.encSkHex);
  });

  it("「予備鍵ではない」と答えると記録せず、失効の案内を出す(端末鍵の生成は成立する)", async () => {
    const { registration } = await registerOnce();
    const { env, server } = await start([
      statusHandler([rowOf(registration)]),
      wrapHandler(registration.wrapId, registration),
      noMembershipsHandler,
    ]);
    seedTokenOnly(env, server.origin);
    env.setPromptResponses(["no"]);
    browserPosting(env, () => ({ credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX }));
    expect(await runCli(["key", "recover", "--passkey"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.prompts).toEqual([RESERVE_QUESTION]);
    expect(env.errors.join("\n")).toContain(
      `the opened key ${reserve.fingerprintHex} was not recorded as your reserve key. If it is the key of a lost or retired device, revoke it now: \`maruhi device revoke ${reserve.fingerprintHex}\`. Then create a separate reserve key with \`maruhi key recovery\``,
    );
    const stored = env.keychain.get(masterKeyEntryName(server.origin, owner.userId));
    expect(stored).toBeDefined();
    expect(stored).not.toBe(serializedReserveRecord());
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
        "Cannot decrypt the wrapped reserve key with this passkey",
        1,
      ],
    ];
    for (const [post, expected, fetches] of cases) {
      const { env, server } = await start([
        statusHandler([rowOf(registration)]),
        wrapHandler(registration.wrapId, registration),
        noMembershipsHandler,
      ]);
      seedTokenOnly(env, server.origin);
      browserPosting(env, () => post);
      expect(await runCli(["key", "recover", "--passkey"], env.layer), expected).toBe(1);
      expect(env.errors.join("\n"), expected).toContain(expected);
      expect(passkeyFetches(server), expected).toHaveLength(fetches);
      // 開封に失敗したら端末鍵の生成にも進まない
      expect(env.prompts, expected).toEqual([]);
      expect(env.keychain.has(masterKeyEntryName(server.origin, owner.userId)), expected).toBe(
        false,
      );
    }
    // サーバーが行と食い違うラップ(別 credential の登録)を返したら fail-closed
    const swapped = { ...registration, credentialIdHex: "ab".repeat(8) };
    const { env, server } = await start([
      statusHandler([rowOf(registration)]),
      wrapHandler(registration.wrapId, swapped),
      noMembershipsHandler,
    ]);
    seedTokenOnly(env, server.origin);
    browserPosting(env, () => ({ credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX }));
    expect(await runCli(["key", "recover", "--passkey"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "The wrap fetched from the server belongs to a different passkey",
    );
    expect(env.prompts).toEqual([]);
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
    // 端末鍵のある端末は、儀式にもサーバーにも触れる前に拒否する
    const hasKey = await start([statusHandler([row])]);
    seedSession(hasKey.env, hasKey.server.origin, owner);
    expect(await runCli(["key", "recover", "--passkey"], hasKey.env.layer)).toBe(1);
    expect(hasKey.env.errors.join("\n")).toContain(DEVICE_KEY_EXISTS_REFUSAL);
    expect(hasKey.env.browserOpens).toEqual([]);
    expect(hasKey.server.requests).toHaveLength(0);
    expect(hasKey.env.keychain.get(masterKeyEntryName(hasKey.server.origin, owner.userId))).toBe(
      serializedRecordOf(owner),
    );

    const agent = await start([statusHandler([row])]);
    seedTokenOnly(agent.env, agent.server.origin);
    agent.env.setAgent({ isAgent: true });
    expect(await runCli(["key", "recover", "--passkey"], agent.env.layer)).toBe(1);
    expect(agent.env.errors.join("\n")).toContain(
      "Refused to open the reserve key with a passkey because an AI agent environment was detected (the opened key would land in the agent's session; run this yourself on a human interactive terminal)",
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
  // 封印は台帳の開封(コード入力)が最初のゲート(recovery.ts)。復元・削除は
  // パスキー儀式のゲート(passkey.ts)
  const CEREMONIES = [
    { argv: ["key", "seal", "passkey"], noun: "Recovery-code entry", seed: "key" },
    { argv: ["key", "recover", "--passkey"], noun: "Passkey recovery", seed: "token" },
    { argv: ["key", "seal", "remove", WRAP_ID], noun: "Passkey wrap removal", seed: "token" },
  ] as const;

  it("stdin / stdout / stderr のどれか 1 つでも端末でなければ、サーバーにもブラウザにも触れずに拒否する", async () => {
    for (const ceremony of CEREMONIES) {
      for (const terminal of CHANNELS) {
        const label = `${ceremony.argv.join(" ")} ${JSON.stringify(terminal)}`;
        const { env, server } = await start([
          statusHandler([
            {
              wrapId: WRAP_ID,
              label: null,
              credentialIdHex: CREDENTIAL_HEX,
              prfSaltHex: "66".repeat(32),
              updatedAtMs: 1,
            },
          ]),
          ledger.handler,
          onRequest("DELETE", `/auth/key-wraps/passkey/${WRAP_ID}`, () => ({ status: 204 })),
        ]);
        if (ceremony.seed === "key") {
          seedDeviceAndLedger(env, server.origin);
        } else {
          seedTokenOnly(env, server.origin);
        }
        env.setTerminal(terminal);
        browserPosting(env, () => ({ credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX }));
        expect(await runCli([...ceremony.argv], env.layer), label).toBe(1);
        expect(env.errors.join("\n"), label).toContain(
          `${ceremony.noun} is only allowed on an interactive terminal (stdin, stdout, and stderr must all be terminals; pipes, redirects, CI, and AI agents are refused)`,
        );
        expect(env.prompts, label).toEqual([]);
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
        prfSaltHex: "66".repeat(32),
        updatedAtMs: 1754006400000,
      },
      {
        wrapId: OTHER_WRAP_ID,
        label: null,
        credentialIdHex: "ff".repeat(16),
        prfSaltHex: "77".repeat(32),
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
