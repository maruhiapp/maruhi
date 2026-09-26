// Integration tests for the passkey PRF path (CRYPTO_SPEC §8.2 /
// AUTH_SPEC §13-7 — KL3 K5, 2026-09-19 DK K4): `maruhi key seal passkey` /
// `maruhi key recover --passkey` / `maruhi key seal list|remove`. Wraps
// and decryptions are real crypto, the server is a wire-level mock, and
// the test plays the browser via `setBrowserOpenHandler` (POSTing the PRF
// in place of the page — integration-options.md supplement 20 ruling J).
//
// Properties pinned down:
//  1. Sealing runs "unseal the ledger (code / --passkey) → PRF → KEK →
//     wrap → POST last"; the ledger row opens with the same
//     `derivePasskeyKek` + master-wrap AAD (user_id / passkey-prf /
//     wrap_id) as the test vectors, and its contents are a **reserve-key**
//     record (not a device key)
//  2. Recovery fetches one ledger wrap, decrypts the reserve key with the
//     same PRF, generates a **new device key**, and stores it in the
//     keychain (the reserve key is never stored — K4-1). The blob fetch
//     happens exactly once before the ceremony (multiple registrations are
//     chosen by number)
//  3. Gates: agent environments, non-terminals, an existing key, no
//     registration, and the cap are all refused before the listener is
//     stood up (sealing hits the recovery-code gate first)
//  4. The page's reason codes map onto English guidance, and nothing is
//     written to the ledger
//  5. A pre-DK ledger (a device-key duplicate) is never sealed to — it
//     guides toward `maruhi key recovery`

import { decodeHex, derivePasskeyKek, unwrapMasterBlob, wrapMasterSecret } from "@maruhi/crypto";
import { Effect, Redacted } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  masterKeyEntryName,
  parseStoredMasterKey,
  serializeStoredMasterKey,
  tokenEntryName,
} from "../src/keychain.ts";
import { makeFileOwnDeviceStore, ownDevicesPathOf } from "../src/own-devices.ts";
import type { PrfPagePost } from "../src/passkey-page.ts";
import { formatRecoveryCode } from "../src/recovery-code.ts";
import { appendableProjectHandlers, projectListHandlerOf } from "./support/chain-handler.ts";
import {
  addOwnerDeviceOp,
  buildChain,
  genesisOp,
  makeTestUser,
  type TestUser,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

/** This device's device key (the side seeded into the keychain). */
let owner: TestUser;
/** The reserve key sealed in the ledger (the side that never enters the keychain). */
let reserve: TestUser;
/** The ledger — the reserve key wrapped with the recovery code (GET /auth/recovery) — and that code. */
let ledger: Ledger;
const servers: MockServer[] = [];

const PRF_HEX = "53ed1bf3f3a19eb2fda745bfcc680cc45739f1840514c10609a6863483fd260c";
const CREDENTIAL_HEX = "3cb8db37e0370e63a3849be601db91faf1306f83dcfb24c6428da106499921e2";
const WRAP_ID = "01JMKWRAP000000000000PASSK";
const OTHER_WRAP_ID = "01JMKWRAP000000000000THER0";

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

/** The project list the recovery tail (finishRecovery) scans (§11-5) — empty. */
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

/** The latest confirmation code shown on the terminal (stderr) — when two ceremonies run back to back it's the later one (unseal → register). */
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

/** Plays the browser: reads config.json and returns one POST carrying the terminal's code. */
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

/** Serialization of a key record (same shape as seedSession / the ledger). */
function serializedRecordOf(user: TestUser): string {
  return serializeStoredMasterKey({
    suite: "maruhi/v1",
    encPubHex: user.encPubHex,
    encSkHex: Redacted.make(user.encSkHex),
    sigPubHex: user.sigPubHex,
    sigSkSeedHex: Redacted.make(user.sigSkSeedHex),
    // The test's `reserve` is a CLI-generated reserve key (marked — DK K16).
    // Everything else is a device key
    ...(user === reserve ? { kind: "reserve" as const } : {}),
  });
}

/** Serialization of the reserve-key record sealed in the ledger (a sealed row's contents must be this). */
function serializedReserveRecord(): string {
  return serializedRecordOf(reserve);
}

interface Ledger {
  /** GET /auth/recovery (B wrapped with the recovery code). */
  readonly handler: MockHandler;
  /** The recovery code that opens the ledger (display form). */
  readonly code: string;
}

/**
 * Wraps `user`'s record under a known recovery code and serves it at GET
 * /auth/recovery (same assembly as recovery.test.ts). The AAD's user_id is
 * the session's user = owner.
 */
async function ledgerFor(user: TestUser): Promise<Ledger> {
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const wrapped = await wrapMasterSecret({
    recoverySecret: secret,
    userId: owner.userId,
    // JSON.stringify won't work — the secret side gets wrapped in
    // redactions (same trap as production recovery.ts)
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

/** Places the device key in the keychain and the reserve key in the ledger, and queues one code entry. */
function seedDeviceAndLedger(env: TestEnv, origin: string): void {
  seedSession(env, origin, owner);
  env.setPromptResponses([ledger.code]);
}

async function registerOnce(label?: string): Promise<{
  readonly registration: RegistrationBody;
  readonly env: TestEnv;
  readonly server: MockServer;
}> {
  // A value assigned inside a closure gets narrowed by TS, so receive it
  // in a box
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
  // Unsealing the ledger (code entry) comes before the ceremony (the
  // browser opens after unsealing)
  expect(env.prompts).toEqual(["Enter your recovery code: "]);
  expect(seen.config).toMatchObject({
    mode: "register",
    rpId: "localhost",
    userName: `maruhi · ${new URL(server.origin).host}`,
    excludeCredentialIdsHex: [],
  });
  const registration = captured.body;
  if (registration === null) throw new Error("registration was not posted");
  // The salt the page used and the salt sent to the ledger are the same
  // value (a disagreement would make recovery impossible)
  expect(seen.config).toMatchObject({ prfSaltHex: registration.prfSaltHex });
  return { registration, env, server };
}

describe("maruhi key seal passkey (registration)", () => {
  it("unseals the ledger, derives the KEK from the PRF, wraps reserve key B, and registers it on the ledger (POST comes last)", async () => {
    const { registration, env, server } = await registerOnce("MacBook Touch ID");
    expect(registration.rpId).toBe("localhost");
    expect(registration.credentialIdHex).toBe(CREDENTIAL_HEX);
    expect(registration.prfSaltHex).toMatch(/^[0-9a-f]{64}$/);
    expect(registration.label).toBe("MacBook Touch ID");
    expect(registration.wrap.suite).toBe("maruhi/v1");
    // The ledger row opens via the same path as the test vectors
    // (derivePasskeyKek + master-wrap AAD)
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
    // What gets sealed is the **reserve key** opened from the ledger, not
    // the device key in the keychain
    const sealed = new TextDecoder().decode(opened.value);
    expect(sealed).toBe(serializedReserveRecord());
    expect(sealed).not.toBe(serializedRecordOf(owner));
    expect(sealed).not.toContain(owner.encSkHex);
    // Transplanted to a different wrap_id it won't open (the AAD
    // binding)
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
    // The project list can't be read (this server doesn't serve it) =
    // can't be confirmed, but since the opened key carries the reserve-key
    // mark, seal it and record it as a reserve key (DK K16-6 — a marked
    // key can never be a device key)
    expect(stderr).not.toContain("could not list your projects");
    const recorded = await Effect.runPromise(
      makeFileOwnDeviceStore(ownDevicesPathOf(env.configPath)).load(server.origin, owner.userId),
    );
    expect(
      (recorded.state === "loaded" ? recorded.devices : []).map((row) => [
        row.keyFingerprintHex,
        row.source,
      ]),
    ).toEqual([[reserve.fingerprintHex, "reserve"]]);
    expect(stderr).toContain("Open this page in your browser");
    expect(stderr).toContain(env.browserOpens[0]);
    expect(stderr).not.toContain(PRF_HEX);
    expect(stderr).not.toContain(registration.wrap.ciphertextHex);
    expect(stderr).not.toContain(ledger.code);
    expect(stderr).not.toContain(reserve.encSkHex);
    // The keychain's device key is left untouched (not replaced by the
    // reserve key)
    expect(env.keychain.get(masterKeyEntryName(server.origin, owner.userId))).toBe(
      serializedRecordOf(owner),
    );
  });

  it("--passkey can unseal the ledger and seal (the unsealing ceremony → the registration ceremony)", async () => {
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

  it("with no label, label is not sent; a non-accepted --label form is a usage error (exit 2)", async () => {
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

  it("passes existing credentials as excludeCredentials and refuses at the cap (5) without opening the browser", async () => {
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

    // The cap check happens after unsealing the ledger (unsealing is the
    // qualification for changing it) and before the listener stands up
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

  it("a POST with a wrong confirmation code isn't accepted (and doesn't consume the ceremony); a retyped correct code passes", async () => {
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
      // The shape where a different-UID user picks up the token and
      // sends a fake PRF = doesn't know the code
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

  it("brute-forcing the confirmation code fails the whole ceremony and writes nothing to the ledger", async () => {
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

  it("the page's reason codes map to guidance and nothing is written to the ledger", async () => {
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

  it("never seals to a pre-DK ledger (a device-key duplicate) — guides toward `maruhi key recovery`", async () => {
    // Ledger B = this device's own key → sealing would only create one
    // more device-key duplicate, so refuse
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

  it("on a different device too, when the ledger's key is the chain's first key (a pre-DK duplicate), refuses to seal and guides toward `maruhi key recovery` (DK K14-4)", async () => {
    // Device = owner (the DK device). Ledger B = reserve, but on the chain
    // it's that person's genesis key
    const chain = await buildChain([
      { actor: reserve, operation: genesisOp(reserve) },
      { actor: reserve, operation: addOwnerDeviceOp(owner) },
    ]);
    const { env, server } = await start([
      statusHandler([]),
      ledger.handler,
      registerHandler(() => {}),
      projectListHandlerOf([chain]),
      ...appendableProjectHandlers(chain),
    ]);
    seedSession(env, server.origin, owner);
    env.setPromptResponses([ledger.code]);
    browserPosting(env, () => ({ credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX }));
    expect(await runCli(["key", "seal", "passkey"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      `The recovery ledger holds key ${reserve.fingerprintHex}, your first key on 1 project (${chain.projectId}) (the key you created or joined that project with): a copy of a device key from an install before device keys, not a separate reserve key. Run \`maruhi key recovery\` first: it creates a reserve key, seals it with a new recovery code and replaces the ledger. Then re-run \`maruhi key seal passkey\``,
    );
    expect(env.browserOpens).toEqual([]);
    expect(server.requests.filter((r) => r.method === "POST")).toHaveLength(0);
  });

  it("agent environments, non-terminals, and keyless devices are refused before the listener stands up (the code-entry gate first)", async () => {
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

    // Loading the device key precedes unsealing (a keyless device has no
    // qualification to seal)
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

/** A status passkey row (carries the public parameter prfSaltHex). */
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

describe("maruhi key recover --passkey (recovery)", () => {
  it("ceremonies across all credentials, fetches only the row of the answering credential's wrap, opens the reserve key, and stores a new device key (the fetch comes after the ceremony)", async () => {
    const { registration } = await registerOnce();
    // A different salt per row (pins the evalByCredential mapping —
    // identical salts couldn't detect a mix-up)
    const other = {
      ...registration,
      wrapId: OTHER_WRAP_ID,
      credentialIdHex: "ff".repeat(16),
      prfSaltHex: "77".repeat(32),
    };
    // The reserve key is a key owner's device added via add_device
    // (DK K14 — judged along the same path as the ledger)
    const chain = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addOwnerDeviceOp(reserve) },
    ]);
    const { env, server } = await start([
      statusHandler([rowOf(other, "YubiKey"), rowOf(registration, "Touch ID")]),
      wrapHandler(OTHER_WRAP_ID, other),
      wrapHandler(registration.wrapId, registration),
      projectListHandlerOf([chain]),
      ...appendableProjectHandlers(chain),
    ]);
    seedTokenOnly(env, server.origin);
    env.setPromptResponses(["yes"]);
    const seen: { config?: unknown; fetchesAtCeremony?: number } = {};
    browserPosting(
      env,
      () => {
        // At ceremony time the blob hasn't been fetched yet (the grounds
        // for an abort not consuming the window)
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
    // No interaction after the ceremony (no code entry, and a key
    // carrying the reserve-key mark is recorded without asking —
    // DK K16-3)
    expect(env.prompts).toEqual([]);
    expect(env.errors.join("\n")).toContain(
      `Note: recorded ${reserve.fingerprintHex} on this machine as your reserve key`,
    );
    expect(passkeyFetches(server).map((r) => r.path)).toEqual([
      `/auth/key-wraps/passkey/${registration.wrapId}`,
    ]);
    // The opened reserve key is not stored; a **new** device key for
    // this device is generated and stored (K4-1 / K4-10)
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

  it("when the opened key is the first key (a pre-DK duplicate), records it unasked but emits the revocation notice (the device-key generation itself stands — DK K14)", async () => {
    const { registration } = await registerOnce();
    // The ledger's key is the project's genesis key = that person's
    // first key
    const chain = await buildChain([{ actor: reserve, operation: genesisOp(reserve) }]);
    const { env, server } = await start([
      statusHandler([rowOf(registration)]),
      wrapHandler(registration.wrapId, registration),
      projectListHandlerOf([chain]),
      ...appendableProjectHandlers(chain),
    ]);
    seedTokenOnly(env, server.origin);
    browserPosting(env, () => ({ credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX }));
    expect(await runCli(["key", "recover", "--passkey"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.prompts).toEqual([]);
    expect(env.errors.join("\n")).toContain(
      `the opened key ${reserve.fingerprintHex} is your first key on 1 project (${chain.projectId}) (the key you created or joined that project with), so it is a copy of a device key from an install before device keys, not a reserve key, and it was not recorded as one. If the machine that held it is lost or retired, revoke it now: \`maruhi device revoke ${reserve.fingerprintHex}\`. Then run \`maruhi key recovery\`: it seals a separate reserve key in its place`,
    );
    const stored = env.keychain.get(masterKeyEntryName(server.origin, owner.userId));
    expect(stored).toBeDefined();
    expect(stored).not.toBe(serializedReserveRecord());
  });

  it("aborts, unregistered credentials, wrong PRFs, and a wrap disagreeing with the row don't recover; an abort fetches no blob", async () => {
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
      // When unsealing fails it doesn't proceed to device-key
      // generation
      expect(env.prompts, expected).toEqual([]);
      expect(env.keychain.has(masterKeyEntryName(server.origin, owner.userId)), expected).toBe(
        false,
      );
    }
    // A server returning a wrap disagreeing with the row (another
    // credential's registration) is fail-closed
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

  it("a rate limit after the ceremony becomes guidance and nothing remains in the keychain", async () => {
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

describe("maruhi key recover --passkey (precondition refusals)", () => {
  it("no registration, an existing key, agent environments, and non-terminals are refused before the listener stands up", async () => {
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
    // A device holding a device key is refused before touching the
    // ceremony or the server
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

  it("specifying --handoff and --passkey together is a usage error", async () => {
    const { env, server } = await start([]);
    seedTokenOnly(env, server.origin);
    expect(await runCli(["key", "recover", "--passkey", "--handoff"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Choose one of --handoff and --passkey");
  });
});

describe("the ceremony's 3-channel TTY gate (ADR-0016 decision 7)", () => {
  const CHANNELS = [
    { stdin: false, stdout: true, stderr: true },
    { stdin: true, stdout: false, stderr: true },
    { stdin: true, stdout: true, stderr: false },
  ] as const;
  // Sealing's first gate is unsealing the ledger (code entry)
  // (recovery.ts). Recovery and removal use the passkey ceremony's gate
  // (passkey.ts)
  const CEREMONIES = [
    { argv: ["key", "seal", "passkey"], noun: "Recovery-code entry", seed: "key" },
    { argv: ["key", "recover", "--passkey"], noun: "Passkey recovery", seed: "token" },
    { argv: ["key", "seal", "remove", WRAP_ID], noun: "Passkey wrap removal", seed: "token" },
  ] as const;

  it("if any one of stdin / stdout / stderr isn't a terminal, refuses without touching server or browser", async () => {
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
  it("list prints only the ledger's public parameters and remove deletes the row (with the terminal gate)", async () => {
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
    // list carries no gate (public information only)
    env.logs.length = 0;
    expect(await runCli(["key", "seal", "list"], env.layer)).toBe(0);
    expect(env.logs).toHaveLength(2);
  });

  it("list prints a single line saying so when there is no registration", async () => {
    const { env, server } = await start([statusHandler([])]);
    seedTokenOnly(env, server.origin);
    expect(await runCli(["key", "seal", "list"], env.layer)).toBe(0);
    expect(env.logs).toEqual([
      "No passkeys are registered (seal your key with `maruhi key seal passkey`)",
    ]);
  });
});
