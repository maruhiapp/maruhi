// Integration tests for `maruhi guardian add / list / remove / wards`
// (CRYPTO_SPEC §8.3 / AUTH_SPEC §13-7 — KL3). Wraps and share sealing are
// real crypto; the server is a wire-level mock.
//
// Properties pinned down (2026-09-19 DK K4 — the wrap target B is not a
// device key but the **reserve key**):
//  1. add takes the guardian's key from **every device** of the
//     chain-derived current member, stands the §6.5 read-aloud ceremony
//     (re-entering the final word) once per device, then unseals the ledger
//     with the recovery code before registering. Registered shares open
//     under the guardian's secret key; with `any` a single share, with `all`
//     the XOR of all shares, decrypts B (= the ledger's reserve-key record,
//     not ward's device key) (roundtrip)
//  2. Non-members, self, duplicates, and a single-person `all` fail before
//     sending
//  3. Agent environments refuse the ceremony (don't let a non-interactive
//     caller decide where key material gets sealed)
//  4. list --project marks share rows disagreeing with the chain's current
//     device set as STALE

import {
  decodeHex,
  fingerprintToWords,
  joinGuardianShares,
  openGuardianShare,
  unwrapMasterBlob,
  wrapMasterSecret,
} from "@maruhi/crypto";
import { Redacted } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  masterKeyEntryName,
  serializeStoredMasterKey,
  type StoredMasterKey,
} from "../src/keychain.ts";
import { formatRecoveryCode } from "../src/recovery-code.ts";
import { chainHandlerOf } from "./support/chain-handler.ts";
import {
  addMemberOp,
  buildChain,
  type BuiltChain,
  genesisOp,
  makeTestUser,
  type TestUser,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

let ward: TestUser;
/** ward's reserve key (the B the ledger seals — a different key from the device key `ward`). */
let reserve: TestUser;
let alice: TestUser;
let bob: TestUser;
let built: BuiltChain;

const servers: MockServer[] = [];

beforeAll(async () => {
  ward = await makeTestUser("user-ward-0001");
  reserve = await makeTestUser("user-ward-0001");
  alice = await makeTestUser("user-alice-0002");
  bob = await makeTestUser("user-bob-00003");
  built = await buildChain([
    { actor: ward, operation: genesisOp(ward) },
    { actor: ward, operation: addMemberOp(alice, "member") },
    { actor: ward, operation: addMemberOp(bob, "member") },
  ]);
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

interface ShareBody {
  readonly shareIndex: number;
  readonly guardianUserId: string;
  readonly guardianEncPubHex: string;
  readonly guardianKeyFingerprintHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

interface CreateBody {
  readonly groupId: string;
  readonly mode: "any" | "all";
  readonly wrap: {
    readonly suite: string;
    readonly nonceHex: string;
    readonly ciphertextHex: string;
  };
  readonly shares: readonly ShareBody[];
}

function createHandler(record: (body: CreateBody) => void): MockHandler {
  return onRequest("POST", "/auth/key-wraps/guardians", (request) => {
    const body = request.body as CreateBody;
    record(body);
    return { status: 200, json: { groupId: body.groupId } };
  });
}

/** The ledger / reserve-key record (same shape as seedSession). */
function recordOf(user: TestUser): StoredMasterKey {
  return {
    suite: "maruhi/v1",
    encPubHex: user.encPubHex,
    encSkHex: Redacted.make(user.encSkHex),
    sigPubHex: user.sigPubHex,
    sigSkSeedHex: Redacted.make(user.sigSkSeedHex),
    // The test's `reserve` is a CLI-generated reserve key (marked — DK K16).
    // Everything else is a device key
    ...(user === reserve ? { kind: "reserve" as const } : {}),
  };
}

/** The serialized reserve-key record (the wrap's plaintext = the value the opened wrap must equal). */
function serializedReserve(): string {
  return serializeStoredMasterKey(recordOf(reserve));
}

/**
 * `GET /auth/recovery`: the ledger — ward's reserve-key record wrapped with
 * the recovery code (`guardian add` unseals the ledger before sealing the
 * shares — K4-2).
 */
async function recoveryHandler(): Promise<{ handler: MockHandler; code: string }> {
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const wrapped = await wrapMasterSecret({
    recoverySecret: secret,
    userId: ward.userId,
    // JSON.stringify(record) won't work — the secret side gets wrapped in
    // redactions (same trap as recovery.ts)
    masterSecretBlob: new TextEncoder().encode(serializedReserve()),
  });
  if (!wrapped.ok) throw new Error("test wrap failed");
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

interface Started {
  readonly env: TestEnv;
  readonly server: MockServer;
}

async function startEnv(handlers: readonly MockHandler[], user: TestUser): Promise<Started> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, user);
  await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
  return { env, server };
}

/** The number of registration sends (for the check that must fail before sending). */
function createCount(server: MockServer): number {
  return server.requests.filter(
    (request) => request.method === "POST" && request.path === "/auth/key-wraps/guardians",
  ).length;
}

/** The final word of the guardian's fingerprint (the §6.5 ceremony response). */
async function lastWordOf(user: TestUser): Promise<string> {
  const bytes = decodeHex(user.fingerprintHex);
  if (bytes === null) throw new Error("fingerprint hex");
  const words = await fingerprintToWords(bytes);
  if (!words.ok) throw new Error("fingerprint words");
  return words.value[words.value.length - 1] ?? "";
}

const hex = (value: string): Uint8Array => {
  const bytes = decodeHex(value);
  if (bytes === null) throw new Error("hex");
  return bytes;
};

/** Guardian `user` opens the share addressed to them (same shape as the server's share distribution). */
async function openShareAs(user: TestUser, body: CreateBody): Promise<Uint8Array> {
  const share = body.shares.find((entry) => entry.guardianUserId === user.userId);
  if (share === undefined) throw new Error("share missing");
  const opened = await openGuardianShare({
    guardianKeyPair: user.encKeyPair,
    wrapped: { enc: hex(share.encHex), ciphertext: hex(share.ciphertextHex) },
    context: {
      userId: ward.userId,
      groupId: body.groupId,
      mode: body.mode,
      shareIndex: share.shareIndex,
      guardianUserId: user.userId,
    },
  });
  if (!opened.ok) throw new Error("share did not open");
  return opened.value;
}

async function unwrapWith(kek: Uint8Array, body: CreateBody): Promise<string> {
  const unwrapped = await unwrapMasterBlob({
    kek,
    wrapped: { nonce: hex(body.wrap.nonceHex), ciphertext: hex(body.wrap.ciphertextHex) },
    context: { userId: ward.userId, kind: "guardian", wrapRef: body.groupId, mode: body.mode },
  });
  if (!unwrapped.ok) throw new Error("blob did not unwrap");
  return new TextDecoder().decode(unwrapped.value);
}

describe("maruhi guardian add", () => {
  it("any: registers via the ceremony and ledger unsealing, and a single guardian's share decrypts B (the reserve key) (roundtrip)", async () => {
    let created: CreateBody | null = null;
    const ledger = await recoveryHandler();
    const { env, server } = await startEnv(
      [
        chainHandlerOf(built),
        ledger.handler,
        createHandler((body) => {
          created = body;
        }),
      ],
      ward,
    );
    // Order: ceremony (the guardian's final word per device) → unsealing
    // the ledger (recovery code)
    env.setPromptResponses([await lastWordOf(alice), ledger.code]);
    expect(await runCli(["guardian", "add", "--mode", "any", alice.userId], env.layer)).toBe(0);
    const body = created as CreateBody | null;
    expect(body?.mode).toBe("any");
    expect(body?.groupId).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    // One share row per guardian device (the fixture's guardian has 1
    // device)
    expect(body?.shares.map((share) => share.guardianUserId)).toEqual([alice.userId]);
    expect(body?.shares[0]?.guardianKeyFingerprintHex).toBe(alice.fingerprintHex);
    expect(body?.shares[0]?.guardianEncPubHex).toBe(alice.encPubHex);
    if (body === null) throw new Error("no registration");
    // any: share = the KEK itself. The wrap's contents are the ledger's
    // reserve key, not ward's device key
    const share = await openShareAs(alice, body);
    const unwrapped = await unwrapWith(share, body);
    expect(unwrapped).toBe(serializedReserve());
    expect(unwrapped).not.toBe(env.keychain.get(masterKeyEntryName(server.origin, ward.userId)));
    expect(unwrapped).not.toContain(ward.encSkHex);
    // The ledger is unsealed once (GET /auth/recovery)
    expect(
      server.requests.filter((r) => r.method === "GET" && r.path === "/auth/recovery"),
    ).toHaveLength(1);
    // The ceremony display is the word list (stdout); key material and the
    // code appear nowhere
    const logs = env.logs.join("\n");
    expect(logs).toContain(`Guardian ${alice.userId} — device key fingerprint:`);
    expect(logs).toContain("Registered guardian group");
    expect(logs).toContain(`1. ${alice.userId} (1 device: ${alice.fingerprintHex})`);
    expect(env.errors.join("\n")).toContain(
      `opened the reserve key (fingerprint ${reserve.fingerprintHex}) for this change`,
    );
    expect(logs).not.toContain(reserve.encSkHex);
    expect(env.errors.join("\n")).not.toContain(reserve.encSkHex);
    expect(logs).not.toContain(ledger.code);
    expect(env.errors.join("\n")).not.toContain(ledger.code);
  });

  it("all: B decrypts only under the XOR of every guardian's share", async () => {
    let created: CreateBody | null = null;
    const ledger = await recoveryHandler();
    const { env } = await startEnv(
      [
        chainHandlerOf(built),
        ledger.handler,
        createHandler((body) => {
          created = body;
        }),
      ],
      ward,
    );
    env.setPromptResponses([await lastWordOf(alice), await lastWordOf(bob), ledger.code]);
    expect(
      await runCli(["guardian", "add", "--mode", "all", alice.userId, bob.userId], env.layer),
    ).toBe(0);
    const body = created as CreateBody | null;
    if (body === null) throw new Error("no registration");
    expect(body.mode).toBe("all");
    expect(body.shares.map((share) => share.shareIndex)).toEqual([1, 2]);
    const shareA = await openShareAs(alice, body);
    const shareB = await openShareAs(bob, body);
    const joined = joinGuardianShares({ mode: "all", shares: [shareA, shareB], expectedCount: 2 });
    if (!joined.ok) throw new Error("join");
    expect(await unwrapWith(joined.value, body)).toBe(serializedReserve());
    // A single share alone cannot open it
    await expect(unwrapWith(shareA, body)).rejects.toThrow();
  });

  it("on ceremony failure the ledger is never opened, nothing is registered, and no key material is sent", async () => {
    let createSeen = false;
    const ledger = await recoveryHandler();
    const { env, server } = await startEnv(
      [
        chainHandlerOf(built),
        ledger.handler,
        createHandler(() => {
          createSeen = true;
        }),
      ],
      ward,
    );
    env.setPromptResponses(["wrong", "wrong", "wrong"]);
    expect(await runCli(["guardian", "add", "--mode", "any", alice.userId], env.layer)).toBe(1);
    expect(createSeen).toBe(false);
    expect(env.errors.join("\n")).toContain("Guardian key fingerprint confirmation failed");
    // If the ceremony doesn't pass, it never reaches unsealing the ledger
    // (code entry)
    expect(server.requests.some((r) => r.path === "/auth/recovery")).toBe(false);
  });

  it("when the ledger is a device-key duplicate (pre-DK), guides toward `key recovery` first and does not register", async () => {
    let createSeen = false;
    // The ledger is wrapping ward's device key itself (the legacy master
    // key)
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const wrapped = await wrapMasterSecret({
      recoverySecret: secret,
      userId: ward.userId,
      masterSecretBlob: new TextEncoder().encode(serializeStoredMasterKey(recordOf(ward))),
    });
    if (!wrapped.ok) throw new Error("test wrap failed");
    const { env } = await startEnv(
      [
        chainHandlerOf(built),
        onRequest("GET", "/auth/recovery", () => ({
          status: 200,
          json: {
            suite: "maruhi/v1",
            nonceHex: Buffer.from(wrapped.value.nonce).toString("hex"),
            ciphertextHex: Buffer.from(wrapped.value.ciphertext).toString("hex"),
            updatedAtMs: 1754006400000,
          },
        })),
        createHandler(() => {
          createSeen = true;
        }),
      ],
      ward,
    );
    env.setPromptResponses([
      await lastWordOf(alice),
      Redacted.value(formatRecoveryCode(Redacted.make(secret))),
    ]);
    expect(await runCli(["guardian", "add", "--mode", "any", alice.userId], env.layer)).toBe(1);
    expect(createSeen).toBe(false);
    expect(env.errors.join("\n")).toContain(
      "The recovery ledger holds a copy of this device's key (an install from before device keys), not a separate reserve key. Run `maruhi key recovery` first: it creates a reserve key, seals it with a new recovery code and replaces the ledger. Then re-run `maruhi guardian add …`",
    );
  });

  it("non-members, self, duplicates, and a single-person `all` fail before sending", async () => {
    const { env, server } = await startEnv([chainHandlerOf(built), createHandler(() => {})], ward);
    expect(await runCli(["guardian", "add", "--mode", "any", "user-stranger"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("is not a current member of project");
    expect(await runCli(["guardian", "add", "--mode", "any", ward.userId], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("You cannot be your own guardian");
    expect(
      await runCli(["guardian", "add", "--mode", "any", alice.userId, alice.userId], env.layer),
    ).toBe(2);
    expect(env.errors.join("\n")).toContain("The same user was given more than once");
    expect(await runCli(["guardian", "add", "--mode", "all", alice.userId], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Mode all needs at least 2 guardians");
    expect(await runCli(["guardian", "add", "--mode", "some", alice.userId], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Specify --mode (any | all)");
    expect(createCount(server)).toBe(0);
  });

  it("refuses the ceremony in AI-agent environments and non-terminals (same gate as the handoff)", async () => {
    let createSeen = false;
    const { env } = await startEnv(
      [
        chainHandlerOf(built),
        createHandler(() => {
          createSeen = true;
        }),
      ],
      ward,
    );
    env.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["guardian", "add", "--mode", "any", alice.userId], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("an AI agent environment was detected");
    // The piped-stdin form of answering the ceremony prompt
    // (non-terminal) is also refused
    env.setAgent({ isAgent: false });
    env.setTerminal({ stdin: false });
    env.setPromptResponses([await lastWordOf(alice)]);
    expect(await runCli(["guardian", "add", "--mode", "any", alice.userId], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("only allowed on an interactive terminal");
    expect(createSeen).toBe(false);
  });
});

function statusHandler(groups: readonly unknown[]): MockHandler {
  return onRequest("GET", "/auth/key-wraps", () => ({
    status: 200,
    json: {
      recoveryCode: { registered: true, updatedAtMs: 1754006400000 },
      passkeys: [],
      guardianGroups: groups,
    },
  }));
}

const GROUP_ID = "01J9Z8Y7X6W5V4T3S2R1Q0P9N8";

describe("maruhi guardian list / remove / wards", () => {
  it("list --project marks share rows disagreeing with the chain's current device set as STALE", async () => {
    const { env } = await startEnv(
      [
        chainHandlerOf(built),
        statusHandler([
          {
            groupId: GROUP_ID,
            mode: "all",
            createdAtMs: 1754006400000,
            guardians: [
              {
                shareIndex: 1,
                guardianUserId: alice.userId,
                guardianKeyFingerprintHex: alice.fingerprintHex,
              },
              {
                shareIndex: 2,
                guardianUserId: bob.userId,
                guardianKeyFingerprintHex: "00".repeat(16),
              },
            ],
          },
        ]),
      ],
      ward,
    );
    expect(await runCli(["guardian", "list", "--project", built.projectId], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(`${GROUP_ID}  mode all  2 guardians`);
    expect(logs).toContain(`  1. ${alice.userId} (1 device: ${alice.fingerprintHex})`);
    expect(logs).not.toContain(`  1. ${alice.userId} (1 device: ${alice.fingerprintHex})  STALE`);
    expect(logs).toContain(`  2. ${bob.userId} (1 device: ${"00".repeat(16)})  STALE`);
    expect(env.errors.join("\n")).toContain(
      `${bob.userId} has none of these devices on the chain any more, so their share cannot be opened — this all-mode group can no longer restore your reserve key. Remove the group and add it again`,
    );
  });

  it("list suggests add when there is no group", async () => {
    const { env } = await startEnv([statusHandler([])], ward);
    expect(await runCli(["guardian", "list"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("No guardian groups");
  });

  it("remove succeeds on 204; a 404 suggests the list", async () => {
    let deletes = 0;
    const { env } = await startEnv(
      [
        onRequest("DELETE", `/auth/key-wraps/guardians/${GROUP_ID}`, () => {
          deletes += 1;
          return deletes === 1
            ? { status: 204 }
            : { status: 404, json: { _tag: "KeyWrapNotFound" } };
        }),
      ],
      ward,
    );
    expect(await runCli(["guardian", "remove", GROUP_ID], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain(`Removed guardian group ${GROUP_ID}`);
    expect(await runCli(["guardian", "remove", GROUP_ID], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("No guardian group with that ID");
  });

  it("wards lists the wards you are a guardian of", async () => {
    const { env } = await startEnv(
      [
        onRequest("GET", "/auth/guardian/wards", () => ({
          status: 200,
          json: {
            wards: [
              {
                wardUserId: ward.userId,
                wardLogin: "ward-login",
                groupId: GROUP_ID,
                mode: "any",
                shareIndex: 1,
                createdAtMs: 1754006400000,
              },
            ],
          },
        })),
      ],
      alice,
    );
    expect(await runCli(["guardian", "wards"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain(
      `ward-login (${ward.userId})  group ${GROUP_ID}  mode any  share 1`,
    );
  });
});
