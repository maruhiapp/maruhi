import { unwrapMasterSecret, wrapMasterSecret } from "@maruhi/crypto";
import { type GeneratedIdentity, generateIdentity, testUserId } from "@maruhi/test-kit";
import { Effect, Redacted } from "effect";
import { afterEach, describe, expect, it } from "vite-plus/test";

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
import { formatRecoveryCode, parseRecoveryCode } from "../src/reserve.package/recovery-code.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { ledgerHandlerFor, storedMasterRecord, storedReserveRecord } from "./support/ledger.ts";
import { type MockHandler, MockServer, offSpec, onEndpoint } from "./support/server.ts";

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
    JSON.stringify({
      token: "maruhi_pat_stored",
      userId,
      tokenId: "tok_1",
      expiresAtMs: 4_102_444_800_000,
    }),
  );
  return env;
}

function statusHandler(registered: boolean): MockHandler {
  return onEndpoint("auth.recoveryStatus", () => ({
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
  return onEndpoint("auth.recoveryPut", (request) => {
    record(request.body as PutBody);
    return { status: 204 };
  });
}

function noProjectsHandler(): MockHandler {
  return onEndpoint("membership.list", () => ({ status: 200, json: { projects: [] } }));
}

async function recordedReservesOf(
  env: TestEnv,
  origin: string,
  userId: string,
): Promise<readonly OwnDeviceEntry[]> {
  const loaded = await Effect.runPromise(
    makeFileOwnDeviceStore(ownDevicesPathOf(env.configPath)).load(origin, testUserId(userId)),
  );
  if (loaded.state !== "loaded") {
    return [];
  }
  return loaded.devices.filter(
    (device) => device.source === "reserve" && device.revokedAtMs === null,
  );
}

function storedDeviceRecord(env: TestEnv, origin: string, userId: string): StoredMasterKey {
  const record = parseStoredMasterKey(
    env.keychain.get(masterKeyEntryName(origin, testUserId(userId))) ?? "",
  );
  if (record === null) throw new Error("expected a device-key record in the keychain");
  return record;
}

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

function unwrapParsed(parsed: Redacted.Redacted<Uint8Array> | null): Uint8Array | null {
  return parsed === null ? null : Redacted.value(parsed);
}

describe("recovery-code notation (Base32)", () => {
  it("roundtrip: 32 bytes → 13 groups → restore (absorbs case / whitespace / hyphen differences)", () => {
    for (let round = 0; round < 8; round += 1) {
      const secret = crypto.getRandomValues(new Uint8Array(32));
      const code = Redacted.value(formatRecoveryCode(Redacted.make(secret)));
      expect(code).toMatch(/^[A-Z2-7]{4}(-[A-Z2-7]{4}){12}$/);
      expect(unwrapParsed(parseRecoveryCode(code))).toEqual(secret);
      expect(unwrapParsed(parseRecoveryCode(code.toLowerCase().replaceAll("-", " ")))).toEqual(
        secret,
      );
    }
  });

  it("rejects off-alphabet characters, wrong lengths, and non-zero padding", () => {
    const secret = new Uint8Array(32).fill(7);
    const code = Redacted.value(formatRecoveryCode(Redacted.make(secret)));
    expect(parseRecoveryCode(code.replace(/^./, "0"))).toBeNull();
    expect(parseRecoveryCode(code.replace(/^./, "1"))).toBeNull();
    expect(parseRecoveryCode(code.slice(0, -1))).toBeNull();
    expect(parseRecoveryCode(`${code}A`)).toBeNull();
    const symbols = code.replaceAll("-", "");
    const tampered = `${symbols.slice(0, -1)}H`;
    expect(parseRecoveryCode(tampered)).toBeNull();
  });
});

async function unwrapWithDisplayedCode(
  env: TestEnv,
  body: PutBody | null,
  userId: string,
): Promise<StoredMasterKey> {
  const secret = parseRecoveryCode(displayedCode(env));
  if (secret === null) throw new Error("expected a parsed recovery secret");
  const unwrapped = await unwrapMasterSecret({
    recoverySecret: Redacted.value(secret),
    userId: testUserId(userId),
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

describe("the reserve-key mark (CRYPTO_SPEC §8 — DK K16)", () => {
  const base = {
    suite: "maruhi/v1",
    encPubHex: "aa".repeat(32),
    encSkHex: "bb".repeat(32),
    sigPubHex: "cc".repeat(32),
    sigSkSeedHex: "dd".repeat(32),
  };

  it("the mark is carried on read and write and is absent on records without it", () => {
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

  it("an unknown mark value is not read — treated as a broken record", () => {
    expect(parseStoredMasterKey(JSON.stringify({ ...base, kind: "device" }))).toBeNull();
  });

  it("stops without using a marked key in the keychain as a device key", async () => {
    const user = await generateIdentity("user-0001");
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

describe("maruhi key generate recovery issuance", () => {
  it("issue → register → actually decryptable with the displayed code (roundtrip) + save verification", async () => {
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
    const reserve = await unwrapWithDisplayedCode(env, body, "user-0001");
    expect(reserve.suite).toBe("maruhi/v1");
    expect(reserve.encPubHex).toMatch(/^[0-9a-f]{64}$/);
    expect(reserve.kind).toBe("reserve");
    const device = storedDeviceRecord(env, maruhi.origin, "user-0001");
    expect(device.kind).toBeUndefined();
    expect(reserve.encPubHex).not.toBe(device.encPubHex);
    expect(serializeStoredMasterKey(reserve)).not.toBe(serializeStoredMasterKey(device));
    const reserves = await recordedReservesOf(env, maruhi.origin, "user-0001");
    expect(reserves).toHaveLength(1);
    expect(reserves[0]?.encPubHex).toBe(reserve.encPubHex);
    expect(reserves[0]?.sigPubHex).toBe(reserve.sigPubHex);
    expect(env.errors.join("\n")).toContain(
      `created your reserve key (fingerprint ${reserves[0]?.keyFingerprintHex})`,
    );
    expect(env.errors.join("\n")).toContain("Save confirmation complete");
    expect(env.logs.join("\n")).not.toContain(displayedCode(env));
    expect([...env.keychain.values()].join("\n")).not.toContain(Redacted.value(reserve.encSkHex));
  });

  it("does not generate fail-closed when the ledger state cannot be read (--new-identity excepted)", async () => {
    let statusAnswers = false;
    const status: MockHandler = (request) =>
      statusAnswers ? null : request.path === "/auth/recovery/status" ? { status: 404 } : null;
    const maruhi = await start([status, statusHandler(true), putHandler(() => {})]);
    const env = await loggedInEnv(maruhi.origin, "user-0001");
    expect(await runCli(["key", "generate"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Cannot check whether your account already has a recovery ledger",
    );
    expect(
      env.keychain.get(masterKeyEntryName(maruhi.origin, testUserId("user-0001"))),
    ).toBeUndefined();
    statusAnswers = true;
    env.setPromptResponses([lastGroupOf(env)]);
    expect(await runCli(["key", "generate", "--new-identity"], env.layer)).toBe(0);
    expect(
      env.keychain.get(masterKeyEntryName(maruhi.origin, testUserId("user-0001"))),
    ).toBeDefined();
    expect(env.errors.join("\n")).toContain("Replacing the existing recovery registration");
  });

  it("guides an account that already has a ledger to `maruhi device add` as a second device", async () => {
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
    expect(
      env.keychain.get(masterKeyEntryName(maruhi.origin, testUserId("user-0001"))),
    ).toBeUndefined();
  });

  it("fails after 3 save-verification failures but guides that the registration remains", async () => {
    const maruhi = await start([statusHandler(false), putHandler(() => {})]);
    const env = await loggedInEnv(maruhi.origin, "user-0001");
    env.setPromptResponses(["XXXX", "YYYY", "ZZZZ"]);
    expect(await runCli(["key", "generate"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Save confirmation failed");
    expect(errors).toContain("`maruhi key recovery`");
    expect(
      env.keychain.get(masterKeyEntryName(maruhi.origin, testUserId("user-0001"))),
    ).toBeDefined();
  });

  it("skips issuance in an AI-agent environment and guides toward a human device", async () => {
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
    expect(
      env.keychain.get(masterKeyEntryName(maruhi.origin, testUserId("user-0001"))),
    ).toBeDefined();
    expect(await recordedReservesOf(env, maruhi.origin, "user-0001")).toHaveLength(0);
  });

  it("key generation still succeeds when registration fails, and guides the re-issue command", async () => {
    const maruhi = await start([
      statusHandler(false),
      onEndpoint("auth.recoveryPut", () => offSpec({ status: 500, bodyText: "boom" })),
    ]);
    const env = await loggedInEnv(maruhi.origin, "user-0001");
    expect(await runCli(["key", "generate"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "the device key generation itself is complete; create the reserve key later with `maruhi key recovery`",
    );
    expect(
      env.keychain.get(masterKeyEntryName(maruhi.origin, testUserId("user-0001"))),
    ).toBeDefined();
    expect(await recordedReservesOf(env, maruhi.origin, "user-0001")).toHaveLength(0);
  });
});

describe("maruhi key recovery (issue / re-issue)", () => {
  it("generates a reserve key and seals it for the first time when unregistered", async () => {
    const user = await generateIdentity("user-0001");
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
    expect(storedDeviceRecord(env, maruhi.origin, user.userId).encPubHex).toBe(user.encPubHex);
  });

  it("when already registered (reserve key), opens the ledger first and re-issues with explicit notice that it is a replacement", async () => {
    const user = await generateIdentity("user-0001");
    const reserveUser = await generateIdentity("user-0001-reserve");
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
    const reserve = await unwrapWithDisplayedCode(env, put as PutBody | null, user.userId);
    expect(serializeStoredMasterKey(reserve)).toBe(
      serializeStoredMasterKey(storedReserveRecord(reserveUser)),
    );
    const reserves = await recordedReservesOf(env, maruhi.origin, user.userId);
    expect(reserves.map((entry) => entry.keyFingerprintHex)).toEqual([reserveUser.fingerprintHex]);
    expect(storedDeviceRecord(env, maruhi.origin, user.userId).encPubHex).toBe(user.encPubHex);
    expect([...env.keychain.values()].join("\n")).not.toContain(reserveUser.encSkHex);
  });

  it("--replace substitutes without opening the ledger (the escape hatch for a lost code)", async () => {
    const user = await generateIdentity("user-0001");
    let fetched = false;
    let put: PutBody | null = null;
    const maruhi = await start([
      statusHandler(true),
      onEndpoint("auth.recoveryGet", () => {
        fetched = true;
        return { status: 404, json: { _tag: "RecoveryWrapNotFound" } };
      }),
      putHandler((body) => {
        put = body;
      }),
      noProjectsHandler(),
      onEndpoint("keyWraps.status", () => ({
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
    expect(errors).toContain(
      "no previous reserve key is recorded on this machine, so none was revoked",
    );
    expect(errors).not.toContain("seal the current reserve key are deleted");
    expect(errors).not.toContain("run `maruhi key recovery --passkey` instead");
    expect(await recordedReservesOf(env, maruhi.origin, user.userId)).toHaveLength(1);
    const before = env.errors.length;
    expect(await runCli(["key", "recovery", "--passkey", "--replace"], env.layer)).toBe(2);
    expect(env.errors.slice(before).join("\n")).toContain(
      "--passkey cannot be combined with --replace",
    );
  });

  it("--replace shows the count and the --passkey alternative before writing when passkey rows exist, then removes them", async () => {
    const user = await generateIdentity("user-0001");
    const wrapId = "01JMKWRAP000000000000PASSK";
    const deleted: string[] = [];
    let put: PutBody | null = null;
    const maruhi = await start([
      statusHandler(true),
      putHandler((body) => {
        put = body;
      }),
      noProjectsHandler(),
      onEndpoint("keyWraps.status", () => ({
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
      onEndpoint("keyWraps.passkeyDelete", { wrapId }, () => {
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
    expect(errors.indexOf("replacing the recovery ledger")).toBeLessThan(
      errors.indexOf("Issued your recovery code"),
    );
    expect(deleted).toEqual([wrapId]);
    expect(errors).toContain("removed 1 passkey wrap and 0 guardian groups");
  });

  it("--replace does not stop the replacement when the ledger's row list is unreadable (warning in the general form + Note)", async () => {
    const user = await generateIdentity("user-0001");
    let put: PutBody | null = null;
    const maruhi = await start([
      statusHandler(true),
      putHandler((body) => {
        put = body;
      }),
      noProjectsHandler(),
      onEndpoint("keyWraps.status", () => offSpec({ status: 500, json: { _tag: "Internal" } })),
    ]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    seedSession(env, maruhi.origin, user);
    env.setPromptResponses([lastGroupOf(env)]);
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

  it("refuses issuance in an AI-agent environment", async () => {
    const user = await generateIdentity("user-0001");
    const maruhi = await start([statusHandler(false), putHandler(() => {})]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    seedSession(env, maruhi.origin, user);
    env.setAgent({ isAgent: true });
    expect(await runCli(["key", "recovery"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("AI agent environment");
  });

  it("refuses before issuance (before registration / display) when any of stdin / stdout / stderr is non-TTY", async () => {
    for (const terminal of [
      { stdin: false, stdout: true, stderr: true },
      { stdin: true, stdout: false, stderr: true },
      { stdin: true, stdout: true, stderr: false },
    ]) {
      const user = await generateIdentity("user-0001");
      let putSeen = false;
      const maruhi = await start([
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
      expect(putSeen).toBe(false);
      expect(env.errors.some((line) => /^ {4}[A-Z2-7]{4}-/.test(line))).toBe(false);
      expect(env.prompts).toHaveLength(0);
      expect(await recordedReservesOf(env, maruhi.origin, user.userId)).toHaveLength(0);
    }
  });
});

describe("maruhi key recover (restore)", () => {
  function wrappedBlobHandler(
    user: GeneratedIdentity,
    secret: Uint8Array,
  ): Promise<{ handler: MockHandler; code: string }> {
    return ledgerHandlerFor(storedReserveRecord(user), user.userId, secret);
  }

  it("opens the reserve key with the correct code, issues a new device key, and discards the reserve key", async () => {
    const user = await generateIdentity("user-0001");
    const reserveUser = await generateIdentity("user-0001-reserve");
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
    expect(env.prompts).toEqual(["Enter your recovery code: "]);
    const device = storedDeviceRecord(env, maruhi.origin, user.userId);
    expect(device.encPubHex).not.toBe(reserveUser.encPubHex);
    expect(device.encPubHex).toMatch(/^[0-9a-f]{64}$/);
    expect(serializeStoredMasterKey(device)).not.toBe(
      serializeStoredMasterKey(storedReserveRecord(reserveUser)),
    );
    const keychainDump = [...env.keychain.values()].join("\n");
    expect(keychainDump).not.toContain(reserveUser.encSkHex);
    expect(keychainDump).not.toContain(reserveUser.sigSkSeedHex);
    expect(await recordedReservesOf(env, maruhi.origin, user.userId)).toHaveLength(1);
    const output = env.logs.join("\n");
    expect(output).toContain("Generated this device's key and stored it in the OS keychain");
    expect(output).toContain(
      `Opened key ${reserveUser.fingerprintHex} from the recovery ledger. It is used only to register this machine's new device key, then discarded`,
    );
    const shown = env.logs.find((line) => line.startsWith("key fingerprint: "));
    expect(shown).toBeDefined();
    expect(shown).toMatch(/^key fingerprint: [0-9a-f]{32}$/);
    expect(shown).not.toBe(`key fingerprint: ${reserveUser.fingerprintHex}`);
    expect(env.errors.join("\n")).toContain(
      "the reserve key was discarded from memory; it stays sealed in the recovery ledger only. This device now signs with its own key",
    );
    expect(output).not.toContain(reserveUser.encSkHex);
    expect(output).not.toContain(code);
    expect(env.errors.join("\n")).not.toContain(reserveUser.encSkHex);
  });

  it("records a key carrying the reserve-key mark without asking, even on no chain (DK K16-6)", async () => {
    const user = await generateIdentity("user-0001");
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { handler, code } = await wrappedBlobHandler(user, secret);
    const maruhi = await start([handler, noProjectsHandler()]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    env.setPromptResponses([code]);
    expect(await runCli(["key", "recover"], env.layer)).toBe(0);
    expect(env.prompts).toEqual(["Enter your recovery code: "]);
    expect(await recordedReservesOf(env, maruhi.origin, user.userId)).toHaveLength(1);
    expect(env.errors.join("\n")).toContain(
      `Note: recorded ${user.fingerprintHex} on this machine as your reserve key`,
    );
    expect(storedDeviceRecord(env, maruhi.origin, user.userId).encPubHex).not.toBe(user.encPubHex);
  });

  it("does not dead-end an unknown-suite blob; guides toward updating and re-registering", async () => {
    const user = await generateIdentity("user-0001");
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const future = { ...storedMasterRecord(user), suite: "maruhi/v2" };
    const wrapped = await wrapMasterSecret({
      recoverySecret: secret,
      userId: user.userId,
      masterSecretBlob: new TextEncoder().encode(serializeStoredMasterKey(future)),
    });
    if (!wrapped.ok) throw new Error("test wrap failed");
    const maruhi = await start([
      onEndpoint("auth.recoveryGet", () => ({
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
    expect(errors).not.toContain("This code cannot restore");
    expect(errors).toContain("do not discard");
    expect(env.keychain.get(masterKeyEntryName(maruhi.origin, user.userId))).toBeUndefined();
  });

  it("distinguishes uninterpretable blobs by shape, and states re-registration belongs to another device", async () => {
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
      const user = await generateIdentity("user-0001");
      const secret = crypto.getRandomValues(new Uint8Array(32));
      const wrapped = await wrapMasterSecret({
        recoverySecret: secret,
        userId: user.userId,
        masterSecretBlob: new TextEncoder().encode(testCase.blob),
      });
      if (!wrapped.ok) throw new Error("test wrap failed");
      const maruhi = await start([
        onEndpoint("auth.recoveryGet", () => ({
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

  it("retries a wrong code locally and fails after 3 attempts (fetch happens once)", async () => {
    const user = await generateIdentity("user-0001");
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

  it("a tampered wrap gets the same retry wording as a wrong code (the full messages)", async () => {
    const user = await generateIdentity("user-0001");
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const wrapped = await wrapMasterSecret({
      recoverySecret: secret,
      userId: user.userId,
      masterSecretBlob: new TextEncoder().encode(
        serializeStoredMasterKey(storedReserveRecord(user)),
      ),
    });
    if (!wrapped.ok) throw new Error("test wrap failed");
    const tampered = wrapped.value.ciphertext.slice();
    tampered[0] = (tampered[0] ?? 0) ^ 0x01;
    const maruhi = await start([
      onEndpoint("auth.recoveryGet", () => ({
        status: 200,
        json: {
          suite: "maruhi/v1",
          nonceHex: Buffer.from(wrapped.value.nonce).toString("hex"),
          ciphertextHex: Buffer.from(tampered).toString("hex"),
          updatedAtMs: 1754006400000,
        },
      })),
      noProjectsHandler(),
    ]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    const code = Redacted.value(formatRecoveryCode(Redacted.make(secret)));
    env.setPromptResponses([code, code, code]);
    expect(await runCli(["key", "recover"], env.layer)).toBe(1);
    expect(env.errors).toEqual([
      "Cannot decrypt. Check that the code is correct",
      "Cannot decrypt. Check that the code is correct",
      "Cannot decrypt. Check that the code is correct",
      "maruhi: Recovery-code entry failed repeatedly. Check the code and re-run",
    ]);
    expect(env.keychain.get(masterKeyEntryName(maruhi.origin, user.userId))).toBeUndefined();
  });

  it("refuses code input in an AI-agent environment (the symmetric line to the issuance side)", async () => {
    const user = await generateIdentity("user-0001");
    let fetched = false;
    const maruhi = await start([
      onEndpoint("auth.recoveryGet", () => {
        fetched = true;
        return { status: 404, json: { _tag: "RecoveryWrapNotFound" } };
      }),
    ]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    env.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["key", "recover"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Refused to read a recovery code");
    expect(fetched).toBe(false);
  });

  it("refuses before the blob fetch when any of stdin / stdout / stderr is non-TTY", async () => {
    for (const terminal of [
      { stdin: false, stdout: true, stderr: true },
      { stdin: true, stdout: false, stderr: true },
      { stdin: true, stdout: true, stderr: false },
    ]) {
      const user = await generateIdentity("user-0001");
      let fetched = false;
      const maruhi = await start([
        onEndpoint("auth.recoveryGet", () => {
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

  it("refuses before touching the server on a device that already has a device key", async () => {
    const user = await generateIdentity("user-0001");
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

  it("guides the registration steps when unregistered (404)", async () => {
    const user = await generateIdentity("user-0001");
    const maruhi = await start([
      onEndpoint("auth.recoveryGet", () => ({
        status: 404,
        json: { _tag: "RecoveryWrapNotFound" },
      })),
    ]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    expect(await runCli(["key", "recover"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("No recovery code is registered for your account");
  });

  it("a rate limit (429) reports the seconds until retry", async () => {
    const user = await generateIdentity("user-0001");
    const maruhi = await start([
      onEndpoint("auth.recoveryGet", () => ({
        status: 429,
        json: { _tag: "RecoveryRateLimited", retryAfterSeconds: 1800 },
      })),
    ]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    expect(await runCli(["key", "recover"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("after 1800 seconds");
  });
});
