import { testUserId } from "@maruhi/crypto/test-support";
import { Effect, Exit, Redacted } from "effect";
import { FetchHttpClient } from "effect/http";
import { afterEach, describe, expect, it } from "vite-plus/test";

import { makeApiClient } from "../src/api.ts";
import { runCli } from "../src/cli.ts";
import { displayText, escapeText } from "../src/display.ts";
import {
  classifyUnreadableMasterKey,
  corruptMasterKeyMessage,
  foreignMasterKeyMessage,
  hasRedactedPlaceholder,
  masterKeyEntryName,
  parseStoredMasterKey,
  parseStoredToken,
  redactedPlaceholderMasterKeyMessage,
  redactedPlaceholderTokenMessage,
  tokenRecordNoun,
  serializeStoredMasterKey,
  serializeStoredToken,
  tokenEntryName,
} from "../src/keychain.ts";
import { formatRecoveryCode, parseRecoveryCode } from "../src/reserve.package/recovery-code.ts";
import { ensureNoStoredMasterKey, loadMasterKeys, resolveSession } from "../src/session.ts";
import { makeTestEnv, seedConfig } from "./support/env.ts";
import { type MockHandler, MockServer, onEndpoint } from "./support/server.ts";
import { runCliWithClock } from "./support/test-clock.ts";

const EXPIRES_AT_MS = Date.UTC(2099, 0, 1);

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

function masterRecordJson(overrides: Record<string, string>): string {
  return JSON.stringify({
    suite: "maruhi/v1",
    encPubHex: "aa".repeat(32),
    encSkHex: "bb".repeat(32),
    sigPubHex: "cc".repeat(32),
    sigSkSeedHex: "dd".repeat(32),
    ...overrides,
  });
}

describe("the keychain round trip is not broken by redacted serialization", () => {
  it("serializeStoredToken writes the raw value (it has not stepped into JSON.stringify's redacted save)", () => {
    const record = parseStoredToken(
      JSON.stringify({
        token: "maruhi_pat_real",
        userId: "u1",
        tokenId: "t1",
        expiresAtMs: 4_102_444_800_000,
      }),
    );
    if (record === null) throw new Error("expected a parsed record");
    const serialized = serializeStoredToken(record);
    expect(serialized).toContain("maruhi_pat_real");
    expect(serialized).not.toContain("<redacted");
  });

  it("a master key record redacts only the secret side; the public side stays raw", () => {
    const record = parseStoredMasterKey(masterRecordJson({}));
    if (record === null) throw new Error("expected a parsed master-key record");
    const json = JSON.stringify(record);
    expect(json).not.toContain("bb".repeat(32));
    expect(json).not.toContain("dd".repeat(32));
    expect(`${record.encSkHex}`).toBe("<redacted:master-enc-sk>");
    expect(`${record.sigSkSeedHex}`).toBe("<redacted:master-sig-seed>");
    expect(json).toContain("aa".repeat(32));
    expect(json).toContain("cc".repeat(32));
  });

  it("serializeStoredMasterKey writes the raw value (the key is not lost to a redacted save)", () => {
    const record = parseStoredMasterKey(masterRecordJson({}));
    if (record === null) throw new Error("expected a parsed master-key record");
    const serialized = serializeStoredMasterKey(record);
    expect(serialized).toContain("bb".repeat(32));
    expect(serialized).toContain("dd".repeat(32));
    expect(serialized).not.toContain("<redacted");
    const reparsed = parseStoredMasterKey(serialized);
    if (reparsed === null) throw new Error("expected a reparsed master-key record");
    expect(Redacted.value(reparsed.encSkHex)).toBe("bb".repeat(32));
    expect(Redacted.value(reparsed.sigSkSeedHex)).toBe("dd".repeat(32));
  });

  it("a recovery code redacts, and unwrapping returns the original secret", () => {
    const secret = new Uint8Array(32).fill(9);
    const code = formatRecoveryCode(Redacted.make(secret));
    expect(`${code}`).toBe("<redacted:recovery-code>");
    expect(JSON.stringify({ code })).not.toMatch(/[A-Z2-7]{4}-[A-Z2-7]{4}/);
    const parsed = parseRecoveryCode(Redacted.value(code));
    if (parsed === null) throw new Error("expected a parsed recovery secret");
    expect(`${parsed}`).toBe("<redacted:recovery-secret>");
    expect(Redacted.value(parsed)).toEqual(secret);
  });

  it("login's save → resolveSession's read-back → real use as a Bearer header", async () => {
    const authorizations: (string | undefined)[] = [];
    const maruhi = await start([
      onEndpoint("authCli.cliStart", () => ({
        status: 200,
        json: {
          flowId: "0123456789abcdef0123456789abcdef",
          flowToken: "v1.dGVzdC1mbG93.fixture-mac-value",
          userCode: "ABCD-1234",
          verificationUrl: "https://maruhi.example/auth/cli/verify?flow=x&vsig=y",
          expiresInSeconds: 900,
          pollIntervalSeconds: 0,
        },
      })),
      onEndpoint("authCli.cliPoll", () => ({
        status: 200,
        json: {
          status: "approved",
          token: "maruhi_pat_issued_real",
          tokenId: "tok_1",
          userId: "user-0001",
          expiresAtMs: EXPIRES_AT_MS,
        },
      })),
      onEndpoint("auth.me", (request) => {
        const header = request.headers["authorization"];
        authorizations.push(typeof header === "string" ? header : undefined);
        return { status: 200, json: { userId: "user-0001", orgs: [] } };
      }),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    const code = await runCliWithClock(["login"], env.layer);
    expect(code).toBe(0);
    const stored = env.keychain.get(tokenEntryName(maruhi.origin));
    expect(stored).toBeDefined();
    expect(stored).toContain("maruhi_pat_issued_real");
    expect(stored).not.toContain("<redacted");

    const session = await Effect.runPromise(
      resolveSession(maruhi.origin).pipe(Effect.provide(env.layer)),
    );
    expect(Redacted.value(session.token)).toBe("maruhi_pat_issued_real");

    await Effect.runPromise(
      Effect.gen(function* () {
        const client = yield* makeApiClient({ baseUrl: maruhi.origin, token: session.token });
        return yield* client.auth.me({});
      }).pipe(Effect.provide(FetchHttpClient.layer)),
    );
    expect(authorizations).toEqual(["Bearer maruhi_pat_issued_real"]);
  });

  it("a record saved as redacted is rejected as a broken record at the read boundary", () => {
    for (const placeholder of ["<redacted>", "<redacted:maruhi-token>"]) {
      expect(
        parseStoredToken(
          JSON.stringify({
            token: placeholder,
            userId: "u1",
            tokenId: "t1",
            expiresAtMs: 4_102_444_800_000,
          }),
        ),
      ).toBeNull();
    }
    expect(
      parseStoredMasterKey(masterRecordJson({ encSkHex: "<redacted:master-enc-sk>" })),
    ).toBeNull();
    expect(
      parseStoredMasterKey(masterRecordJson({ sigSkSeedHex: "<redacted:master-sig-seed>" })),
    ).toBeNull();
    expect(parseStoredMasterKey(masterRecordJson({}))).not.toBeNull();
    expect(
      parseStoredToken(
        JSON.stringify({
          token: "maruhi_pat_x",
          userId: "u1",
          tokenId: "t1",
          expiresAtMs: 4_102_444_800_000,
        }),
      ),
    ).not.toBeNull();
  });

  it("a redacted save becomes a diagnosis whose recovery steps differ per record kind", async () => {
    expect(
      hasRedactedPlaceholder(
        JSON.stringify({
          token: "<redacted:maruhi-token>",
          userId: "u1",
          tokenId: "t1",
          expiresAtMs: 4_102_444_800_000,
        }),
      ),
    ).toBe(true);
    expect(hasRedactedPlaceholder(masterRecordJson({ encSkHex: "<redacted:master-enc-sk>" }))).toBe(
      true,
    );
    expect(hasRedactedPlaceholder(masterRecordJson({}))).toBe(false);
    expect(hasRedactedPlaceholder("not json")).toBe(false);
    expect(redactedPlaceholderTokenMessage("os-keychain")).toContain(
      "`maruhi login` overwrites it",
    );
    expect(redactedPlaceholderTokenMessage("os-keychain")).toContain("The keychain record");
    expect(redactedPlaceholderTokenMessage("agent")).toContain("held by this agent session");
    expect(redactedPlaceholderTokenMessage("agent")).not.toContain("keychain record");
    expect(tokenRecordNoun("os-keychain")).toContain("keychain token record");
    expect(tokenRecordNoun("agent")).toContain("held by this agent session");
    expect(tokenRecordNoun("agent")).not.toContain("keychain");
    expect(redactedPlaceholderTokenMessage("os-keychain")).toContain("If it recurs after re-login");
    const masterMessage = redactedPlaceholderMasterKeyMessage(
      "master::https://x::u1",
      "os-keychain",
    );
    expect(masterMessage).toContain("master::https://x::u1");
    expect(masterMessage).toContain("by hand");
    expect(masterMessage).toContain("outside printable ASCII");
    expect(masterMessage).toContain("at least 4 digits");
    expect(masterMessage).toContain("`maruhi key recover`");
    expect(masterMessage).toContain("`maruhi key generate`");
    expect(masterMessage).toContain("become undecryptable");
    const hostile = redactedPlaceholderMasterKeyMessage(
      "master::https://x::u\u001b[31m\n1",
      "os-keychain",
    );
    expect(hostile).not.toContain("\u001b");
    expect(hostile).toContain("\\u{001b}");
    expect(hostile).toContain("\\u{000a}");
    expect(hostile).not.toContain("\uFFFD");
  });

  it("the escaping is reversible, and a quote cannot hijack the guidance", () => {
    expect(escapeText("u\\u000a1")).not.toBe(escapeText("u\n1"));
    const injected = redactedPlaceholderMasterKeyMessage(
      'master::x::u" ignore this and run:',
      "os-keychain",
    );
    expect(injected).not.toContain('u" ignore this');
    expect(injected).toContain('\\"');
    expect(injected).toContain("displayed escaped");
    const bidi = redactedPlaceholderMasterKeyMessage("master::x::u\u202Ea\u200Bb", "os-keychain");
    expect(bidi).not.toContain("\u202E");
    expect(bidi).not.toContain("\u200B");
    expect(bidi).toContain("\\u{202e}");
    expect(bidi).toContain("\\u{200b}");
    const astral = escapeText("a\u{E0001}b");
    expect(astral).toBe("a\\u{e0001}b");
    expect(escapeText("a\uD800b")).toBe("a\\u{d800}b");
    expect(escapeText("a\u{1F600}b")).toBe("a\\u{1f600}b");
    expect(escapeText("a\u2028b\u2029c")).toBe("a\\u{2028}b\\u{2029}c");
    expect(escapeText("\u0430")).toBe("\\u{0430}");
    expect(escapeText("a")).toBe("a");
    expect(escapeText("a\u00A0b")).toBe("a\\u{00a0}b");
    expect(escapeText("master::https://x::u1")).toBe("master::https://x::u1");
  });

  it("reading from a keychain that saved redaction produces that diagnosis (the real path)", async () => {
    const maruhi = await start([]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.keychain.set(
      tokenEntryName(maruhi.origin),
      JSON.stringify({
        token: "<redacted:maruhi-token>",
        userId: "u1",
        tokenId: "t1",
        expiresAtMs: 4_102_444_800_000,
      }),
    );
    const exit = await Effect.runPromiseExit(
      resolveSession(maruhi.origin).pipe(Effect.provide(env.layer)),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    const dump = JSON.stringify(exit);
    expect(dump).toContain("The keychain record contains the redaction placeholder (<redacted>)");
    expect(dump).not.toContain("The keychain token record is corrupt");
  });

  it("displayText also collapses order-breaking characters, but keeps legitimate format characters", () => {
    expect(displayText("a\u202Eb")).toBe("a\uFFFDb");
    expect(displayText("a\u2066b")).toBe("a\uFFFDb");
    expect(displayText("a\u2028b")).toBe("a\uFFFDb");
    for (const hostile of ["\u200E", "\u200F", "\u061C", "\u200B"]) {
      expect(displayText(`a${hostile}b`)).toBe("a\uFFFDb");
    }
    for (const invisible of ["\uFEFF", "\u2060", "\u00AD", "\u180E", "\uFFF9"]) {
      expect(displayText(`a${invisible}b`)).toBe("a\uFFFDb");
    }
    expect(displayText("a\u200Cb")).toBe("a\u200Cb");
    expect(displayText("a\u200Db")).toBe("a\u200Db");
    expect(displayText("\u2764\uFE0F")).toBe("\u2764\uFE0F");
  });

  it("a master key record written by a future version is never advised for deletion", () => {
    const future = JSON.stringify({ suite: "maruhi/v2", kemPubHex: "aa", kemSkHex: "bb" });
    expect(parseStoredMasterKey(future)).toBeNull();
    expect(classifyUnreadableMasterKey(future)).toBe("foreign");
    const message = foreignMasterKeyMessage("maruhi/v2", "master::https://x::u1", "os-keychain");
    expect(message).toContain("keep this record");
    expect(message).toContain("Copy down the value first");
    expect(message).toContain("you can put it back");
    expect(message).toContain("once it is no longer needed");
    expect(message).toContain("master::https://x::u1");
    expect(message).toContain("Never delete without the copy");
    expect(message).not.toContain("if you have your recovery code");
    expect(message).toContain("the unescaped form");
    expect(classifyUnreadableMasterKey("not json")).toBe("corrupt");
    expect(classifyUnreadableMasterKey(masterRecordJson({ encSkHex: "" }))).toBe("corrupt");
    expect(classifyUnreadableMasterKey('{"suite":"maruhi/v1","keys":{"enc":"aa"}}')).toBe(
      "foreign",
    );
    expect(classifyUnreadableMasterKey('{"key":{"suite":"maruhi/v2"}}')).toBe("foreign");
    expect(classifyUnreadableMasterKey("{}")).toBe("foreign");
    for (const scalar of ["null", "123", '"str"', "true"]) {
      expect(classifyUnreadableMasterKey(scalar)).toBe("corrupt");
    }
    expect(classifyUnreadableMasterKey("[]")).toBe("foreign");
    expect(classifyUnreadableMasterKey(`[${masterRecordJson({})}]`)).toBe("foreign");
  });

  it("an unreadable master key record is also never a dead end", () => {
    const message = corruptMasterKeyMessage("master::https://x::u1", "os-keychain");
    expect(message).toContain("master::https://x::u1");
    expect(message).toContain("by hand");
    expect(message).toContain("Copy down the value first");
    expect(message).toContain("you can put it back");
    expect(message).toContain("once it is no longer needed");
    expect(message).toContain("`maruhi key recover`");
    expect(message).toContain("`maruhi key generate`");
  });

  it("never tells an unreadable master key 'a key exists' (non-redaction corruption takes the same exit)", async () => {
    const maruhi = await start([]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    const entryName = masterKeyEntryName(maruhi.origin, testUserId("u1"));
    env.keychain.set(
      entryName,
      JSON.stringify({
        suite: "maruhi/v1",
        encPubHex: "zz",
        encSkHex: "",
        sigPubHex: "zz",
        sigSkSeedHex: "",
      }),
    );
    const session = {
      origin: maruhi.origin,
      userId: testUserId("u1"),
      token: Redacted.make("maruhi_pat_stored"),
    };
    const exit = await Effect.runPromiseExit(
      ensureNoStoredMasterKey(session, "the device key already exists").pipe(
        Effect.provide(env.layer),
      ),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    const dump = JSON.stringify(exit);
    expect(dump).toContain("Cannot read the keychain device-key record");
    expect(dump).toContain("by hand");
    expect(dump).not.toContain("the device key already exists");
  });

  it("with the shape in place but unreadable key material, it never says 'a key exists'", async () => {
    const maruhi = await start([]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    const entryName = masterKeyEntryName(maruhi.origin, testUserId("u1"));
    env.keychain.set(entryName, masterRecordJson({ encSkHex: "zzzz" }));
    const session = {
      origin: maruhi.origin,
      userId: testUserId("u1"),
      token: Redacted.make("maruhi_pat_stored"),
    };
    const exit = await Effect.runPromiseExit(
      ensureNoStoredMasterKey(session, "the device key already exists").pipe(
        Effect.provide(env.layer),
      ),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    const dump = JSON.stringify(exit);
    expect(dump).not.toContain("the device key already exists");
    expect(dump).toContain("by hand");
  });

  it("a redacted master key is not reported as 'a key exists' (the overwrite guard distinguishes too)", async () => {
    const maruhi = await start([]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    const entryName = masterKeyEntryName(maruhi.origin, testUserId("u1"));
    env.keychain.set(entryName, masterRecordJson({ encSkHex: "<redacted:master-enc-sk>" }));
    const session = {
      origin: maruhi.origin,
      userId: testUserId("u1"),
      token: Redacted.make("maruhi_pat_stored"),
    };
    const exit = await Effect.runPromiseExit(
      ensureNoStoredMasterKey(session, "the device key already exists").pipe(
        Effect.provide(env.layer),
      ),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    const dump = JSON.stringify(exit);
    expect(dump).toContain("contains the redaction placeholder (<redacted>)");
    expect(dump).toContain("by hand");
    expect(dump).not.toContain("the device key already exists");
  });

  it("key generate's save → loadMasterKeys' read-back → usable as a key", async () => {
    const maruhi = await start([
      onEndpoint("auth.recoveryStatus", () => ({
        status: 200,
        json: { registered: false, updatedAtMs: null },
      })),
      onEndpoint("auth.recoveryPut", () => ({ status: 204 })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.keychain.set(
      tokenEntryName(maruhi.origin),
      JSON.stringify({
        token: "maruhi_pat_stored",
        userId: "user-0001",
        tokenId: "tok_1",
        expiresAtMs: 4_102_444_800_000,
      }),
    );
    env.setPromptResponses([
      () => {
        const line = env.errors.find((entry) => /^ {4}[A-Z2-7]{4}(-[A-Z2-7]{4}){12}$/.test(entry));
        if (line === undefined) throw new Error("recovery code line not found");
        const groups = line.trim().split("-");
        return groups[groups.length - 1] ?? "";
      },
    ]);

    expect(await runCli(["key", "generate"], env.layer)).toBe(0);
    const stored = env.keychain.get(masterKeyEntryName(maruhi.origin, testUserId("user-0001")));
    expect(stored).toBeDefined();
    expect(stored).not.toContain("<redacted");

    const keys = await Effect.runPromise(
      loadMasterKeys({
        origin: maruhi.origin,
        userId: testUserId("user-0001"),
        token: Redacted.make("maruhi_pat_stored"),
      }).pipe(Effect.provide(env.layer)),
    );
    expect(env.logs.join("\n")).toContain(`key fingerprint: ${keys.fingerprintHex}`);
    expect(keys.encKeyPair.privateKey.extractable).toBe(false);
    expect(keys.sigKeyPair.privateKey.extractable).toBe(false);
  });

  it("if MARUHI_TOKEN holds a redaction, it names the reason before any communication", async () => {
    const requests: string[] = [];
    const maruhi = await start([
      onEndpoint("auth.me", (request) => {
        requests.push(request.path);
        return { status: 200, json: { userId: "u", orgs: [] } };
      }),
    ]);
    const env = await makeTestEnv();
    env.setEnvVar("MARUHI_TOKEN", "  <redacted:maruhi-token>\n");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", maruhi.origin);
    const exit = await Effect.runPromiseExit(
      resolveSession(maruhi.origin).pipe(Effect.provide(env.layer)),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    const dump = JSON.stringify(exit);
    expect(dump).toContain("redaction placeholder (<redacted>) itself");
    expect(dump).not.toContain("Authentication with MARUHI_TOKEN failed");
    expect(requests).toEqual([]);
  });

  it("a token via the MARUHI_TOKEN path is also wrapped, and sent as the raw value", async () => {
    const authorizations: (string | undefined)[] = [];
    const maruhi = await start([
      onEndpoint("auth.me", (request) => {
        const header = request.headers["authorization"];
        authorizations.push(typeof header === "string" ? header : undefined);
        return { status: 200, json: { userId: "user-env", orgs: [] } };
      }),
    ]);
    const env = await makeTestEnv();
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env_real");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", maruhi.origin);
    const session = await Effect.runPromise(
      resolveSession(maruhi.origin).pipe(Effect.provide(env.layer)),
    );
    expect(`${session.token}`).toBe("<redacted:maruhi-token>");
    expect(Redacted.value(session.token)).toBe("maruhi_pat_env_real");
    expect(authorizations).toEqual(["Bearer maruhi_pat_env_real"]);
  });
});
