import { Effect, Exit, Layer } from "effect";
import { afterEach, describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { Keychain, masterKeyEntryName, tokenEntryName } from "../src/keychain.ts";
import {
  cryptoBackendUsable,
  resolveServerOrigin,
  storeMasterKeyGuarded,
  unsupportedCryptoCause,
  unsupportedCryptoMessage,
} from "../src/session.ts";
import { makeTestUser, testUserId } from "./support/crypto.ts";
import { makeTestEnv, seedConfig } from "./support/env.ts";
import { MockServer, onRequest } from "./support/server.ts";

let servers: MockServer[] = [];

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

describe("resolveServerOrigin", () => {
  it("resolves flag → config in order and normalizes to an origin", async () => {
    const origin = await Effect.runPromise(
      resolveServerOrigin("https://maruhi.example/some/path", {}),
    );
    expect(origin).toBe("https://maruhi.example");
    const fromConfig = await Effect.runPromise(
      resolveServerOrigin(undefined, { server: "http://localhost:8787" }),
    );
    expect(fromConfig).toBe("http://localhost:8787");
  });

  it("unset or malformed URLs are errors", async () => {
    const missing = await Effect.runPromiseExit(resolveServerOrigin(undefined, {}));
    expect(Exit.isFailure(missing)).toBe(true);
    const invalid = await Effect.runPromiseExit(resolveServerOrigin("not-a-url", {}));
    expect(Exit.isFailure(invalid)).toBe(true);
  });

  it("allows http: only for loopback (blocks plaintext sends)", async () => {
    const loopback = await Effect.runPromise(resolveServerOrigin("http://localhost:8787", {}));
    expect(loopback).toBe("http://localhost:8787");
    const remote = await Effect.runPromiseExit(resolveServerOrigin("http://maruhi.example", {}));
    expect(Exit.isFailure(remote)).toBe(true);
    expect(JSON.stringify(remote)).toContain("loopback");
  });
});

describe("storeMasterKeyGuarded (save with overwrite detection)", () => {
  const ENTRY = masterKeyEntryName("https://maruhi.test", testUserId("user-1"));

  const fakeKeychain = (input: {
    readonly initial?: string;
    readonly onSet?: (store: Map<string, string>) => void;
  }) => {
    const store = new Map<string, string>();
    if (input.initial !== undefined) {
      store.set(ENTRY, input.initial);
    }
    return {
      store,
      layer: Layer.succeed(Keychain, {
        kind: "os-keychain",
        get: (name: string) => Effect.sync(() => store.get(name) ?? null),
        set: (name: string, value: string) =>
          Effect.sync(() => {
            store.set(name, value);
            input.onSet?.(store);
          }),
        remove: (name: string) => Effect.sync(() => void store.delete(name)),
      }),
    };
  };

  it("can save into an empty entry", async () => {
    const keychain = fakeKeychain({});
    const exit = await Effect.runPromiseExit(
      storeMasterKeyGuarded(ENTRY, "record-mine").pipe(Effect.provide(keychain.layer)),
    );
    expect(Exit.isSuccess(exit)).toBe(true);
    expect(keychain.store.get(ENTRY)).toBe("record-mine");
  });

  it("does not overwrite a record that appeared between the check and the write", async () => {
    const keychain = fakeKeychain({ initial: "record-other" });
    const exit = await Effect.runPromiseExit(
      storeMasterKeyGuarded(ENTRY, "record-mine").pipe(Effect.provide(keychain.layer)),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(JSON.stringify(exit)).toContain("at the same time");
    expect(keychain.store.get(ENTRY)).toBe("record-other");
  });

  it("fails when overwritten right after writing (does not proceed to recovery issuance)", async () => {
    const keychain = fakeKeychain({
      onSet: (store) => store.set(ENTRY, "record-other"),
    });
    const exit = await Effect.runPromiseExit(
      storeMasterKeyGuarded(ENTRY, "record-mine").pipe(Effect.provide(keychain.layer)),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(JSON.stringify(exit)).toContain("no recovery code was issued");
  });
});

describe("cryptoBackendUsable", () => {
  it("is true in a working environment (never blames corruption on the environment)", async () => {
    expect(await Effect.runPromise(cryptoBackendUsable())).toBe(true);
  });

  it("environment-caused shared wording does not contain 'what is intact' (it differs per path)", () => {
    expect(unsupportedCryptoCause).not.toContain("do not delete");
    expect(unsupportedCryptoCause).not.toContain("stored");
    expect(unsupportedCryptoMessage).toContain("do not delete it");
  });
});

describe("the MARUHI_TOKEN env-var path", () => {
  it("works without a keychain by resolving userId via /auth/me", async () => {
    const user = await makeTestUser("user-env-0001");
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", (request) => {
        expect(request.headers["authorization"]).toBe("Bearer maruhi_pat_env");
        return { status: 200, json: { userId: user.userId, orgs: [] } };
      }),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", server.origin);
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("No device key on this machine");
  });

  it("pre-warns on stderr when expiry is within 14 days (ruling CL — the env-var path learns it from /auth/me self-disclosure)", async () => {
    const user = await makeTestUser("user-env-0001");
    const DAY_MS = 24 * 60 * 60 * 1000;
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", () => ({
        status: 200,
        json: { userId: user.userId, orgs: [], tokenExpiresAtMs: Date.now() + 5 * DAY_MS },
      })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", server.origin);
    await runCli(["key", "show"], env.layer);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Warning: the API token expires on");
    expect(errors).toContain("days left");
    expect(errors).toContain("--show-token");
  });

  it("does not warn when expiry is outside the window (env-var path)", async () => {
    const user = await makeTestUser("user-env-0001");
    const DAY_MS = 24 * 60 * 60 * 1000;
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", () => ({
        status: 200,
        json: { userId: user.userId, orgs: [], tokenExpiresAtMs: Date.now() + 60 * DAY_MS },
      })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", server.origin);
    await runCli(["key", "show"], env.layer);
    expect(env.errors.join("\n")).not.toContain("Warning: the API token expires");
  });

  it("the keychain path warns without network from the record's stored expiry", async () => {
    const DAY_MS = 24 * 60 * 60 * 1000;
    const server = await MockServer.start([]);
    servers.push(server);

    const nearEnv = await makeTestEnv();
    await seedConfig(nearEnv, { server: server.origin });
    nearEnv.keychain.set(
      tokenEntryName(server.origin),
      JSON.stringify({
        token: "maruhi_pat_keychain",
        userId: "user-0001",
        tokenId: "tok_1",
        expiresAtMs: Date.now() + 3 * DAY_MS,
      }),
    );
    await runCli(["key", "show"], nearEnv.layer);
    const nearErrors = nearEnv.errors.join("\n");
    expect(nearErrors).toContain("Warning: the API token expires on");
    expect(nearErrors).toContain("Sign in again with `maruhi login`");
    expect(server.requests).toHaveLength(0);
  });

  it("the env var takes precedence over the keychain", async () => {
    const user = await makeTestUser("user-env-0001");
    let presented = "";
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", (request) => {
        presented = String(request.headers["authorization"]);
        return { status: 200, json: { userId: user.userId, orgs: [] } };
      }),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.keychain.set(
      tokenEntryName(server.origin),
      JSON.stringify({
        token: "maruhi_pat_keychain",
        userId: user.userId,
        tokenId: "tok_1",
        expiresAtMs: 4_102_444_800_000,
      }),
    );
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", server.origin);
    await runCli(["key", "show"], env.layer);
    expect(presented).toBe("Bearer maruhi_pat_env");
  });

  it("fails with a guidance message when /auth/me returns 401", async () => {
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", () => ({ status: 401, json: { _tag: "Unauthorized" } })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", server.origin);
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Authentication with MARUHI_TOKEN failed");
    expect(errors).toContain("expired or revoked");
    expect(errors).toContain("update the MARUHI_TOKEN value");
  });

  it("treats a whitespace-only MARUHI_TOKEN as unset (no round trip with an empty token)", async () => {
    let hit = false;
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", () => {
        hit = true;
        return { status: 200, json: { userId: "u", orgs: [] } };
      }),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.setEnvVar("MARUHI_TOKEN", " \n");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", server.origin);
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    expect(hit).toBe(false);
    expect(env.errors.join("\n")).toContain("Not logged in");
  });

  it("does not use MARUHI_TOKEN and guides when MARUHI_TOKEN_ORIGIN is unset", async () => {
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", () => ({ status: 200, json: { userId: "u", orgs: [] } })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "requires MARUHI_TOKEN_ORIGIN to name the target server origin",
    );
  });

  it("a malformed MARUHI_TOKEN_ORIGIN is an execution failure (1) that shows where to fix", async () => {
    let hit = false;
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", () => {
        hit = true;
        return { status: 200, json: { userId: "u", orgs: [] } };
      }),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", "notaurl");
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    const text = env.errors.join("\n");
    expect(text).toContain("fix the MARUHI_TOKEN_ORIGIN env var");
    expect(text).not.toContain("notaurl");
    expect(hit).toBe(false);
  });

  it("does not send the token when MARUHI_TOKEN_ORIGIN does not match the connection target", async () => {
    let hit = false;
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", () => {
        hit = true;
        return { status: 200, json: { userId: "u", orgs: [] } };
      }),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", "https://other.example");
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not match the connection target");
    expect(hit).toBe(false);
  });
});
