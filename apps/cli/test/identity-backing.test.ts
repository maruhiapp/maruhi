// Unit + command tests for the backing source `github-signing-keys`
// (CRYPTO_SPEC §6.5 — IV2).
//
// Properties pinned down:
//  1. checkSigningKeyBacking: sends only the login, fixed host, fail-closed
//     (failures and impossibility come back as types, never as CliError),
//     and skips anything that isn't ssh-ed25519
//  2. `key publish`: prints the OpenSSH line (stdout is the key line alone)
//     and `--gh` calls gh (stdin = the key line, GH_ENV); a gh failure is
//     an error carrying the manual steps
//  3. The registration path forward (ruling G (6)): `yes` right after `key
//     generate` registers; non-interactive / no / agent / `identityBacking
//     = none` never ask, or only print guidance
//  4. `config set identityBacking` acceptance checks

import { Effect, Redacted } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { checkSigningKeyBacking } from "../src/github-signing-keys.ts";
import { masterKeyEntryName, serializeStoredToken, tokenEntryName } from "../src/keychain.ts";
import { GH_ENV } from "../src/sync-exec.ts";
import { makeTestUser, type TestUser } from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { githubSigningKeysHandler, sshLineOf } from "./support/invite.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

let alice: TestUser;
let bob: TestUser;

const servers: MockServer[] = [];

beforeAll(async () => {
  alice = await makeTestUser("user-alice-11");
  bob = await makeTestUser("user-bob-22");
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

async function start(handlers: readonly MockHandler[]): Promise<MockServer> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  return server;
}

async function verdictOf(env: TestEnv, login: string, sigPubHex: string) {
  return Effect.runPromise(
    checkSigningKeyBacking({ login, sigPubHex }).pipe(Effect.provide(env.layer)),
  );
}

function loggedIn(env: TestEnv, origin: string, user: TestUser): void {
  env.keychain.set(
    tokenEntryName(origin),
    serializeStoredToken({
      token: Redacted.make("maruhi_pat_Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St9x123"),
      userId: user.userId,
      tokenId: "tok_1",
    }),
  );
}

/** The correct answer to the recovery-code save confirmation (the final group from the shown stderr). */
function saveConfirmation(env: TestEnv): () => string {
  return () => {
    const line = env.errors.find((item) => /^ {4}[A-Z2-7]{4}(-[A-Z2-7]{4})+$/.test(item));
    const groups = (line ?? "").trim().split("-");
    return groups[groups.length - 1] ?? "";
  };
}

function recoveryHandlers(): MockHandler[] {
  return [
    onRequest("GET", "/auth/recovery/status", () => ({
      status: 200,
      json: { registered: false, updatedAtMs: null },
    })),
    onRequest("PUT", "/auth/recovery", () => ({ status: 204 })),
  ];
}

describe("checkSigningKeyBacking (querying the backing source)", () => {
  it("is a match when the named login's signing-key list contains the key byte-for-byte", async () => {
    const requests: string[] = [];
    const github = await start([
      (request) => {
        requests.push(`${request.method} ${request.path}`);
        return null;
      },
      githubSigningKeysHandler("bob", [
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0 bob@laptop",
        `${sshLineOf(bob)} maruhi ${bob.fingerprintHex}`,
      ]),
    ]);
    const env = await makeTestEnv();
    env.setVendorOrigin("api.github.com", github.origin);
    expect(await verdictOf(env, "bob", bob.sigPubHex)).toEqual({ kind: "match" });
    // Only the login is sent (no query, no body)
    expect(requests).toEqual(["GET /users/bob/ssh_signing_keys"]);
  });

  it("distinguishes key-absent / login-absent / fetch-failed / wrong-shape as types and never fails", async () => {
    const github = await start([
      githubSigningKeysHandler("bob", [sshLineOf(alice)]),
      githubSigningKeysHandler("ghost", [], 404),
      githubSigningKeysHandler("limited", [], 403),
      onRequest("GET", "/users/odd/ssh_signing_keys", () => ({
        status: 200,
        json: { not: "an array" },
      })),
    ]);
    const env = await makeTestEnv();
    env.setVendorOrigin("api.github.com", github.origin);
    expect(await verdictOf(env, "bob", bob.sigPubHex)).toEqual({ kind: "not-registered" });
    expect(await verdictOf(env, "ghost", bob.sigPubHex)).toEqual({ kind: "no-user" });
    expect((await verdictOf(env, "limited", bob.sigPubHex)).kind).toBe("unavailable");
    expect((await verdictOf(env, "odd", bob.sigPubHex)).kind).toBe("unavailable");
    // A malformed login never even issues the query (treated as
    // impossible)
    expect((await verdictOf(env, "-bad-", bob.sigPubHex)).kind).toBe("unavailable");
  });
});

describe("maruhi key publish", () => {
  it("prints exactly one OpenSSH line to stdout and the steps to stderr", async () => {
    const maruhi = await start([]);
    const env = await makeTestEnv();
    seedSession(env, maruhi.origin, bob);
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["key", "publish"], env.layer)).toBe(0);
    expect(env.logs).toEqual([sshLineOf(bob)]);
    expect(env.errors.join("\n")).toContain("https://github.com/settings/ssh/new");
    expect(env.errors.join("\n")).toContain("`maruhi key publish --gh`");
    expect(env.execCalls).toHaveLength(0);
  });

  it("--gh calls gh ssh-key add with stdin = the key line, and reports failures with the manual steps", async () => {
    const maruhi = await start([]);
    const env = await makeTestEnv();
    seedSession(env, maruhi.origin, bob);
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["key", "publish", "--gh"], env.layer)).toBe(0);
    expect(env.execCalls).toHaveLength(1);
    const call = env.execCalls[0];
    if (call === undefined) throw new Error("no exec call");
    expect(call.command).toEqual([
      "gh",
      "ssh-key",
      "add",
      "-",
      "--type",
      "signing",
      "--title",
      `maruhi ${bob.fingerprintHex}`,
    ]);
    expect(new TextDecoder().decode(call.stdin)).toBe(`${sshLineOf(bob)}\n`);
    expect(call.extraEnv).toEqual(GH_ENV);
    expect(env.logs.join("\n")).toContain("Registered your signing key on GitHub");

    const env2 = await makeTestEnv();
    seedSession(env2, maruhi.origin, bob);
    await seedConfig(env2, { server: maruhi.origin });
    env2.setExecHandler(() => ({
      exitCode: 4,
      output: "To get started with GitHub CLI, please run: gh auth login\n",
    }));
    expect(await runCli(["key", "publish", "--gh"], env2.layer)).toBe(1);
    expect(env2.errors.join("\n")).toContain("gh could not add the signing key (exit 4");
    expect(env2.errors.join("\n")).toContain("https://github.com/settings/ssh/new");
  });
});

describe("the registration path forward right after key generation (ruling G (6))", () => {
  it("yes completes registration via gh; no / EOF only print guidance (the generation itself stands)", async () => {
    const maruhi = await start(recoveryHandlers());
    const env = await makeTestEnv();
    loggedIn(env, maruhi.origin, bob);
    await seedConfig(env, { server: maruhi.origin });
    env.setPromptResponses([saveConfirmation(env), "yes"]);
    expect(await runCli(["key", "generate"], env.layer)).toBe(0);
    expect(env.prompts[1]).toContain("Type yes to register it now through the gh CLI");
    expect(env.execCalls).toHaveLength(1);
    expect(env.execCalls[0]?.command.slice(0, 3)).toEqual(["gh", "ssh-key", "add"]);
    expect(env.logs.join("\n")).toContain("Registered your signing key on GitHub");

    const env2 = await makeTestEnv();
    loggedIn(env2, maruhi.origin, bob);
    await seedConfig(env2, { server: maruhi.origin });
    env2.setPromptResponses([saveConfirmation(env2), "no"]);
    expect(await runCli(["key", "generate"], env2.layer)).toBe(0);
    expect(env2.execCalls).toHaveLength(0);
    expect(env2.errors.join("\n")).toContain("register it later with `maruhi key publish`");
    expect(env2.keychain.get(masterKeyEntryName(maruhi.origin, bob.userId))).toBeDefined();

    // EOF (answers exhausted) also means "do not register"
    const env3 = await makeTestEnv();
    loggedIn(env3, maruhi.origin, bob);
    await seedConfig(env3, { server: maruhi.origin });
    env3.setPromptResponses([saveConfirmation(env3)]);
    expect(await runCli(["key", "generate"], env3.layer)).toBe(0);
    expect(env3.execCalls).toHaveLength(0);
    expect(env3.errors.join("\n")).toContain("register it later with `maruhi key publish`");
  });

  it("prints only guidance on non-interactive terminals and nothing with identityBacking = none", async () => {
    const maruhi = await start(recoveryHandlers());
    const env = await makeTestEnv();
    loggedIn(env, maruhi.origin, bob);
    await seedConfig(env, { server: maruhi.origin });
    // Agent environment: it performs neither recovery-code issuance nor
    // the registration prompt on your behalf (guidance only)
    env.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["key", "generate"], env.layer)).toBe(0);
    expect(env.prompts).toHaveLength(0);
    expect(env.execCalls).toHaveLength(0);
    expect(env.errors.join("\n")).toContain(
      "register this key on GitHub as a signing key with `maruhi key publish`",
    );

    const env2 = await makeTestEnv();
    loggedIn(env2, maruhi.origin, bob);
    await seedConfig(env2, { server: maruhi.origin, identityBacking: "none" });
    env2.setPromptResponses([saveConfirmation(env2)]);
    expect(await runCli(["key", "generate"], env2.layer)).toBe(0);
    expect(env2.prompts).toHaveLength(1);
    expect(env2.errors.join("\n")).not.toContain("maruhi key publish");
  });
});

describe("config identityBacking", () => {
  it("accepts only the closed set of values and get returns the configured value", async () => {
    const env = await makeTestEnv();
    expect(await runCli(["config", "set", "identityBacking", "none"], env.layer)).toBe(0);
    expect(await runCli(["config", "get", "identityBacking"], env.layer)).toBe(0);
    expect(env.logs).toContain("none");
    expect(await runCli(["config", "set", "identityBacking", "ldap"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain(
      "identityBacking must be one of: github-signing-keys | none",
    );
  });
});
