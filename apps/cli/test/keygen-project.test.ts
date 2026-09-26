// Tests for key generate / show and project init (genesis) / verify.

import { computeChainEntryHash, verifyChain, type ChainEntry } from "@maruhi/crypto";
import { Redacted } from "effect";
import { afterEach, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { masterKeyEntryName, parseStoredMasterKey, tokenEntryName } from "../src/keychain.ts";
import { addMemberOp, buildChain, genesisOp, makeTestUser } from "./support/crypto.ts";
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

/** The recovery-registration status response (called by the tail of key show / generate). */
function recoveryStatusHandler(registered: boolean): MockHandler {
  return onRequest("GET", "/auth/recovery/status", () => ({
    status: 200,
    json: { registered, updatedAtMs: registered ? 1754006400000 : null },
  }));
}

/** Accepts the recovery-wrap registration (the PUT of generate / recovery). */
function recoveryPutHandler(): MockHandler {
  return onRequest("PUT", "/auth/recovery", () => ({ status: 204 }));
}

/**
 * Extracts the recovery-code line (4 chars × 13 groups) from the stderr
 * output. Being key material, the code never goes to stdout (which can be
 * redirected).
 */
function displayedRecoveryCode(env: TestEnv): string {
  const line = env.errors.find((entry) => /^ {4}[A-Z2-7]{4}(-[A-Z2-7]{4}){12}$/.test(entry));
  if (line === undefined) {
    throw new Error("recovery code line not found in stderr output");
  }
  return line.trim();
}

/** Lazily queues the correct answer (the code's final group) to the save-confirmation prompt. */
function queueSaveConfirmation(env: TestEnv): void {
  env.setPromptResponses([
    () => {
      const groups = displayedRecoveryCode(env).split("-");
      return groups[groups.length - 1] ?? "";
    },
  ]);
}

describe("maruhi key", () => {
  it("generate stores the key in the keychain and displays the FP (never the secret key)", async () => {
    const maruhi = await start([recoveryStatusHandler(false), recoveryPutHandler()]);
    const env = await loggedInEnv(maruhi.origin, "user-0001");
    queueSaveConfirmation(env);
    expect(await runCli(["key", "generate"], env.layer)).toBe(0);
    const stored = env.keychain.get(masterKeyEntryName(maruhi.origin, "user-0001"));
    expect(stored).toBeDefined();
    const record = parseStoredMasterKey(stored ?? "");
    expect(record).not.toBeNull();
    if (record === null) throw new Error("expected a parsed master-key record");
    expect(record.suite).toBe("maruhi/v1");
    // The secret side is a Redacted. Inspecting the raw value (length, no
    // leakage into output) unwraps it first
    const encSkHex = Redacted.value(record.encSkHex);
    const sigSkSeedHex = Redacted.value(record.sigSkSeedHex);
    expect(encSkHex).toHaveLength(64);
    // No redaction was stored = a record capable of restoring the key was
    // written
    expect(stored).toContain(encSkHex);
    // No secret-key material leaks into the output
    const output = env.logs.join("\n");
    expect(output).toContain("key fingerprint:");
    expect(output).not.toContain(encSkHex);
    expect(output).not.toContain(sigSkSeedHex);
  });

  it("refuses to overwrite an existing key", async () => {
    const maruhi = await start([recoveryStatusHandler(false), recoveryPutHandler()]);
    const env = await loggedInEnv(maruhi.origin, "user-0001");
    queueSaveConfirmation(env);
    expect(await runCli(["key", "generate"], env.layer)).toBe(0);
    expect(await runCli(["key", "generate"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("already exists");
  });

  it("rejects a master-key record of an unknown suite", async () => {
    const user = await makeTestUser("user-0001");
    const maruhi = await start([]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    env.keychain.set(
      masterKeyEntryName(maruhi.origin, user.userId),
      JSON.stringify({
        suite: "maruhi/v2",
        encPubHex: user.encPubHex,
        encSkHex: user.encSkHex,
        sigPubHex: user.sigPubHex,
        sigSkSeedHex: user.sigSkSeedHex,
      }),
    );
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    const message = env.errors.join("\n");
    // It names the cause (which suite)
    expect(message).toContain("maruhi/v2");
    // Unlike corruption, it must **not** be deleted: letting a user delete
    // a key a future version wrote means permanent loss. Show the same
    // guidance as the overwrite-prevention guard
    // (ensureNoStoredMasterKey)
    expect(message).toContain("keep this record");
    // The escape hatch is shown only in its **reversible** form (copy the
    // value down before deleting)
    expect(message).toContain("Copy down the value first");
  });

  it("show displays only the public key and FP, plus the recovery registration status", async () => {
    const user = await makeTestUser("user-0001");
    const maruhi = await start([recoveryStatusHandler(true)]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    seedSession(env, maruhi.origin, user);
    expect(await runCli(["key", "show"], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).toContain(user.encPubHex);
    expect(output).toContain(user.fingerprintHex);
    expect(output).toContain("recovery:               registered");
    expect(output).not.toContain(user.encSkHex);
    expect(output).not.toContain(user.sigSkSeedHex);
  });

  it("show does not fail when the recovery status can't be fetched (usable offline)", async () => {
    const user = await makeTestUser("user-0001");
    // No recovery/status handler = the situation where the server does
    // not respond
    const maruhi = await start([]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    seedSession(env, maruhi.origin, user);
    expect(await runCli(["key", "show"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain(user.fingerprintHex);
    expect(env.logs.join("\n")).toContain("recovery:               could not be checked");
    expect(env.errors.join("\n")).toContain("recovery registration status could not be checked");
  });

  it("show nudges issuance when recovery is unregistered (the safekeeping reminder)", async () => {
    const user = await makeTestUser("user-0001");
    const maruhi = await start([recoveryStatusHandler(false)]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    seedSession(env, maruhi.origin, user);
    expect(await runCli(["key", "show"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("recovery:               not registered");
    expect(env.errors.join("\n")).toContain("create one with `maruhi key recovery`");
  });

  it("show sanitizes a userId containing control characters", async () => {
    const user = await makeTestUser("user\u001b[31m-0001");
    const maruhi = await start([recoveryStatusHandler(true)]);
    const env = await loggedInEnv(maruhi.origin, user.userId);
    seedSession(env, maruhi.origin, user);
    expect(await runCli(["key", "show"], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).not.toContain("\u001b");
    expect(output).toContain("user\uFFFD[31m-0001");
  });
});

function meHandler(userId: string, orgs: readonly { orgId: string; slug: string }[]): MockHandler {
  return onRequest("GET", "/auth/me", () => ({
    status: 200,
    json: {
      userId,
      orgs: orgs.map((org) => ({ ...org, name: org.slug, role: "owner" })),
    },
  }));
}

/** Accepts genesis and returns the entry hash as the ID, like the real server. */
function initHandler(record: (body: { orgId: string; entry: ChainEntry }) => void): MockHandler {
  return async (request) => {
    if (request.method !== "POST" || request.path !== "/projects") {
      return null;
    }
    const body = request.body as { orgId: string; entry: ChainEntry };
    record(body);
    const hash = await computeChainEntryHash(body.entry);
    return { status: 200, json: { projectId: hash, headSeq: 1, headHashHex: hash } };
  };
}

describe("maruhi project init", () => {
  it("signs and sends genesis, then cross-checks the response against the foreseen project ID", async () => {
    const user = await makeTestUser("user-0001");
    let submitted: { orgId: string; entry: ChainEntry } | null = null;
    const maruhi = await start([
      meHandler(user.userId, [{ orgId: "org_personal", slug: "me" }]),
      initHandler((body) => {
        submitted = body;
      }),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    seedSession(env, maruhi.origin, user);

    expect(await runCli(["project", "init"], env.layer)).toBe(0);
    // The personal org is auto-selected (the display layer doesn't show
    // org — §9-1), and the submitted genesis is verifiable on its own
    const body = submitted as { orgId: string; entry: ChainEntry } | null;
    expect(body?.orgId).toBe("org_personal");
    const verified = await verifyChain([body?.entry as ChainEntry]);
    expect(verified.ok).toBe(true);
    const hash = await computeChainEntryHash(body?.entry as ChainEntry);
    expect(env.logs.join("\n")).toContain(`Created project ${hash}`);
  });

  it("fails when the server returns an ID differing from the genesis hash", async () => {
    const user = await makeTestUser("user-0001");
    const bogus = "ab".repeat(32);
    const maruhi = await start([
      meHandler(user.userId, [{ orgId: "org_personal", slug: "me" }]),
      onRequest("POST", "/projects", () => ({
        status: 200,
        json: { projectId: bogus, headSeq: 1, headHashHex: bogus },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    seedSession(env, maruhi.origin, user);
    expect(await runCli(["project", "init"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not match the genesis hash");
  });

  it("reports an empty org precisely as a state anomaly (never says 'multiple memberships')", async () => {
    const user = await makeTestUser("user-0001");
    const maruhi = await start([meHandler(user.userId, [])]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    seedSession(env, maruhi.origin, user);
    expect(await runCli(["project", "init"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("do not belong to any org");
    expect(errors).not.toContain("multiple orgs");
  });

  it("multiple orgs require --org. A slug can create it", async () => {
    const user = await makeTestUser("user-0001");
    let submittedOrgId = "";
    const maruhi = await start([
      meHandler(user.userId, [
        { orgId: "org_personal", slug: "me" },
        { orgId: "org_team", slug: "team" },
      ]),
      initHandler((body) => {
        submittedOrgId = body.orgId;
      }),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    seedSession(env, maruhi.origin, user);

    expect(await runCli(["project", "init"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("--org");

    expect(await runCli(["project", "init", "--org", "team"], env.layer)).toBe(0);
    expect(submittedOrgId).toBe("org_team");
  });
});

describe("maruhi project verify", () => {
  it("verifies the chain and displays members and epochs", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const member = await makeTestUser("user-member-2222");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(member, "reader") },
    ]);
    const maruhi = await start([
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: built.hashes[built.hashes.length - 1],
        },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    seedSession(env, maruhi.origin, owner);
    expect(await runCli(["project", "verify", "--project", built.projectId], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).toContain("Chain verification OK");
    expect(output).toContain(owner.userId);
    expect(output).toContain(member.userId);
    expect(output).toContain(`fp=${member.fingerprintHex}`);
  });
});
