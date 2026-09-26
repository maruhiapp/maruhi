// Integration tests for `maruhi server grant` (CRYPTO_SPEC §9 /
// AUTH_SPEC §12-6). Pins at wire level: the server-key confirmation
// ceremony, the grant_server append (a 4-field payload), the backfill
// across every environment × every epoch, and mid-run recovery
// (409 = already registered).

import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import type { ChainEntry } from "@maruhi/crypto";
import {
  computeChainEntryHash,
  computeServerKeyFingerprint,
  encodeHex,
  fingerprintToWords,
} from "@maruhi/crypto";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  buildChain,
  createEnvironmentOp,
  genesisOp,
  makeTestUser,
  rotateEpochOp,
  type TestUser,
  wrapDekFor,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "env-app-1";

let owner: TestUser;
let member: TestUser;
let dek1: Uint8Array;
let dek2: Uint8Array;

// The deployment's server key (public side only — grant never needs the
// server secret key)
const SERVER_ENC_PUB_HEX = "5a".repeat(32);
let serverFpHex: string;
let serverFpWords: readonly string[];

const servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  member = await makeTestUser("user-member-2222");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
  const fp = await computeServerKeyFingerprint(Uint8Array.from({ length: 32 }, () => 0x5a));
  if (!fp.ok) throw new Error("server fingerprint failed");
  serverFpHex = encodeHex(fp.value);
  const words = await fingerprintToWords(fp.value);
  if (!words.ok) throw new Error("server fingerprint words failed");
  serverFpWords = words.value;
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

interface GrantServerState {
  readonly handlers: readonly MockHandler[];
  readonly appendedEntries: ChainEntry[];
  readonly registerBodies: { readonly environmentId: string; readonly deks: readonly unknown[] }[];
  readonly registerResponder: {
    respond:
      | ((body: { readonly deks: readonly unknown[] }) => { status: number; json: unknown } | null)
      | null;
  };
}

/**
 * The stateful mock for grant flows: the chain (accepts appends),
 * /auth/config, per-environment listMine (your own wraps), and deks
 * registration (capture + response replacement).
 */
async function makeGrantServer(input: {
  readonly built: Awaited<ReturnType<typeof buildChain>>;
  readonly deksByEnvironment: Readonly<
    Record<string, readonly Awaited<ReturnType<typeof wrapDekFor>>[]>
  >;
  readonly authConfig?: Record<string, unknown>;
}): Promise<GrantServerState> {
  const projectId = input.built.projectId;
  const entries: ChainEntry[] = [...input.built.entries];
  const hashes: string[] = [...input.built.hashes];
  const appendedEntries: ChainEntry[] = [];
  const registerBodies: GrantServerState["registerBodies"] = [];
  const registerResponder: GrantServerState["registerResponder"] = { respond: null };

  const handlers: MockHandler[] = [
    onRequest("GET", "/auth/config", () => ({
      status: 200,
      json: input.authConfig ?? {
        githubClientId: "dummy-client-id",
        serverKeyFingerprintHex: serverFpHex,
        serverEncPubHex: SERVER_ENC_PUB_HEX,
      },
    })),
    onRequest("GET", `/projects/${projectId}/chain`, () => ({
      status: 200,
      json: {
        projectId,
        entries,
        headSeq: entries.length,
        headHashHex: hashes[hashes.length - 1],
      },
    })),
    async (request) => {
      if (request.method !== "POST" || request.path !== `/projects/${projectId}/chain/entries`) {
        return null;
      }
      const body = request.body as { readonly entry: ChainEntry };
      appendedEntries.push(body.entry);
      entries.push(body.entry);
      hashes.push(await computeChainEntryHash(body.entry));
      return {
        status: 200,
        json: { projectId, headSeq: entries.length, headHashHex: hashes[hashes.length - 1] },
      };
    },
    (request) => {
      const match = /^\/projects\/[^/]+\/environments\/([^/]+)\/deks$/.exec(request.path);
      if (match === null) {
        return null;
      }
      const environmentId = match[1] ?? "";
      if (request.method === "GET") {
        return {
          status: 200,
          json: { deks: input.deksByEnvironment[environmentId] ?? [] },
        };
      }
      if (request.method === "POST") {
        const body = request.body as { readonly deks: readonly unknown[] };
        registerBodies.push({ environmentId, deks: body.deks });
        const injected = registerResponder.respond?.(body);
        return injected ?? { status: 204, json: undefined };
      }
      return null;
    },
  ];
  return { handlers, appendedEntries, registerBodies, registerResponder };
}

async function startGrantEnv(
  state: GrantServerState,
  projectId: string,
  user: TestUser,
): Promise<TestEnv> {
  const server = await MockServer.start([...state.handlers]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, user);
  await seedConfig(env, { server: server.origin, defaultProject: projectId });
  return env;
}

/** The canonical chain: create (epoch 1) → rotate (epoch 2). Two epochs to backfill. */
async function builtWithTwoEpochs() {
  return buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
  ]);
}

async function ownWraps(projectId: string) {
  const common = { projectId, environmentId: ENV_ID, recipient: owner, signer: owner };
  return [
    await wrapDekFor({ ...common, epoch: 1, dek: dek1 }),
    await wrapDekFor({ ...common, epoch: 2, dek: dek2 }),
  ];
}

describe("maruhi server grant", () => {
  it("runs the ceremony (--expect-fingerprint) → grant_server append (4 fields) → backfill of every epoch", async () => {
    const built = await builtWithTwoEpochs();
    const state = await makeGrantServer({
      built,
      deksByEnvironment: { [ENV_ID]: await ownWraps(built.projectId) },
    });
    const env = await startGrantEnv(state, built.projectId, owner);

    expect(
      await runCli(
        ["server", "grant", "--environments", ENV_ID, "--expect-fingerprint", serverFpHex],
        env.layer,
      ),
    ).toBe(0);

    // The appended grant_server payload (§6.2's 4-field structured
    // form)
    expect(state.appendedEntries).toHaveLength(1);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "grant_server") throw new Error("grant entry missing");
    expect(entry.payload.serverEncPubHex).toBe(SERVER_ENC_PUB_HEX);
    expect(entry.payload.serverKeyFingerprintHex).toBe(serverFpHex);
    expect(entry.payload.scopeEnvironmentIds).toEqual([ENV_ID]);
    expect(entry.payload.leasePolicy).toEqual([]);

    // Backfill: the server-bound wraps of every epoch (1 and 2)
    // registered in one request
    expect(state.registerBodies).toHaveLength(1);
    const wraps = state.registerBodies[0]?.deks as readonly {
      recipientClass?: string;
      recipientUserId: string;
      recipientEncPubHex: string;
      epoch: number;
    }[];
    expect(wraps.map((wrap) => wrap.epoch)).toEqual([1, 2]);
    expect(wraps.every((wrap) => wrap.recipientClass === "server")).toBe(true);
    expect(wraps.every((wrap) => wrap.recipientUserId === serverFpHex)).toBe(true);
    expect(wraps.every((wrap) => wrap.recipientEncPubHex === SERVER_ENC_PUB_HEX)).toBe(true);

    const logs = env.logs.join("\n");
    expect(logs).toContain("Backfill: 2 newly registered, 0 already registered");
    // §9: the always-on disclosure notice (Note — stderr) + the word
    // display
    expect(env.errors.join("\n")).toContain("disclosed to the server");
    expect(logs).toContain(serverFpWords[11] ?? "");
  });

  it("mid-run recovery: a live grant with identical content is not appended again, and a 409 converges as per-epoch already-registered", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
      {
        actor: owner,
        operation: {
          op: "grant_server",
          payload: {
            serverEncPubHex: SERVER_ENC_PUB_HEX,
            serverKeyFingerprintHex: serverFpHex,
            scopeEnvironmentIds: [ENV_ID],
            leasePolicy: [],
          },
        },
      },
    ]);
    const state = await makeGrantServer({
      built,
      deksByEnvironment: { [ENV_ID]: await ownWraps(built.projectId) },
    });
    // epoch 1 is already registered (the interrupted previous run's
    // mid-state): the batch gets 409, and of the per-epoch calls only
    // epoch 1 gets 409
    state.registerResponder.respond = (body) => {
      const epochs = (body.deks as readonly { epoch: number }[]).map((wrap) => wrap.epoch);
      if (epochs.includes(1)) {
        return {
          status: 409,
          json: { _tag: "DekWrapExists", epoch: 1, recipientUserId: serverFpHex },
        };
      }
      return null;
    };
    const env = await startGrantEnv(state, built.projectId, owner);

    expect(
      await runCli(
        ["server", "grant", "--environments", ENV_ID, "--expect-fingerprint", serverFpHex],
        env.layer,
      ),
    ).toBe(0);
    // No append (identical content) · batch 409 → 2 per-epoch requests
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.registerBodies.map((body) => body.deks.length)).toEqual([2, 1, 1]);
    const logs = env.logs.join("\n");
    expect(logs).toContain("skipping the chain append");
    expect(logs).toContain("Backfill: 1 newly registered, 1 already registered");
  });

  it("the interactive ceremony: confirmed by retyping the last of 12 words (3 mistypes abort with no append)", async () => {
    const built = await builtWithTwoEpochs();
    const state = await makeGrantServer({
      built,
      deksByEnvironment: { [ENV_ID]: await ownWraps(built.projectId) },
    });
    const env = await startGrantEnv(state, built.projectId, owner);
    env.setPromptResponses([serverFpWords[11] ?? ""]);
    expect(await runCli(["server", "grant", "--environments", ENV_ID], env.layer)).toBe(0);
    expect(state.appendedEntries).toHaveLength(1);

    // 3 mistypes → abort (no append)
    const state2 = await makeGrantServer({
      built: await builtWithTwoEpochs(),
      deksByEnvironment: {},
    });
    const env2 = await startGrantEnv(state2, built.projectId, owner);
    env2.setPromptResponses(["wrong", "wrong", "wrong"]);
    expect(await runCli(["server", "grant", "--environments", ENV_ID], env2.layer)).toBe(1);
    expect(state2.appendedEntries).toHaveLength(0);
    expect(env2.errors.join("\n")).toContain("Server key fingerprint confirmation failed");
  });

  it("an --expect-fingerprint mismatch aborts in the ceremony (no append)", async () => {
    const built = await builtWithTwoEpochs();
    const state = await makeGrantServer({ built, deksByEnvironment: {} });
    const env = await startGrantEnv(state, built.projectId, owner);
    const wrongFp = `${serverFpHex.slice(0, 31)}${serverFpHex[31] === "0" ? "1" : "0"}`;
    expect(
      await runCli(
        ["server", "grant", "--environments", ENV_ID, "--expect-fingerprint", wrongFp],
        env.layer,
      ),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "--expect-fingerprint does not match the fingerprint of the server-provided key",
    );
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("refuses the interactive ceremony in an AI-agent environment (guides toward --expect-fingerprint)", async () => {
    const built = await builtWithTwoEpochs();
    const state = await makeGrantServer({ built, deksByEnvironment: {} });
    const env = await startGrantEnv(state, built.projectId, owner);
    env.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["server", "grant", "--environments", ENV_ID], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("--expect-fingerprint");
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("a server without a configured key (no field in /auth/config) is guided to SELF_HOSTING", async () => {
    const built = await builtWithTwoEpochs();
    const state = await makeGrantServer({
      built,
      deksByEnvironment: {},
      authConfig: { githubClientId: "dummy-client-id" },
    });
    const env = await startGrantEnv(state, built.projectId, owner);
    expect(
      await runCli(
        ["server", "grant", "--environments", ENV_ID, "--expect-fingerprint", serverFpHex],
        env.layer,
      ),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("SELF_HOSTING");
  });

  it("aborts when /auth/config's FP and the recomputed FP of the enc public key disagree (the ceremony's self-consistency premise)", async () => {
    const built = await builtWithTwoEpochs();
    const state = await makeGrantServer({
      built,
      deksByEnvironment: {},
      // The FP is genuine but the enc public key is something else: the
      // shape where a malicious server pairs an arbitrary key with "the
      // FP the user already verified from the record". If the
      // recomputation check didn't catch it the ceremony would be
      // meaningless
      authConfig: {
        githubClientId: "dummy-client-id",
        serverKeyFingerprintHex: serverFpHex,
        serverEncPubHex: "5b".repeat(32),
      },
    });
    const env = await startGrantEnv(state, built.projectId, owner);
    expect(
      await runCli(
        ["server", "grant", "--environments", ENV_ID, "--expect-fingerprint", serverFpHex],
        env.layer,
      ),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "The server-provided enc public key does not match serverKeyFingerprintHex",
    );
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.registerBodies).toHaveLength(0);
  });

  it("a multi-environment scope backfills every environment × every epoch", async () => {
    const ENV_B = "env-app-2";
    const dekB = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_B, dekB) },
    ]);
    const common = { projectId: built.projectId, recipient: owner, signer: owner };
    const state = await makeGrantServer({
      built,
      deksByEnvironment: {
        [ENV_ID]: [await wrapDekFor({ ...common, environmentId: ENV_ID, epoch: 1, dek: dek1 })],
        [ENV_B]: [await wrapDekFor({ ...common, environmentId: ENV_B, epoch: 1, dek: dekB })],
      },
    });
    const env = await startGrantEnv(state, built.projectId, owner);

    expect(
      await runCli(
        [
          "server",
          "grant",
          "--environments",
          `${ENV_ID},${ENV_B}`,
          "--expect-fingerprint",
          serverFpHex,
        ],
        env.layer,
      ),
    ).toBe(0);

    expect(state.appendedEntries).toHaveLength(1);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "grant_server") throw new Error("grant entry missing");
    expect(entry.payload.scopeEnvironmentIds).toEqual([ENV_ID, ENV_B]);

    // One request per environment × the server-bound wrap of its single
    // epoch
    const byEnvironment = new Map(
      state.registerBodies.map((body) => [body.environmentId, body.deks]),
    );
    expect([...byEnvironment.keys()].toSorted()).toEqual([ENV_ID, ENV_B]);
    for (const deks of byEnvironment.values()) {
      const wraps = deks as readonly { recipientClass?: string; recipientUserId: string }[];
      expect(wraps).toHaveLength(1);
      expect(wraps[0]?.recipientClass).toBe("server");
      expect(wraps[0]?.recipientUserId).toBe(serverFpHex);
    }
    expect(env.logs.join("\n")).toContain("Backfill: 2 newly registered, 0 already registered");
  });

  it("non-owners are refused (§6.2)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      {
        actor: owner,
        operation: {
          op: "add_member",
          payload: {
            targetUserId: member.userId,
            encPubHex: member.encPubHex,
            sigPubHex: member.sigPubHex,
            role: "member",
            scopeKind: "all",
            scopeEnvironmentIds: [],
          },
        },
      },
      { actor: member, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    const state = await makeGrantServer({ built, deksByEnvironment: {} });
    const env = await startGrantEnv(state, built.projectId, member);
    expect(
      await runCli(
        ["server", "grant", "--environments", ENV_ID, "--expect-fingerprint", serverFpHex],
        env.layer,
      ),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("Only an owner can run grant_server");
  });

  it("a re-grant narrowing the scope guides toward revoke and refuses (the two-layer rule — §6.3)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      {
        actor: owner,
        operation: createEnvironmentOp("env-two-2", crypto.getRandomValues(new Uint8Array(32))),
      },
      {
        actor: owner,
        operation: {
          op: "grant_server",
          payload: {
            serverEncPubHex: SERVER_ENC_PUB_HEX,
            serverKeyFingerprintHex: serverFpHex,
            scopeEnvironmentIds: [ENV_ID, "env-two-2"],
            leasePolicy: [],
          },
        },
      },
    ]);
    const state = await makeGrantServer({ built, deksByEnvironment: {} });
    const env = await startGrantEnv(state, built.projectId, owner);
    expect(
      await runCli(
        ["server", "grant", "--environments", ENV_ID, "--expect-fingerprint", serverFpHex],
        env.layer,
      ),
    ).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("The disclosure scope can only grow");
    expect(errors).toContain("env-two-2");
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("normalizes --lease-policy's JSON (ascending sort of constraints) onto the payload", async () => {
    const built = await builtWithTwoEpochs();
    const state = await makeGrantServer({
      built,
      deksByEnvironment: { [ENV_ID]: await ownWraps(built.projectId) },
    });
    const env = await startGrantEnv(state, built.projectId, owner);
    const policyPath = join(dirname(env.configPath), "lease-policy.json");
    await mkdir(dirname(policyPath), { recursive: true });
    await writeFile(
      policyPath,
      JSON.stringify([
        {
          issuerUrl: "https://token.actions.githubusercontent.com",
          audience: "https://maruhi.example.com",
          // Regardless of written order (repository → ref), it's
          // normalized to ascending code points
          claimConstraints: { repository: "acme-dummy/app", ref: "refs/heads/main" },
        },
      ]),
    );

    expect(
      await runCli(
        [
          "server",
          "grant",
          "--environments",
          ENV_ID,
          "--lease-policy",
          policyPath,
          "--expect-fingerprint",
          serverFpHex,
        ],
        env.layer,
      ),
    ).toBe(0);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "grant_server") throw new Error("grant entry missing");
    expect(entry.payload.leasePolicy).toEqual([
      {
        issuerUrl: "https://token.actions.githubusercontent.com",
        audience: "https://maruhi.example.com",
        claimConstraints: [
          { claimName: "ref", claimValue: "refs/heads/main" },
          { claimName: "repository", claimValue: "acme-dummy/app" },
        ],
      },
    ]);
    expect(env.logs.join("\n")).toContain("lease_policy has 1 element");
  });

  it("requires a non-empty claimConstraints on every --lease-policy element", async () => {
    const built = await builtWithTwoEpochs();
    const state = await makeGrantServer({ built, deksByEnvironment: {} });
    const env = await startGrantEnv(state, built.projectId, owner);
    const policyPath = join(dirname(env.configPath), "unsafe-policy.json");
    await mkdir(dirname(policyPath), { recursive: true });

    await writeFile(
      policyPath,
      JSON.stringify([
        {
          issuerUrl: "https://token.actions.githubusercontent.com",
          audience: "https://maruhi.example.com",
        },
      ]),
    );
    const missingErrorsStart = env.errors.length;
    expect(
      await runCli(
        ["server", "grant", "--environments", ENV_ID, "--lease-policy", policyPath],
        env.layer,
      ),
    ).toBe(2);
    expect(env.errors.slice(missingErrorsStart).join("\n")).toContain(
      "claimConstraints is required for every element",
    );

    await writeFile(
      policyPath,
      JSON.stringify([
        {
          issuerUrl: "https://token.actions.githubusercontent.com",
          audience: "https://maruhi.example.com",
          claimConstraints: {},
        },
      ]),
    );
    const emptyErrorsStart = env.errors.length;
    expect(
      await runCli(
        ["server", "grant", "--environments", ENV_ID, "--lease-policy", policyPath],
        env.layer,
      ),
    ).toBe(2);
    expect(env.errors.slice(emptyErrorsStart).join("\n")).toContain(
      "claimConstraints must have at least one entry per element",
    );
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("--environments is required (minimal-disclosure default) and a malformed JSON file is a usage error", async () => {
    const built = await builtWithTwoEpochs();
    const state = await makeGrantServer({ built, deksByEnvironment: {} });
    const env = await startGrantEnv(state, built.projectId, owner);
    expect(await runCli(["server", "grant"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("grant requires --environments");

    const badPath = join(dirname(env.configPath), "bad-policy.json");
    await mkdir(dirname(badPath), { recursive: true });
    await writeFile(badPath, "{ not json");
    expect(
      await runCli(
        ["server", "grant", "--environments", ENV_ID, "--lease-policy", badPath],
        env.layer,
      ),
    ).toBe(2);
    expect(env.errors.join("\n")).toContain("--lease-policy content is invalid: not valid JSON");
  });
});
