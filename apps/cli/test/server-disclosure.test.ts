// Tests for the constant display of server disclosure (CRYPTO_SPEC §9 —
// "this project is disclosed to the server").
//
// Invariants pinned down:
//  1. The shared prologue states it on every command that opens a project
//     whose verified chain carries an active grant naming an environment:
//     a project-level command (member list) and a value command (pull) both
//     show it, on stderr, so a `--json` document on stdout is unchanged
//  2. Nothing is said for a project without a grant, after revoke_server,
//     or once deletions emptied the grant's scope
//  3. `env list` marks each disclosed environment (human column and the
//     `disclosedToServerKeyFingerprintsHex` JSON field — the server keys,
//     empty when none)
//  4. `project verify` lists the disclosing grants (fingerprint, scope,
//     lease policy, grant seq), and says "none" when there are none
//  5. Chain-derived only: every input is the verified chain (the mocks serve
//     no grant report — there is none to trust)

import type { ProjectId } from "@maruhi/core";
import { computeServerKeyFingerprint, encodeHex } from "@maruhi/crypto";
import { Effect } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { verifyChainSnapshot } from "../src/chain-sync.ts";
import { runCli } from "../src/cli.ts";
import { NoticeLedger } from "../src/notice.ts";
import { noteServerDisclosure } from "../src/server-disclosure.ts";
import {
  buildChain,
  type BuiltChain,
  type ChainStep,
  createEnvironmentOp,
  deleteEnvironmentOp,
  environmentStatementFor,
  genesisOp,
  grantServerOp,
  makeTestUser,
  revokeServerOp,
  rotateEpochOp,
  type TestUser,
  type WireDistributedEnvironmentStatement,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import {
  chainHandler as pullChainHandler,
  ENV_ID,
  fixture,
  pullHandler,
} from "./support/pull-run.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

/** The deployment's server key and a mirror's (public halves only). */
const SERVER_ENC_PUB_HEX = "5a".repeat(32);
const MIRROR_ENC_PUB_HEX = "a5".repeat(32);

const LEASE_POLICY = [
  {
    issuerUrl: "https://token.actions.githubusercontent.com",
    audience: "https://maruhi.example",
    claimConstraints: [{ claimName: "repository", claimValue: "acme/app" }],
  },
];

let owner: TestUser;
let serverFpHex: string;
let mirrorFpHex: string;
const dek = () => crypto.getRandomValues(new Uint8Array(32));

const servers: MockServer[] = [];

async function fingerprintOf(encPubHex: string): Promise<string> {
  const bytes = Uint8Array.from(encPubHex.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));
  const fp = await computeServerKeyFingerprint(bytes);
  if (!fp.ok) throw new Error("server fingerprint failed");
  return encodeHex(fp.value);
}

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  serverFpHex = await fingerprintOf(SERVER_ENC_PUB_HEX);
  mirrorFpHex = await fingerprintOf(MIRROR_ENC_PUB_HEX);
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

/** genesis → env-prod, env-dev → the given steps. */
async function chainWith(steps: readonly ChainStep[]): Promise<BuiltChain> {
  return buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp("env-prod", dek()) },
    { actor: owner, operation: createEnvironmentOp("env-dev", dek()) },
    ...steps,
  ]);
}

async function grantProd(): Promise<ChainStep> {
  return {
    actor: owner,
    operation: await grantServerOp(["env-prod"], LEASE_POLICY, SERVER_ENC_PUB_HEX),
  };
}

function servedChain(built: BuiltChain): MockHandler {
  return onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
    status: 200,
    json: {
      projectId: built.projectId,
      entries: built.entries,
      headSeq: built.entries.length,
      headHashHex: built.hashes[built.hashes.length - 1],
      attestations: [],
    },
  }));
}

/** The environment list endpoint serving the live environments' statements. */
async function listHandler(built: BuiltChain, environmentIds: readonly string[]) {
  const statements: WireDistributedEnvironmentStatement[] = [];
  for (const environmentId of environmentIds) {
    statements.push(
      await environmentStatementFor({
        projectId: built.projectId,
        environmentId,
        name: environmentId === "env-prod" ? "Production" : "Development",
        author: owner,
        head: { seq: 1, hashHex: built.projectId },
      }),
    );
  }
  return onRequest("GET", `/projects/${built.projectId}/environments`, () => ({
    status: 200,
    json: {
      environments: statements.map((statement) => ({
        environmentId: statement.environmentId,
        currentEpoch: 1,
        statement,
      })),
      schemaPolicy: "enabled" as const,
    },
  }));
}

async function startEnv(
  built: BuiltChain,
  live: readonly string[] = ["env-dev", "env-prod"],
): Promise<TestEnv> {
  const server = await MockServer.start([servedChain(built), await listHandler(built, live)]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
  return env;
}

function disclosureNote(projectId: string, fingerprintHex: string, environments: string): string {
  return `Note: project ${projectId} is disclosed to the server (CRYPTO_SPEC §9): server key ${fingerprintHex} can decrypt the values of ${environments}`;
}

interface EnvListDocument {
  readonly environments: readonly {
    readonly environmentId: string;
    readonly disclosedToServerKeyFingerprintsHex: readonly string[];
  }[];
}

describe("the prologue's server-disclosure Note (§9)", () => {
  it("is stated on a project-level command while a grant is active, on stderr only", async () => {
    const built = await chainWith([await grantProd()]);
    const env = await startEnv(built);
    expect(await runCli(["member", "list", "--json"], env.layer)).toBe(0);
    expect(env.errors).toContain(
      disclosureNote(built.projectId, serverFpHex, "environment env-prod"),
    );
    // stdout stays one JSON document
    expect(() => JSON.parse(env.logs.join("\n")) as unknown).not.toThrow();
    expect(env.logs.join("\n")).not.toContain("disclosed to the server");
  });

  it("says nothing for a project without a grant (pure E2EE)", async () => {
    const env = await startEnv(await chainWith([]));
    expect(await runCli(["member", "list"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).not.toContain("disclosed to the server");
  });

  it("stops once the grant is revoked on the chain", async () => {
    const env = await startEnv(
      await chainWith([
        await grantProd(),
        { actor: owner, operation: revokeServerOp(serverFpHex) },
        { actor: owner, operation: rotateEpochOp("env-prod", 2, dek()) },
        { actor: owner, operation: rotateEpochOp("env-dev", 2, dek()) },
      ]),
    );
    expect(await runCli(["member", "list"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).not.toContain("disclosed to the server");
  });

  it("says nothing once deletions emptied the grant's scope", async () => {
    const env = await startEnv(
      await chainWith([
        await grantProd(),
        { actor: owner, operation: deleteEnvironmentOp("env-prod") },
      ]),
      ["env-dev"],
    );
    expect(await runCli(["member", "list"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).not.toContain("disclosed to the server");
  });

  it("states each grant on its own line (a mirror's key is another server), fingerprint ascending", async () => {
    // Granted in both orders, so the output order cannot be the chain's
    const mirrorGrant: ChainStep = {
      actor: owner,
      operation: await grantServerOp(["env-prod", "env-dev"], [], MIRROR_ENC_PUB_HEX),
    };
    for (const steps of [
      [await grantProd(), mirrorGrant],
      [mirrorGrant, await grantProd()],
    ]) {
      const built = await chainWith(steps);
      const env = await startEnv(built);
      expect(await runCli(["member", "list"], env.layer)).toBe(0);
      const lines = env.errors.filter((line) => line.includes("disclosed to the server"));
      const expected = [
        disclosureNote(built.projectId, serverFpHex, "environment env-prod"),
        disclosureNote(built.projectId, mirrorFpHex, "environments env-dev, env-prod"),
      ].toSorted((a, b) => (a < b ? -1 : 1));
      expect(lines).toEqual(expected);
    }
  });

  it("is stated on pull of a granted environment, before its output", async () => {
    // The pull fixture's chain, extended by a grant of its environment: the
    // same steps sign the same entries, so the fixture's values still verify
    const granted = await buildChain([
      { actor: fixture.owner, operation: genesisOp(fixture.owner) },
      { actor: fixture.owner, operation: createEnvironmentOp(ENV_ID, fixture.dek1) },
      { actor: fixture.owner, operation: rotateEpochOp(ENV_ID, 2, fixture.dek2) },
      {
        actor: fixture.owner,
        operation: await grantServerOp([ENV_ID], [], SERVER_ENC_PUB_HEX),
      },
    ]);
    expect(granted.projectId).toBe(fixture.built.projectId);
    const server = await MockServer.start([servedChain(granted), pullHandler()]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, fixture.owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: granted.projectId,
      defaultEnvironment: ENV_ID,
    });
    expect(await runCli(["pull"], env.layer)).toBe(0);
    expect(env.errors).toContain(
      disclosureNote(granted.projectId, serverFpHex, `environment ${ENV_ID}`),
    );
    expect(env.logs.join("\n")).toContain("ALPHA");
  });

  it("is absent on pull of an environment of a project without a grant", async () => {
    const server = await MockServer.start([pullChainHandler(), pullHandler()]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, fixture.owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: fixture.built.projectId,
      defaultEnvironment: ENV_ID,
    });
    expect(await runCli(["pull"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).not.toContain("disclosed to the server");
  });
});

describe("the Note across projects in one run (§9)", () => {
  it("names each project, so one run's ledger keeps one line per project with the same grant", async () => {
    // Every project on a deployment is granted to the same server key, and
    // environment IDs repeat across projects: without the project the two
    // lines would be identical and the run's ledger would print one
    const other = await makeTestUser("user-owner-2222");
    const grant = await grantServerOp(["env-prod"], LEASE_POLICY, SERVER_ENC_PUB_HEX);
    const first = await chainWith([{ actor: owner, operation: grant }]);
    const second = await buildChain([
      { actor: other, operation: genesisOp(other) },
      { actor: other, operation: createEnvironmentOp("env-prod", dek()) },
      { actor: other, operation: grant },
    ]);
    expect(second.projectId).not.toBe(first.projectId);
    const env = await makeTestEnv();
    await Effect.runPromise(
      Effect.gen(function* () {
        for (const built of [first, second]) {
          const verified = yield* verifyChainSnapshot({
            projectId: built.projectId as ProjectId,
            entries: built.entries,
            claimedHeadSeq: built.entries.length,
            claimedHeadHashHex: built.hashes[built.hashes.length - 1] ?? "",
          });
          yield* noteServerDisclosure(verified);
        }
      }).pipe(Effect.provideService(NoticeLedger, new Set<string>()), Effect.provide(env.layer)),
    );
    expect(env.errors).toEqual([
      disclosureNote(first.projectId, serverFpHex, "environment env-prod"),
      disclosureNote(second.projectId, serverFpHex, "environment env-prod"),
    ]);
  });
});

describe("env list's server-disclosure column (§9)", () => {
  it("marks the granted environment only (human row and JSON)", async () => {
    const built = await chainWith([await grantProd()]);
    const human = await startEnv(built);
    expect(await runCli(["env", "list"], human.layer)).toBe(0);
    const logs = human.logs.join("\n");
    expect(logs).toContain(
      "env-prod\tProduction\tactive\tepoch=1\tin-scope=yes\tdisclosed-to-server=yes",
    );
    expect(logs).toContain(
      "env-dev\tDevelopment\tactive\tepoch=1\tin-scope=yes\tdisclosed-to-server=no",
    );

    const json = await startEnv(built);
    expect(await runCli(["env", "list", "--json"], json.layer)).toBe(0);
    const document = JSON.parse(json.logs.join("\n")) as EnvListDocument;
    expect(
      document.environments.map((row) => [
        row.environmentId,
        row.disclosedToServerKeyFingerprintsHex,
      ]),
    ).toEqual([
      ["env-dev", []],
      ["env-prod", [serverFpHex]],
    ]);
  });

  it("marks nothing after the grant is revoked", async () => {
    const env = await startEnv(
      await chainWith([
        await grantProd(),
        { actor: owner, operation: revokeServerOp(serverFpHex) },
        { actor: owner, operation: rotateEpochOp("env-prod", 2, dek()) },
        { actor: owner, operation: rotateEpochOp("env-dev", 2, dek()) },
      ]),
    );
    expect(await runCli(["env", "list", "--json"], env.layer)).toBe(0);
    const document = JSON.parse(env.logs.join("\n")) as EnvListDocument;
    expect(document.environments.map((row) => row.disclosedToServerKeyFingerprintsHex)).toEqual([
      [],
      [],
    ]);
  });
});

describe("project verify's server grants (§9)", () => {
  it("lists each disclosing grant with its fingerprint, scope, lease policy and grant seq", async () => {
    const env = await startEnv(await chainWith([await grantProd()]));
    expect(await runCli(["project", "verify"], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(
      "Server grants (1) — the environments in scope are disclosed to the server (CRYPTO_SPEC §9):",
    );
    expect(logs).toContain(
      `  ${serverFpHex}\tscope=env-prod\tlease-policy=1 element\tgranted at seq=4`,
    );
  });

  it("says none for a project without a grant, and after a revocation", async () => {
    const none = await startEnv(await chainWith([]));
    expect(await runCli(["project", "verify"], none.layer)).toBe(0);
    expect(none.logs).toContain(
      "Server grants: none (no environment is disclosed to the server — CRYPTO_SPEC §9)",
    );

    const revoked = await startEnv(
      await chainWith([
        await grantProd(),
        { actor: owner, operation: revokeServerOp(serverFpHex) },
        { actor: owner, operation: rotateEpochOp("env-prod", 2, dek()) },
        { actor: owner, operation: rotateEpochOp("env-dev", 2, dek()) },
      ]),
    );
    expect(await runCli(["project", "verify"], revoked.layer)).toBe(0);
    expect(revoked.logs).toContain(
      "Server grants: none (no environment is disclosed to the server — CRYPTO_SPEC §9)",
    );
  });
});
