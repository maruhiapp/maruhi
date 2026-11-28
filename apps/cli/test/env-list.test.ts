import {
  addMemberOp,
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  deleteEnvironmentOp,
  distributedEnvironmentStatement,
  type GeneratedIdentity,
  generateIdentity,
  genesisOp,
  rotateEpochOp,
  type WireDistributedEnvironmentStatement,
} from "@maruhi/test-kit";
import { afterEach, beforeAll, describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { masterKeyEntryName } from "../src/keychain.ts";
import { servedChain } from "./support/chain-handler.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onEndpoint } from "./support/server.ts";

let owner: GeneratedIdentity;
let devMember: GeneratedIdentity;
let built: BuiltChain;
let devStatement: WireDistributedEnvironmentStatement;
let prodStatement: WireDistributedEnvironmentStatement;
let oldStatement: WireDistributedEnvironmentStatement;

const servers: MockServer[] = [];

beforeAll(async () => {
  owner = await generateIdentity("user-owner-1111");
  devMember = await generateIdentity("user-dev-2222");
  const dek = () => crypto.getRandomValues(new Uint8Array(32));
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp("env-prod", dek()) },
    { actor: owner, operation: createEnvironmentOp("env-dev", dek()) },
    { actor: owner, operation: createEnvironmentOp("env-old", dek()) },
    { actor: owner, operation: rotateEpochOp("env-prod", 2, dek()) },
    { actor: owner, operation: addMemberOp(devMember, "member", ["env-dev"]) },
    { actor: owner, operation: deleteEnvironmentOp("env-old") },
  ]);
  const head = { seq: 1, hashHex: built.projectId };
  const statementOf = (environmentId: string, name: string) =>
    distributedEnvironmentStatement({
      projectId: built.projectId,
      environmentId,
      name,
      author: owner,
      head,
    });
  devStatement = await statementOf("env-dev", "Development");
  prodStatement = await statementOf("env-prod", "Production");
  oldStatement = await statementOf("env-old", "Legacy");
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

function chainHandler(): MockHandler {
  return onEndpoint("membership.get", { projectId: built.projectId }, () => ({
    status: 200,
    json: servedChain(built.projectId, built.entries, built.hashes),
  }));
}

function listHandler(statements: readonly WireDistributedEnvironmentStatement[]): MockHandler {
  return onEndpoint("environments.list", { projectId: built.projectId }, () => ({
    status: 200,
    json: {
      environments: statements.map((statement) => ({
        environmentId: statement.environmentId,
        currentEpoch: 99,
        statement,
      })),
      schemaPolicy: "enabled" as const,
    },
  }));
}

async function startEnv(
  user: GeneratedIdentity,
  statements: readonly WireDistributedEnvironmentStatement[] = [devStatement, prodStatement],
): Promise<TestEnv & { readonly server: MockServer }> {
  const server = await MockServer.start([chainHandler(), listHandler(statements)]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, user);
  await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
  return { ...env, server };
}

interface ListDocument {
  readonly scopeBasis: string;
  readonly environments: readonly {
    readonly environmentId: string;
    readonly name: string | null;
    readonly status: string;
    readonly currentEpoch: number;
    readonly inScope: boolean;
    readonly disclosedToServerKeyFingerprintsHex: readonly string[];
  }[];
}

describe("maruhi env list", () => {
  it("lists the chain's active environments with the verified name, chain epoch and scope (ID ascending)", async () => {
    const env = await startEnv(owner);
    expect(await runCli(["env", "list"], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(`Environments (2) — verified chain head seq=${built.entries.length}:`);
    expect(logs).toContain(
      "env-dev\tDevelopment\tactive\tepoch=1\tin-scope=yes\tdisclosed-to-server=no",
    );
    expect(logs).toContain(
      "env-prod\tProduction\tactive\tepoch=2\tin-scope=yes\tdisclosed-to-server=no",
    );
    expect(logs.indexOf("env-dev")).toBeLessThan(logs.indexOf("env-prod"));
    expect(logs).not.toContain("env-old");
    expect(env.errors.join("\n")).toContain("1 deleted environment not shown (--all lists them)");
  });

  it("--all adds chain-deleted environments (no name, never in scope)", async () => {
    const env = await startEnv(owner);
    expect(await runCli(["env", "list", "--all"], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain("Environments (3)");
    expect(logs).toContain("env-old\t-\tdeleted\tepoch=1\tin-scope=no\tdisclosed-to-server=no");
  });

  it("judges the scope column by the caller's effective scope", async () => {
    const env = await startEnv(devMember);
    expect(await runCli(["env", "list", "--json"], env.layer)).toBe(0);
    const document = JSON.parse(env.logs.join("\n")) as ListDocument;
    expect(document.scopeBasis).toBe("device");
    expect(document.environments).toEqual([
      {
        environmentId: "env-dev",
        name: "Development",
        status: "active",
        currentEpoch: 1,
        inScope: true,
        disclosedToServerKeyFingerprintsHex: [],
      },
      {
        environmentId: "env-prod",
        name: "Production",
        status: "active",
        currentEpoch: 2,
        inScope: false,
        disclosedToServerKeyFingerprintsHex: [],
      },
    ]);
  });

  it("--json --all includes deleted environments", async () => {
    const env = await startEnv(owner);
    expect(await runCli(["env", "list", "--json", "--all"], env.layer)).toBe(0);
    const document = JSON.parse(env.logs.join("\n")) as ListDocument;
    expect(document.environments.map((row) => [row.environmentId, row.name, row.status])).toEqual([
      ["env-dev", "Development", "active"],
      ["env-old", null, "deleted"],
      ["env-prod", "Production", "active"],
    ]);
  });

  it("runs keyless and under an agent (zero values), falling back to the member scope with a Note", async () => {
    const env = await startEnv(devMember);
    env.setAgent({ isAgent: true, name: "testbot" });
    env.setTerminal({ stdin: false, stdout: false, stderr: false });
    env.keychain.delete(masterKeyEntryName(env.server.origin, devMember.userId));
    expect(await runCli(["env", "list", "--json"], env.layer)).toBe(0);
    const document = JSON.parse(env.logs.join("\n")) as ListDocument;
    expect(document.scopeBasis).toBe("member");
    expect(document.environments.map((row) => row.inScope)).toEqual([true, false]);
    expect(env.errors.join("\n")).toContain(
      "Note: this machine has no usable device key, so in-scope shows your member scope (no device cap is applied)",
    );
  });

  it("refuses a listing that omits a live environment the chain created (never skipped)", async () => {
    const env = await startEnv(owner, [devStatement]);
    expect(await runCli(["env", "list"], env.layer)).not.toBe(0);
    expect(env.errors.join("\n")).toContain(
      "The environment list omits environment env-prod, which the verified chain created",
    );
    expect(env.logs).toEqual([]);
  });

  it("re-syncs once when a live environment is unlisted: a deletion landing after this view's sync is not evidence", async () => {
    const raced = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      {
        actor: owner,
        operation: createEnvironmentOp("env-prod", crypto.getRandomValues(new Uint8Array(32))),
      },
      {
        actor: owner,
        operation: createEnvironmentOp("env-dev", crypto.getRandomValues(new Uint8Array(32))),
      },
      { actor: owner, operation: deleteEnvironmentOp("env-prod") },
    ]);
    const dev = await distributedEnvironmentStatement({
      projectId: raced.projectId,
      environmentId: "env-dev",
      name: "Development",
      author: owner,
      head: { seq: 1, hashHex: raced.projectId },
    });
    let chainCalls = 0;
    const server = await MockServer.start([
      onEndpoint("membership.get", { projectId: raced.projectId }, () => {
        chainCalls += 1;
        const length = chainCalls === 1 ? raced.entries.length - 1 : raced.entries.length;
        return {
          status: 200,
          json: servedChain(
            raced.projectId,
            raced.entries.slice(0, length),
            raced.hashes.slice(0, length),
          ),
        };
      }),
      onEndpoint("environments.list", { projectId: raced.projectId }, () => ({
        status: 200,
        json: {
          environments: [{ environmentId: "env-dev", currentEpoch: 1, statement: dev }],
          schemaPolicy: "enabled" as const,
        },
      })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: raced.projectId });
    expect(await runCli(["env", "list", "--all", "--json"], env.layer)).toBe(0);
    const document = JSON.parse(env.logs.join("\n")) as ListDocument;
    expect(document.environments.map((row) => [row.environmentId, row.status])).toEqual([
      ["env-dev", "active"],
      ["env-prod", "deleted"],
    ]);
  });

  it("refuses a listing that serves a chain-deleted environment as live (a resurrection — §6.3)", async () => {
    const env = await startEnv(owner, [devStatement, prodStatement, oldStatement]);
    expect(await runCli(["env", "list", "--all"], env.layer)).not.toBe(0);
    expect(env.errors.join("\n")).toContain(
      `Environment env-old is deleted on the verified chain (delete_environment at seq ${built.entries.length}), yet the server distributed it as live`,
    );
    expect(env.logs).toEqual([]);
  });

  it("refuses a listed statement that fails verification (never skipped)", async () => {
    const forged = { ...prodStatement, name: "Production (forged)" };
    const env = await startEnv(owner, [devStatement, forged]);
    expect(await runCli(["env", "list"], env.layer)).not.toBe(0);
    expect(env.errors.join("\n")).toContain(
      "Verification of environment env-prod's meta statement failed (reason=signature-invalid)",
    );
    expect(env.logs).toEqual([]);
  });

  it("refuses a listed environment the chain never created, after one resync", async () => {
    const ghost = await distributedEnvironmentStatement({
      projectId: built.projectId,
      environmentId: "env-ghost",
      name: "Ghost",
      author: owner,
      head: { seq: 1, hashHex: built.projectId },
    });
    const env = await startEnv(owner, [devStatement, prodStatement, ghost]);
    expect(await runCli(["env", "list"], env.layer)).not.toBe(0);
    expect(env.errors.join("\n")).toContain(
      "The environment list still names a chain head or an environment the verified chain does not have after a resync",
    );
  });
});
