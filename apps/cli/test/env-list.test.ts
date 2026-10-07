// Tests for `maruhi env list` (the verified chain's environments joined with
// their verified environment statements).
//
// Invariants pinned down:
//  1. The set of environments is the verified chain's create_environment
//     entries; the status is chain-derived (delete_environment — CRYPTO_SPEC
//     §6.2); a live row carries the verified statement's name, the
//     chain-derived epoch, and whether the caller's effective scope covers
//     it. Deleted environments (no name — nothing of them is distributed)
//     appear only with --all; --json is one document
//  2. Fail-closed: a live chain environment missing from the list, a
//     chain-deleted one served as live (a resurrection), or a listed
//     statement failing verification, is an error — never silently skipped
//  3. Zero values: no agent gate, and no master key required. Without this
//     machine's device key the scope column falls back to the member scope
//     and says so (scopeBasis "member")

import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { masterKeyEntryName } from "../src/keychain.ts";
import {
  addScopedMemberOp,
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  deleteEnvironmentOp,
  environmentStatementFor,
  genesisOp,
  makeTestUser,
  rotateEpochOp,
  type TestUser,
  type WireDistributedEnvironmentStatement,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

let owner: TestUser;
let devMember: TestUser;
let built: BuiltChain;
let devStatement: WireDistributedEnvironmentStatement;
let prodStatement: WireDistributedEnvironmentStatement;
/** env-old's statement from before its chain deletion (serving it is a resurrection). */
let oldStatement: WireDistributedEnvironmentStatement;

const servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  devMember = await makeTestUser("user-dev-2222");
  const dek = () => crypto.getRandomValues(new Uint8Array(32));
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp("env-prod", dek()) },
    { actor: owner, operation: createEnvironmentOp("env-dev", dek()) },
    { actor: owner, operation: createEnvironmentOp("env-old", dek()) },
    { actor: owner, operation: rotateEpochOp("env-prod", 2, dek()) },
    { actor: owner, operation: addScopedMemberOp(devMember, "member", ["env-dev"]) },
    { actor: owner, operation: deleteEnvironmentOp("env-old") },
  ]);
  const head = { seq: 1, hashHex: built.projectId };
  const statementOf = (environmentId: string, name: string) =>
    environmentStatementFor({
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

/** The environment list endpoint serving the given statements (the server's advisory epoch is a decoy). */
function listHandler(statements: readonly WireDistributedEnvironmentStatement[]): MockHandler {
  return onRequest("GET", `/projects/${built.projectId}/environments`, () => ({
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
  user: TestUser,
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
  }[];
}

describe("maruhi env list", () => {
  it("lists the chain's active environments with the verified name, chain epoch and scope (ID ascending)", async () => {
    const env = await startEnv(owner);
    expect(await runCli(["env", "list"], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(`Environments (2) — verified chain head seq=${built.entries.length}:`);
    expect(logs).toContain("env-dev\tDevelopment\tactive\tepoch=1\tin-scope=yes");
    // The epoch is chain-derived (the rotation), not the server's advisory value
    expect(logs).toContain("env-prod\tProduction\tactive\tepoch=2\tin-scope=yes");
    expect(logs.indexOf("env-dev")).toBeLessThan(logs.indexOf("env-prod"));
    // The deleted environment is hidden without --all, and that is said
    expect(logs).not.toContain("env-old");
    expect(env.errors.join("\n")).toContain("1 deleted environment not shown (--all lists them)");
  });

  it("--all adds chain-deleted environments (no name, never in scope)", async () => {
    const env = await startEnv(owner);
    expect(await runCli(["env", "list", "--all"], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain("Environments (3)");
    expect(logs).toContain("env-old\t-\tdeleted\tepoch=1\tin-scope=no");
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
      },
      {
        environmentId: "env-prod",
        name: "Production",
        status: "active",
        currentEpoch: 2,
        inScope: false,
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
    const ghost = await environmentStatementFor({
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
