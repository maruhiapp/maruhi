import { type ChainEntry, computeChainEntryHash } from "@maruhi/crypto";
import {
  addMemberOp,
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  deleteEnvironmentOp,
  distributedEnvironmentStatement,
  distributedManifest,
  distributedManifestHashOf,
  distributedStatementHashOf,
  distributedVariableStatement,
  type GeneratedIdentity,
  generateIdentity,
  genesisOp,
  headOf,
  testProjectId,
  type WireDistributedEnvironmentStatement,
  type WireDistributedManifest,
  type WireDistributedVariableStatement,
} from "@maruhi/test-kit";
import { Effect } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { makeFileFloorStore } from "../src/floor-log.ts";
import type { ProjectFloor } from "../src/floor.ts";
import { lastHashOf } from "./support/chain-handler.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { makeMetaEnvironmentServer, type MetaEnvironmentState } from "./support/meta-server.ts";
import {
  type EndpointAnswer,
  type MockHandler,
  type MockRequest,
  MockServer,
  offSpec,
  onEndpoint,
} from "./support/server.ts";

const ENV_ID = "dev";
const ENV_NAME = "Development";

let owner: GeneratedIdentity;
let member: GeneratedIdentity;
let built: BuiltChain;
let deletedChain: BuiltChain;
let envStatement: WireDistributedEnvironmentStatement;
let port: WireDistributedVariableStatement;
let manifestV1: WireDistributedManifest;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await generateIdentity("user-owner-1111");
  member = await generateIdentity("user-member-2222");
  const steps = [
    { actor: owner, operation: genesisOp(owner) },
    {
      actor: owner,
      operation: createEnvironmentOp(ENV_ID, crypto.getRandomValues(new Uint8Array(32))),
    },
    { actor: owner, operation: addMemberOp(member, "member") },
  ];
  built = await buildChain(steps);
  deletedChain = await buildChain([
    ...steps,
    { actor: owner, operation: deleteEnvironmentOp(ENV_ID) },
  ]);
  const common = { projectId: built.projectId, environmentId: ENV_ID };
  const head = { seq: 1, hashHex: built.projectId };
  envStatement = await distributedEnvironmentStatement({
    ...common,
    name: ENV_NAME,
    author: owner,
    head,
  });
  port = await distributedVariableStatement({
    ...common,
    variableId: "v-port",
    name: "PORT",
    author: owner,
    head,
  });
  manifestV1 = await distributedManifest({
    ...common,
    epoch: 1,
    issuer: owner,
    head: headOf(built, built.entries.length),
    envStatement,
    statements: [port],
  });
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

async function startEnv(options?: {
  readonly user?: GeneratedIdentity;
  readonly before?: (state: MetaEnvironmentState) => readonly MockHandler[];
  readonly ignoreEnvironmentMutations?: boolean;
  readonly resurrectDeleted?: boolean;
}): Promise<{ env: TestEnv; state: MetaEnvironmentState; requests: () => MockRequest[] }> {
  const { state, handlers } = makeMetaEnvironmentServer({
    chain: built,
    owner,
    environmentId: ENV_ID,
    envStatement,
    initialVariables: [port],
    ...(options?.ignoreEnvironmentMutations === undefined
      ? {}
      : { ignoreEnvironmentMutations: options.ignoreEnvironmentMutations }),
    ...(options?.resurrectDeleted === undefined
      ? {}
      : { resurrectDeleted: options.resurrectDeleted }),
  });
  state.manifest = manifestV1;
  const server = await MockServer.start([...(options?.before?.(state) ?? []), ...handlers]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, options?.user ?? owner);
  await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
  return { env, state, requests: () => server.requests };
}

async function loadFloor(env: TestEnv): Promise<ProjectFloor> {
  const loaded = await Effect.runPromise(
    makeFileFloorStore(env.floorDir).load(testProjectId(built.projectId)),
  );
  expect(loaded.floor).not.toBeNull();
  return loaded.floor as ProjectFloor;
}

function bodyOf(request: MockRequest | undefined): {
  statement: Record<string, unknown>;
  manifest?: Record<string, unknown>;
} {
  return request?.body as {
    statement: Record<string, unknown>;
    manifest?: Record<string, unknown>;
  };
}

function deletionBodyOf(request: MockRequest | undefined): {
  parentHeadHashHex: string;
  entry: Record<string, unknown>;
} {
  return request?.body as { parentHeadHashHex: string; entry: Record<string, unknown> };
}

function headConflict(): EndpointAnswer<"environments.remove"> {
  return {
    status: 409,
    json: {
      _tag: "ChainHeadConflict",
      currentHeadSeq: built.entries.length,
      currentHeadHashHex: lastHashOf(built.hashes),
    },
  };
}

function environmentCalls(requests: readonly MockRequest[], method: string): MockRequest[] {
  return requests.filter(
    (request) =>
      request.method === method &&
      request.path === `/projects/${built.projectId}/environments/${ENV_ID}`,
  );
}

async function concurrentRename(state: MetaEnvironmentState, name: string): Promise<void> {
  const renamed = await distributedEnvironmentStatement({
    projectId: built.projectId,
    environmentId: ENV_ID,
    name,
    author: owner,
    head: headOf(built, built.entries.length),
    metaVersion: 2,
    prevMetaSigHashHex: await distributedStatementHashOf(built.projectId, envStatement),
  });
  state.envStatement = renamed;
  state.manifest = await distributedManifest({
    projectId: built.projectId,
    environmentId: ENV_ID,
    epoch: 1,
    issuer: owner,
    head: headOf(built, built.entries.length),
    envStatement: renamed,
    statements: [port],
    manifestVersion: 2,
    prevManifestSigHashHex: await distributedManifestHashOf(built.projectId, manifestV1),
  });
}

function once<Answer>(
  response: Answer,
  sideEffect?: () => Promise<void>,
): () => Promise<Answer | null> {
  let answered = false;
  return async () => {
    if (answered) {
      return null;
    }
    answered = true;
    await sideEffect?.();
    return response;
  };
}

function renameConflictOnce(
  response: EndpointAnswer<"environments.rename">,
  sideEffect?: () => Promise<void>,
): MockHandler {
  return onEndpoint(
    "environments.rename",
    { projectId: built.projectId, environmentId: ENV_ID },
    once(response, sideEffect),
  );
}

function removeConflictOnce(
  response: EndpointAnswer<"environments.remove">,
  sideEffect?: () => Promise<void>,
): MockHandler {
  return onEndpoint(
    "environments.remove",
    { projectId: built.projectId, environmentId: ENV_ID },
    once(response, sideEffect),
  );
}

describe("maruhi env rename", () => {
  it("signs the next statement and manifest over the verified state and confirms the effect", async () => {
    const { env, state } = await startEnv();
    expect(await runCli(["env", "rename", ENV_ID, "Staging"], env.layer)).toBe(0);
    expect(state.mutations.map((m) => m.kind)).toEqual(["rename-environment"]);
    const body = bodyOf(state.mutations[0]?.request);
    expect(body.statement).toMatchObject({
      environmentId: ENV_ID,
      name: "Staging",
      status: "active",
      metaVersion: 2,
      prevMetaSigHashHex: await distributedStatementHashOf(built.projectId, envStatement),
      chainHeadSeq: built.entries.length,
    });
    expect(body.manifest).toMatchObject({
      manifestVersion: 2,
      envMetaVersion: 2,
      variablesDigestHex: manifestV1.variablesDigestHex,
      prevManifestSigHashHex: await distributedManifestHashOf(built.projectId, manifestV1),
    });
    expect(env.logs.join("\n")).toContain(
      "Renamed environment dev from Development to Staging (metaVersion=2)",
    );
    const floor = await loadFloor(env);
    expect(floor.environments[ENV_ID]).toMatchObject({ metaVersion: 2 });
    expect(floor.intents.filter((intent) => intent.environmentId === ENV_ID)).toEqual([]);
  });

  it("signs the NFC form of the new name (§12-1)", async () => {
    const { env, state } = await startEnv();
    expect(await runCli(["env", "rename", ENV_ID, "Café"], env.layer)).toBe(0);
    expect(bodyOf(state.mutations[0]?.request).statement["name"]).toBe("Café");
  });

  it("refuses a rename to the current name without sending anything", async () => {
    const { env, state } = await startEnv();
    expect(await runCli(["env", "rename", ENV_ID, ENV_NAME], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("is already named Development");
    expect(state.mutations).toEqual([]);
  });

  it("refuses a reader before signing (member or above — §12-3)", async () => {
    const reader = await generateIdentity("user-reader-3333");
    const readerChain = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      {
        actor: owner,
        operation: createEnvironmentOp(ENV_ID, crypto.getRandomValues(new Uint8Array(32))),
      },
      { actor: owner, operation: addMemberOp(reader, "reader") },
    ]);
    const { handlers, state } = makeMetaEnvironmentServer({
      chain: readerChain,
      owner,
      environmentId: ENV_ID,
      envStatement,
    });
    const server = await MockServer.start(handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, reader);
    await seedConfig(env, { server: server.origin, defaultProject: readerChain.projectId });
    expect(await runCli(["env", "rename", ENV_ID, "Staging"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("A reader cannot rename environments");
    expect(state.mutations).toEqual([]);
  });

  it("retries a metaVersion conflict by re-verifying the winner and re-signing both the statement and the manifest", async () => {
    const seen: { winner?: WireDistributedEnvironmentStatement } = {};
    const { env, requests } = await startEnv({
      before: (current) => [
        renameConflictOnce(
          { status: 409, json: { _tag: "MetaVersionConflict", currentMetaVersion: 2 } },
          async () => {
            await concurrentRename(current, "Concurrent");
            seen.winner = current.envStatement;
          },
        ),
      ],
    });
    expect(await runCli(["env", "rename", ENV_ID, "Staging"], env.layer)).toBe(0);
    const patches = environmentCalls(requests(), "PATCH");
    expect(patches).toHaveLength(2);
    const winner = seen.winner;
    expect(winner).toBeDefined();
    const retried = bodyOf(patches[1]);
    expect(retried.statement).toMatchObject({
      name: "Staging",
      metaVersion: 3,
      prevMetaSigHashHex:
        winner === undefined ? "" : await distributedStatementHashOf(built.projectId, winner),
    });
    expect(retried.manifest).toMatchObject({ manifestVersion: 3, envMetaVersion: 3 });
    expect(env.logs.join("\n")).toContain("from Concurrent to Staging (metaVersion=3)");
  });

  it("retries a manifestVersion conflict with a re-signed composite", async () => {
    const { env, requests } = await startEnv({
      before: () => [
        renameConflictOnce({
          status: 409,
          json: { _tag: "ManifestVersionConflict", currentManifestVersion: 1 },
        }),
      ],
    });
    expect(await runCli(["env", "rename", ENV_ID, "Staging"], env.layer)).toBe(0);
    expect(environmentCalls(requests(), "PATCH")).toHaveLength(2);
  });

  it("renders a duplicate-name refusal precisely and does not retry it", async () => {
    const { env, requests } = await startEnv({
      before: () => [
        renameConflictOnce({
          status: 409,
          json: { _tag: "EnvironmentConflict", environmentId: ENV_ID, reason: "duplicate-name" },
        }),
      ],
    });
    expect(await runCli(["env", "rename", ENV_ID, "Production"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Another environment in this project is already named Production",
    );
    expect(environmentCalls(requests(), "PATCH")).toHaveLength(1);
  });

  it("renders a NameNotNfc refusal (not as an unexpected error)", async () => {
    const { env } = await startEnv({
      before: () => [renameConflictOnce({ status: 422, json: { _tag: "NameNotNfc" } })],
    });
    expect(await runCli(["env", "rename", ENV_ID, "Staging"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("not NFC-normalized");
  });

  it("fails when the 2xx is not reflected in the verified distribution (1-E′)", async () => {
    const { env } = await startEnv({ ignoreEnvironmentMutations: true });
    expect(await runCli(["env", "rename", ENV_ID, "Staging"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("environment rename");
    expect(errors).toContain("unconfirmed");
    expect(env.logs.join("\n")).not.toContain("Renamed environment");
  });
});

describe("maruhi env rm", () => {
  it("deletes after the ID is retyped and confirms its delete_environment entry on the verified chain", async () => {
    const { env, state } = await startEnv();
    env.setPromptResponses([ENV_ID]);
    expect(await runCli(["env", "rm", ENV_ID], env.layer)).toBe(0);
    expect(state.mutations.map((m) => m.kind)).toEqual(["remove-environment"]);
    const body = deletionBodyOf(state.mutations[0]?.request);
    expect(body.parentHeadHashHex).toBe(built.hashes[built.hashes.length - 1]);
    expect(body.entry).toMatchObject({
      op: "delete_environment",
      seq: built.entries.length + 1,
      payload: { environmentId: ENV_ID },
      actor: { userId: owner.userId, keyFingerprintHex: owner.fingerprintHex },
    });
    expect(body).not.toHaveProperty("statement");
    expect(body).not.toHaveProperty("manifest");
    expect(state.chainEntries).toHaveLength(built.entries.length + 1);
    expect(env.errors.join("\n")).toContain(
      "You are about to delete environment dev (Development)",
    );
    expect(env.logs.join("\n")).toContain(
      "Deleted environment dev (Development; delete_environment at chain seq 4)",
    );
  });

  it("afterwards pull refuses the environment and a second rm reports it as deleted, from the chain alone", async () => {
    const { env, state, requests } = await startEnv();
    expect(await runCli(["env", "rm", ENV_ID, "--force"], env.layer)).toBe(0);
    const before = requests().length;
    expect(await runCli(["pull", "--env", ENV_ID], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Environment dev is deleted (delete_environment at chain seq 4)",
    );
    expect(await runCli(["env", "rm", ENV_ID, "--force"], env.layer)).toBe(1);
    expect(state.mutations.map((m) => m.kind)).toEqual(["remove-environment"]);
    expect(
      requests()
        .slice(before)
        .filter((request) => request.path.includes(`/environments/${ENV_ID}`)),
    ).toEqual([]);
  });

  it("prints the variables' verified names, marking open rotation flags, before the confirmation", async () => {
    const { env } = await startEnv({
      before: () => [
        onEndpoint("rotation.flags", { projectId: built.projectId }, () => ({
          status: 200,
          json: {
            flags: [
              {
                environmentId: ENV_ID,
                variableId: "v-port",
                basis: "readable",
                targetUserId: member.userId,
                recommendedAtMs: 1_700_000_000_000,
                triggerChainSeq: 3,
                trigger: "remove_member",
              },
              {
                environmentId: "prod",
                variableId: "v-other",
                basis: "read",
                targetUserId: member.userId,
                recommendedAtMs: 1_700_000_000_000,
                triggerChainSeq: 3,
                trigger: "remove_member",
              },
            ],
          },
        })),
      ],
    });
    env.setPromptResponses([ENV_ID]);
    expect(await runCli(["env", "rm", ENV_ID], env.layer)).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      "Variables of environment dev by their verified names (after the deletion none of these names can be verified again",
    );
    expect(errors).toContain("  PORT (v-port) — rotation flag open");
    expect(errors).toContain("The open rotation flags outlive the deletion");
    expect(errors).not.toContain("v-other");
    expect(errors.indexOf("PORT (v-port)")).toBeLessThan(
      errors.indexOf("You are about to delete environment dev"),
    );
  });

  it("a failed flag read is a note and does not stop the deletion", async () => {
    const { env, state } = await startEnv();
    expect(await runCli(["env", "rm", ENV_ID, "--force"], env.layer)).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("could not read the rotation flags");
    expect(errors).toContain("  PORT (v-port)\n");
    expect(errors).not.toContain("The open rotation flags outlive the deletion");
    expect(state.mutations.map((m) => m.kind)).toEqual(["remove-environment"]);
  });

  it("aborts on a mistyped ID without signing or sending", async () => {
    const { env, requests } = await startEnv();
    env.setPromptResponses(["prod"]);
    expect(await runCli(["env", "rm", ENV_ID], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("the typed ID did not match");
    expect(environmentCalls(requests(), "DELETE")).toEqual([]);
  });

  it("refuses a non-interactive run without --force", async () => {
    const { env, requests } = await startEnv();
    env.setTerminal({ stdout: false });
    expect(await runCli(["env", "rm", ENV_ID], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Re-run with --force");
    expect(env.prompts).toHaveLength(0);
    expect(environmentCalls(requests(), "DELETE")).toEqual([]);
  });

  it("--force passes non-interactively but still states the consequence", async () => {
    const { env, state } = await startEnv();
    env.setTerminal({ stdin: false, stdout: false });
    expect(await runCli(["env", "rm", ENV_ID, "--force"], env.layer)).toBe(0);
    expect(state.mutations.map((m) => m.kind)).toEqual(["remove-environment"]);
    expect(env.prompts).toHaveLength(0);
    expect(env.errors.join("\n")).toContain("without confirmation (--force)");
  });

  it("refuses a non-admin before prompting (admin or above — §12-3)", async () => {
    const { env, requests } = await startEnv({ user: member });
    expect(await runCli(["env", "rm", ENV_ID, "--force"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Only admins and owners can delete environments");
    expect(env.prompts).toHaveLength(0);
    expect(environmentCalls(requests(), "DELETE")).toEqual([]);
  });

  it("retries a chain-head conflict over a re-synced view (the then-current name)", async () => {
    const { env, requests } = await startEnv({
      before: (current) => [
        removeConflictOnce(headConflict(), () => concurrentRename(current, "Renamed")),
      ],
    });
    expect(await runCli(["env", "rm", ENV_ID, "--force"], env.layer)).toBe(0);
    const deletes = environmentCalls(requests(), "DELETE");
    expect(deletes).toHaveLength(2);
    expect(deletionBodyOf(deletes[1]).entry).toMatchObject({
      op: "delete_environment",
      payload: { environmentId: ENV_ID },
    });
    expect(env.logs.join("\n")).toContain(
      "Deleted environment dev (Renamed; delete_environment at chain seq 4)",
    );
    expect(env.errors.join("\n")).toContain(
      "Note: Environment dev was renamed concurrently from Development to Renamed; deleting it under its new name (the confirmation binds the ID, not the name)",
    );
    expect(env.prompts).toHaveLength(0);
  });

  it("prints no rename notice when a conflict re-resolves the same name", async () => {
    const { env, requests } = await startEnv({
      before: () => [removeConflictOnce(headConflict())],
    });
    expect(await runCli(["env", "rm", ENV_ID, "--force"], env.layer)).toBe(0);
    expect(environmentCalls(requests(), "DELETE")).toHaveLength(2);
    expect(env.errors.join("\n")).not.toContain("renamed concurrently");
  });

  it("reports a concurrent deletion seen after a chain-head conflict as already done, without resending", async () => {
    const { env, requests } = await startEnv({
      before: (current) => [
        removeConflictOnce(headConflict(), async () => {
          current.chainEntries.push(deletedChain.entries[built.entries.length] as ChainEntry);
          current.chainHashes.push(deletedChain.hashes[built.hashes.length] as string);
          current.environmentDeleted = true;
        }),
      ],
    });
    expect(await runCli(["env", "rm", ENV_ID, "--force"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Environment dev is deleted (delete_environment at chain seq 4). Deletion is terminal: a deleted environment cannot be restored, and its ID can never be reused. Nothing was changed by this run",
    );
    expect(environmentCalls(requests(), "DELETE")).toHaveLength(1);
  });

  it("renders a ChainEntryInvalid refusal and does not retry it", async () => {
    const { env, requests } = await startEnv({
      before: () => [
        removeConflictOnce({
          status: 422,
          json: { _tag: "ChainEntryInvalid", seq: 4, reason: "environment-out-of-scope" },
        }),
      ],
    });
    expect(await runCli(["env", "rm", ENV_ID, "--force"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "The chain entry was rejected by server-side validation (seq=4, reason=environment-out-of-scope)",
    );
    expect(environmentCalls(requests(), "DELETE")).toHaveLength(1);
  });

  it("refuses a server that keeps serving the environment as live after its chain deletion (resurrection — §6.3)", async () => {
    const { env } = await startEnv({ resurrectDeleted: true });
    expect(await runCli(["env", "rm", ENV_ID, "--force"], env.layer)).toBe(0);
    expect(await runCli(["env", "list"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Environment dev is deleted on the verified chain (delete_environment at seq 4), yet the server distributed it as live",
    );
  });

  it("reconciles a deletion whose response was lost on the next run (journal-before-send — 3-F)", async () => {
    const { env } = await startEnv({
      before: (current) => [
        onEndpoint(
          "environments.remove",
          { projectId: built.projectId, environmentId: ENV_ID },
          async (request) => {
            const body = { entry: request.body.entry as ChainEntry };
            current.chainEntries.push(body.entry);
            current.chainHashes.push(await computeChainEntryHash(body.entry));
            current.environmentDeleted = true;
            return offSpec({ status: 502, bodyText: "bad gateway" });
          },
        ),
      ],
    });
    expect(await runCli(["env", "rm", ENV_ID, "--force"], env.layer)).toBe(1);
    expect(env.logs.join("\n")).not.toContain("Deleted environment");
    expect(await runCli(["env", "list", "--all"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain(
      "an earlier delete_environment for environment dev (interrupted before its confirmation) is confirmed as accepted on the chain",
    );
    expect(env.logs.join("\n")).toContain("dev\t-\tdeleted");
    const floor = await loadFloor(env);
    expect(floor.intents).toEqual([]);
  });

  it("fails when the 2xx is not reflected on the verified chain (1-E′)", async () => {
    const { env } = await startEnv({ ignoreEnvironmentMutations: true });
    expect(await runCli(["env", "rm", ENV_ID, "--force"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("environment deletion");
    expect(errors).toContain("unconfirmed");
    expect(env.logs.join("\n")).not.toContain("Deleted environment");
  });
});
