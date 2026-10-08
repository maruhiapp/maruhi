// Tests for `maruhi env rename` (the environment's own meta statement —
// AUTH_SPEC §12-4 → the §12-5 meta rules) and `maruhi env rm` (the
// delete_environment chain entry — AUTH_SPEC §12-4 / CRYPTO_SPEC §6.2).
//
// Invariants pinned down:
//  1. A rename signs over the verified current statement: metaVersion + 1,
//     prev chained to its signed-bytes hash, NFC name, bundled with the next
//     manifest (manifestVersion + 1, envMeta = the new statement). A
//     deletion is a delete_environment entry at the verified head (no
//     statement, no manifest)
//  2. A CAS conflict (409 — metaVersion / manifestVersion for a rename,
//     the chain head for a deletion) re-syncs, re-verifies and re-signs; a
//     determinate refusal is rendered and not retried
//  3. Deletion is terminal: an interactive run requires retyping the
//     environment ID, a non-interactive run refuses without --force, and a
//     non-admin is refused before any prompt or send
//  4. Before the confirmation, a deletion prints the variables' verified
//     names and which of them carry an open rotation flag: the deletion
//     takes the names, the flags outlive it (AUDIT_SPEC §7)
//  5. Success is the verified effect (1-E′), not the 2xx: a rename shows up
//     in the verified metadata pull, a deletion as its own entry on the
//     verified chain; afterwards the deleted environment is refused by pull
//     and by a second `env rm` from the chain alone, and a server serving it
//     as live again is refused

import { type ChainEntry, computeChainEntryHash } from "@maruhi/crypto";
import { Effect } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { makeFileFloorStore } from "../src/floor-log.ts";
import type { ProjectFloor } from "../src/floor.ts";
import {
  addMemberOp,
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  deleteEnvironmentOp,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  manifestFor,
  manifestHashOf,
  statementFor,
  statementHashOf,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedManifest,
  type WireDistributedVariableStatement,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { makeMetaEnvironmentServer, type MetaEnvironmentState } from "./support/meta-server.ts";
import { type MockHandler, type MockRequest, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "dev";
const ENV_NAME = "Development";

let owner: TestUser;
let member: TestUser;
let built: BuiltChain;
/** `built` plus the owner's delete_environment of ENV_ID (seq 4 — a concurrent deletion). */
let deletedChain: BuiltChain;
let envStatement: WireDistributedEnvironmentStatement;
let port: WireDistributedVariableStatement;
let manifestV1: WireDistributedManifest;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  member = await makeTestUser("user-member-2222");
  const steps = [
    { actor: owner, operation: genesisOp(owner) },
    {
      actor: owner,
      operation: createEnvironmentOp(ENV_ID, crypto.getRandomValues(new Uint8Array(32))),
    },
    { actor: owner, operation: addMemberOp(member, "member") },
  ];
  built = await buildChain(steps);
  // Same steps (Ed25519 signing is deterministic), so the prefix is identical
  deletedChain = await buildChain([
    ...steps,
    { actor: owner, operation: deleteEnvironmentOp(ENV_ID) },
  ]);
  const common = { projectId: built.projectId, environmentId: ENV_ID };
  const head = { seq: 1, hashHex: built.projectId };
  envStatement = await environmentStatementFor({ ...common, name: ENV_NAME, author: owner, head });
  port = await statementFor({ ...common, variableId: "v-port", name: "PORT", author: owner, head });
  manifestV1 = await manifestFor({
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

/**
 * Starts the honest in-memory environment (with optional handlers tried
 * first — injected refusals / concurrent changes) and a logged-in CLI.
 */
async function startEnv(options?: {
  readonly user?: TestUser;
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

/** Reads the floor (the fold of the observation log). */
async function loadFloor(env: TestEnv): Promise<ProjectFloor> {
  const loaded = await Effect.runPromise(makeFileFloorStore(env.floorDir).load(built.projectId));
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

/** The environment deletion composite's body (AUTH_SPEC §12-4). */
function deletionBodyOf(request: MockRequest | undefined): {
  parentHeadHashHex: string;
  entry: Record<string, unknown>;
} {
  return request?.body as { parentHeadHashHex: string; entry: Record<string, unknown> };
}

/** A chain-head CAS conflict answer (the head the mock claims is irrelevant: the client re-syncs). */
function headConflict(): { readonly status: number; readonly json: unknown } {
  return {
    status: 409,
    json: {
      _tag: "ChainHeadConflict",
      currentHeadSeq: built.entries.length,
      currentHeadHashHex: built.hashes[built.hashes.length - 1],
    },
  };
}

/** Only the requests of one method against the environment resource itself. */
function environmentCalls(requests: readonly MockRequest[], method: string): MockRequest[] {
  return requests.filter(
    (request) =>
      request.method === method &&
      request.path === `/projects/${built.projectId}/environments/${ENV_ID}`,
  );
}

/**
 * A concurrent rename landing on the honest server (metaVersion 2 + the
 * manifest chained to v1): the material a 409 retry must re-verify.
 */
async function concurrentRename(state: MetaEnvironmentState, name: string): Promise<void> {
  const renamed = await environmentStatementFor({
    projectId: built.projectId,
    environmentId: ENV_ID,
    name,
    author: owner,
    head: headOf(built, built.entries.length),
    metaVersion: 2,
    prevMetaSigHashHex: await statementHashOf(built.projectId, envStatement),
  });
  state.envStatement = renamed;
  state.manifest = await manifestFor({
    projectId: built.projectId,
    environmentId: ENV_ID,
    epoch: 1,
    issuer: owner,
    head: headOf(built, built.entries.length),
    envStatement: renamed,
    statements: [port],
    manifestVersion: 2,
    prevManifestSigHashHex: await manifestHashOf(built.projectId, manifestV1),
  });
}

/** A handler answering the first `method` call on the environment once (after an optional concurrent change). */
function conflictOnce(
  method: string,
  response: { readonly status: number; readonly json: unknown },
  sideEffect?: () => Promise<void>,
): MockHandler {
  let answered = false;
  return async (request) => {
    if (
      answered ||
      request.method !== method ||
      request.path !== `/projects/${built.projectId}/environments/${ENV_ID}`
    ) {
      return null;
    }
    answered = true;
    await sideEffect?.();
    return response;
  };
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
      prevMetaSigHashHex: await statementHashOf(built.projectId, envStatement),
      chainHeadSeq: built.entries.length,
    });
    // The manifest advances by one, keeps the meta set and copies the new envMeta (§4.3)
    expect(body.manifest).toMatchObject({
      manifestVersion: 2,
      envMetaVersion: 2,
      variablesDigestHex: manifestV1.variablesDigestHex,
      prevManifestSigHashHex: await manifestHashOf(built.projectId, manifestV1),
    });
    expect(env.logs.join("\n")).toContain(
      "Renamed environment dev from Development to Staging (metaVersion=2)",
    );
    // The confirmation pull joined the new statement into the floor
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
    const reader = await makeTestUser("user-reader-3333");
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
        conflictOnce(
          "PATCH",
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
    // prev chains to the concurrent winner (refetched and re-verified — §12-5)
    expect(retried.statement).toMatchObject({
      name: "Staging",
      metaVersion: 3,
      prevMetaSigHashHex:
        winner === undefined ? "" : await statementHashOf(built.projectId, winner),
    });
    expect(retried.manifest).toMatchObject({ manifestVersion: 3, envMetaVersion: 3 });
    expect(env.logs.join("\n")).toContain("from Concurrent to Staging (metaVersion=3)");
  });

  it("retries a manifestVersion conflict with a re-signed composite", async () => {
    const { env, requests } = await startEnv({
      before: () => [
        conflictOnce("PATCH", {
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
        conflictOnce("PATCH", {
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
      before: () => [conflictOnce("PATCH", { status: 422, json: { _tag: "NameNotNfc" } })],
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
    // The deletion is a chain entry at the verified head (parent-head CAS)
    expect(body.parentHeadHashHex).toBe(built.hashes[built.hashes.length - 1]);
    expect(body.entry).toMatchObject({
      op: "delete_environment",
      seq: built.entries.length + 1,
      payload: { environmentId: ENV_ID },
      actor: { userId: owner.userId, keyFingerprintHex: owner.fingerprintHex },
    });
    // No statement or manifest travels with a deletion (§12-4)
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
    // The refusals are chain-derived: neither run asked about the environment itself
    expect(
      requests()
        .slice(before)
        .filter((request) => request.path.includes(`/environments/${ENV_ID}`)),
    ).toEqual([]);
  });

  it("prints the variables' verified names, marking open rotation flags, before the confirmation", async () => {
    const { env } = await startEnv({
      before: () => [
        onRequest("GET", `/projects/${built.projectId}/rotation/flags`, () => ({
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
    // The record comes before the confirmation line
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
        conflictOnce("DELETE", headConflict(), () => concurrentRename(current, "Renamed")),
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
    // The name the confirmation showed changed: one line says so (the
    // confirmation binds the ID, so there is no second prompt)
    expect(env.errors.join("\n")).toContain(
      "Note: Environment dev was renamed concurrently from Development to Renamed; deleting it under its new name (the confirmation binds the ID, not the name)",
    );
    expect(env.prompts).toHaveLength(0);
  });

  it("prints no rename notice when a conflict re-resolves the same name", async () => {
    const { env, requests } = await startEnv({
      before: () => [conflictOnce("DELETE", headConflict())],
    });
    expect(await runCli(["env", "rm", ENV_ID, "--force"], env.layer)).toBe(0);
    expect(environmentCalls(requests(), "DELETE")).toHaveLength(2);
    expect(env.errors.join("\n")).not.toContain("renamed concurrently");
  });

  it("reports a concurrent deletion seen after a chain-head conflict as already done, without resending", async () => {
    const { env, requests } = await startEnv({
      before: (current) => [
        conflictOnce("DELETE", headConflict(), async () => {
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
        conflictOnce("DELETE", {
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
        // The server applies the deletion, but the response is lost (a
        // gateway error with no server error body leaves the intent open)
        async (request) => {
          if (
            request.method !== "DELETE" ||
            request.path !== `/projects/${built.projectId}/environments/${ENV_ID}`
          ) {
            return null;
          }
          const body = request.body as { readonly entry: ChainEntry };
          current.chainEntries.push(body.entry);
          current.chainHashes.push(await computeChainEntryHash(body.entry));
          current.environmentDeleted = true;
          return { status: 502, bodyText: "bad gateway" };
        },
      ],
    });
    expect(await runCli(["env", "rm", ENV_ID, "--force"], env.layer)).toBe(1);
    expect(env.logs.join("\n")).not.toContain("Deleted environment");
    // The next run's prologue finds this machine's entry in the slot after
    // the declared head and closes the intent as accepted
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
