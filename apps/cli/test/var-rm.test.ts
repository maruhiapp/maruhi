// Tests for `maruhi var rm` (S4 — variable removal).
//
// Invariants pinned down:
//  1. **Removing a v2 variable keeps the schema fields and layout
//     byte-exact from just before** (CRYPTO_SPEC §4.2's removal
//     convention); **removing a v1 variable stays in v1 form** (no v2
//     fields — don't silently upgrade the layout)
//  2. Removal is terminal: removing an active variable requires explicit
//     interactive confirmation (retyping the variable name), and in a
//     non-interactive environment it's refused without --force
//     (fail-closed). A declared variable isn't silently removed either
//  3. The existing discipline of metadata operations: 3-F intent
//     (journal-before-send) + 1-E' effect confirmation (verified
//     distribution of the tombstone) + the floor's advance to the
//     tombstone
//  4. Already-removed or nonexistent names are typed errors before any
//     signing or sending

import { Effect } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { makeFileFloorStore } from "../src/floor-log.ts";
import type { ProjectFloor } from "../src/floor.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  manifestFor,
  manifestHashOf,
  statementFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedVariableStatement,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { makeMetaEnvironmentServer, type MetaEnvironmentState } from "./support/meta-server.ts";
import { type MockRequest, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "dev";
const DESCRIPTION = "Primary endpoint of the shop";

let owner: TestUser;
let built: BuiltChain;
let envStatement: WireDistributedEnvironmentStatement;
/** v2 declared (url type, required, with a description). */
let declaredV2: WireDistributedVariableStatement;
/** v2 active (with schema fields). */
let activeV2: WireDistributedVariableStatement;
/** v1 active (no schema fields — the traditional shape). */
let activeV1: WireDistributedVariableStatement;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    {
      actor: owner,
      operation: createEnvironmentOp(ENV_ID, crypto.getRandomValues(new Uint8Array(32))),
    },
  ]);
  const common = { projectId: built.projectId, environmentId: ENV_ID };
  const head = { seq: 1, hashHex: built.projectId };
  envStatement = await environmentStatementFor({ ...common, name: ENV_ID, author: owner, head });
  declaredV2 = await statementFor({
    ...common,
    variableId: "v-declared",
    name: "SHOP_URL",
    author: owner,
    head,
    status: "declared",
    schema: { varType: "url", required: true, description: DESCRIPTION },
  });
  activeV2 = await statementFor({
    ...common,
    variableId: "v-port",
    name: "PORT",
    author: owner,
    head,
    schema: { varType: "number", required: true, description: "listen port" },
  });
  activeV1 = await statementFor({
    ...common,
    variableId: "v-legacy",
    name: "LEGACY_KEY",
    author: owner,
    head,
  });
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

async function startRmEnv(options?: {
  readonly initialVariables?: readonly WireDistributedVariableStatement[];
  readonly initialTombstones?: readonly WireDistributedVariableStatement[];
  readonly ignoreRemovals?: boolean;
}): Promise<{ env: TestEnv; state: MetaEnvironmentState }> {
  const { state, handlers } = makeMetaEnvironmentServer({
    chain: built,
    owner,
    environmentId: ENV_ID,
    envStatement,
    initialVariables: options?.initialVariables ?? [declaredV2, activeV2, activeV1],
    initialTombstones: options?.initialTombstones ?? [],
    ...(options?.ignoreRemovals === undefined ? {} : { ignoreRemovals: options.ignoreRemovals }),
  });
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: built.projectId,
    defaultEnvironment: ENV_ID,
  });
  return { env, state };
}

function lastServer(): MockServer {
  const server = servers[servers.length - 1];
  if (server === undefined) {
    throw new Error("no mock server started");
  }
  return server;
}

/** Reads the floor (the fold of the observation log). */
async function loadFloor(env: TestEnv): Promise<ProjectFloor> {
  const loaded = await Effect.runPromise(makeFileFloorStore(env.floorDir).load(built.projectId));
  expect(loaded.floor).not.toBeNull();
  return loaded.floor as ProjectFloor;
}

describe("maruhi var rm (the removal statement's shape)", () => {
  it("removing a v2 declared variable keeps the schema fields and layout byte-exact (§4.2)", async () => {
    const { env, state } = await startRmEnv();
    env.setPromptResponses(["SHOP_URL"]);
    expect(await runCli(["var", "rm", "SHOP_URL"], env.layer)).toBe(0);
    expect(state.mutations.map((m) => m.kind)).toEqual(["remove"]);
    const body = state.mutations[0]?.request.body as {
      statement: Record<string, unknown>;
      manifest: Record<string, unknown>;
    };
    expect(body.statement["status"]).toBe("deleted");
    expect(body.statement["metaVersion"]).toBe(2);
    // name keeps the previous name verbatim (removal doesn't empty it —
    // §4.2)
    expect(body.statement["name"]).toBe("SHOP_URL");
    // Schema fields and layout hold the previous statement's values
    // byte-exact
    expect(body.statement["layoutVersion"]).toBe(2);
    expect(body.statement["varType"]).toBe("url");
    expect(body.statement["required"]).toBe(true);
    expect(body.statement["description"]).toBe(DESCRIPTION);
    expect(body.statement["prevMetaSigHashHex"]).not.toBe("");
    // The manifest is re-issued over the set including the tombstone
    // (§4.3)
    expect(body.manifest["manifestVersion"]).toBe(2);
    const output = env.logs.join("\n");
    expect(output).toContain("Deleted SHOP_URL");
    expect(output).toContain("declared only");
    // The floor advances to the tombstone (the material for detecting a
    // removal silently revoked)
    const floor = await loadFloor(env);
    expect(floor.environments[ENV_ID]?.variables["v-declared"]).toMatchObject({
      status: "deleted",
      metaVersion: 2,
    });
  });

  it("removing a v1 variable stays in v1 form (no v2 fields)", async () => {
    const { env, state } = await startRmEnv();
    env.setPromptResponses(["LEGACY_KEY"]);
    expect(await runCli(["var", "rm", "LEGACY_KEY"], env.layer)).toBe(0);
    const body = state.mutations[0]?.request.body as { statement: Record<string, unknown> };
    expect(body.statement["status"]).toBe("deleted");
    expect(body.statement["name"]).toBe("LEGACY_KEY");
    expect(body.statement).not.toHaveProperty("layoutVersion");
    expect(body.statement).not.toHaveProperty("varType");
    expect(body.statement).not.toHaveProperty("required");
    expect(body.statement).not.toHaveProperty("description");
    expect(env.logs.join("\n")).toContain("every stored version) was deleted");
  });
});

describe("explicit confirmation of removal (fail-closed)", () => {
  it("an interactive environment requires retyping the variable name, and on mismatch signs and sends nothing", async () => {
    const { env, state } = await startRmEnv();
    env.setPromptResponses(["WRONG_NAME"]);
    expect(await runCli(["var", "rm", "SHOP_URL"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("the typed name did not match");
    expect(state.mutations).toEqual([]);
    // Nothing was sent before confirmation (just the resolution's
    // metadata pull and chain sync)
    expect(lastServer().requests.filter((request) => request.method === "DELETE")).toHaveLength(0);
  });

  it("makes the removal's consequences explicit before confirming (active = every version disappears, terminal)", async () => {
    const { env } = await startRmEnv();
    env.setPromptResponses(["PORT"]);
    expect(await runCli(["var", "rm", "PORT"], env.layer)).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("every stored version) is deleted immediately");
    expect(errors).toContain("Deletion is terminal");
  });

  it("a non-interactive environment is refused without --force", async () => {
    const { env, state } = await startRmEnv();
    env.setTerminal({ stdout: false });
    expect(await runCli(["var", "rm", "SHOP_URL"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Re-run with --force");
    expect(state.mutations).toEqual([]);
  });

  it("--force skips confirmation but still surfaces the facts (passes non-interactively)", async () => {
    const { env, state } = await startRmEnv();
    env.setTerminal({ stdin: false, stdout: false });
    expect(await runCli(["var", "rm", "SHOP_URL", "--force"], env.layer)).toBe(0);
    expect(state.mutations.map((m) => m.kind)).toEqual(["remove"]);
    expect(env.prompts).toHaveLength(0);
    expect(env.errors.join("\n")).toContain("without confirmation (--force)");
  });
});

describe("target resolution (typed errors before signing / sending)", () => {
  it("an already-removed name is refused with 'already deleted (terminal)'", async () => {
    const tombstone = await statementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "v-gone",
      name: "GONE",
      author: owner,
      head: { seq: 1, hashHex: built.projectId },
      status: "deleted",
      metaVersion: 2,
    });
    const { env, state } = await startRmEnv({
      initialVariables: [activeV1],
      initialTombstones: [tombstone],
    });
    expect(await runCli(["var", "rm", "GONE", "--force"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("already deleted (deletion is terminal");
    expect(state.mutations).toEqual([]);
  });

  it("a nonexistent name is an explicit error", async () => {
    const { env, state } = await startRmEnv();
    expect(await runCli(["var", "rm", "NO_SUCH", "--force"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not exist in this environment");
    expect(state.mutations).toEqual([]);
  });
});

describe("the CAS retry and the binding to the confirmed target", () => {
  it("when re-resolution returns a different variableId, it stops with a typed error (never removes an unconfirmed variable)", async () => {
    // The post-confirmation 409 (a concurrent metadata op) →
    // re-resolution finds **a different variable** under the same name
    // (a concurrent removal + a same-named creation). Since the
    // confirmation binds the variableId, this retry must not proceed
    const replacement = await statementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "v-replacement",
      name: "SHOP_URL",
      author: owner,
      head: { seq: 1, hashHex: built.projectId },
      status: "declared",
      schema: { varType: "url", required: true, description: "" },
    });
    const firstManifest = await manifestFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      issuer: owner,
      head: headOf(built, 2),
      envStatement,
      statements: [declaredV2],
    });
    // The second-and-later distributions give the post-replacement set
    // (the manifest advances by prev-chaining — don't confuse this with
    // the same-version different-hash equivocation refusal)
    const secondManifest = await manifestFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      issuer: owner,
      head: headOf(built, 2),
      envStatement,
      statements: [replacement],
      manifestVersion: 2,
      prevManifestSigHashHex: await manifestHashOf(built.projectId, firstManifest),
    });
    let metadataCalls = 0;
    const deleteCalls: MockRequest[] = [];
    const server = await MockServer.start([
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: built.hashes[built.hashes.length - 1],
        },
      })),
      onRequest("GET", `/projects/${built.projectId}/environments/${ENV_ID}/pull/metadata`, () => {
        metadataCalls += 1;
        const first = metadataCalls === 1;
        return {
          status: 200,
          json: {
            environmentId: ENV_ID,
            currentEpoch: 1,
            statement: envStatement,
            variables: first ? [declaredV2] : [replacement],
            deletedVariables: [],
            manifest: first ? firstManifest : secondManifest,
          },
        };
      }),
      (request) => {
        if (request.method !== "DELETE") {
          return null;
        }
        deleteCalls.push(request);
        return { status: 409, json: { _tag: "MetaVersionConflict", currentMetaVersion: 2 } };
      },
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: built.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setPromptResponses(["SHOP_URL"]);
    expect(await runCli(["var", "rm", "SHOP_URL"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("different variable than the one you confirmed");
    // Only the single 409-refused call — no DELETE was sent toward the
    // other variableId
    expect(deleteCalls).toHaveLength(1);
    expect(deleteCalls[0]?.path.endsWith("/variables/v-declared")).toBe(true);
  });
});

describe("effect confirmation (1-E' — §12-10 (3))", () => {
  it("even on a 204, if the tombstone doesn't show up in the verified distribution it fails and the floor doesn't advance", async () => {
    const { env, state } = await startRmEnv({ ignoreRemovals: true });
    env.setPromptResponses(["SHOP_URL"]);
    expect(await runCli(["var", "rm", "SHOP_URL"], env.layer)).toBe(1);
    expect(state.mutations.map((m) => m.kind)).toEqual(["remove"]);
    const errors = env.errors.join("\n");
    expect(errors).toContain("variable deletion");
    expect(errors).toContain("unconfirmed");
    // The floor hasn't advanced to the tombstone (don't write your own
    // assumption onto the floor)
    const floor = await loadFloor(env);
    expect(floor.environments[ENV_ID]?.variables["v-declared"]).toBeUndefined();
  });
});
