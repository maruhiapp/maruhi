// Integration tests for `maruhi rotation list|dismiss` (AUDIT_SPEC §4.1 /
// §7 — Wave 2 B2) and the always-on warning about unconverged rotation
// mandates / the project verify detail.
//
// Properties pinned down:
//  1. list displays the server's derived view and resolves variable names
//     from verified meta statements (deleted variables via the tombstone's
//     name — §4.2). Names are never mixed into an identifier-only response
//     (TCB discipline — AUDIT_SPEC §7)
//  2. dismiss sends a single pair / --all (--env narrows it; folds per
//     pair) to the operations endpoint, and reports a 404 (no live flag)
//     with a path forward
//  3. An unconverged rotation mandate (an environment whose current epoch
//     didn't start after the mandate entry) is always warned about after
//     the command's sync (never when converged). project verify shows the
//     same derivation's detail. Guidance adapts to the target's current
//     state (no re-running a destructive op on a re-added target), and a
//     deleted environment's verification failure is a notice only — the
//     command still succeeds (the chain verification succeeded)

import type { ChainEntry } from "@maruhi/crypto";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  addMemberOp,
  buildChain,
  type BuiltChain,
  changeRoleOp,
  createEnvironmentOp,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  manifestFor,
  removeMemberOp,
  rotateEpochOp,
  statementFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedVariableStatement,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "env-app-1";

let owner: TestUser;
let target: TestUser;
let dek1: Uint8Array;
let dek2: Uint8Array;

const servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  target = await makeTestUser("user-target-2222");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

/** A converged chain (rotated after the remove — no unconverged warning). */
async function convergedChain(): Promise<BuiltChain> {
  return buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: addMemberOp(target, "member") },
    { actor: owner, operation: removeMemberOp(target) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
  ]);
}

/** An unconverged chain (no rotate after the remove — the §7 mandate left dangling). */
async function unconvergedChain(): Promise<BuiltChain> {
  return buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: addMemberOp(target, "member") },
    { actor: owner, operation: removeMemberOp(target) },
  ]);
}

interface WireFlag {
  readonly environmentId: string;
  readonly variableId: string;
  readonly basis: "read" | "readable";
  readonly targetUserId?: string;
  readonly targetServerKeyFingerprintHex?: string;
  readonly recommendedAtMs: number;
  readonly triggerChainSeq: number;
  /** AUDIT_SPEC §3.3's trigger (2026-09-14 ES. Legacy servers don't carry it). */
  readonly trigger?: "remove_member" | "change_role" | "revoke_server";
}

interface RotationServerState {
  readonly handlers: readonly MockHandler[];
  readonly dismissBodies: {
    readonly targets: readonly { environmentId: string; variableId: string }[];
  }[];
}

/** The mock for the rotation flows: chain, environment list, metadata pull, flags, dismissals. */
async function makeRotationServer(input: {
  readonly built: BuiltChain;
  readonly flags: readonly WireFlag[];
  readonly currentEpoch?: number;
  /** An insert into dismissals (undefined = accept 204). */
  readonly onDismiss?: () => { status: number; json?: unknown } | undefined;
  /** Whether the metadata pull works (false = 404 — the degraded name-resolution path). */
  readonly metadataAvailable?: boolean;
  /** Whether the environment-list GET works (false = 500 — the deleted-environment verification failure path). */
  readonly environmentsAvailable?: boolean;
}): Promise<RotationServerState> {
  const projectId = input.built.projectId;
  const currentEpoch = input.currentEpoch ?? 1;
  const dismissBodies: {
    readonly targets: readonly { environmentId: string; variableId: string }[];
  }[] = [];
  const envStatement: WireDistributedEnvironmentStatement = await environmentStatementFor({
    projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head: headOf(input.built, 1),
  });
  const activeStatement: WireDistributedVariableStatement = await statementFor({
    projectId,
    environmentId: ENV_ID,
    variableId: "va",
    name: "ALPHA",
    author: owner,
    head: headOf(input.built, 1),
  });
  const deletedStatement: WireDistributedVariableStatement = await statementFor({
    projectId,
    environmentId: ENV_ID,
    variableId: "vdel",
    name: "DELETED_KEY",
    author: owner,
    head: headOf(input.built, 1),
    status: "deleted",
    metaVersion: 2,
  });
  const manifest = await manifestFor({
    projectId,
    environmentId: ENV_ID,
    epoch: currentEpoch,
    issuer: owner,
    head: headOf(input.built, input.built.entries.length),
    envStatement,
    statements: [activeStatement, deletedStatement],
  });

  const handlers: MockHandler[] = [
    onRequest("GET", `/projects/${projectId}/chain`, () => ({
      status: 200,
      json: {
        projectId,
        entries: input.built.entries as readonly ChainEntry[],
        headSeq: input.built.entries.length,
        headHashHex: input.built.hashes[input.built.hashes.length - 1],
      },
    })),
    onRequest("GET", `/projects/${projectId}/environments`, () =>
      input.environmentsAvailable === false
        ? { status: 500, json: { message: "injected environments failure" } }
        : {
            status: 200,
            json: {
              environments: [{ environmentId: ENV_ID, currentEpoch, statement: envStatement }],
            },
          },
    ),
    onRequest("GET", `/projects/${projectId}/environments/${ENV_ID}/pull/metadata`, () =>
      input.metadataAvailable === false
        ? { status: 404, json: { _tag: "EnvironmentNotFound", environmentId: ENV_ID } }
        : {
            status: 200,
            json: {
              environmentId: ENV_ID,
              currentEpoch,
              statement: envStatement,
              variables: [activeStatement],
              deletedVariables: [deletedStatement],
              manifest,
            },
          },
    ),
    onRequest("GET", `/projects/${projectId}/rotation/flags`, () => ({
      status: 200,
      json: { flags: input.flags },
    })),
    (request) => {
      if (
        request.method !== "POST" ||
        request.path !== `/projects/${projectId}/rotation/dismissals`
      ) {
        return null;
      }
      const injected = input.onDismiss?.();
      if (injected !== undefined) {
        return injected;
      }
      dismissBodies.push(
        request.body as {
          readonly targets: readonly { environmentId: string; variableId: string }[];
        },
      );
      return { status: 204 };
    },
  ];
  return { handlers, dismissBodies };
}

async function startEnv(state: RotationServerState, projectId: string): Promise<TestEnv> {
  const server = await MockServer.start([...state.handlers]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, { server: server.origin, defaultProject: projectId });
  return env;
}

function flagFor(overrides: Partial<WireFlag> & { readonly variableId: string }): WireFlag {
  return {
    environmentId: ENV_ID,
    basis: "readable",
    targetUserId: target.userId,
    recommendedAtMs: 1_700_000_000_000,
    triggerChainSeq: 4,
    ...overrides,
  };
}

describe("maruhi rotation list", () => {
  it("displays the flags and resolves variable names from verified statements (tombstones included)", async () => {
    const built = await convergedChain();
    const state = await makeRotationServer({
      built,
      currentEpoch: 2,
      flags: [
        flagFor({ variableId: "va", basis: "read" }),
        flagFor({ variableId: "vdel", basis: "readable", trigger: "change_role" }),
      ],
    });
    const env = await startEnv(state, built.projectId);

    expect(await runCli(["rotation", "list"], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain("Rotation flags: 2 active flags");
    // trigger = change_role (demotion / narrowing — 2026-09-14 ES) is
    // distinguished from removal. No trigger (legacy server) keeps the
    // traditional member: display
    expect(logs).toContain(`member (role/scope changed):${target.userId}`);
    // Name resolution: active comes from the statement, deleted from the
    // tombstone's name (§4.2)
    expect(logs).toContain("ALPHA (va)");
    expect(logs).toContain("DELETED_KEY (vdel)");
    expect(logs).toContain("read (confirmed fetch)");
    expect(logs).toContain("readable (fetch was possible)");
    expect(logs).toContain(`member:${target.userId}`);
    // The resolution paths (resolve via push / dismiss for the deleted)
    expect(logs).toContain("maruhi rotation dismiss");
    // The chain is converged, so no unconverged warning appears
    expect(env.errors.join("\n")).not.toContain("unconverged rotation mandate");
  });

  it("environments whose metadata can't be fetched degrade to identifier display (the list itself doesn't stop)", async () => {
    const built = await convergedChain();
    const state = await makeRotationServer({
      built,
      currentEpoch: 2,
      flags: [flagFor({ variableId: "va", basis: "read" })],
      metadataAvailable: false,
    });
    const env = await startEnv(state, built.projectId);
    expect(await runCli(["rotation", "list"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("va");
    expect(env.logs.join("\n")).not.toContain("ALPHA");
    expect(env.errors.join("\n")).toContain("could not fetch verified metadata");
  });

  it("with no flags it says just that", async () => {
    const built = await convergedChain();
    const state = await makeRotationServer({ built, currentEpoch: 2, flags: [] });
    const env = await startEnv(state, built.projectId);
    expect(await runCli(["rotation", "list"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("No rotation flags are currently active");
  });
});

describe("maruhi rotation dismiss", () => {
  it("sends a single pair's dismissal to the operations endpoint", async () => {
    const built = await convergedChain();
    const state = await makeRotationServer({
      built,
      currentEpoch: 2,
      flags: [flagFor({ variableId: "vdel" })],
    });
    const env = await startEnv(state, built.projectId);
    expect(await runCli(["rotation", "dismiss", "vdel", "--env", ENV_ID], env.layer)).toBe(0);
    expect(state.dismissBodies).toEqual([
      { targets: [{ environmentId: ENV_ID, variableId: "vdel" }] },
    ]);
    expect(env.logs.join("\n")).toContain("Dismissed 1 rotation flag (");
  });

  it("--all folds every live flag per pair and dismisses them (narrowed by --env)", async () => {
    const built = await convergedChain();
    const state = await makeRotationServer({
      built,
      currentEpoch: 2,
      flags: [
        // Multiple flags on the same pair (a re-removal — different
        // recommended times) fold into one pair
        flagFor({ variableId: "va" }),
        flagFor({ variableId: "va", recommendedAtMs: 1_700_000_100_000 }),
        flagFor({ variableId: "vdel" }),
        // Another environment's flag is excluded by the --env narrowing
        flagFor({ variableId: "vother", environmentId: "env-other" }),
      ],
    });
    const env = await startEnv(state, built.projectId);
    expect(await runCli(["rotation", "dismiss", "--all", "--env", ENV_ID], env.layer)).toBe(0);
    expect(state.dismissBodies).toEqual([
      {
        targets: [
          { environmentId: ENV_ID, variableId: "va" },
          { environmentId: ENV_ID, variableId: "vdel" },
        ],
      },
    ]);
    expect(env.logs.join("\n")).toContain("Dismissed 2 rotation flags (");
  });

  it("a 404 for a pair with no live flag is reported with a path forward (all-or-nothing abort)", async () => {
    const built = await convergedChain();
    const state = await makeRotationServer({
      built,
      currentEpoch: 2,
      flags: [flagFor({ variableId: "va" })],
      onDismiss: () => ({
        status: 404,
        json: { _tag: "RotationFlagNotFound", environmentId: ENV_ID, variableId: "va" },
      }),
    });
    const env = await startEnv(state, built.projectId);
    expect(await runCli(["rotation", "dismiss", "va", "--env", ENV_ID], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("No active flag for variable");
    expect(errors).toContain("maruhi rotation list");
  });

  it("no target specified (neither --all nor a pair) is guided to the usage", async () => {
    const built = await convergedChain();
    const state = await makeRotationServer({ built, currentEpoch: 2, flags: [] });
    const env = await startEnv(state, built.projectId);
    expect(await runCli(["rotation", "dismiss"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Specify what to dismiss");
  });
});

describe("the always-on warning for unconverged rotation mandates (CRYPTO_SPEC §7 — B2)", () => {
  it("warns, with guidance to the converging command, about environments whose current epoch didn't start after the mandate entry", async () => {
    const built = await unconvergedChain();
    const state = await makeRotationServer({ built, currentEpoch: 1, flags: [] });
    const env = await startEnv(state, built.projectId);
    expect(await runCli(["rotation", "list"], env.layer)).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("unconverged rotation mandate");
    expect(errors).toContain(`member-removed (target=${target.userId}`);
    expect(errors).toContain(ENV_ID);
    // An actionable warning (the B2 ruling): it names the converging
    // command
    expect(errors).toContain(
      `re-running \`maruhi member remove ${target.userId}\` converges the mandate`,
    );
  });

  it("a rolled-back mandate (the target was re-added) does not guide toward re-running the destructive op", async () => {
    // Re-added with the same key after the remove (rotation still absent)
    // — the mandate remains, but suggesting a member-remove re-run would
    // have an active member deleted
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
      { actor: owner, operation: removeMemberOp(target) },
      { actor: owner, operation: addMemberOp(target, "member") },
    ]);
    const state = await makeRotationServer({ built, currentEpoch: 1, flags: [] });
    const env = await startEnv(state, built.projectId);
    expect(await runCli(["rotation", "list"], env.layer)).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("unconverged rotation mandate");
    expect(errors).toContain("the target has been re-added");
    expect(errors).toContain("maruhi env rotate");
    expect(errors).not.toContain("re-running `maruhi member remove");
  });

  it("a target deleted after demotion isn't guided toward a change-role re-run (a current-members-only op)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
      {
        actor: owner,
        operation: {
          op: "change_role",
          payload: {
            targetUserId: target.userId,
            newRole: "reader",
            scopeKind: "all",
            scopeEnvironmentIds: [],
          },
        },
      },
      { actor: owner, operation: removeMemberOp(target) },
    ]);
    const state = await makeRotationServer({ built, currentEpoch: 1, flags: [] });
    const env = await startEnv(state, built.projectId);
    expect(await runCli(["rotation", "list"], env.layer)).toBe(0);
    const errors = env.errors.join("\n");
    // The demotion-mandate row steers toward env rotate (change-role
    // can't be re-run with the target absent)
    expect(errors).toContain("role-demoted");
    expect(errors).toContain("the target has been removed");
    expect(errors).not.toContain("maruhi member change-role");
    // The removal-mandate row suggests a member-remove re-run as before
    expect(errors).toContain(
      `re-running \`maruhi member remove ${target.userId}\` converges the mandate`,
    );
  });

  it("a scope narrowing warns only about the narrowed portion's environments as the fourth kind, scope-narrowed (ES K4 — CRYPTO_SPEC §7)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: createEnvironmentOp("env-other", dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
      { actor: owner, operation: changeRoleOp(target, "member", ["env-other"]) },
    ]);
    const state = await makeRotationServer({ built, currentEpoch: 1, flags: [] });
    const env = await startEnv(state, built.projectId);
    expect(await runCli(["rotation", "list"], env.layer)).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `scope-narrowed (target=${target.userId}, seq=5): environments ${ENV_ID}`,
    );
    expect(errors).not.toContain(`environments ${ENV_ID}, env-other`);
    expect(errors).toContain("maruhi member change-role");
    expect(errors).not.toContain("role-demoted");
  });

  it("project verify doesn't fail on a deleted environment's verification failure (it notices and defers only the convergence judgement)", async () => {
    const built = await unconvergedChain();
    const state = await makeRotationServer({
      built,
      currentEpoch: 1,
      flags: [],
      environmentsAvailable: false,
    });
    const env = await startEnv(state, built.projectId);
    // Chain verification succeeded, so exit 0 (the verification failure
    // is a notice only)
    expect(await runCli(["project", "verify", "--project", built.projectId], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("Chain verification OK");
    const errors = env.errors.join("\n");
    expect(errors).toContain("cannot be confirmed");
    expect(errors).not.toContain("Unconverged rotation mandate:");
  });

  it("project verify shows the same derivation's detail (none when converged)", async () => {
    const unconverged = await unconvergedChain();
    const state = await makeRotationServer({ built: unconverged, currentEpoch: 1, flags: [] });
    const env = await startEnv(state, unconverged.projectId);
    expect(await runCli(["project", "verify", "--project", unconverged.projectId], env.layer)).toBe(
      0,
    );
    expect(env.errors.join("\n")).toContain("Unconverged rotation mandate: member-removed");

    const converged = await convergedChain();
    const convergedState = await makeRotationServer({
      built: converged,
      currentEpoch: 2,
      flags: [],
    });
    const convergedEnv = await startEnv(convergedState, converged.projectId);
    expect(
      await runCli(["project", "verify", "--project", converged.projectId], convergedEnv.layer),
    ).toBe(0);
    expect(convergedEnv.logs.join("\n")).toContain("Rotation mandates: none unconverged");
  });
});
