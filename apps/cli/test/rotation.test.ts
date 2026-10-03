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
import { describeDue } from "../src/max-age.ts";
import {
  addMemberOp,
  addScopedMemberOp,
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
  /** AUDIT_SPEC §3.3's trigger (2026-09-14 ES). */
  readonly trigger: "remove_member" | "change_role" | "revoke_server";
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
  /** When set, a layout-v3 variable with max age 30 days exists, last pushed at this time (PF6 R9). */
  readonly expiringPushedAtMs?: number;
  /** Whether that variable's history can be read (false = 500 — the unreadable-age path of `--fail-on-due`). */
  readonly historyAvailable?: boolean;
  /** When set, the latest version is a re-encryption pushed at this time (`sameValueAs` the version pushed at `expiringPushedAtMs`). */
  readonly reencryptedAtMs?: number;
  /** The expiries of the pending sealed proposals listed to the caller (default none); null = the list fails (500). */
  readonly pendingProposalExpiries?: readonly number[] | null;
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
  // A layout-v3 statement declaring a max age (PF6 R9 — the expiring section)
  const expiringStatement: WireDistributedVariableStatement = await statementFor({
    projectId,
    environmentId: ENV_ID,
    variableId: "vexp",
    name: "STRIPE_SECRET_KEY",
    author: owner,
    head: headOf(input.built, 1),
    schema: { varType: "string", required: true, description: "", maxAgeDays: 30 },
  });
  const expiringStatements = input.expiringPushedAtMs === undefined ? [] : [expiringStatement];
  const manifest = await manifestFor({
    projectId,
    environmentId: ENV_ID,
    epoch: currentEpoch,
    issuer: owner,
    head: headOf(input.built, input.built.entries.length),
    envStatement,
    statements: [activeStatement, deletedStatement, ...expiringStatements],
  });

  const handlers: MockHandler[] = [
    onRequest("GET", `/projects/${projectId}/chain`, () => ({
      status: 200,
      json: {
        projectId,
        entries: input.built.entries as readonly ChainEntry[],
        headSeq: input.built.entries.length,
        headHashHex: input.built.hashes[input.built.hashes.length - 1],
        attestations: [],
      },
    })),
    onRequest("GET", `/projects/${projectId}/environments`, () =>
      input.environmentsAvailable === false
        ? { status: 500, json: { message: "injected environments failure" } }
        : {
            status: 200,
            json: {
              environments: [{ environmentId: ENV_ID, currentEpoch, statement: envStatement }],
              schemaPolicy: "enabled",
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
              variables: [activeStatement, ...expiringStatements],
              deletedVariables: [deletedStatement],
              manifest,
              schemaPolicy: "enabled" as const,
            },
          },
    ),
    onRequest("GET", `/projects/${projectId}/environments/${ENV_ID}/variables/vexp/versions`, () =>
      input.historyAvailable === false
        ? { status: 500, json: { message: "injected history failure" } }
        : {
            status: 200,
            json: {
              variableId: "vexp",
              versions: [
                ...(input.reencryptedAtMs === undefined
                  ? []
                  : [
                      {
                        version: 4,
                        epoch: currentEpoch,
                        writerUserId: owner.userId,
                        writerKeyFingerprintHex: owner.fingerprintHex,
                        pushedAtMs: input.reencryptedAtMs,
                        sameValueAs: 3,
                        flagsIfCurrent: 0,
                      },
                    ]),
                {
                  version: 3,
                  epoch: currentEpoch,
                  writerUserId: owner.userId,
                  writerKeyFingerprintHex: owner.fingerprintHex,
                  pushedAtMs: input.expiringPushedAtMs ?? 0,
                  flagsIfCurrent: 0,
                },
              ],
            },
          },
    ),
    onRequest("GET", `/projects/${projectId}/rotation/flags`, () => ({
      status: 200,
      json: { flags: input.flags },
    })),
    onRequest("GET", `/projects/${projectId}/rotation/proposals`, () =>
      input.pendingProposalExpiries === null
        ? { status: 500, json: { message: "injected proposal-list failure" } }
        : {
            status: 200,
            json: {
              proposals: (input.pendingProposalExpiries ?? []).map((expiresAtMs, index) => ({
                proposalId: `0000000000000000000000000000000${index}`,
                environmentId: ENV_ID,
                connector: "exec",
                facts: [],
                claimsDigestHex: "00".repeat(32),
                grantChainSeq: 1,
                createdAtMs: 0,
                expiresAtMs,
                variables: [],
              })),
            },
          },
    ),
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
    trigger: "remove_member",
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
    // distinguished from removal. remove_member keeps the member: display
    expect(logs).toContain(`member (role/scope changed):${target.userId}`);
    // Name resolution: active comes from the statement, deleted from the
    // tombstone's name (§4.2)
    expect(logs).toContain("ALPHA (va)");
    expect(logs).toContain("DELETED_KEY (vdel)");
    expect(logs).toContain("read (confirmed fetch)");
    expect(logs).toContain("readable (fetch was possible)");
    expect(logs).toContain(`member:${target.userId}`);
    // The resolution paths (resolve via push / dismiss for the deleted) —
    // one "next:" action per row (PF6 R3; no rotation config in cwd = the by-hand route)
    expect(logs).toContain(
      "    next: rotate at the issuer, then `maruhi push ALPHA --env env-app-1` (runbooks: https://maruhi.app/docs/rotation)",
    );
    expect(logs).toContain(
      "    next: deleted — rotate at the issuer, then `maruhi rotation dismiss vdel --env env-app-1` (a deleted variable cannot be pushed)",
    );
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
    // The check cannot pass on it: the environment's ages are unknown (A-11)
    const check = await startEnv(state, built.projectId);
    expect(await runCli(["rotation", "list", "--fail-on-due"], check.layer)).toBe(1);
    expect(check.errors.join("\n")).toContain(
      `Cannot judge the check: the expiring values of 1 environment could not be listed (${ENV_ID})`,
    );
  });

  it("--fail-on-pending under a scoped member's token cannot pass: the server lists that scope only (A-12)", async () => {
    const scoped = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addScopedMemberOp(target, "member", [ENV_ID]) },
    ]);
    const asScoped = async (state: RotationServerState) => {
      const server = await MockServer.start([...state.handlers]);
      servers.push(server);
      const env = await makeTestEnv();
      seedSession(env, server.origin, target);
      await seedConfig(env, { server: server.origin, defaultProject: scoped.projectId });
      return env;
    };
    const none = await asScoped(
      await makeRotationServer({ built: scoped, flags: [], pendingProposalExpiries: [] }),
    );
    expect(await runCli(["rotation", "list", "--fail-on-pending"], none.layer)).toBe(1);
    expect(none.errors.join("\n")).toContain(
      `Cannot judge the check: the pending proposals are unknown: only the environments in your scope are listed (${ENV_ID}); run it with a member whose scope covers every environment`,
    );
    // A known pending proposal is still exit 3 (due over unknown — A-10)
    const some = await asScoped(
      await makeRotationServer({
        built: scoped,
        flags: [],
        pendingProposalExpiries: [Date.now() + 24 * 60 * 60 * 1000],
      }),
    );
    expect(await runCli(["rotation", "list", "--fail-on-pending"], some.layer)).toBe(3);
    expect(some.errors.join("\n")).toContain("1 sealed proposal awaiting a member");
    expect(some.errors.join("\n")).toContain("also the pending proposals are unknown");
  });

  it("with no flags it says just that", async () => {
    const built = await convergedChain();
    const state = await makeRotationServer({ built, currentEpoch: 2, flags: [] });
    const env = await startEnv(state, built.projectId);
    expect(await runCli(["rotation", "list"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("No rotation flags are currently active");
    expect(env.logs.join("\n")).not.toContain("Expiring values");
  });

  it("lists values past, or close to, the max age their layout-v3 schema declares, with the next step (PF6 R9)", async () => {
    const built = await convergedChain();
    const day = 24 * 60 * 60 * 1000;
    // Pushed 40 days ago under a 30-day max age: expired 10 days ago
    const expired = await makeRotationServer({
      built,
      currentEpoch: 2,
      flags: [],
      expiringPushedAtMs: Date.now() - 40 * day,
    });
    const env = await startEnv(expired, built.projectId);
    expect(await runCli(["rotation", "list"], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain("Expiring values: 1 value past the declared max age");
    expect(logs).toMatch(
      /\[expired\] env-app-1 STRIPE_SECRET_KEY: max age 30d, pushed \d{4}-\d{2}-\d{2}, expired 10 days ago — next: rotate at the issuer, then `maruhi push STRIPE_SECRET_KEY --env env-app-1`/,
    );
    // Pushed 25 days ago: due in 5 days (inside the 14-day window)
    const soon = await makeRotationServer({
      built,
      currentEpoch: 2,
      flags: [],
      expiringPushedAtMs: Date.now() - 25 * day,
    });
    const soonEnv = await startEnv(soon, built.projectId);
    expect(await runCli(["rotation", "list"], soonEnv.layer)).toBe(0);
    expect(soonEnv.logs.join("\n")).toContain("Expiring values: 1 value due within 14 days");
    expect(soonEnv.logs.join("\n")).toContain("[due] env-app-1 STRIPE_SECRET_KEY: max age 30d");
    // Pushed yesterday: nothing to report
    const fresh = await makeRotationServer({
      built,
      currentEpoch: 2,
      flags: [],
      expiringPushedAtMs: Date.now() - day,
    });
    const freshEnv = await startEnv(fresh, built.projectId);
    expect(await runCli(["rotation", "list"], freshEnv.layer)).toBe(0);
    expect(freshEnv.logs.join("\n")).not.toContain("Expiring values");
  });

  it("--fail-on-due exits 3 when a value is past its max age, --due-within widens it, and fresh values exit 0 (PF7a S-B)", async () => {
    const built = await convergedChain();
    const day = 24 * 60 * 60 * 1000;
    // Expired 10 days ago: the plain listing still exits 0; --fail-on-due makes it 3
    const expired = await makeRotationServer({
      built,
      currentEpoch: 2,
      flags: [],
      expiringPushedAtMs: Date.now() - 40 * day,
    });
    const plain = await startEnv(expired, built.projectId);
    expect(await runCli(["rotation", "list"], plain.layer)).toBe(0);
    const env = await startEnv(expired, built.projectId);
    expect(await runCli(["rotation", "list", "--fail-on-due"], env.layer)).toBe(3);
    expect(env.errors.join("\n")).toContain(
      "Rotation due (exit 3): 1 value past the declared max age (STRIPE_SECRET_KEY)",
    );
    // The listing itself was still printed in full
    expect(env.logs.join("\n")).toContain("[expired] env-app-1 STRIPE_SECRET_KEY");
    // Due in 5 days: past-due-only passes, a 7-day window fails
    const soon = await makeRotationServer({
      built,
      currentEpoch: 2,
      flags: [],
      expiringPushedAtMs: Date.now() - 25 * day,
    });
    const soonPass = await startEnv(soon, built.projectId);
    expect(await runCli(["rotation", "list", "--fail-on-due"], soonPass.layer)).toBe(0);
    const soonFail = await startEnv(soon, built.projectId);
    expect(
      await runCli(["rotation", "list", "--fail-on-due", "--due-within", "7"], soonFail.layer),
    ).toBe(3);
    expect(soonFail.errors.join("\n")).toContain(
      "Rotation due (exit 3): 1 value due within 7 days (STRIPE_SECRET_KEY)",
    );
    // --due-within is meaningless without --fail-on-due (a usage error, before any network)
    const misuse = await startEnv(soon, built.projectId);
    expect(await runCli(["rotation", "list", "--due-within", "7"], misuse.layer)).toBe(2);
    expect(misuse.errors.join("\n")).toContain(
      "--due-within applies to --fail-on-due / --fail-on-pending only",
    );
  });

  it("--fail-on-pending exits 3 while a sealed proposal awaits a member, 0 once none does, and 1 when the list could not be read (PF7b A-9)", async () => {
    const built = await convergedChain();
    const day = 24 * 60 * 60 * 1000;
    const pending = await makeRotationServer({
      built,
      flags: [],
      pendingProposalExpiries: [Date.now() + 3 * day, Date.now() + 20 * day],
    });
    const plain = await startEnv(pending, built.projectId);
    expect(await runCli(["rotation", "list"], plain.layer)).toBe(0);
    expect(plain.logs.join("\n")).toContain(
      "Pending sealed proposals: 2 proposals minted by CI jobs await a member",
    );
    const env = await startEnv(pending, built.projectId);
    expect(
      await runCli(["rotation", "list", "--fail-on-pending", "--due-within", "7"], env.layer),
    ).toBe(3);
    expect(env.errors.join("\n")).toContain(
      "Rotation due (exit 3): 2 sealed proposals awaiting a member (1 expiring within 7 days)",
    );
    const none = await startEnv(
      await makeRotationServer({ built, flags: [], pendingProposalExpiries: [] }),
      built.projectId,
    );
    expect(await runCli(["rotation", "list", "--fail-on-pending"], none.layer)).toBe(0);
    // An unreadable list is a failed check, not a passed one
    const broken = await startEnv(
      await makeRotationServer({ built, flags: [], pendingProposalExpiries: null }),
      built.projectId,
    );
    expect(await runCli(["rotation", "list", "--fail-on-pending"], broken.layer)).toBe(1);
    expect(broken.errors.join("\n")).toContain(
      "Cannot judge the check: the pending proposals are unknown: they could not be read",
    );
  });

  it("the age is the plaintext's: a re-encryption of an old value does not reset the clock (B-9)", async () => {
    const built = await convergedChain();
    const day = 24 * 60 * 60 * 1000;
    const reencrypted = await makeRotationServer({
      built,
      currentEpoch: 2,
      flags: [],
      expiringPushedAtMs: Date.now() - 40 * day,
      reencryptedAtMs: Date.now() - 1 * day,
    });
    const env = await startEnv(reencrypted, built.projectId);
    expect(await runCli(["rotation", "list", "--fail-on-due"], env.layer)).toBe(3);
    expect(env.logs.join("\n")).toContain("[expired] env-app-1 STRIPE_SECRET_KEY");
  });

  it("--fail-on-due exits 1, not 0 or 3, when a history could not be read (an unknown age is not a passed check)", async () => {
    const built = await convergedChain();
    const unreadable = await makeRotationServer({
      built,
      currentEpoch: 2,
      flags: [],
      expiringPushedAtMs: Date.now() - 40 * 24 * 60 * 60 * 1000,
      historyAvailable: false,
    });
    // The plain listing notes the failure and still exits 0
    const plain = await startEnv(unreadable, built.projectId);
    expect(await runCli(["rotation", "list"], plain.layer)).toBe(0);
    expect(plain.errors.join("\n")).toContain(
      "could not read the history of STRIPE_SECRET_KEY in environment env-app-1",
    );
    // The check cannot pass on an age it could not read
    const check = await startEnv(unreadable, built.projectId);
    expect(await runCli(["rotation", "list", "--fail-on-due"], check.layer)).toBe(1);
    expect(check.errors.join("\n")).toContain(
      "Cannot judge the check: the history of 1 value could not be read (env-app-1/STRIPE_SECRET_KEY)",
    );
    // Something known due is due whatever else could not be read (A-10):
    // exit 3 carries the known part, and names the unread part on the line
    const partly = await startEnv(
      await makeRotationServer({
        built,
        currentEpoch: 2,
        flags: [flagFor({ variableId: "va" })],
        expiringPushedAtMs: Date.now() - 40 * 24 * 60 * 60 * 1000,
        historyAvailable: false,
      }),
      built.projectId,
    );
    expect(
      await runCli(["rotation", "list", "--fail-on-due", "--fail-on-flags"], partly.layer),
    ).toBe(3);
    expect(partly.errors.join("\n")).toContain(
      "Rotation due (exit 3): 1 rotation flag active; also the history of 1 value could not be read (env-app-1/STRIPE_SECRET_KEY)",
    );
    // --fail-on-flags alone does not need the age
    const flagsOnly = await startEnv(unreadable, built.projectId);
    expect(await runCli(["rotation", "list", "--fail-on-flags"], flagsOnly.layer)).toBe(0);
  });

  it("describeDue counts days the way the --due-within window does (never 'due today' for a value the window would miss)", () => {
    const day = 24 * 60 * 60 * 1000;
    const nowMs = 1_800_000_000_000;
    const row = (dueAtMs: number) => ({
      environmentId: "env-app-1",
      variableId: "vexp",
      name: "STRIPE_SECRET_KEY",
      maxAgeDays: 30,
      pushedAtMs: 0,
      dueAtMs,
    });
    expect(describeDue(row(nowMs + 0.4 * day), nowMs)).toBe("due in 1 day");
    expect(describeDue(row(nowMs + 1.6 * day), nowMs)).toBe("due in 2 days");
    expect(describeDue(row(nowMs + 7 * day), nowMs)).toBe("due in 7 days");
    expect(describeDue(row(nowMs), nowMs)).toBe("expired today");
    expect(describeDue(row(nowMs - 0.4 * day), nowMs)).toBe("expired today");
    expect(describeDue(row(nowMs - 1.6 * day), nowMs)).toBe("expired 1 day ago");
    expect(describeDue(row(nowMs - 10 * day), nowMs)).toBe("expired 10 days ago");
  });

  it("--fail-on-flags exits 3 while a rotation flag is active (and 0 once none is)", async () => {
    const built = await convergedChain();
    const flagged = await makeRotationServer({
      built,
      currentEpoch: 2,
      flags: [flagFor({ variableId: "va", basis: "read" })],
    });
    const env = await startEnv(flagged, built.projectId);
    expect(await runCli(["rotation", "list", "--fail-on-flags"], env.layer)).toBe(3);
    expect(env.errors.join("\n")).toContain("Rotation due (exit 3): 1 rotation flag active");
    const clear = await makeRotationServer({ built, currentEpoch: 2, flags: [] });
    const clearEnv = await startEnv(clear, built.projectId);
    expect(
      await runCli(["rotation", "list", "--fail-on-flags", "--fail-on-due"], clearEnv.layer),
    ).toBe(0);
    expect(clearEnv.errors.join("\n")).not.toContain("Rotation due");
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
