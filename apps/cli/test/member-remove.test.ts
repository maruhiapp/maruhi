// Integration tests for `maruhi member remove` / `maruhi member
// change-role` (CRYPTO_SPEC §6.2 / §7).
//
// Properties pinned down:
//  1. Appending remove_member + forced rotation of every environment
//     (reason=member-removed). The new epoch's complete wrap set does
//     **not** include the removed target
//  2. Interruption recovery: already appended (target already a
//     non-member) → don't append, resume the sweep / already rotated
//     after removal → confirmation only (chain-derived — no progress file)
//  3. Refusing self-removal and self-demotion below member (the fulfiller
//     of the §7 mandate would vanish)
//  4. change-role: demotion below member sweeps (reason=role-demoted);
//     promotion doesn't. A no-op re-run on a born-reader carries no
//     mandate
//  5. Operations targeting an admin / owner are owner-only (§6.2's early
//     check)

import type { WrappedDek } from "@maruhi/api-schema";
import type { ChainEntry } from "@maruhi/crypto";
import { computeChainEntryHash } from "@maruhi/crypto";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
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
  type TestUser,
  type WireCheckpointSnapshot,
  type WireDistributedManifest,
  type WireRecipientDek,
  wrapDekFor,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, type MockResponse, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "env-app-1";

let owner: TestUser;
let target: TestUser;
let admin2: TestUser;
let dek1: Uint8Array;
let dek2: Uint8Array;

const servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  target = await makeTestUser("user-target-2222");
  admin2 = await makeTestUser("user-admin2-3333");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

interface RotateBody {
  readonly parentHeadHashHex: string;
  readonly entry: ChainEntry & {
    readonly op: "rotate_epoch";
    readonly payload: {
      readonly environmentId: string;
      readonly newEpoch: number;
      readonly reason: string;
      readonly dekCommitmentHex: string;
    };
  };
  readonly deks: readonly WrappedDek[];
  /** The bundled manifest (§12-4 — issued form. issuer is contracted to be the calling principal). */
  readonly manifest: Omit<WireDistributedManifest, "issuerUserId" | "issuerKeyFingerprintHex">;
  /** The boundary checkpoint (H+2 — §12-4's required bundle). */
  readonly checkpoint: ChainEntry & { readonly op: "checkpoint" };
}

interface RemoveServerState {
  readonly handlers: readonly MockHandler[];
  readonly appendedEntries: ChainEntry[];
  readonly rotateBodies: RotateBody[];
  /** dek_wraps registrations (the change-role widening backfill — §12-6). */
  readonly registerBodies: { environmentId: string; deks: readonly WrappedDek[] }[];
  readonly counters: { appendAttempts: number };
}

/**
 * A stateful mock for the remove / change-role flows (a slimmed-down
 * server-revoke test mock): chain GET / append POST, environment list,
 * pull (no variables), and accepting the rotate composite.
 */
async function makeRemoveServer(input: {
  readonly built: BuiltChain;
  readonly environments: Readonly<
    Record<string, { currentEpoch: number; deks: WireRecipientDek[] }>
  >;
  /** An insert into the chain append (409 etc.). undefined = accept. */
  readonly onAppend?: (call: number) => MockResponse | undefined;
  /** When onAppend inserts, swap subsequent chains to this form (a concurrent append). */
  readonly chainAfterConflict?: BuiltChain;
  /** The principal sending the rotate composite (default = owner). Issuer of accepted manifests and recipient of the self-destined wrap it stores. */
  readonly rotator?: TestUser;
  /** Environments listed with a status = "deleted" meta statement (verified deletion). */
  readonly deletedEnvironments?: readonly string[];
}): Promise<RemoveServerState> {
  const rotator = input.rotator ?? owner;
  const projectId = input.built.projectId;
  const entries: ChainEntry[] = [...input.built.entries];
  const hashes: string[] = [...input.built.hashes];
  const appendedEntries: ChainEntry[] = [];
  const rotateBodies: RotateBody[] = [];
  const registerBodies: { environmentId: string; deks: readonly WrappedDek[] }[] = [];
  const counters = { appendAttempts: 0 };
  const environments = input.environments;
  /** Per-environment stored latest manifest (lazily issued on first pull → replaced on rotate acceptance). */
  const manifests = new Map<string, WireDistributedManifest>();
  /** Per-environment stored checkpoint snapshot (§16-2 — no variables = empty enumeration). */
  const checkpointSnapshots = new Map<string, WireCheckpointSnapshot>();
  const deletedEnvironments = input.deletedEnvironments ?? [];
  const listedStatements = await Promise.all(
    [...new Set([...Object.keys(environments), ...deletedEnvironments])].map((environmentId) =>
      environmentStatementFor({
        projectId,
        environmentId,
        name: environmentId,
        author: owner,
        head: headOf(input.built, 1),
        // Deletion is a tombstone (status deleted, metaVersion + 1 — §12-5)
        ...(deletedEnvironments.includes(environmentId)
          ? { status: "deleted" as const, metaVersion: 2 }
          : {}),
      }),
    ),
  );

  const handlers: MockHandler[] = [
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
      const injected = input.onAppend?.(counters.appendAttempts);
      counters.appendAttempts += 1;
      if (injected !== undefined) {
        if (input.chainAfterConflict !== undefined) {
          entries.splice(0, entries.length, ...input.chainAfterConflict.entries);
          hashes.splice(0, hashes.length, ...input.chainAfterConflict.hashes);
        }
        return injected;
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
    onRequest("GET", `/projects/${projectId}/environments`, () => ({
      status: 200,
      json: {
        environments: listedStatements.map((statement) => ({
          environmentId: statement.environmentId,
          currentEpoch: environments[statement.environmentId]?.currentEpoch ?? 1,
          statement,
        })),
      },
    })),
    async (request) => {
      const match = new RegExp(`^/projects/${projectId}/environments/([^/]+)/pull$`).exec(
        request.path,
      );
      if (match === null || request.method !== "GET") {
        return null;
      }
      const environmentId = match[1] ?? "";
      const environment = environments[environmentId];
      if (environment === undefined) {
        return { status: 404, json: { _tag: "EnvironmentNotFound", environmentId: match[1] } };
      }
      const statement = listedStatements.find((item) => item.environmentId === match[1]);
      let manifest = manifests.get(environmentId);
      if (manifest === undefined && statement !== undefined) {
        manifest = await manifestFor({
          projectId,
          environmentId,
          epoch: environment.currentEpoch,
          issuer: owner,
          head: { seq: entries.length, hashHex: hashes[hashes.length - 1] ?? "" },
          envStatement: statement,
          statements: [],
        });
        manifests.set(environmentId, manifest);
      }
      const checkpointSnapshot = checkpointSnapshots.get(environmentId);
      return {
        status: 200,
        json: {
          environmentId: match[1],
          currentEpoch: environment.currentEpoch,
          statement,
          variables: [],
          deletedVariables: [],
          deks: environment.deks,
          manifest,
          // Always bundle the baseline checkpoint's stored row when one
          // exists (§12-7 — rule 2's material)
          ...(checkpointSnapshot === undefined ? {} : { checkpointSnapshot }),
        },
      };
    },
    async (request) => {
      const match = new RegExp(`^/projects/${projectId}/environments/([^/]+)/rotate$`).exec(
        request.path,
      );
      if (match === null || request.method !== "POST") {
        return null;
      }
      const environmentId = match[1] ?? "";
      const environment = environments[environmentId];
      if (environment === undefined) {
        return { status: 404, json: { _tag: "EnvironmentNotFound", environmentId } };
      }
      const body = request.body as RotateBody;
      rotateBodies.push(body);
      // Two entries accepted: rotate + boundary checkpoint (§12-4)
      entries.push(body.entry, body.checkpoint);
      hashes.push(
        await computeChainEntryHash(body.entry),
        await computeChainEntryHash(body.checkpoint),
      );
      // Snapshot stored in the same transaction as acceptance (§16-2 — no
      // variables = empty)
      checkpointSnapshots.set(environmentId, {
        chainSeq: entries.length,
        entryHashHex: hashes[hashes.length - 1] ?? "",
        values: [],
      });
      environment.currentEpoch = body.entry.payload.newEpoch;
      // The accepted bundled manifest (§12-4) becomes the stored latest
      // fed to distribution (§12-5)
      manifests.set(environmentId, {
        ...body.manifest,
        issuerUserId: rotator.userId,
        issuerKeyFingerprintHex: rotator.fingerprintHex,
      });
      for (const wrap of body.deks) {
        if (wrap.recipientUserId !== rotator.userId) {
          continue;
        }
        environment.deks.push({
          suite: wrap.suite,
          epoch: wrap.epoch,
          encHex: wrap.encHex,
          ciphertextHex: wrap.ciphertextHex,
          signatureHex: wrap.signatureHex,
          signerUserId: rotator.userId,
          signerKeyFingerprintHex: rotator.fingerprintHex,
        });
      }
      return {
        status: 200,
        json: {
          environmentId,
          currentEpoch: environment.currentEpoch,
          headSeq: entries.length,
          headHashHex: hashes[hashes.length - 1],
        },
      };
    },
  ];
  // dek_wraps (fetching your own = the backfill's input / registering =
  // the widening's output)
  handlers.push((request) => {
    const match = new RegExp(`^/projects/${projectId}/environments/([^/]+)/deks$`).exec(
      request.path,
    );
    if (match === null) {
      return null;
    }
    const environment = environments[match[1] ?? ""];
    if (environment === undefined) {
      return { status: 404, json: { _tag: "EnvironmentNotFound", environmentId: match[1] } };
    }
    if (request.method === "GET") {
      return { status: 200, json: { deks: environment.deks } };
    }
    if (request.method === "POST") {
      const body = request.body as { readonly deks: readonly WrappedDek[] };
      registerBodies.push({ environmentId: match[1] ?? "", deks: body.deks });
      return { status: 204 };
    }
    return null;
  });
  return { handlers, appendedEntries, rotateBodies, registerBodies, counters };
}

async function startEnv(
  state: RemoveServerState,
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

async function ownerWrap(
  projectId: string,
  environmentId: string,
  epoch: number,
  dek: Uint8Array,
): Promise<WireRecipientDek> {
  return wrapDekFor({ projectId, environmentId, epoch, dek, recipient: owner, signer: owner });
}

describe("maruhi member remove", () => {
  it("appends remove_member and force-rotates every environment with reason=member-removed (no wrap to the removed target)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
      { actor: owner, operation: addMemberOp(admin2, "member") },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)] },
      },
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(0);

    expect(state.appendedEntries).toHaveLength(1);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "remove_member") throw new Error("remove entry missing");
    expect(entry.payload.targetUserId).toBe(target.userId);

    // §7: forced rotation. The complete wrap set = every current member
    // after the removal (including continuing member admin2, not just the
    // caller). The removed target is excluded
    expect(state.rotateBodies).toHaveLength(1);
    const rotate = state.rotateBodies[0];
    if (rotate === undefined) throw new Error("rotate body missing");
    expect(rotate.entry.payload.newEpoch).toBe(2);
    expect(rotate.entry.payload.reason).toBe("member-removed");
    expect(rotate.deks.map((wrap) => wrap.recipientUserId).toSorted()).toEqual(
      [owner.userId, admin2.userId].toSorted(),
    );

    const logs = env.logs.join("\n");
    expect(logs).toContain("Appended remove_member to the chain");
    expect(logs).toContain(
      "Done: the member removal and the rotation of every environment in the target's scope completed",
    );
  });

  it("on detecting a concurrent removal during the ChainHeadConflict (409) resync, doesn't append and proceeds to the sweep (§12-4)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
    ]);
    // Concurrently with the send, another owner device had removed the
    // same target (an extension chain)
    const concurrent = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
      { actor: owner, operation: removeMemberOp(target) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)] },
      },
      onAppend: (call) =>
        call === 0
          ? {
              status: 409,
              json: {
                _tag: "ChainHeadConflict",
                currentHeadSeq: concurrent.entries.length,
                currentHeadHashHex: concurrent.hashes[concurrent.hashes.length - 1] ?? "",
              },
            }
          : undefined,
      chainAfterConflict: concurrent,
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(0);
    // The append was attempted once (409) only — the resync detected the
    // removal and no double-append happens
    expect(state.counters.appendAttempts).toBe(1);
    expect(state.appendedEntries).toHaveLength(0);
    // The §7 mandate (sweep) is fulfilled as one's own share
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("member-removed");
    expect(env.logs.join("\n")).toContain("The target was already removed");
  });

  it("interruption recovery: when the target is already a non-member (remove on record), doesn't append and resumes the sweep", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
      { actor: owner, operation: removeMemberOp(target) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)] },
      },
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("member-removed");
    expect(env.logs.join("\n")).toContain("The target was already removed");
    // A converging command doesn't emit the always-on warning about an
    // unconverged mandate (rotation-sweep.ts): this chain is unconverged at
    // sync time (no rotate after the remove), but our own sweep report
    // conveys the same fact more precisely — don't double-warn
    expect(env.errors.join("\n")).not.toContain("unconverged rotation mandate");
  });

  it("interruption recovery: already rotated and re-encrypted after removal → confirmation only, nothing changes (idempotent)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
      { actor: owner, operation: removeMemberOp(target) },
      { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 2, deks: [await ownerWrap(built.projectId, ENV_ID, 2, dek2)] },
      },
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(0);
    expect(env.logs.join("\n")).toContain("Already rotated (epoch newer than the mandate entry");
  });

  it("refuses removing yourself (you can't fulfil the §7 mandate yourself)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(target, "member") },
    ]);
    const state = await makeRemoveServer({ built, environments: {} });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "remove", owner.userId], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("You cannot remove yourself");
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("an admin removing an admin is owner-only; an unknown target is an error (§6.2's early check)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(admin2, "admin") },
      { actor: owner, operation: addMemberOp(target, "admin") },
    ]);
    const state = await makeRemoveServer({ built, environments: {} });
    const env = await startEnv(state, built.projectId, admin2);
    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Only an owner can run remove_member against an admin / owner",
    );
    expect(state.appendedEntries).toHaveLength(0);

    const state2 = await makeRemoveServer({ built, environments: {} });
    const env2 = await startEnv(state2, built.projectId, owner);
    expect(await runCli(["member", "remove", "user-nobody-0000"], env2.layer)).toBe(1);
    expect(env2.errors.join("\n")).toContain("the chain has no removal record for it");
  });
});

describe("maruhi member change-role", () => {
  it("demotion below member appends + rotates every environment (reason=role-demoted)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)] },
      },
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(
      await runCli(["member", "change-role", target.userId, "--role", "reader"], env.layer),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(1);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "change_role") throw new Error("change_role entry missing");
    expect(entry.payload).toEqual({
      targetUserId: target.userId,
      newRole: "reader",
      // The K2 CLI keeps the target's current scope (all) (--env arrived
      // in K4)
      scopeKind: "all",
      scopeEnvironmentIds: [],
    });
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("role-demoted");
    // The demoted member keeps receiving the new epoch's wrap as a reader
    // (§7 — the mandate is epoch-anchor soundness, not confidentiality)
    expect(state.rotateBodies[0]?.deks.map((wrap) => wrap.recipientUserId).toSorted()).toEqual(
      [owner.userId, target.userId].toSorted(),
    );
    expect(env.logs.join("\n")).toContain(
      "Done: the change and the rotation of the affected environments completed",
    );
  });

  it("promotion (reader → member) carries no rotation mandate", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "reader") },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)] },
      },
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(
      await runCli(["member", "change-role", target.userId, "--role", "member"], env.layer),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(1);
    expect(state.rotateBodies).toHaveLength(0);
    expect(env.logs.join("\n")).toContain(
      "Done: the role / scope was changed (no rotation mandate)",
    );
  });

  it("a no-op re-run on a born-reader member neither appends nor sweeps", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "reader") },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)] },
      },
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(
      await runCli(["member", "change-role", target.userId, "--role", "reader"], env.layer),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(0);
    expect(env.logs.join("\n")).toContain(
      "Done: the role / scope was changed (no rotation mandate)",
    );
  });

  it("interruption recovery: demotion already appended but rotation unfinished → don't append, resume the sweep", async () => {
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
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)] },
      },
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(
      await runCli(["member", "change-role", target.userId, "--role", "reader"], env.layer),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("role-demoted");
    expect(env.logs.join("\n")).toContain("The target already has the specified role");
  });

  it("a no-op re-run on a born-reader doesn't pick up a sweep even with someone's unconverged mandate (the target-scope criterion)", async () => {
    // target was born a reader (no demotion mandate of its own). Someone
    // else's (admin2's) remove follows, and its rotation is unconverged —
    // under a global criterion this no-op would pick up admin2's mandate
    // and kick off a rotation of every environment
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "reader") },
      { actor: owner, operation: addMemberOp(admin2, "member") },
      { actor: owner, operation: removeMemberOp(admin2) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)] },
      },
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(
      await runCli(["member", "change-role", target.userId, "--role", "reader"], env.layer),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(0);
    expect(env.logs.join("\n")).toContain(
      "Done: the role / scope was changed (no rotation mandate)",
    );
  });

  it("demoting oneself below member is refused (the person can't fulfill the §7 mandate themselves)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(admin2, "owner") },
    ]);
    const state = await makeRemoveServer({ built, environments: {} });
    const env = await startEnv(state, built.projectId, owner);

    expect(
      await runCli(["member", "change-role", owner.userId, "--role", "reader"], env.layer),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("You cannot demote yourself below member");
    expect(state.appendedEntries).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Environment scope (2026-09-15 ES K4 — CRYPTO_SPEC §6.2 / §7, design
// record es-design.md §10)
// ---------------------------------------------------------------------------

const ENV_DEV = "env-dev";
const ENV_PROD = "env-prod";

/** A mock's environment set holding the two envs dev / prod (epoch 1), with owner-bound wraps. */
async function twoEnvironments(
  projectId: string,
): Promise<Record<string, { currentEpoch: number; deks: WireRecipientDek[] }>> {
  return {
    [ENV_DEV]: { currentEpoch: 1, deks: [await ownerWrap(projectId, ENV_DEV, 1, dek1)] },
    [ENV_PROD]: { currentEpoch: 1, deks: [await ownerWrap(projectId, ENV_PROD, 1, dek2)] },
  };
}

describe("environment scope (ES K4): the mandate's environment set and change-role --env", () => {
  it("removing a listed{dev} member rotates only dev (remove = the target's current scope — §7)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addScopedMemberOp(target, "member", [ENV_DEV]) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(0);
    expect(state.rotateBodies.map((body) => body.entry.payload.environmentId)).toEqual([ENV_DEV]);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("member-removed");
    expect(env.logs.join("\n")).toContain(
      "Done: the member removal and the rotation of every environment in the target's scope completed",
    );
  });

  it("narrowing via change-role --env rotates only the narrowed portion with reason=scope-narrowed, and the new DEK is not wrapped to the target (R(E))", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addMemberOp(target, "member") },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(
      await runCli(["member", "change-role", target.userId, "--env", ENV_DEV], env.layer),
    ).toBe(0);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "change_role") throw new Error("change_role entry missing");
    // role stays as-is (--role omitted); scope is fully replaced (§6.2)
    expect(entry.payload).toEqual({
      targetUserId: target.userId,
      newRole: "member",
      scopeKind: "listed",
      scopeEnvironmentIds: [ENV_DEV],
    });
    expect(state.rotateBodies.map((body) => body.entry.payload.environmentId)).toEqual([ENV_PROD]);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("scope-narrowed");
    // The new epoch's complete set = R(prod) = { owner } (excludes the
    // narrowed target — §6.3)
    expect(state.rotateBodies[0]?.deks.map((wrap) => wrap.recipientUserId)).toEqual([owner.userId]);
    expect(state.registerBodies).toHaveLength(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(`scope=${ENV_DEV}`);
    expect(logs).toContain("Scope narrowed by 1 environment");
    expect(logs).toContain(
      "Done: the change and the rotation of the affected environments completed",
    );
  });

  it("widening via change-role --all-envs backfills the widened portion's every epoch to the target without rotating (§12-6)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addScopedMemberOp(target, "member", [ENV_DEV]) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "change-role", target.userId, "--all-envs"], env.layer)).toBe(0);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "change_role") throw new Error("change_role entry missing");
    expect(entry.payload).toEqual({
      targetUserId: target.userId,
      newRole: "member",
      scopeKind: "all",
      scopeEnvironmentIds: [],
    });
    expect(state.rotateBodies).toHaveLength(0);
    // The widened portion = prod only (dev is already held). Recipient =
    // the target, epoch 1
    expect(state.registerBodies.map((body) => body.environmentId)).toEqual([ENV_PROD]);
    expect(state.registerBodies[0]?.deks.map((wrap) => [wrap.epoch, wrap.recipientUserId])).toEqual(
      [[1, target.userId]],
    );
    const logs = env.logs.join("\n");
    expect(logs).toContain("1 environment added to the member's scope");
    expect(logs).toContain("Done: the role / scope was changed (no rotation mandate)");
  });

  it("interruption recovery: the narrowing entry already appended but rotate unfinished → re-running the same flags doesn't append and rotates only the narrowed portion", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addMemberOp(target, "member") },
      { actor: owner, operation: changeRoleOp(target, "member", [ENV_DEV]) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(
      await runCli(["member", "change-role", target.userId, "--env", ENV_DEV], env.layer),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies.map((body) => body.entry.payload.environmentId)).toEqual([ENV_PROD]);
    expect(env.logs.join("\n")).toContain("nothing was appended");
  });

  it("a CAS retry resolves the kept side (role / scope) from the post-resync view and doesn't overwrite a concurrent change (Cursor Bugbot)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addMemberOp(target, "reader") },
    ]);
    // Concurrently with the send, another owner device had promoted the
    // target to member (an extension chain)
    const concurrent = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addMemberOp(target, "reader") },
      { actor: owner, operation: changeRoleOp(target, "member", null) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
      onAppend: (call) =>
        call === 0
          ? {
              status: 409,
              json: {
                _tag: "ChainHeadConflict",
                currentHeadSeq: concurrent.entries.length,
                currentHeadHashHex: concurrent.hashes[concurrent.hashes.length - 1] ?? "",
              },
            }
          : undefined,
      chainAfterConflict: concurrent,
    });
    const env = await startEnv(state, built.projectId, owner);

    // A run that only changes scope: the re-sign keeps the post-promotion
    // role (member)
    expect(
      await runCli(["member", "change-role", target.userId, "--env", ENV_DEV], env.layer),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(1);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "change_role") throw new Error("change_role entry missing");
    expect(entry.payload).toEqual({
      targetUserId: target.userId,
      newRole: "member",
      scopeKind: "listed",
      scopeEnvironmentIds: [ENV_DEV],
    });
    expect(entry.seq).toBe(6);
  });

  it("input rules: no-change, combining --env with --all-envs, and --env on an owner are usage errors (before any traffic)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: addMemberOp(target, "admin") },
    ]);
    for (const argv of [
      ["member", "change-role", target.userId],
      ["member", "change-role", target.userId, "--env", ENV_DEV, "--all-envs"],
      ["member", "change-role", target.userId, "--role", "owner", "--env", ENV_DEV],
    ]) {
      const state = await makeRemoveServer({ built, environments: {} });
      const env = await startEnv(state, built.projectId, owner);
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(state.appendedEntries, argv.join(" ")).toHaveLength(0);
    }
    // An unknown environment ID stops at the on-chain existence check
    // (the pre-judgement for unknown-environment)
    const state = await makeRemoveServer({ built, environments: {} });
    const env = await startEnv(state, built.projectId, owner);
    expect(
      await runCli(["member", "change-role", target.userId, "--env", "env-nope"], env.layer),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("does not exist on this project's chain");
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("a valued pull refuses out-of-scope before traffic, while a meta-only one (schema) doesn't care about scope (§6.3 / §12-7 — ruling G-2)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addScopedMemberOp(target, "member", [ENV_DEV]) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
    });
    const server = await MockServer.start([...state.handlers]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, target);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["pull", "--env", ENV_PROD], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      `Cannot operate on environment ${ENV_PROD}: it is outside your environment scope`,
    );
    expect(env.errors.join("\n")).toContain(`your scope: ${ENV_DEV}`);
    expect(server.requests.filter((request) => request.path.includes("/pull"))).toHaveLength(0);

    // A meta-only pull (`maruhi schema`) issues the request even outside
    // scope (the mock doesn't have it so it ends in 404, but it doesn't
    // stop on the scope-refusal wording)
    const schemaEnv = await makeTestEnv();
    seedSession(schemaEnv, server.origin, target);
    await seedConfig(schemaEnv, { server: server.origin, defaultProject: built.projectId });
    await runCli(["schema", "--env", ENV_PROD], schemaEnv.layer);
    expect(schemaEnv.errors.join("\n")).not.toContain("outside your environment scope");
    expect(
      server.requests.filter((request) => request.path.includes(`/${ENV_PROD}/pull/metadata`)),
    ).toHaveLength(1);
  });

  it("interruption recovery: even with a third party's change_role after a widening backfill stalls, re-derive the widened portion from the whole history and resume (pullfrog)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addScopedMemberOp(target, "member", [ENV_DEV]) },
      // Widening (backfill interrupted) → a third party appends a
      // change_role that only changes the role
      { actor: owner, operation: changeRoleOp(target, "member", null) },
      { actor: owner, operation: changeRoleOp(target, "admin", null) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "change-role", target.userId, "--all-envs"], env.layer)).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.registerBodies.map((body) => body.environmentId)).toEqual([ENV_PROD]);
    expect(state.rotateBodies).toHaveLength(0);
  });

  it("refuses narrowing your own scope (you can't fulfil the §7 mandate yourself)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addScopedMemberOp(admin2, "admin", [ENV_DEV, ENV_PROD]) },
    ]);
    const state = await makeRemoveServer({ built, environments: {} });
    const env = await startEnv(state, built.projectId, admin2);
    expect(
      await runCli(["member", "change-role", admin2.userId, "--env", ENV_DEV], env.layer),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("You cannot narrow your own scope");
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("--role owner fully replaces a listed target's scope with all and backfills the widened portion (§6.2 owner = all)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addScopedMemberOp(target, "admin", [ENV_DEV]) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
    });
    const env = await startEnv(state, built.projectId, owner);
    expect(
      await runCli(["member", "change-role", target.userId, "--role", "owner"], env.layer),
    ).toBe(0);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "change_role") throw new Error("change_role entry missing");
    expect(entry.payload).toMatchObject({ newRole: "owner", scopeKind: "all" });
    expect(state.registerBodies.map((body) => body.environmentId)).toEqual([ENV_PROD]);
  });

  it("--no-envs replaces the scope with listed{} (zero environments) and rotates every environment of the old scope as the narrowed portion (§6.2's empty listed)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addScopedMemberOp(target, "admin", [ENV_DEV]) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
    });
    const env = await startEnv(state, built.projectId, owner);
    expect(await runCli(["member", "change-role", target.userId, "--no-envs"], env.layer)).toBe(0);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "change_role") throw new Error("change_role entry missing");
    expect(entry.payload).toMatchObject({
      newRole: "admin",
      scopeKind: "listed",
      scopeEnvironmentIds: [],
    });
    expect(state.rotateBodies.map((body) => body.entry.payload.environmentId)).toEqual([ENV_DEV]);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("scope-narrowed");
  });

  it("change-role --env drops duplicates and malformed forms as usage (2) before traffic", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
    ]);
    for (const argv of [
      ["member", "change-role", target.userId, "--env", ENV_DEV, "--env", ENV_DEV],
      ["member", "change-role", target.userId, "--env", "-bad id"],
      ["member", "change-role", target.userId, "--no-envs", "--all-envs"],
    ]) {
      const state = await makeRemoveServer({ built, environments: {} });
      const env = await startEnv(state, built.projectId, owner);
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(state.appendedEntries, argv.join(" ")).toHaveLength(0);
    }
  });

  it("someone-else's mandate environments outside the caller's scope aren't rotated but are noted, while one's own mandate is fulfilled (§7 — independent review S2)", async () => {
    const devAdmin = await makeTestUser("user-devadmin-4444");
    // owner narrowed target from {dev, prod} to {dev} but prod's rotate is
    // unconverged. A dev-only admin demotes target to reader (symmetric
    // difference ∅ · old ∪ new = {dev} ⊆ {dev})
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addScopedMemberOp(devAdmin, "admin", [ENV_DEV]) },
      { actor: owner, operation: addScopedMemberOp(target, "member", [ENV_DEV, ENV_PROD]) },
      { actor: owner, operation: changeRoleOp(target, "member", [ENV_DEV]) },
    ]);
    // The distributed self-destined wraps are for the caller (devAdmin)
    // (the mock doesn't filter by recipient, so swap them)
    const environments = {
      [ENV_DEV]: {
        currentEpoch: 1,
        deks: [
          await wrapDekFor({
            projectId: built.projectId,
            environmentId: ENV_DEV,
            epoch: 1,
            dek: dek1,
            recipient: devAdmin,
            signer: owner,
          }),
        ],
      },
      [ENV_PROD]: { currentEpoch: 1, deks: [] },
    };
    const state = await makeRemoveServer({ built, environments, rotator: devAdmin });
    const env = await startEnv(state, built.projectId, devAdmin);
    expect(
      await runCli(["member", "change-role", target.userId, "--role", "reader"], env.layer),
    ).toBe(0);
    expect(state.rotateBodies.map((body) => body.entry.payload.environmentId)).toEqual([ENV_DEV]);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("role-demoted");
    expect(env.errors.join("\n")).toContain(
      `1 environment with a pending rotation mandate is outside your scope and cannot be rotated by you (${ENV_PROD})`,
    );
  });

  it("when the unconverged portion of someone else's widening lies only outside your scope, it notes it and exits 0 with no backfill (Cursor Bugbot)", async () => {
    const devAdmin = await makeTestUser("user-devadmin-4444");
    // owner widened target from {dev} to {dev, prod} but prod's backfill
    // is unconverged. A dev-only admin re-runs with the same scope
    // (symmetric difference ∅ = a resume of an already-appended entry)
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addScopedMemberOp(devAdmin, "admin", [ENV_DEV]) },
      { actor: owner, operation: addScopedMemberOp(target, "member", [ENV_DEV]) },
      { actor: owner, operation: changeRoleOp(target, "member", [ENV_DEV, ENV_PROD]) },
    ]);
    const state = await makeRemoveServer({ built, environments: {} });
    const env = await startEnv(state, built.projectId, devAdmin);
    expect(
      await runCli(
        ["member", "change-role", target.userId, "--env", ENV_DEV, "--env", ENV_PROD],
        env.layer,
      ),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.registerBodies).toHaveLength(0);
    expect(env.errors.join("\n")).toContain(
      `1 environment widened earlier for this member (${ENV_PROD}) is outside your scope, so you cannot backfill it`,
    );
  });

  it("a verified-deleted environment leaves the widened portion and doesn't appear in the out-of-scope note (pullfrog)", async () => {
    const devAdmin = await makeTestUser("user-devadmin-4444");
    // Same "someone else's widening is unconverged" as the case above, but
    // prod has since been deleted. No one can fill it, so no note is
    // emitted (the §12-6 mandate vanishes with the deletion)
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addScopedMemberOp(devAdmin, "admin", [ENV_DEV]) },
      { actor: owner, operation: addScopedMemberOp(target, "member", [ENV_DEV]) },
      { actor: owner, operation: changeRoleOp(target, "member", [ENV_DEV, ENV_PROD]) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {},
      deletedEnvironments: [ENV_PROD],
    });
    const env = await startEnv(state, built.projectId, devAdmin);
    expect(
      await runCli(
        ["member", "change-role", target.userId, "--env", ENV_DEV, "--env", ENV_PROD],
        env.layer,
      ),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.registerBodies).toHaveLength(0);
    expect(env.errors.join("\n")).not.toContain("widened earlier for this member");
  });

  it("a listed admin cannot remove a target outside their scope (principle 1's pre-judgement — pullfrog)", async () => {
    const devAdmin = await makeTestUser("user-devadmin-4444");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addScopedMemberOp(devAdmin, "admin", [ENV_DEV]) },
      { actor: owner, operation: addScopedMemberOp(target, "reader", [ENV_DEV, ENV_PROD]) },
    ]);
    const state = await makeRemoveServer({ built, environments: {} });
    const env = await startEnv(state, built.projectId, devAdmin);
    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not contain the target's scope");
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("a listed admin cannot append a change_role touching outside their scope (principle 1's pre-judgement)", async () => {
    const devAdmin = await makeTestUser("user-devadmin-4444");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addScopedMemberOp(devAdmin, "admin", [ENV_DEV]) },
      { actor: owner, operation: addScopedMemberOp(target, "reader", [ENV_DEV, ENV_PROD]) },
    ]);
    // Symmetric difference {prod} ⊄ {dev}: a dev-only admin cannot sign a
    // narrowing away from prod
    const narrow = await makeRemoveServer({ built, environments: {} });
    const narrowEnv = await startEnv(narrow, built.projectId, devAdmin);
    expect(
      await runCli(["member", "change-role", target.userId, "--env", ENV_DEV], narrowEnv.layer),
    ).toBe(1);
    expect(narrowEnv.errors.join("\n")).toContain("scope-not-contained");
    expect(narrow.appendedEntries).toHaveLength(0);
    // When the role changes, old ∪ new = {dev, prod} ⊄ {dev}
    const promote = await makeRemoveServer({ built, environments: {} });
    const promoteEnv = await startEnv(promote, built.projectId, devAdmin);
    expect(
      await runCli(["member", "change-role", target.userId, "--role", "member"], promoteEnv.layer),
    ).toBe(1);
    expect(promoteEnv.errors.join("\n")).toContain("scope-not-contained");
    expect(promote.appendedEntries).toHaveLength(0);
  });
});
