// Integration tests for `maruhi member add` (CRYPTO_SPEC §6.2 / §6.5 / §7, AUTH_SPEC §12-6 / §15).
//
// Properties pinned here:
//  1. add_member is built from the listing's acceptance block (key, user_id;
//     role from the invite row). §6.5's independent verification, issuance-pin
//     match, and FP ceremony (--expect-fingerprint / last-word re-entry /
//     agent refusal) all stand before the append
//  2. Backfill: wraps all environments × all epochs to the new member; 409 =
//     already registered, resumed idempotently (same key already a member → skip the append)
//  3. Re-adding (past membership under another key) deletes the 409 slot then
//     re-registers to repair (key-history gate — a rerun with the same key never deletes)

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import type { WrappedDek } from "@maruhi/api-schema";
import type { ChainEntry } from "@maruhi/crypto";
import { computeChainEntryHash, decodeHex, fingerprintToWords } from "@maruhi/crypto";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  addMemberOp,
  addScopedMemberOp,
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  removeMemberOp,
  rotateEpochOp,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireRecipientDek,
  wrapDekFor,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import {
  type AcceptanceFixture,
  acceptanceFixture,
  flipHex,
  githubSigningKeysHandler,
  INVITE_ID,
  issueInviteFixture,
  type IssuedInviteFixture,
  sshLineOf,
} from "./support/invite.ts";
import { type MockHandler, type MockResponse, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "env-app-1";

let inviter: TestUser;
let acceptor: TestUser;
let dek1: Uint8Array;
let dek2: Uint8Array;

const servers: MockServer[] = [];

beforeAll(async () => {
  inviter = await makeTestUser("user-inviter-11");
  acceptor = await makeTestUser("user-acceptor-22");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

type Acceptance = AcceptanceFixture;

/**
 * The issued invites per project (with the inviter's issuance signature).
 * Prepared by the acceptanceFor / issuedFor calls so invitationRow can synchronously carry the issuance text.
 */
const issuedByProject = new Map<string, IssuedInviteFixture>();

async function issuedFor(projectId: string): Promise<IssuedInviteFixture> {
  const cached = issuedByProject.get(projectId);
  if (cached !== undefined) {
    return cached;
  }
  const issued = await issueInviteFixture({
    inviter,
    projectId,
    headHashHex: "cd".repeat(32),
    headSeq: 1,
  });
  issuedByProject.set(projectId, issued);
  return issued;
}

/** The accepter's own proper acceptance block (with the §6.5 acceptance signature + link signature). */
async function acceptanceFor(projectId: string, invitee: TestUser): Promise<Acceptance> {
  return acceptanceFixture({ projectId, issued: await issuedFor(projectId), invitee });
}

interface AddServerState {
  readonly handlers: readonly MockHandler[];
  readonly appendedEntries: ChainEntry[];
  readonly registerBodies: {
    readonly environmentId: string;
    readonly deks: readonly WrappedDek[];
  }[];
  readonly removeBodies: {
    readonly environmentId: string;
    readonly wraps: readonly { epoch: number; recipientUserId: string }[];
  }[];
  readonly counters: { appendAttempts: number; registerAttempts: number };
}

/** Per-method handler for the dek_wraps route (/environments/:id/deks). */
function onDeksRoute(
  projectId: string,
  method: string,
  respond: (environmentId: string, request: Parameters<MockHandler>[0]) => ReturnType<MockHandler>,
): MockHandler {
  return (request) => {
    const match = new RegExp(`^/projects/${projectId}/environments/([^/]+)/deks$`).exec(
      request.path,
    );
    if (match === null || request.method !== method) {
      return null;
    }
    return respond(match[1] ?? "", request);
  };
}

/**
 * Stateful mock for the member-add flow. Simulates dek_wraps slot occupancy:
 * registering into an (environment:epoch:recipient) present in `occupiedSlots`
 * returns 409 (§12-6's no-overwrite), and deletion frees the slot. A batch
 * registration gets 409 if even one slot is occupied (atomic acceptance).
 */
async function makeAddServer(input: {
  readonly built: BuiltChain;
  readonly invitation: Readonly<Record<string, unknown>>;
  readonly ownDeks: readonly WireRecipientDek[];
  readonly currentEpoch?: number;
  readonly occupiedSlots?: readonly string[];
  /**
   * Slot → the stored recipient enc public key (hex). A 409 on a listed slot
   * carries `storedRecipientEncPubHex` (the post-supplement AUTH_SPEC §12-6
   * server). An unlisted slot's 409 has no field (the pre-supplement server).
   */
  readonly occupiedSlotEncPub?: Readonly<Record<string, string>>;
  readonly listedStatements?: readonly WireDistributedEnvironmentStatement[];
  /** Injection into chain appends (e.g. 409). undefined = accept. */
  readonly onAppend?: (call: number) => MockResponse | undefined;
  /** When onAppend injects, the chain is replaced with this shape from then on (a concurrent append). */
  readonly chainAfterConflict?: BuiltChain;
  /** Injection into dek_wraps registration (call-count based). undefined = normal processing. */
  readonly onRegister?: (call: number) => MockResponse | undefined;
}): Promise<AddServerState> {
  const projectId = input.built.projectId;
  const entries: ChainEntry[] = [...input.built.entries];
  const hashes: string[] = [...input.built.hashes];
  const appendedEntries: ChainEntry[] = [];
  const registerBodies: { environmentId: string; deks: readonly WrappedDek[] }[] = [];
  const removeBodies: {
    environmentId: string;
    wraps: readonly { epoch: number; recipientUserId: string }[];
  }[] = [];
  const counters = { appendAttempts: 0, registerAttempts: 0 };
  const occupied = new Set(input.occupiedSlots ?? []);
  const listedStatements = input.listedStatements ?? [
    await environmentStatementFor({
      projectId,
      environmentId: ENV_ID,
      name: ENV_ID,
      author: inviter,
      head: headOf(input.built, 1),
    }),
  ];

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
    onRequest("GET", `/projects/${projectId}/invites`, () => ({
      status: 200,
      json: { invitations: [input.invitation] },
    })),
    onRequest("GET", `/projects/${projectId}/environments`, () => ({
      status: 200,
      json: {
        environments: listedStatements.map((statement) => ({
          environmentId: statement.environmentId,
          currentEpoch: input.currentEpoch ?? 1,
          statement,
        })),
      },
    })),
    onDeksRoute(projectId, "GET", () => ({ status: 200, json: { deks: input.ownDeks } })),
    onDeksRoute(projectId, "POST", (environmentId, request) => {
      const injected = input.onRegister?.(counters.registerAttempts);
      counters.registerAttempts += 1;
      if (injected !== undefined) {
        return injected;
      }
      const body = request.body as { readonly deks: readonly WrappedDek[] };
      const conflict = body.deks.find((wrap) =>
        occupied.has(`${environmentId}:${wrap.epoch}:${wrap.recipientUserId}`),
      );
      if (conflict !== undefined) {
        const slot = `${environmentId}:${conflict.epoch}:${conflict.recipientUserId}`;
        const storedEncPub = input.occupiedSlotEncPub?.[slot];
        return {
          status: 409,
          json: {
            _tag: "DekWrapExists",
            epoch: conflict.epoch,
            recipientUserId: conflict.recipientUserId,
            // Only a post-supplement AUTH_SPEC §12-6 server carries this (optional field)
            ...(storedEncPub === undefined ? {} : { storedRecipientEncPubHex: storedEncPub }),
          },
        };
      }
      registerBodies.push({ environmentId, deks: body.deks });
      for (const wrap of body.deks) {
        occupied.add(`${environmentId}:${wrap.epoch}:${wrap.recipientUserId}`);
      }
      return { status: 204 };
    }),
    onDeksRoute(projectId, "DELETE", (environmentId, request) => {
      const body = request.body as {
        readonly wraps: readonly { epoch: number; recipientUserId: string }[];
      };
      removeBodies.push({ environmentId, wraps: body.wraps });
      for (const wrap of body.wraps) {
        const slot = `${environmentId}:${wrap.epoch}:${wrap.recipientUserId}`;
        if (!occupied.has(slot)) {
          return {
            status: 404,
            json: {
              _tag: "DekWrapNotFound",
              epoch: wrap.epoch,
              recipientUserId: wrap.recipientUserId,
            },
          };
        }
        occupied.delete(slot);
      }
      return { status: 204 };
    }),
  ];
  return { handlers, appendedEntries, registerBodies, removeBodies, counters };
}

function invitationRow(
  projectId: string,
  acceptance: Acceptance | null,
  overrides?: Readonly<Record<string, unknown>>,
): Record<string, unknown> {
  return {
    id: INVITE_ID,
    projectId,
    role: "member",
    scopeKind: "all",
    scopeEnvironmentIds: [],
    status: acceptance === null ? "pending" : "accepted",
    inviterUserId: inviter.userId,
    issuance: issuedByProject.get(projectId)?.issuance ?? null,
    createdAtMs: 1755200000000,
    expiresAtMs: 1755993600000,
    acceptance,
    ...overrides,
  };
}

async function startAddEnv(
  state: AddServerState,
  projectId: string,
): Promise<TestEnv & { readonly serverOrigin: string }> {
  const server = await MockServer.start([...state.handlers]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, inviter);
  await seedConfig(env, { server: server.origin, defaultProject: projectId });
  return { ...env, serverOrigin: server.origin };
}

/** Reads the fingerprint book (KF) file contents. */
async function readBook(
  env: TestEnv,
): Promise<Record<string, Record<string, { fingerprints: Record<string, unknown> }>>> {
  const json = await readFile(env.fingerprintBookPath, "utf8");
  return (
    JSON.parse(json) as {
      known: Record<string, Record<string, { fingerprints: Record<string, unknown> }>>;
    }
  ).known;
}

describe("maruhi member add", () => {
  it("builds add_member from the acceptance block and backfills all environments × all epochs (--expect-fingerprint)", async () => {
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: inviter, operation: rotateEpochOp(ENV_ID, 2, dek2) },
    ]);
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor)),
      currentEpoch: 2,
      ownDeks: [
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: inviter,
          signer: inviter,
        }),
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 2,
          dek: dek2,
          recipient: inviter,
          signer: inviter,
        }),
      ],
    });
    const env = await startAddEnv(state, built.projectId);

    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(0);

    // add_member payload = the acceptance block's key + the invite row's role
    expect(state.appendedEntries).toHaveLength(1);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "add_member") throw new Error("add_member entry missing");
    expect(entry.payload).toEqual({
      targetUserId: acceptor.userId,
      encPubHex: acceptor.encPubHex,
      sigPubHex: acceptor.sigPubHex,
      role: "member",
      // Signs with the invite row's scope (the K2 CLI issues only all) — AUTH_SPEC §15-2
      scopeKind: "all",
      scopeEnvironmentIds: [],
    });

    // Backfill: wraps epochs 1-2 to the new member (accepted as a single batch)
    expect(state.registerBodies).toHaveLength(1);
    const wraps = state.registerBodies[0]?.deks ?? [];
    expect(wraps.map((wrap) => [wrap.epoch, wrap.recipientUserId])).toEqual([
      [1, acceptor.userId],
      [2, acceptor.userId],
    ]);
    expect(wraps.every((wrap) => wrap.recipientEncPubHex === acceptor.encPubHex)).toBe(true);
    expect(state.removeBodies).toHaveLength(0);
    expect(env.logs.join("\n")).toContain(
      "Done: DEK wraps for every environment in the member's scope × every epoch were distributed to the new member (CRYPTO_SPEC §7)",
    );
  });

  it("rejects add_member before the ceremony when the executor's scope does not contain the invite row's scope (principle 1 — independent review S1)", async () => {
    const devAdmin = await makeTestUser("user-devadmin-4444");
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: inviter, operation: createEnvironmentOp("env-prod", dek2) },
      { actor: inviter, operation: addScopedMemberOp(devAdmin, "admin", [ENV_ID]) },
    ]);
    // The invite row is all (issuer = owner). A dev-only admin runs add
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor)),
      currentEpoch: 1,
      ownDeks: [],
    });
    const server = await MockServer.start([...state.handlers]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, devAdmin);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
    env.setAgent({ isAgent: true, name: "testbot" });
    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("does not contain the invite's scope");
    // Neither the ceremony (agent refusal) nor the append is reached
    expect(env.errors.join("\n")).not.toContain("AI agent environment");
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("a listed-scope invite is signed with the invite row's scope and backfill is limited to the target scope's environments (ES K4 — §7)", async () => {
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: inviter, operation: createEnvironmentOp("env-prod", dek2) },
    ]);
    // The issuance text covers the scope (CRYPTO_SPEC §6.5), so the acceptance block is built from the listed issuance text
    issuedByProject.set(
      built.projectId,
      await issueInviteFixture({
        inviter,
        projectId: built.projectId,
        headHashHex: "cd".repeat(32),
        headSeq: 1,
        scope: { scopeKind: "listed", scopeEnvironmentIds: [ENV_ID] },
      }),
    );
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor), {
        scopeKind: "listed",
        scopeEnvironmentIds: [ENV_ID],
      }),
      currentEpoch: 1,
      ownDeks: [
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: inviter,
          signer: inviter,
        }),
      ],
      listedStatements: [
        await environmentStatementFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          name: ENV_ID,
          author: inviter,
          head: headOf(built, 1),
        }),
        await environmentStatementFor({
          projectId: built.projectId,
          environmentId: "env-prod",
          name: "env-prod",
          author: inviter,
          head: headOf(built, 1),
        }),
      ],
    });
    const env = await startAddEnv(state, built.projectId);

    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(0);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "add_member") throw new Error("add_member entry missing");
    expect(entry.payload.role).toBe("member");
    expect(entry.payload.scopeKind).toBe("listed");
    expect(entry.payload.scopeEnvironmentIds).toEqual([ENV_ID]);
    // prod is outside the target scope — no wrap is made (making one gets the server to return 422 scope-out-of-range)
    expect(state.registerBodies.map((body) => body.environmentId)).toEqual([ENV_ID]);
    expect(env.logs.join("\n")).toContain("in the member's scope × every epoch");
    // A chain built by the same steps gets the same projectId — do not leak the listed issuance text into other tests
    issuedByProject.delete(built.projectId);
  });

  it("re-syncs on ChainHeadConflict (409), re-signs add_member, and retries (§12-4)", async () => {
    const passerby = await makeTestUser("user-passerby-5555");
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    // A chain grown by another member's append concurrent with the send (an extension of the same prefix)
    const concurrent = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: inviter, operation: addMemberOp(passerby, "reader") },
    ]);
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor)),
      ownDeks: [
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: inviter,
          signer: inviter,
        }),
      ],
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
    const env = await startAddEnv(state, built.projectId);

    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(0);

    // The append is attempted twice (409 → re-sync + re-sign → accepted). The accepted entry is a child of the new head
    expect(state.counters.appendAttempts).toBe(2);
    expect(state.appendedEntries).toHaveLength(1);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "add_member") throw new Error("add_member entry missing");
    expect(entry.seq).toBe(concurrent.entries.length + 1);
    expect(entry.payload.targetUserId).toBe(acceptor.userId);
    // The backfill completes too
    expect(
      state.registerBodies.flatMap((body) => body.deks.map((wrap) => wrap.recipientUserId)),
    ).toEqual([acceptor.userId]);
  });

  it("when re-registration fails after a repair-path deletion, fails while making explicit that the slot is empty", async () => {
    // Delete → re-register is not atomic: a failure in between leaves the target
    // with no wrap for that epoch. Buried in generic wording, that goes unnoticed
    const oldKeys = await makeTestUser(acceptor.userId);
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: inviter, operation: addMemberOp(oldKeys, "member") },
      { actor: inviter, operation: removeMemberOp(oldKeys) },
      { actor: inviter, operation: rotateEpochOp(ENV_ID, 2, dek2) },
    ]);
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor)),
      currentEpoch: 2,
      ownDeks: [
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: inviter,
          signer: inviter,
        }),
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 2,
          dek: dek2,
          recipient: inviter,
          signer: inviter,
        }),
      ],
      occupiedSlots: [`${ENV_ID}:1:${acceptor.userId}`],
      // Call order: 0 = batch (409) → 1 = epoch-1 single (409) → delete → 2 = re-register
      onRegister: (call) => (call === 2 ? { status: 500, json: {} } : undefined),
    });
    const env = await startAddEnv(state, built.projectId);

    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(1);
    // The delete already ran = the slot is empty
    expect(state.removeBodies).toEqual([
      {
        environmentId: ENV_ID,
        wraps: [
          {
            epoch: 1,
            recipientUserId: acceptor.userId,
            recipientEncPubHex: expect.any(String) as string,
          },
        ],
      },
    ]);
    const errors = env.errors.join("\n");
    expect(errors).toContain("slot remains empty");
    expect(errors).toContain("re-run `maruhi member add` to resume");
  });

  it("can add through the ceremony (last-word re-entry); an agent environment refuses without the flag", async () => {
    const acceptorFpBytes = decodeHex(acceptor.fingerprintHex);
    if (acceptorFpBytes === null) throw new Error("fp");
    const words = await fingerprintToWords(acceptorFpBytes);
    if (!words.ok) throw new Error("words");

    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    const ownDeks = [
      await wrapDekFor({
        projectId: built.projectId,
        environmentId: ENV_ID,
        epoch: 1,
        dek: dek1,
        recipient: inviter,
        signer: inviter,
      }),
    ];
    const acceptance = await acceptanceFor(built.projectId, acceptor);

    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, acceptance),
      ownDeks,
    });
    const env = await startAddEnv(state, built.projectId);
    env.setPromptResponses([words.value[words.value.length - 1] ?? ""]);
    expect(await runCli(["member", "add"], env.layer)).toBe(0);
    expect(state.appendedEntries).toHaveLength(1);
    expect(env.logs.join("\n")).toContain(`role:    member (will be granted to this member)`);

    // Agent environment: no --expect-fingerprint is refused (never let it stand in for the ceremony)
    const state2 = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, acceptance),
      ownDeks,
    });
    const env2 = await startAddEnv(state2, built.projectId);
    env2.setAgent({ isAgent: true });
    expect(await runCli(["member", "add"], env2.layer)).toBe(1);
    expect(env2.errors.join("\n")).toContain(
      "Refused to run the acceptance-key confirmation ceremony",
    );
    expect(state2.appendedEntries).toHaveLength(0);
  });

  it("interruption recovery: if already a member with the same key, skips the append and converges the backfill's 409 as already-registered", async () => {
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: inviter, operation: addMemberOp(acceptor, "member") },
    ]);
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor)),
      ownDeks: [
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: inviter,
          signer: inviter,
        }),
      ],
      // The previous run already registered (membership under the acceptance key = no repair needed)
      occupiedSlots: [`${ENV_ID}:1:${acceptor.userId}`],
    });
    const env = await startAddEnv(state, built.projectId);

    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.registerBodies).toHaveLength(0);
    // Membership under the same key never triggers delete (repair) — the key-history gate
    expect(state.removeBodies).toHaveLength(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain("already a member with the same key");
    expect(logs).toContain("1 already registered");
  });

  it("re-adding (past membership under another key): deletes the 409 slot then re-registers to repair to the new key", async () => {
    // The old key identity for the same user_id (past membership)
    const oldKeys = await makeTestUser(acceptor.userId);
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: inviter, operation: addMemberOp(oldKeys, "member") },
      { actor: inviter, operation: removeMemberOp(oldKeys) },
      { actor: inviter, operation: rotateEpochOp(ENV_ID, 2, dek2) },
    ]);
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor)),
      currentEpoch: 2,
      ownDeks: [
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: inviter,
          signer: inviter,
        }),
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 2,
          dek: dek2,
          recipient: inviter,
          signer: inviter,
        }),
      ],
      // The old-key wrap from the past membership occupies the epoch-1 slot
      occupiedSlots: [`${ENV_ID}:1:${acceptor.userId}`],
    });
    const env = await startAddEnv(state, built.projectId);

    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(0);

    // epoch 1 is deleted → re-registered (repair); epoch 2 registers normally
    expect(state.removeBodies).toEqual([
      {
        environmentId: ENV_ID,
        wraps: [
          {
            epoch: 1,
            recipientUserId: acceptor.userId,
            recipientEncPubHex: expect.any(String) as string,
          },
        ],
      },
    ]);
    const registered = state.registerBodies.flatMap((body) =>
      body.deks.map((wrap) => [wrap.epoch, wrap.recipientEncPubHex] as const),
    );
    // The re-registered epoch-1 wrap is addressed to the **new key** (the substance of the repair)
    expect(registered).toContainEqual([1, acceptor.encPubHex]);
    expect(registered).toContainEqual([2, acceptor.encPubHex]);
    const logs = env.logs.join("\n");
    expect(logs).toContain("If leftover wraps addressed to the old key are found, the repair path");
    expect(logs).toContain("1 old-key wrap repaired");
  });

  it("does not delete when the 409's stored enc public key matches the acceptance key — even with a different-key membership history (blocks mis-deletion)", async () => {
    // A rerun of "past membership under another key + the immediately preceding
    // member add partially completed under the current key". The key-history
    // heuristic suspects stale (the old check would mis-delete), but the 409
    // carries the stored enc public key (= the current key), so an exact comparison detects already-registered (AUTH_SPEC §12-6 supplement)
    const oldKeys = await makeTestUser(acceptor.userId);
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: inviter, operation: addMemberOp(oldKeys, "member") },
      { actor: inviter, operation: removeMemberOp(oldKeys) },
      { actor: inviter, operation: rotateEpochOp(ENV_ID, 2, dek2) },
      // Re-adding under the current key was already accepted (the previous run interrupted) — resume backfill only
      { actor: inviter, operation: addMemberOp(acceptor, "member") },
    ]);
    const slot = `${ENV_ID}:1:${acceptor.userId}`;
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor)),
      currentEpoch: 2,
      ownDeks: [
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: inviter,
          signer: inviter,
        }),
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 2,
          dek: dek2,
          recipient: inviter,
          signer: inviter,
        }),
      ],
      // The previous run already registered epoch 1 **under the current key** (partial completion)
      occupiedSlots: [slot],
      occupiedSlotEncPub: { [slot]: acceptor.encPubHex },
    });
    const env = await startAddEnv(state, built.projectId);

    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(0);
    // A match = already registered (idempotent). Not a single delete (mis-deletion) fires
    expect(state.removeBodies).toHaveLength(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain("1 already registered");
    expect(logs).not.toContain("old-key wraps repaired");
  });

  it("repairs when the 409's stored enc public key mismatches the acceptance key, regardless of key history (the field wins)", async () => {
    // The key history has no other key (the heuristic does not suspect stale),
    // but the 409's field declares another key. Pins that the field **wins over**
    // the heuristic (a mutation dropping the comparison for estimation fails only this test)
    const strangerKeys = await makeTestUser("user-someone-else");
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    const slot = `${ENV_ID}:1:${acceptor.userId}`;
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor)),
      ownDeks: [
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: inviter,
          signer: inviter,
        }),
      ],
      occupiedSlots: [slot],
      occupiedSlotEncPub: { [slot]: strangerKeys.encPubHex },
    });
    const env = await startAddEnv(state, built.projectId);

    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(0);
    // A mismatch = repair (delete → re-register). Independent of the key-history gate
    expect(state.removeBodies).toEqual([
      {
        environmentId: ENV_ID,
        wraps: [
          {
            epoch: 1,
            recipientUserId: acceptor.userId,
            recipientEncPubHex: expect.any(String) as string,
          },
        ],
      },
    ]);
    const registered = state.registerBodies.flatMap((body) =>
      body.deks.map((wrap) => [wrap.epoch, wrap.recipientEncPubHex] as const),
    );
    expect(registered).toContainEqual([1, acceptor.encPubHex]);
    const logs = env.logs.join("\n");
    expect(logs).toContain("1 old-key wrap repaired");
  });

  it("a completed row can resume with an explicit id; a rerun without id guides toward that path", async () => {
    // The shape where add_member already ran (the server updated the row to completed) + the backfill was interrupted
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: inviter, operation: addMemberOp(acceptor, "member") },
    ]);
    const acceptance = await acceptanceFor(built.projectId, acceptor);
    const completedRow = invitationRow(built.projectId, acceptance, { status: "completed" });
    const ownDeks = [
      await wrapDekFor({
        projectId: built.projectId,
        environmentId: ENV_ID,
        epoch: 1,
        dek: dek1,
        recipient: inviter,
        signer: inviter,
      }),
    ];

    // No id: a completed row is never auto-selected (past members' rows
    // accumulate), but the error guides toward the resume path (explicit id)
    const state1 = await makeAddServer({ built, invitation: completedRow, ownDeks });
    const env1 = await startAddEnv(state1, built.projectId);
    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env1.layer),
    ).toBe(1);
    expect(env1.errors.join("\n")).toContain("pass it explicitly: `maruhi member add <invite-id>`");
    expect(state1.appendedEntries).toHaveLength(0);

    // Explicit id: completed row + same-key membership → no append; resume backfill only
    const state2 = await makeAddServer({ built, invitation: completedRow, ownDeks });
    const env2 = await startAddEnv(state2, built.projectId);
    expect(
      await runCli(
        ["member", "add", INVITE_ID, "--expect-fingerprint", acceptor.fingerprintHex],
        env2.layer,
      ),
    ).toBe(0);
    expect(state2.appendedEntries).toHaveLength(0);
    expect(
      state2.registerBodies.flatMap((body) => body.deks.map((wrap) => wrap.recipientUserId)),
    ).toEqual([acceptor.userId]);
    expect(env2.logs.join("\n")).toContain("already a member with the same key");
  });

  it("aborts before appending on issuance-signature / link-signature / acceptance-signature failure, issuance-pin mismatch, or a missing issuance text", async () => {
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    const acceptance = await acceptanceFor(built.projectId, acceptor);

    for (const [invitation, fragment] of [
      // role tampering (covered by the issuance signature — fails issuance-text verification)
      [
        invitationRow(built.projectId, acceptance, { role: "admin" }),
        "issue signature that does not verify",
      ],
      // key swapping (breaks the declared-key binding of both signatures — the link signature is reported first)
      [
        invitationRow(built.projectId, { ...acceptance, inviteeEncPubHex: "aa".repeat(32) }),
        "the link signature failed verification",
      ],
      // tampering of the acceptance signature only
      [
        invitationRow(built.projectId, {
          ...acceptance,
          signatureHex: flipHex(acceptance.signatureHex),
        }),
        "the acceptance signature failed verification",
      ],
    ] as const) {
      const state = await makeAddServer({ built, invitation, ownDeks: [] });
      const env = await startAddEnv(state, built.projectId);
      expect(
        await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
        fragment,
      ).toBe(1);
      expect(env.errors.join("\n"), fragment).toContain(fragment);
      expect(state.appendedEntries, fragment).toHaveLength(0);
    }

    // A server declaration whose issuance pin and link_pub disagree (row substitution)
    const state2 = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, acceptance),
      ownDeks: [],
    });
    const env2 = await startAddEnv(state2, built.projectId);
    await mkdir(env2.pinsDir, { recursive: true });
    await writeFile(
      join(env2.pinsDir, `${built.projectId}.json`),
      JSON.stringify({
        v: 1,
        anchor: null,
        issued: {
          [INVITE_ID]: {
            linkPubHex: "ee".repeat(32),
            role: "member",
            expiresAtMs: 1755993600000,
            expectedGithubLogin: null,
          },
        },
      }),
    );
    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env2.layer),
    ).toBe(1);
    expect(env2.errors.join("\n")).toContain("does not match the local record from issuance");
    expect(state2.appendedEntries).toHaveLength(0);
  });

  it("rejects as duplicate-member-key before appending when the acceptance key matches a current member's key", async () => {
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    // The shape where an attacker declares the inviter's public key verbatim in
    // their acceptance (the signature is self-bound, so it cannot be made without
    // the inviter's secret key — only the early consensus-rule check is under test here, so we build a "key reuse" acceptance signed with the inviter's own key)
    const sock = await acceptanceFixture({
      projectId: built.projectId,
      issued: await issuedFor(built.projectId),
      invitee: inviter,
      inviteeUserId: "user-sock-99999",
    });
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, sock),
      ownDeks: [],
    });
    const env = await startAddEnv(state, built.projectId);
    expect(
      await runCli(["member", "add", "--expect-fingerprint", inviter.fingerprintHex], env.layer),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("duplicate-member-key");
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("an --expect-fingerprint mismatch (suspected interception) aborts before appending", async () => {
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor)),
      ownDeks: [],
    });
    const env = await startAddEnv(state, built.projectId);
    expect(await runCli(["member", "add", "--expect-fingerprint", "0".repeat(32)], env.layer)).toBe(
      1,
    );
    expect(env.errors.join("\n")).toContain("The acceptance may have been hijacked");
    expect(state.appendedEntries).toHaveLength(0);
  });

  describe("the identity-backing source (IV2 — fulfillment shape 4)", () => {
    /** Adds an impersonated GitHub signing-key list to a server state with an accepted invite + one environment. */
    async function backedState(
      built: BuiltChain,
      registeredKeys: readonly string[],
      status = 200,
    ): Promise<AddServerState> {
      const state = await makeAddServer({
        built,
        invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor)),
        ownDeks: [
          await wrapDekFor({
            projectId: built.projectId,
            environmentId: ENV_ID,
            epoch: 1,
            dek: dek1,
            recipient: inviter,
            signer: inviter,
          }),
        ],
      });
      return {
        ...state,
        handlers: [...state.handlers, githubSigningKeysHandler("bob", registeredKeys, status)],
      };
    }

    async function backedEnv(
      state: AddServerState,
      projectId: string,
    ): Promise<TestEnv & { readonly serverOrigin: string }> {
      const env = await startAddEnv(state, projectId);
      env.setVendorOrigin("api.github.com", env.serverOrigin);
      return env;
    }

    async function chain(): Promise<BuiltChain> {
      return buildChain([
        { actor: inviter, operation: genesisOp(inviter) },
        { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
      ]);
    }

    it("proceeds to add_member without confirmation input when the --github peer already has the acceptance key registered (even in an agent environment)", async () => {
      const built = await chain();
      const state = await backedState(built, [sshLineOf(acceptor)]);
      const env = await backedEnv(state, built.projectId);
      expect(await runCli(["member", "add", "--github", "bob"], env.layer)).toBe(0);
      expect(env.prompts).toHaveLength(0);
      expect(state.appendedEntries).toHaveLength(1);
      expect(env.logs.join("\n")).toContain(
        "Acceptance key verified: it is registered as a signing key on github.com/bob",
      );
      // A successful machine match is not recorded to the book (the book records human out-of-band confirmation — ruling D ②)
      await expect(readBook(env)).rejects.toThrow();

      const state2 = await backedState(built, [sshLineOf(acceptor)]);
      const env2 = await backedEnv(state2, built.projectId);
      env2.setAgent({ isAgent: true, name: "test-agent" });
      expect(await runCli(["member", "add", "--github", "bob"], env2.layer)).toBe(0);
      expect(env2.prompts).toHaveLength(0);
      expect(state2.appendedEntries).toHaveLength(1);
    });

    it("uses the issuance pin's destination login as the default, and still requires --expect-fingerprint on top of the match", async () => {
      const built = await chain();
      const state = await backedState(built, [sshLineOf(acceptor)]);
      const env = await backedEnv(state, built.projectId);
      const issued = await issuedFor(built.projectId);
      await mkdir(env.pinsDir, { recursive: true });
      await writeFile(
        join(env.pinsDir, `${built.projectId}.json`),
        JSON.stringify({
          v: 1,
          anchor: null,
          issued: {
            [INVITE_ID]: {
              linkPubHex: issued.linkPubHex,
              role: "member",
              expiresAtMs: 1755993600000,
              expectedGithubLogin: "bob",
            },
          },
        }),
      );
      expect(await runCli(["member", "add"], env.layer)).toBe(0);
      expect(env.prompts).toHaveLength(0);
      expect(env.logs.join("\n")).toContain("The invite was issued for github.com/bob");
      expect(state.appendedEntries).toHaveLength(1);

      const state2 = await backedState(built, [sshLineOf(acceptor)]);
      const env2 = await backedEnv(state2, built.projectId);
      expect(
        await runCli(
          ["member", "add", "--github", "bob", "--expect-fingerprint", "0".repeat(32)],
          env2.layer,
        ),
      ).toBe(1);
      expect(env2.errors.join("\n")).toContain("The acceptance may have been hijacked");
      expect(state2.appendedEntries).toHaveLength(0);
    });

    it("unregistered stops at a two-way choice (default = ask them to re-run, yes = run the ceremony now). An unreachable listing goes to the ceremony", async () => {
      const acceptorFpBytes = decodeHex(acceptor.fingerprintHex);
      if (acceptorFpBytes === null) throw new Error("fp");
      const words = await fingerprintToWords(acceptorFpBytes);
      if (!words.ok) throw new Error("words");
      const built = await chain();

      // Unregistered + empty answer → stops without appending
      const state = await backedState(built, [sshLineOf(inviter)]);
      const env = await backedEnv(state, built.projectId);
      env.setPromptResponses([""]);
      expect(await runCli(["member", "add", "--github", "bob"], env.layer)).toBe(1);
      expect(env.prompts[0]).toContain("Type yes to confirm the 12 words now");
      expect(env.errors.join("\n")).toContain(
        "Ask github.com/bob to register their key with `maruhi key publish`",
      );
      expect(state.appendedEntries).toHaveLength(0);

      // Unregistered + yes → to the ceremony (last word)
      const state2 = await backedState(built, [sshLineOf(inviter)]);
      const env2 = await backedEnv(state2, built.projectId);
      env2.setPromptResponses(["yes", words.value[words.value.length - 1] ?? ""]);
      expect(await runCli(["member", "add", "--github", "bob"], env2.layer)).toBe(0);
      expect(env2.prompts).toHaveLength(2);
      expect(env2.prompts[1]).toContain("type the last of the 12 words");
      expect(state2.appendedEntries).toHaveLength(1);

      // Unreachable (cap) → note + ceremony (no two-way choice)
      const state3 = await backedState(built, [], 403);
      const env3 = await backedEnv(state3, built.projectId);
      env3.setPromptResponses([words.value[words.value.length - 1] ?? ""]);
      expect(await runCli(["member", "add", "--github", "bob"], env3.layer)).toBe(0);
      expect(env3.prompts).toHaveLength(1);
      expect(env3.errors.join("\n")).toContain("could not be fetched");
      expect(state3.appendedEntries).toHaveLength(1);

      // identityBacking = none → no match (note + ceremony)
      const state4 = await backedState(built, [sshLineOf(acceptor)]);
      const env4 = await backedEnv(state4, built.projectId);
      await seedConfig(env4, {
        server: env4.serverOrigin,
        defaultProject: built.projectId,
        identityBacking: "none",
      });
      env4.setPromptResponses([words.value[words.value.length - 1] ?? ""]);
      expect(await runCli(["member", "add", "--github", "bob"], env4.layer)).toBe(0);
      expect(env4.errors.join("\n")).toContain("identityBacking is none");
      expect(env4.prompts).toHaveLength(1);
    });
  });

  it("fingerprint book: a ceremony success is recorded and a rerun passes with a yes confirmation only (an agent environment is still refused) (KF)", async () => {
    const acceptorFpBytes = decodeHex(acceptor.fingerprintHex);
    if (acceptorFpBytes === null) throw new Error("fp");
    const words = await fingerprintToWords(acceptorFpBytes);
    if (!words.ok) throw new Error("words");

    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor)),
      ownDeks: [
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: inviter,
          signer: inviter,
        }),
      ],
    });
    const env = await startAddEnv(state, built.projectId);

    // Run 1: the ceremony (last-word re-entry) → the success is recorded to the book
    env.setPromptResponses([words.value[words.value.length - 1] ?? ""]);
    expect(await runCli(["member", "add"], env.layer)).toBe(0);
    expect(env.prompts).toHaveLength(1);
    const recorded = await readBook(env);
    // Added to the set (DK — old records are not erased; they remain as the same person's other devices)
    expect(
      Object.keys(recorded[env.serverOrigin]?.[acceptor.userId]?.fingerprints ?? {}),
    ).toContain(acceptor.fingerprintHex);
    expect(env.errors.join("\n")).toContain("recorded the verified fingerprint");

    // Run 2 (already a member → backfill-only rerun): a book hit exempts the
    // 12-word read-out re-run, but the explicit yes confirmation of the grant
    // itself remains. The two read-out-match instruction lines are not printed on a hit (no exemption note right after the instruction)
    const logsBeforeSecondRun = env.logs.length;
    env.setPromptResponses(["yes"]);
    expect(await runCli(["member", "add"], env.layer)).toBe(0);
    expect(env.prompts).toHaveLength(2);
    expect(env.prompts[1]).toContain("Type yes to add");
    const secondRunLogs = env.logs.slice(logsBeforeSecondRun).join("\n");
    expect(secondRunLogs).toContain("not required again");
    expect(secondRunLogs).not.toContain("reads to you out of band");

    // Run 3 (agent environment): a book hit does not allow standing in (the flag is required)
    env.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["member", "add"], env.layer)).toBe(1);
    expect(env.prompts).toHaveLength(2);
    expect(env.errors.join("\n")).toContain(
      "Refused to run the acceptance-key confirmation ceremony",
    );

    // Run 4 (non-interactive — stdin is a pipe): a book hit does not advance to
    // the yes confirmation; it returns to the full ceremony (last-word re-entry)
    // — a blind `printf yes |` cannot pass (the primary boundary is the terminal)
    env.setAgent({ isAgent: false });
    env.setTerminal({ stdin: false });
    env.setPromptResponses([words.value[words.value.length - 1] ?? ""]);
    expect(await runCli(["member", "add"], env.layer)).toBe(0);
    expect(env.prompts).toHaveLength(3);
    expect(env.prompts[2]).toContain("type the last of the 12 words");
    expect(env.errors.join("\n")).toContain("stdin is not an interactive terminal");

    // Run 5 (stdout redirected): the boundary is stdin AND stdout (&&) — pins a
    // single-sided implementation mistake
    env.setTerminal({ stdin: true, stdout: false });
    env.setPromptResponses([words.value[words.value.length - 1] ?? ""]);
    expect(await runCli(["member", "add"], env.layer)).toBe(0);
    expect(env.prompts).toHaveLength(4);
    expect(env.prompts[3]).toContain("type the last of the 12 words");
    expect(env.errors.join("\n")).toContain("stdout is not an interactive terminal");
  });

  it("fingerprint book: a mismatch never auto-passes — it warns, returns to the ceremony, and a success overwrites (KF)", async () => {
    const acceptorFpBytes = decodeHex(acceptor.fingerprintHex);
    if (acceptorFpBytes === null) throw new Error("fp");
    const words = await fingerprintToWords(acceptorFpBytes);
    if (!words.ok) throw new Error("words");

    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    const invitation = invitationRow(
      built.projectId,
      await acceptanceFor(built.projectId, acceptor),
    );
    const ownDeks = [
      await wrapDekFor({
        projectId: built.projectId,
        environmentId: ENV_ID,
        epoch: 1,
        dek: dek1,
        recipient: inviter,
        signer: inviter,
      }),
    ];
    const seedStaleBook = async (env: TestEnv & { readonly serverOrigin: string }) => {
      await writeFile(
        env.fingerprintBookPath,
        JSON.stringify({
          v: 1,
          known: {
            [env.serverOrigin]: {
              [acceptor.userId]: { fingerprintHex: "00".repeat(16), verifiedAtMs: 1700000000000 },
            },
          },
        }),
      );
    };

    // Interactive environment: the warning + ceremony are not skipped. The
    // success overwrites the book with the new fingerprint (reflecting a legitimate key update via `maruhi key generate`)
    const state = await makeAddServer({ built, invitation, ownDeks });
    const env = await startAddEnv(state, built.projectId);
    await seedStaleBook(env);
    env.setPromptResponses([words.value[words.value.length - 1] ?? ""]);
    expect(await runCli(["member", "add"], env.layer)).toBe(0);
    expect(env.prompts).toHaveLength(1);
    expect(env.errors.join("\n")).toContain("is not among the one verified");
    const recorded = await readBook(env);
    // Added to the set (DK — old records are not erased; they remain as the same person's other devices)
    expect(
      Object.keys(recorded[env.serverOrigin]?.[acceptor.userId]?.fingerprints ?? {}),
    ).toContain(acceptor.fingerprintHex);

    // Agent environment + mismatch + no flag = refused as before (never auto-passes)
    const state2 = await makeAddServer({ built, invitation, ownDeks });
    const env2 = await startAddEnv(state2, built.projectId);
    await seedStaleBook(env2);
    env2.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["member", "add"], env2.layer)).toBe(1);
    expect(env2.errors.join("\n")).toContain(
      "Refused to run the acceptance-key confirmation ceremony",
    );
    expect(state2.appendedEntries).toHaveLength(0);
  });

  it("fingerprint book: an --expect-fingerprint match success is also recorded (the stale-record warning never appears on the flag path) (KF)", async () => {
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor)),
      ownDeks: [
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: inviter,
          signer: inviter,
        }),
      ],
    });
    const env = await startAddEnv(state, built.projectId);
    // Stale record (the shape of re-running with the flag right after a
    // legitimate key update): the flag matches the actual fingerprint, so "the out-of-band check is required again" is not shown; the record is overwritten
    await writeFile(
      env.fingerprintBookPath,
      JSON.stringify({
        v: 1,
        known: {
          [env.serverOrigin]: {
            [acceptor.userId]: { fingerprintHex: "00".repeat(16), verifiedAtMs: 1700000000000 },
          },
        },
      }),
    );

    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(0);
    expect(env.errors.join("\n")).not.toContain("is not among the one verified");
    const recorded = await readBook(env);
    // Added to the set (DK — old records are not erased; they remain as the same person's other devices)
    expect(
      Object.keys(recorded[env.serverOrigin]?.[acceptor.userId]?.fingerprints ?? {}),
    ).toContain(acceptor.fingerprintHex);
  });
});
