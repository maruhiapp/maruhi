import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import type { WrappedDek } from "@maruhi/api-schema";
import type { ChainEntry } from "@maruhi/crypto";
import { decodeHex, fingerprintToWords } from "@maruhi/crypto";
import {
  addMemberOp,
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  distributedEnvironmentStatement,
  distributedWrap,
  type GeneratedIdentity,
  generateIdentity,
  genesisOp,
  grantServerOp,
  headOf,
  removeMemberOp,
  revokeServerOp,
  rotateEpochOp,
  testEnvironmentId,
  type WireDistributedEnvironmentStatement,
  type WireRecipientDek,
} from "@maruhi/test-kit";
import type { ApiSuccess } from "@maruhi/test-kit/api";
import { afterEach, beforeAll, describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import {
  acceptAppendedEntry,
  injectedAppendResponse,
  servedChain,
} from "./support/chain-handler.ts";
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
import { type MockHandler, type MockResponse, MockServer, onEndpoint } from "./support/server.ts";

const ENV_ID = "env-app-1";

let inviter: GeneratedIdentity;
let acceptor: GeneratedIdentity;
let dek1: Uint8Array;
let dek2: Uint8Array;

const servers: MockServer[] = [];

beforeAll(async () => {
  inviter = await generateIdentity("user-inviter-11");
  acceptor = await generateIdentity("user-acceptor-22");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

type Acceptance = AcceptanceFixture;
type InvitationRow = ApiSuccess<"invites.list">["invitations"][number];

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

async function acceptanceFor(projectId: string, invitee: GeneratedIdentity): Promise<Acceptance> {
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

async function makeAddServer(input: {
  readonly built: BuiltChain;
  readonly invitation: InvitationRow;
  readonly ownDeks: readonly WireRecipientDek[];
  readonly currentEpoch?: number;
  readonly occupiedSlots?: readonly string[];
  readonly occupiedSlotEncPub?: Readonly<Record<string, string>>;
  readonly listedStatements?: readonly WireDistributedEnvironmentStatement[];
  readonly onAppend?: (call: number) => MockResponse | undefined;
  readonly chainAfterConflict?: BuiltChain;
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
    await distributedEnvironmentStatement({
      projectId,
      environmentId: ENV_ID,
      name: ENV_ID,
      author: inviter,
      head: headOf(input.built, 1),
    }),
  ];

  const handlers: MockHandler[] = [
    onEndpoint("membership.get", { projectId }, () => ({
      status: 200,
      json: servedChain(projectId, entries, hashes),
    })),
    async (request) => {
      if (request.method !== "POST" || request.path !== `/projects/${projectId}/chain/entries`) {
        return null;
      }
      const injected = injectedAppendResponse(input, counters.appendAttempts, entries, hashes);
      counters.appendAttempts += 1;
      if (injected !== undefined) {
        return injected;
      }
      const body = request.body as { readonly entry: ChainEntry };
      appendedEntries.push(body.entry);
      return acceptAppendedEntry(projectId, entries, hashes, body.entry);
    },
    onEndpoint("invites.list", { projectId }, () => ({
      status: 200,
      json: { invitations: [input.invitation] },
    })),
    onEndpoint("environments.list", { projectId }, () => ({
      status: 200,
      json: {
        environments: listedStatements.map((statement) => ({
          environmentId: statement.environmentId,
          currentEpoch: input.currentEpoch ?? 1,
          statement,
        })),
        schemaPolicy: "enabled",
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
            storedRecipientEncPubHex: storedEncPub ?? conflict.recipientEncPubHex,
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
  overrides?: Partial<InvitationRow>,
): InvitationRow {
  const issued = issuedByProject.get(projectId);
  if (issued === undefined) {
    throw new Error("invitationRow: issue the invitation first");
  }
  return {
    id: INVITE_ID,
    projectId,
    role: "member",
    scopeKind: "all",
    scopeEnvironmentIds: [],
    status: acceptance === null ? "pending" : "accepted",
    inviterUserId: inviter.userId,
    issuance: issued.issuance,
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
        await distributedWrap({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: inviter,
          signer: inviter,
        }),
        await distributedWrap({
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

    expect(state.appendedEntries).toHaveLength(1);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "add_member") throw new Error("add_member entry missing");
    expect(entry.payload).toEqual({
      targetUserId: acceptor.userId,
      encPubHex: acceptor.encPubHex,
      sigPubHex: acceptor.sigPubHex,
      role: "member",
      scopeKind: "all",
      scopeEnvironmentIds: [],
    });

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
    const devAdmin = await generateIdentity("user-devadmin-4444");
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: inviter, operation: createEnvironmentOp("env-prod", dek2) },
      { actor: inviter, operation: addMemberOp(devAdmin, "admin", [ENV_ID]) },
    ]);
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
    expect(env.errors.join("\n")).not.toContain("AI agent environment");
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("a listed-scope invite is signed with the invite row's scope and backfill is limited to the target scope's environments (ES K4 — §7)", async () => {
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: inviter, operation: createEnvironmentOp("env-prod", dek2) },
    ]);
    issuedByProject.set(
      built.projectId,
      await issueInviteFixture({
        inviter,
        projectId: built.projectId,
        headHashHex: "cd".repeat(32),
        headSeq: 1,
        scope: { scopeKind: "listed", scopeEnvironmentIds: [testEnvironmentId(ENV_ID)] },
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
        await distributedWrap({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: inviter,
          signer: inviter,
        }),
      ],
      listedStatements: [
        await distributedEnvironmentStatement({
          projectId: built.projectId,
          environmentId: ENV_ID,
          name: ENV_ID,
          author: inviter,
          head: headOf(built, 1),
        }),
        await distributedEnvironmentStatement({
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
    expect(state.registerBodies.map((body) => body.environmentId)).toEqual([ENV_ID]);
    expect(env.logs.join("\n")).toContain("in the member's scope × every epoch");
    issuedByProject.delete(built.projectId);
  });

  it("re-syncs on ChainHeadConflict (409), re-signs add_member, and retries (§12-4)", async () => {
    const passerby = await generateIdentity("user-passerby-5555");
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    const concurrent = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: inviter, operation: addMemberOp(passerby, "reader") },
    ]);
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor)),
      ownDeks: [
        await distributedWrap({
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

    expect(state.counters.appendAttempts).toBe(2);
    expect(state.appendedEntries).toHaveLength(1);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "add_member") throw new Error("add_member entry missing");
    expect(entry.seq).toBe(concurrent.entries.length + 1);
    expect(entry.payload.targetUserId).toBe(acceptor.userId);
    expect(
      state.registerBodies.flatMap((body) => body.deks.map((wrap) => wrap.recipientUserId)),
    ).toEqual([acceptor.userId]);
  });

  it("when re-registration fails after a repair-path deletion, fails while making explicit that the slot is empty", async () => {
    const oldKeys = await generateIdentity(acceptor.userId);
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
        await distributedWrap({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: inviter,
          signer: inviter,
        }),
        await distributedWrap({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 2,
          dek: dek2,
          recipient: inviter,
          signer: inviter,
        }),
      ],
      occupiedSlots: [`${ENV_ID}:1:${acceptor.userId}`],
      occupiedSlotEncPub: { [`${ENV_ID}:1:${acceptor.userId}`]: oldKeys.encPubHex },
      onRegister: (call) => (call === 2 ? { status: 500, json: {} } : undefined),
    });
    const env = await startAddEnv(state, built.projectId);

    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(1);
    expect(state.removeBodies).toEqual([
      {
        environmentId: ENV_ID,
        wraps: [
          {
            epoch: 1,
            recipientClass: "member",
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
      await distributedWrap({
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
        await distributedWrap({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: inviter,
          signer: inviter,
        }),
      ],
      occupiedSlots: [`${ENV_ID}:1:${acceptor.userId}`],
    });
    const env = await startAddEnv(state, built.projectId);

    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.registerBodies).toHaveLength(0);
    expect(state.removeBodies).toHaveLength(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain("already a member with the same key");
    expect(logs).toContain("1 already registered");
  });

  it("re-adding (past membership under another key): deletes the 409 slot then re-registers to repair to the new key", async () => {
    const oldKeys = await generateIdentity(acceptor.userId);
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
        await distributedWrap({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: inviter,
          signer: inviter,
        }),
        await distributedWrap({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 2,
          dek: dek2,
          recipient: inviter,
          signer: inviter,
        }),
      ],
      occupiedSlots: [`${ENV_ID}:1:${acceptor.userId}`],
      occupiedSlotEncPub: { [`${ENV_ID}:1:${acceptor.userId}`]: oldKeys.encPubHex },
    });
    const env = await startAddEnv(state, built.projectId);

    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(0);

    expect(state.removeBodies).toEqual([
      {
        environmentId: ENV_ID,
        wraps: [
          {
            epoch: 1,
            recipientClass: "member",
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
    expect(registered).toContainEqual([2, acceptor.encPubHex]);
    const logs = env.logs.join("\n");
    expect(logs).toContain("If leftover wraps addressed to the old key are found, the repair path");
    expect(logs).toContain("1 old-key wrap repaired");
  });

  it("does not delete when the 409's stored enc public key matches the acceptance key — even with a different-key membership history (blocks mis-deletion)", async () => {
    const oldKeys = await generateIdentity(acceptor.userId);
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: inviter, operation: addMemberOp(oldKeys, "member") },
      { actor: inviter, operation: removeMemberOp(oldKeys) },
      { actor: inviter, operation: rotateEpochOp(ENV_ID, 2, dek2) },
      { actor: inviter, operation: addMemberOp(acceptor, "member") },
    ]);
    const slot = `${ENV_ID}:1:${acceptor.userId}`;
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor)),
      currentEpoch: 2,
      ownDeks: [
        await distributedWrap({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: inviter,
          signer: inviter,
        }),
        await distributedWrap({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 2,
          dek: dek2,
          recipient: inviter,
          signer: inviter,
        }),
      ],
      occupiedSlots: [slot],
      occupiedSlotEncPub: { [slot]: acceptor.encPubHex },
    });
    const env = await startAddEnv(state, built.projectId);

    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(0);
    expect(state.removeBodies).toHaveLength(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain("1 already registered");
    expect(logs).not.toContain("old-key wraps repaired");
  });

  it("repairs when the 409's stored enc public key mismatches the acceptance key, regardless of key history", async () => {
    const strangerKeys = await generateIdentity("user-someone-else");
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    const slot = `${ENV_ID}:1:${acceptor.userId}`;
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor)),
      ownDeks: [
        await distributedWrap({
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
    expect(state.removeBodies).toEqual([
      {
        environmentId: ENV_ID,
        wraps: [
          {
            epoch: 1,
            recipientClass: "member",
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
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: inviter, operation: addMemberOp(acceptor, "member") },
    ]);
    const acceptance = await acceptanceFor(built.projectId, acceptor);
    const completedRow = invitationRow(built.projectId, acceptance, { status: "completed" });
    const ownDeks = [
      await distributedWrap({
        projectId: built.projectId,
        environmentId: ENV_ID,
        epoch: 1,
        dek: dek1,
        recipient: inviter,
        signer: inviter,
      }),
    ];

    const state1 = await makeAddServer({ built, invitation: completedRow, ownDeks });
    const env1 = await startAddEnv(state1, built.projectId);
    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env1.layer),
    ).toBe(1);
    expect(env1.errors.join("\n")).toContain("pass it explicitly: `maruhi member add <invite-id>`");
    expect(state1.appendedEntries).toHaveLength(0);

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
      [
        invitationRow(built.projectId, acceptance, { role: "admin" }),
        "issue signature that does not verify",
      ],
      [
        invitationRow(built.projectId, { ...acceptance, inviteeEncPubHex: "aa".repeat(32) }),
        "the link signature failed verification",
      ],
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
            scopeKind: "all",
            scopeEnvironmentIds: [],
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

  it("rejects as duplicate-member-key before appending when the acceptance enc key is a server key a grant has named, revoked since (CRYPTO_SPEC §6.2 key uniqueness)", async () => {
    const grant = await grantServerOp([ENV_ID], [], acceptor.encPubHex);
    if (grant.op !== "grant_server") {
      throw new Error("grantServerOp built another operation");
    }
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: inviter, operation: grant },
      { actor: inviter, operation: revokeServerOp(grant.payload.serverKeyFingerprintHex) },
    ]);
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor)),
      ownDeks: [],
    });
    const env = await startAddEnv(state, built.projectId);
    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain(
      `The acceptance key is server key ${grant.payload.serverKeyFingerprintHex}, which a grant has named, so no device may hold it (consensus rule duplicate-member-key — CRYPTO_SPEC §6.2). add_member cannot proceed with this acceptance`,
    );
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
    async function backedState(
      built: BuiltChain,
      registeredKeys: readonly string[],
      status = 200,
    ): Promise<AddServerState> {
      const state = await makeAddServer({
        built,
        invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor)),
        ownDeks: [
          await distributedWrap({
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
              scopeKind: "all",
              scopeEnvironmentIds: [],
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

      const state = await backedState(built, [sshLineOf(inviter)]);
      const env = await backedEnv(state, built.projectId);
      env.setPromptResponses([""]);
      expect(await runCli(["member", "add", "--github", "bob"], env.layer)).toBe(1);
      expect(env.prompts[0]).toContain("Type yes to confirm the 12 words now");
      expect(env.errors.join("\n")).toContain(
        "Ask github.com/bob to register their key with `maruhi key publish`",
      );
      expect(state.appendedEntries).toHaveLength(0);

      const state2 = await backedState(built, [sshLineOf(inviter)]);
      const env2 = await backedEnv(state2, built.projectId);
      env2.setPromptResponses(["yes", words.value[words.value.length - 1] ?? ""]);
      expect(await runCli(["member", "add", "--github", "bob"], env2.layer)).toBe(0);
      expect(env2.prompts).toHaveLength(2);
      expect(env2.prompts[1]).toContain("type the last of the 12 words");
      expect(state2.appendedEntries).toHaveLength(1);

      const state3 = await backedState(built, [], 403);
      const env3 = await backedEnv(state3, built.projectId);
      env3.setPromptResponses([words.value[words.value.length - 1] ?? ""]);
      expect(await runCli(["member", "add", "--github", "bob"], env3.layer)).toBe(0);
      expect(env3.prompts).toHaveLength(1);
      expect(env3.errors.join("\n")).toContain("could not be fetched");
      expect(state3.appendedEntries).toHaveLength(1);

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
        await distributedWrap({
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

    env.setPromptResponses([words.value[words.value.length - 1] ?? ""]);
    expect(await runCli(["member", "add"], env.layer)).toBe(0);
    expect(env.prompts).toHaveLength(1);
    const recorded = await readBook(env);
    expect(
      Object.keys(recorded[env.serverOrigin]?.[acceptor.userId]?.fingerprints ?? {}),
    ).toContain(acceptor.fingerprintHex);
    expect(env.errors.join("\n")).toContain("recorded the verified fingerprint");

    const logsBeforeSecondRun = env.logs.length;
    env.setPromptResponses(["yes"]);
    expect(await runCli(["member", "add"], env.layer)).toBe(0);
    expect(env.prompts).toHaveLength(2);
    expect(env.prompts[1]).toContain("Type yes to add");
    const secondRunLogs = env.logs.slice(logsBeforeSecondRun).join("\n");
    expect(secondRunLogs).toContain("not required again");
    expect(secondRunLogs).not.toContain("reads to you out of band");

    env.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["member", "add"], env.layer)).toBe(1);
    expect(env.prompts).toHaveLength(2);
    expect(env.errors.join("\n")).toContain(
      "Refused to run the acceptance-key confirmation ceremony",
    );

    env.setAgent({ isAgent: false });
    env.setTerminal({ stdin: false });
    env.setPromptResponses([words.value[words.value.length - 1] ?? ""]);
    expect(await runCli(["member", "add"], env.layer)).toBe(0);
    expect(env.prompts).toHaveLength(3);
    expect(env.prompts[2]).toContain("type the last of the 12 words");
    expect(env.errors.join("\n")).toContain("stdin is not an interactive terminal");

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
      await distributedWrap({
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
          v: 2,
          known: {
            [env.serverOrigin]: {
              [acceptor.userId]: {
                fingerprints: { ["00".repeat(16)]: { verifiedAtMs: 1700000000000 } },
              },
            },
          },
        }),
      );
    };

    const state = await makeAddServer({ built, invitation, ownDeks });
    const env = await startAddEnv(state, built.projectId);
    await seedStaleBook(env);
    env.setPromptResponses([words.value[words.value.length - 1] ?? ""]);
    expect(await runCli(["member", "add"], env.layer)).toBe(0);
    expect(env.prompts).toHaveLength(1);
    expect(env.errors.join("\n")).toContain("is not among the one verified");
    const recorded = await readBook(env);
    expect(
      Object.keys(recorded[env.serverOrigin]?.[acceptor.userId]?.fingerprints ?? {}),
    ).toContain(acceptor.fingerprintHex);

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
        await distributedWrap({
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
    await writeFile(
      env.fingerprintBookPath,
      JSON.stringify({
        v: 2,
        known: {
          [env.serverOrigin]: {
            [acceptor.userId]: {
              fingerprints: { ["00".repeat(16)]: { verifiedAtMs: 1700000000000 } },
            },
          },
        },
      }),
    );

    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(0);
    expect(env.errors.join("\n")).not.toContain("is not among the one verified");
    const recorded = await readBook(env);
    expect(
      Object.keys(recorded[env.serverOrigin]?.[acceptor.userId]?.fingerprints ?? {}),
    ).toContain(acceptor.fingerprintHex);
  });
});
