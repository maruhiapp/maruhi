import type { WrappedDek } from "@maruhi/api-schema";
import type { ChainEntry } from "@maruhi/crypto";
import {
  computeChainEntryHash,
  importEncryptionKeyPair,
  importSigningPublicKey,
  unwrapDek,
  verifyDekCommitment,
  verifyDekWrapSignature,
} from "@maruhi/crypto";
import { Effect } from "effect";
import { afterEach, describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { makeFileFloorStore } from "../src/floor-log.ts";
import {
  addMemberOp,
  addScopedMemberOp,
  buildChain,
  createEnvironmentOp,
  genesisOp,
  grantServerOp,
  hexBytes,
  makeTestUser,
  removeMemberOp,
  statementHashOf,
  testEnvironmentId,
  testProjectId,
  testUserId,
  type TestUser,
  variablesDigestOf,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, type MockResponse, MockServer, onRequest } from "./support/server.ts";

interface CompositeCreateBody {
  readonly parentHeadHashHex: string;
  readonly entry: ChainEntry & { readonly op: "create_environment" };
  readonly statement: {
    readonly environmentId: string;
    readonly name: string;
    readonly status: string;
    readonly metaVersion: number;
    readonly prevMetaSigHashHex: string;
    readonly chainHeadHashHex: string;
    readonly chainHeadSeq: number;
    readonly signatureHex: string;
  };
  readonly deks: WrappedDek[];
  readonly manifest: {
    readonly suite: string;
    readonly environmentId: string;
    readonly epoch: number;
    readonly manifestVersion: number;
    readonly variablesDigestHex: string;
    readonly envMetaVersion: number;
    readonly envMetaSigHashHex: string;
    readonly prevManifestSigHashHex: string;
    readonly chainHeadHashHex: string;
    readonly chainHeadSeq: number;
    readonly signatureHex: string;
  };
}

let servers: MockServer[] = [];

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

async function startEnv(
  projectId: string,
  handlers: readonly MockHandler[],
  user: TestUser,
): Promise<TestEnv> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, user);
  await seedConfig(env, { server: server.origin, defaultProject: projectId });
  return env;
}

function chainHandler(
  projectId: string,
  built: Awaited<ReturnType<typeof buildChain>>,
): MockHandler {
  return onRequest("GET", `/projects/${projectId}/chain`, () => ({
    status: 200,
    json: {
      projectId,
      entries: built.entries,
      headSeq: built.entries.length,
      headHashHex: built.hashes[built.hashes.length - 1],
      attestations: [],
    },
  }));
}

function acceptingCreateServer(input: {
  readonly projectId: string;
  readonly base: Awaited<ReturnType<typeof buildChain>>;
  readonly concurrent?: Awaited<ReturnType<typeof buildChain>>;
  readonly onCreate?: (call: number, body: CompositeCreateBody) => MockResponse | undefined;
  readonly acceptedResponse?: (call: number, body: CompositeCreateBody) => MockResponse;
}): { readonly handlers: readonly MockHandler[]; readonly bodies: CompositeCreateBody[] } {
  const entries: ChainEntry[] = [...input.base.entries];
  const hashes: string[] = [...input.base.hashes];
  const bodies: CompositeCreateBody[] = [];
  let createCalls = 0;
  const handlers: MockHandler[] = [
    onRequest("GET", `/projects/${input.projectId}/chain`, () => ({
      status: 200,
      json: {
        projectId: input.projectId,
        entries,
        headSeq: entries.length,
        headHashHex: hashes[hashes.length - 1],
        attestations: [],
      },
    })),
    async (request) => {
      if (
        request.method !== "POST" ||
        request.path !== `/projects/${input.projectId}/environments`
      ) {
        return null;
      }
      const body = request.body as CompositeCreateBody;
      bodies.push(body);
      const injected = input.onCreate?.(createCalls, body);
      const call = createCalls;
      createCalls += 1;
      if (injected !== undefined) {
        return injected;
      }
      if (call === 0 && input.concurrent !== undefined) {
        entries.splice(0, entries.length, ...input.concurrent.entries);
        hashes.splice(0, hashes.length, ...input.concurrent.hashes);
        return {
          status: 409,
          json: {
            _tag: "ChainHeadConflict",
            currentHeadSeq: entries.length,
            currentHeadHashHex: hashes[hashes.length - 1],
          },
        };
      }
      entries.push(body.entry);
      hashes.push(await computeChainEntryHash(body.entry));
      return (
        input.acceptedResponse?.(call, body) ?? {
          status: 200,
          json: {
            environmentId: body.entry.payload.environmentId,
            currentEpoch: 1,
            headSeq: entries.length,
            headHashHex: hashes[hashes.length - 1],
          },
        }
      );
    },
  ];
  return { handlers, bodies };
}

async function verifyAndUnwrapWrap(input: {
  readonly wrap: WrappedDek;
  readonly projectId: string;
  readonly signer: TestUser;
  readonly recipient: TestUser;
}): Promise<Uint8Array> {
  const { wrap, projectId, signer, recipient } = input;
  expect(wrap.epoch).toBe(1);
  expect(wrap.recipientEncPubHex).toBe(recipient.encPubHex);
  const signerKey = await importSigningPublicKey(hexBytes(signer.sigPubHex));
  if (!signerKey.ok) {
    throw new Error("sig key import failed");
  }
  const verified = await verifyDekWrapSignature({
    context: {
      suite: wrap.suite,
      projectId: testProjectId(projectId),
      environmentId: testEnvironmentId("staging"),
      epoch: wrap.epoch,
      recipientUserId: testUserId(wrap.recipientUserId),
      recipientEncPubHex: wrap.recipientEncPubHex,
      encHex: wrap.encHex,
      ciphertextHex: wrap.ciphertextHex,
      signerUserId: signer.userId,
    },
    signatureHex: wrap.signatureHex,
    signerPublicKey: signerKey.value,
  });
  expect(verified.ok).toBe(true);
  const pair = await importEncryptionKeyPair({
    publicKey: hexBytes(recipient.encPubHex),
    privateKey: hexBytes(recipient.encSkHex),
  });
  if (!pair.ok) {
    throw new Error("enc key import failed");
  }
  const dek = await unwrapDek({
    recipientKeyPair: pair.value,
    wrapped: { enc: hexBytes(wrap.encHex), ciphertext: hexBytes(wrap.ciphertextHex) },
    context: {
      projectId: testProjectId(projectId),
      environmentId: testEnvironmentId("staging"),
      epoch: 1,
      recipientUserId: testUserId(wrap.recipientUserId),
    },
  });
  if (!dek.ok) {
    throw new Error("unwrap failed");
  }
  return dek.value;
}

describe("maruhi env create", () => {
  it("composite request: bundles the signed create_environment entry (with commitment) + the complete wrap set", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const member = await makeTestUser("user-member-2222");
    const removed = await makeTestUser("user-removed-3333");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(member, "reader") },
      { actor: owner, operation: addMemberOp(removed, "member") },
      { actor: owner, operation: removeMemberOp(removed) },
    ]);
    const head = built.hashes[built.hashes.length - 1] ?? "";
    const server = acceptingCreateServer({ projectId: built.projectId, base: built });
    const env = await startEnv(built.projectId, server.handlers, owner);

    expect(await runCli(["env", "create", "staging", "--name", "Staging"], env.layer)).toBe(0);
    const body = server.bodies[0];
    if (body === undefined) throw new Error("composite create was not called");
    expect(body.statement.name).toBe("Staging");
    expect(body.statement.environmentId).toBe("staging");
    expect(body.statement.status).toBe("active");
    expect(body.statement.metaVersion).toBe(1);
    expect(body.statement.prevMetaSigHashHex).toBe("");
    expect(body.statement.chainHeadHashHex).toBe(head);
    expect(body.statement.chainHeadSeq).toBe(built.entries.length);
    expect(body.statement.signatureHex).toMatch(/^[0-9a-f]{128}$/);
    expect(body.parentHeadHashHex).toBe(head);
    expect(body.entry.op).toBe("create_environment");
    expect(body.entry.seq).toBe(built.entries.length + 1);
    expect(body.entry.prevHashHex).toBe(head);
    expect(body.entry.actor.userId).toBe(owner.userId);
    expect(body.entry.payload.environmentId).toBe("staging");
    expect(body.deks.map((wrap) => wrap.recipientUserId).toSorted()).toEqual(
      [owner.userId, member.userId].toSorted(),
    );
    const deks: Uint8Array[] = [];
    for (const wrap of body.deks) {
      deks.push(
        await verifyAndUnwrapWrap({
          wrap,
          projectId: built.projectId,
          signer: owner,
          recipient: wrap.recipientUserId === owner.userId ? owner : member,
        }),
      );
    }
    expect(deks).toHaveLength(2);
    expect(Buffer.from(deks[0] ?? []).toString("hex")).toBe(
      Buffer.from(deks[1] ?? []).toString("hex"),
    );
    const dek = deks[0];
    if (dek === undefined) throw new Error("missing dek");
    const matched = await verifyDekCommitment({
      context: {
        suite: "maruhi/v1",
        projectId: testProjectId(built.projectId),
        environmentId: testEnvironmentId("staging"),
        epoch: 1,
      },
      dek,
      expectedCommitmentHex: body.entry.payload.dekCommitmentHex,
    });
    expect(matched.ok).toBe(true);
    expect(body.manifest.manifestVersion).toBe(1);
    expect(body.manifest.prevManifestSigHashHex).toBe("");
    expect(body.manifest.environmentId).toBe("staging");
    expect(body.manifest.epoch).toBe(1);
    expect(body.manifest.chainHeadHashHex).toBe(head);
    expect(body.manifest.chainHeadSeq).toBe(built.entries.length);
    expect(body.manifest.variablesDigestHex).toBe(await variablesDigestOf(built.projectId, []));
    expect(body.manifest.envMetaVersion).toBe(1);
    expect(body.manifest.envMetaSigHashHex).toBe(
      await statementHashOf(built.projectId, {
        suite: "maruhi/v1",
        environmentId: "staging",
        name: "Staging",
        status: "active",
        metaVersion: 1,
        prevMetaSigHashHex: "",
        chainHeadHashHex: head,
        chainHeadSeq: built.entries.length,
        signatureHex: body.statement.signatureHex,
        authorUserId: owner.userId,
        authorKeyFingerprintHex: owner.fingerprintHex,
      }),
    );
    expect(body.manifest.signatureHex).toMatch(/^[0-9a-f]{128}$/);
  });

  it("ChainHeadConflict (409) resyncs, re-signs the entry, and retries (§12-4)", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const other = await makeTestUser("user-other-4444");
    const chainA = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const chainB = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(other, "reader") },
    ]);
    expect(chainB.projectId).toBe(chainA.projectId);
    const headB = chainB.hashes[chainB.hashes.length - 1] ?? "";
    const server = acceptingCreateServer({
      projectId: chainA.projectId,
      base: chainA,
      concurrent: chainB,
    });
    const env = await startEnv(chainA.projectId, server.handlers, owner);

    expect(await runCli(["env", "create", "staging"], env.layer)).toBe(0);
    expect(server.bodies).toHaveLength(2);
    const [first, second] = server.bodies;
    if (first === undefined || second === undefined) throw new Error("missing bodies");
    expect(first.entry.seq).toBe(2);
    expect(second.entry.seq).toBe(3);
    expect(second.parentHeadHashHex).toBe(headB);
    expect(second.entry.prevHashHex).toBe(headB);
    expect(second.entry.signatureHex).not.toBe(first.entry.signatureHex);
    expect(second.statement.chainHeadHashHex).toBe(headB);
    expect(second.statement.chainHeadSeq).toBe(chainB.entries.length);
    expect(second.statement.signatureHex).not.toBe(first.statement.signatureHex);
    expect(second.entry.payload.dekCommitmentHex).toBe(first.entry.payload.dekCommitmentHex);
    expect(first.deks.map((wrap) => wrap.recipientUserId)).toEqual([owner.userId]);
    expect(second.deks.map((wrap) => wrap.recipientUserId).toSorted()).toEqual(
      [owner.userId, other.userId].toSorted(),
    );
    expect(env.logs.join("\n")).toContain("DEK wrapped for 2 current members");
  });

  it("the ChainHeadConflict resync carries an extension check (no re-signing onto a shortened or forked chain)", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const other = await makeTestUser("user-other-4444");
    const long = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(other, "reader") },
    ]);
    const short = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    let chainCalls = 0;
    const bodies: CompositeCreateBody[] = [];
    const env = await startEnv(
      long.projectId,
      [
        onRequest("GET", `/projects/${long.projectId}/chain`, () => {
          chainCalls += 1;
          const built = chainCalls === 1 ? long : short;
          return {
            status: 200,
            json: {
              projectId: long.projectId,
              entries: built.entries,
              headSeq: built.entries.length,
              headHashHex: built.hashes[built.hashes.length - 1],
              attestations: [],
            },
          };
        }),
        onRequest("POST", `/projects/${long.projectId}/environments`, (request) => {
          bodies.push(request.body as CompositeCreateBody);
          return {
            status: 409,
            json: {
              _tag: "ChainHeadConflict",
              currentHeadSeq: short.entries.length,
              currentHeadHashHex: short.hashes[short.hashes.length - 1],
            },
          };
        }),
      ],
      owner,
    );

    expect(await runCli(["env", "create", "staging"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("not an extension of the verified view");
    expect(bodies).toHaveLength(1);
  });

  it("reuses the wrap set on a ChainHeadConflict retry when the member set is unchanged (§12-4)", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const chainA = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const passerby = await makeTestUser("user-passerby-5555");
    const chainB = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(passerby, "reader") },
      { actor: owner, operation: removeMemberOp(passerby) },
    ]);
    expect(chainB.projectId).toBe(chainA.projectId);
    const headB = chainB.hashes[chainB.hashes.length - 1] ?? "";
    const server = acceptingCreateServer({
      projectId: chainA.projectId,
      base: chainA,
      concurrent: chainB,
    });
    const env = await startEnv(chainA.projectId, server.handlers, owner);

    expect(await runCli(["env", "create", "staging"], env.layer)).toBe(0);
    expect(server.bodies).toHaveLength(2);
    const [first, second] = server.bodies;
    if (first === undefined || second === undefined) throw new Error("missing bodies");
    expect(second.entry.prevHashHex).toBe(headB);
    expect(second.deks).toEqual(first.deks);
  });

  it("after a ChainHeadConflict, the checks run again on the resynced view: a concurrent creation of the same ID stops the retry", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const chainA = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const chainB = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp("staging", new Uint8Array(32).fill(2)) },
    ]);
    const server = acceptingCreateServer({
      projectId: chainA.projectId,
      base: chainA,
      concurrent: chainB,
    });
    const env = await startEnv(chainA.projectId, server.handlers, owner);

    expect(await runCli(["env", "create", "staging"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Environment ID staging is already used on the chain");
    expect(server.bodies).toHaveLength(1);
  });

  it("an AuditHeadNotReady (503) is retried like a conflict; after five attempts the wording names both causes", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const base = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const server = acceptingCreateServer({
      projectId: base.projectId,
      base,
      onCreate: () => ({ status: 503, json: { _tag: "AuditHeadNotReady" } }),
    });
    const env = await startEnv(base.projectId, server.handlers, owner);

    expect(await runCli(["env", "create", "staging"], env.layer)).toBe(1);
    expect(server.bodies).toHaveLength(5);
    expect(env.errors.join("\n")).toContain(
      "The environment creation kept being rejected with retryable conflicts (a chain-head conflict, or audit-head materialization in progress) after 5 attempts. Wait a moment and re-run — server-side progress is preserved",
    );
  });

  it("a missing environment-ID positional is refused before the network (never calls the create API with a bogus id)", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const server = await MockServer.start([chainHandler(built.projectId, built)]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
    const code = await runCli(["env", "create"], env.layer);
    expect(code === 1 || code === 2).toBe(true);
    expect(server.requests).toHaveLength(0);
  });

  it("a reader cannot create environments (member or above — §6.2). Refused before any wraps are built", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const reader = await makeTestUser("user-reader-5555");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(reader, "reader") },
    ]);
    const server = await MockServer.start([chainHandler(built.projectId, built)]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, reader);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["env", "create", "staging"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("A reader cannot create environments");
    expect(server.requests.filter((request) => request.method === "POST")).toHaveLength(0);
  });

  it("a listed-scope member cannot create environments (scope = all only — §6.2 / ruling E). Refused before any wraps are built", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const dev = await makeTestUser("user-dev-6666");
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp("dev", dek) },
      { actor: owner, operation: addScopedMemberOp(dev, "admin", ["dev"]) },
    ]);
    const server = await MockServer.start([chainHandler(built.projectId, built)]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, dev);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["env", "create", "staging"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Only members whose environment scope is `all` can create environments",
    );
    expect(server.requests.filter((request) => request.method === "POST")).toHaveLength(0);
  });

  it("when the environment being created is inside a grant_server's disclosure scope, the complete set includes the server-destined wrap and it succeeds (§12-4)", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: await grantServerOp(["staging"]) },
    ]);
    const grantEntry = built.entries[1];
    if (grantEntry?.op !== "grant_server") throw new Error("grant entry missing");
    const server = acceptingCreateServer({ projectId: built.projectId, base: built });
    const env = await startEnv(built.projectId, server.handlers, owner);
    expect(await runCli(["env", "create", "staging"], env.layer)).toBe(0);
    const body = server.bodies[0] as unknown as {
      deks: readonly {
        recipientClass?: string;
        recipientUserId: string;
        recipientEncPubHex: string;
      }[];
    };
    expect(body.deks).toHaveLength(2);
    const serverWrap = body.deks.find((wrap) => wrap.recipientClass === "server");
    expect(serverWrap?.recipientUserId).toBe(grantEntry.payload.serverKeyFingerprintHex);
    expect(serverWrap?.recipientEncPubHex).toBe(grantEntry.payload.serverEncPubHex);
  });

  it("a grant_server with an empty scope targets no environment (creation can proceed without a server-destined wrap)", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: await grantServerOp([]) },
    ]);
    const server = acceptingCreateServer({ projectId: built.projectId, base: built });
    const env = await startEnv(built.projectId, server.handlers, owner);
    expect(await runCli(["env", "create", "staging"], env.layer)).toBe(0);
    const body = server.bodies[0] as unknown as { deks: readonly { recipientClass?: string }[] };
    expect(body.deks).toHaveLength(1);
    expect(body.deks.every((wrap) => wrap.recipientClass === "member")).toBe(true);
  });

  it("a grant_server disclosing only another environment does not stop creating this one (a §6.2 scope is a subset)", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: await grantServerOp(["dev"]) },
    ]);
    const server = acceptingCreateServer({ projectId: built.projectId, base: built });
    const env = await startEnv(built.projectId, server.handlers, owner);

    expect(await runCli(["env", "create", "staging"], env.layer)).toBe(0);
    expect(server.bodies).toHaveLength(1);
  });

  it("the completion report's epoch is the structural 1, not the server's claim (§12-4)", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const server = acceptingCreateServer({
      projectId: built.projectId,
      base: built,
      acceptedResponse: () => ({
        status: 200,
        json: {
          environmentId: "staging",
          currentEpoch: 7,
          headSeq: built.entries.length + 1,
          headHashHex: "cd".repeat(32),
        },
      }),
    });
    const env = await startEnv(built.projectId, server.handlers, owner);

    expect(await runCli(["env", "create", "staging"], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain("epoch=1");
    expect(logs).not.toContain("epoch=7");
  });

  it("establishes the v1 floor (empty variable set + self-issued manifest) after the acceptance check and closes the intent", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const server = acceptingCreateServer({ projectId: built.projectId, base: built });
    const env = await startEnv(built.projectId, server.handlers, owner);

    expect(await runCli(["env", "create", "staging"], env.layer)).toBe(0);
    const loaded = await Effect.runPromise(
      makeFileFloorStore(env.floorDir).load(testProjectId(built.projectId)),
    );
    const record = loaded.floor?.environments["staging"];
    expect(record?.manifest).toMatchObject({ manifestVersion: 1, epoch: 1 });
    expect(record?.metaVersion).toBe(1);
    expect(record?.pullEpoch).toBe(1);
    expect(record?.observedEpoch).toBe(1);
    expect(record?.variables).toEqual({});
    expect(loaded.floor?.intents).toEqual([]);
  });

  it("does not call 2xx a success when the chain lacks our entry, and does not advance the floor (§12-10 (3))", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const server = acceptingCreateServer({
      projectId: built.projectId,
      base: built,
      onCreate: () => ({
        status: 200,
        json: {
          environmentId: "staging",
          currentEpoch: 1,
          headSeq: built.entries.length + 1,
          headHashHex: "cd".repeat(32),
        },
      }),
    });
    const env = await startEnv(built.projectId, server.handlers, owner);

    expect(await runCli(["env", "create", "staging"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("does not show this run's create_environment");
    const loaded = await Effect.runPromise(
      makeFileFloorStore(env.floorDir).load(testProjectId(built.projectId)),
    );
    expect(loaded.floor?.environments["staging"]).toBeUndefined();
    expect(loaded.floor?.intents).toHaveLength(1);
    expect(loaded.floor?.intents[0]).toMatchObject({
      op: "create_environment",
      environmentId: "staging",
    });
  });

  it("an intent left by a run whose acceptance-check resync failed is resolved by the next run's reconciliation (chain sync), advancing the floor", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const entries: ChainEntry[] = [...built.entries];
    const hashes: string[] = [...built.hashes];
    let chainCalls = 0;
    const server = await MockServer.start([
      onRequest("GET", `/projects/${built.projectId}/chain`, () => {
        chainCalls += 1;
        if (chainCalls > 1) {
          return { status: 502, bodyText: "bad gateway" };
        }
        return {
          status: 200,
          json: {
            projectId: built.projectId,
            entries,
            headSeq: entries.length,
            headHashHex: hashes[hashes.length - 1],
            attestations: [],
          },
        };
      }),
      async (request) => {
        if (
          request.method !== "POST" ||
          request.path !== `/projects/${built.projectId}/environments`
        ) {
          return null;
        }
        const body = request.body as CompositeCreateBody;
        entries.push(body.entry);
        hashes.push(await computeChainEntryHash(body.entry));
        return {
          status: 200,
          json: {
            environmentId: "staging",
            currentEpoch: 1,
            headSeq: entries.length,
            headHashHex: hashes[hashes.length - 1],
          },
        };
      },
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
    expect(await runCli(["env", "create", "staging"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("post-acceptance confirmation");
    let loaded = await Effect.runPromise(
      makeFileFloorStore(env.floorDir).load(testProjectId(built.projectId)),
    );
    expect(loaded.floor?.intents).toHaveLength(1);
    expect(loaded.floor?.environments["staging"]).toBeUndefined();

    const phase2 = await MockServer.start(
      acceptingCreateServer({
        projectId: built.projectId,
        base: { projectId: built.projectId, entries: [...entries], hashes: [...hashes] },
      }).handlers,
    );
    servers.push(phase2);
    seedSession(env, phase2.origin, owner);
    await seedConfig(env, { server: phase2.origin, defaultProject: built.projectId });
    env.errors.length = 0;
    expect(await runCli(["env", "create", "staging2"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("confirmed as accepted on the chain");
    loaded = await Effect.runPromise(
      makeFileFloorStore(env.floorDir).load(testProjectId(built.projectId)),
    );
    expect(loaded.floor?.environments["staging"]?.manifest).toMatchObject({
      manifestVersion: 1,
      epoch: 1,
    });
    expect(loaded.floor?.environments["staging2"]?.manifest).toMatchObject({ manifestVersion: 1 });
    expect(loaded.floor?.intents).toEqual([]);
  });

  it("sends no composite when the intent append fails (journal-before-send is fail-closed)", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const server = acceptingCreateServer({ projectId: built.projectId, base: built });
    const env = await startEnv(built.projectId, server.handlers, owner);
    env.failFloorIntentAppends();

    expect(await runCli(["env", "create", "staging"], env.layer)).toBe(1);
    expect(server.bodies).toHaveLength(0);
    expect(env.errors.join("\n")).toContain("intent");
  });

  it("refuses early, without calling HTTP, an environment ID already observed on the chain (unique across all history — §6.2)", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp("burned", new Uint8Array(32).fill(1)) },
    ]);
    const server = await MockServer.start([chainHandler(built.projectId, built)]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["env", "create", "burned"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("already used on the chain");
    expect(
      server.requests.filter((request) => request.method === "POST").map((request) => request.path),
    ).toEqual([]);
  });
});
