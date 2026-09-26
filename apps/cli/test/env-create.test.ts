// Tests for the composite environment-creation request (§12-4): signing the
// create_environment entry (with the epoch-1 commitment — §5.2/§6.2),
// parent-head CAS, the wrap set matching the verified current-member set
// exactly (the client side of §6.3's ghost-member defense), signer = the
// calling principal (§5.1), re-signing retries on ChainHeadConflict, refusal
// while a grant_server is in force, and early refusal of an environment ID
// already observed on the chain.

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
import { afterEach, describe, expect, it } from "vitest";

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
  type TestUser,
  variablesDigestOf,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, type MockResponse, MockServer, onRequest } from "./support/server.ts";

/** Body of the composite create request (api-schema's environments.create payload). */
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
  /** The bundled manifest (§12-4 — manifestVersion 1, empty variable set, empty prev). */
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
    },
  }));
}

/**
 * A minimal composite-create mock mimicking the real server's state
 * transitions: appends an accepted create_environment entry to the chain and
 * serves it to later chain fetches (the acceptance-check resync — §12-10
 * (3)). Same rationale as env-rotate.test.ts's makeServer — since the effect
 * check is a chain sync, a mock that merely returns 200 can never succeed.
 */
function acceptingCreateServer(input: {
  readonly projectId: string;
  readonly base: Awaited<ReturnType<typeof buildChain>>;
  /** Per-call override response for create (undefined = accept). Skips acceptance. */
  readonly onCreate?: (call: number, body: CompositeCreateBody) => MockResponse | undefined;
  /** Override for the response returned after accepting (appending to the chain) — for the lying-attestation negative. */
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

/** Verifies one wrap's §5.1 signature (signer = owner) and unwraps it as the recipient; returns the DEK. */
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
      projectId,
      environmentId: "staging",
      epoch: wrap.epoch,
      recipientUserId: wrap.recipientUserId,
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
      projectId,
      environmentId: "staging",
      epoch: 1,
      recipientUserId: wrap.recipientUserId,
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
    // The display name rides on the EnvironmentMetaStatement
    // (metaVersion 1) (§12-4). The declared head is the pre-append current
    // head (= the bundled entry's prev)
    expect(body.statement.name).toBe("Staging");
    expect(body.statement.environmentId).toBe("staging");
    expect(body.statement.status).toBe("active");
    expect(body.statement.metaVersion).toBe(1);
    expect(body.statement.prevMetaSigHashHex).toBe("");
    expect(body.statement.chainHeadHashHex).toBe(head);
    expect(body.statement.chainHeadSeq).toBe(built.entries.length);
    expect(body.statement.signatureHex).toMatch(/^[0-9a-f]{128}$/);
    // Parent-head CAS + the entry is signed by actor = the calling
    // principal, placed right after the current head (seq = head + 1)
    expect(body.parentHeadHashHex).toBe(head);
    expect(body.entry.op).toBe("create_environment");
    expect(body.entry.seq).toBe(built.entries.length + 1);
    expect(body.entry.prevHashHex).toBe(head);
    expect(body.entry.actor.userId).toBe(owner.userId);
    expect(body.entry.payload.environmentId).toBe("staging");
    // Wrap recipients = exactly the verified current-member set (nothing
    // addressed to removed members)
    expect(body.deks.map((wrap) => wrap.recipientUserId).toSorted()).toEqual(
      [owner.userId, member.userId].toSorted(),
    );
    // Each wrap carries a §5.1 signature (signer = the calling principal =
    // owner) and its recipient can decrypt. Every recipient obtains the same
    // DEK
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
    // The entry's dek_commitment_hex is the bundled DEK's §5.2 commitment
    // (recipients check the unwrapped DEK against this value before using
    // it)
    const dek = deks[0];
    if (dek === undefined) throw new Error("missing dek");
    const matched = await verifyDekCommitment({
      context: {
        suite: "maruhi/v1",
        projectId: built.projectId,
        environmentId: "staging",
        epoch: 1,
      },
      dek,
      expectedCommitmentHex: body.entry.payload.dekCommitmentHex,
    });
    expect(matched.ok).toBe(true);
    // The bundled manifest (§12-4): manifestVersion 1, the canonical digest
    // of the empty variable set, empty prev, epoch 1 (after the composite
    // applies — §12-5 (4)), and the declared head is the pre-append current
    // head. envMeta is the bundled statement's (metaVersion, signed-bytes
    // hash)
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
    // A chain extended by a concurrent append (same genesis + add_member)
    const chainB = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(other, "reader") },
    ]);
    expect(chainB.projectId).toBe(chainA.projectId);
    const headB = chainB.hashes[chainB.hashes.length - 1] ?? "";
    // The first sync serves chainA; post-409 resyncs serve chainB (+ the
    // accepted entry)
    const entries: ChainEntry[] = [...chainA.entries];
    const hashes: string[] = [...chainA.hashes];
    const bodies: CompositeCreateBody[] = [];
    const env = await startEnv(
      chainA.projectId,
      [
        onRequest("GET", `/projects/${chainA.projectId}/chain`, () => ({
          status: 200,
          json: {
            projectId: chainA.projectId,
            entries,
            headSeq: entries.length,
            headHashHex: hashes[hashes.length - 1],
          },
        })),
        async (request) => {
          if (
            request.method !== "POST" ||
            request.path !== `/projects/${chainA.projectId}/environments`
          ) {
            return null;
          }
          const body = request.body as CompositeCreateBody;
          bodies.push(body);
          if (bodies.length === 1) {
            // Another member had appended concurrently with the send
            // (parent-head CAS failure)
            entries.splice(0, entries.length, ...chainB.entries);
            hashes.splice(0, hashes.length, ...chainB.hashes);
            return {
              status: 409,
              json: {
                _tag: "ChainHeadConflict",
                currentHeadSeq: chainB.entries.length,
                currentHeadHashHex: headB,
              },
            };
          }
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
      ],
      owner,
    );

    expect(await runCli(["env", "create", "staging"], env.layer)).toBe(0);
    expect(bodies).toHaveLength(2);
    const [first, second] = bodies;
    if (first === undefined || second === undefined) throw new Error("missing bodies");
    // The retry re-signs the entry with the new head as parent (seq / prev /
    // signature all change)
    expect(first.entry.seq).toBe(2);
    expect(second.entry.seq).toBe(3);
    expect(second.parentHeadHashHex).toBe(headB);
    expect(second.entry.prevHashHex).toBe(headB);
    expect(second.entry.signatureHex).not.toBe(first.entry.signatureHex);
    // The statement is **also** re-signed (declared head = the new head
    // before the append — §12-4)
    expect(second.statement.chainHeadHashHex).toBe(headB);
    expect(second.statement.chainHeadSeq).toBe(chainB.entries.length);
    expect(second.statement.signatureHex).not.toBe(first.statement.signatureHex);
    // The commitment (= the already-generated DEK) stays unchanged
    expect(second.entry.payload.dekCommitmentHex).toBe(first.entry.payload.dekCommitmentHex);
    // The member set changed (other was added), so the wrap set is rebuilt
    expect(first.deks.map((wrap) => wrap.recipientUserId)).toEqual([owner.userId]);
    expect(second.deks.map((wrap) => wrap.recipientUserId).toSorted()).toEqual(
      [owner.userId, other.userId].toSorted(),
    );
    // The completion report's member count is the size of the wrap set
    // **actually registered** (not the 1 from the starting view). Don't
    // report a number disagreeing with the rebuilt set
    expect(env.logs.join("\n")).toContain("DEK wrapped for 2 current members");
  });

  it("the ChainHeadConflict resync carries an extension check (no re-signing onto a shortened or forked chain)", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const other = await makeTestUser("user-other-4444");
    // The chain served after the 409 is shorter than the one seen first (2
    // entries) = a rollback. Even if it verifies as signatures go, the entry
    // must not be re-signed in this state nor the wrap set rebuilt on the
    // rolled-back member set (§6.3-2b)
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
    // No re-signing on the rolled-back view (the send happened exactly
    // once)
    expect(bodies).toHaveLength(1);
  });

  it("reuses the wrap set on a ChainHeadConflict retry when the member set is unchanged (§12-4)", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const chainA = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    // A chain that grew while the member set (user_id → enc key) stayed
    // unchanged (a rename-equivalent via change_role to keep own role at
    // owner isn't allowed, so advance only the head via "add then
    // immediately remove")
    const passerby = await makeTestUser("user-passerby-5555");
    const chainB = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(passerby, "reader") },
      { actor: owner, operation: removeMemberOp(passerby) },
    ]);
    expect(chainB.projectId).toBe(chainA.projectId);
    const headB = chainB.hashes[chainB.hashes.length - 1] ?? "";
    const entries: ChainEntry[] = [...chainA.entries];
    const hashes: string[] = [...chainA.hashes];
    const bodies: CompositeCreateBody[] = [];
    const env = await startEnv(
      chainA.projectId,
      [
        onRequest("GET", `/projects/${chainA.projectId}/chain`, () => ({
          status: 200,
          json: {
            projectId: chainA.projectId,
            entries,
            headSeq: entries.length,
            headHashHex: hashes[hashes.length - 1],
          },
        })),
        async (request) => {
          if (
            request.method !== "POST" ||
            request.path !== `/projects/${chainA.projectId}/environments`
          ) {
            return null;
          }
          const body = request.body as CompositeCreateBody;
          bodies.push(body);
          if (bodies.length === 1) {
            entries.splice(0, entries.length, ...chainB.entries);
            hashes.splice(0, hashes.length, ...chainB.hashes);
            return {
              status: 409,
              json: {
                _tag: "ChainHeadConflict",
                currentHeadSeq: chainB.entries.length,
                currentHeadHashHex: headB,
              },
            };
          }
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
      ],
      owner,
    );

    expect(await runCli(["env", "create", "staging"], env.layer)).toBe(0);
    expect(bodies).toHaveLength(2);
    const [first, second] = bodies;
    if (first === undefined || second === undefined) throw new Error("missing bodies");
    // The entry is re-signed (prev changes) but the wrap set is not rebuilt
    // (HPKE Seal is randomized — a re-wrap would change enc / ct /
    // signature)
    expect(second.entry.prevHashHex).toBe(headB);
    expect(second.deks).toEqual(first.deks);
  });

  it("a missing environment-ID positional is refused before the network (never calls the create API with a bogus id)", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const server = await MockServer.start([chainHandler(built.projectId, built)]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
    // The args layer rejects the required positional (usage error = exit
    // 2). The handler's undefined guard is defense in depth so that even if
    // that pre-phase is bypassed, "undefined" fails RESOURCE_ID_PATTERN.
    // Either way, no HTTP happens
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

    // Does not wait for the server's generic 403: waiting would mean the
    // DEK generation + per-member HPKE wraps + signing all run before being
    // refused (same discipline as env rotate)
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
      // A scope that pre-disclosed a not-yet-created ID (the consensus
      // rules have no existence check for scopes)
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
    // Complete set = current members (owner) + the server key of the
    // in-scope grant. The server-destined wrap puts the server-key FP in the
    // recipient position (CRYPTO_SPEC §9)
    expect(body.deks).toHaveLength(2);
    const serverWrap = body.deks.find((wrap) => wrap.recipientClass === "server");
    expect(serverWrap?.recipientUserId).toBe(grantEntry.payload.serverKeyFingerprintHex);
    expect(serverWrap?.recipientEncPubHex).toBe(grantEntry.payload.serverEncPubHex);
  });

  it("a grant_server with an empty scope targets no environment (creation can proceed without a server-destined wrap)", async () => {
    // §6.2 doesn't define an empty scope's meaning, but the complete-set
    // check (§12-4) keys on "environments included in the scope", so empty =
    // nothing targeted. Client and server use the same includes check (a
    // split would make the composite permanently 422)
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
    expect(body.deks.every((wrap) => wrap.recipientClass === undefined)).toBe(true);
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
    // Taking the post-acceptance fact from the server's self-assertion would
    // relax, on the create side alone, the "claims are not the source of
    // truth" discipline laid down on the rotate side. create_environment
    // always establishes epoch 1, so report 1 whatever the claim says
    const owner = await makeTestUser("user-owner-1111");
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const server = acceptingCreateServer({
      projectId: built.projectId,
      base: built,
      // Accepts (appends to the chain) but lies in the attestation (the
      // real server returns 1 — composite-programs.ts). The effect check
      // runs on chain derivation, so this still succeeds
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
    const loaded = await Effect.runPromise(makeFileFloorStore(env.floorDir).load(built.projectId));
    const record = loaded.floor?.environments["staging"];
    // The environment floor of an empty variable set: environment meta v1,
    // self-issued manifest v1 (epoch 1), and rule (c)'s baseline = 1
    // (established atomically with the empty coverage)
    expect(record?.manifest).toMatchObject({ manifestVersion: 1, epoch: 1 });
    expect(record?.metaVersion).toBe(1);
    expect(record?.pullEpoch).toBe(1);
    expect(record?.observedEpoch).toBe(1);
    expect(record?.variables).toEqual({});
    // The intent is closed since the effect check (§12-10 (3)) passed
    expect(loaded.floor?.intents).toEqual([]);
  });

  it("does not call 2xx a success when the chain lacks our entry, and does not advance the floor (§12-10 (3))", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    // Returns 200 but never appends to the chain = a lying 2xx (malicious
    // or buggy server)
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
    const loaded = await Effect.runPromise(makeFileFloorStore(env.floorDir).load(built.projectId));
    // The floor did not advance (don't write your own assumptions onto the
    // floor)
    expect(loaded.floor?.environments["staging"]).toBeUndefined();
    // The check-obligation record (intent) remains unresolved (the next
    // run's reconciliation target)
    expect(loaded.floor?.intents).toHaveLength(1);
    expect(loaded.floor?.intents[0]).toMatchObject({
      op: "create_environment",
      environmentId: "staging",
    });
  });

  it("an intent left by a run whose acceptance-check resync failed is resolved by the next run's reconciliation (chain sync), advancing the floor", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    // Phase 1: acceptance (the chain append) happens, but the check resync
    // (the second chain fetch) fails = the acceptance-unknown case. It
    // errors out and the intent remains
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
    let loaded = await Effect.runPromise(makeFileFloorStore(env.floorDir).load(built.projectId));
    expect(loaded.floor?.intents).toHaveLength(1);
    expect(loaded.floor?.environments["staging"]).toBeUndefined();

    // Phase 2: the next run (creating a different environment) reconciles
    // the intent in its pre-phase via a chain sync — it confirms acceptance,
    // so the floor (self-issued manifest) advances
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
    loaded = await Effect.runPromise(makeFileFloorStore(env.floorDir).load(built.projectId));
    // The reconciliation has recovered the interrupted create's self-issued
    // manifest onto the floor
    expect(loaded.floor?.environments["staging"]?.manifest).toMatchObject({
      manifestVersion: 1,
      epoch: 1,
    });
    // staging2's own v1 floor and intent resolution proceed as usual
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
    // Don't fire a security-critical mutation without the check-obligation
    // record
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
    // No environment-creation HTTP call occurred (only the chain fetch)
    expect(
      server.requests.filter((request) => request.method === "POST").map((request) => request.path),
    ).toEqual([]);
  });
});
