import {
  addMemberOp,
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  type GeneratedIdentity,
  generateIdentity,
  genesisOp,
  removeMemberOp,
  rotateEpochOp,
  testEnvironmentId,
  testProjectId,
} from "@maruhi/test-kit";
import { Effect, Exit, Redacted } from "effect";
import { FetchHttpClient } from "effect/http";
import { afterEach, beforeAll, describe, expect, it } from "vite-plus/test";

import { makeApiClient } from "../src/api.ts";
import { syncProject } from "../src/chain-sync.ts";
import { type MockResponse, MockServer, onRequest } from "./support/server.ts";

let owner: GeneratedIdentity;
let member: GeneratedIdentity;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await generateIdentity("user-owner-1111");
  member = await generateIdentity("user-member-2222");
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

async function startServer(handlers: Parameters<typeof MockServer.start>[0]): Promise<MockServer> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  return server;
}

function chainResponse(projectId: string, built: BuiltChain): MockResponse {
  return {
    status: 200,
    json: {
      projectId,
      entries: built.entries,
      headSeq: built.entries.length,
      headHashHex: built.hashes[built.hashes.length - 1],
      attestations: [],
    },
  };
}

function runSync(origin: string, projectId: string) {
  return Effect.runPromiseExit(
    Effect.gen(function* () {
      const client = yield* makeApiClient({
        baseUrl: origin,
        token: Redacted.make("maruhi_pat_test"),
      });
      return yield* syncProject(client, testProjectId(projectId));
    }).pipe(Effect.provide(FetchHttpClient.layer)),
  );
}

function failureMessage(exit: Awaited<ReturnType<typeof runSync>>): string {
  return JSON.stringify(exit);
}

describe("syncProject (§6.3)", () => {
  it("verifies a valid chain and keeps removed members' keys in the history index", async () => {
    const dek1 = crypto.getRandomValues(new Uint8Array(32));
    const dek2 = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(member, "member") },
      { actor: member, operation: createEnvironmentOp("prod", dek1) },
      { actor: member, operation: rotateEpochOp("prod", 2, dek2) },
      { actor: owner, operation: removeMemberOp(member) },
    ]);
    const server = await startServer([
      onRequest("GET", `/projects/${built.projectId}/chain`, () =>
        chainResponse(built.projectId, built),
      ),
    ]);
    const exit = await runSync(server.origin, built.projectId);
    expect(Exit.isSuccess(exit)).toBe(true);
    if (!Exit.isSuccess(exit)) {
      return;
    }
    const verified = exit.value;
    expect([...verified.state.members.keys()]).toEqual([owner.userId]);
    const prod = verified.state.environments.get(testEnvironmentId("prod"));
    expect(prod?.currentEpoch).toBe(2);
    expect(prod?.createdAtSeq).toBe(3);
    expect(prod?.epochStartSeqs.get(1)).toBe(3);
    expect(prod?.epochStartSeqs.get(2)).toBe(4);
    expect(prod?.dekCommitments.get(2)).toMatch(/^[0-9a-f]{64}$/);
    const bindings = verified.keyHistory.get(member.userId);
    expect(bindings).toHaveLength(1);
    expect(bindings?.[0]?.sigPubHex).toBe(member.sigPubHex);
    expect(bindings?.[0]?.keyFingerprintHex).toBe(member.fingerprintHex);
  });

  it("rejects a signature-forged chain (verifyChain delegation)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(member, "member") },
    ]);
    const second = built.entries[1];
    if (second === undefined) {
      throw new Error("fixture");
    }
    const tampered = [built.entries[0], { ...second, timestampMs: second.timestampMs + 1 }];
    const server = await startServer([
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: tampered,
          headSeq: 2,
          headHashHex: built.hashes[1],
          attestations: [],
        },
      })),
    ]);
    const exit = await runSync(server.origin, built.projectId);
    expect(Exit.isFailure(exit)).toBe(true);
    const failure = JSON.parse(failureMessage(exit)) as {
      readonly cause: {
        readonly reasons: readonly [{ readonly error: { readonly message: string } }];
      };
    };
    expect(failure.cause.reasons[0].error.message).toBe(
      "Chain verification failed (seq=2, reason=bad-signature). The server may be distributing an invalid chain",
    );
  });

  it("rejects a substitution whose genesis hash doesn't match the project ID (§6.4)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const other = await buildChain([{ actor: member, operation: genesisOp(member) }]);
    expect(other.projectId).not.toBe(built.projectId);
    const server = await startServer([
      onRequest("GET", `/projects/${built.projectId}/chain`, () =>
        chainResponse(built.projectId, other),
      ),
    ]);
    const exit = await runSync(server.origin, built.projectId);
    expect(Exit.isFailure(exit)).toBe(true);
    expect(failureMessage(exit)).toContain("genesis hash");
  });

  it("rejects a disagreement between the server's declared head and the derived head", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(member, "member") },
    ]);
    const server = await startServer([
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: built.entries,
          headSeq: 1,
          headHashHex: built.hashes[0],
          attestations: [],
        },
      })),
    ]);
    const exit = await runSync(server.origin, built.projectId);
    expect(Exit.isFailure(exit)).toBe(true);
    expect(failureMessage(exit)).toContain("chain head");
  });

  it("also rejects a declared head whose seq is right but whose hash is false", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(member, "member") },
    ]);
    const server = await startServer([
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: "ab".repeat(32),
          attestations: [],
        },
      })),
    ]);
    const exit = await runSync(server.origin, built.projectId);
    expect(Exit.isFailure(exit)).toBe(true);
    expect(failureMessage(exit)).toContain("chain head");
  });
});
