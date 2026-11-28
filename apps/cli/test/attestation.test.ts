import { readFile } from "node:fs/promises";
import { join } from "node:path";

import type { ProjectId } from "@maruhi/core";
import { signHeadAttestation } from "@maruhi/crypto";
import {
  addMemberOp,
  buildChain,
  type BuiltChain,
  type GeneratedIdentity,
  generateIdentity,
  genesisOp,
  removeMemberOp,
  testProjectId,
} from "@maruhi/test-kit";
import { Effect, Exit, Redacted } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vite-plus/test";

import { makeApiClient } from "../src/api.ts";
import {
  reconcileDistributedAttestations,
  submitHeadAttestationIfAdvanced,
} from "../src/attestation.ts";
import {
  type DistributedAttestationWire,
  verifyChainSnapshot,
  type VerifiedProject,
} from "../src/chain-sync.ts";
import type { CliError } from "../src/errors.ts";
import { lastHashOf } from "./support/chain-handler.ts";
import { makeTestEnv, type TestEnv } from "./support/env.ts";
import { MockServer, onEndpoint } from "./support/server.ts";

let owner: GeneratedIdentity;
let member: GeneratedIdentity;
let outsider: GeneratedIdentity;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await generateIdentity("user-owner-1111");
  member = await generateIdentity("user-member-2222");
  outsider = await generateIdentity("user-outsider-3333");
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

async function verifiedViewOf(
  built: BuiltChain,
  upTo: number,
  attestations: readonly DistributedAttestationWire[],
): Promise<VerifiedProject> {
  return Effect.runPromise(
    verifyChainSnapshot({
      projectId: built.projectId as ProjectId,
      entries: built.entries.slice(0, upTo),
      claimedHeadSeq: upTo,
      claimedHeadHashHex: built.hashes[upTo - 1] ?? "",
      attestations,
    }),
  );
}

async function attestationBy(
  attester: GeneratedIdentity,
  projectId: string,
  head: { readonly seq: number; readonly hashHex: string },
  overrides?: Partial<DistributedAttestationWire>,
): Promise<DistributedAttestationWire> {
  const signed = await signHeadAttestation({
    context: {
      suite: "maruhi/v1",
      projectId: testProjectId(projectId),
      attesterUserId: attester.userId,
      chainHeadHashHex: head.hashHex,
      chainHeadSeq: head.seq,
    },
    signingKey: attester.sigKeyPair.privateKey,
  });
  if (!signed.ok) {
    throw new Error("attestation signing failed");
  }
  return {
    suite: "maruhi/v1",
    attesterUserId: attester.userId,
    attesterKeyFingerprintHex: attester.fingerprintHex,
    chainHeadHashHex: head.hashHex,
    chainHeadSeq: head.seq,
    signatureHex: signed.value,
    ...overrides,
  };
}

function runReconcile(
  env: TestEnv,
  input: {
    readonly projectId: string;
    readonly view: VerifiedProject;
    readonly resync?: Effect.Effect<VerifiedProject, CliError>;
  },
) {
  return Effect.runPromiseExit(
    reconcileDistributedAttestations({
      projectId: testProjectId(input.projectId),
      view: input.view,
      resync: input.resync ?? Effect.die(new Error("resync must not be reached in this test")),
    }).pipe(Effect.provide(env.layer)),
  );
}

function failureText(exit: Exit.Exit<unknown, unknown>): string {
  return JSON.stringify(exit);
}

async function buildStandardChain(): Promise<BuiltChain> {
  return buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: addMemberOp(member, "member") },
    { actor: owner, operation: removeMemberOp(member) },
  ]);
}

describe("reconcileDistributedAttestations (checking — §6.3 / §6.6)", () => {
  it("correctly sorts matching attestations, forged ones that fail verification, and non-current-member ones (no interruption)", async () => {
    const env = await makeTestEnv();
    const built = await buildStandardChain();
    const head2 = { seq: 2, hashHex: built.hashes[1] ?? "" };
    const matching = await attestationBy(member, built.projectId, head2);
    const forged = {
      ...matching,
      signatureHex: `${matching.signatureHex.slice(0, -2)}${matching.signatureHex.endsWith("00") ? "01" : "00"}`,
    };
    const unknown = await attestationBy(outsider, built.projectId, head2);
    const view = await verifiedViewOf(built, 2, [matching, forged, unknown]);
    const exit = await runReconcile(env, { projectId: built.projectId, view });
    expect(Exit.isSuccess(exit), failureText(exit)).toBe(true);
    if (Exit.isSuccess(exit)) {
      expect(exit.value).toBe(view);
    }
    expect(env.errors).toEqual([]);
  });

  it("a past attestation by a removed member to an in-tenure head is not checking material (the current-member check in §6.6 (1))", async () => {
    const env = await makeTestEnv();
    const built = await buildStandardChain();
    const inTenure = await attestationBy(member, built.projectId, {
      seq: 2,
      hashHex: built.hashes[1] ?? "",
    });
    const view = await verifiedViewOf(built, 3, [inTenure]);
    const exit = await runReconcile(env, { projectId: built.projectId, view });
    expect(Exit.isSuccess(exit), failureText(exit)).toBe(true);
  });

  it("(a) attestation seq ≤ own head with a hash mismatch = hard evidence: interrupt, warn, store evidence append-only", async () => {
    const env = await makeTestEnv();
    const built = await buildStandardChain();
    const forkedHash = "ef".repeat(32);
    const contradicting = await attestationBy(member, built.projectId, {
      seq: 2,
      hashHex: forkedHash,
    });
    const view = await verifiedViewOf(built, 2, [contradicting]);
    const exit = await runReconcile(env, { projectId: built.projectId, view });
    expect(Exit.isFailure(exit)).toBe(true);
    const message = failureText(exit);
    expect(message).toContain("Head-attestation cross-check");
    expect(message).toContain("server equivocation");
    expect(message).toContain(forkedHash);
    const evidenceRaw = await readFile(
      join(env.floorDir, `${built.projectId}.attestation-evidence.jsonl`),
      "utf8",
    );
    const records = evidenceRaw
      .split("\n")
      .filter((line) => line.trim() !== "")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      kind: "head-mismatch",
      attestation: {
        attesterUserId: member.userId,
        chainHeadHashHex: forkedHash,
        chainHeadSeq: 2,
        signatureHex: contradicting.signatureHex,
      },
      localView: {
        headSeq: 2,
        headHashHex: built.hashes[1],
        entryHashAtAttestedSeq: built.hashes[1],
      },
    });
  });

  it("(b) attestation seq > own head = resolved as an extension via bounded resync is normal (returns the advanced view)", async () => {
    const env = await makeTestEnv();
    const built = await buildStandardChain();
    const head3 = { seq: 3, hashHex: built.hashes[2] ?? "" };
    const ahead = await attestationBy(owner, built.projectId, head3);
    const view = await verifiedViewOf(built, 2, [ahead]);
    const resyncView = await verifiedViewOf(built, 3, [ahead]);
    const exit = await runReconcile(env, {
      projectId: built.projectId,
      view,
      resync: Effect.succeed(resyncView),
    });
    expect(Exit.isSuccess(exit), failureText(exit)).toBe(true);
    if (Exit.isSuccess(exit)) {
      expect(exit.value.state.headSeq).toBe(3);
    }
  });

  it("(b) an attestation unresolved after resync is treated like (a) (unresolved-after-resync evidence, with dedup)", async () => {
    const env = await makeTestEnv();
    const built = await buildStandardChain();
    const unresolvable = await attestationBy(owner, built.projectId, {
      seq: 5,
      hashHex: "ab".repeat(32),
    });
    const view = await verifiedViewOf(built, 3, [unresolvable]);
    const resyncView = await verifiedViewOf(built, 3, [unresolvable]);
    const exit = await runReconcile(env, {
      projectId: built.projectId,
      view,
      resync: Effect.succeed(resyncView),
    });
    expect(Exit.isFailure(exit)).toBe(true);
    const evidenceRaw = await readFile(
      join(env.floorDir, `${built.projectId}.attestation-evidence.jsonl`),
      "utf8",
    );
    const records = evidenceRaw.split("\n").filter((line) => line.trim() !== "");
    expect(records).toHaveLength(1);
    expect(records[0]).toContain('"kind":"unresolved-after-resync"');
  });

  it("(b) mixing a same-key forged record with only the hash rewritten into the resync view does not disable carry-over checking", async () => {
    const env = await makeTestEnv();
    const built = await buildStandardChain();
    const genuineHash = "ab".repeat(32);
    const genuine = await attestationBy(owner, built.projectId, {
      seq: 5,
      hashHex: genuineHash,
    });
    const tampered = { ...genuine, chainHeadHashHex: "cd".repeat(32) };
    const view = await verifiedViewOf(built, 3, [genuine]);
    const resyncView = await verifiedViewOf(built, 3, [tampered]);
    const exit = await runReconcile(env, {
      projectId: built.projectId,
      view,
      resync: Effect.succeed(resyncView),
    });
    expect(Exit.isFailure(exit)).toBe(true);
    const evidenceRaw = await readFile(
      join(env.floorDir, `${built.projectId}.attestation-evidence.jsonl`),
      "utf8",
    );
    const records = evidenceRaw.split("\n").filter((line) => line.trim() !== "");
    expect(records).toHaveLength(1);
    expect(records[0]).toContain('"kind":"unresolved-after-resync"');
    expect(records[0]).toContain(genuineHash);
  });
});

describe("wiring into the command pre-phase (project verify — interruption on conflicting attestations)", () => {
  async function verifyCommandEnv(
    built: BuiltChain,
    attestations: readonly DistributedAttestationWire[],
  ): Promise<TestEnv> {
    const server = await startServer([
      onEndpoint("membership.get", { projectId: built.projectId }, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: lastHashOf(built.hashes),
          attestations,
        },
      })),
    ]);
    const env = await makeTestEnv();
    const { seedConfig, seedSession } = await import("./support/env.ts");
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
    return env;
  }

  it("project verify succeeds under a distribution of matching attestations", async () => {
    const { runCli } = await import("../src/cli.ts");
    const built = await buildStandardChain();
    const matching = await attestationBy(owner, built.projectId, {
      seq: 3,
      hashHex: built.hashes[2] ?? "",
    });
    const env = await verifyCommandEnv(built, [matching]);
    expect(await runCli(["project", "verify"], env.layer)).toBe(0);
    const floorLog = await readFile(join(env.floorDir, `${built.projectId}.jsonl`), "utf8");
    expect(floorLog).toContain('"r":"head"');
  });

  it("project verify interrupts under a distribution of conflicting attestations, leaving a warning and evidence", async () => {
    const { runCli } = await import("../src/cli.ts");
    const built = await buildStandardChain();
    const contradicting = await attestationBy(owner, built.projectId, {
      seq: 2,
      hashHex: "ef".repeat(32),
    });
    const env = await verifyCommandEnv(built, [contradicting]);
    expect(await runCli(["project", "verify"], env.layer)).not.toBe(0);
    const output = env.errors.join("\n");
    expect(output).toContain("Head-attestation cross-check");
    const evidenceRaw = await readFile(
      join(env.floorDir, `${built.projectId}.attestation-evidence.jsonl`),
      "utf8",
    );
    expect(evidenceRaw).toContain('"kind":"head-mismatch"');
    const floorLog = await readFile(join(env.floorDir, `${built.projectId}.jsonl`), "utf8").catch(
      () => "",
    );
    expect(floorLog).not.toContain('"r":"head"');
  });
});

describe("submitHeadAttestationIfAdvanced (submission — SHOULD)", () => {
  async function submissionProgram(
    env: TestEnv,
    origin: string,
    view: VerifiedProject,
    projectId: string,
  ): Promise<void> {
    await Effect.runPromise(
      Effect.gen(function* () {
        const client = yield* makeApiClient({
          baseUrl: origin,
          token: Redacted.make("maruhi_pat_test"),
        });
        yield* submitHeadAttestationIfAdvanced({
          client,
          projectId: testProjectId(projectId),
          view,
          attesterUserId: owner.userId,
          signingKey: owner.sigKeyPair.privateKey,
        });
      }).pipe(Effect.provide(env.layer)),
    );
  }

  it("submits only when the verified head advanced past the last attestation, and updates the tracking", async () => {
    const env = await makeTestEnv();
    const built = await buildStandardChain();
    const server = await startServer([
      onEndpoint("membership.attest", { projectId: built.projectId }, () => ({
        status: 204,
      })),
    ]);
    const view2 = await verifiedViewOf(built, 2, []);
    await submissionProgram(env, server.origin, view2, built.projectId);
    const puts = () =>
      server.requests.filter(
        (request) =>
          request.method === "PUT" &&
          request.path === `/projects/${built.projectId}/head-attestation`,
      );
    expect(puts()).toHaveLength(1);
    expect(puts()[0]?.body).toMatchObject({
      suite: "maruhi/v1",
      chainHeadHashHex: built.hashes[1],
      chainHeadSeq: 2,
    });
    await submissionProgram(env, server.origin, view2, built.projectId);
    expect(puts()).toHaveLength(1);
    const view3 = await verifiedViewOf(built, 3, []);
    await submissionProgram(env, server.origin, view3, built.projectId);
    expect(puts()).toHaveLength(2);
    expect(puts()[1]?.body).toMatchObject({ chainHeadSeq: 3 });
    expect(env.errors).toEqual([]);
    const tracked = JSON.parse(
      await readFile(join(env.floorDir, `${built.projectId}.attested.json`), "utf8"),
    ) as { head: { seq: number } };
    expect(tracked.head.seq).toBe(3);
  });

  it("submits even at the same seq when the hash differs (seq-only suppression would close the attestation path under equivocation)", async () => {
    const env = await makeTestEnv();
    const built = await buildStandardChain();
    const server = await startServer([
      onEndpoint("membership.attest", { projectId: built.projectId }, () => ({
        status: 204,
      })),
    ]);
    const view3 = await verifiedViewOf(built, 3, []);
    await submissionProgram(env, server.origin, view3, built.projectId);
    expect(server.requests).toHaveLength(1);
    const { writeFile } = await import("node:fs/promises");
    await writeFile(
      join(env.floorDir, `${built.projectId}.attested.json`),
      `${JSON.stringify({ v: 1, head: { seq: 3, hashHex: "ef".repeat(32) } })}\n`,
    );
    await submissionProgram(env, server.origin, view3, built.projectId);
    expect(server.requests).toHaveLength(2);
  });

  it("reads a tracking file without the format version as corrupt (the head is submitted again)", async () => {
    const env = await makeTestEnv();
    const built = await buildStandardChain();
    const server = await startServer([
      onEndpoint("membership.attest", { projectId: built.projectId }, () => ({
        status: 204,
      })),
    ]);
    const view3 = await verifiedViewOf(built, 3, []);
    await submissionProgram(env, server.origin, view3, built.projectId);
    expect(server.requests).toHaveLength(1);
    const { writeFile } = await import("node:fs/promises");
    await writeFile(
      join(env.floorDir, `${built.projectId}.attested.json`),
      `${JSON.stringify({ head: { seq: 3, hashHex: built.hashes[2] } })}\n`,
    );
    await submissionProgram(env, server.origin, view3, built.projectId);
    expect(server.requests).toHaveLength(2);
    expect(env.errors).toEqual([]);
  });

  it("a submission failure (old server = route missing) degrades to a one-line warning without failing the command", async () => {
    const env = await makeTestEnv();
    const built = await buildStandardChain();
    const server = await startServer([]);
    const view = await verifiedViewOf(built, 2, []);
    await submissionProgram(env, server.origin, view, built.projectId);
    expect(env.errors.some((line) => line.includes("could not submit the head attestation"))).toBe(
      true,
    );
    await expect(
      readFile(join(env.floorDir, `${built.projectId}.attested.json`), "utf8"),
    ).rejects.toThrow();
  });

  it("warns on 409 (AttestationRegression) distinguished as a symptom of floor corruption / a concurrent CLI", async () => {
    const env = await makeTestEnv();
    const built = await buildStandardChain();
    const server = await startServer([
      onEndpoint("membership.attest", { projectId: built.projectId }, () => ({
        status: 409,
        json: { _tag: "AttestationRegression", storedSeq: 9 },
      })),
    ]);
    const view = await verifiedViewOf(built, 2, []);
    await submissionProgram(env, server.origin, view, built.projectId);
    expect(env.errors).toEqual(
      expect.arrayContaining([
        "Warning: the server rejected this head attestation as a regression (it stores a later attestation from this account). This can indicate local floor damage or a concurrent CLI on another machine that has seen a later chain — run `maruhi project verify` and compare with other members if you do not recognize this",
      ]),
    );
  });
});
