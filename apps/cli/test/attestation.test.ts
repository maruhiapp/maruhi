// Tests for the client side of head gossip (CRYPTO_SPEC §6.3 / §6.6).
// session-27 §13-5 attestation clause: the two-way split in distribution
// checking (a mismatch at seq ≤ own head = immediate evidence / seq > own
// head = resync → resolve), evidence storage (floor-evidence format),
// interruption on conflicting attestations, and the submission trigger (only
// on advance — tracking the last attestation).

import { readFile } from "node:fs/promises";
import { join } from "node:path";

import type { ProjectId } from "@maruhi/core";
import { signHeadAttestation } from "@maruhi/crypto";
import { Effect, Exit, Redacted } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { makeApiClient } from "../src/api.ts";
import {
  reconcileDistributedAttestations,
  submitHeadAttestationIfAdvanced,
} from "../src/attestation.ts";
import type { CliError } from "../src/errors.ts";
import {
  type DistributedAttestationWire,
  verifyChainSnapshot,
  type VerifiedProject,
} from "../src/sync.ts";
import {
  addMemberOp,
  type BuiltChain,
  buildChain,
  genesisOp,
  makeTestUser,
  removeMemberOp,
  type TestUser,
} from "./support/crypto.ts";
import { makeTestEnv, type TestEnv } from "./support/env.ts";
import { MockServer, onRequest } from "./support/server.ts";

let owner: TestUser;
let member: TestUser;
let outsider: TestUser;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  member = await makeTestUser("user-member-2222");
  outsider = await makeTestUser("user-outsider-3333");
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

/** Builds a verified view directly (checking is a pure, network-independent check). */
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

/** Signs and builds a §6.6 attestation wire with the attester's key. */
async function attestationBy(
  attester: TestUser,
  projectId: string,
  head: { readonly seq: number; readonly hashHex: string },
  overrides?: Partial<DistributedAttestationWire>,
): Promise<DistributedAttestationWire> {
  const signed = await signHeadAttestation({
    context: {
      suite: "maruhi/v1",
      projectId,
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
      projectId: input.projectId,
      view: input.view,
      resync: input.resync ?? Effect.die(new Error("resync must not be reached in this test")),
    }).pipe(Effect.provide(env.layer)),
  );
}

function failureText(exit: Exit.Exit<unknown, unknown>): string {
  return JSON.stringify(exit);
}

/** The standard 3-entry chain: genesis → add_member(member) → remove_member. */
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
    // Forged signature (1 bit flipped) = not checking material (keeps out a
    // warning-triggering DoS)
    const forged = {
      ...matching,
      signatureHex: `${matching.signatureHex.slice(0, -2)}${matching.signatureHex.endsWith("00") ? "01" : "00"}`,
    };
    // An attester outside the history = not checking material
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
    // member was removed at seq 3. An attestation to an in-tenure seq (2)
    // passes §6.6 verification in shape, but a non-current member's
    // attestation is not checking material even when distributed
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
    // A valid signature by member (a current member) attesting to a head
    // different from the own view's seq 2 = the split-view cross-
    // distribution shape
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
    // The evidence (attestation + own view's chain digest) lands in the
    // append-only file
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
    // The own view is at seq 2 and the attestation at seq 3 (we're just
    // stale). The resync returns all 3 entries + the same attestation set
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
    // Attests to seq 5, beyond the own head (3) — unreachable even after
    // resync
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
    // The same attestation appears both among the carried-over future
    // entries and in the resynced view's own attestation set, but the
    // evidence is deduplicated to a single record (two lines would read as
    // two members contradicting each other)
    expect(records).toHaveLength(1);
    expect(records[0]).toContain('"kind":"unresolved-after-resync"');
  });

  it("(b) mixing a same-key forged record with only the hash rewritten into the resync view does not disable carry-over checking", async () => {
    const env = await makeTestEnv();
    const built = await buildStandardChain();
    // Genuine: an attestation to seq 5 beyond the own head (3) — the shape
    // that stays unresolved after resync
    const genuineHash = "ab".repeat(32);
    const genuine = await attestationBy(owner, built.projectId, {
      seq: 5,
      hashHex: genuineHash,
    });
    // Forged: a record with identical attesterUserId / chainHeadSeq /
    // signatureHex and only chainHeadHashHex rewritten. Under partial-key
    // dedup the genuine carry-over (first.future) would be dropped on a key
    // clash, the forged side would be silently skipped by signature
    // verification, and second.future would come out empty = no interruption
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
    // The genuine attestation remains as unresolved-after-resync evidence
    // (the forged record fails signature verification and never becomes
    // checking material)
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
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: built.hashes[built.hashes.length - 1],
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
    // The head of a view that passed checking is still recorded on the floor
    // as before (floor advance happens after every check passes, but a
    // success must not drop its floor material)
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
    // The interrupted view's head is not recorded on the floor: recording it
    // before checking would put the rejected fork in the floor's permanent
    // record and make every later honest chain get rejected as a hash
    // mismatch (floor advance happens after all checks pass)
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
          projectId,
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
      onRequest("PUT", `/projects/${built.projectId}/head-attestation`, () => ({
        status: 204,
        bodyText: "",
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
    // A non-advancing re-run does not submit (last-attestation tracking —
    // attested.json)
    await submissionProgram(env, server.origin, view2, built.projectId);
    expect(puts()).toHaveLength(1);
    // Resubmits once the head advances
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
      onRequest("PUT", `/projects/${built.projectId}/head-attestation`, () => ({
        status: 204,
        bodyText: "",
      })),
    ]);
    const view3 = await verifiedViewOf(built, 3, []);
    await submissionProgram(env, server.origin, view3, built.projectId);
    expect(server.requests).toHaveLength(1);
    // Mimics being shown a different chain at the same seq with a different
    // hash (equivocation) under floor corruption / first-run fail-open: the
    // tracking's hash is rewritten to another value. The seq hasn't advanced
    // but the hash differs, so submission is not suppressed — preserves the
    // path by which other members detect the fork via this device's
    // attestation
    const { writeFile } = await import("node:fs/promises");
    await writeFile(
      join(env.floorDir, `${built.projectId}.attested.json`),
      `${JSON.stringify({ v: 1, head: { seq: 3, hashHex: "ef".repeat(32) } })}\n`,
    );
    await submissionProgram(env, server.origin, view3, built.projectId);
    expect(server.requests).toHaveLength(2);
  });

  it("a submission failure (old server = route missing) degrades to a one-line warning without failing the command", async () => {
    const env = await makeTestEnv();
    const built = await buildStandardChain();
    const server = await startServer([]); // all 404 (an old server without the attestation PUT)
    const view = await verifiedViewOf(built, 2, []);
    await submissionProgram(env, server.origin, view, built.projectId);
    expect(env.errors.some((line) => line.includes("could not submit the head attestation"))).toBe(
      true,
    );
    // The tracking does not advance since the submission didn't happen
    // (retry next time)
    await expect(
      readFile(join(env.floorDir, `${built.projectId}.attested.json`), "utf8"),
    ).rejects.toThrow();
  });

  it("warns on 409 (AttestationRegression) distinguished as a symptom of floor corruption / a concurrent CLI", async () => {
    const env = await makeTestEnv();
    const built = await buildStandardChain();
    const server = await startServer([
      onRequest("PUT", `/projects/${built.projectId}/head-attestation`, () => ({
        status: 409,
        json: { _tag: "AttestationRegression", storedSeq: 9 },
      })),
    ]);
    const view = await verifiedViewOf(built, 2, []);
    await submissionProgram(env, server.origin, view, built.projectId);
    expect(
      env.errors.some((line) => line.includes("rejected this head attestation as a regression")),
    ).toBe(true);
  });
});
