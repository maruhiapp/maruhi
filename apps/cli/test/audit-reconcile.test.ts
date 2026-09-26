// Integration tests for `maruhi audit reconcile` (AUDIT_SPEC §6 — admin audit
// cross-check).
//
// Properties pinned down:
//  1. Positive case: advancing 2 notarizations — membership (a), non-regression
//     (b), position floor (c), and the attested head's membership all hold —
//     exits 0
//  2. Membership violation (a) = reported as evidence of row tampering
//     (Row-tampering evidence)
//  3. Position violations (b)(c) = reported as evidence of a server not
//     enforcing the acceptance policy (Acceptance-policy violation — a state
//     where staleness replay is possible)
//  4. A missing seq = reported as a trace of deletion; stops before emitting
//     downstream derived false positives
//  5. The attested value from GET /audit-head is also checked for membership
//     in the recomputed sequence (session-38 ruling AK)
//  6. AuditHeadNotReady (503) is absorbed by bounded retries
//  7. Below effective admin (write scope) fails with a clear error before
//     fetching any rows
//
// The audit rows are the test's constructed "server claims"; the notarized
// heads are computed with the real computeAuditRowDigest /
// computeAuditHeadHash (the canonical implementation pinned by
// audit-head.json) — pins that the check's verdict depends on the real hash
// chain.

import type { AuditHeadRow, ChainEntry, ChainOperation } from "@maruhi/crypto";
import { computeAuditHeadHash, computeAuditRowDigest, SUITE_ID } from "@maruhi/crypto";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  buildChain,
  type BuiltChain,
  genesisOp,
  makeTestUser,
  type TestUser,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, type MockResponse, onRequest } from "./support/server.ts";

const BASE_TS = 1_756_000_000_000;

let owner: TestUser;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

/** Deterministic 32-digit hex row id (test-only — the real server assigns randomly). */
function idOf(seq: number): string {
  return seq.toString(16).padStart(32, "0");
}

/**
 * Internal key for the mock's ordering (even a negative that drops seq can be
 * recovered from the id — idOf is seq in hex).
 */
function orderOf(row: Record<string, unknown>): number {
  return typeof row["seq"] === "number" ? row["seq"] : Number.parseInt(String(row["id"]), 16);
}

/** An audit row the test constructs (shared material for the wire form and the computation-input form). */
interface SeedRow {
  readonly seq: number;
  readonly event: string;
  readonly chainSeq?: number;
  readonly payload?: Readonly<Record<string, unknown>>;
}

/** A wire audit row (admin-visible — carries seq). */
function wireRowOf(row: SeedRow): Record<string, unknown> {
  return {
    id: idOf(row.seq),
    seq: row.seq,
    serverTs: BASE_TS + row.seq,
    event: row.event,
    actor: { type: "user", userId: owner.userId },
    ...(row.chainSeq === undefined ? {} : { chainSeq: row.chainSeq }),
    ...(row.payload === undefined ? {} : { payload: row.payload }),
  };
}

/** The computation-input form (same mapping as the CLI's recomputation — the 17 columns of §5.1). */
function headRowOf(row: SeedRow): AuditHeadRow {
  return {
    seq: row.seq,
    rowId: idOf(row.seq),
    serverTs: BASE_TS + row.seq,
    clientTs: null,
    event: row.event,
    actorType: "user",
    actorUserId: owner.userId,
    actorKeyFingerprintHex: null,
    actorApiTokenId: null,
    targetUserId: null,
    targetKeyFingerprintHex: null,
    environmentId: null,
    variableId: null,
    epoch: null,
    version: null,
    chainSeq: row.chainSeq ?? null,
    payloadText: row.payload === undefined ? null : JSON.stringify(row.payload),
  };
}

/** Computes the cumulative hash sequence h_1..h_N with the canonical implementation (index 0 = h_1). */
async function headsOf(rows: readonly SeedRow[]): Promise<readonly string[]> {
  const heads: string[] = [];
  let head = "";
  for (const row of rows) {
    const digest = await computeAuditRowDigest(headRowOf(row));
    if (!digest.ok) {
      throw new Error(`digest failed at seq ${row.seq}`);
    }
    const next = await computeAuditHeadHash(SUITE_ID, head, row.seq, digest.value);
    if (!next.ok) {
      throw new Error(`head failed at seq ${row.seq}`);
    }
    head = next.value;
    heads.push(head);
  }
  return heads;
}

function checkpointOp(auditHeadHashHex: string): ChainOperation {
  return { op: "checkpoint", payload: { environments: [], auditHeadHashHex } };
}

interface ReconcileServerInput {
  readonly built: BuiltChain;
  /** Audit rows to distribute (wire form). Default = all of rows. */
  readonly served: readonly Record<string, unknown>[];
  readonly declaredHeadHex: string;
  readonly tokenScopes?: readonly unknown[];
  /** Per-call override for audit-head (undefined = return the attestation with 200). */
  readonly onAuditHead?: (call: number) => MockResponse | undefined;
}

interface ReconcileServerState {
  readonly handlers: readonly MockHandler[];
  readonly eventCalls: () => number;
  readonly auditHeadCalls: () => number;
}

/** Every endpoint reconcile needs (chain / auth/me / audit-head / audit/events). */
function makeReconcileServer(input: ReconcileServerInput): ReconcileServerState {
  const projectId = input.built.projectId;
  let eventCalls = 0;
  let auditHeadCalls = 0;
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
    onRequest("GET", "/auth/me", () => ({
      status: 200,
      json: {
        userId: owner.userId,
        orgs: [],
        ...(input.tokenScopes === undefined ? {} : { tokenScopes: input.tokenScopes }),
      },
    })),
    onRequest("GET", `/projects/${projectId}/audit-head`, () => {
      const injected = input.onAuditHead?.(auditHeadCalls);
      auditHeadCalls += 1;
      if (injected !== undefined) {
        return injected;
      }
      return { status: 200, json: { auditHeadHashHex: input.declaredHeadHex } };
    }),
    (request) => {
      if (request.method !== "GET" || request.path !== `/projects/${projectId}/audit/events`) {
        return null;
      }
      eventCalls += 1;
      const before = request.query["before"];
      const limit = Number(request.query["limit"] ?? "50");
      let cursorSeq = Number.POSITIVE_INFINITY;
      if (before !== undefined) {
        const cursor = input.served.find((row) => row["id"] === before);
        if (cursor === undefined) {
          return { status: 200, json: { events: [] } };
        }
        cursorSeq = orderOf(cursor);
      }
      const page = [...input.served]
        .filter((row) => orderOf(row) < cursorSeq)
        .toSorted((a, b) => orderOf(b) - orderOf(a))
        .slice(0, limit);
      return { status: 200, json: { events: page } };
    },
  ];
  return { handlers, eventCalls: () => eventCalls, auditHeadCalls: () => auditHeadCalls };
}

async function seededEnv(server: MockServer, projectId: string): Promise<TestEnv> {
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, { server: server.origin, defaultProject: projectId });
  return env;
}

/**
 * Standard fixture: chain = genesis (1) → checkpoint (2) → checkpoint (3).
 * Audit rows = mirror rows 1..3 + extra row 4 (㊙ payload — pushed through the
 * real computation including the non-ASCII round-trip). checkpoint 2 notarizes
 * h_1 (first — (c) is vacuously true), checkpoint 3 notarizes h_2 (floor =
 * checkpoint 2's mirror row seq2 ≥, (b) non-regression) = the positive case.
 * Each violation is built by overriding head*.
 */
async function makeFixture(overrides?: {
  /** Override for the notarized head (arg = recomputed sequence h_1..h_4 — for building violation cases). */
  readonly headAtChain2?: (heads: readonly string[]) => string;
  readonly headAtChain3?: (heads: readonly string[]) => string;
}): Promise<{ rows: readonly SeedRow[]; heads: readonly string[]; built: BuiltChain }> {
  const rows: readonly SeedRow[] = [
    { seq: 1, event: "chain.genesis", chainSeq: 1 },
    { seq: 2, event: "chain.checkpointed", chainSeq: 2 },
    { seq: 3, event: "chain.checkpointed", chainSeq: 3 },
    { seq: 4, event: "var.read", payload: { note: "㊙ / まる ひ", nested: { list: [1, 2] } } }, // english-exempt: non-ASCII payload fixture exercising the round-trip
  ];
  const heads = await headsOf(rows);
  const built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: checkpointOp(overrides?.headAtChain2?.(heads) ?? heads[0]!) },
    { actor: owner, operation: checkpointOp(overrides?.headAtChain3?.(heads) ?? heads[1]!) },
  ]);
  return { rows, heads, built };
}

describe("maruhi audit reconcile (AUDIT_SPEC §6 admin cross-check)", () => {
  it("positive case: advancing 2 notarizations — membership (a), position (b)(c), attestation membership all hold and exit 0", async () => {
    const { rows, heads, built } = await makeFixture();
    const state = makeReconcileServer({
      built,
      served: rows.map(wireRowOf),
      declaredHeadHex: heads[3]!,
      tokenScopes: [{ project: built.projectId, permission: "admin" }],
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId);

    expect(await runCli(["audit", "reconcile"], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).toContain("Audit reconciliation OK");
    expect(output).toContain("4 audit rows recomputed, 2 notarized checkpoints checked");
    // §6's explicit residual (outside the notarized prefix is unprotected) is
    // noted in one line on success (Note — stderr; stdout carries only the
    // command's output)
    expect(env.errors.join("\n")).toContain("not covered until the next attested checkpoint");
  });

  it("the zero-notarization positive case does not print 'checks passed' and states it is vacuously true", async () => {
    // Chain = genesis only (no notarized checkpoints). Audit rows = its single
    // mirror row
    const rows: readonly SeedRow[] = [{ seq: 1, event: "chain.genesis", chainSeq: 1 }];
    const heads = await headsOf(rows);
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const state = makeReconcileServer({
      built,
      served: rows.map(wireRowOf),
      declaredHeadHex: heads[0]!,
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId);

    expect(await runCli(["audit", "reconcile"], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    // What was verified is only no missing seqs + attestation membership —
    // not claimed: (a)(b)(c) passing
    expect(output).toContain("Audit reconciliation OK (nothing notarized yet)");
    expect(output).toContain("vacuous until an effective admin issues");
    expect(output).not.toContain("checks passed");
  });

  it("membership violation (a): a notarized head absent from the recomputed sequence = reported as row-tampering evidence", async () => {
    const { rows, heads, built } = await makeFixture({ headAtChain3: () => "ab".repeat(32) });
    const state = makeReconcileServer({
      built,
      served: rows.map(wireRowOf),
      declaredHeadHex: heads[3]!,
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId);

    expect(await runCli(["audit", "reconcile"], env.layer)).toBe(1);
    const output = env.errors.join("\n");
    expect(output).toContain("[Row-tampering evidence]");
    expect(output).toContain(
      "checkpoint at chain seq 3 notarizes an audit head that does not appear",
    );
    expect(output).toContain("membership check (a)");
    // The two-category summary wording (§6): a membership violation = rows
    // altered or deleted after notarization
    expect(output).toContain("rows in the notarized prefix were altered or deleted");
  });

  it("position violation (c): consecutive notarizations of a non-advancing head = reported as acceptance-policy non-enforcement evidence", async () => {
    // checkpoint 3 notarizes the same h_1 as checkpoint 2 (serving an existing
    // old head forever). (b) passes since it admits equality; (c)'s position
    // floor (the immediately preceding checkpoint's mirror row seq2) drops it
    // — the same predicate as the acceptance check
    const { rows, heads, built } = await makeFixture({ headAtChain3: (h) => h[0]! });
    const state = makeReconcileServer({
      built,
      served: rows.map(wireRowOf),
      declaredHeadHex: heads[3]!,
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId);

    expect(await runCli(["audit", "reconcile"], env.layer)).toBe(1);
    const output = env.errors.join("\n");
    expect(output).toContain("[Acceptance-policy violation (stale-replay risk)]");
    expect(output).toContain("position-floor check (c)");
    expect(output).toContain("the server accepted attestations it must reject");
    // Not a membership violation (h_1 exists) — the categories aren't
    // conflated
    expect(output).not.toContain("[Row-tampering evidence]");
  });

  it("position violation (b): a regression in the notarized position is also reported as acceptance-policy non-enforcement", async () => {
    const { rows, heads, built } = await makeFixture({
      headAtChain2: (h) => h[2]!,
      headAtChain3: (h) => h[0]!,
    });
    const state = makeReconcileServer({
      built,
      served: rows.map(wireRowOf),
      declaredHeadHex: heads[3]!,
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId);

    expect(await runCli(["audit", "reconcile"], env.layer)).toBe(1);
    const output = env.errors.join("\n");
    expect(output).toContain("non-regression check (b)");
    expect(output).toContain("[Acceptance-policy violation (stale-replay risk)]");
  });

  it("a missing seq = reported as a trace of deletion and stops before derived false positives", async () => {
    const { rows, heads, built } = await makeFixture();
    const state = makeReconcileServer({
      built,
      // Drop seq 3 (checkpoint 3's mirror row) = trace of deletion
      served: rows.filter((row) => row.seq !== 3).map(wireRowOf),
      declaredHeadHex: heads[3]!,
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId);

    expect(await runCli(["audit", "reconcile"], env.layer)).toBe(1);
    const output = env.errors.join("\n");
    expect(output).toContain("audit seq 3 is missing");
    expect(output).toContain("trace of deleted rows");
    // The chain past the gap disagrees entirely, so it never reaches the
    // membership check (doesn't mass-produce false attributions)
    expect(output).not.toContain("membership check (a)");
  });

  it("also checks the GET /audit-head attested value for membership in the recomputed sequence (session-38 ruling AK)", async () => {
    const { rows, built } = await makeFixture();
    const state = makeReconcileServer({
      built,
      served: rows.map(wireRowOf),
      declaredHeadHex: "12".repeat(32),
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId);

    expect(await runCli(["audit", "reconcile"], env.layer)).toBe(1);
    const output = env.errors.join("\n");
    expect(output).toContain("declared by GET /audit-head does not appear");
    expect(output).toContain("[Row-tampering evidence]");
  });

  it("absorbs AuditHeadNotReady (503) with bounded retries", async () => {
    const { rows, heads, built } = await makeFixture();
    const state = makeReconcileServer({
      built,
      served: rows.map(wireRowOf),
      declaredHeadHex: heads[3]!,
      onAuditHead: (call) =>
        call === 0 ? { status: 503, json: { _tag: "AuditHeadNotReady" } } : undefined,
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId);

    expect(await runCli(["audit", "reconcile"], env.layer)).toBe(0);
    expect(state.auditHeadCalls()).toBe(2);
    expect(env.logs.join("\n")).toContain("Audit reconciliation OK");
  });

  it("below effective admin (write scope) is a clear error before any row fetch", async () => {
    const { rows, heads, built } = await makeFixture();
    const state = makeReconcileServer({
      built,
      served: rows.map(wireRowOf),
      declaredHeadHex: heads[3]!,
      tokenScopes: [{ project: built.projectId, permission: "write" }],
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId);

    expect(await runCli(["audit", "reconcile"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("requires effective admin permission");
    // Never starts the cross-check (zero row fetches and zero attestation
    // fetches)
    expect(state.eventCalls()).toBe(0);
    expect(state.auditHeadCalls()).toBe(0);
  });

  it("a row without seq (a non-admin-view response) aborts as a self-contradiction", async () => {
    const { rows, heads, built } = await makeFixture();
    const noSeq = rows.map(wireRowOf).map((row) => {
      const { seq: _seq, ...rest } = row;
      return rest;
    });
    const state = makeReconcileServer({ built, served: noSeq, declaredHeadHex: heads[3]! });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId);

    expect(await runCli(["audit", "reconcile"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("carries no seq");
  });
});
