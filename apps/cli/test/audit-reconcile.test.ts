import type { AuditHeadRow, ChainOperation } from "@maruhi/crypto";
import { computeAuditHeadHash, computeAuditRowDigest, SUITE_ID } from "@maruhi/crypto";
import {
  buildChain,
  type BuiltChain,
  type GeneratedIdentity,
  generateIdentity,
  genesisOp,
} from "@maruhi/test-kit";
import type { ApiSuccess } from "@maruhi/test-kit/api";
import { afterEach, beforeAll, describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { servedChain } from "./support/chain-handler.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type EndpointAnswer, type MockHandler, MockServer, onEndpoint } from "./support/server.ts";

const BASE_TS = 1_756_000_000_000;

let owner: GeneratedIdentity;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await generateIdentity("user-owner-1111");
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

function idOf(seq: number): string {
  return seq.toString(16).padStart(32, "0");
}

function orderOf(row: Record<string, unknown>): number {
  return typeof row["seq"] === "number" ? row["seq"] : Number.parseInt(String(row["id"]), 16);
}

interface SeedRow {
  readonly seq: number;
  readonly event: string;
  readonly chainSeq?: number;
  readonly payload?: Readonly<Record<string, unknown>>;
}

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
  readonly served: readonly Record<string, unknown>[];
  readonly declaredHeadHex: string;
  readonly tokenScopes?: NonNullable<ApiSuccess<"auth.me">["tokenScopes"]>;
  readonly onAuditHead?: (call: number) => EndpointAnswer<"audit.auditHead"> | undefined;
}

interface ReconcileServerState {
  readonly handlers: readonly MockHandler[];
  readonly eventCalls: () => number;
  readonly auditHeadCalls: () => number;
}

function makeReconcileServer(input: ReconcileServerInput): ReconcileServerState {
  const projectId = input.built.projectId;
  let eventCalls = 0;
  let auditHeadCalls = 0;
  const handlers: MockHandler[] = [
    onEndpoint("membership.get", { projectId }, () => ({
      status: 200,
      json: servedChain(projectId, input.built.entries, input.built.hashes),
    })),
    onEndpoint("auth.me", () => ({
      status: 200,
      json: {
        userId: owner.userId,
        orgs: [],
        ...(input.tokenScopes === undefined ? {} : { tokenScopes: input.tokenScopes }),
      },
    })),
    onEndpoint("audit.auditHead", { projectId }, () => {
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

async function makeFixture(overrides?: {
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
    expect(env.errors.join("\n")).toContain("not covered until the next attested checkpoint");
  });

  it("the zero-notarization positive case does not print 'checks passed' and states it is vacuously true", async () => {
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
    expect(output).toContain("rows in the notarized prefix were altered or deleted");
  });

  it("position violation (c): consecutive notarizations of a non-advancing head = reported as acceptance-policy non-enforcement evidence", async () => {
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
