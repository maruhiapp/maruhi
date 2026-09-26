// Integration tests for `maruhi audit` (AUDIT_SPEC §6 / §7 — Phase 2 C1).
//
// Properties pinned down:
//  1. list displays audit rows, and a variable's display name resolves only
//     from verified statements. The payload's name snapshot (a server claim)
//     is shown distinctly as the "record" and never promoted to the display
//     name position (TCB discipline — AUDIT_SPEC §7)
//  2. chain.* mirror rows are cross-checked against the verified chain (the
//     shared mapping chainMirrorEvent): a match is mirror=OK, a mismatch is a
//     warning + exit code 1. A row outside chain.* claiming a chain_seq is
//     likewise shown with a label and counts as an integrity violation
//     (evidence of tampering — §6)
//  3. verify checks the mirror bijection (§1-5): omission (concealed
//     deletion), alteration, and duplication are each detected with exit
//     code 1
//  4. invites / self display the D1-side rows; self annotates the implication
//     of watch-worthy events (auth.recovery_blob_fetched — §3.1)
//  5. Argument-shape errors (--project on self, out-of-range limit, unknown
//     operation) are usage errors (2) before any communication

import type { ProposalIndex } from "@maruhi/core";
import { chainMirrorEvents, indexProposals } from "@maruhi/core";
import type { ChainEntry, ChainOperation, ProposableOperation } from "@maruhi/crypto";
import { verifyChainWithHistory } from "@maruhi/crypto";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  addMemberOp,
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  manifestFor,
  statementFor,
  type TestUser,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "env-audit-1";
const BASE_TS = 1_755_000_000_000;

let owner: TestUser;
let member: TestUser;
let dek1: Uint8Array;

const servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  member = await makeTestUser("user-member-2222");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

/** Base chain (genesis → environment creation → member add; no pending obligations). */
async function baseChain(): Promise<BuiltChain> {
  return buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: addMemberOp(member, "member") },
  ]);
}

type WireRow = Record<string, unknown>;

/** Deterministic 32-digit hex row id (test-only — the real server assigns randomly). */
function idOf(seq: number): string {
  return seq.toString(16).padStart(32, "0");
}

/** Assigns entries while dropping undefined ones (same shape as the wire's optionalKey). */
function assignPresent(target: Record<string, unknown>, source: Record<string, unknown>): void {
  for (const [key, value] of Object.entries(source)) {
    if (value !== undefined) {
      target[key] = value;
    }
  }
}

/** Proposal index of the verified chain (the same core derivation as the server's — input to the four-eyes rows). */
async function proposalIndexOf(built: BuiltChain): Promise<ProposalIndex> {
  const verified = await verifyChainWithHistory(built.entries);
  if (!verified.ok) {
    throw new Error(`fixture chain does not verify: ${JSON.stringify(verified.error)}`);
  }
  return indexProposals(
    built.entries,
    (seq) => built.hashes[seq - 1],
    new Set(verified.value.state.pendingProposals.keys()),
  );
}

/** Verified entry → wire mirror rows (built from the same shared mapping as the server's). */
function wireMirrorRows(entry: ChainEntry, firstSeq: number, index: ProposalIndex): WireRow[] {
  return chainMirrorEvents(entry, BASE_TS + firstSeq, index).map((record, offset) => {
    const seq = firstSeq + offset;
    const actor: Record<string, unknown> = { type: record.actorType };
    assignPresent(actor, {
      userId: record.actorUserId,
      keyFingerprintHex: record.actorKeyFingerprintHex,
    });
    const row: WireRow = {
      id: idOf(seq),
      seq,
      serverTs: record.serverTs,
      event: record.event,
      actor,
    };
    assignPresent(row, {
      clientTs: record.clientTs,
      targetUserId: record.targetUserId,
      targetKeyFingerprintHex: record.targetKeyFingerprintHex,
      environmentId: record.environmentId,
      epoch: record.epoch,
      chainSeq: record.chainSeq,
      payload: record.payload,
    });
    return row;
  });
}

/**
 * Mirror rows for every chain entry (audit seq runs from 1; a completed
 * approve produces 2 rows — AUDIT_SPEC §3.4 — so on a chain containing
 * four-eyes, audit seq ≠ chain seq).
 */
async function mirrorRowsOf(built: BuiltChain): Promise<WireRow[]> {
  const index = await proposalIndexOf(built);
  const rows: WireRow[] = [];
  for (const entry of built.entries) {
    rows.push(...wireMirrorRows(entry, rows.length + 1, index));
  }
  return rows;
}

/**
 * Mock of the audit-events endpoint: applies event / eventPrefix / before /
 * limit with the server's semantics (seq-descending, row-id cursor
 * resolution, unknown id → empty page). eventPrefix is a prefix match
 * (AUDIT_SPEC §7).
 */
function auditEventsHandler(projectId: string, rows: () => readonly WireRow[]): MockHandler {
  return (request) => {
    if (request.method !== "GET" || request.path !== `/projects/${projectId}/audit/events`) {
      return null;
    }
    const eventFilter = request.query["event"];
    const prefixFilter = request.query["eventPrefix"];
    const chainSeqPresent = request.query["chainSeqPresent"];
    const before = request.query["before"];
    const limit = Number(request.query["limit"] ?? "50");
    let cursorSeq = Number.POSITIVE_INFINITY;
    if (before !== undefined) {
      const cursor = rows().find((row) => row["id"] === before);
      if (cursor === undefined) {
        return { status: 200, json: { events: [] } };
      }
      cursorSeq = cursor["seq"] as number;
    }
    const filtered = rows()
      .filter((row) => (eventFilter === undefined ? true : row["event"] === eventFilter))
      .filter((row) =>
        prefixFilter === undefined ? true : String(row["event"]).startsWith(prefixFilter),
      )
      .filter((row) => (chainSeqPresent === undefined ? true : row["chainSeq"] !== undefined))
      .filter((row) => (row["seq"] as number) < cursorSeq)
      .toSorted((a, b) => (b["seq"] as number) - (a["seq"] as number))
      .slice(0, limit);
    return { status: 200, json: { events: filtered } };
  };
}

interface AuditServerInput {
  readonly built: BuiltChain;
  readonly rows: readonly WireRow[];
  /** Whether the metadata pull succeeds (false = 404 — the degradation path for name resolution). */
  readonly metadataAvailable?: boolean;
}

async function makeAuditServer(input: AuditServerInput): Promise<readonly MockHandler[]> {
  const projectId = input.built.projectId;
  const envStatement = await environmentStatementFor({
    projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head: headOf(input.built, 2),
  });
  const activeStatement = await statementFor({
    projectId,
    environmentId: ENV_ID,
    variableId: "va",
    name: "ALPHA",
    author: owner,
    head: headOf(input.built, 2),
  });
  const manifest = await manifestFor({
    projectId,
    environmentId: ENV_ID,
    epoch: 1,
    issuer: owner,
    head: headOf(input.built, input.built.entries.length),
    envStatement,
    statements: [activeStatement],
  });
  return [
    onRequest("GET", `/projects/${projectId}/chain`, () => ({
      status: 200,
      json: {
        projectId,
        entries: input.built.entries as readonly ChainEntry[],
        headSeq: input.built.entries.length,
        headHashHex: input.built.hashes[input.built.hashes.length - 1],
      },
    })),
    onRequest("GET", `/projects/${projectId}/environments/${ENV_ID}/pull/metadata`, () =>
      input.metadataAvailable === false
        ? { status: 404, json: { _tag: "EnvironmentNotFound", environmentId: ENV_ID } }
        : {
            status: 200,
            json: {
              environmentId: ENV_ID,
              currentEpoch: 1,
              statement: envStatement,
              variables: [activeStatement],
              deletedVariables: [],
              manifest,
            },
          },
    ),
    auditEventsHandler(projectId, () => input.rows),
  ];
}

async function startEnv(handlers: readonly MockHandler[], projectId?: string): Promise<TestEnv> {
  const server = await MockServer.start([...handlers]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, {
    server: server.origin,
    ...(projectId === undefined ? {} : { defaultProject: projectId }),
  });
  return env;
}

/** A var.version_pushed row (for checking name resolution and payload display). */
function pushRow(seq: number, payload?: Record<string, unknown>): WireRow {
  return {
    id: idOf(seq),
    seq,
    serverTs: BASE_TS + seq,
    event: "var.version_pushed",
    actor: { type: "user", userId: member.userId },
    environmentId: ENV_ID,
    variableId: "va",
    epoch: 1,
    version: 2,
    ...(payload === undefined ? {} : { payload }),
  };
}

/** An aggregated var.read row (AUDIT_SPEC §3.3 — one row per environment per valued pull). */
function aggregatedReadRow(seq: number, extraPayload: Record<string, unknown> = {}): WireRow {
  return {
    id: idOf(seq),
    seq,
    serverTs: BASE_TS + seq,
    event: "var.read",
    actor: { type: "user", userId: member.userId, apiTokenId: "tok-1" },
    environmentId: ENV_ID,
    payload: {
      variables: [
        { variableId: "va", epoch: 1, version: 2 },
        { variableId: "vb", epoch: 1, version: 1 },
      ],
      ...extraPayload,
    },
  };
}

describe("maruhi audit (list)", () => {
  it("an aggregated var.read shows a count summary; --expand-reads expands it to one line per variable", async () => {
    const built = await baseChain();
    // seq=5 carries a payload (authMethod) other than the variable list
    const rows = [
      ...(await mirrorRowsOf(built)),
      aggregatedReadRow(4),
      aggregatedReadRow(5, { authMethod: "github_oauth" }),
    ];
    const env = await startEnv(await makeAuditServer({ built, rows }), built.projectId);

    expect(await runCli(["audit"], env.layer)).toBe(0);
    const summary = env.logs.join("\n");
    const readLine = env.logs.find((line) => line.startsWith("seq=4\t"));
    expect(readLine).toContain("read=2 variables");
    // The listing (payload) is neither folded into the single line as
    // recorded= nor expanded
    expect(readLine).not.toContain("recorded=");
    // A payload other than the listing still shows under recorded=
    // (listing excluded)
    const withMethod = env.logs.find((line) => line.startsWith("seq=5\t"));
    expect(withMethod).toContain('recorded={"authMethod":"github_oauth"}');
    expect(withMethod).not.toContain('"variables"');
    expect(summary).not.toContain("var=ALPHA");
    // The aggregated-form guidance is a Note (stderr) — not mixed into the
    // list (stdout)
    expect(env.errors.join("\n")).toContain("--expand-reads");

    const expanded = await makeTestEnv();
    seedSession(expanded, servers[servers.length - 1]?.origin ?? "", owner);
    await seedConfig(expanded, {
      server: servers[servers.length - 1]?.origin ?? "",
      defaultProject: built.projectId,
    });
    expect(await runCli(["audit", "--expand-reads"], expanded.layer)).toBe(0);
    const logs = expanded.logs.join("\n");
    expect(logs).toContain("read=2 variables");
    // Expansion lines: display names come from verified statements (va =
    // ALPHA); an absent variable shows only its id
    expect(logs).toContain("- var=ALPHA (va)\tepoch=1\tversion=2");
    expect(logs).toContain("- var=vb\tepoch=1\tversion=1");
    expect(expanded.errors.join("\n")).not.toContain("--expand-reads");

    // With --var, the matching variable's entries are attached inline (no
    // expansion)
    const filtered = await makeTestEnv();
    seedSession(filtered, servers[servers.length - 1]?.origin ?? "", owner);
    await seedConfig(filtered, {
      server: servers[servers.length - 1]?.origin ?? "",
      defaultProject: built.projectId,
    });
    expect(await runCli(["audit", "--var", "va"], filtered.layer)).toBe(0);
    const matchedLine = filtered.logs.find((line) => line.startsWith("seq=4\t"));
    expect(matchedLine).toContain("read=2 variables\tmatched=var=ALPHA (va)\tepoch=1\tversion=2");
    expect(filtered.logs.join("\n")).not.toContain("- var=vb");
  });

  it("displays rows, resolves names from verified statements, and cross-checks mirror rows OK", async () => {
    const built = await baseChain();
    // The payload's name snapshot is a server claim — never promoted to the
    // display-name position
    const rows = [...(await mirrorRowsOf(built)), pushRow(4, { name: "EVIL_NAME" })];
    const env = await startEnv(await makeAuditServer({ built, rows }), built.projectId);

    expect(await runCli(["audit"], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    // Newest first (seq descending)
    const positions = [4, 3, 2, 1].map((seq) => logs.indexOf(`seq=${seq}\t`));
    expect(positions.every((index) => index >= 0)).toBe(true);
    expect(positions).toEqual([...positions].toSorted((a, b) => a - b));
    // Mirror cross-check (rows matching the shared mapping are OK)
    expect(logs).toContain("chain.genesis");
    expect(logs).toContain("chain.member_added");
    expect(logs).toContain("mirror=OK");
    // Display names come only from verified statements. The payload's
    // snapshot appears only inside "recorded="
    expect(logs).toContain("var=ALPHA (va)");
    expect(logs).not.toContain("var=EVIL_NAME");
    expect(logs).toContain("EVIL_NAME");
    expect(env.errors.join("\n")).not.toContain("does not match the verified chain");
  });

  it("an environment whose metadata cannot be fetched degrades to identifier display (the list is not stopped)", async () => {
    const built = await baseChain();
    const rows = [...(await mirrorRowsOf(built)), pushRow(4)];
    const env = await startEnv(
      await makeAuditServer({ built, rows, metadataAvailable: false }),
      built.projectId,
    );
    expect(await runCli(["audit"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("var=va");
    expect(env.logs.join("\n")).not.toContain("ALPHA");
    expect(env.errors.join("\n")).toContain("could not fetch verified metadata");
  });

  it("a tampered mirror row (actor swapped) is a warning + exit code 1", async () => {
    const built = await baseChain();
    const rows = await mirrorRowsOf(built);
    const tampered = rows[2];
    if (tampered === undefined) {
      throw new Error("fixture is missing the add_member mirror row");
    }
    rows[2] = { ...tampered, actor: { type: "user", userId: "user-evil-9999" } };
    const env = await startEnv(await makeAuditServer({ built, rows }), built.projectId);
    expect(await runCli(["audit"], env.layer)).toBe(1);
    expect(env.logs.join("\n")).toContain("mirror=mismatch");
    const errors = env.errors.join("\n");
    expect(errors).toContain("does not match the verified chain");
    expect(errors).toContain("actor.user_id");
  });

  it("a row outside chain.* claiming a chain_seq gets an explicit distrust label + exit code 1", async () => {
    const built = await baseChain();
    const forged = {
      ...pushRow(4),
      event: "member.add",
      chainSeq: 2,
    };
    const env = await startEnv(
      await makeAuditServer({ built, rows: [...(await mirrorRowsOf(built)), forged] }),
      built.projectId,
    );

    expect(await runCli(["audit"], env.layer)).toBe(1);
    const logs = env.logs.join("\n");
    expect(logs).toContain("member.add");
    expect(logs).toContain("chain_seq=2");
    expect(logs).toContain(
      "mirror=unverified (chain_seq is invalid outside the chain.* namespace)",
    );
    const errors = env.errors.join("\n");
    expect(errors).toContain("only chain.* mirror rows may carry chain provenance");
  });

  it("passes --event and --before / --limit through to the query unchanged", async () => {
    const built = await baseChain();
    // Plant a row at seq=9 and request earlier rows (seq < 9) via the row-id
    // cursor
    const rows = [...(await mirrorRowsOf(built)), pushRow(4), pushRow(9)];
    const handlers = await makeAuditServer({ built, rows });
    const server = await MockServer.start([...handlers]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(
      await runCli(
        ["audit", "--event", "var.version_pushed", "--limit", "10", "--before", idOf(9)],
        env.layer,
      ),
    ).toBe(0);
    const audit = server.requests.find((request) => request.path.endsWith("/audit/events"));
    expect(audit?.query).toMatchObject({
      event: "var.version_pushed",
      limit: "10",
      before: idOf(9),
    });
    const logs = env.logs.join("\n");
    // The cursor row itself (seq=9) is excluded; only the seq=4 row returns
    expect(logs).toContain("seq=4\t");
    expect(logs).not.toContain("seq=9\t");
    expect(logs).toContain("var.version_pushed");
    expect(logs).not.toContain("chain.genesis");
  });
});

describe("maruhi audit verify (mirror bijection check — §1-5 / §6)", () => {
  it("bijection + all-fields match is OK (exit code 0)", async () => {
    const built = await baseChain();
    const env = await startEnv(
      await makeAuditServer({ built, rows: await mirrorRowsOf(built) }),
      built.projectId,
    );
    expect(await runCli(["audit", "verify"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("Mirror bijection verification OK");
  });

  it("detects an omitted mirror row (concealed deletion)", async () => {
    const built = await baseChain();
    // Drop the mirror of seq=3 (add_member) — an omission invisible in
    // principle to per-row cross-checking
    const rows = (await mirrorRowsOf(built)).filter((row) => row["seq"] !== 3);
    const env = await startEnv(await makeAuditServer({ built, rows }), built.projectId);
    expect(await runCli(["audit", "verify"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("no corresponding chain.member_added mirror row");
    expect(errors).toContain("chain_seq=3");
  });

  it("detects an altered mirror row (key FP swapped)", async () => {
    const built = await baseChain();
    const rows = await mirrorRowsOf(built);
    const genesis = rows[0];
    if (genesis === undefined) {
      throw new Error("fixture is missing the genesis mirror row");
    }
    rows[0] = {
      ...genesis,
      actor: {
        ...(genesis["actor"] as Record<string, unknown>),
        keyFingerprintHex: "ab".repeat(16),
      },
    };
    const env = await startEnv(await makeAuditServer({ built, rows }), built.projectId);
    expect(await runCli(["audit", "verify"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("actor.key_fingerprint");
  });

  it("detects duplicate mirror rows for the same chain_seq", async () => {
    const built = await baseChain();
    const rows = await mirrorRowsOf(built);
    const duplicated = rows[2];
    if (duplicated === undefined) {
      throw new Error("fixture is missing the add_member mirror row");
    }
    rows.push({ ...duplicated, id: idOf(9), seq: 9 });
    const env = await startEnv(await makeAuditServer({ built, rows }), built.projectId);
    expect(await runCli(["audit", "verify"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("duplicates");
  });

  it("detects a forged token-attribution display (actor.api_token_id added)", async () => {
    const built = await baseChain();
    const rows = await mirrorRowsOf(built);
    const tampered = rows[2];
    if (tampered === undefined) {
      throw new Error("fixture is missing the add_member mirror row");
    }
    rows[2] = {
      ...tampered,
      actor: { ...(tampered["actor"] as Record<string, unknown>), apiTokenId: "tok-evil" },
    };
    const env = await startEnv(await makeAuditServer({ built, rows }), built.projectId);
    expect(await runCli(["audit", "verify"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("actor.api_token_id");
  });

  it("detects as a continuity violation a forged row claiming an unreachable chain_seq (blocks a permanent slip-through)", async () => {
    const built = await baseChain();
    const rows = await mirrorRowsOf(built);
    const template = rows[2];
    if (template === undefined) {
      throw new Error("fixture is missing the add_member mirror row");
    }
    // A forged row claiming a point far beyond head (3) — must not be
    // counted as "unverified" and reported OK
    rows.push({ ...template, id: idOf(50), seq: 50, chainSeq: 50000 });
    const env = await startEnv(await makeAuditServer({ built, rows }), built.projectId);
    expect(await runCli(["audit", "verify"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("not contiguous");
    expect(env.logs.join("\n")).not.toContain("Mirror bijection verification OK");
  });

  it("detects a forged row claiming a chain.* name absent from the mapping", async () => {
    const built = await baseChain();
    const rows = await mirrorRowsOf(built);
    const template = rows[2];
    if (template === undefined) {
      throw new Error("fixture is missing the add_member mirror row");
    }
    // Fetching by exact match of known mirror names would never retrieve
    // this row (no omission, no duplication) and it would look OK — fetch by
    // prefix match and drop it as an unknown op
    rows.push({ ...template, id: idOf(9), seq: 9, event: "chain.role_granted" });
    const env = await startEnv(await makeAuditServer({ built, rows }), built.projectId);
    expect(await runCli(["audit", "verify"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("unknown chain op");
    expect(errors).toContain("chain.role_granted");
    expect(env.logs.join("\n")).not.toContain("Mirror bijection verification OK");
  });

  it("a forged row outside chain.* claiming a chain_seq is also fetched via the presence filter and detected", async () => {
    const built = await baseChain();
    const rows = await mirrorRowsOf(built);
    const forged = {
      ...pushRow(9),
      event: "chainx.grant",
      chainSeq: 2,
    };
    const handlers = await makeAuditServer({ built, rows: [...rows, forged] });
    const server = await MockServer.start([...handlers]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["audit", "verify"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("outside the chain.* namespace");
    expect(errors).toContain("chainx.grant");
    expect(env.logs.join("\n")).not.toContain("Mirror bijection verification OK");
    expect(
      server.requests.some(
        (request) =>
          request.path.endsWith("/audit/events") && request.query["chainSeqPresent"] === "true",
      ),
    ).toBe(true);
  });

  it("new rows continuing right after head are not condemned as forged, but not called OK either (exit 1 + re-run guidance)", async () => {
    const built = await baseChain();
    const rows = await mirrorRowsOf(built);
    const template = rows[2];
    if (template === undefined) {
      throw new Error("fixture is missing the add_member mirror row");
    }
    // The shape where the chain grew one entry right after syncing
    // (chain_seq = head + 1)
    rows.push({ ...template, id: idOf(4), seq: 4, chainSeq: 4 });
    const env = await startEnv(await makeAuditServer({ built, rows }), built.projectId);
    expect(await runCli(["audit", "verify"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Mirror verification incomplete");
    expect(errors).not.toContain("not contiguous");
    expect(env.logs.join("\n")).not.toContain("Mirror bijection verification OK");
  });
});

const removeMemberOp = (target: TestUser): ProposableOperation => ({
  op: "remove_member",
  payload: { targetUserId: target.userId },
});
const policyOp = (requiredApprovals: number): ChainOperation => ({
  op: "set_approval_policy",
  payload: { ops: ["remove_member"], requiredApprovals },
});
const proposeOp = (inner: ProposableOperation): ChainOperation => ({
  op: "propose",
  payload: { inner, expiresAtMs: BASE_TS * 2 },
});
const approveOp = (proposalHashHex: string): ChainOperation => ({
  op: "approve",
  payload: { proposalHashHex },
});

describe("maruhi audit verify — four-eyes application rows (AUDIT_SPEC §3.4 — K5)", () => {
  /**
   * A chain where, under a policy (required), an owner proposes removing a
   * member and an approver stacks an approve. With required = 2 the second
   * owner's single vote completes it; with required = 3 it stays pending (an
   * uncompleted approve). The propose hash is referenced after building once
   * (signing is deterministic, so the same prefix yields the same hash).
   */
  async function fourEyesChain(requiredApprovals: 2 | 3): Promise<BuiltChain> {
    const owner2 = await makeTestUser("user-owner-3333");
    const owner3 = await makeTestUser("user-owner-4444");
    const prefix = [
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(member, "member") },
      { actor: owner, operation: addMemberOp(owner2, "owner") },
      { actor: owner, operation: addMemberOp(owner3, "owner") },
      { actor: owner, operation: policyOp(requiredApprovals) },
      { actor: owner, operation: proposeOp(removeMemberOp(member)) },
    ];
    const proposed = await buildChain(prefix);
    const proposalHash = proposed.hashes[proposed.hashes.length - 1];
    if (proposalHash === undefined) {
      throw new Error("fixture chain has no propose hash");
    }
    return buildChain([...prefix, { actor: owner2, operation: approveOp(proposalHash) }]);
  }

  it("bijection OK including the completed approve's 2 rows (chain.approved + application row)", async () => {
    const built = await fourEyesChain(2);
    const rows = await mirrorRowsOf(built);
    // 8 entries ↔ 9 rows (the seq-8 approve yields chain.approved +
    // chain.member_removed)
    expect(rows).toHaveLength(built.entries.length + 1);
    expect(rows.filter((row) => row["chainSeq"] === 8).map((row) => row["event"])).toEqual([
      "chain.approved",
      "chain.member_removed",
    ]);
    const env = await startEnv(await makeAuditServer({ built, rows }), built.projectId);
    expect(await runCli(["audit", "verify"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("Mirror bijection verification OK");
  });

  it("detects an omitted application row", async () => {
    const built = await fourEyesChain(2);
    const rows = (await mirrorRowsOf(built)).filter(
      (row) => row["event"] !== "chain.member_removed",
    );
    const env = await startEnv(await makeAuditServer({ built, rows }), built.projectId);
    expect(await runCli(["audit", "verify"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("chain_seq=8");
    expect(errors).toContain("no corresponding chain.member_removed mirror row");
  });

  it("detects altered viaProposalSeq / actor on the application row and a faked completed", async () => {
    const built = await fourEyesChain(2);
    const rows = await mirrorRowsOf(built);
    const applied = rows.findIndex((row) => row["event"] === "chain.member_removed");
    const approved = rows.findIndex((row) => row["event"] === "chain.approved");
    const appliedRow = rows[applied];
    const approvedRow = rows[approved];
    if (appliedRow === undefined || approvedRow === undefined) {
      throw new Error("fixture is missing the four-eyes rows");
    }
    rows[applied] = { ...appliedRow, payload: { viaProposalSeq: 6 } };
    rows[approved] = { ...approvedRow, payload: { proposalChainSeq: 7, completed: false } };
    const env = await startEnv(await makeAuditServer({ built, rows }), built.projectId);
    expect(await runCli(["audit", "verify"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("payload: expected");
    expect(errors).toContain('"viaProposalSeq":7');
    expect(errors).toContain('"completed":true');
  });

  it("detects an application row attached to an uncompleted approve as an extra row", async () => {
    const built = await fourEyesChain(3);
    const rows = await mirrorRowsOf(built);
    // 1 vote under required = 3: only chain.approved (completed = false) is
    // correct
    expect(rows).toHaveLength(built.entries.length);
    const approved = rows.find((row) => row["event"] === "chain.approved");
    if (approved === undefined) {
      throw new Error("fixture is missing the approve row");
    }
    expect(approved["payload"]).toEqual({ proposalChainSeq: 7, completed: false });
    rows.push({
      ...approved,
      id: idOf(99),
      seq: 99,
      event: "chain.member_removed",
      targetUserId: member.userId,
      payload: { viaProposalSeq: 7 },
    });
    const env = await startEnv(await makeAuditServer({ built, rows }), built.projectId);
    expect(await runCli(["audit", "verify"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("unexpected mirror row");
    expect(errors).toContain("chain.member_removed");
  });

  it("list displays both rows of the same chain_seq as cross-check OK", async () => {
    const built = await fourEyesChain(2);
    const env = await startEnv(
      await makeAuditServer({ built, rows: await mirrorRowsOf(built) }),
      built.projectId,
    );
    expect(await runCli(["audit", "list"], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain("chain.approved");
    expect(logs).toContain("chain.member_removed");
    expect(logs).not.toContain("mirror=mismatch");
    expect(env.errors.join("\n")).not.toContain("chain provenance claim");
  });
});

describe("maruhi audit verify — continuity of rows beyond head (a chain_seq caps at 2 rows)", () => {
  it("detects a chain_seq beyond head claiming 3+ rows as forged", async () => {
    const built = await baseChain();
    const rows = await mirrorRowsOf(built);
    const template = rows[2];
    if (template === undefined) {
      throw new Error("fixture is missing the add_member mirror row");
    }
    // 3 rows at chain_seq = head + 1 (even a completed approve caps at 2
    // rows — AUDIT_SPEC §3.4)
    for (const seq of [4, 5, 6]) {
      rows.push({ ...template, id: idOf(seq), seq, chainSeq: 4 });
    }
    const env = await startEnv(await makeAuditServer({ built, rows }), built.projectId);
    expect(await runCli(["audit", "verify"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("no chain entry has more than 2 mirror rows");
    expect(errors).toContain("chain_seq=4");
    expect(env.logs.join("\n")).not.toContain("Mirror bijection verification OK");
  });

  it("2 rows beyond head (the completed-approve shape) are not a continuity violation", async () => {
    const built = await baseChain();
    const rows = await mirrorRowsOf(built);
    const template = rows[2];
    if (template === undefined) {
      throw new Error("fixture is missing the add_member mirror row");
    }
    rows.push({ ...template, id: idOf(4), seq: 4, chainSeq: 4 });
    rows.push({ ...template, id: idOf(5), seq: 5, chainSeq: 4 });
    const env = await startEnv(await makeAuditServer({ built, rows }), built.projectId);
    expect(await runCli(["audit", "verify"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Mirror verification incomplete");
    expect(errors).not.toContain("more than 2 mirror rows");
    expect(errors).not.toContain("not contiguous");
  });
});

describe("maruhi audit invites / self", () => {
  it("invites displays the D1-side invite.* rows", async () => {
    const built = await baseChain();
    const handlers = [
      ...(await makeAuditServer({ built, rows: await mirrorRowsOf(built) })),
      onRequest("GET", `/projects/${built.projectId}/audit/invites`, () => ({
        status: 200,
        json: {
          // D1 responses carry no seq (AUDIT_SPEC §7 — the global counter
          // is not disclosed)
          events: [
            {
              id: idOf(12),
              serverTs: BASE_TS,
              event: "invite.created",
              actor: { type: "user", userId: owner.userId },
              projectId: built.projectId,
              payload: { inviteId: "inv-0001", role: "member" },
            },
          ],
        },
      })),
    ];
    const env = await startEnv(handlers, built.projectId);
    expect(await runCli(["audit", "invites"], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain("invite.created");
    expect(logs).toContain("inv-0001");
  });

  it("a chain_seq arriving via the D1 path is also not shown unlabeled — it is an integrity violation", async () => {
    const built = await baseChain();
    const handlers = [
      ...(await makeAuditServer({ built, rows: await mirrorRowsOf(built) })),
      onRequest("GET", `/projects/${built.projectId}/audit/invites`, () => ({
        status: 200,
        json: {
          events: [
            {
              id: idOf(13),
              serverTs: BASE_TS,
              event: "invite.created",
              actor: { type: "user", userId: owner.userId },
              projectId: built.projectId,
              chainSeq: 2,
            },
          ],
        },
      })),
    ];
    const env = await startEnv(handlers, built.projectId);
    expect(await runCli(["audit", "invites"], env.layer)).toBe(1);
    expect(env.logs.join("\n")).toContain(
      "chain_seq=2 (mirror=unverified (chain_seq is invalid on this audit endpoint))",
    );
    expect(env.errors.join("\n")).toContain("this endpoint does not store chain provenance");
  });

  it("self displays account events and annotates the implications of watch-worthy events", async () => {
    const handlers = [
      onRequest("GET", "/auth/audit/events", () => ({
        status: 200,
        json: {
          // D1 responses carry no seq (AUDIT_SPEC §7)
          events: [
            {
              id: idOf(2),
              serverTs: BASE_TS + 2,
              event: "auth.recovery_blob_fetched",
              actor: { type: "user", userId: owner.userId },
            },
            {
              id: idOf(1),
              serverTs: BASE_TS + 1,
              event: "auth.token_created",
              actor: { type: "user", userId: owner.userId },
              payload: { name: "cli:host" },
            },
          ],
        },
      })),
    ];
    const env = await startEnv(handlers);
    expect(await runCli(["audit", "self"], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain("auth.recovery_blob_fetched");
    expect(logs).toContain("auth.token_created");
    // The watch-worthy event's implication is a Note (stderr)
    expect(env.errors.join("\n")).toContain("reissue your recovery code");
  });
});

describe("argument-shape checks (before any communication)", () => {
  it("rejects --project on audit self as an operation-only option (exit 2)", async () => {
    const env = await makeTestEnv();
    expect(await runCli(["audit", "self", "--project", "x"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Unknown flag");
  });

  it("out-of-range limit and unknown operations are usage errors (exit 2)", async () => {
    const env = await makeTestEnv();
    expect(await runCli(["audit", "--limit", "0"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("--limit must be an integer between 1 and 200");
    const env2 = await makeTestEnv();
    expect(await runCli(["audit", "bogus"], env2.layer)).toBe(2);
    expect(env2.errors.join("\n")).toContain("Unknown subcommand");
  });
});
