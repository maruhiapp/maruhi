// Integration tests for server-side membership-log storage
// (CRYPTO_SPEC §6.4) + authorization (AUTH_SPEC §11) — genesis
// acceptance, canonical-vector replay, and the incremental-load
// cache.
// Verifies the HttpApi via SELF, DO SQLite, and D1 on
// @cloudflare/vitest-plugin (real workerd environment).
//
// The shared fixture and vector-replay helpers live in
// support/membership-scenario.ts (authorization, negatives, and the
// acceptance policy live in membership-authz / membership-negatives-*
// / membership-policy — for the split's motivation see the top of the
// scenario module).

import type { ChainEntry } from "@maruhi/crypto";
import { env, evictDurableObject, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { bearer } from "./support/auth.ts";
import {
  firstFourEyesSeq,
  toWireEntry,
  vectorEntries,
  vectorExtendedChains,
  vectorProjectId,
} from "./support/chain-vectors.ts";
import { signEntryAt } from "./support/data-crypto.ts";
import {
  appendEntry,
  getChain,
  initChain,
  registerMembershipScenario,
  replayNegativePrefix,
  replayVectorChain,
  tokenFor,
  VECTOR_ORG,
} from "./support/membership-scenario.ts";
import { queryProjectDo, readAuditEvents } from "./support/project-do.ts";

registerMembershipScenario();

describe("environment", () => {
  it("runs inside workerd", () => {
    expect(navigator.userAgent).toBe("Cloudflare-Workers");
  });
});

describe("POST /projects (genesis acceptance + org linkage §11-3)", () => {
  it("accepts the vector genesis, derives project id = genesis entry hash, records the org row", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    const response = await initChain(toWireEntry(genesis));
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      projectId: vectorProjectId,
      headSeq: 1,
      headHashHex: genesis.entry_hash_hex,
    });
    // The D1 projects row (org-attribution metadata) follows
    const row = await env.DB.prepare("SELECT org_id FROM projects WHERE id = ?")
      .bind(vectorProjectId)
      .first<{ org_id: string }>();
    expect(row?.org_id).toBe(VECTOR_ORG);
  });

  it("rejects a duplicate genesis submission with 409", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    await initChain(toWireEntry(genesis));
    const second = await initChain(toWireEntry(genesis));
    expect(second.status).toBe(409);
    const body = (await second.json()) as { projectId: string };
    expect(body.projectId).toBe(vectorProjectId);
  });

  it("repairs a missing projects row idempotently for the genesis actor (§11-3)", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    await initChain(toWireEntry(genesis));
    // Simulate a crash after DO acceptance but before the D1 row insert: delete just the row
    await env.DB.prepare("DELETE FROM projects WHERE id = ?").bind(vectorProjectId).run();
    const retried = await initChain(toWireEntry(genesis));
    expect(retried.status).toBe(200);
    await expect(retried.json()).resolves.toEqual({
      projectId: vectorProjectId,
      headSeq: 1,
      headHashHex: genesis.entry_hash_hex,
    });
    const row = await env.DB.prepare("SELECT org_id FROM projects WHERE id = ?")
      .bind(vectorProjectId)
      .first<{ org_id: string }>();
    expect(row?.org_id).toBe(VECTOR_ORG);
  });

  it("rejects init into an org the caller is not a member of (403 org-membership-required)", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    const response = await initChain(toWireEntry(genesis), { orgId: "org-not-mine" });
    expect(response.status).toBe(403);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("org-membership-required");
  });

  it("rejects init whose genesis actor is not the authenticated user (403 actor-mismatch §11-1)", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    const response = await initChain(toWireEntry(genesis), {
      headers: bearer(tokenFor("user-member-0002")),
    });
    expect(response.status).toBe(403);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("actor-mismatch");
  });

  it("rejects a non-genesis entry with 422 (bad-seq)", async () => {
    const entry2 = vectorEntries[1];
    if (entry2 === undefined) throw new Error("missing vector entry 2");
    const response = await initChain(toWireEntry(entry2));
    expect(response.status).toBe(422);
    const body = (await response.json()) as { seq: number; reason: string };
    expect(body.reason).toBe("bad-seq");
  });
});

describe("chain replay (canonical vectors; create/rotate go through composites)", () => {
  // The canonical chain's full 24 entries (2026-09-14 ES + PF1 —
  // including the four-eyes 4 ops at seq 20-24. K5 removed the
  // acceptance guard and restored full replay)
  const lastSeq = vectorEntries[vectorEntries.length - 1]?.seq ?? 0;

  it("accepts the whole vector chain with interleaved boundary checkpoints, append-only", async () => {
    // A boundary checkpoint (H+2) is inserted per composite (vector
    // seq 3 / 4 / 8 / 10 / 11) (§12-4). The vector's seq 1-24 are all
    // accepted in this order
    expect(lastSeq).toBeGreaterThan(firstFourEyesSeq);
    const { head } = await replayVectorChain(lastSeq);

    const response = await getChain(vectorProjectId);
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      projectId: string;
      entries: ChainEntry[];
      headSeq: number;
      headHashHex: string;
    };
    // The expected op list = the vector body's op list with a boundary checkpoint inserted right after each create / rotate
    const expectedOps = vectorEntries.flatMap((v) =>
      v.op === "create_environment" || v.op === "rotate_epoch" ? [v.op, "checkpoint"] : [v.op],
    );
    expect(body.projectId).toBe(vectorProjectId);
    expect(body.headSeq).toBe(expectedOps.length);
    expect(body.headHashHex).toBe(head.hashHex);
    expect(body.entries.map((entry) => entry.seq)).toEqual(expectedOps.map((_, i) => i + 1));
    expect(body.entries.map((entry) => entry.op)).toEqual(expectedOps);
    // The op list minus checkpoints equals the vector body (the same operation sequence was accepted)
    expect(
      body.entries.filter((entry) => entry.op !== "checkpoint").map((entry) => entry.op),
    ).toEqual(vectorEntries.map((v) => v.op));

    // Inspect DO SQLite's real data directly (append-only storage and
    // the hash chain). Up to the first composite's checkpoint insertion
    // (seq 1-3), entries are accepted as the vector's fixed bytes
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(vectorProjectId));
    await runInDurableObject(stub, (_instance, state) => {
      const rows = state.storage.sql
        .exec("SELECT seq, entry_hash_hex FROM chain_entries ORDER BY seq")
        .toArray();
      expect(rows.length).toBe(expectedOps.length);
      expect(rows.slice(0, 3).map((row) => row["entry_hash_hex"])).toEqual(
        vectorEntries.slice(0, 3).map((v) => v.entry_hash_hex),
      );
    });
  });
});

type AuditRow = Record<string, unknown>;

/** Read an audit row's payload (a JSON string). */
const payloadOf = (row: AuditRow): Record<string, unknown> =>
  JSON.parse(String(row["payload"])) as Record<string, unknown>;

/** The rows for a chain_seq (in audit seq order). */
const rowsAt = (rows: readonly AuditRow[], chainSeq: number): AuditRow[] =>
  rows.filter((row) => row["chain_seq"] === chainSeq);

/** The nth row for a chain_seq (fails if absent). */
function rowAt(rows: readonly AuditRow[], chainSeq: number, nth = 0): AuditRow {
  const row = rowsAt(rows, chainSeq)[nth];
  if (row === undefined) throw new Error(`no audit row #${nth} for chain_seq=${chainSeq}`);
  return row;
}

/** Get the seq of op's nth entry on the replayed chain. */
function seqOf(entries: readonly ChainEntry[], op: ChainEntry["op"], nth = 0): number {
  const found = entries.filter((entry) => entry.op === op)[nth];
  if (found === undefined) throw new Error(`replayed chain has no ${op} #${nth}`);
  return found.seq;
}

async function projectionRowsFor(userId: string): Promise<number> {
  const row = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM project_members WHERE project_id = ? AND user_id = ?",
  )
    .bind(vectorProjectId, userId)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

describe("acceptance and mirroring of the four-eyes 4 ops (PF1 — K5; AUDIT_SPEC §3.4)", () => {
  // The canonical chain's seq 20-24 = set_approval_policy /
  // propose(change_role: devmember → reader listed{dev} — proposer
  // owner-0001's single vote) / approve(owner-0014 — reaches quorum 2 =
  // completed) / propose(remove_member — proposer devadmin-0011 is an
  // admin, no vote) / withdraw(owner-0015). Since the actual seqs after
  // replay shift by the inserted boundary checkpoints, resolve them by
  // op from the fetched chain
  it("mirrors the four-eyes entries with proposalChainSeq / completed and writes the applied inner-op row", async () => {
    await replayVectorChain(vectorEntries[vectorEntries.length - 1]?.seq ?? 0);
    const chain = await readChain();
    const policySeq = seqOf(chain.entries, "set_approval_policy");
    const firstProposeSeq = seqOf(chain.entries, "propose", 0);
    const approveSeq = seqOf(chain.entries, "approve");
    const secondProposeSeq = seqOf(chain.entries, "propose", 1);
    const withdrawSeq = seqOf(chain.entries, "withdraw");
    const rows = await readAuditEvents(vectorProjectId);

    // One row per entry (a bijection) — only the completed approve has a second row (the applied row)
    for (const entry of chain.entries) {
      expect(rowsAt(rows, entry.seq).length, `chain_seq=${entry.seq} (${entry.op})`).toBe(
        entry.seq === approveSeq ? 2 : 1,
      );
    }

    const policy = rowAt(rows, policySeq);
    expect(policy["event"]).toBe("chain.approval_policy_changed");
    expect(payloadOf(policy)).toEqual({
      ops: ["change_role", "grant_server", "remove_member", "set_approval_policy"],
      requiredApprovals: 2,
    });

    const proposed = rowAt(rows, firstProposeSeq);
    expect(proposed["event"]).toBe("chain.proposed");
    expect(payloadOf(proposed)).toMatchObject({ innerOp: "change_role" });
    // The inner payload is not copied (the chain is the source of truth)
    expect(payloadOf(proposed)["inner"]).toBeUndefined();

    // The completed approve: chain.approved (completed = true) + the
    // inner op's applied row (same chain_seq; actor = proposer
    // owner-0001, target = devmember, viaProposalSeq = the proposal's
    // seq)
    const approved = rowAt(rows, approveSeq, 0);
    const applied = rowAt(rows, approveSeq, 1);
    expect(approved["event"]).toBe("chain.approved");
    expect(approved["actor_user_id"]).toBe("user-owner-0014");
    expect(payloadOf(approved)).toEqual({ proposalChainSeq: firstProposeSeq, completed: true });
    expect(applied["event"]).toBe("chain.role_changed");
    expect(applied["actor_user_id"]).toBe("user-owner-0001");
    expect(applied["target_user_id"]).toBe("user-devmember-0010");
    expect(payloadOf(applied)).toEqual({
      newRole: "reader",
      scopeKind: "listed",
      scopeEnvironmentIds: ["env-dev-0002"],
      viaProposalSeq: firstProposeSeq,
    });
    // The audit seq orders mirror row → applied row (read detections after the mirror)
    expect(Number(approved["seq"])).toBeLessThan(Number(applied["seq"]));

    const withdrawn = rowAt(rows, withdrawSeq);
    expect(withdrawn["event"]).toBe("chain.proposal_withdrawn");
    expect(payloadOf(withdrawn)).toEqual({ proposalChainSeq: secondProposeSeq });

    // devmember got a projection row when seq 13's add_member was
    // accepted (§11-5 (2)); the demotion (an applied change_role) does
    // not remove it
    expect(await projectionRowsFor("user-devmember-0010")).toBe(1);
  });

  it("writes the applied member_removed row only for the approve that reaches the quorum and drops the projection row", async () => {
    // The derived chain proposal-completed (base 23):
    // approve@24 (owner-0014 — 1 vote, incomplete) → approve@25
    // (owner-0015 — completes at quorum 2 = applies remove_member on
    // devmember)
    const extended = vectorExtendedChains["proposal-completed"];
    const last = extended?.entries[extended.entries.length - 1];
    if (last === undefined) throw new Error("missing extended chain proposal-completed");
    // replayNegativePrefix with a chain argument replays all of a derived chain's entries
    const { head } = await replayNegativePrefix({
      entry: { seq: last.seq + 1 },
      chain: "proposal-completed",
    });

    const chain = await readChain();
    // The derived chain's two entries follow the canonical chain's completed approve (~seq 22)
    const firstApproveSeq = seqOf(chain.entries, "approve", 1);
    const completingSeq = seqOf(chain.entries, "approve", 2);
    expect(completingSeq).toBe(head.seq);
    const rows = await readAuditEvents(vectorProjectId);

    expect(rowsAt(rows, firstApproveSeq).map((row) => row["event"])).toEqual(["chain.approved"]);
    expect(payloadOf(rowAt(rows, firstApproveSeq))).toMatchObject({ completed: false });

    const approved = rowAt(rows, completingSeq, 0);
    const applied = rowAt(rows, completingSeq, 1);
    expect(approved["event"]).toBe("chain.approved");
    expect(payloadOf(approved)).toMatchObject({ completed: true });
    expect(applied["event"]).toBe("chain.member_removed");
    expect(applied["target_user_id"]).toBe("user-devmember-0010");
    // The proposer (devadmin-0011 — admin. Not a vote, but the applied row's actor)
    expect(applied["actor_user_id"]).toBe("user-devadmin-0011");
    expect(payloadOf(applied)).toEqual({ viaProposalSeq: seqOf(chain.entries, "propose", 1) });

    // §11-5 (3): an applied remove_member drops the projection row (the worker's D1 post-processing — K5-H)
    expect(await projectionRowsFor("user-devmember-0010")).toBe(0);
    // The removed member can no longer read (§11-2)
    const denied = await getChain(vectorProjectId, bearer(tokenFor("user-devmember-0010")));
    expect(denied.status).toBe(404);
    // The chain-row count = the set of mirror rows' chain_seq values (applied rows are second rows on an existing seq)
    const distinct = new Set(rows.map((row) => row["chain_seq"]).filter((seq) => seq !== null));
    expect(distinct.size).toBe(chain.headSeq);
    expect(
      await queryProjectDo(vectorProjectId, "SELECT COUNT(*) AS n FROM chain_entries"),
    ).toEqual([{ n: chain.headSeq }]);
  });
});

const readChain = async () => {
  const response = await getChain(vectorProjectId);
  expect(response.status).toBe(200);
  return (await response.json()) as {
    projectId: string;
    entries: ChainEntry[];
    headSeq: number;
    headHashHex: string;
  };
};

describe("the chain's incremental-load cache (chain-store.ts StateCache.chain)", () => {
  it("an append→read→append round trip returns the same result as a full load (incremental reflection of composite appends included)", async () => {
    // Replaying seq 1-12 alternates "append (incremental reflection) →
    // read (incremental load)" every step, and composite acceptance
    // (the create/rotate + boundary checkpoint two-entry insertSync
    // path) is also reflected into the cache
    const { members } = await replayVectorChain(12);
    const warm = await readChain();

    // DO eviction = discarding the in-memory cache. The next read must
    // fall back to a full load and return exactly what the warm cache
    // returned
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(vectorProjectId));
    await evictDurableObject(stub);
    const cold = await readChain();
    expect(cold).toEqual(warm);

    // Appends are still accepted after the fallback and are incrementally reflected into later reads
    const target = members.find((userId) => userId !== "user-owner-0001");
    if (target === undefined) throw new Error("vector chain has no removable member");
    const { entry } = await signEntryAt({
      seq: warm.headSeq + 1,
      prevHashHex: warm.headHashHex,
      actorUserId: "user-owner-0001",
      operation: { op: "remove_member", payload: { targetUserId: target } },
    });
    const appended = await appendEntry(vectorProjectId, warm.headHashHex, entry);
    expect(appended.status).toBe(200);
    const after = await readChain();
    expect(after.headSeq).toBe(warm.headSeq + 1);
    expect(after.entries.slice(0, warm.headSeq)).toEqual(warm.entries);
    expect(after.entries[warm.headSeq]).toEqual(entry);

    // Discarding the cache again still reaches the same result via full load
    await evictDurableObject(stub);
    const coldAfter = await readChain();
    expect(coldAfter).toEqual(after);
  });
});
