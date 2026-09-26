// The bounded contract of lazy audit-head extension (AuditHeadNotReady —
// AUDIT_SPEC §5.1 / AUTH_SPEC §16-2).
//
// Properties being pinned:
//  1. Unit semantics of bounded extension: "more-remains" at the chunk
//     limit; progress is saved per chunk, and a re-invocation resumes from
//     the saved tail and converges
//  2. The three paths that read the audit head (GET /audit-head,
//     standalone acceptance, and the boundary composite's non-empty
//     notarization) return a retryable 503 AuditHeadNotReady when the
//     limit is reached
//  3. fail-closed: on reaching the limit, the audit-head-unknown / stale
//     judgments are not made against a stale column — even a fabricated
//     head's notarization gets a 503 first, and only after the column
//     reaches MAX(seq) does it become a 422 audit-head-unknown (the
//     post-completion acceptance semantics are unchanged)
//  4. Every retry advances (the saved column grows monotonically per call)

import { env, evictDurableObject, runInDurableObject } from "cloudflare:test";
import { Effect } from "effect";
import { describe, expect, it } from "vitest";

import type { AuditEventInput, AuditHeadExtensionOutcome } from "../src/audit-store.ts";
import { makeAuditStore, MAX_HEAD_EXTENSION_CHUNKS_PER_CALL } from "../src/audit-store.ts";
import { commitmentOf, makeDek, signEntryAt, wrapDekForAll } from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  createEnvironmentOk,
  OWNER,
  projectId,
  requestJson,
  rotateEnvironmentComposite,
} from "./support/data-fixture.ts";
import { ENV, fixture, registerDataScenario, token } from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

/** The maximum rows one bounded-extension call can process (chunk limit × 50 rows). */
const ROWS_PER_CALL = MAX_HEAD_EXTENSION_CHUNKS_PER_CALL * 50;

/** A seed row (any non-mirror event of §5.1; does not touch the chain_seq invariant). */
function backlogEvent(): AuditEventInput {
  return {
    serverTs: 1_700_000_000_000,
    event: "var.read",
    actorType: "user",
    actorUserId: OWNER,
    environmentId: "env-backlog-0001",
    variableId: "var-backlog-0001",
    epoch: 1,
    version: 1,
  };
}

/**
 * Seed a backlog of audit rows directly into DO storage (audit rows are
 * only written by real operations, so HTTP cannot produce enough rows to
 * reach the bounded-extension limit). After appending, evict the instance
 * so the DO's numbering cache / state cache are re-read.
 */
async function seedAuditBacklog(count: number): Promise<void> {
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
  await runInDurableObject(stub, (_instance, state) => {
    const store = makeAuditStore(state.storage.sql);
    const events = Array.from({ length: count }, backlogEvent);
    store.appendManySync(events);
  });
  await evictDurableObject(stub);
}

/** The length of the saved cumulative hash column (observing progress). */
async function hashedCount(): Promise<number> {
  const rows = await queryProjectDo(projectId, "SELECT COUNT(*) AS n FROM audit_head_hashes");
  return Number(rows[0]?.["n"]);
}

async function fetchAuditHead(authToken: string): Promise<Response> {
  return requestJson("GET", "/audit-head", authToken);
}

async function expectNotReady(response: Response): Promise<void> {
  expect(response.status).toBe(503);
  const body = (await response.json()) as Record<string, unknown>;
  expect(body).toMatchObject({ _tag: "AuditHeadNotReady" });
}

describe("unit semantics of bounded extension (audit-store — maxHeadExtensionChunks)", () => {
  it("returns more-remains at the chunk limit, resumes from the saved tail, and converges", async () => {
    // A DO independent of the fixture's project DO (its constructor applies
    // the migrations, so it can be used as-is as a bare SqlStorage)
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName("audit-head-bounded-unit"));
    await runInDurableObject(stub, async (_instance, state) => {
      const sql = state.storage.sql;
      sql.exec("DELETE FROM audit_events");
      sql.exec("DELETE FROM audit_head_hashes");
      const bounded = makeAuditStore(sql, { maxHeadExtensionChunks: 2 });
      bounded.appendManySync(Array.from({ length: 130 }, backlogEvent));
      // First call: cut off at 2 chunks × 50 rows — progress is saved
      const first: AuditHeadExtensionOutcome = await Effect.runPromise(bounded.ensureHeadCurrent);
      expect(first).toBe("more-remains");
      const afterFirst = sql.exec("SELECT COUNT(*) AS n FROM audit_head_hashes").toArray()[0];
      expect(Number(afterFirst?.["n"])).toBe(100);
      // Second call: the remaining 30 rows from the saved tail (100) — reached in a fractional chunk
      const second: AuditHeadExtensionOutcome = await Effect.runPromise(bounded.ensureHeadCurrent);
      expect(second).toBe("current");
      const afterSecond = sql.exec("SELECT COUNT(*) AS n FROM audit_head_hashes").toArray()[0];
      expect(Number(afterSecond?.["n"])).toBe(130);
      // Post-convergence idempotence: a default-limit store observes the same column and the same head
      const unbounded = makeAuditStore(sql);
      expect(await Effect.runPromise(unbounded.ensureHeadCurrent)).toBe("current");
      expect(unbounded.currentHeadHexSync()).toBe(bounded.currentHeadHexSync());
      expect(unbounded.currentHeadHexSync()).toMatch(/^[0-9a-f]{64}$/);
    });
    await evictDurableObject(stub);
  });

  it("a call that finishes exactly at the limit does not return more-remains (the remaining-row existence check)", async () => {
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName("audit-head-bounded-exact"));
    await runInDurableObject(stub, async (_instance, state) => {
      const sql = state.storage.sql;
      sql.exec("DELETE FROM audit_events");
      sql.exec("DELETE FROM audit_head_hashes");
      const bounded = makeAuditStore(sql, { maxHeadExtensionChunks: 2 });
      bounded.appendManySync(Array.from({ length: 100 }, backlogEvent));
      expect(await Effect.runPromise(bounded.ensureHeadCurrent)).toBe("current");
    });
    await evictDurableObject(stub);
  });
});

describe("bounded extension on GET /audit-head (503 AuditHeadNotReady and retry convergence)", () => {
  it("returns 503 when the backlog exceeds the limit, and retries always advance until they converge on 200", async () => {
    await seedAuditBacklog(ROWS_PER_CALL + 30);
    const first = await fetchAuditHead(token(OWNER));
    await expectNotReady(first);
    // Even on the failure response the progress is saved (= it advanced by the full limit)
    const afterFirst = await hashedCount();
    expect(afterFirst).toBe(ROWS_PER_CALL);
    // The second call arrives with the remainder (the backlog's fraction + the base scenario's mirror rows)
    const second = await fetchAuditHead(token(OWNER));
    expect(second.status).toBe(200);
    const body = (await second.json()) as { auditHeadHashHex: string };
    expect(body.auditHeadHashHex).toMatch(/^[0-9a-f]{64}$/);
    expect(await hashedCount()).toBeGreaterThan(afterFirst);
  });
});

/** Send a standalone checkpoint (zero environments + notarization — valid under the consensus rules). */
async function sendAttestedCheckpoint(
  auditHeadHashHex: string,
): Promise<{ response: Response; headHashHex: string; seq: number }> {
  const { entry, hash } = await signEntryAt({
    seq: fixture.head.seq + 1,
    prevHashHex: fixture.head.hashHex,
    actorUserId: OWNER,
    operation: { op: "checkpoint", payload: { environments: [], auditHeadHashHex } },
  });
  const response = await requestJson("POST", "/chain/entries", token(OWNER), {
    parentHeadHashHex: fixture.head.hashHex,
    entry,
  });
  if (response.status === 200) {
    fixture.head = { seq: entry.seq, hashHex: hash };
  }
  return { response, headHashHex: hash, seq: entry.seq };
}

describe("fail-closed standalone acceptance (unknown / stale are not judged on a stale column)", () => {
  it("even a fabricated head's notarization gets 503 while backlogged — only after the column arrives does it become 422 audit-head-unknown", async () => {
    await seedAuditBacklog(ROWS_PER_CALL + 20);
    const fabricated = "ef".repeat(32);
    const first = await sendAttestedCheckpoint(fabricated);
    // fail-closed: do not run the membership check against a partially
    // extended column (if it did, this would incorrectly become a 422
    // audit-head-unknown)
    await expectNotReady(first.response);
    const progressed = await hashedCount();
    expect(progressed).toBe(ROWS_PER_CALL);
    // Resend (the chain has not advanced): the column reaches MAX(seq)
    // and the post-completion acceptance semantics are unchanged — the
    // fabricated head fails the membership check with a 422
    const second = await sendAttestedCheckpoint(fabricated);
    expect(second.response.status).toBe(422);
    expect(((await second.response.json()) as { reason: string }).reason).toBe(
      "audit-head-unknown",
    );
    // A notarization of the real head is accepted (the column has arrived — the third extension covers only the delta)
    const head = await fetchAuditHead(token(OWNER));
    expect(head.status).toBe(200);
    const declared = ((await head.json()) as { auditHeadHashHex: string }).auditHeadHashHex;
    const third = await sendAttestedCheckpoint(declared);
    expect(third.response.status).toBe(200);
  });
});

describe("bounded extension of the boundary composite (rotate)'s non-empty notarization", () => {
  it("returns 503 AuditHeadNotReady while backlogged, and is accepted on resend", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const headResponse = await fetchAuditHead(token(OWNER));
    expect(headResponse.status).toBe(200);
    const attested = ((await headResponse.json()) as { auditHeadHashHex: string }).auditHeadHashHex;
    await seedAuditBacklog(ROWS_PER_CALL + 10);
    const next = makeDek();
    const send = async (): Promise<Response> =>
      rotateEnvironmentComposite(fixture, {
        environmentId: ENV,
        newEpoch: 2,
        actorUserId: OWNER,
        deks: await wrapDekForAll({
          projectId,
          environmentId: ENV,
          epoch: 2,
          dek: next,
          recipientUserIds: ALL_MEMBERS,
          signerUserId: OWNER,
        }),
        dekCommitmentHex: await commitmentOf(projectId, ENV, 2, next),
        checkpointAuditHeadHashHex: attested,
      });
    const first = await send();
    await expectNotReady(first);
    // The progress is saved — the resend's re-extension covers only the
    // remainder, and the notarization (the real head) is at or above the
    // position lower bound (immediately before = the creation boundary
    // checkpoint's mirror row), so it is accepted
    const second = await send();
    expect(second.status).toBe(200);
  });
});
