import { generateDek } from "@maruhi/crypto";
import { signEntryAt, testDekCommitmentHex } from "@maruhi/test-kit";
import { env, evictDurableObject, runInDurableObject } from "cloudflare:test";
import { Effect } from "effect";
import { describe, expect, it } from "vite-plus/test";

import type { AuditEventInput, AuditHeadExtensionOutcome } from "../src/audit-store.ts";
import { makeAuditStore, MAX_HEAD_EXTENSION_CHUNKS_PER_CALL } from "../src/audit-store.ts";
import { ensureProjectDoTables } from "../src/do/do-schema.ts";
import { identityOf, wrapDekForAll } from "./support/data-crypto.ts";
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

const ROWS_PER_CALL = MAX_HEAD_EXTENSION_CHUNKS_PER_CALL * 50;

function backlogEvent(): AuditEventInput {
  return {
    serverTs: 1_700_000_000_000,
    event: "var.version_pushed",
    actorType: "user",
    actorUserId: OWNER,
    environmentId: "env-backlog-0001",
    variableId: "var-backlog-0001",
    epoch: 1,
    version: 1,
  };
}

async function seedAuditBacklog(count: number): Promise<void> {
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
  await runInDurableObject(stub, (_instance, state) => {
    const store = makeAuditStore(state.storage.sql);
    const events = Array.from({ length: count }, backlogEvent);
    store.appendManySync(events);
  });
  await evictDurableObject(stub);
}

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
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName("audit-head-bounded-unit"));
    await runInDurableObject(stub, async (_instance, state) => {
      ensureProjectDoTables(state.storage);
      const sql = state.storage.sql;
      sql.exec("DELETE FROM audit_events");
      sql.exec("DELETE FROM audit_head_hashes");
      const bounded = makeAuditStore(sql, { maxHeadExtensionChunks: 2 });
      bounded.appendManySync(Array.from({ length: 130 }, backlogEvent));
      const first: AuditHeadExtensionOutcome = await Effect.runPromise(bounded.ensureHeadCurrent);
      expect(first).toBe("more-remains");
      const afterFirst = sql.exec("SELECT COUNT(*) AS n FROM audit_head_hashes").toArray()[0];
      expect(Number(afterFirst?.["n"])).toBe(100);
      const second: AuditHeadExtensionOutcome = await Effect.runPromise(bounded.ensureHeadCurrent);
      expect(second).toBe("current");
      const afterSecond = sql.exec("SELECT COUNT(*) AS n FROM audit_head_hashes").toArray()[0];
      expect(Number(afterSecond?.["n"])).toBe(130);
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
      ensureProjectDoTables(state.storage);
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
    const afterFirst = await hashedCount();
    expect(afterFirst).toBe(ROWS_PER_CALL);
    const second = await fetchAuditHead(token(OWNER));
    expect(second.status).toBe(200);
    const body = (await second.json()) as { auditHeadHashHex: string };
    expect(body.auditHeadHashHex).toMatch(/^[0-9a-f]{64}$/);
    expect(await hashedCount()).toBeGreaterThan(afterFirst);
  });
});

async function sendAttestedCheckpoint(
  auditHeadHashHex: string,
): Promise<{ response: Response; headHashHex: string; seq: number }> {
  const { entry, hash } = await signEntryAt({
    seq: fixture.head.seq + 1,
    prevHashHex: fixture.head.hashHex,
    actor: identityOf(OWNER),
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
    await expectNotReady(first.response);
    const progressed = await hashedCount();
    expect(progressed).toBe(ROWS_PER_CALL);
    const second = await sendAttestedCheckpoint(fabricated);
    expect(second.response.status).toBe(422);
    expect(((await second.response.json()) as { reason: string }).reason).toBe(
      "audit-head-unknown",
    );
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
    const next = generateDek();
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
        dekCommitmentHex: await testDekCommitmentHex(projectId, ENV, 2, next),
        checkpointAuditHeadHashHex: attested,
      });
    const first = await send();
    await expectNotReady(first);
    const second = await send();
    expect(second.status).toBe(200);
  });
});
