// 監査ヘッド遅延拡張の有界契約(AuditHeadNotReady — AUDIT_SPEC §5.1 /
// AUTH_SPEC §16-2。2026-08-28 セッション 38 = PR #99 レビュー申し送りの解消)。
//
// 固定する性質:
//  1. 有界伸長の単体意味論: チャンク上限で "more-remains"、進捗はチャンク単位で
//     保存され、再呼び出しが保存済み末尾から再開して収束する
//  2. 監査ヘッドを読む 3 経路(GET /audit-head・standalone 受理・境界複合の
//     非空公証)は、上限到達時に retryable な 503 AuditHeadNotReady を返す
//  3. fail-closed: 上限到達時に audit-head-unknown / stale の判定を古い列で
//     行わない — 偽ヘッドの公証もまず 503 で、列が MAX(seq) に到達した後に
//     はじめて 422 audit-head-unknown になる(完了後の受理意味論は不変)
//  4. 再試行は必ず前進する(呼び出しごとに保存済み列が単調に伸びる)

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

/** 有界伸長の 1 呼び出しが処理できる最大行数(チャンク上限 × 50 行)。 */
const ROWS_PER_CALL = MAX_HEAD_EXTENSION_CHUNKS_PER_CALL * 50;

/** 種行(§5.1 の任意の非ミラーイベント。chain_seq 不変条件に触れない)。 */
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
 * 監査行のバックログを DO ストレージへ直接シードする(監査行は実操作でしか
 * 書かれないため、HTTP 経由では有界伸長の上限に届く行数を作れない)。追記後は
 * インスタンスを退去し、DO 内の採番キャッシュ・状態キャッシュを再読込させる。
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

/** 保存済み累積ハッシュ列の長さ(進捗の観測)。 */
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

describe("有界伸長の単体意味論(audit-store — maxHeadExtensionChunks)", () => {
  it("チャンク上限で more-remains を返し、保存済み末尾から再開して収束する", async () => {
    // フィクスチャの project DO とは独立の DO(コンストラクタがマイグレーションを
    // 適用するため、素の SqlStorage としてそのまま使える)
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName("audit-head-bounded-unit"));
    await runInDurableObject(stub, async (_instance, state) => {
      const sql = state.storage.sql;
      sql.exec("DELETE FROM audit_events");
      sql.exec("DELETE FROM audit_head_hashes");
      const bounded = makeAuditStore(sql, { maxHeadExtensionChunks: 2 });
      bounded.appendManySync(Array.from({ length: 130 }, backlogEvent));
      // 1 回目: 2 チャンク × 50 行で打ち切り — 進捗は保存される
      const first: AuditHeadExtensionOutcome = await Effect.runPromise(bounded.ensureHeadCurrent);
      expect(first).toBe("more-remains");
      const afterFirst = sql.exec("SELECT COUNT(*) AS n FROM audit_head_hashes").toArray()[0];
      expect(Number(afterFirst?.["n"])).toBe(100);
      // 2 回目: 保存済み末尾(100)から残り 30 行 — 端数チャンクで到達
      const second: AuditHeadExtensionOutcome = await Effect.runPromise(bounded.ensureHeadCurrent);
      expect(second).toBe("current");
      const afterSecond = sql.exec("SELECT COUNT(*) AS n FROM audit_head_hashes").toArray()[0];
      expect(Number(afterSecond?.["n"])).toBe(130);
      // 収束後の冪等性: 既定上限のストアも同じ列・同じヘッドを観測する
      const unbounded = makeAuditStore(sql);
      expect(await Effect.runPromise(unbounded.ensureHeadCurrent)).toBe("current");
      expect(unbounded.currentHeadHexSync()).toBe(bounded.currentHeadHexSync());
      expect(unbounded.currentHeadHexSync()).toMatch(/^[0-9a-f]{64}$/);
    });
    await evictDurableObject(stub);
  });

  it("ちょうど上限で完了した呼び出しは more-remains を返さない(残行の存在検査)", async () => {
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

describe("GET /audit-head の有界伸長(503 AuditHeadNotReady と再試行の収束)", () => {
  it("バックログが上限を超えると 503、再試行が必ず前進して 200 に収束する", async () => {
    await seedAuditBacklog(ROWS_PER_CALL + 30);
    const first = await fetchAuditHead(token(OWNER));
    await expectNotReady(first);
    // 失敗応答でも進捗は保存済み(= 上限いっぱい前進している)
    const afterFirst = await hashedCount();
    expect(afterFirst).toBe(ROWS_PER_CALL);
    // 2 回目は残り(バックログの端数 + ベースシナリオのミラー行)で到達する
    const second = await fetchAuditHead(token(OWNER));
    expect(second.status).toBe(200);
    const body = (await second.json()) as { auditHeadHashHex: string };
    expect(body.auditHeadHashHex).toMatch(/^[0-9a-f]{64}$/);
    expect(await hashedCount()).toBeGreaterThan(afterFirst);
  });
});

/** standalone checkpoint(環境ゼロ + 公証 — 合意規則上有効)を送る。 */
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

describe("standalone 受理の fail-closed(unknown / stale を古い列で判定しない)", () => {
  it("偽ヘッドの公証もバックログ中はまず 503 — 列到達後にはじめて 422 audit-head-unknown", async () => {
    await seedAuditBacklog(ROWS_PER_CALL + 20);
    const fabricated = "ef".repeat(32);
    const first = await sendAttestedCheckpoint(fabricated);
    // fail-closed: 途中までの列に対して所属検査を走らせない(走らせると
    // ここは 422 audit-head-unknown になってしまう)
    await expectNotReady(first.response);
    const progressed = await hashedCount();
    expect(progressed).toBe(ROWS_PER_CALL);
    // 再送(チェーンは前進していない): 列が MAX(seq) に到達し、完了後の
    // 受理意味論は不変 — 偽ヘッドは所属検査で 422 になる
    const second = await sendAttestedCheckpoint(fabricated);
    expect(second.response.status).toBe(422);
    expect(((await second.response.json()) as { reason: string }).reason).toBe(
      "audit-head-unknown",
    );
    // 実ヘッドの公証は受理される(列は到達済み — 3 回目の伸長は差分のみ)
    const head = await fetchAuditHead(token(OWNER));
    expect(head.status).toBe(200);
    const declared = ((await head.json()) as { auditHeadHashHex: string }).auditHeadHashHex;
    const third = await sendAttestedCheckpoint(declared);
    expect(third.response.status).toBe(200);
  });
});

describe("境界複合(rotate)の非空公証の有界伸長", () => {
  it("バックログ中は 503 AuditHeadNotReady、再送で受理される", async () => {
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
    // 進捗は保存済み — 再送の再伸長は残りだけになり、公証(実ヘッド)は
    // 位置下限(直前 = 作成境界 checkpoint のミラー行)以上なので受理される
    const second = await send();
    expect(second.status).toBe(200);
  });
});
