// 運用基盤 H3 — 復元 worker のジョブ処理(docs/notes/hosted-ops.md §2-E / §5-2)。
//
// HTTP を持たない復元 worker は R2 の restore/jobs/ を読んで DO RPC(opsRestore)を呼び、
// restore/results/ に静的コード + 検証値を書く。DO 名(= プロジェクト ID)はジョブに
// 書かず退避物の genesis から導出することを、実 DO(テスト worker の名前空間 =
// production 相当)で固定する。

import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import type { OpsBackupOutcome } from "../src/chain-do.ts";
import { OPS_BACKUP_MAX_BYTES } from "../src/ops-policy.ts";
import type { RestoreJobResult } from "../src/restore-worker.ts";
import { processRestoreJobs, projectIdFromSnapshot } from "../src/restore-worker.ts";
import { seedProjectActivity } from "./support/audit-read-scenario.ts";
import { OWNER, projectId, READER, requestJson } from "./support/data-fixture.ts";
import { ENV, registerDataScenario, token } from "./support/data-scenario.ts";
import { resetProjectDo } from "./support/project-do.ts";

registerDataScenario();

const bucket = env.OPS_BACKUP_BUCKET as R2Bucket;
const restoreEnv = { OPS_BACKUP_BUCKET: bucket, PRODUCTION_PROJECT_CHAIN: env.PROJECT_CHAIN };

async function snapshot(): Promise<Extract<OpsBackupOutcome, { kind: "uploaded" }>> {
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
  const outcome = (await stub.opsBackup({
    keyPrefix: "do",
    nowMs: Date.now(),
    maxBytes: OPS_BACKUP_MAX_BYTES,
    skipIfUnchanged: null,
  })) as OpsBackupOutcome;
  if (outcome.kind !== "uploaded") {
    throw new Error(`unexpected backup outcome: ${outcome.kind}`);
  }
  return outcome;
}

async function result(name: string): Promise<RestoreJobResult> {
  const object = await bucket.get(`restore/results/${name}.json`);
  expect(object).not.toBeNull();
  return (await object?.json()) as RestoreJobResult;
}

describe("復元 worker(restore-worker.ts)", () => {
  it("derives the project id from the snapshot's genesis entry (no capability in the job)", async () => {
    await seedProjectActivity();
    const uploaded = await snapshot();
    const object = await bucket.get(uploaded.objectKey);
    expect(await projectIdFromSnapshot(object?.body as ReadableStream)).toBe(projectId);
  });

  it("restores a production target from a job file and writes a verification result", async () => {
    await seedProjectActivity();
    // 監査ヘッド列を実体化しておく(トレーラに監査ヘッドが載る = 突合材料)
    expect((await requestJson("GET", "/audit-head", token(OWNER))).status).toBe(200);
    const uploaded = await snapshot();
    await resetProjectDo(projectId);
    await bucket.put(
      "restore/jobs/drill-1.json",
      JSON.stringify({ objectKey: uploaded.objectKey, target: "production" }),
    );

    expect(await processRestoreJobs(restoreEnv)).toEqual(["drill-1"]);
    const outcome = await result("drill-1");
    expect(outcome.status).toBe("ok");
    if (outcome.status === "ok") {
      expect(outcome.verification.chainHeadSeq).toBe(uploaded.trailer.chainHeadSeq);
      expect(outcome.verification.chainHeadHashHex).toBe(uploaded.trailer.chainHeadHashHex);
      expect(outcome.verification.auditMaxSeq).toBe(uploaded.trailer.auditMaxSeq);
      expect(outcome.verification.auditHeadHashHex).toBe(uploaded.trailer.auditHeadHashHex);
      expect(outcome.verification.rows).toEqual(uploaded.trailer.rows);
    }
    // ジョブは消え、結果にプロジェクト ID は載らない
    expect(await bucket.head("restore/jobs/drill-1.json")).toBeNull();
    expect(JSON.stringify(outcome)).not.toContain(projectId);
    // 復元先は本当に同じ DO(製品経路が動く)
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);
  });

  it("reports static failure codes: malformed job, unavailable drill target, missing snapshot, non-empty DO", async () => {
    await seedProjectActivity();
    const uploaded = await snapshot();
    await bucket.put("restore/jobs/bad.json", "not json");
    // 破損した退避物(gzip ではない・切れた multipart の残骸相当)— 例外を逃がさず
    // 静的コードで結果を書き、ジョブを消す(消さないと毎分の cron が永久に再試行する)
    await bucket.put("do/test/corrupt.ndjson.gz", new Uint8Array([1, 2, 3, 4, 5]));
    await bucket.put(
      "restore/jobs/corrupt.json",
      JSON.stringify({ objectKey: "do/test/corrupt.ndjson.gz", target: "production" }),
    );
    await bucket.put(
      "restore/jobs/drill.json",
      JSON.stringify({ objectKey: uploaded.objectKey, target: "drill" }),
    );
    await bucket.put(
      "restore/jobs/missing.json",
      JSON.stringify({ objectKey: "do/none", target: "production" }),
    );
    await bucket.put(
      "restore/jobs/occupied.json",
      JSON.stringify({ objectKey: uploaded.objectKey, target: "production" }),
    );
    const processed = await processRestoreJobs(restoreEnv);
    expect(processed.toSorted()).toEqual(["bad", "corrupt", "drill", "missing", "occupied"]);
    expect(await result("bad")).toEqual({ status: "failed", code: "job-malformed" });
    expect(await result("corrupt")).toEqual({ status: "failed", code: "snapshot-malformed" });
    expect(await bucket.head("restore/jobs/corrupt.json")).toBeNull();
    expect(await result("drill")).toEqual({ status: "failed", code: "target-unavailable" });
    expect(await result("missing")).toEqual({ status: "failed", code: "snapshot-missing" });
    expect(await result("occupied")).toEqual({ status: "failed", code: "not-empty" });
  });
});
