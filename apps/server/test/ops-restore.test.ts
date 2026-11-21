import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vite-plus/test";

import type { OpsBackupOutcome } from "../src/do/do-ops.ts";
import { OPS_BACKUP_MAX_BYTES } from "../src/ops/ops-policy.ts";
import type { RestoreJobResult } from "../src/restore-worker.ts";
import { processRestoreJobs, projectIdFromSnapshot } from "../src/restore-worker.ts";
import { seedProjectActivity } from "./support/audit-read-scenario.ts";
import { OWNER, projectId, READER, requestJson } from "./support/data-fixture.ts";
import { ENV, registerDataScenario, token } from "./support/data-scenario.ts";
import { queryProjectDo, resetProjectDo } from "./support/project-do.ts";

registerDataScenario();

const bucket = env.OPS_BACKUP_BUCKET as R2Bucket;
const restoreEnv = { OPS_BACKUP_BUCKET: bucket, PRODUCTION_PROJECT_CHAIN: env.PROJECT_CHAIN };

beforeEach(async () => {
  const listed = await bucket.list({ prefix: "restore/" });
  if (listed.objects.length > 0) {
    await bucket.delete(listed.objects.map((object) => object.key));
  }
});

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

describe("restore worker (restore-worker.ts)", () => {
  it("derives the project id from the snapshot's genesis entry (no capability in the job)", async () => {
    await seedProjectActivity();
    const uploaded = await snapshot();
    const object = await bucket.get(uploaded.objectKey);
    expect(await projectIdFromSnapshot(object?.body as ReadableStream)).toBe(projectId);
  });

  it("restores a production target from a job file and writes a verification result", async () => {
    await seedProjectActivity();
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
    expect(await bucket.head("restore/jobs/drill-1.json")).toBeNull();
    expect(await bucket.head("restore/running/drill-1.json")).toBeNull();
    expect(JSON.stringify(outcome)).not.toContain(projectId);
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);
  });

  it("a missing object on a fresh destination leaves no tables (Sc-7 / A-4)", async () => {
    const fresh = "d4".repeat(32);
    await resetProjectDo(fresh);
    const freshStub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(fresh));
    const outcome = await freshStub.opsRestore("do/does-not-exist.ndjson.gz");
    expect(outcome).toEqual({ kind: "refused", code: "object-missing" });
    expect(
      await queryProjectDo(fresh, "SELECT name FROM sqlite_master WHERE type = 'table'"),
    ).toEqual([]);
  });

  it("claims the job (moves it out of restore/jobs/) before the restore RPC runs", async () => {
    await seedProjectActivity();
    const uploaded = await snapshot();
    await bucket.put(
      "restore/jobs/claimed.json",
      JSON.stringify({ objectKey: uploaded.objectKey, target: "production" }),
    );
    const seen: { jobs: R2Object | null; running: R2Object | null }[] = [];
    const observingNamespace = {
      idFromName: (name: string) => env.PROJECT_CHAIN.idFromName(name),
      get: () => ({
        opsRestore: async () => {
          seen.push({
            jobs: await bucket.head("restore/jobs/claimed.json"),
            running: await bucket.head("restore/running/claimed.json"),
          });
          return { kind: "refused", code: "not-empty" } as const;
        },
      }),
    } as unknown as typeof env.PROJECT_CHAIN;
    expect(
      await processRestoreJobs({ ...restoreEnv, PRODUCTION_PROJECT_CHAIN: observingNamespace }),
    ).toEqual(["claimed"]);
    expect(seen).toHaveLength(1);
    expect(seen[0]?.jobs).toBeNull();
    expect(seen[0]?.running).not.toBeNull();
    expect(await bucket.head("restore/running/claimed.json")).toBeNull();
    expect(await result("claimed")).toEqual({ status: "failed", code: "not-empty" });
  });

  it("reports static failure codes: malformed job, unavailable drill target, missing snapshot, non-empty DO", async () => {
    await seedProjectActivity();
    const uploaded = await snapshot();
    await bucket.put("restore/jobs/bad.json", "not json");
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
