// Operations foundation — the restore worker's job processing
// (docs/notes/hosted-ops.md §2-E / §5-2).
//
// The restore worker has no HTTP: it reads restore/jobs/ in R2, calls the DO
// RPC (opsRestore), and writes a static code + verification values into
// restore/results/. A real DO (the test worker's namespace = production
// equivalent) pins that the DO name (= project id) is not written in the job
// but derived from the snapshot's genesis.

import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

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

// The restore worker scans the product key layout (restore/jobs/ etc.), and
// this file requires an exact match on the scan result (the set of job
// names). The prefix cannot be made unique to this file, so each test empties
// restore/ and builds its own preconditions (R2 is outside storage isolation
// — see the isolate: false note in apps/server/vitest.config.ts)
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
    // Materialize the audit-head column first (the trailer carries the
    // audit head = material for the diff)
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
    // The job is gone (and nothing is left in the claiming running/ either);
    // the result carries no project id
    expect(await bucket.head("restore/jobs/drill-1.json")).toBeNull();
    expect(await bucket.head("restore/running/drill-1.json")).toBeNull();
    expect(JSON.stringify(outcome)).not.toContain(projectId);
    // The restore target really is the same DO (the product path works)
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);
  });

  it("claims the job (moves it out of restore/jobs/) before the restore RPC runs", async () => {
    await seedProjectActivity();
    const uploaded = await snapshot();
    await bucket.put(
      "restore/jobs/claimed.json",
      JSON.stringify({ objectKey: uploaded.objectKey, target: "production" }),
    );
    // While the restore RPC runs, the jobs/ key must already be gone and
    // moved into running/ (a restore can take minutes — this invariant keeps
    // the next per-minute cron from picking up the same job and overwriting
    // its success result with not-empty). Swap the namespace to observe from
    // inside the RPC
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
    // After completion nothing remains in running/ either
    expect(await bucket.head("restore/running/claimed.json")).toBeNull();
    expect(await result("claimed")).toEqual({ status: "failed", code: "not-empty" });
  });

  it("reports static failure codes: malformed job, unavailable drill target, missing snapshot, non-empty DO", async () => {
    await seedProjectActivity();
    const uploaded = await snapshot();
    await bucket.put("restore/jobs/bad.json", "not json");
    // A corrupt snapshot (not gzip — the equivalent of a truncated multipart
    // leftover) — the exception is not let through; a static code is written
    // and the job deleted (otherwise the per-minute cron would retry it
    // forever)
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
