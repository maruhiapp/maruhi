// Operations foundation — DO -> R2 evacuation and restore
// (docs/notes/hosted-ops.md §2-D / §2-E / §4-2).
//
// Against a real project DO (@cloudflare/vitest-plugin): evacuate a fixture
// (chain, environments, variables, audit rows built via the API), write it
// back into an emptied DO, and pin that the chain head, audit head (the
// ensureHeadCurrent value), every table's rows, and the gapless audit seq
// (AUDIT_SPEC §5.1) all match. The same real DO also covers the absence of
// an overwrite path (refusing to restore into a non-empty DO), refusing a
// partially-failed snapshot, the skip rule, the multipart path, and sweep
// records.

import {
  createExecutionContext,
  createScheduledController,
  env,
  runInDurableObject,
} from "cloudflare:test";
import { Context, Effect } from "effect";
import { describe, expect, it } from "vitest";

import type { Env, OpsBackupOutcome, OpsRestoreOutcome } from "../src/chain-do.ts";
import { makeDbServices, OpsRepo } from "../src/db.package/index.ts";
import { PROJECT_DO_TABLES } from "../src/do-schema.ts";
import { SNAPSHOT_FORMAT, SNAPSHOT_FORMAT_VERSION } from "../src/do-snapshot.ts";
import worker from "../src/index.ts";
import { runBackupSweep } from "../src/ops-backup.ts";
import { OPS_BACKUP_MAX_BYTES, OPS_HOURLY_CRON } from "../src/ops-policy.ts";
import { seedProjectActivity } from "./support/audit-read-scenario.ts";
import { OWNER, projectId, READER, requestJson } from "./support/data-fixture.ts";
import { ENV, registerDataScenario, token } from "./support/data-scenario.ts";
import { evictProjectDo, queryProjectDo, resetProjectDo } from "./support/project-do.ts";

registerDataScenario();

const workerEnv = env as unknown as Env;
const bucket = env.OPS_BACKUP_BUCKET as R2Bucket;
const stub = () => env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
const doIdHex = () => env.PROJECT_CHAIN.idFromName(projectId).toString();

type SkipMarks = { auditSeq: number; chainSeq: number; attestationMark: number };

const backupInput = (skipIfUnchanged: SkipMarks | null = null) => ({
  keyPrefix: "do",
  nowMs: Date.now(),
  maxBytes: OPS_BACKUP_MAX_BYTES,
  skipIfUnchanged,
});

async function backup(skipIfUnchanged: SkipMarks | null = null): Promise<OpsBackupOutcome> {
  return (await stub().opsBackup(backupInput(skipIfUnchanged))) as OpsBackupOutcome;
}

async function restore(objectKey: string): Promise<OpsRestoreOutcome> {
  return (await stub().opsRestore(objectKey)) as OpsRestoreOutcome;
}

/** All rows of every table (rowid order) — for pre/post-restore diffing. */
async function allRows(): Promise<Record<string, Record<string, unknown>[]>> {
  const rows: Record<string, Record<string, unknown>[]> = {};
  for (const table of PROJECT_DO_TABLES) {
    rows[table] = await queryProjectDo(projectId, `SELECT * FROM ${table} ORDER BY rowid`);
  }
  return rows;
}

async function auditHeadViaApi(): Promise<string> {
  const response = await requestJson("GET", "/audit-head", token(OWNER));
  expect(response.status).toBe(200);
  return ((await response.json()) as { auditHeadHashHex: string }).auditHeadHashHex;
}

async function gzipLines(lines: readonly string[]): Promise<Uint8Array> {
  const stream = new Blob([lines.map((line) => `${line}\n`).join("")])
    .stream()
    .pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

describe("DO -> R2 evacuation and restore into an empty DO (hosted-ops.md §2-D / §2-E)", () => {
  it("round-trips chain head, audit head and every row; the object key carries no project id", async () => {
    await seedProjectActivity();
    const headBefore = await auditHeadViaApi();
    const rowsBefore = await allRows();
    expect(rowsBefore["audit_events"]?.length).toBeGreaterThan(3);

    const outcome = await backup();
    expect(outcome.kind).toBe("uploaded");
    if (outcome.kind !== "uploaded") {
      return;
    }
    // key = do/<image of idFromName>/<timestamp>.ndjson.gz — carries no
    // capability (project id)
    expect(outcome.objectKey).toMatch(
      /^do\/[0-9a-f]{64}\/\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.\d{3}Z\.ndjson\.gz$/,
    );
    expect(outcome.objectKey.startsWith(`do/${doIdHex()}/`)).toBe(true);
    expect(outcome.objectKey).not.toContain(projectId);
    expect(outcome.storageLevel).toBe("admit");
    expect(outcome.trailer.auditHeadHashHex).toBe(headBefore);
    for (const table of PROJECT_DO_TABLES) {
      expect(outcome.trailer.rows[table]).toBe(rowsBefore[table]?.length);
    }
    expect(await bucket.head(outcome.objectKey)).not.toBeNull();

    // Empty it and write back (resetProjectDo leaves schema_meta = the same
    // schema version)
    await resetProjectDo(projectId);
    const restored = await restore(outcome.objectKey);
    expect(restored.kind).toBe("restored");
    if (restored.kind !== "restored") {
      return;
    }
    expect(restored.chainHeadSeq).toBe(outcome.trailer.chainHeadSeq);
    expect(restored.chainHeadHashHex).toBe(outcome.trailer.chainHeadHashHex);
    expect(restored.auditMaxSeq).toBe(outcome.trailer.auditMaxSeq);
    expect(restored.auditHeadHashHex).toBe(headBefore);
    expect(restored.rows).toEqual(outcome.trailer.rows);
    expect(await allRows()).toEqual(rowsBefore);
    // Audit seq stays gapless (AUDIT_SPEC §5.1)
    const seqs = (await queryProjectDo(projectId, "SELECT seq FROM audit_events ORDER BY seq")).map(
      (row) => Number(row["seq"]),
    );
    expect(seqs).toEqual(seqs.map((_, index) => index + 1));
    // After restore the product path works as-is (instance memory was
    // discarded — the pre-restore empty state is never served)
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);
    expect(await auditHeadViaApi()).not.toBe(headBefore); // the pull adds a var.read = the head advances
  });

  it("refuses to restore into a non-empty DO (no overwrite path) and leaves it untouched", async () => {
    await seedProjectActivity();
    const outcome = await backup();
    expect(outcome.kind).toBe("uploaded");
    const rowsBefore = await allRows();
    const refused = await restore(outcome.kind === "uploaded" ? outcome.objectKey : "");
    expect(refused).toEqual({ kind: "refused", code: "not-empty" });
    expect(await allRows()).toEqual(rowsBefore);
  });

  it("refuses a missing object, a snapshot without a trailer and a schema mismatch — the DO stays empty", async () => {
    const schemaVersion = Number(
      (await queryProjectDo(projectId, "SELECT version FROM schema_meta WHERE id = 1"))[0]?.[
        "version"
      ],
    );
    await resetProjectDo(projectId);
    expect(await restore("do/missing")).toEqual({ kind: "refused", code: "object-missing" });

    const header = {
      kind: "header",
      format: SNAPSHOT_FORMAT,
      version: SNAPSHOT_FORMAT_VERSION,
      schemaVersion,
      takenAtMs: 1,
      doIdHex: doIdHex(),
    };
    await bucket.put(
      "do/test/truncated.ndjson.gz",
      await gzipLines([
        JSON.stringify(header),
        JSON.stringify({
          kind: "table",
          table: "environments",
          columns: ["environment_id", "name", "latest_meta_version", "created_at", "deleted_at"],
        }),
        JSON.stringify({ kind: "row", table: "environments", values: ["env-x", "X", 1, 1, null] }),
      ]),
    );
    expect(await restore("do/test/truncated.ndjson.gz")).toEqual({
      kind: "refused",
      code: "trailer-missing",
    });
    // The partially written rows are gone (rolled back to empty)
    expect(await queryProjectDo(projectId, "SELECT * FROM environments")).toEqual([]);

    await bucket.put(
      "do/test/schema.ndjson.gz",
      await gzipLines([JSON.stringify({ ...header, schemaVersion: schemaVersion + 1 })]),
    );
    expect(await restore("do/test/schema.ndjson.gz")).toEqual({
      kind: "refused",
      code: "schema-mismatch",
    });
    expect(await queryProjectDo(projectId, "SELECT * FROM chain_entries")).toEqual([]);
  });

  it("refuses snapshot column lists that do not match the live table (injected / reordered / unknown / non-string)", async () => {
    const schemaVersion = Number(
      (await queryProjectDo(projectId, "SELECT version FROM schema_meta WHERE id = 1"))[0]?.[
        "version"
      ],
    );
    await resetProjectDo(projectId);
    const header = {
      kind: "header",
      format: SNAPSHOT_FORMAT,
      version: SNAPSHOT_FORMAT_VERSION,
      schemaVersion,
      takenAtMs: 1,
      doIdHex: doIdHex(),
    };
    const envColumns = [
      "environment_id",
      "name",
      "latest_meta_version",
      "created_at",
      "deleted_at",
    ];
    const chainColumns = (
      await queryProjectDo(
        projectId,
        "SELECT name FROM pragma_table_info('chain_entries') ORDER BY cid",
      )
    ).map((row) => String(row["name"]));
    expect(chainColumns.length).toBeGreaterThan(1);
    const cases: { name: string; table: string; columns: unknown }[] = [
      {
        name: "injected",
        table: "environments",
        columns: [...envColumns.slice(0, 4), "a); DROP TABLE chain_entries; --"],
      },
      {
        name: "injected-chain",
        table: "chain_entries",
        columns: [...chainColumns.slice(0, -1), "a); DROP TABLE chain_entries; --"],
      },
      { name: "reordered", table: "environments", columns: envColumns.toReversed() },
      {
        name: "reordered-chain",
        table: "chain_entries",
        columns: [...chainColumns.slice(1), chainColumns[0]],
      },
      { name: "unknown", table: "environments", columns: [...envColumns.slice(0, 4), "bogus"] },
      { name: "extra", table: "environments", columns: [...envColumns, "bogus"] },
      { name: "non-string", table: "environments", columns: [...envColumns.slice(0, 4), 1] },
      { name: "not-array", table: "environments", columns: "environment_id" },
    ];
    for (const { name, table, columns } of cases) {
      const key = `do/test/columns-${name}.ndjson.gz`;
      await bucket.put(
        key,
        await gzipLines([
          JSON.stringify(header),
          JSON.stringify({ kind: "table", table, columns }),
          JSON.stringify({ kind: "trailer", rows: {} }),
        ]),
      );
      expect(await restore(key), name).toEqual({ kind: "refused", code: "malformed" });
      // The table is not destroyed (no DROP), the DO stays empty, and no
      // staging table is left behind
      expect(await queryProjectDo(projectId, "SELECT * FROM chain_entries"), name).toEqual([]);
      expect(
        await queryProjectDo(
          projectId,
          "SELECT name FROM sqlite_master WHERE name = 'chain_entries_restore'",
        ),
        name,
      ).toEqual([]);
    }
  });

  it("skips when the audit / chain watermarks are unchanged, and uploads again after a pull wrote var.read", async () => {
    await seedProjectActivity();
    const first = await backup();
    expect(first.kind).toBe("uploaded");
    if (first.kind !== "uploaded") {
      return;
    }
    const marks = {
      auditSeq: first.auditSeq,
      chainSeq: first.chainSeq,
      attestationMark: first.attestationMark,
    };
    const second = await backup(marks);
    expect(second.kind).toBe("skipped");
    // The head-attestation upsert writes neither a chain row nor an audit
    // row (AUTH_SPEC §16-1), but counts as a content change that lifts the
    // skip (the third watermark)
    await runInDurableObject(stub(), (_instance, state) => {
      state.storage.sql.exec(
        `INSERT INTO head_attestations (attester_user_id, suite, chain_head_seq, chain_head_hash_hex, signature_hex, attester_key_fingerprint, accepted_at)
         VALUES ('user-attester', 'maruhi/v1', 1, '', '', 'fp', ?)`,
        Date.now(),
      );
    });
    await evictProjectDo(projectId);
    const afterAttestation = await backup(marks);
    expect(afterAttestation.kind).toBe("uploaded");
    if (afterAttestation.kind !== "uploaded") {
      return;
    }
    expect(afterAttestation.attestationMark).toBeGreaterThan(marks.attestationMark);
    marks.attestationMark = afterAttestation.attestationMark;
    expect((await backup(marks)).kind).toBe("skipped");
    // A pull with values writes an audit row (var.read) = treated as changed
    // content, so it evacuates again
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);
    const third = await backup(marks);
    expect(third.kind).toBe("uploaded");
    if (third.kind === "uploaded") {
      expect(third.auditSeq).toBeGreaterThan(marks.auditSeq);
      expect(third.objectKey).not.toBe(first.objectKey); // never overwritten (timestamped keys)
    }
  });

  it("refuses oversize DOs without touching the bucket", async () => {
    await seedProjectActivity();
    const outcome = (await stub().opsBackup({
      ...backupInput(),
      keyPrefix: "oversize-test",
      maxBytes: 1,
    })) as OpsBackupOutcome;
    expect(outcome.kind).toBe("oversize");
    const listed = await bucket.list({ prefix: `oversize-test/${doIdHex()}/` });
    expect(listed.objects).toEqual([]);
  });

  it("completes a multipart upload whose size is an exact multiple of the part size (no empty final part)", async () => {
    await seedProjectActivity();
    await runInDurableObject(stub(), (_instance, state) => {
      for (let version = 2; version <= 200; version++) {
        const random = crypto.getRandomValues(new Uint8Array(32 * 1024));
        const hex = [...random].map((b) => b.toString(16).padStart(2, "0")).join("");
        state.storage.sql.exec(
          `INSERT INTO variable_versions (environment_id, variable_id, version, suite, epoch, nonce_hex, ciphertext_hex, ciphertext_bytes,
             prev_value_sig_hash_hex, chain_head_hash_hex, chain_head_seq, signature_hex, signed_bytes_hash_hex, writer_user_id, writer_key_fingerprint, created_at)
           VALUES ('env-bulk', 'var-bulk', ?, 'maruhi/v1', 1, '00', ?, ?, '', '', 1, '', '', 'user-bulk', 'fp', ?)`,
          version,
          hex,
          hex.length / 2,
          version,
        );
      }
    });
    await evictProjectDo(projectId);
    // Evacuate twice with the same nowMs (= same header, same key): the first
    // run measures the compressed total, and the second uses exactly that
    // total as the part size to force the "0 bytes remaining" path
    const nowMs = Date.now();
    const probe = (await stub().opsBackup({ ...backupInput(), nowMs })) as OpsBackupOutcome;
    expect(probe.kind).toBe("uploaded");
    if (probe.kind !== "uploaded") {
      return;
    }
    expect(probe.bytes).toBeGreaterThan(5 * 1024 * 1024);
    const exact = (await stub().opsBackup({
      ...backupInput(),
      nowMs,
      partBytes: probe.bytes,
    })) as OpsBackupOutcome;
    expect(exact.kind).toBe("uploaded");
    if (exact.kind !== "uploaded") {
      return;
    }
    expect(exact.bytes).toBe(probe.bytes);
    expect((await bucket.head(exact.objectKey))?.size).toBe(probe.bytes);
  });

  it("uses multipart for large snapshots (uniform parts) and still restores identically", async () => {
    await seedProjectActivity();
    // Seed hard-to-compress rows (random-hex ciphertexts) directly to push
    // the compressed size past 5 MiB
    await runInDurableObject(stub(), (_instance, state) => {
      for (let version = 2; version <= 200; version++) {
        const random = crypto.getRandomValues(new Uint8Array(32 * 1024));
        const hex = [...random].map((b) => b.toString(16).padStart(2, "0")).join("");
        state.storage.sql.exec(
          `INSERT INTO variable_versions (environment_id, variable_id, version, suite, epoch, nonce_hex, ciphertext_hex, ciphertext_bytes,
             prev_value_sig_hash_hex, chain_head_hash_hex, chain_head_seq, signature_hex, signed_bytes_hash_hex, writer_user_id, writer_key_fingerprint, created_at)
           VALUES ('env-bulk', 'var-bulk', ?, 'maruhi/v1', 1, '00', ?, ?, '', '', 1, '', '', 'user-bulk', 'fp', ?)`,
          version,
          hex,
          hex.length / 2,
          version,
        );
      }
    });
    await evictProjectDo(projectId);
    // Materialize the audit-head column first (the restore side extends it
    // up to MAX(seq), so evacuating before materialization would make
    // post-restore audit_head_hashes look larger)
    await auditHeadViaApi();
    const rowsBefore = await allRows();
    const outcome = (await stub().opsBackup({
      ...backupInput(),
      partBytes: 5 * 1024 * 1024,
    })) as OpsBackupOutcome;
    expect(outcome.kind).toBe("uploaded");
    if (outcome.kind !== "uploaded") {
      return;
    }
    expect(outcome.bytes).toBeGreaterThan(5 * 1024 * 1024);
    const head = await bucket.head(outcome.objectKey);
    expect(head?.size).toBe(outcome.bytes);
    await resetProjectDo(projectId);
    const restored = await restore(outcome.objectKey);
    expect(restored.kind).toBe("restored");
    expect(await allRows()).toEqual(rowsBefore);
  });
});

const opsRepo = () => Context.get(makeDbServices(env.DB), OpsRepo);

describe("evacuation sweep (ops-backup.ts) and the hourly cron", () => {
  const sweep = (target: Env = workerEnv) =>
    Effect.runPromise(runBackupSweep(target).pipe(Effect.provideService(OpsRepo, opsRepo())));

  it("records a success keyed by project with the DO id image, then skips the unchanged project", async () => {
    await seedProjectActivity();
    const first = await sweep();
    expect(first).toMatchObject({
      enabled: true,
      visited: 1,
      uploaded: 1,
      skipped: 0,
      failed: 0,
      truncated: false,
    });
    const record = await opsRepo().backupRecord(projectId).pipe(Effect.runPromise);
    expect(record).not.toBeNull();
    expect(record?.doIdHex).toBe(doIdHex());
    expect(record?.lastSuccessAt).not.toBeNull();
    expect(record?.storageLevel).toBe("admit");
    expect(record?.lastObjectKey).not.toContain(projectId);
    expect(record?.consecutiveFailures).toBe(0);

    const second = await sweep();
    expect(second).toMatchObject({ visited: 1, uploaded: 0, skipped: 1 });
    const after = await opsRepo().backupRecord(projectId).pipe(Effect.runPromise);
    expect(after?.lastObjectKey).toBe(record?.lastObjectKey);
    // The end was reached, so the cursor returns to the start (empty string)
    expect(await opsRepo().getState("backup_sweep_cursor").pipe(Effect.runPromise)).toBe("");
  });

  it("records oversize without counting it as a consecutive failure (and clears earlier ones)", async () => {
    await seedProjectActivity();
    // Seed one failure first: verifies that recording an oversize resets the
    // counter to 0 on the UPDATE branch too (starting from no row would only
    // exercise the INSERT branch)
    await opsRepo()
      .recordBackupAttempt(
        projectId,
        doIdHex(),
        { kind: "failure", code: "rpc-failed", storageLevel: null },
        Date.now(),
      )
      .pipe(Effect.runPromise);
    const before = await opsRepo().backupRecord(projectId).pipe(Effect.runPromise);
    expect(before?.consecutiveFailures).toBe(1);
    const result = await Effect.runPromise(
      runBackupSweep(workerEnv, { maxBytes: 1 }).pipe(Effect.provideService(OpsRepo, opsRepo())),
    );
    expect(result).toMatchObject({ visited: 1, oversize: 1, failed: 0 });
    const record = await opsRepo().backupRecord(projectId).pipe(Effect.runPromise);
    expect(record?.lastFailureCode).toBe("oversize");
    expect(record?.consecutiveFailures).toBe(0);
    const summary = await opsRepo().backupSummary(Date.now()).pipe(Effect.runPromise);
    expect(summary.oversizeProjects).toBe(1);
    expect(summary.failingProjects).toBe(0);
  });

  it("is a no-op without the bucket binding (self-hosting default)", async () => {
    const { OPS_BACKUP_BUCKET: _bucket, ...withoutBucket } = workerEnv;
    const result = await sweep(withoutBucket);
    expect(result).toMatchObject({ enabled: false, visited: 0 });
    expect(await opsRepo().backupRecord(projectId).pipe(Effect.runPromise)).toBeNull();
  });

  it("honours the visit budget and keeps the cursor for the next run", async () => {
    await seedProjectActivity();
    const result = await Effect.runPromise(
      runBackupSweep(workerEnv, { maxProjects: 0 }).pipe(Effect.provideService(OpsRepo, opsRepo())),
    );
    expect(result).toMatchObject({ visited: 0, truncated: true });
  });

  it("the hourly cron runs the sweep (and leaves the daily session cleanup contract alone)", async () => {
    await seedProjectActivity();
    await worker.scheduled?.(
      createScheduledController({ cron: OPS_HOURLY_CRON }),
      env,
      createExecutionContext(),
    );
    const record = await opsRepo().backupRecord(projectId).pipe(Effect.runPromise);
    expect(record?.lastSuccessAt).not.toBeNull();
  });
});
