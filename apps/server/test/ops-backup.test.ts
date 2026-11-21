import {
  createExecutionContext,
  createScheduledController,
  env,
  runInDurableObject,
} from "cloudflare:test";
import { Context, Effect } from "effect";
import { describe, expect, it, vi } from "vite-plus/test";

import { makeDbServices, OpsRepo } from "../src/db.package/index.ts";
import type { Env } from "../src/do/chain-do.ts";
import type { OpsBackupOutcome, OpsRestoreOutcome } from "../src/do/do-ops.ts";
import { PROJECT_DO_TABLES } from "../src/do/do-schema.ts";
import { SNAPSHOT_FORMAT, SNAPSHOT_FORMAT_VERSION } from "../src/do/do-snapshot.ts";
import worker from "../src/index.ts";
import { runBackupSweep } from "../src/ops/ops-backup.ts";
import { OPS_BACKUP_MAX_BYTES, OPS_HOURLY_CRON } from "../src/ops/ops-policy.ts";
import { ServerLoggerLive } from "../src/server-logger.ts";
import { seedProjectActivity } from "./support/audit-read-scenario.ts";
import { testProjectId } from "./support/data-crypto.ts";
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
    const seqs = (await queryProjectDo(projectId, "SELECT seq FROM audit_events ORDER BY seq")).map(
      (row) => Number(row["seq"]),
    );
    expect(seqs).toEqual(seqs.map((_, index) => index + 1));
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);
    expect(await auditHeadViaApi()).not.toBe(headBefore);
  });

  it("refuses a snapshot whose audit log has a gap: the restored DO stays empty (ruling J revision, round 9)", async () => {
    await seedProjectActivity();
    const outcome = await backup();
    expect(outcome.kind).toBe("uploaded");
    if (outcome.kind !== "uploaded") {
      return;
    }
    const object = await bucket.get(outcome.objectKey);
    const text = await new Response(
      object?.body.pipeThrough(new DecompressionStream("gzip")),
    ).text();
    const lines = text.split("\n").filter((line) => line !== "");
    const tableLine = lines.findIndex((line) => {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      return parsed["kind"] === "table" && parsed["table"] === "audit_events";
    });
    const seqIndex = (
      (JSON.parse(lines[tableLine] ?? "{}") as { columns: string[] }).columns ?? []
    ).indexOf("seq");
    const second = lines.findIndex((line) => {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      return (
        parsed["kind"] === "row" &&
        parsed["table"] === "audit_events" &&
        (parsed["values"] as unknown[])[seqIndex] === 2
      );
    });
    expect(second).toBeGreaterThan(-1);
    const trailer = JSON.parse(lines[lines.length - 1] ?? "{}") as {
      rows: Record<string, number>;
    };
    const gapped = [
      ...lines.slice(0, second),
      ...lines.slice(second + 1, -1),
      JSON.stringify({
        ...trailer,
        rows: { ...trailer.rows, audit_events: (trailer.rows["audit_events"] ?? 1) - 1 },
      }),
    ];
    await bucket.put("do/test/gapped.ndjson.gz", await gzipLines(gapped));
    await resetProjectDo(projectId);
    expect(await restore("do/test/gapped.ndjson.gz")).toEqual({
      kind: "refused",
      code: "malformed",
    });
    expect(await queryProjectDo(projectId, "SELECT COUNT(*) AS n FROM audit_events")).toEqual([
      { n: 0 },
    ]);
    expect(await queryProjectDo(projectId, "SELECT COUNT(*) AS n FROM chain_entries")).toEqual([
      { n: 0 },
    ]);
    expect((await restore(outcome.objectKey)).kind).toBe("restored");
  });

  it("refuses a snapshot with an audit row the canonical form refuses: nothing is promoted, the DO stays empty (ruling J revision, round 10)", async () => {
    await seedProjectActivity();
    const outcome = await backup();
    expect(outcome.kind).toBe("uploaded");
    if (outcome.kind !== "uploaded") {
      return;
    }
    const object = await bucket.get(outcome.objectKey);
    const text = await new Response(
      object?.body.pipeThrough(new DecompressionStream("gzip")),
    ).text();
    const lines = text.split("\n").filter((line) => line !== "");
    const tableLine = lines.findIndex((line) => {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      return parsed["kind"] === "table" && parsed["table"] === "audit_events";
    });
    const columns = (JSON.parse(lines[tableLine] ?? "{}") as { columns: string[] }).columns ?? [];
    const second = lines.findIndex((line) => {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      return (
        parsed["kind"] === "row" &&
        parsed["table"] === "audit_events" &&
        (parsed["values"] as unknown[])[columns.indexOf("seq")] === 2
      );
    });
    expect(second).toBeGreaterThan(-1);
    const row = JSON.parse(lines[second] ?? "{}") as { values: unknown[] };
    const values = [...row.values];
    values[columns.indexOf("server_ts")] = -1;
    const corrupt = lines.map((line, at) =>
      at === second ? JSON.stringify({ ...row, values }) : line,
    );
    await bucket.put("do/test/unhashable.ndjson.gz", await gzipLines(corrupt));
    await resetProjectDo(projectId);
    expect(await restore("do/test/unhashable.ndjson.gz")).toEqual({
      kind: "refused",
      code: "malformed",
    });
    expect(await queryProjectDo(projectId, "SELECT COUNT(*) AS n FROM chain_entries")).toEqual([
      { n: 0 },
    ]);
    expect(await queryProjectDo(projectId, "SELECT COUNT(*) AS n FROM audit_head_hashes")).toEqual([
      { n: 0 },
    ]);
    expect((await restore(outcome.objectKey)).kind).toBe("restored");
  });

  it("refuses a snapshot whose audit row carries a malformed key fingerprint: nothing is promoted, the DO stays empty", async () => {
    await seedProjectActivity();
    const outcome = await backup();
    expect(outcome.kind).toBe("uploaded");
    if (outcome.kind !== "uploaded") {
      return;
    }
    const object = await bucket.get(outcome.objectKey);
    const text = await new Response(
      object?.body.pipeThrough(new DecompressionStream("gzip")),
    ).text();
    const lines = text.split("\n").filter((line) => line !== "");
    const tableLine = lines.findIndex((line) => {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      return parsed["kind"] === "table" && parsed["table"] === "audit_events";
    });
    const columns = (JSON.parse(lines[tableLine] ?? "{}") as { columns: string[] }).columns ?? [];
    const second = lines.findIndex((line) => {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      return (
        parsed["kind"] === "row" &&
        parsed["table"] === "audit_events" &&
        (parsed["values"] as unknown[])[columns.indexOf("seq")] === 2
      );
    });
    expect(second).toBeGreaterThan(-1);
    const row = JSON.parse(lines[second] ?? "{}") as { values: unknown[] };
    const values = [...row.values];
    values[columns.indexOf("actor_key_fingerprint")] = "not-a-fingerprint";
    const corrupt = lines.map((line, at) =>
      at === second ? JSON.stringify({ ...row, values }) : line,
    );
    await bucket.put("do/test/bad-fingerprint.ndjson.gz", await gzipLines(corrupt));
    await resetProjectDo(projectId);
    expect(await restore("do/test/bad-fingerprint.ndjson.gz")).toEqual({
      kind: "refused",
      code: "malformed",
    });
    expect(await queryProjectDo(projectId, "SELECT COUNT(*) AS n FROM chain_entries")).toEqual([
      { n: 0 },
    ]);
    expect(await queryProjectDo(projectId, "SELECT COUNT(*) AS n FROM audit_head_hashes")).toEqual([
      { n: 0 },
    ]);
    expect((await restore(outcome.objectKey)).kind).toBe("restored");
  });

  it("refuses a snapshot that emits a table twice, the trailer counting only the last segment: the DO stays empty", async () => {
    await seedProjectActivity();
    const outcome = await backup();
    expect(outcome.kind).toBe("uploaded");
    if (outcome.kind !== "uploaded") {
      return;
    }
    const object = await bucket.get(outcome.objectKey);
    const text = await new Response(
      object?.body.pipeThrough(new DecompressionStream("gzip")),
    ).text();
    const lines = text.split("\n").filter((line) => line !== "");
    const tableLine = lines.find((line) => {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      return parsed["kind"] === "table" && parsed["table"] === "environments";
    });
    expect(tableLine).toBeDefined();
    const firstRow = lines.find((line) => {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      return parsed["kind"] === "row" && parsed["table"] === "environments";
    });
    expect(firstRow).toBeDefined();
    const row = JSON.parse(firstRow ?? "{}") as { values: unknown[] };
    const extra = JSON.stringify({
      kind: "row",
      table: "environments",
      values: [`${String(row.values[0])}-extra`, ...row.values.slice(1)],
    });
    const trailer = JSON.parse(lines[lines.length - 1] ?? "{}") as {
      rows: Record<string, number>;
    };
    const attacked = [
      ...lines.slice(0, -1),
      tableLine ?? "",
      extra,
      JSON.stringify({ ...trailer, rows: { ...trailer.rows, environments: 1 } }),
    ];
    await bucket.put("do/test/repeated-table.ndjson.gz", await gzipLines(attacked));
    await resetProjectDo(projectId);
    expect(await restore("do/test/repeated-table.ndjson.gz")).toEqual({
      kind: "refused",
      code: "malformed",
    });
    expect(await queryProjectDo(projectId, "SELECT COUNT(*) AS n FROM environments")).toEqual([
      { n: 0 },
    ]);
    expect(await queryProjectDo(projectId, "SELECT COUNT(*) AS n FROM chain_entries")).toEqual([
      { n: 0 },
    ]);
    expect((await restore(outcome.objectKey)).kind).toBe("restored");
  });

  it("refuses a snapshot whose trailer watermarks do not match the restored rows: the DO stays empty", async () => {
    await seedProjectActivity();
    const outcome = await backup();
    expect(outcome.kind).toBe("uploaded");
    if (outcome.kind !== "uploaded") {
      return;
    }
    const object = await bucket.get(outcome.objectKey);
    const text = await new Response(
      object?.body.pipeThrough(new DecompressionStream("gzip")),
    ).text();
    const lines = text.split("\n").filter((line) => line !== "");
    const trailer = JSON.parse(lines[lines.length - 1] ?? "{}") as {
      rows: Record<string, number>;
      chainHeadSeq: number;
      chainHeadHashHex: string;
      auditMaxSeq: number;
      auditHeadHashHex: string | null;
    };
    const cases: { name: string; trailer: typeof trailer }[] = [
      { name: "chain-seq", trailer: { ...trailer, chainHeadSeq: trailer.chainHeadSeq + 1 } },
      { name: "chain-hash", trailer: { ...trailer, chainHeadHashHex: "0".repeat(64) } },
      { name: "audit-seq", trailer: { ...trailer, auditMaxSeq: trailer.auditMaxSeq + 1 } },
      { name: "audit-head", trailer: { ...trailer, auditHeadHashHex: "0".repeat(64) } },
    ];
    await resetProjectDo(projectId);
    for (const { name, trailer: doctored } of cases) {
      const key = `do/test/watermark-${name}.ndjson.gz`;
      await bucket.put(key, await gzipLines([...lines.slice(0, -1), JSON.stringify(doctored)]));
      expect(await restore(key), name).toEqual({ kind: "refused", code: "trailer-mismatch" });
      expect(await queryProjectDo(projectId, "SELECT * FROM chain_entries"), name).toEqual([]);
    }
    expect((await restore(outcome.objectKey)).kind).toBe("restored");
  });

  it("refuses a snapshot whose manifest declares a chain head the staged chain does not carry: the DO stays empty", async () => {
    await seedProjectActivity();
    const outcome = await backup();
    expect(outcome.kind).toBe("uploaded");
    if (outcome.kind !== "uploaded") {
      return;
    }
    const object = await bucket.get(outcome.objectKey);
    const text = await new Response(
      object?.body.pipeThrough(new DecompressionStream("gzip")),
    ).text();
    const lines = text.split("\n").filter((line) => line !== "");
    const tableLine = lines.findIndex((line) => {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      return parsed["kind"] === "table" && parsed["table"] === "environment_manifests";
    });
    const columns = (JSON.parse(lines[tableLine] ?? "{}") as { columns: string[] }).columns ?? [];
    const first = lines.findIndex((line) => {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      return parsed["kind"] === "row" && parsed["table"] === "environment_manifests";
    });
    expect(first).toBeGreaterThan(-1);
    const row = JSON.parse(lines[first] ?? "{}") as { values: unknown[] };
    const values = [...row.values];
    values[columns.indexOf("chain_head_hash_hex")] = "0".repeat(64);
    const attacked = lines.map((line, at) =>
      at === first ? JSON.stringify({ ...row, values }) : line,
    );
    await bucket.put("do/test/foreign-manifest.ndjson.gz", await gzipLines(attacked));
    await resetProjectDo(projectId);
    expect(await restore("do/test/foreign-manifest.ndjson.gz")).toEqual({
      kind: "refused",
      code: "malformed",
    });
    expect(await queryProjectDo(projectId, "SELECT COUNT(*) AS n FROM chain_entries")).toEqual([
      { n: 0 },
    ]);
    expect((await restore(outcome.objectKey)).kind).toBe("restored");
  });

  it("refuses a snapshot that omits the manifest row of a chain-live environment: the DO stays empty", async () => {
    await seedProjectActivity();
    const outcome = await backup();
    expect(outcome.kind).toBe("uploaded");
    if (outcome.kind !== "uploaded") {
      return;
    }
    const object = await bucket.get(outcome.objectKey);
    const text = await new Response(
      object?.body.pipeThrough(new DecompressionStream("gzip")),
    ).text();
    const lines = text.split("\n").filter((line) => line !== "");
    const manifestRow = lines.findIndex((line) => {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      return parsed["kind"] === "row" && parsed["table"] === "environment_manifests";
    });
    expect(manifestRow).toBeGreaterThan(-1);
    const trailer = JSON.parse(lines[lines.length - 1] ?? "{}") as {
      rows: Record<string, number>;
    };
    const attacked = [
      ...lines.slice(0, manifestRow),
      ...lines.slice(manifestRow + 1, -1),
      JSON.stringify({
        ...trailer,
        rows: {
          ...trailer.rows,
          environment_manifests: (trailer.rows["environment_manifests"] ?? 1) - 1,
        },
      }),
    ];
    await bucket.put("do/test/missing-manifest.ndjson.gz", await gzipLines(attacked));
    await resetProjectDo(projectId);
    expect(await restore("do/test/missing-manifest.ndjson.gz")).toEqual({
      kind: "refused",
      code: "malformed",
    });
    expect(await queryProjectDo(projectId, "SELECT COUNT(*) AS n FROM chain_entries")).toEqual([
      { n: 0 },
    ]);
    expect(await queryProjectDo(projectId, "SELECT COUNT(*) AS n FROM environments")).toEqual([
      { n: 0 },
    ]);
    expect((await restore(outcome.objectKey)).kind).toBe("restored");
  });

  it("refuses a snapshot whose checkpoint rows are not exactly the chain's latest tuples (omitted / added): the DO stays empty", async () => {
    await seedProjectActivity();
    const outcome = await backup();
    expect(outcome.kind).toBe("uploaded");
    if (outcome.kind !== "uploaded") {
      return;
    }
    const object = await bucket.get(outcome.objectKey);
    const text = await new Response(
      object?.body.pipeThrough(new DecompressionStream("gzip")),
    ).text();
    const lines = text.split("\n").filter((line) => line !== "");
    const tableLine = lines.findIndex((line) => {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      return parsed["kind"] === "table" && parsed["table"] === "environment_checkpoints";
    });
    const columns = (JSON.parse(lines[tableLine] ?? "{}") as { columns: string[] }).columns ?? [];
    const first = lines.findIndex((line) => {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      return parsed["kind"] === "row" && parsed["table"] === "environment_checkpoints";
    });
    expect(first).toBeGreaterThan(-1);
    const trailer = JSON.parse(lines[lines.length - 1] ?? "{}") as {
      rows: Record<string, number>;
    };
    const count = trailer.rows["environment_checkpoints"] ?? 0;
    const withCount = (rows: number) =>
      JSON.stringify({
        ...trailer,
        rows: { ...trailer.rows, environment_checkpoints: rows },
      });
    const omitted = [...lines.slice(0, first), ...lines.slice(first + 1, -1), withCount(count - 1)];
    const row = JSON.parse(lines[first] ?? "{}") as { values: unknown[] };
    const extraValues = [...row.values];
    const idIndex = columns.indexOf("environment_id");
    extraValues[idIndex] = `${String(row.values[idIndex])}-extra`;
    const added = [
      ...lines.slice(0, first + 1),
      JSON.stringify({ ...row, values: extraValues }),
      ...lines.slice(first + 1, -1),
      withCount(count + 1),
    ];
    await resetProjectDo(projectId);
    for (const [name, doctored] of [
      ["omitted", omitted],
      ["added", added],
    ] as const) {
      const key = `do/test/checkpoints-${name}.ndjson.gz`;
      await bucket.put(key, await gzipLines(doctored));
      expect(await restore(key), name).toEqual({ kind: "refused", code: "malformed" });
      expect(
        await queryProjectDo(projectId, "SELECT COUNT(*) AS n FROM chain_entries"),
        name,
      ).toEqual([{ n: 0 }]);
    }
    expect((await restore(outcome.objectKey)).kind).toBe("restored");
  });

  it("refuses a snapshot whose DEK wrap names an epoch the chain has not opened: the DO stays empty", async () => {
    await seedProjectActivity();
    const outcome = await backup();
    expect(outcome.kind).toBe("uploaded");
    if (outcome.kind !== "uploaded") {
      return;
    }
    const object = await bucket.get(outcome.objectKey);
    const text = await new Response(
      object?.body.pipeThrough(new DecompressionStream("gzip")),
    ).text();
    const lines = text.split("\n").filter((line) => line !== "");
    const tableLine = lines.findIndex((line) => {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      return parsed["kind"] === "table" && parsed["table"] === "dek_wraps";
    });
    const columns = (JSON.parse(lines[tableLine] ?? "{}") as { columns: string[] }).columns ?? [];
    const first = lines.findIndex((line) => {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      return parsed["kind"] === "row" && parsed["table"] === "dek_wraps";
    });
    expect(first).toBeGreaterThan(-1);
    const row = JSON.parse(lines[first] ?? "{}") as { values: unknown[] };
    const values = [...row.values];
    values[columns.indexOf("epoch")] = 99;
    const attacked = lines.map((line, at) =>
      at === first ? JSON.stringify({ ...row, values }) : line,
    );
    await bucket.put("do/test/foreign-wrap.ndjson.gz", await gzipLines(attacked));
    await resetProjectDo(projectId);
    expect(await restore("do/test/foreign-wrap.ndjson.gz")).toEqual({
      kind: "refused",
      code: "malformed",
    });
    expect(await queryProjectDo(projectId, "SELECT COUNT(*) AS n FROM chain_entries")).toEqual([
      { n: 0 },
    ]);
    expect((await restore(outcome.objectKey)).kind).toBe("restored");
  });

  it("restores a chain-less snapshot (header and trailer only) and still accepts the intact snapshot after it", async () => {
    await seedProjectActivity();
    const outcome = await backup();
    expect(outcome.kind).toBe("uploaded");
    if (outcome.kind !== "uploaded") {
      return;
    }
    const schemaVersion = Number(
      (await queryProjectDo(projectId, "SELECT version FROM schema_meta WHERE id = 1"))[0]?.[
        "version"
      ],
    );
    await bucket.put(
      "do/test/chain-less.ndjson.gz",
      await gzipLines([
        JSON.stringify({
          kind: "header",
          format: SNAPSHOT_FORMAT,
          version: SNAPSHOT_FORMAT_VERSION,
          schemaVersion,
          takenAtMs: 1,
          doIdHex: doIdHex(),
        }),
        JSON.stringify({
          kind: "trailer",
          rows: {},
          chainHeadSeq: 0,
          chainHeadHashHex: null,
          auditMaxSeq: 0,
          auditHeadHashHex: "",
          databaseSizeBytes: 0,
        }),
      ]),
    );
    await resetProjectDo(projectId);
    const restored = await restore("do/test/chain-less.ndjson.gz");
    expect(restored.kind).toBe("restored");
    if (restored.kind === "restored") {
      expect(restored.chainHeadSeq).toBe(0);
      expect(restored.chainHeadHashHex).toBeNull();
    }
    expect(await queryProjectDo(projectId, "SELECT COUNT(*) AS n FROM chain_entries")).toEqual([
      { n: 0 },
    ]);
    expect((await restore(outcome.objectKey)).kind).toBe("restored");
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
    expect(await stub().opsRestore("do/test/truncated.ndjson.gz", "0".repeat(32))).toEqual({
      kind: "refused",
      code: "object-changed",
    });
    const current = await bucket.head("do/test/truncated.ndjson.gz");
    expect(await stub().opsRestore("do/test/truncated.ndjson.gz", current?.etag)).toEqual({
      kind: "refused",
      code: "trailer-missing",
    });
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
    const chainColumns = (
      await queryProjectDo(
        projectId,
        "SELECT name FROM pragma_table_info('chain_entries') ORDER BY cid",
      )
    ).map((row) => String(row["name"]));
    expect(chainColumns.length).toBeGreaterThan(1);
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
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);
    const third = await backup(marks);
    expect(third.kind).toBe("uploaded");
    if (third.kind === "uploaded") {
      expect(third.auditSeq).toBeGreaterThan(marks.auditSeq);
      expect(third.objectKey).not.toBe(first.objectKey);
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
    await runInDurableObject(stub(), (_instance, state) => {
      const genesisHash = String(
        state.storage.sql
          .exec("SELECT entry_hash_hex FROM chain_entries WHERE seq = 1")
          .toArray()[0]?.["entry_hash_hex"],
      );
      for (let version = 2; version <= 200; version++) {
        const random = crypto.getRandomValues(new Uint8Array(32 * 1024));
        const hex = [...random].map((b) => b.toString(16).padStart(2, "0")).join("");
        state.storage.sql.exec(
          `INSERT INTO variable_versions (environment_id, variable_id, version, suite, epoch, nonce_hex, ciphertext_hex, ciphertext_bytes,
             prev_value_sig_hash_hex, chain_head_hash_hex, chain_head_seq, signature_hex, signed_bytes_hash_hex, writer_user_id, writer_key_fingerprint, created_at)
           VALUES ('env-bulk', 'var-bulk', ?, 'maruhi/v1', 1, '00', ?, ?, '', ?, 1, '', '', 'user-bulk', 'fp', ?)`,
          version,
          hex,
          hex.length / 2,
          genesisHash,
          version,
        );
      }
    });
    await evictProjectDo(projectId);
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

  it("skips a never-initialized DO without materializing its tables (Sc-7 / A-4)", async () => {
    const fresh = "c9".repeat(32);
    await resetProjectDo(fresh);
    const freshStub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(fresh));
    const outcome = (await freshStub.opsBackup(backupInput())) as OpsBackupOutcome;
    expect(outcome.kind).toBe("skipped");
    expect(
      await queryProjectDo(fresh, "SELECT name FROM sqlite_master WHERE type = 'table'"),
    ).toEqual([]);
  });
});

const opsRepo = () => Context.get(makeDbServices(env.DB), OpsRepo);

const withLogger = <A, E, R>(program: Effect.Effect<A, E, R>) =>
  program.pipe(Effect.provide(ServerLoggerLive));

describe("evacuation sweep (ops-backup.ts) and the hourly cron", () => {
  const sweep = (target: Env = workerEnv) =>
    Effect.runPromise(
      runBackupSweep(target).pipe(Effect.provideService(OpsRepo, opsRepo()), withLogger),
    );

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
    const record = await opsRepo().backupRecord(testProjectId(projectId)).pipe(Effect.runPromise);
    expect(record).not.toBeNull();
    expect(record?.doIdHex).toBe(doIdHex());
    expect(record?.lastSuccessAt).not.toBeNull();
    expect(record?.storageLevel).toBe("admit");
    expect(record?.lastObjectKey).not.toContain(projectId);
    expect(record?.consecutiveFailures).toBe(0);

    const second = await sweep();
    expect(second).toMatchObject({ visited: 1, uploaded: 0, skipped: 1 });
    const after = await opsRepo().backupRecord(testProjectId(projectId)).pipe(Effect.runPromise);
    expect(after?.lastObjectKey).toBe(record?.lastObjectKey);
    expect(await opsRepo().getState("backup_sweep_cursor").pipe(Effect.runPromise)).toBe("");
  });

  it("restarts from the beginning on a malformed stored sweep cursor, with the static warning only", async () => {
    await seedProjectActivity();
    await opsRepo()
      .setState("backup_sweep_cursor", "not-a-project-id", Date.now())
      .pipe(Effect.runPromise);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const result = await sweep();
      expect(result).toMatchObject({ enabled: true, visited: 1, uploaded: 1, truncated: false });
      expect(warn.mock.calls).toEqual([
        ["backup sweep cursor is not a valid project id; restarting the sweep from the beginning"],
      ]);
      expect(JSON.stringify(warn.mock.calls)).not.toContain("not-a-project-id");
    } finally {
      warn.mockRestore();
    }
    expect(await opsRepo().getState("backup_sweep_cursor").pipe(Effect.runPromise)).toBe("");
  });

  it("records oversize without counting it as a consecutive failure (and clears earlier ones)", async () => {
    await seedProjectActivity();
    await opsRepo()
      .recordBackupAttempt(
        testProjectId(projectId),
        doIdHex(),
        { kind: "failure", code: "rpc-failed", storageLevel: null },
        Date.now(),
      )
      .pipe(Effect.runPromise);
    const before = await opsRepo().backupRecord(testProjectId(projectId)).pipe(Effect.runPromise);
    expect(before?.consecutiveFailures).toBe(1);
    const result = await Effect.runPromise(
      runBackupSweep(workerEnv, { maxBytes: 1 }).pipe(
        Effect.provideService(OpsRepo, opsRepo()),
        withLogger,
      ),
    );
    expect(result).toMatchObject({ visited: 1, oversize: 1, failed: 0 });
    const record = await opsRepo().backupRecord(testProjectId(projectId)).pipe(Effect.runPromise);
    expect(record?.lastFailureCode).toBe("oversize");
    expect(record?.consecutiveFailures).toBe(0);
    const summary = await opsRepo().backupSummary(Date.now()).pipe(Effect.runPromise);
    expect(summary.oversizeProjects).toBe(1);
    expect(summary.failingProjects).toBe(0);
  });

  it("records a rejected backup RPC as rpc-failed with the static warning only (RpcCallError, caught by tag)", async () => {
    const rejectionText = "dummy DO failure text";
    const rejecting = {
      idFromName: (name: string) => workerEnv.PROJECT_CHAIN.idFromName(name),
      get: () => ({ opsBackup: () => Promise.reject(new TypeError(rejectionText)) }),
    } as unknown as Env["PROJECT_CHAIN"];
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const result = await sweep({ ...workerEnv, PROJECT_CHAIN: rejecting });
      expect(result).toMatchObject({ enabled: true, visited: 1, uploaded: 0, failed: 1 });
      expect(warn.mock.calls).toEqual([
        ["project backup RPC failed; the project is retried on the next sweep"],
      ]);
      expect(JSON.stringify(warn.mock.calls)).not.toContain(rejectionText);
    } finally {
      warn.mockRestore();
    }
    const record = await opsRepo().backupRecord(testProjectId(projectId)).pipe(Effect.runPromise);
    expect(record?.lastFailureCode).toBe("rpc-failed");
    expect(record?.consecutiveFailures).toBe(1);
  });

  it("is a no-op without the bucket binding (self-hosting default)", async () => {
    const { OPS_BACKUP_BUCKET: _bucket, ...withoutBucket } = workerEnv;
    const result = await sweep(withoutBucket);
    expect(result).toMatchObject({ enabled: false, visited: 0 });
    expect(
      await opsRepo().backupRecord(testProjectId(projectId)).pipe(Effect.runPromise),
    ).toBeNull();
  });

  it("honours the visit budget and keeps the cursor for the next run", async () => {
    await seedProjectActivity();
    const result = await Effect.runPromise(
      runBackupSweep(workerEnv, { maxProjects: 0 }).pipe(
        Effect.provideService(OpsRepo, opsRepo()),
        withLogger,
      ),
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
    const record = await opsRepo().backupRecord(testProjectId(projectId)).pipe(Effect.runPromise);
    expect(record?.lastSuccessAt).not.toBeNull();
  });
});
