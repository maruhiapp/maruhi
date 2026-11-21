import { testUserId } from "@maruhi/crypto/test-support";
import { env, runInDurableObject } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vite-plus/test";

import {
  isMutationTracked,
  PROJECT_DO_LATEST_SCHEMA_VERSION,
  PROJECT_DO_TABLES,
  readProjectDoSchemaVersion,
} from "../src/do/do-schema.ts";
import { exportSnapshotPage, type ExportCursorState } from "../src/do/do-snapshot-export.ts";
import { SNAPSHOT_FORMAT_VERSION } from "../src/do/do-snapshot.ts";
import { MAX_EXPORTS_PER_WINDOW } from "../src/policy.ts";
import type { RestoreJobResult } from "../src/restore-worker.ts";
import { processRestoreJobs } from "../src/restore-worker.ts";
import { fetchEvents, seedProjectActivity } from "./support/audit-read-scenario.ts";
import { cliToken, resetAuthDb, seedUser } from "./support/auth.ts";
import { addMemberOperation, changeRoleOperation } from "./support/data-crypto.ts";
import {
  appendOperation,
  createEnvironmentOk,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
  STRANGER,
} from "./support/data-fixture.ts";
import {
  createVariableOk,
  ENV,
  fixture,
  registerDataScenario,
  token,
  VAR,
} from "./support/data-scenario.ts";
import {
  evictProjectDo,
  queryProjectDo,
  readAuditEvents,
  resetProjectDo,
} from "./support/project-do.ts";

registerDataScenario();

const bucket = env.OPS_BACKUP_BUCKET as R2Bucket;
const restoreEnv = {
  OPS_BACKUP_BUCKET: bucket,
  PRODUCTION_PROJECT_CHAIN: env.PROJECT_CHAIN,
  DB: env.DB,
};

beforeEach(async () => {
  const listed = await bucket.list({ prefix: "restore/" });
  if (listed.objects.length > 0) {
    await bucket.delete(listed.objects.map((object) => object.key));
  }
});

interface WirePage {
  readonly lines: readonly string[];
  readonly next?: string;
  readonly head: {
    readonly chainHeadSeq: number;
    readonly chainHeadHashHex: string;
    readonly auditMaxSeq: number;
  };
}

interface WireIdentities {
  readonly exportedBy: string;
  readonly identities: readonly {
    readonly userId: string;
    readonly provider: string;
    readonly providerUserId: string;
    readonly providerLogin?: string;
  }[];
  readonly unlinked: readonly string[];
}

async function exportPage(userId: string, cursor?: string): Promise<Response> {
  return requestJson(
    "GET",
    `/export${cursor === undefined ? "" : `?cursor=${encodeURIComponent(cursor)}`}`,
    token(userId),
  );
}

async function exportAll(): Promise<{ lines: string[]; pages: WirePage[] }> {
  const lines: string[] = [];
  const pages: WirePage[] = [];
  let cursor: string | undefined;
  for (;;) {
    const response = await exportPage(OWNER, cursor);
    if (response.status !== 200) {
      throw new Error(`export page failed: ${response.status} ${await response.text()}`);
    }
    const page = (await response.json()) as WirePage;
    pages.push(page);
    lines.push(...page.lines);
    cursor = page.next;
    if (cursor === undefined) {
      return { lines, pages };
    }
  }
}

function parsedLine(line: string | undefined): Record<string, unknown> {
  return JSON.parse(line ?? "{}") as Record<string, unknown>;
}

function rowCounts(lines: readonly string[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const line of lines) {
    const parsed = parsedLine(line);
    const table = String(parsed["table"]);
    if (parsed["kind"] === "table") {
      counts[table] = 0;
    } else if (parsed["kind"] === "row") {
      counts[table] = (counts[table] ?? 0) + 1;
    }
  }
  return counts;
}

async function gzipLines(lines: readonly string[]): Promise<Uint8Array> {
  const stream = new Blob([`${lines.join("\n")}\n`])
    .stream()
    .pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

function base64Url(text: string): string {
  return btoa(text).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

async function expectStatusOk(response: Response): Promise<void> {
  if (response.status !== 200) {
    throw new Error(`expected HTTP 200, got ${response.status}: ${await response.clone().text()}`);
  }
}

async function jobResult(name: string): Promise<RestoreJobResult> {
  const object = await bucket.get(`restore/results/${name}.json`);
  expect(object).not.toBeNull();
  return (await object?.json()) as RestoreJobResult;
}

async function exportToBucket(): Promise<{
  readonly objectKey: string;
  readonly identitiesKey: string;
  readonly trailer: Record<string, unknown>;
  readonly identities: WireIdentities;
}> {
  const { lines } = await exportAll();
  const objectKey = `do/export-test/${Date.now()}.ndjson.gz`;
  await bucket.put(objectKey, await gzipLines(lines));
  const identitiesResponse = await requestJson("GET", "/export/identities", token(OWNER));
  expect(identitiesResponse.status).toBe(200);
  const identities = (await identitiesResponse.json()) as WireIdentities;
  const identitiesKey = `${objectKey}.identities.json`;
  await bucket.put(identitiesKey, JSON.stringify(identities));
  return { objectKey, identitiesKey, trailer: parsedLine(lines[lines.length - 1]), identities };
}

async function expectDestinationUnmaterialized(): Promise<void> {
  expect(
    await queryProjectDo(projectId, "SELECT name FROM sqlite_master WHERE type = 'table'"),
  ).toEqual([]);
}

async function liveCounts(): Promise<Record<string, number>> {
  const counts: Record<string, number> = {};
  for (const table of PROJECT_DO_TABLES) {
    const rows = await queryProjectDo(projectId, `SELECT COUNT(*) AS n FROM ${table}`);
    counts[table] = Number(rows[0]?.["n"] ?? 0);
  }
  return counts;
}

async function importWith(
  name: string,
  objectKey: string,
  companion: unknown,
): Promise<RestoreJobResult> {
  const identitiesKey = `restore/${name}.identities.json`;
  await bucket.put(identitiesKey, JSON.stringify(companion));
  await bucket.put(
    `restore/jobs/${name}.json`,
    JSON.stringify({ objectKey, target: "production", identitiesKey }),
  );
  expect(await processRestoreJobs(restoreEnv)).toEqual([name]);
  return jobResult(name);
}

async function d1Rows(query: string, ...bindings: (string | number)[]) {
  return (
    await env.DB.prepare(query)
      .bind(...bindings)
      .all()
  ).results;
}

function readProjectDoSchemaVersionOf(): number {
  return PROJECT_DO_LATEST_SCHEMA_VERSION;
}

describe("project export (AUTH_SPEC §11-6)", () => {
  it("pages the project in the evacuation format, records project.exported, and the restore path accepts the file", async () => {
    await seedProjectActivity();
    expect((await requestJson("GET", "/audit-head", token(OWNER))).status).toBe(200);
    const { lines, pages } = await exportAll();
    const header = parsedLine(lines[0]);
    expect(header).toMatchObject({ kind: "header", format: "maruhi-do-snapshot", version: 1 });
    const trailer = parsedLine(lines[lines.length - 1]);
    expect(trailer["kind"]).toBe("trailer");
    expect(trailer["rows"]).toEqual(rowCounts(lines));
    expect(trailer["rows"]).toEqual(await liveCounts());
    expect(trailer["chainHeadSeq"]).toBe(fixture.head.seq);
    expect(trailer["chainHeadHashHex"]).toBe(fixture.head.hashHex);
    expect(pages[0]?.head.chainHeadHashHex).toBe(fixture.head.hashHex);
    const exportedSeq = await queryProjectDo(
      projectId,
      "SELECT seq FROM audit_events WHERE event = 'project.exported'",
    );
    expect(pages[0]?.head.auditMaxSeq).toBe(exportedSeq[0]?.["seq"]);
    const tables = lines
      .map((line) => parsedLine(line))
      .filter((line) => line["kind"] === "table")
      .map((line) => line["table"]);
    expect(tables[tables.length - 1]).toBe("chain_entries");
    const exported = (await readAuditEvents(projectId)).filter(
      (event) => event["event"] === "project.exported",
    );
    expect(exported).toHaveLength(1);
    expect(exported[0]).toMatchObject({ actor_type: "user", actor_user_id: OWNER });
    expect(JSON.parse(String(exported[0]?.["payload"]))).toMatchObject({
      chainHeadSeq: fixture.head.seq,
    });
    expect(lines.some((line) => line.includes('"project.exported"'))).toBe(true);
    const objectKey = "do/export-test/roundtrip.ndjson.gz";
    await bucket.put(objectKey, await gzipLines(lines));
    await resetProjectDo(projectId);
    await bucket.put(
      "restore/jobs/export-roundtrip.json",
      JSON.stringify({ objectKey, target: "production" }),
    );
    expect(await processRestoreJobs(restoreEnv)).toEqual(["export-roundtrip"]);
    const outcome = await jobResult("export-roundtrip");
    expect(outcome.status).toBe("ok");
    if (outcome.status === "ok") {
      expect(outcome.verification.chainHeadSeq).toBe(trailer["chainHeadSeq"]);
      expect(outcome.verification.chainHeadHashHex).toBe(trailer["chainHeadHashHex"]);
      expect(outcome.verification.rows).toEqual(trailer["rows"]);
      expect(outcome.identities).toBeUndefined();
    }
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);
  });

  it("pages respect the row and byte bounds, resume mid-table, and add up to the live tables", async () => {
    await seedProjectActivity();
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
    const exportedSeq = Number(
      (await queryProjectDo(projectId, "SELECT COALESCE(MAX(seq), 0) AS m FROM audit_events"))[0]?.[
        "m"
      ],
    );
    const pages = await runInDurableObject(stub, (_instance, state) => {
      const sql = state.storage.sql;
      const collected: { lines: readonly string[]; bytes: number; rows: number }[] = [];
      let cursor: ExportCursorState | null = null;
      for (let n = 0; n < 10_000; n += 1) {
        const page = exportSnapshotPage({
          sql,
          tables: PROJECT_DO_TABLES,
          schemaVersion: readProjectDoSchemaVersion(sql),
          doIdHex: "ab".repeat(32),
          takenAtMs: 1_700_000_000_000,
          cursor,
          exportedSeq,
          maxRows: 3,
          maxBytes: 700,
        });
        if (page.kind !== "page") {
          throw new Error("unexpected change");
        }
        if (n === 1) {
          sql.exec(
            "INSERT INTO audit_events (seq, row_id, server_ts, event, actor_type) VALUES (?, ?, ?, 'var.read', 'user')",
            exportedSeq + 1,
            "row-read-between-pages",
            Date.now(),
          );
        }
        const encoder = new TextEncoder();
        collected.push({
          lines: page.lines,
          bytes: page.lines.reduce((sum, line) => sum + encoder.encode(line).length + 1, 0),
          rows: page.lines.filter((line) => parsedLine(line)["kind"] === "row").length,
        });
        cursor = page.next;
        if (cursor === null) {
          return collected;
        }
      }
      throw new Error("no trailer");
    });
    expect(pages.length).toBeGreaterThan(3);
    const all = pages.flatMap((page) => page.lines);
    expect(parsedLine(all[0])["kind"]).toBe("header");
    expect(parsedLine(all[all.length - 1])["kind"]).toBe("trailer");
    const live = await liveCounts();
    expect(live["audit_events"]).toBe(exportedSeq + 1);
    const bounded = { ...live, audit_events: exportedSeq };
    expect(rowCounts(all)).toEqual(bounded);
    const trailer = parsedLine(all[all.length - 1]);
    expect(trailer["rows"]).toEqual(bounded);
    expect(trailer["auditMaxSeq"]).toBe(exportedSeq);
    for (const page of pages) {
      expect(page.rows).toBeLessThanOrEqual(3);
      const last = page.lines[page.lines.length - 1] ?? "";
      expect(page.bytes - (new TextEncoder().encode(last).length + 1)).toBeLessThan(700);
    }
    const tables = all.map((line) => parsedLine(line)).filter((line) => line["kind"] === "table");
    expect(new Set(tables.map((line) => line["table"])).size).toBe(tables.length);
  });

  it("is owner-only on both endpoints: members, admins and readers 403, strangers the uniform 404", async () => {
    await seedProjectActivity();
    expect((await exportPage(MEMBER)).status).toBe(403);
    expect((await exportPage(READER)).status).toBe(403);
    expect((await exportPage(STRANGER)).status).toBe(404);
    expect((await requestJson("GET", "/export/identities", token(MEMBER))).status).toBe(403);
    expect((await requestJson("GET", "/export/identities", token(STRANGER))).status).toBe(404);
    await appendOperation(fixture, OWNER, changeRoleOperation(MEMBER, "admin"));
    expect((await exportPage(MEMBER)).status).toBe(403);
    expect((await requestJson("GET", "/export/identities", token(MEMBER))).status).toBe(403);
    const exported = (await readAuditEvents(projectId)).filter(
      (event) => event["event"] === "project.exported",
    );
    expect(exported).toHaveLength(0);
    await expectStatusOk(await exportPage(OWNER));
    const ownerView = await fetchEvents(token(OWNER), { eventPrefix: "project." });
    expect(ownerView.events.map((event) => event.event)).toContain("project.exported");
    const memberView = await fetchEvents(token(READER), { eventPrefix: "project." });
    expect(memberView.events.map((event) => event.event)).not.toContain("project.exported");
  });

  it("refuses a foreign or stale cursor with 409, continues on a current one, and bounds the window with 429", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const first = await exportPage(OWNER);
    expect(first.status).toBe(200);
    const head = ((await first.json()) as WirePage).head;
    const foreign = await exportPage(OWNER, base64Url(JSON.stringify({ hello: "world" })));
    expect(foreign.status).toBe(409);
    expect(await foreign.json()).toMatchObject({ _tag: "ExportChanged" });
    const mutation = await queryProjectDo(projectId, "SELECT seq FROM mutation_state WHERE id = 1");
    const cursorOf = (overrides: Record<string, unknown>) =>
      base64Url(
        JSON.stringify({
          table: 0,
          started: false,
          rowid: -1,
          rows: {},
          exportedSeq: head.auditMaxSeq,
          marks: {
            chainHeadSeq: head.chainHeadSeq,
            chainHeadHashHex: head.chainHeadHashHex,
            mutationSeq: Number(mutation[0]?.["seq"] ?? 0),
            schemaVersion: readProjectDoSchemaVersionOf(),
            formatVersion: SNAPSHOT_FORMAT_VERSION,
          },
          ...overrides,
        }),
      );
    const current = cursorOf({});
    const continued = await exportPage(OWNER, current);
    expect(continued.status).toBe(200);
    const page = (await continued.json()) as WirePage;
    expect(parsedLine(page.lines[0])["kind"]).toBe("table");
    expect((await requestJson("GET", `/environments/${ENV}/pull`, token(READER))).status).toBe(200);
    expect((await exportPage(OWNER, current)).status).toBe(200);
    const liveAudit = await queryProjectDo(projectId, "SELECT COUNT(*) AS n FROM audit_events");
    expect(Number(liveAudit[0]?.["n"])).toBeGreaterThan(head.auditMaxSeq);
    await appendOperation(fixture, OWNER, changeRoleOperation(MEMBER, "owner"));
    const afterPromotion = await exportPage(OWNER);
    expect(afterPromotion.status).toBe(200);
    const ownersHead = ((await afterPromotion.json()) as WirePage).head;
    const ownersMutation = await queryProjectDo(
      projectId,
      "SELECT seq FROM mutation_state WHERE id = 1",
    );
    const ownersCursor = (overrides: Record<string, unknown>) =>
      cursorOf({
        exportedSeq: ownersHead.auditMaxSeq,
        marks: {
          chainHeadSeq: ownersHead.chainHeadSeq,
          chainHeadHashHex: ownersHead.chainHeadHashHex,
          mutationSeq: Number(ownersMutation[0]?.["seq"] ?? 0),
          schemaVersion: readProjectDoSchemaVersionOf(),
          formatVersion: SNAPSHOT_FORMAT_VERSION,
        },
        ...overrides,
      });
    expect((await exportPage(OWNER, ownersCursor({}))).status).toBe(200);
    expect((await exportPage(MEMBER, ownersCursor({}))).status).toBe(409);
    expect(
      (
        await exportPage(
          OWNER,
          ownersCursor({
            marks: {
              chainHeadSeq: ownersHead.chainHeadSeq,
              chainHeadHashHex: ownersHead.chainHeadHashHex,
              mutationSeq: Number(ownersMutation[0]?.["seq"] ?? 0),
              schemaVersion: readProjectDoSchemaVersionOf() + 1,
              formatVersion: SNAPSHOT_FORMAT_VERSION,
            },
          }),
        )
      ).status,
    ).toBe(409);
    expect((await exportPage(OWNER, ownersCursor({ exportedSeq: 1 }))).status).toBe(409);
    const beyond = base64Url(
      JSON.stringify({ ...JSON.parse(atob(current)), table: 999, started: false }),
    );
    expect((await exportPage(OWNER, beyond)).status).toBe(409);
    const fractional = base64Url(
      JSON.stringify({ ...JSON.parse(atob(current)), table: 0.5, rowid: -2 }),
    );
    expect((await exportPage(OWNER, fractional)).status).toBe(409);
    await createVariableOk(dek, "var-second-0002", "SECOND", "value-two");
    const stale = await exportPage(OWNER, ownersCursor({}));
    expect(stale.status).toBe(409);
    await queryProjectDo(
      projectId,
      "UPDATE lease_windows SET count = ?, window_start = ? WHERE kind = 'exported'",
      MAX_EXPORTS_PER_WINDOW,
      Date.now(),
    );
    const limited = await exportPage(OWNER);
    expect(limited.status).toBe(429);
    expect(await limited.json()).toMatchObject({ _tag: "ExportRateLimited" });
    expect((await exportPage(OWNER, ownersCursor({}))).status).toBe(409);
  });

  it("refuses a continuation whose exported row's payload does not decode to the cursor's head (ruling D revision)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const first = await exportPage(OWNER);
    expect(first.status).toBe(200);
    const head = ((await first.json()) as WirePage).head;
    const exportedSeq = head.auditMaxSeq;
    const mutation = await queryProjectDo(projectId, "SELECT seq FROM mutation_state WHERE id = 1");
    const cursor = base64Url(
      JSON.stringify({
        table: 0,
        started: false,
        rowid: -1,
        rows: {},
        exportedSeq,
        marks: {
          chainHeadSeq: head.chainHeadSeq,
          chainHeadHashHex: head.chainHeadHashHex,
          mutationSeq: Number(mutation[0]?.["seq"] ?? 0),
          schemaVersion: readProjectDoSchemaVersionOf(),
          formatVersion: SNAPSHOT_FORMAT_VERSION,
        },
      }),
    );
    const stored = (
      await queryProjectDo(projectId, "SELECT payload FROM audit_events WHERE seq = ?", exportedSeq)
    )[0];
    const payload = String(stored?.["payload"]);
    expect(JSON.parse(payload)).toMatchObject({
      chainHeadSeq: head.chainHeadSeq,
      chainHeadHashHex: head.chainHeadHashHex,
    });
    const writePayload = (text: string) =>
      queryProjectDo(
        projectId,
        "UPDATE audit_events SET payload = ? WHERE seq = ?",
        text,
        exportedSeq,
      );
    expect((await exportPage(OWNER, cursor)).status).toBe(200);
    for (const bad of [
      "not json",
      "5",
      '"x"',
      "null",
      "{}",
      JSON.stringify([head.chainHeadSeq, head.chainHeadHashHex]),
      JSON.stringify({ chainHeadSeq: head.chainHeadSeq }),
      JSON.stringify({ chainHeadSeq: "1", chainHeadHashHex: head.chainHeadHashHex }),
      JSON.stringify({
        chainHeadSeq: head.chainHeadSeq + 1,
        chainHeadHashHex: head.chainHeadHashHex,
      }),
      JSON.stringify({ chainHeadSeq: head.chainHeadSeq, chainHeadHashHex: "00" }),
    ]) {
      await writePayload(bad);
      const refused = await exportPage(OWNER, cursor);
      expect(refused.status).toBe(409);
      expect(await refused.json()).toMatchObject({ _tag: "ExportChanged" });
    }
    await writePayload(payload);
    expect((await exportPage(OWNER, cursor)).status).toBe(200);
  });

  it("exports the audit log up to the mark: the trailer's counts stay the first page's after reads in between", async () => {
    await seedProjectActivity();
    const first = await exportPage(OWNER);
    expect(first.status).toBe(200);
    const page = (await first.json()) as WirePage;
    expect((await requestJson("GET", `/environments/${ENV}/pull`, token(READER))).status).toBe(200);
    expect((await requestJson("GET", `/environments/${ENV}/pull`, token(MEMBER))).status).toBe(200);
    const lines = [...page.lines];
    let cursor = page.next;
    while (cursor !== undefined) {
      const next = await exportPage(OWNER, cursor);
      expect(next.status).toBe(200);
      const parsed = (await next.json()) as WirePage;
      lines.push(...parsed.lines);
      cursor = parsed.next;
    }
    const trailer = parsedLine(lines[lines.length - 1]);
    expect(trailer["auditMaxSeq"]).toBe(page.head.auditMaxSeq);
    expect((trailer["rows"] as Record<string, number>)["audit_events"]).toBe(page.head.auditMaxSeq);
    expect(trailer["rows"]).toEqual(rowCounts(lines));
    const live = await liveCounts();
    expect(live["audit_events"]).toBeGreaterThan(page.head.auditMaxSeq);
    const objectKey = "do/export-test/bounded.ndjson.gz";
    await bucket.put(objectKey, await gzipLines(lines));
    await resetProjectDo(projectId);
    await bucket.put(
      "restore/jobs/export-bounded.json",
      JSON.stringify({ objectKey, target: "production" }),
    );
    expect(await processRestoreJobs(restoreEnv)).toEqual(["export-bounded"]);
    const outcome = await jobResult("export-bounded");
    expect(outcome.status).toBe("ok");
    if (outcome.status === "ok") {
      expect(outcome.verification.auditMaxSeq).toBe(page.head.auditMaxSeq);
      expect(outcome.verification.auditHeadHashHex).toBe(trailer["auditHeadHashHex"]);
    }
  });

  it("the identities companion lists the current members' provider identities and names an unlinked member", async () => {
    await seedProjectActivity();
    const DEV = testUserId("user-devmember-0010");
    await appendOperation(fixture, OWNER, addMemberOperation(DEV, "member"));
    const response = await requestJson("GET", "/export/identities", token(OWNER));
    expect(response.status).toBe(200);
    const body = (await response.json()) as WireIdentities;
    expect(body.exportedBy).toBe(OWNER);
    expect(body.unlinked).toEqual([DEV]);
    expect(body.identities.map((identity) => identity.userId)).toEqual(
      [OWNER, MEMBER, READER].toSorted(),
    );
    expect(body.identities.find((identity) => identity.userId === MEMBER)).toEqual({
      userId: MEMBER,
      provider: "github",
      providerUserId: "9002",
      providerLogin: "user9002",
    });
    expect(JSON.stringify(body)).not.toContain(STRANGER);
    expect(JSON.stringify(body)).not.toContain("9009");
  });
});

describe("project import (the restore job with identitiesKey)", () => {
  it("provisions the members with the chain's user ids, and the first login on the destination lands on them", async () => {
    await seedProjectActivity();
    const { objectKey, identitiesKey, trailer } = await exportToBucket();
    await resetProjectDo(projectId);
    await resetAuthDb();
    await bucket.put(
      "restore/jobs/import-1.json",
      JSON.stringify({ objectKey, target: "production", identitiesKey }),
    );
    expect(await processRestoreJobs(restoreEnv)).toEqual(["import-1"]);
    const outcome = await jobResult("import-1");
    expect(outcome.status).toBe("ok");
    expect(outcome.identities).toEqual({
      kind: "provisioned",
      existing: 0,
      created: 3,
      members: 3,
      project: "created",
    });
    if (outcome.status === "ok") {
      expect(outcome.verification.chainHeadHashHex).toBe(trailer["chainHeadHashHex"]);
    }
    expect((await d1Rows("SELECT id FROM users ORDER BY id")).map((row) => row["id"])).toEqual(
      [OWNER, MEMBER, READER].toSorted(),
    );
    expect(
      await d1Rows(
        "SELECT user_id FROM linked_identities WHERE provider = 'github' AND provider_user_id = '9001'",
      ),
    ).toEqual([{ user_id: OWNER }]);
    const ownerOrg = await d1Rows(
      "SELECT id FROM organizations WHERE slug = ?",
      `u-${OWNER.toLowerCase()}`,
    );
    expect(ownerOrg).toHaveLength(1);
    expect(await d1Rows("SELECT org_id FROM projects WHERE id = ?", projectId)).toEqual([
      { org_id: ownerOrg[0]?.["id"] },
    ]);
    expect(
      (
        await d1Rows(
          "SELECT user_id FROM project_members WHERE project_id = ? ORDER BY user_id",
          projectId,
        )
      ).map((row) => row["user_id"]),
    ).toEqual([OWNER, MEMBER, READER].toSorted());
    expect(
      await d1Rows("SELECT COUNT(*) AS n FROM user_audit_events WHERE event = 'auth.user_created'"),
    ).toEqual([{ n: 3 }]);
    const created = await d1Rows(
      "SELECT payload FROM org_audit_events WHERE event = 'org.project_created'",
    );
    expect(JSON.parse(String(created[0]?.["payload"]))).toMatchObject({ imported: true });
    const ownerToken = await cliToken(9001);
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, ownerToken);
    expect(pull.status).toBe(200);
    const listed = await requestJson("GET", "/chain", ownerToken);
    expect(listed.status).toBe(200);
    await bucket.put(
      "restore/jobs/import-2.json",
      JSON.stringify({ objectKey, target: "production", identitiesKey }),
    );
    expect(await processRestoreJobs(restoreEnv)).toEqual(["import-2"]);
    expect(await jobResult("import-2")).toEqual({
      status: "failed",
      code: "not-empty",
      identities: { kind: "provisioned", existing: 3, created: 0, members: 3, project: "kept" },
    });
    expect(await d1Rows("SELECT COUNT(*) AS n FROM projects")).toEqual([{ n: 1 }]);
    await env.DB.batch([
      env.DB.prepare("DELETE FROM project_members WHERE user_id = ?").bind(READER),
      env.DB.prepare("DELETE FROM memberships WHERE user_id = ?").bind(READER),
      env.DB.prepare("DELETE FROM org_audit_events WHERE actor_user_id = ?").bind(READER),
      env.DB.prepare("DELETE FROM user_audit_events WHERE actor_user_id = ?").bind(READER),
      env.DB.prepare("DELETE FROM organizations WHERE slug = ?").bind(`u-${READER.toLowerCase()}`),
      env.DB.prepare("DELETE FROM linked_identities WHERE user_id = ?").bind(READER),
      env.DB.prepare("DELETE FROM users WHERE id = ?").bind(READER),
    ]);
    await bucket.put(
      "restore/jobs/import-3.json",
      JSON.stringify({ objectKey, target: "production", identitiesKey }),
    );
    expect(await processRestoreJobs(restoreEnv)).toEqual(["import-3"]);
    expect((await jobResult("import-3")).identities).toEqual({
      kind: "provisioned",
      existing: 2,
      created: 1,
      members: 3,
      project: "kept",
    });
    expect(await d1Rows("SELECT COUNT(*) AS n FROM users")).toEqual([{ n: 3 }]);
    expect(
      await d1Rows(
        "SELECT COUNT(*) AS n FROM org_audit_events WHERE event = 'org.project_created'",
      ),
    ).toEqual([{ n: 1 }]);
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO organizations (id, slug, name, created_at) VALUES ('org-other-0001', 'other-org', 'Other', 0)",
      ),
      env.DB.prepare("UPDATE projects SET org_id = 'org-other-0001' WHERE id = ?").bind(projectId),
    ]);
    await bucket.put(
      "restore/jobs/import-4.json",
      JSON.stringify({ objectKey, target: "production", identitiesKey }),
    );
    expect(await processRestoreJobs(restoreEnv)).toEqual(["import-4"]);
    expect(await jobResult("import-4")).toEqual({
      status: "failed",
      code: "import-refused",
      identities: { kind: "refused", code: "project-exists" },
    });
    expect(JSON.stringify(outcome)).not.toContain(projectId);
  });

  function expectedTriggers(table: string): string[] {
    if (isMutationTracked(table)) {
      return [`mutation_${table}_delete`, `mutation_${table}_insert`, `mutation_${table}_update`];
    }
    return table === "audit_events" ? ["mutation_audit_events_write"] : [];
  }

  async function counterSeq(): Promise<number> {
    const rows = await queryProjectDo(projectId, "SELECT seq FROM mutation_state WHERE id = 1");
    return Number(rows[0]?.["seq"]);
  }

  it("the mutation counter is the schema's: every tracked snapshot table carries the three triggers and a direct row change moves it", async () => {
    await seedProjectActivity();
    for (const table of PROJECT_DO_TABLES) {
      const triggers = await queryProjectDo(
        projectId,
        "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ? ORDER BY name",
        table,
      );
      expect(triggers.map((row) => row["name"])).toEqual(expectedTriggers(table));
    }
    const triggered = await queryProjectDo(
      projectId,
      "SELECT DISTINCT tbl_name FROM sqlite_master WHERE type = 'trigger' ORDER BY tbl_name",
    );
    expect(
      triggered
        .map((row) => String(row["tbl_name"]))
        .every((table) => PROJECT_DO_TABLES.includes(table)),
    ).toBe(true);
    const before = await counterSeq();
    await queryProjectDo(projectId, "UPDATE variables SET name = name");
    const after = await counterSeq();
    expect(after).toBeGreaterThan(before);
    const auditRow = (event: string, rowId: string) =>
      queryProjectDo(
        projectId,
        "INSERT INTO audit_events (server_ts, event, actor_type, row_id) VALUES (1, ?, 'system', ?)",
        event,
        rowId,
      );
    await auditRow("rotation.dismissed", "ff".repeat(16));
    const afterWrite = await counterSeq();
    expect(afterWrite).toBe(after + 1);
    await auditRow("var.read", "fe".repeat(16));
    expect(await counterSeq()).toBe(afterWrite);
    const auditTrigger = await queryProjectDo(
      projectId,
      "SELECT rowid, sql FROM sqlite_master WHERE type = 'trigger' AND name = 'mutation_audit_events_write'",
    );
    await evictProjectDo(projectId);
    expect(
      await queryProjectDo(
        projectId,
        "SELECT rowid, sql FROM sqlite_master WHERE type = 'trigger' AND name = 'mutation_audit_events_write'",
      ),
    ).toEqual(auditTrigger);
    await queryProjectDo(projectId, "DROP TRIGGER mutation_audit_events_write");
    await queryProjectDo(
      projectId,
      "CREATE TRIGGER mutation_audit_events_write AFTER INSERT ON audit_events WHEN NEW.event NOT IN ('var.read') BEGIN INSERT INTO mutation_state (id, seq) VALUES (1, 1) ON CONFLICT(id) DO UPDATE SET seq = seq + 1; END",
    );
    await evictProjectDo(projectId);
    const reasserted = await queryProjectDo(
      projectId,
      "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'mutation_audit_events_write'",
    );
    expect(String(reasserted[0]?.["sql"])).toContain("'server.lease_issued'");
    expect(String(reasserted[0]?.["sql"])).toContain("'project.exported'");
    const current = String(reasserted[0]?.["sql"]);
    await queryProjectDo(projectId, "DROP TRIGGER mutation_audit_events_write");
    await queryProjectDo(projectId, current.replace("seq = seq + 1", "seq = seq + 2"));
    await evictProjectDo(projectId);
    const redone = await queryProjectDo(
      projectId,
      "SELECT rowid, sql FROM sqlite_master WHERE type = 'trigger' AND name = 'mutation_audit_events_write'",
    );
    expect(String(redone[0]?.["sql"])).toBe(current);
    await queryProjectDo(projectId, "CREATE TABLE later_marker (id INTEGER PRIMARY KEY)");
    await evictProjectDo(projectId);
    const untouched = await queryProjectDo(
      projectId,
      "SELECT rowid, sql FROM sqlite_master WHERE type = 'trigger' AND name = 'mutation_audit_events_write'",
    );
    expect(untouched).toEqual(redone);
    await queryProjectDo(projectId, "DROP TABLE later_marker");
    await queryProjectDo(
      projectId,
      "INSERT INTO lease_windows (kind, window_start, count) VALUES ('issued', 1, 1)",
    );
    expect(await counterSeq()).toBe(afterWrite);
  });

  it("refuses a companion read at another chain head than the file's, and accepts a re-run under a co-owner's project row", async () => {
    await seedProjectActivity();
    await appendOperation(fixture, OWNER, changeRoleOperation(MEMBER, "owner"));
    const { objectKey, identitiesKey, identities } = await exportToBucket();
    await resetProjectDo(projectId);
    await resetAuthDb();
    expect(
      await importWith("import-stale", objectKey, {
        ...identities,
        chainHeadHashHex: "00".repeat(32),
      }),
    ).toEqual({
      status: "failed",
      code: "import-refused",
      identities: { kind: "refused", code: "identities-stale" },
    });
    await expectDestinationUnmaterialized();
    await bucket.put(
      "restore/jobs/import-first.json",
      JSON.stringify({ objectKey, target: "production", identitiesKey }),
    );
    expect(await processRestoreJobs(restoreEnv)).toEqual(["import-first"]);
    expect((await jobResult("import-first")).identities).toMatchObject({
      kind: "provisioned",
      project: "created",
    });
    expect(
      (await importWith("import-coowner", objectKey, { ...identities, exportedBy: MEMBER }))
        .identities,
    ).toEqual({ kind: "provisioned", existing: 3, created: 0, members: 3, project: "kept" });
  });

  it("asks everything before the DO is touched: a refused import leaves the destination empty, a tampered chain is refused as such, and a drill rehearses", async () => {
    await seedProjectActivity();
    const { objectKey, identitiesKey, identities } = await exportToBucket();
    const { lines } = await exportAll();
    await resetProjectDo(projectId);
    await resetAuthDb();
    await seedUser("user-somebody-0099", 9002);
    const conflict = await importWith("import-pre-conflict", objectKey, identities);
    expect(conflict).toEqual({
      status: "failed",
      code: "import-refused",
      identities: { kind: "refused", code: "identity-conflict" },
    });
    await expectDestinationUnmaterialized();
    await env.DB.batch([
      env.DB.prepare("DELETE FROM linked_identities"),
      env.DB.prepare("DELETE FROM users"),
    ]);
    const tampered = lines.map((line) => {
      const parsed = parsedLine(line);
      if (parsed["kind"] !== "row" || parsed["table"] !== "chain_entries") {
        return line;
      }
      const values = [...(parsed["values"] as unknown[])];
      values[2] = "00".repeat(32);
      return JSON.stringify({ ...parsed, values });
    });
    const tamperedKey = "do/export-test/tampered.ndjson.gz";
    await bucket.put(tamperedKey, await gzipLines(tampered));
    expect(await importWith("import-tampered", tamperedKey, identities)).toEqual({
      status: "failed",
      code: "snapshot-chain-invalid",
    });
    await expectDestinationUnmaterialized();
    await bucket.put(
      "restore/jobs/import-drill.json",
      JSON.stringify({ objectKey, target: "drill", identitiesKey }),
    );
    expect(await processRestoreJobs(restoreEnv)).toEqual(["import-drill"]);
    expect(await jobResult("import-drill")).toEqual({
      status: "failed",
      code: "target-unavailable",
      identities: { kind: "rehearsed", existing: 0, created: 3, members: 3, project: "absent" },
    });
    expect(await d1Rows("SELECT COUNT(*) AS n FROM users")).toEqual([{ n: 0 }]);
    expect(await d1Rows("SELECT COUNT(*) AS n FROM projects")).toEqual([{ n: 0 }]);
  });

  it("refuses an identity already bound to another account without writing anything, and the retry after the fix provisions the restored project", async () => {
    await seedProjectActivity();
    const { objectKey, identitiesKey } = await exportToBucket();
    await resetProjectDo(projectId);
    await resetAuthDb();
    await seedUser("user-somebody-0099", 9002);
    await bucket.put(
      "restore/jobs/import-conflict.json",
      JSON.stringify({ objectKey, target: "production", identitiesKey }),
    );
    expect(await processRestoreJobs(restoreEnv)).toEqual(["import-conflict"]);
    const outcome = await jobResult("import-conflict");
    expect(outcome).toEqual({
      status: "failed",
      code: "import-refused",
      identities: { kind: "refused", code: "identity-conflict" },
    });
    expect(await d1Rows("SELECT COUNT(*) AS n FROM users")).toEqual([{ n: 1 }]);
    expect(await d1Rows("SELECT COUNT(*) AS n FROM projects")).toEqual([{ n: 0 }]);
    await env.DB.batch([
      env.DB.prepare("DELETE FROM linked_identities"),
      env.DB.prepare("DELETE FROM users"),
    ]);
    await bucket.put(
      "restore/jobs/import-retry.json",
      JSON.stringify({ objectKey, target: "production", identitiesKey }),
    );
    expect(await processRestoreJobs(restoreEnv)).toEqual(["import-retry"]);
    const retried = await jobResult("import-retry");
    expect(retried.status).toBe("ok");
    expect(retried.identities).toEqual({
      kind: "provisioned",
      existing: 0,
      created: 3,
      members: 3,
      project: "created",
    });
    expect((await requestJson("GET", "/chain", await cliToken(9002))).status).toBe(200);
    await bucket.put("restore/identities-bad.json", "not json");
    await bucket.put(
      "restore/jobs/import-missing.json",
      JSON.stringify({ objectKey, target: "production", identitiesKey: "restore/none.json" }),
    );
    await bucket.put(
      "restore/jobs/import-malformed.json",
      JSON.stringify({
        objectKey,
        target: "production",
        identitiesKey: "restore/identities-bad.json",
      }),
    );
    expect((await processRestoreJobs(restoreEnv)).toSorted()).toEqual([
      "import-malformed",
      "import-missing",
    ]);
    expect((await jobResult("import-missing")).identities).toEqual({
      kind: "refused",
      code: "identities-missing",
    });
    expect((await jobResult("import-malformed")).identities).toEqual({
      kind: "refused",
      code: "identities-malformed",
    });
  });

  it("refuses ids the restored chain does not confirm, a taken id, and malformed companions; counts members who already exist", async () => {
    await seedProjectActivity();
    const { objectKey, identities } = await exportToBucket();
    await resetProjectDo(projectId);
    await resetAuthDb();
    const ghost = {
      ...identities,
      identities: [
        ...identities.identities,
        { userId: "user-ghost-0099", provider: "github", providerUserId: "9555" },
      ],
    };
    const ghosted = await importWith("import-ghost", objectKey, ghost);
    expect(ghosted).toEqual({
      status: "failed",
      code: "import-refused",
      identities: { kind: "refused", code: "identity-not-member" },
    });
    expect(
      (await importWith("import-notowner", objectKey, { ...identities, exportedBy: MEMBER }))
        .identities,
    ).toEqual({
      kind: "refused",
      code: "exporter-not-owner",
    });
    expect(
      (
        await importWith("import-noexporter", objectKey, {
          ...identities,
          exportedBy: "user-absent-0001",
        })
      ).identities,
    ).toEqual({ kind: "refused", code: "exporter-missing" });
    expect(
      (await importWith("import-empty", objectKey, { ...identities, identities: [] })).identities,
    ).toEqual({
      kind: "refused",
      code: "identities-empty",
    });
    const repeated = {
      ...identities,
      identities: [...identities.identities, ...identities.identities],
    };
    expect((await importWith("import-repeated", objectKey, repeated)).identities).toEqual({
      kind: "refused",
      code: "identities-malformed",
    });
    expect(await d1Rows("SELECT COUNT(*) AS n FROM users")).toEqual([{ n: 0 }]);
    await seedUser(OWNER, 9777);
    expect((await importWith("import-taken", objectKey, identities)).identities).toEqual({
      kind: "refused",
      code: "user-id-taken",
    });
    await env.DB.batch([
      env.DB.prepare("DELETE FROM linked_identities"),
      env.DB.prepare("DELETE FROM users"),
    ]);
    await seedUser(MEMBER, 9002);
    const outcome = await importWith("import-existing", objectKey, identities);
    expect(outcome.identities).toEqual({
      kind: "provisioned",
      existing: 1,
      created: 2,
      members: 3,
      project: "created",
    });
    expect(await d1Rows("SELECT COUNT(*) AS n FROM users")).toEqual([{ n: 3 }]);
  });
});
