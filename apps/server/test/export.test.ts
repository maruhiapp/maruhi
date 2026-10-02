// Integration tests for the project export API and the import path (PF3 —
// AUTH_SPEC §11-6, docs/notes/pf3-design.md). Verifies the HttpApi, the DO
// and D1 via SELF on @cloudflare/vitest-plugin (the real workerd
// environment).
//
// What this suite pins:
// - the pages reproduce the evacuation format (header / table / row /
//   trailer; the trailer's counts equal the rows emitted) and the restore
//   path accepts the gzipped lines unchanged — the project is readable
//   again afterwards
// - the first page records `project.exported` (the owner as actor) and
//   the exported audit log carries that row
// - owner only (members and admins 403, strangers the uniform 404); a
//   cursor the server did not mint or whose marks are stale is 409; the
//   per-project window is 429
// - the identities companion lists the current members' provider
//   identities (never a provider id of a non-member)
// - an import job provisions the members with the chain's user ids so the
//   first login on the destination lands on them (identity continuity),
//   refuses a colliding account without writing anything, and reports the
//   static codes

import { env, runInDurableObject } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { PROJECT_DO_TABLES, readProjectDoSchemaVersion } from "../src/do-schema.ts";
import { type ExportCursorState, exportSnapshotPage } from "../src/do-snapshot.ts";
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
import { queryProjectDo, readAuditEvents, resetProjectDo } from "./support/project-do.ts";

registerDataScenario();

const bucket = env.OPS_BACKUP_BUCKET as R2Bucket;
const restoreEnv = {
  OPS_BACKUP_BUCKET: bucket,
  PRODUCTION_PROJECT_CHAIN: env.PROJECT_CHAIN,
  DB: env.DB,
};

// The restore worker scans the product key layout (restore/jobs/ …), so
// every test empties restore/ first (R2 is outside storage isolation)
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

/** Pages the whole export as the CLI does (the lines in order, the pages for inspection). */
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

/** Row lines per table line (the trailer's counts must equal these — an empty table counts 0). */
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

/** Exports the live project and parks the file (and the identities companion) in the bucket. */
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

/** The live row count of every snapshot table (the export's trailer must say exactly this). */
async function liveCounts(): Promise<Record<string, number>> {
  const counts: Record<string, number> = {};
  for (const table of PROJECT_DO_TABLES) {
    const rows = await queryProjectDo(projectId, `SELECT COUNT(*) AS n FROM ${table}`);
    counts[table] = Number(rows[0]?.["n"] ?? 0);
  }
  return counts;
}

/** Writes an identities companion of the given shape and runs an import job named `name`. */
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

describe("project export (AUTH_SPEC §11-6)", () => {
  it("pages the project in the evacuation format, records project.exported, and the restore path accepts the file", async () => {
    await seedProjectActivity();
    // Materialize the audit-head column (the trailer carries the head)
    expect((await requestJson("GET", "/audit-head", token(OWNER))).status).toBe(200);
    const { lines, pages } = await exportAll();
    const header = parsedLine(lines[0]);
    expect(header).toMatchObject({ kind: "header", format: "maruhi-do-snapshot", version: 1 });
    const trailer = parsedLine(lines[lines.length - 1]);
    expect(trailer["kind"]).toBe("trailer");
    expect(trailer["rows"]).toEqual(rowCounts(lines));
    // … and those counts are the live tables' (not only self-consistent)
    expect(trailer["rows"]).toEqual(await liveCounts());
    expect(trailer["chainHeadSeq"]).toBe(fixture.head.seq);
    expect(trailer["chainHeadHashHex"]).toBe(fixture.head.hashHex);
    expect(pages[0]?.head.chainHeadHashHex).toBe(fixture.head.hashHex);
    // The audit row is appended before the marks are taken: the first
    // page's audit seq is that row's seq
    const exportedSeq = await queryProjectDo(
      projectId,
      "SELECT seq FROM audit_events WHERE event = 'project.exported'",
    );
    expect(pages[0]?.head.auditMaxSeq).toBe(exportedSeq[0]?.["seq"]);
    // chain_entries is the last table (the restore's "chain comes last" rule)
    const tables = lines
      .map((line) => parsedLine(line))
      .filter((line) => line["kind"] === "table")
      .map((line) => line["table"]);
    expect(tables[tables.length - 1]).toBe("chain_entries");
    // The export records itself: the audit row exists and is inside the export
    const exported = (await readAuditEvents(projectId)).filter(
      (event) => event["event"] === "project.exported",
    );
    expect(exported).toHaveLength(1);
    expect(exported[0]).toMatchObject({ actor_type: "user", actor_user_id: OWNER });
    expect(JSON.parse(String(exported[0]?.["payload"]))).toMatchObject({
      chainHeadSeq: fixture.head.seq,
    });
    expect(lines.some((line) => line.includes('"project.exported"'))).toBe(true);
    // The file restores into an empty DO and the project is readable again
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
          maxRows: 3,
          maxBytes: 700,
        });
        if (page.kind !== "page") {
          throw new Error("unexpected change");
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
    expect(rowCounts(all)).toEqual(await liveCounts());
    expect(parsedLine(all[all.length - 1])["rows"]).toEqual(await liveCounts());
    for (const page of pages) {
      expect(page.rows).toBeLessThanOrEqual(3);
      // A page passes the byte bound by at most its last line (the row that crossed it)
      const last = page.lines[page.lines.length - 1] ?? "";
      expect(page.bytes - (new TextEncoder().encode(last).length + 1)).toBeLessThan(700);
    }
    // Every row line of the concatenation follows its table line exactly once
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
    // An admin is not an owner either (ruling E)
    await appendOperation(fixture, OWNER, changeRoleOperation(MEMBER, "admin"));
    expect((await exportPage(MEMBER)).status).toBe(403);
    expect((await requestJson("GET", "/export/identities", token(MEMBER))).status).toBe(403);
    // Nothing was recorded for the refused calls
    const exported = (await readAuditEvents(projectId)).filter(
      (event) => event["event"] === "project.exported",
    );
    expect(exported).toHaveLength(0);
    // The export row is class 2: an owner sees it in the audit read, a member does not
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
    // A cursor the server never minted (well-formed base64url, wrong shape)
    const foreign = await exportPage(OWNER, base64Url(JSON.stringify({ hello: "world" })));
    expect(foreign.status).toBe(409);
    expect(await foreign.json()).toMatchObject({ _tag: "ExportChanged" });
    // A cursor carrying the current marks continues (no header on a continuation)
    const attestation = await queryProjectDo(
      projectId,
      "SELECT COALESCE(MAX(accepted_at), 0) AS m FROM head_attestations",
    );
    const current = base64Url(
      JSON.stringify({
        table: 0,
        started: false,
        rowid: -1,
        rows: {},
        marks: {
          chainHeadSeq: head.chainHeadSeq,
          chainHeadHashHex: head.chainHeadHashHex,
          auditMaxSeq: head.auditMaxSeq,
          attestationMark: Number(attestation[0]?.["m"] ?? 0),
        },
      }),
    );
    const continued = await exportPage(OWNER, current);
    expect(continued.status).toBe(200);
    const page = (await continued.json()) as WirePage;
    expect(parsedLine(page.lines[0])["kind"]).toBe("table");
    // A cursor past the table order is refused too (never a 500)
    const beyond = base64Url(
      JSON.stringify({ ...JSON.parse(atob(current)), table: 999, started: false }),
    );
    expect((await exportPage(OWNER, beyond)).status).toBe(409);
    const fractional = base64Url(
      JSON.stringify({ ...JSON.parse(atob(current)), table: 0.5, rowid: -2 }),
    );
    expect((await exportPage(OWNER, fractional)).status).toBe(409);
    // A data-only write between pages (a push appends an audit row, no chain
    // entry) makes the same cursor stale
    await createVariableOk(dek, "var-second-0002", "SECOND", "value-two");
    const stale = await exportPage(OWNER, current);
    expect(stale.status).toBe(409);
    // The window: the first page consumed one slot; an exhausted window is 429
    await queryProjectDo(
      projectId,
      "UPDATE lease_windows SET count = ?, window_start = ? WHERE kind = 'exported'",
      MAX_EXPORTS_PER_WINDOW,
      Date.now(),
    );
    const limited = await exportPage(OWNER);
    expect(limited.status).toBe(429);
    expect(await limited.json()).toMatchObject({ _tag: "ExportRateLimited" });
    // A continuation is not window-counted (the cursor path skips the window)
    expect((await exportPage(OWNER, current)).status).toBe(409);
  });

  it("the identities companion lists the current members' provider identities and names an unlinked member", async () => {
    await seedProjectActivity();
    // A member on the chain with no linked identity on this deployment
    const DEV = "user-devmember-0010";
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
    // A non-member's identity is never listed
    expect(JSON.stringify(body)).not.toContain(STRANGER);
    expect(JSON.stringify(body)).not.toContain("9009");
  });
});

describe("project import (the restore job with identitiesKey)", () => {
  it("provisions the members with the chain's user ids, and the first login on the destination lands on them", async () => {
    await seedProjectActivity();
    const { objectKey, identitiesKey, trailer } = await exportToBucket();
    // A fresh destination: no project DO, no accounts
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
    });
    if (outcome.status === "ok") {
      expect(outcome.verification.chainHeadHashHex).toBe(trailer["chainHeadHashHex"]);
    }
    // The D1 side looks as if every member had logged in once and the owner
    // had created the project here (users with the chain's ids, the login
    // lookup rows, personal orgs, the projects row, the projection)
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
    // Identity continuity: a login with the owner's GitHub id resolves to the
    // chain's user id, so the project is theirs on the destination
    const ownerToken = await cliToken(9001);
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, ownerToken);
    expect(pull.status).toBe(200);
    const listed = await requestJson("GET", "/chain", ownerToken);
    expect(listed.status).toBe(200);
    // Re-running the same job: the DO refuses (not-empty) and so does D1 (project-exists)
    await bucket.put(
      "restore/jobs/import-2.json",
      JSON.stringify({ objectKey, target: "production", identitiesKey }),
    );
    expect(await processRestoreJobs(restoreEnv)).toEqual(["import-2"]);
    expect(await jobResult("import-2")).toEqual({
      status: "failed",
      code: "not-empty",
      identities: { kind: "refused", code: "project-exists" },
    });
    // The results carry no project id (the same discipline as restores)
    expect(JSON.stringify(outcome)).not.toContain(projectId);
  });

  it("refuses an identity already bound to another account without writing anything, and the retry after the fix provisions the restored project", async () => {
    await seedProjectActivity();
    const { objectKey, identitiesKey } = await exportToBucket();
    await resetProjectDo(projectId);
    await resetAuthDb();
    // Somebody logged in with the member's GitHub id before the import
    await seedUser("user-somebody-0099", 9002);
    await bucket.put(
      "restore/jobs/import-conflict.json",
      JSON.stringify({ objectKey, target: "production", identitiesKey }),
    );
    expect(await processRestoreJobs(restoreEnv)).toEqual(["import-conflict"]);
    const outcome = await jobResult("import-conflict");
    expect(outcome.status).toBe("ok");
    expect(outcome.identities).toEqual({ kind: "refused", code: "identity-conflict" });
    expect(await d1Rows("SELECT COUNT(*) AS n FROM users")).toEqual([{ n: 1 }]);
    expect(await d1Rows("SELECT COUNT(*) AS n FROM projects")).toEqual([{ n: 0 }]);
    // The operator removes the colliding account and resubmits: the DO is
    // already restored (not-empty) and the D1 step runs
    await env.DB.batch([
      env.DB.prepare("DELETE FROM linked_identities"),
      env.DB.prepare("DELETE FROM users"),
    ]);
    await bucket.put(
      "restore/jobs/import-retry.json",
      JSON.stringify({ objectKey, target: "production", identitiesKey }),
    );
    expect(await processRestoreJobs(restoreEnv)).toEqual(["import-retry"]);
    expect(await jobResult("import-retry")).toEqual({
      status: "failed",
      code: "not-empty",
      identities: { kind: "provisioned", existing: 0, created: 3, members: 3 },
    });
    expect((await requestJson("GET", "/chain", await cliToken(9002))).status).toBe(200);
    // A missing companion and a malformed one are static codes
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
    // The companion is confirmed against the chain before anything is written
    const ghost = {
      ...identities,
      identities: [
        ...identities.identities,
        { userId: "user-ghost-0099", provider: "github", providerUserId: "9555" },
      ],
    };
    expect((await importWith("import-ghost", objectKey, ghost)).identities).toEqual({
      kind: "refused",
      code: "identity-not-member",
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
    // The chain's owner id is held by somebody with another GitHub id
    await seedUser(OWNER, 9777);
    expect((await importWith("import-taken", objectKey, identities)).identities).toEqual({
      kind: "refused",
      code: "user-id-taken",
    });
    await env.DB.batch([
      env.DB.prepare("DELETE FROM linked_identities"),
      env.DB.prepare("DELETE FROM users"),
    ]);
    // A member who already logged in here with the same identity is kept as-is
    await seedUser(MEMBER, 9002);
    const outcome = await importWith("import-existing", objectKey, identities);
    expect(outcome.identities).toEqual({
      kind: "provisioned",
      existing: 1,
      created: 2,
      members: 3,
    });
    expect(await d1Rows("SELECT COUNT(*) AS n FROM users")).toEqual([{ n: 3 }]);
  });
});
