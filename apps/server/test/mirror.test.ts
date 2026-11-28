import { changeRoleOp, signEntryAt } from "@maruhi/test-kit";
import { env, runInDurableObject, SELF } from "cloudflare:test";
import { Effect } from "effect";
import { describe, expect, it } from "vite-plus/test";

import {
  ensureProjectDoTables,
  PROJECT_DO_TABLES,
  readProjectDoSchemaVersion,
} from "../src/do/do-schema.ts";
import { restoreSnapshot, type RestoreFailureCode } from "../src/do/do-snapshot-restore.ts";
import { JSON_HEADERS } from "./support/auth.ts";
import { identityOf, vectorKeyOf } from "./support/data-crypto.ts";
import {
  appendOperation,
  createEnvironmentOk,
  deleteEnvironmentRequest,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
  rotateEnvironmentOk,
  STRANGER,
} from "./support/data-fixture.ts";
import {
  createVariableOk,
  deleteVariableRequest,
  ENV,
  fixture,
  registerDataScenario,
  setSchemaPolicyOk,
  token,
  VAR,
} from "./support/data-scenario.ts";
import { readyProject, requestLease, workloadKeyPair } from "./support/lease-scenario.ts";
import { makeOidcToken } from "./support/lease.ts";
import { evictProjectDo, queryProjectDo, resetProjectDo } from "./support/project-do.ts";
import { createVariableV3Request } from "./support/schema-scenario.ts";

registerDataScenario();

const SOURCE = "https://my.maruhi.app";

interface WirePage {
  readonly lines: readonly string[];
  readonly next?: string;
}

interface WireStatus {
  readonly mirror: boolean;
  readonly sourceOrigin?: string;
  readonly lastSync?: {
    readonly chainHeadSeq: number;
    readonly auditMaxSeq: number;
    readonly attestationMark: number;
    readonly mutationSeq?: number;
  };
  readonly nextSequence?: number;
  readonly head: {
    readonly chainHeadSeq: number;
    readonly chainHeadHashHex: string;
    readonly auditMaxSeq?: number;
  };
}

interface WirePageOutcome {
  readonly nextSequence: number;
  readonly committed?: { readonly chainHeadSeq: number; readonly chainHeadHashHex: string };
}

function parsedLine(line: string | undefined): Record<string, unknown> {
  return JSON.parse(line ?? "{}") as Record<string, unknown>;
}

async function exportAll(): Promise<string[]> {
  const lines: string[] = [];
  let cursor: string | undefined;
  for (;;) {
    const response = await requestJson(
      "GET",
      `/export${cursor === undefined ? "" : `?cursor=${encodeURIComponent(cursor)}`}`,
      token(OWNER),
    );
    expect(response.status).toBe(200);
    const page = (await response.json()) as WirePage;
    lines.push(...page.lines);
    cursor = page.next;
    if (cursor === undefined) {
      return lines;
    }
  }
}

async function restoreLines(lines: readonly string[]): Promise<void> {
  await resetProjectDo(projectId);
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
  const text = `${lines.join("\n")}\n`;
  await runInDurableObject(stub, async (_instance, state) => {
    ensureProjectDoTables(state.storage);
    await Effect.runPromise(
      restoreSnapshot({
        storage: state.storage,
        tables: PROJECT_DO_TABLES,
        schemaVersion: readProjectDoSchemaVersion(state.storage.sql),
        body: new Blob([text]).stream().pipeThrough(new CompressionStream("gzip")),
        storesAuditHeads: () => true,
      }),
    );
  });
  await evictProjectDo(projectId);
}

async function restoreLinesRefusal(lines: readonly string[]): Promise<RestoreFailureCode | null> {
  await resetProjectDo(projectId);
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
  const text = `${lines.join("\n")}\n`;
  const code = await runInDurableObject(stub, async (_instance, state) => {
    ensureProjectDoTables(state.storage);
    return Effect.runPromise(
      restoreSnapshot({
        storage: state.storage,
        tables: PROJECT_DO_TABLES,
        schemaVersion: readProjectDoSchemaVersion(state.storage.sql),
        body: new Blob([text]).stream().pipeThrough(new CompressionStream("gzip")),
        storesAuditHeads: () => true,
      }).pipe(
        Effect.map((): RestoreFailureCode | null => null),
        Effect.catchTag("RestoreRefused", (error) => Effect.succeed(error.code)),
      ),
    );
  });
  await evictProjectDo(projectId);
  return code;
}

const status = (userId = READER) => requestJson("GET", "/mirror", token(userId));
const mark = (userId: string, sourceOrigin = SOURCE) =>
  requestJson("PUT", "/mirror", token(userId), { sourceOrigin });
const unmark = (userId: string) => requestJson("DELETE", "/mirror", token(userId));
const SOURCE_MUTATION_SEQ = 7;
const page = (userId: string, sequence: number, lines: readonly string[]) =>
  requestJson("PUT", "/mirror/pages", token(userId), {
    sequence,
    lines,
    sourceMutationSeq: SOURCE_MUTATION_SEQ,
  });

async function statusOk(userId = READER): Promise<WireStatus> {
  const response = await status(userId);
  expect(response.status).toBe(200);
  return (await response.json()) as WireStatus;
}

async function upload(lines: readonly string[], size: number): Promise<Response> {
  let sequence = 0;
  for (let start = 0; start < lines.length; start += size) {
    const response = await page(OWNER, sequence, lines.slice(start, start + size));
    if (start + size >= lines.length) {
      return response;
    }
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ nextSequence: sequence + 1 });
    sequence += 1;
  }
  throw new Error("no lines");
}

async function expectRejected(response: Response, reason: string): Promise<void> {
  expect(response.status).toBe(422);
  await expect(response.json()).resolves.toEqual({ _tag: "MirrorSyncRejected", reason });
}

async function stagingTables(): Promise<string[]> {
  const rows = await queryProjectDo(
    projectId,
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE '%\\_mirror%' ESCAPE '\\' ORDER BY name",
  );
  return rows.map((row) => String(row["name"]));
}

async function count(query: string): Promise<number> {
  return Number((await queryProjectDo(projectId, query))[0]?.["n"] ?? -1);
}

async function rawAppend(actorUserId: string): Promise<Response> {
  const { entry } = await signEntryAt({
    seq: fixture.head.seq + 1,
    prevHashHex: fixture.head.hashHex,
    actor: identityOf(actorUserId),
    operation: changeRoleOp({ userId: READER }, "member"),
  });
  return requestJson("POST", "/chain/entries", token(actorUserId), {
    parentHeadHashHex: fixture.head.hashHex,
    entry,
  });
}

function withTrailer(lines: readonly string[], patch: Record<string, unknown>): string[] {
  const trailer = parsedLine(lines[lines.length - 1]);
  return [...lines.slice(0, -1), JSON.stringify({ ...trailer, ...patch })];
}

describe("mirrors (AUTH_SPEC §11-7)", () => {
  it("marks, refuses writes, serves reads, replicates forward, keeps its own windows and audit rows, and promotes", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const older = await exportAll();
    const olderTrailer = parsedLine(older[older.length - 1]);
    await appendOperation(fixture, OWNER, changeRoleOp({ userId: READER }, "member"));
    await createVariableOk(dek, "var-second", "SECOND", "two");
    expect((await requestJson("GET", `/environments/${ENV}/pull`, token(READER))).status).toBe(200);
    await queryProjectDo(
      projectId,
      "INSERT INTO lease_bindings (binding_key_hex, ephemeral_pub_hex, expires_at) VALUES ('ab', 'zz', 9999999999999), ('source-only', 'ef', 9999999999999), ('source-expired', 'ee', 1)",
    );
    const newer = await exportAll();
    const newerTrailer = parsedLine(newer[newer.length - 1]);
    expect(Number(newerTrailer["chainHeadSeq"])).toBe(Number(olderTrailer["chainHeadSeq"]) + 1);

    await restoreLines(older);
    expect((await mark(READER)).status).toBe(403);
    expect((await mark(MEMBER)).status).toBe(403);
    expect((await mark(STRANGER)).status).toBe(404);
    expect((await page(STRANGER, 0, older)).status).toBe(404);
    const marked = await mark(OWNER);
    expect(marked.status).toBe(200);
    expect(await marked.json()).toMatchObject({
      mirror: true,
      sourceOrigin: SOURCE,
      head: { chainHeadSeq: olderTrailer["chainHeadSeq"] },
    });
    await expect(mark(OWNER).then((r) => r.json())).resolves.toEqual({
      _tag: "MirrorState",
      reason: "already-mirror",
    });
    const repointed = await mark(OWNER, "https://other.maruhi.app");
    expect(repointed.status).toBe(200);
    expect(await repointed.json()).toMatchObject({
      mirror: true,
      sourceOrigin: "https://other.maruhi.app",
      head: { chainHeadSeq: olderTrailer["chainHeadSeq"] },
    });
    expect((await mark(OWNER)).status).toBe(200);
    expect((await statusOk()).sourceOrigin).toBe(SOURCE);

    expect(
      (await requestJson("PUT", "/schema-policy", token(STRANGER), { schemaPolicy: "enabled" }))
        .status,
    ).toBe(404);
    const refused = await rawAppend(OWNER);
    expect(refused.status).toBe(403);
    await expect(refused.json()).resolves.toEqual({
      _tag: "Forbidden",
      reason: "mirror-read-only",
    });
    const policy = await requestJson("PUT", "/schema-policy", token(OWNER), {
      schemaPolicy: "locked",
    });
    expect(policy.status).toBe(403);
    expect((await requestJson("GET", "/schema-policy", token(READER))).status).toBe(200);
    const pulled = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pulled.status).toBe(200);
    expect(((await pulled.json()) as { variables: unknown[] }).variables).toHaveLength(1);
    expect((await requestJson("GET", "/audit/events", token(READER))).status).toBe(200);
    const ownRows = await count(
      `SELECT COUNT(*) AS n FROM audit_events WHERE seq > ${Number(olderTrailer["auditMaxSeq"])}`,
    );
    expect(ownRows).toBeGreaterThan(0);
    await queryProjectDo(
      projectId,
      "INSERT INTO lease_windows (kind, window_start, count) VALUES ('issued', 1, 7)",
    );
    await queryProjectDo(
      projectId,
      "INSERT INTO lease_bindings (binding_key_hex, ephemeral_pub_hex, expires_at) VALUES ('ab', 'cd', 9999999999999), ('own-expired', 'dd', 1)",
    );
    await queryProjectDo(
      projectId,
      "INSERT INTO attestation_windows (attester_user_id, window_start, count) VALUES (?, 1, 3)",
      OWNER,
    );

    expect((await page(MEMBER, 0, newer.slice(0, 3))).status).toBe(403);
    const last = await upload(newer, 7);
    expect(last.status).toBe(200);
    const outcome = (await last.json()) as WirePageOutcome;
    expect(outcome).toEqual({
      nextSequence: 0,
      committed: {
        atMs: expect.any(Number),
        chainHeadSeq: newerTrailer["chainHeadSeq"],
        chainHeadHashHex: newerTrailer["chainHeadHashHex"],
        auditMaxSeq: newerTrailer["auditMaxSeq"],
        attestationMark: 0,
        mutationSeq: SOURCE_MUTATION_SEQ,
        ownAuditRows: ownRows,
      },
    });
    const synced = await statusOk(OWNER);
    expect(synced.lastSync).toMatchObject({
      chainHeadSeq: newerTrailer["chainHeadSeq"],
      attestationMark: 0,
      mutationSeq: SOURCE_MUTATION_SEQ,
    });
    expect(synced.nextSequence).toBeUndefined();
    expect(synced.head.chainHeadHashHex).toBe(newerTrailer["chainHeadHashHex"]);
    expect(synced.head.auditMaxSeq).toBeGreaterThanOrEqual(Number(newerTrailer["auditMaxSeq"]));
    const readerView = await statusOk(READER);
    expect(readerView.sourceOrigin).toBe(SOURCE);
    expect(readerView.head.chainHeadHashHex).toBe(newerTrailer["chainHeadHashHex"]);
    expect(readerView.head.auditMaxSeq).toBeUndefined();
    expect(readerView.lastSync).toBeUndefined();
    const chain = await requestJson("GET", "/chain", token(READER));
    expect(chain.status).toBe(200);
    expect(((await chain.json()) as { headSeq: number }).headSeq).toBe(
      newerTrailer["chainHeadSeq"],
    );
    const pulledAgain = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pulledAgain.status).toBe(200);
    expect(((await pulledAgain.json()) as { variables: unknown[] }).variables).toHaveLength(2);
    expect(
      await queryProjectDo(projectId, "SELECT count FROM lease_windows WHERE kind = 'issued'"),
    ).toEqual([{ count: 7 }]);
    expect(
      await queryProjectDo(
        projectId,
        "SELECT binding_key_hex, ephemeral_pub_hex FROM lease_bindings ORDER BY binding_key_hex",
      ),
    ).toEqual([
      { binding_key_hex: "ab", ephemeral_pub_hex: "cd" },
      { binding_key_hex: "source-only", ephemeral_pub_hex: "ef" },
    ]);
    expect(await queryProjectDo(projectId, "SELECT count FROM attestation_windows")).toEqual([
      { count: 3 },
    ]);
    const replicaAudit = Number(newerTrailer["auditMaxSeq"]);
    expect(await count("SELECT COUNT(*) AS n FROM audit_events")).toBe(replicaAudit + ownRows + 1);
    const carried = await queryProjectDo(
      projectId,
      `SELECT event FROM audit_events WHERE seq > ${replicaAudit} ORDER BY seq`,
    );
    expect(carried.map((row) => row["event"])).toEqual([
      ...Array.from({ length: ownRows }, () => "var.read"),
      "var.read",
    ]);
    expect(await count("SELECT MAX(seq) AS n FROM audit_head_hashes")).toBe(replicaAudit + ownRows);
    expect(await stagingTables()).toEqual([]);
    const again = await upload(newer, 7);
    expect(again.status).toBe(200);
    expect(((await again.json()) as WirePageOutcome).committed).toBeDefined();
    expect(await count("SELECT COUNT(*) AS n FROM audit_events")).toBe(replicaAudit + ownRows + 1);
    expect(
      (
        await queryProjectDo(
          projectId,
          `SELECT event FROM audit_events WHERE seq > ${replicaAudit} ORDER BY seq`,
        )
      ).map((row) => row["event"]),
    ).toEqual(Array.from({ length: ownRows + 1 }, () => "var.read"));
    expect(await count("SELECT MAX(seq) AS n FROM audit_head_hashes")).toBe(
      replicaAudit + ownRows + 1,
    );
    const headLineIndex = newer.findIndex((line) => {
      const parsed = parsedLine(line);
      return (
        parsed["kind"] === "row" &&
        parsed["table"] === "audit_head_hashes" &&
        (parsed["values"] as unknown[])[0] === replicaAudit
      );
    });
    expect(headLineIndex).toBeGreaterThan(-1);
    const otherLog = newer.map((line, index) =>
      index === headLineIndex
        ? JSON.stringify({ ...parsedLine(line), values: [replicaAudit, "ab".repeat(32)] })
        : line,
    );
    await expectRejected(await upload(otherLog, 50), "audit-not-extension");
    expect(await stagingTables()).toEqual([]);
    const firstHeadIndex = newer.findIndex((line) => {
      const parsed = parsedLine(line);
      return (
        parsed["kind"] === "row" &&
        parsed["table"] === "audit_head_hashes" &&
        (parsed["values"] as unknown[])[0] === 1
      );
    });
    expect(firstHeadIndex).toBeGreaterThan(-1);
    const ownHeads = await queryProjectDo(
      projectId,
      `SELECT seq, head_hash_hex FROM audit_head_hashes WHERE seq <= ${replicaAudit} ORDER BY seq`,
    );
    const earlyTamper = newer.map((line, index) =>
      index === firstHeadIndex
        ? JSON.stringify({ ...parsedLine(line), values: [1, "ab".repeat(32)] })
        : line,
    );
    await expectRejected(await upload(earlyTamper, 50), "audit-not-extension");
    expect(await stagingTables()).toEqual([]);
    expect((await upload(newer, 7)).status).toBe(200);
    expect(
      await queryProjectDo(
        projectId,
        `SELECT seq, head_hash_hex FROM audit_head_hashes WHERE seq <= ${replicaAudit} ORDER BY seq`,
      ),
    ).toEqual(ownHeads);
    expect(await count("SELECT MAX(seq) AS n FROM audit_head_hashes")).toBe(
      replicaAudit + ownRows + 1,
    );
    const stagedOnly = newer.slice(0, -1);
    expect((await page(OWNER, 0, stagedOnly)).status).toBe(200);
    const plan = (
      await queryProjectDo(
        projectId,
        `EXPLAIN QUERY PLAN SELECT COUNT(*) AS n FROM audit_events AS own LEFT JOIN audit_events_mirror AS theirs ON theirs.seq = own.seq WHERE own.seq <= ${replicaAudit} AND theirs.seq IS NULL`,
      )
    )
      .map((row) => String(row["detail"]))
      .join("\n");
    expect(plan).toContain("SEARCH theirs USING");
    expect(plan).not.toContain("SCAN theirs");
    expect((await page(OWNER, 0, newer)).status).toBe(200);
    expect(await stagingTables()).toEqual([]);
    const firstRowIndex = newer.findIndex((line) => {
      const parsed = parsedLine(line);
      return parsed["kind"] === "row" && parsed["table"] === "audit_events";
    });
    const rewrittenPrefix = newer.map((line, index) => {
      if (index !== firstRowIndex) {
        return line;
      }
      const row = parsedLine(line) as { values: unknown[] };
      const values = [...row.values];
      values[1] = Number(values[1]) + 1;
      return JSON.stringify({ ...row, values });
    });
    await expectRejected(await upload(rewrittenPrefix, 50), "audit-not-extension");
    expect(await stagingTables()).toEqual([]);
    await expectRejected(await upload(older, 50), "chain-not-extension");
    expect((await statusOk()).nextSequence).toBeUndefined();

    expect((await unmark(MEMBER)).status).toBe(403);
    const promoted = await unmark(OWNER);
    expect(promoted.status).toBe(200);
    expect(await promoted.json()).toMatchObject({ mirror: false });
    await expect(unmark(OWNER).then((r) => r.json())).resolves.toEqual({
      _tag: "MirrorState",
      reason: "not-mirror",
    });
    await expect(page(OWNER, 0, newer).then((r) => r.json())).resolves.toEqual({
      _tag: "MirrorState",
      reason: "not-mirror",
    });
    fixture.head = {
      seq: Number(newerTrailer["chainHeadSeq"]),
      hashHex: String(newerTrailer["chainHeadHashHex"]),
    };
    await appendOperation(fixture, OWNER, changeRoleOp({ userId: READER }, "reader"));
  });

  it("a frozen former primary syncs back from the destination: the rows its export carried are not re-appended (ruling J revision, round 4)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    expect((await mark(OWNER, "https://destination.maruhi.app")).status).toBe(200);
    const markedAudit = await count("SELECT MAX(seq) AS n FROM audit_events");
    expect((await requestJson("GET", `/environments/${ENV}/pull`, token(READER))).status).toBe(200);
    const exported = await exportAll();
    const trailer = parsedLine(exported[exported.length - 1]);
    const exportedAudit = Number(trailer["auditMaxSeq"]);
    expect(exportedAudit).toBeGreaterThan(markedAudit + 1);
    expect((await requestJson("GET", `/environments/${ENV}/pull`, token(READER))).status).toBe(200);
    const last = await upload(exported, 50);
    expect(last.status).toBe(200);
    expect(((await last.json()) as WirePageOutcome).committed).toMatchObject({
      chainHeadSeq: trailer["chainHeadSeq"],
      auditMaxSeq: exportedAudit,
      ownAuditRows: 1,
    });
    expect(await count("SELECT COUNT(*) AS n FROM audit_events")).toBe(exportedAudit + 1);
    expect(await count("SELECT COUNT(DISTINCT row_id) AS n FROM audit_events")).toBe(
      exportedAudit + 1,
    );
    expect(await count("SELECT MAX(seq) AS n FROM audit_events")).toBe(exportedAudit + 1);
    expect(await stagingTables()).toEqual([]);
    expect((await statusOk(OWNER)).lastSync).toBeDefined();
    expect((await mark(OWNER, "https://successor.maruhi.app")).status).toBe(200);
    expect((await statusOk(OWNER)).lastSync).toBeUndefined();
    const auditLineIndex = exported.findIndex((line) => {
      const parsed = parsedLine(line);
      return parsed["kind"] === "row" && parsed["table"] === "audit_events";
    });
    const rewritten = exported.map((line, index) => {
      if (index !== auditLineIndex) {
        return line;
      }
      const row = parsedLine(line) as { values: unknown[] };
      const values = [...row.values];
      const eventIndex = values.findIndex((value) => value === "chain.genesis");
      values[eventIndex === -1 ? 1 : eventIndex] = "chain.rewritten";
      return JSON.stringify({ ...row, values });
    });
    await expectRejected(await upload(rewritten, 50), "malformed");
    expect(await count("SELECT COUNT(*) AS n FROM audit_events")).toBe(exportedAudit + 1);
    expect((await requestJson("GET", `/environments/${ENV}/pull`, token(READER))).status).toBe(200);
    const shorter = await upload(exported, 50);
    expect(shorter.status).toBe(200);
    expect(((await shorter.json()) as WirePageOutcome).committed).toMatchObject({
      auditMaxSeq: exportedAudit,
      ownAuditRows: 2,
    });
    expect(await count("SELECT COUNT(*) AS n FROM audit_events")).toBe(exportedAudit + 2);
    expect((await unmark(OWNER)).status).toBe(200);
  });

  it("a staged audit log with a gap or a seq at or below 0, or a head column longer than the log, is malformed and never replaces the live log (ruling J revision, round 9)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    expect((await mark(OWNER)).status).toBe(200);
    const lines = await exportAll();
    const trailer = parsedLine(lines[lines.length - 1]);
    const rowsOf = (table: string) => Number((trailer["rows"] as Record<string, number>)[table]);
    const tableLine = lines.findIndex((line) => {
      const parsed = parsedLine(line);
      return parsed["kind"] === "table" && parsed["table"] === "audit_events";
    });
    const seqIndex = (parsedLine(lines[tableLine])["columns"] as string[]).indexOf("seq");
    const auditRowAt = (seq: number) =>
      lines.findIndex((line) => {
        const parsed = parsedLine(line);
        return (
          parsed["kind"] === "row" &&
          parsed["table"] === "audit_events" &&
          (parsed["values"] as unknown[])[seqIndex] === seq
        );
      });
    const liveRows = await count("SELECT COUNT(*) AS n FROM audit_events");
    const second = auditRowAt(2);
    expect(second).toBeGreaterThan(-1);
    const gapped = withTrailer(
      lines.filter((_, index) => index !== second),
      { rows: { ...(trailer["rows"] as object), audit_events: rowsOf("audit_events") - 1 } },
    );
    await expectRejected(await upload(gapped, 50), "malformed");
    expect(await stagingTables()).toEqual([]);
    expect(await count("SELECT COUNT(*) AS n FROM audit_events")).toBe(liveRows);
    const first = auditRowAt(1);
    const zeroed = lines.map((line, index) => {
      if (index !== first) {
        return line;
      }
      const row = parsedLine(line) as { values: unknown[] };
      const values = [...row.values];
      values[seqIndex] = 0;
      return JSON.stringify({ ...row, values });
    });
    await expectRejected(await upload(zeroed, 50), "malformed");
    const headsOnly = withTrailer(
      lines.filter((line) => {
        const parsed = parsedLine(line);
        return !(parsed["kind"] === "row" && parsed["table"] === "audit_events");
      }),
      { rows: { ...(trailer["rows"] as object), audit_events: 0 } },
    );
    await expectRejected(await upload(headsOnly, 50), "malformed");
    const lastHead = lines.findIndex((line) => {
      const parsed = parsedLine(line);
      return (
        parsed["kind"] === "row" &&
        parsed["table"] === "audit_head_hashes" &&
        (parsed["values"] as unknown[])[0] === rowsOf("audit_head_hashes")
      );
    });
    expect(lastHead).toBeGreaterThan(-1);
    const shorter = withTrailer(
      lines.filter((_, index) => index !== lastHead),
      {
        rows: {
          ...(trailer["rows"] as object),
          audit_head_hashes: rowsOf("audit_head_hashes") - 1,
        },
      },
    );
    expect((await upload(shorter, 50)).status).toBe(200);
    expect(await count("SELECT MAX(seq) AS n FROM audit_head_hashes")).toBe(
      await count("SELECT MAX(seq) AS n FROM audit_events"),
    );
    expect((await upload(lines, 50)).status).toBe(200);
    expect((await unmark(OWNER)).status).toBe(200);
  });

  it("a staged audit row the canonical form refuses, or an uploaded head column whose tail is no head hash, is malformed before anything live is touched (ruling J revision, round 10)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    expect((await mark(OWNER)).status).toBe(200);
    const lines = await exportAll();
    const columnsOf = (table: string) =>
      parsedLine(
        lines[
          lines.findIndex((line) => {
            const parsed = parsedLine(line);
            return parsed["kind"] === "table" && parsed["table"] === table;
          })
        ],
      )["columns"] as string[];
    const rowIndex = (table: string, seq: number) =>
      lines.findIndex((line) => {
        const parsed = parsedLine(line);
        return (
          parsed["kind"] === "row" &&
          parsed["table"] === table &&
          (parsed["values"] as unknown[])[columnsOf(table).indexOf("seq")] === seq
        );
      });
    const rewrite = (index: number, column: string, value: unknown, table: string) =>
      lines.map((line, at) => {
        if (at !== index) {
          return line;
        }
        const row = parsedLine(line) as { values: unknown[] };
        const values = [...row.values];
        values[columnsOf(table).indexOf(column)] = value;
        return JSON.stringify({ ...row, values });
      });
    const liveHeads = await queryProjectDo(
      projectId,
      "SELECT seq, head_hash_hex FROM audit_head_hashes ORDER BY seq",
    );
    const negative = rewrite(rowIndex("audit_events", 2), "server_ts", -1, "audit_events");
    await expectRejected(await upload(negative, 50), "malformed");
    expect(await stagingTables()).toEqual([]);
    expect(
      await queryProjectDo(
        projectId,
        "SELECT seq, head_hash_hex FROM audit_head_hashes ORDER BY seq",
      ),
    ).toEqual(liveHeads);
    const headCount = Number(
      (parsedLine(lines[lines.length - 1])["rows"] as Record<string, number>)["audit_head_hashes"],
    );
    const bogusTail = rewrite(
      rowIndex("audit_head_hashes", headCount),
      "head_hash_hex",
      "not-a-hash",
      "audit_head_hashes",
    );
    await expectRejected(await upload(bogusTail, 50), "malformed");
    expect(await stagingTables()).toEqual([]);
    expect((await upload(lines, 50)).status).toBe(200);
    expect(await count("SELECT MAX(seq) AS n FROM audit_head_hashes")).toBe(
      await count("SELECT MAX(seq) AS n FROM audit_events"),
    );
    expect((await requestJson("GET", `/environments/${ENV}/pull`, token(READER))).status).toBe(200);
    const later = await exportAll();
    const laterSeq =
      (parsedLine(later[later.length - 1])["rows"] as Record<string, number>)["audit_events"] ?? 0;
    const lastRow = later.findIndex((line) => {
      const parsed = parsedLine(line);
      return (
        parsed["kind"] === "row" &&
        parsed["table"] === "audit_events" &&
        (parsed["values"] as unknown[])[columnsOf("audit_events").indexOf("seq")] === laterSeq
      );
    });
    expect(lastRow).toBeGreaterThan(-1);
    const laterNegative = later.map((line, at) => {
      if (at !== lastRow) {
        return line;
      }
      const row = parsedLine(line) as { values: unknown[] };
      const values = [...row.values];
      values[columnsOf("audit_events").indexOf("server_ts")] = 1.5;
      return JSON.stringify({ ...row, values });
    });
    await expectRejected(await upload(laterNegative, 50), "malformed");
    expect((await upload(later, 50)).status).toBe(200);
    expect((await unmark(OWNER)).status).toBe(200);
  });

  it("a replica without the head column's table line is derived from seq 1; a row under an intact column is checked by shape, not only by hashing (ruling J revision, round 11)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    expect((await mark(OWNER)).status).toBe(200);
    const lines = await exportAll();
    const trailer = parsedLine(lines[lines.length - 1]);
    const columnsOf = (table: string) =>
      parsedLine(
        lines[
          lines.findIndex((line) => {
            const parsed = parsedLine(line);
            return parsed["kind"] === "table" && parsed["table"] === table;
          })
        ],
      )["columns"] as string[];
    const withoutHeads = (from: readonly string[]) =>
      withTrailer(
        from.filter((line) => {
          const parsed = parsedLine(line);
          return parsed["table"] !== "audit_head_hashes";
        }),
        { rows: { ...(trailer["rows"] as object), audit_head_hashes: 0 } },
      );
    expect((await upload(withoutHeads(lines), 50)).status).toBe(200);
    expect(await count("SELECT MAX(seq) AS n FROM audit_head_hashes")).toBe(
      await count("SELECT MAX(seq) AS n FROM audit_events"),
    );
    expect((await mark(OWNER, "https://successor.maruhi.app")).status).toBe(200);
    const seqIndex = columnsOf("audit_events").indexOf("seq");
    const tsIndex = columnsOf("audit_events").indexOf("server_ts");
    const rowIdIndex = columnsOf("audit_events").indexOf("row_id");
    const foreign = (from: readonly string[], badSeq: number | null) =>
      from.map((line) => {
        const parsed = parsedLine(line);
        if (parsed["kind"] !== "row" || parsed["table"] !== "audit_events") {
          return line;
        }
        const values = [...(parsed["values"] as unknown[])];
        values[rowIdIndex] = `ff${String(values[rowIdIndex]).slice(2)}`;
        if (values[seqIndex] === badSeq) {
          values[tsIndex] = -1;
        }
        return JSON.stringify({ ...parsed, values });
      });
    const liveRows = await count("SELECT COUNT(*) AS n FROM audit_events");
    await expectRejected(await upload(withoutHeads(foreign(lines, 2)), 50), "malformed");
    expect(await stagingTables()).toEqual([]);
    expect(await count("SELECT COUNT(*) AS n FROM audit_events")).toBe(liveRows);
    await expectRejected(await upload(foreign(lines, 2), 50), "malformed");
    expect(await stagingTables()).toEqual([]);
    expect((await upload(foreign(lines, null), 50)).status).toBe(200);
    expect((await unmark(OWNER)).status).toBe(200);
  });

  it("the row shape in SQL refuses exactly what the canonical form refuses at the boundary, and never accepts a value the form refuses (ruling J revision, round 12)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    expect((await mark(OWNER)).status).toBe(200);
    const lines = await exportAll();
    const columns = parsedLine(
      lines[
        lines.findIndex((line) => {
          const parsed = parsedLine(line);
          return parsed["kind"] === "table" && parsed["table"] === "audit_events";
        })
      ],
    )["columns"] as string[];
    const seqIndex = columns.indexOf("seq");
    const rowIdIndex = columns.indexOf("row_id");
    const takenPrefixes = new Set(
      lines
        .map(parsedLine)
        .filter((parsed) => parsed["kind"] === "row" && parsed["table"] === "audit_events")
        .map((parsed) => String((parsed["values"] as unknown[])[rowIdIndex]).slice(0, 2)),
    );
    let tag = 0xa0;
    const variant = (seq: number, column: string, value: unknown) =>
      withTrailer(
        lines
          .filter((line) => parsedLine(line)["table"] !== "audit_head_hashes")
          .map((line) => {
            const parsed = parsedLine(line);
            if (parsed["kind"] !== "row" || parsed["table"] !== "audit_events") {
              return line;
            }
            const values = [...(parsed["values"] as unknown[])];
            values[rowIdIndex] = `${tag.toString(16)}${String(values[rowIdIndex]).slice(2)}`;
            if (values[seqIndex] === seq) {
              values[columns.indexOf(column)] = value;
            }
            return JSON.stringify({ ...parsed, values });
          }),
        {
          rows: {
            ...(parsedLine(lines[lines.length - 1])["rows"] as object),
            audit_head_hashes: 0,
          },
        },
      );
    let repoint = 0;
    const repointed = async () => {
      repoint += 1;
      do {
        tag += 1;
      } while (takenPrefixes.has(tag.toString(16)));
      expect((await mark(OWNER, `https://successor-${repoint}.maruhi.app`)).status).toBe(200);
    };
    for (const value of [9007199254740991, 2, "5"]) {
      await repointed();
      const response = await upload(variant(1, "server_ts", value), 50);
      expect(response.status, String(value)).toBe(200);
    }
    for (const value of [9007199254740992, -1, 1.5, "", "0x10", null]) {
      await repointed();
      await expectRejected(await upload(variant(1, "server_ts", value), 50), "malformed");
      expect(await stagingTables()).toEqual([]);
    }
    await repointed();
    await expectRejected(await upload(variant(2, "seq", 1.5), 50), "malformed");
    expect((await unmark(OWNER)).status).toBe(200);
  });

  it("refuses out-of-sequence and malformed pages with static reasons and discards the staging", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const lines = await exportAll();
    const header = parsedLine(lines[0]);
    expect((await mark(OWNER)).status).toBe(200);
    const stagedHead = async (): Promise<number | undefined> => (await statusOk()).nextSequence;

    await expectRejected(await page(OWNER, 1, lines.slice(0, 2)), "sequence-mismatch");
    await expectRejected(await page(OWNER, 0, lines.slice(1, 3)), "malformed");
    await expectRejected(
      await page(OWNER, 0, [
        JSON.stringify({ ...header, schemaVersion: Number(header["schemaVersion"]) + 1 }),
      ]),
      "schema-mismatch",
    );
    await expectRejected(
      await page(OWNER, 0, [
        lines[0] ?? "",
        JSON.stringify({ kind: "table", table: "nope", columns: ["a"] }),
      ]),
      "unknown-table",
    );
    await expectRejected(
      await page(OWNER, 0, [
        lines[0] ?? "",
        JSON.stringify({ kind: "table", table: "lease_windows", columns: ["kind", "count"] }),
      ]),
      "malformed",
    );
    await expectRejected(
      await page(OWNER, 0, [
        lines[0] ?? "",
        JSON.stringify({ kind: "row", table: "lease_windows", values: ["issued", 1, 1] }),
      ]),
      "malformed",
    );
    const tableLine = JSON.stringify({
      kind: "table",
      table: "lease_windows",
      columns: ["kind", "window_start", "count"],
    });
    const rows = Array.from({ length: 2_001 }, (_, index) =>
      JSON.stringify({ kind: "row", table: "lease_windows", values: [`k${index}`, 1, 1] }),
    );
    await expectRejected(
      await page(OWNER, 0, [lines[0] ?? "", tableLine, ...rows]),
      "page-too-large",
    );
    const hugeRow = JSON.stringify({
      kind: "row",
      table: "lease_windows",
      values: ["k".repeat(4 * 1024 * 1024 + 300 * 1024), 1, 1],
    });
    await expectRejected(
      await page(OWNER, 0, [lines[0] ?? "", tableLine, hugeRow]),
      "page-too-large",
    );
    expect((await page(OWNER, 0, lines.slice(0, 4))).status).toBe(200);
    expect(await stagedHead()).toBe(1);
    expect((await stagingTables()).length).toBeGreaterThan(0);
    await expectRejected(await page(OWNER, 5, lines.slice(4, 6)), "sequence-mismatch");
    expect(await stagedHead()).toBe(1);
    await expectRejected(await page(OWNER, 1, ["not json"]), "malformed");
    expect(await stagedHead()).toBeUndefined();
    expect(await stagingTables()).toEqual([]);
    await expectRejected(
      await upload(
        withTrailer(lines, {
          rows: { ...(parsedLine(lines[lines.length - 1])["rows"] as object), variables: 99 },
        }),
        50,
      ),
      "row-count-mismatch",
    );
    const forked = lines.map((line) => {
      const parsed = parsedLine(line);
      if (parsed["kind"] !== "row" || parsed["table"] !== "chain_entries") {
        return line;
      }
      const values = parsed["values"] as unknown[];
      return JSON.stringify({
        ...parsed,
        values: values.map((value) =>
          typeof value === "string" && /^[0-9a-f]{64}$/.test(value) ? `${"0".repeat(63)}1` : value,
        ),
      });
    });
    await expectRejected(await upload(forked, 50), "chain-not-extension");
    const chainColumns = lines
      .map((line) => parsedLine(line))
      .find((parsed) => parsed["kind"] === "table" && parsed["table"] === "chain_entries")?.[
      "columns"
    ] as string[];
    const entryJsonAt = chainColumns.indexOf("entry_json");
    const withChainEntries = (rewrite: (json: string) => string) =>
      lines.map((line) => {
        const parsed = parsedLine(line);
        if (parsed["kind"] !== "row" || parsed["table"] !== "chain_entries") {
          return line;
        }
        const values = [...(parsed["values"] as unknown[])];
        values[entryJsonAt] = rewrite(String(values[entryJsonAt]));
        return JSON.stringify({ ...parsed, values });
      });
    await expectRejected(
      await upload(
        withChainEntries(() => "{}"),
        50,
      ),
      "chain-invalid",
    );
    await expectRejected(
      await upload(
        withChainEntries(() => "not json"),
        50,
      ),
      "malformed",
    );
    await expectRejected(
      await upload(
        withChainEntries((json) => {
          const entry = JSON.parse(json) as { seq: number };
          return JSON.stringify({ ...entry, seq: entry.seq + 100 });
        }),
        50,
      ),
      "chain-invalid",
    );
    const firstAudit = lines.find((line) => {
      const parsed = parsedLine(line);
      return parsed["kind"] === "row" && parsed["table"] === "audit_events";
    });
    const duplicated = withTrailer(
      lines.flatMap((line) => (line === firstAudit ? [line, line] : [line])),
      {
        rows: {
          ...(parsedLine(lines[lines.length - 1])["rows"] as Record<string, number>),
          audit_events:
            Number(
              (parsedLine(lines[lines.length - 1])["rows"] as Record<string, number>)[
                "audit_events"
              ],
            ) + 1,
        },
      },
    );
    await expectRejected(await upload(duplicated, 50), "malformed");
    expect(await stagingTables()).toEqual([]);
    expect((await requestJson("GET", `/environments/${ENV}/pull`, token(READER))).status).toBe(200);
    const seqOf = (line: string): number => Number((parsedLine(line)["values"] as unknown[])[0]);
    const withoutAudit = withTrailer(
      lines.filter((line) => {
        const parsed = parsedLine(line);
        const auditLike =
          parsed["kind"] === "row" &&
          (parsed["table"] === "audit_events" || parsed["table"] === "audit_head_hashes");
        return !auditLike || seqOf(line) === 1;
      }),
      {
        rows: {
          ...(parsedLine(lines[lines.length - 1])["rows"] as object),
          audit_events: 1,
          audit_head_hashes: 1,
        },
      },
    );
    const same = await upload(lines, 50);
    expect(same.status).toBe(200);
    expect(((await same.json()) as WirePageOutcome).committed).toBeDefined();
    await expectRejected(await upload(withoutAudit, 50), "audit-regression");
    expect(await stagingTables()).toEqual([]);
  });

  it("refuses a line whose fields carry wrong types at decode — malformed on the page and the restore path", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const lines = await exportAll();
    const header = parsedLine(lines[0]);
    const rows = parsedLine(lines[lines.length - 1])["rows"] as Record<string, unknown>;
    expect((await mark(OWNER)).status).toBe(200);
    const wrongCount = withTrailer(lines, { rows: { ...rows, variables: "5" } });
    await expectRejected(await upload(wrongCount, 50), "malformed");
    await expectRejected(
      await page(OWNER, 0, [JSON.stringify({ ...header, schemaVersion: "3" })]),
      "malformed",
    );
    await expect(restoreLinesRefusal(wrongCount)).resolves.toBe("malformed");
  });

  it("serves a workload lease on a mirror and refuses the mint after authorization", async () => {
    await readyProject();
    expect((await mark(OWNER)).status).toBe(200);
    const workload = await workloadKeyPair();
    const oidcToken = await makeOidcToken();
    const leased = await requestLease({ oidcToken, ephemeralPubHex: workload.publicKeyHex });
    expect(leased.status).toBe(200);
    const mint = (tokenText: string) =>
      SELF.fetch(
        `https://maruhi.test/projects/${projectId}/environments/${ENV}/rotation-proposals`,
        {
          method: "POST",
          headers: JSON_HEADERS,
          body: JSON.stringify({
            oidcToken: tokenText,
            ephemeralPubHex: workload.publicKeyHex,
            proposal: {
              proposalId: "00112233445566778899aabbccddeeff",
              connector: "exec",
              facts: ["./scripts/rotate.sh: new credential produced"],
              expiresInDays: 7,
              variables: [
                {
                  variableId: VAR,
                  baseVersion: 1,
                  wraps: [
                    {
                      recipientUserId: OWNER,
                      recipientEncPubHex: vectorKeyOf(OWNER).enc_pub_hex,
                      encHex: "ab".repeat(32),
                      ciphertextHex: "cd".repeat(48),
                    },
                  ],
                },
              ],
            },
          }),
        },
      );
    const refused = await mint(oidcToken);
    expect(refused.status).toBe(422);
    await expect(refused.json()).resolves.toEqual({
      _tag: "RotationProposalRejected",
      reason: "mirror-read-only",
    });
    const stranger = await mint(
      await makeOidcToken({ subject: "repo:someone-else/demo:ref:refs/heads/main" }),
    );
    expect(stranger.status).toBe(404);
  });

  it("refuses a replica whose projections regress against the live state or do not bind to its chain, and still commits the legitimate one", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const older = await exportAll();
    await createVariableOk(dek, "var-second", "SECOND", "two");
    const newer = await exportAll();
    await restoreLines(older);
    expect((await mark(OWNER)).status).toBe(200);
    expect((await upload(older, 50)).status).toBe(200);

    const columnsOf = (lines: readonly string[], table: string) =>
      parsedLine(
        lines[
          lines.findIndex((line) => {
            const parsed = parsedLine(line);
            return parsed["kind"] === "table" && parsed["table"] === table;
          })
        ],
      )["columns"] as string[];
    const rowIndexOf = (
      lines: readonly string[],
      table: string,
      pick: (values: unknown[]) => boolean,
    ) =>
      lines.findIndex((line) => {
        const parsed = parsedLine(line);
        return (
          parsed["kind"] === "row" &&
          parsed["table"] === table &&
          pick(parsed["values"] as unknown[])
        );
      });
    const rewriteRow = (
      lines: readonly string[],
      table: string,
      pick: (values: unknown[]) => boolean,
      patch: (values: unknown[], columns: string[]) => void,
    ) => {
      const columns = columnsOf(lines, table);
      const index = rowIndexOf(lines, table, pick);
      expect(index).toBeGreaterThan(-1);
      return lines.map((line, at) => {
        if (at !== index) {
          return line;
        }
        const row = parsedLine(line) as { values: unknown[] };
        const values = [...row.values];
        patch(values, columns);
        return JSON.stringify({ ...row, values });
      });
    };
    const pulledCount = async (): Promise<number> => {
      const pulled = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
      expect(pulled.status).toBe(200);
      return ((await pulled.json()) as { variables: unknown[] }).variables.length;
    };

    const olderManifest = parsedLine(older[rowIndexOf(older, "environment_manifests", () => true)])[
      "values"
    ] as unknown[];
    const regressedManifest = rewriteRow(
      newer,
      "environment_manifests",
      () => true,
      (values) => {
        for (let index = 0; index < values.length; index += 1) {
          values[index] = olderManifest[index];
        }
      },
    );
    await expectRejected(await upload(regressedManifest, 50), "malformed");
    expect(await stagingTables()).toEqual([]);
    expect(await pulledCount()).toBe(1);

    const forgedCheckpoint = rewriteRow(
      newer,
      "environment_checkpoints",
      () => true,
      (values, columns) => {
        values[columns.indexOf("values_digest_hex")] = "ab".repeat(32);
      },
    );
    await expectRejected(await upload(forgedCheckpoint, 50), "malformed");
    expect(await stagingTables()).toEqual([]);
    expect(await pulledCount()).toBe(1);

    const varIdColumn = columnsOf(newer, "variable_meta_statements").indexOf("variable_id");
    const rewrittenStatement = rewriteRow(
      newer,
      "variable_meta_statements",
      (values) => values[varIdColumn] === VAR,
      (values, columns) => {
        values[columns.indexOf("name")] = "RENAMED";
      },
    );
    await expectRejected(await upload(rewrittenStatement, 50), "malformed");
    expect(await stagingTables()).toEqual([]);

    expect((await upload(newer, 50)).status).toBe(200);
    expect(await pulledCount()).toBe(2);
    expect((await unmark(OWNER)).status).toBe(200);
  });

  it("bootstraps into a fully empty mirror and replicates a variable deletion, an epoch rotation and an environment deletion cascade", async () => {
    const genesisOnly = await exportAll();
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await createVariableOk(dek, "var-second", "SECOND", "two");
    const withVars = await exportAll();
    expect((await deleteVariableRequest("var-second", OWNER)).status).toBe(204);
    const afterVarDelete = await exportAll();
    await rotateEnvironmentOk(fixture, MEMBER, ENV, 2);
    const afterRotate = await exportAll();
    expect((await deleteEnvironmentRequest(fixture, ENV, OWNER)).status).toBe(204);
    const afterEnvDelete = await exportAll();

    await restoreLines(genesisOnly);
    expect((await mark(OWNER)).status).toBe(200);
    expect(await count("SELECT COUNT(*) AS n FROM environments")).toBe(0);
    const pulledCount = async (): Promise<number> => {
      const pulled = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
      expect(pulled.status).toBe(200);
      return ((await pulled.json()) as { variables: unknown[] }).variables.length;
    };
    expect((await upload(withVars, 50)).status).toBe(200);
    expect(await pulledCount()).toBe(2);
    expect(await count("SELECT COUNT(*) AS n FROM dek_wraps")).toBe(3);
    expect((await upload(afterVarDelete, 50)).status).toBe(200);
    expect(await pulledCount()).toBe(1);
    expect((await upload(afterRotate, 50)).status).toBe(200);
    expect(await count("SELECT COUNT(*) AS n FROM dek_wraps")).toBe(6);
    expect(await pulledCount()).toBe(1);
    expect((await upload(afterEnvDelete, 50)).status).toBe(200);
    expect(await count("SELECT COUNT(*) AS n FROM dek_wraps")).toBe(0);
    expect(await count("SELECT COUNT(*) AS n FROM variables")).toBe(0);
    expect(await count("SELECT COUNT(*) AS n FROM checkpoint_snapshot_values")).toBe(0);
    const tombstone = await queryProjectDo(
      projectId,
      "SELECT deleted_at FROM environments WHERE environment_id = ?",
      ENV,
    );
    expect(tombstone[0]?.["deleted_at"]).not.toBeNull();
    expect(await stagingTables()).toEqual([]);
    expect((await unmark(OWNER)).status).toBe(200);
  });

  it("refuses replicas that drop, rewrite or resurrect wraps or attestations, flip the policy, or carry unanchored proposals or snapshot rows", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await setSchemaPolicyOk("locked");
    await queryProjectDo(
      projectId,
      "INSERT INTO head_attestations (attester_user_id, attester_key_fingerprint, suite, chain_head_seq, chain_head_hash_hex, signature_hex, accepted_at) VALUES (?, ?, 'maruhi/v1', ?, ?, ?, 1234)",
      MEMBER,
      vectorKeyOf(MEMBER).key_fingerprint_hex,
      fixture.head.seq,
      fixture.head.hashHex,
      "ab".repeat(64),
    );
    const older = await exportAll();
    const secondCreate = await createVariableV3Request({
      variableId: "var-second",
      name: "SECOND",
      plaintext: "two",
      dek,
      schema: { varType: "string" },
    });
    expect(secondCreate.status).toBe(200);
    const newer = await exportAll();
    await restoreLines(older);
    expect((await mark(OWNER)).status).toBe(200);
    expect((await upload(older, 50)).status).toBe(200);

    const columnsOf = (lines: readonly string[], table: string) =>
      parsedLine(
        lines[
          lines.findIndex((line) => {
            const parsed = parsedLine(line);
            return parsed["kind"] === "table" && parsed["table"] === table;
          })
        ],
      )["columns"] as string[];
    const rewriteRow = (
      lines: readonly string[],
      table: string,
      patch: (values: unknown[], columns: string[]) => void,
    ) => {
      const columns = columnsOf(lines, table);
      const index = lines.findIndex((line) => {
        const parsed = parsedLine(line);
        return parsed["kind"] === "row" && parsed["table"] === table;
      });
      expect(index).toBeGreaterThan(-1);
      return lines.map((line, at) => {
        if (at !== index) {
          return line;
        }
        const row = parsedLine(line) as { values: unknown[] };
        const values = [...row.values];
        patch(values, columns);
        return JSON.stringify({ ...row, values });
      });
    };
    const trailerRows = (lines: readonly string[]) =>
      parsedLine(lines[lines.length - 1])["rows"] as Record<string, number>;
    const withoutRows = (lines: readonly string[], table: string) =>
      withTrailer(
        lines.filter((line) => {
          const parsed = parsedLine(line);
          return !(parsed["kind"] === "row" && parsed["table"] === table);
        }),
        { rows: { ...trailerRows(lines), [table]: 0 } },
      );
    const insertRow = (lines: readonly string[], table: string, values: unknown[]) => {
      const tableIndex = lines.findIndex((line) => {
        const parsed = parsedLine(line);
        return parsed["kind"] === "table" && parsed["table"] === table;
      });
      expect(tableIndex).toBeGreaterThan(-1);
      const rowLine = JSON.stringify({ kind: "row", table, values });
      return withTrailer(
        [...lines.slice(0, tableIndex + 1), rowLine, ...lines.slice(tableIndex + 1)],
        { rows: { ...trailerRows(lines), [table]: (trailerRows(lines)[table] ?? 0) + 1 } },
      );
    };
    const pulledCount = async (): Promise<number> => {
      const pulled = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
      expect(pulled.status).toBe(200);
      return ((await pulled.json()) as { variables: unknown[] }).variables.length;
    };

    await expectRejected(await upload(withoutRows(newer, "dek_wraps"), 50), "malformed");
    expect(await stagingTables()).toEqual([]);
    const rewrittenWrap = rewriteRow(newer, "dek_wraps", (values, columns) => {
      values[columns.indexOf("ciphertext_hex")] = "ff".repeat(48);
    });
    await expectRejected(await upload(rewrittenWrap, 50), "malformed");
    expect(await stagingTables()).toEqual([]);
    await expectRejected(await upload(withoutRows(newer, "head_attestations"), 50), "malformed");
    expect(await stagingTables()).toEqual([]);
    const forgedMark = rewriteRow(newer, "head_attestations", (values, columns) => {
      values[columns.indexOf("accepted_at")] = 9999999999999;
    });
    await expectRejected(await upload(forgedMark, 50), "malformed");
    expect(await stagingTables()).toEqual([]);
    const unresolvedHead = insertRow(newer, "head_attestations", [
      READER,
      "cd".repeat(16),
      "maruhi/v1",
      fixture.head.seq,
      "00".repeat(32),
      "ab".repeat(64),
      9999,
    ]);
    await expectRejected(await upload(unresolvedHead, 50), "malformed");
    expect(await stagingTables()).toEqual([]);
    const flippedPolicy = rewriteRow(newer, "project_settings", (values, columns) => {
      values[columns.indexOf("schema_policy")] = "enabled";
    });
    await expectRejected(await upload(flippedPolicy, 50), "malformed");
    expect(await stagingTables()).toEqual([]);
    const unanchoredProposal = insertRow(newer, "rotation_proposals", [
      "00112233445566778899aabbccddeeff",
      ENV,
      "exec",
      "[]",
      "ab".repeat(32),
      fixture.head.seq,
      1,
      9999999999999,
    ]);
    await expectRejected(await upload(unanchoredProposal, 50), "malformed");
    expect(await stagingTables()).toEqual([]);
    const extraSnapshot = insertRow(newer, "checkpoint_snapshot_values", [
      ENV,
      "var-extra",
      1,
      "ab".repeat(32),
    ]);
    await expectRejected(await upload(extraSnapshot, 50), "malformed");
    expect(await stagingTables()).toEqual([]);
    expect(await pulledCount()).toBe(1);

    expect((await upload(newer, 50)).status).toBe(200);
    expect(await pulledCount()).toBe(2);
    expect((await unmark(OWNER)).status).toBe(200);
  });
});
