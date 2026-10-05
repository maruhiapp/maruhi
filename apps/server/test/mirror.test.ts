// Integration tests for mirrors (PF2 — AUTH_SPEC §11-7,
// docs/notes/pf2-design.md). The HttpApi and the DO via SELF on
// @cloudflare/vitest-plugin (the real workerd environment). One deployment
// plays both roles: the project is seeded and exported (the source's
// replica), restored to an older state, marked, and replicated forward.
//
// What this suite pins:
// - the mark is owner-only; a marked project refuses every write with
//   Forbidden `mirror-read-only` and serves reads and leases; the mint
//   is refused after authorization in the proposal vocabulary
// - the pages stage in sequence, the trailer's page commits, the mirror
//   then serves the replica (chain head, variables, audit log), keeps its
//   own lease windows and its own audit rows (re-appended after the
//   replica's), and leaves no staging behind
// - a replica that does not extend the live chain, an out-of-sequence
//   page, and every malformed shape are refused with the static reasons,
//   and a refusal discards the staging in progress
// - unmarking promotes the mirror (writes accepted again)

import { env, runInDurableObject, SELF } from "cloudflare:test";
import { Effect } from "effect";
import { describe, expect, it } from "vitest";

import { PROJECT_DO_TABLES, readProjectDoSchemaVersion } from "../src/do/do-schema.ts";
import { restoreSnapshot, type RestoreFailureCode } from "../src/do/do-snapshot.ts";
import { JSON_HEADERS } from "./support/auth.ts";
import { changeRoleOperation, signEntryAt, vectorKeyOf } from "./support/data-crypto.ts";
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
import { readyProject, requestLease, workloadKeyPair } from "./support/lease-scenario.ts";
import { makeOidcToken } from "./support/lease.ts";
import { evictProjectDo, queryProjectDo, resetProjectDo } from "./support/project-do.ts";

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
    readonly attestationMark?: number;
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

/** Pages the whole export as the CLI does. */
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

/** Restores an exported replica into the emptied DO (the mirror's bootstrap = the §11-6 import). */
async function restoreLines(lines: readonly string[]): Promise<void> {
  await resetProjectDo(projectId);
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
  const text = `${lines.join("\n")}\n`;
  await runInDurableObject(stub, async (_instance, state) => {
    // The stream is created inside the DO's context (an I/O object of
    // the test context cannot be read on behalf of the DO)
    await Effect.runPromise(
      restoreSnapshot({
        storage: state.storage,
        tables: PROJECT_DO_TABLES,
        schemaVersion: readProjectDoSchemaVersion(state.storage.sql),
        body: new Blob([text]).stream().pipeThrough(new CompressionStream("gzip")),
      }),
    );
  });
  await evictProjectDo(projectId);
}

/** Restores like restoreLines but answers the refusal's code (null = the import committed). */
async function restoreLinesRefusal(lines: readonly string[]): Promise<RestoreFailureCode | null> {
  await resetProjectDo(projectId);
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
  const text = `${lines.join("\n")}\n`;
  const code = await runInDurableObject(stub, async (_instance, state) =>
    Effect.runPromise(
      restoreSnapshot({
        storage: state.storage,
        tables: PROJECT_DO_TABLES,
        schemaVersion: readProjectDoSchemaVersion(state.storage.sql),
        body: new Blob([text]).stream().pipeThrough(new CompressionStream("gzip")),
      }).pipe(
        Effect.map((): RestoreFailureCode | null => null),
        Effect.catchTag("RestoreRefused", (error) => Effect.succeed(error.code)),
      ),
    ),
  );
  await evictProjectDo(projectId);
  return code;
}

const status = (userId = READER) => requestJson("GET", "/mirror", token(userId));
const mark = (userId: string, sourceOrigin = SOURCE) =>
  requestJson("PUT", "/mirror", token(userId), { sourceOrigin });
const unmark = (userId: string) => requestJson("DELETE", "/mirror", token(userId));
const page = (userId: string, sequence: number, lines: readonly string[]) =>
  requestJson("PUT", "/mirror/pages", token(userId), { sequence, lines });

async function statusOk(userId = READER): Promise<WireStatus> {
  const response = await status(userId);
  expect(response.status).toBe(200);
  return (await response.json()) as WireStatus;
}

/** Uploads a replica in pages of `size` lines (as the owner); returns the last page's answer. */
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

/** A chain append the fixture does not expect to succeed (the raw request). */
async function rawAppend(actorUserId: string): Promise<Response> {
  const { entry } = await signEntryAt({
    seq: fixture.head.seq + 1,
    prevHashHex: fixture.head.hashHex,
    actorUserId,
    operation: changeRoleOperation(READER, "member"),
  });
  return requestJson("POST", "/chain/entries", token(actorUserId), {
    parentHeadHashHex: fixture.head.hashHex,
    entry,
  });
}

/** Rewrites one field of the lines' trailer. */
function withTrailer(lines: readonly string[], patch: Record<string, unknown>): string[] {
  const trailer = parsedLine(lines[lines.length - 1]);
  return [...lines.slice(0, -1), JSON.stringify({ ...trailer, ...patch })];
}

describe("mirrors (AUTH_SPEC §11-7)", () => {
  it("marks, refuses writes, serves reads, replicates forward, keeps its own windows and audit rows, and promotes", async () => {
    // The source's history: an older replica (R1) and a newer one (R2)
    // whose chain extends R1's
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const older = await exportAll();
    const olderTrailer = parsedLine(older[older.length - 1]);
    await appendOperation(fixture, OWNER, changeRoleOperation(READER, "member"));
    await createVariableOk(dek, "var-second", "SECOND", "two");
    expect((await requestJson("GET", `/environments/${ENV}/pull`, token(READER))).status).toBe(200);
    // The source's first-come bindings travel with the export (merged into
    // the mirror's own at commit, never replacing one — ruling D revision)
    await queryProjectDo(
      projectId,
      "INSERT INTO lease_bindings (binding_key_hex, ephemeral_pub_hex, expires_at) VALUES ('ab', 'zz', 9999999999999), ('source-only', 'ef', 9999999999999), ('source-expired', 'ee', 1)",
    );
    const newer = await exportAll();
    const newerTrailer = parsedLine(newer[newer.length - 1]);
    expect(Number(newerTrailer["chainHeadSeq"])).toBe(Number(olderTrailer["chainHeadSeq"]) + 1);

    // The mirror's bootstrap: the older replica restored, then the mark
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
    // A mark naming another source re-points the mirror without a writable
    // window (ruling C revision, round 4); the same source is still a
    // second mark. The replicated positions stay (the chain head below
    // still bootstraps the replication)
    const repointed = await mark(OWNER, "https://other.maruhi.app");
    expect(repointed.status).toBe(200);
    expect(await repointed.json()).toMatchObject({
      mirror: true,
      sourceOrigin: "https://other.maruhi.app",
      head: { chainHeadSeq: olderTrailer["chainHeadSeq"] },
    });
    expect((await mark(OWNER)).status).toBe(200);
    expect((await statusOk()).sourceOrigin).toBe(SOURCE);

    // Writes are refused after the membership check (a non-member keeps
    // the uniform 404 — the mark is not an oracle), before any state change
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
      schemaPolicy: "enabled",
    });
    expect(policy.status).toBe(403);
    expect((await requestJson("GET", "/schema-policy", token(READER))).status).toBe(200);
    // … reads are served (and the pull leaves the mirror's own audit rows)
    const pulled = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pulled.status).toBe(200);
    expect(((await pulled.json()) as { variables: unknown[] }).variables).toHaveLength(1);
    expect((await requestJson("GET", "/audit/events", token(READER))).status).toBe(200);
    const ownRows = await count(
      `SELECT COUNT(*) AS n FROM audit_events WHERE seq > ${Number(olderTrailer["auditMaxSeq"])}`,
    );
    expect(ownRows).toBeGreaterThan(0);
    // … and the mirror's own rate-limit and first-come state (every kept table)
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

    // The replication (admin or above): pages in sequence, the status shows the progress
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
        // The rows the mirror appended while serving (the pull above)
        ownAuditRows: ownRows,
      },
    });
    const synced = await statusOk(OWNER);
    expect(synced.lastSync).toMatchObject({
      chainHeadSeq: newerTrailer["chainHeadSeq"],
      attestationMark: 0,
    });
    expect(synced.nextSequence).toBeUndefined();
    expect(synced.head.chainHeadHashHex).toBe(newerTrailer["chainHeadHashHex"]);
    expect(synced.head.auditMaxSeq).toBeGreaterThanOrEqual(Number(newerTrailer["auditMaxSeq"]));
    // A reader sees the mark, the source and the chain head — never the
    // audit seq or the replication history (AUDIT_SPEC §7 C1)
    const readerView = await statusOk(READER);
    expect(readerView.sourceOrigin).toBe(SOURCE);
    expect(readerView.head.chainHeadHashHex).toBe(newerTrailer["chainHeadHashHex"]);
    expect(readerView.head.auditMaxSeq).toBeUndefined();
    expect(readerView.lastSync).toBeUndefined();
    // The mirror serves the replica now
    const chain = await requestJson("GET", "/chain", token(READER));
    expect(chain.status).toBe(200);
    expect(((await chain.json()) as { headSeq: number }).headSeq).toBe(
      newerTrailer["chainHeadSeq"],
    );
    const pulledAgain = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pulledAgain.status).toBe(200);
    expect(((await pulledAgain.json()) as { variables: unknown[] }).variables).toHaveLength(2);
    // The kept table, the re-appended own rows, the derived column, no staging
    expect(
      await queryProjectDo(projectId, "SELECT count FROM lease_windows WHERE kind = 'issued'"),
    ).toEqual([{ count: 7 }]);
    // The mirror's own binding stays ('ab' → 'cd', not the source's 'zz'); the
    // source's other live one is merged; expired ones of either side are gone
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
    expect(await count("SELECT COUNT(*) AS n FROM audit_events")).toBe(
      // the second pull above added rows after the sync too
      replicaAudit + ownRows + 1,
    );
    const carried = await queryProjectDo(
      projectId,
      `SELECT event FROM audit_events WHERE seq > ${replicaAudit} ORDER BY seq`,
    );
    expect(carried.map((row) => row["event"])).toEqual([
      ...Array.from({ length: ownRows }, () => "var.read"),
      "var.read",
    ]);
    // The derived audit-head column was extended to the end at the commit
    // (the pull after it extends lazily, as always)
    expect(await count("SELECT MAX(seq) AS n FROM audit_head_hashes")).toBe(replicaAudit + ownRows);
    expect(await stagingTables()).toEqual([]);
    // A second replication of the same replica re-appends the own rows
    // (now one more — the pull after the first sync) after the replica's again
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
    // A replica of the same length whose audit log is not the replicated
    // one (the cumulative hash at the position differs) is refused — the
    // rows the mirror served are never rewritten (ruling J revision, round 6)
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
    // … and one whose column differs BELOW the position: the served heads
    // are the mirror's own derivation, so the uploaded column is a claim
    // checked against them in full, never installed (ruling J revision,
    // round 8)
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
    // A legitimate replica leaves the heads up to the position untouched and
    // derives the rest (the whole column reaches the end again)
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
    // The prefix checks join the staged log on an index, never a scan of it
    // (ruling J revision, round 8): the staging tables carry the live
    // tables' column affinities and an index on seq
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
    // … and so is one that rewrites a row at or below the replicated
    // position while carrying the column untouched: the prefix is compared
    // row for row, not by an uploaded hash (ruling J revision, round 7)
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
    // An older replica never replaces a newer one
    await expectRejected(await upload(older, 50), "chain-not-extension");
    expect((await statusOk()).nextSequence).toBeUndefined();

    // The promotion: writes accepted again
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
    await appendOperation(fixture, OWNER, changeRoleOperation(READER, "reader"));
  });

  it("a frozen former primary syncs back from the destination: the rows its export carried are not re-appended (ruling J revision, round 4)", async () => {
    // The switch-over order of §11-6: the source is marked (frozen) first,
    // then exported. Its audit rows between the mark and the export's own
    // row travel in the file and come back in the destination's replica;
    // only the rows the replica does not carry are the mirror's own
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    expect((await mark(OWNER, "https://destination.maruhi.app")).status).toBe(200);
    const markedAudit = await count("SELECT MAX(seq) AS n FROM audit_events");
    expect((await requestJson("GET", `/environments/${ENV}/pull`, token(READER))).status).toBe(200);
    const exported = await exportAll();
    const trailer = parsedLine(exported[exported.length - 1]);
    const exportedAudit = Number(trailer["auditMaxSeq"]);
    expect(exportedAudit).toBeGreaterThan(markedAudit + 1);
    // A read after the export: the one row the replica does not carry
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
    // A re-point resets the audit floor (ruling C revision, round 5): every
    // row of the log is the mirror's own against the new source — and
    // clears the replication record (ruling H revision, round 9: what the
    // status reports as the last replication is one from the current source)
    expect((await statusOk(OWNER)).lastSync).toBeDefined();
    expect((await mark(OWNER, "https://successor.maruhi.app")).status).toBe(200);
    expect((await statusOk(OWNER)).lastSync).toBeUndefined();
    // A carried row is the mirror's own row byte for byte: a replica that
    // carries one of its row ids with other content cannot rewrite the
    // evidence the mirror witnessed (ruling J revision, round 5)
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
    // The first replica from the new source commits whatever its audit seq,
    // and the rows it does not carry (the two reads) follow it
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
    // A gap: row 2 missing (the trailer agrees on the count)
    const second = auditRowAt(2);
    expect(second).toBeGreaterThan(-1);
    const gapped = withTrailer(
      lines.filter((_, index) => index !== second),
      { rows: { ...(trailer["rows"] as object), audit_events: rowsOf("audit_events") - 1 } },
    );
    await expectRejected(await upload(gapped, 50), "malformed");
    expect(await stagingTables()).toEqual([]);
    expect(await count("SELECT COUNT(*) AS n FROM audit_events")).toBe(liveRows);
    // A seq at 0 (the live primary key accepts it; the log would not be hashable)
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
    // A head column longer than the log (no audit rows, the full column):
    // the first replica after a mark installs the column, so phantom heads
    // would be served from nothing
    const headsOnly = withTrailer(
      lines.filter((line) => {
        const parsed = parsedLine(line);
        return !(parsed["kind"] === "row" && parsed["table"] === "audit_events");
      }),
      { rows: { ...(trailer["rows"] as object), audit_events: 0 } },
    );
    await expectRejected(await upload(headsOnly, 50), "malformed");
    // A column shorter than the log is the normal lazy state: accepted and extended
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
    // … and the mirror still syncs (nothing was bricked)
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
    // A server_ts the canonical form refuses (the schema accepts it)
    const negative = rewrite(rowIndex("audit_events", 2), "server_ts", -1, "audit_events");
    await expectRejected(await upload(negative, 50), "malformed");
    expect(await stagingTables()).toEqual([]);
    expect(
      await queryProjectDo(
        projectId,
        "SELECT seq, head_hash_hex FROM audit_head_hashes ORDER BY seq",
      ),
    ).toEqual(liveHeads);
    // A first replica whose uploaded column's tail is no head hash (with
    // the column reaching the log's end, nothing would have derived from it
    // until the mirror's first own row)
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
    // The intact replica commits, its heads derived past the uploaded
    // column; the column reaches the end at the commit
    expect((await upload(lines, 50)).status).toBe(200);
    expect(await count("SELECT MAX(seq) AS n FROM audit_head_hashes")).toBe(
      await count("SELECT MAX(seq) AS n FROM audit_events"),
    );
    // Past a replicated position the same row is refused the same way (the
    // derivation starts from the mirror's own head at the position)
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
    // No column at all: derived from seq 1 before the swap, so the commit
    // installs a column reaching the log's end
    expect((await upload(withoutHeads(lines), 50)).status).toBe(200);
    expect(await count("SELECT MAX(seq) AS n FROM audit_head_hashes")).toBe(
      await count("SELECT MAX(seq) AS n FROM audit_events"),
    );
    // … and a bad row in such a replica is refused before anything live is
    // touched (every row is derived over). A re-point makes the next
    // replica a first one again (position 0), with the mirror's rows now
    // its own (a foreign row id never matches the carried-row rule)
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
    // Under an intact column that reaches the log's end nothing is derived
    // over the row: its shape refuses it all the same (round 11)
    await expectRejected(await upload(foreign(lines, 2), 50), "malformed");
    expect(await stagingTables()).toEqual([]);
    // The same replica with the row intact commits (a first replica after the re-point)
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
    // Foreign row ids (the carried-row rule never matches), and one
    // column of one row rewritten; the uploaded head column is dropped so
    // every row is derived over as well as shape-checked
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
            // A row id set of its own per variant: a carried row id with
            // other content is a rewrite, refused for its own reason
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
    // Each accepted replica commits at position 0 (a re-point before each)
    let repoint = 0;
    const repointed = async () => {
      repoint += 1;
      tag += 1;
      expect((await mark(OWNER, `https://successor-${repoint}.maruhi.app`)).status).toBe(200);
    };
    // Accepted by both (the affinity converts the text and the real)
    for (const value of [9007199254740991, 2, "5"]) {
      await repointed();
      const response = await upload(variant(1, "server_ts", value), 50);
      expect(response.status, String(value)).toBe(200);
    }
    // Refused by both, or by the SQL alone in the fail-closed direction
    for (const value of [9007199254740992, -1, 1.5, "", "0x10", null]) {
      await repointed();
      await expectRejected(await upload(variant(1, "server_ts", value), 50), "malformed");
      expect(await stagingTables()).toEqual([]);
    }
    // A fractional seq is refused at the trailer, not at the swap's rowid
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
    // A page past the row bound
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
    // A page past the byte bound (one line over the export's bound plus the slack)
    const hugeRow = JSON.stringify({
      kind: "row",
      table: "lease_windows",
      values: ["k".repeat(4 * 1024 * 1024 + 300 * 1024), 1, 1],
    });
    await expectRejected(
      await page(OWNER, 0, [lines[0] ?? "", tableLine, hugeRow]),
      "page-too-large",
    );
    // Staged pages, then a refusal: the staging is discarded (sequence 0 restarts)
    expect((await page(OWNER, 0, lines.slice(0, 4))).status).toBe(200);
    expect(await stagedHead()).toBe(1);
    expect((await stagingTables()).length).toBeGreaterThan(0);
    await expectRejected(await page(OWNER, 5, lines.slice(4, 6)), "sequence-mismatch");
    // … the sequence refusal keeps it
    expect(await stagedHead()).toBe(1);
    await expectRejected(await page(OWNER, 1, ["not json"]), "malformed");
    expect(await stagedHead()).toBeUndefined();
    expect(await stagingTables()).toEqual([]);
    // The trailer's counts
    await expectRejected(
      await upload(
        withTrailer(lines, {
          rows: { ...(parsedLine(lines[lines.length - 1])["rows"] as object), variables: 99 },
        }),
        50,
      ),
      "row-count-mismatch",
    );
    // A forked chain (one entry hash rewritten)
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
    // A chain whose hashes match but whose entries do not verify never
    // replaces the live one (the replica's content, not only its hashes)
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
    // An entry that decodes but whose hash column lies about it
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
    // The live table refuses a staged row (a duplicate audit seq): refused, never a defect
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
    // The project still serves (the live tables were untouched)
    expect((await requestJson("GET", `/environments/${ENV}/pull`, token(READER))).status).toBe(200);
    // An audit log behind the last replicated position (contiguous — a
    // log that is not 1..N is malformed before any position is compared,
    // ruling J revision, round 9): the first row and the first head only
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
    // The same replica (no change) commits — and sets the audit position:
    // the mark itself starts the position at 0 (ruling C revision, round
    // 5), so only a replica behind a replicated position regresses
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
    // A string count in the trailer's rows: refused at decode, before
    // the count check (a well-typed wrong count is row-count-mismatch, above)
    const wrongCount = withTrailer(lines, { rows: { ...rows, variables: "5" } });
    await expectRejected(await upload(wrongCount, 50), "malformed");
    // A string schemaVersion: refused at decode (a numeric mismatch is
    // schema-mismatch, above)
    await expectRejected(
      await page(OWNER, 0, [JSON.stringify({ ...header, schemaVersion: "3" })]),
      "malformed",
    );
    // The restore's reader decodes the same wire union: the same forged
    // trailer is malformed on the import too
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
    // An unauthorized workload still gets the uniform 404 (the mark is judged after authorization)
    const stranger = await mint(
      await makeOidcToken({ subject: "repo:someone-else/demo:ref:refs/heads/main" }),
    );
    expect(stranger.status).toBe(404);
  });
});
