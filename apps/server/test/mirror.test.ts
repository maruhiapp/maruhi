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
import { describe, expect, it } from "vitest";

import { PROJECT_DO_TABLES, readProjectDoSchemaVersion } from "../src/do-schema.ts";
import { restoreSnapshot } from "../src/do-snapshot.ts";
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
  readonly lastSync?: { readonly chainHeadSeq: number; readonly auditMaxSeq: number };
  readonly nextSequence?: number;
  readonly head: { readonly chainHeadSeq: number; readonly chainHeadHashHex: string };
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
    await restoreSnapshot({
      storage: state.storage,
      tables: PROJECT_DO_TABLES,
      schemaVersion: readProjectDoSchemaVersion(state.storage.sql),
      body: new Blob([text]).stream().pipeThrough(new CompressionStream("gzip")),
    });
  });
  await evictProjectDo(projectId);
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

    // Writes are refused after authentication, before any state change
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
    // … and the mirror's own first-come state
    await queryProjectDo(
      projectId,
      "INSERT INTO lease_windows (kind, window_start, count) VALUES ('issued', 1, 7)",
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
      },
    });
    const synced = await statusOk();
    expect(synced.lastSync).toMatchObject({ chainHeadSeq: newerTrailer["chainHeadSeq"] });
    expect(synced.nextSequence).toBeUndefined();
    expect(synced.head.chainHeadHashHex).toBe(newerTrailer["chainHeadHashHex"]);
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
    // An audit log behind the last replicated position
    const withoutAudit = withTrailer(
      lines.filter((line) => {
        const parsed = parsedLine(line);
        return !(parsed["kind"] === "row" && parsed["table"] === "audit_events");
      }),
      { rows: { ...(parsedLine(lines[lines.length - 1])["rows"] as object), audit_events: 0 } },
    );
    await expectRejected(await upload(withoutAudit, 50), "audit-regression");
    // The same replica (no change) commits
    const same = await upload(lines, 50);
    expect(same.status).toBe(200);
    expect(((await same.json()) as WirePageOutcome).committed).toBeDefined();
    expect(await stagingTables()).toEqual([]);
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
              expiresAtMs: Date.now() + 7 * 24 * 60 * 60 * 1000,
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
