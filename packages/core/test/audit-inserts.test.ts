// Tripwire: every new audit row goes through a store's checked serialization
// point (audit-payloads.ts — the payload against its event's AUDIT_SPEC §3
// schema). The types hold the shape at each write; this holds the route:
//
// - D1 (AUDIT_SPEC §5.2): an insert into `userAuditEvents` / `orgAuditEvents`
//   builds its row with `rowOf(` (db.package/audit.ts) or its SELECT with
//   `guardedAuditSelectColumns(`; outside that file and the schema the tables
//   appear only in such an insert, an import, a read (`.from(table)`) or a
//   column reference (`table.column`) — never updated, deleted or aliased
//   into something that could carry an unchecked insert.
// - The project DO (§5.1): the `INSERT INTO audit_events` statement exists
//   once, in audit-store.ts, and each use of it binds `eventBindings(` inside
//   an append that ran `assertAppendable(` first.
//
// Out of scope by design: the replication and restore paths copy existing
// rows table by table (do-mirror.ts / do-snapshot.ts — checked by the restore
// reader, AUTH_SPEC §11-6); they write no new event.

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const SERVER_SRC = join(import.meta.dirname, "../../../apps/server/src");
const D1_TABLES = ["userAuditEvents", "orgAuditEvents"];
/** Where the D1 audit tables may be named outside an insert: their definition, and the store's reads. */
const D1_TABLE_HOMES = new Set(["db.package/schema.ts", "db.package/audit.ts"]);
const DO_STORE = "audit-store.ts";

function serverSources(): ReadonlyMap<string, string> {
  return new Map(
    readdirSync(SERVER_SRC, { recursive: true, encoding: "utf8" })
      .filter((path) => path.endsWith(".ts"))
      .map((path) => [path, readFileSync(join(SERVER_SRC, path), "utf8")]),
  );
}

/** The call chain that starts at `start`: up to the end of the first call after the `insert(…)` (`.values(…)` / `.select(…)`). */
function insertStatement(text: string, start: number): string {
  let depth = 0;
  let closedCalls = 0;
  for (let index = start; index < text.length; index += 1) {
    const char = text[index];
    if (char === "(") {
      depth += 1;
    } else if (char === ")") {
      depth -= 1;
      if (depth === 0) {
        closedCalls += 1;
        // insert(table) is the first call, .values(...) / .select(...) the second
        if (closedCalls === 2) {
          return text.slice(start, index + 1);
        }
      }
    }
  }
  return text.slice(start);
}

/** A reference that cannot write: an import specifier, `.from(table)`, or `table.column`. */
function isReadOrImport(text: string, index: number, table: string, lineText: string): boolean {
  const after = text.slice(index + table.length, index + table.length + 1);
  const before = text.slice(Math.max(0, index - 6), index);
  return (
    /^\s*(import\b|\w+,\s*$|[\w\s,{}]*\} from\b)/.test(lineText) ||
    before.endsWith("from(") ||
    after === "."
  );
}

/** Every violation of the D1 route in the given sources (path:line: what). */
function d1RouteViolations(sources: ReadonlyMap<string, string>): readonly string[] {
  return [...sources].flatMap(([path, text]) =>
    D1_TABLES.flatMap((table) =>
      [...text.matchAll(new RegExp(`\\b${table}\\b`, "g"))].flatMap((match) =>
        d1ReferenceViolation(path, text, table, match.index),
      ),
    ),
  );
}

/** The violation one reference to a D1 audit table makes, if any. */
function d1ReferenceViolation(
  path: string,
  text: string,
  table: string,
  index: number,
): readonly string[] {
  const line = text.slice(0, index).split("\n").length;
  const before = text.slice(Math.max(0, index - 40), index);
  if (/\binsert\(\s*$/.test(before)) {
    const statement = insertStatement(text, before.lastIndexOf("insert(") + index - before.length);
    const checked =
      statement.includes("rowOf(") || statement.includes("guardedAuditSelectColumns(");
    return checked
      ? []
      : [`${path}:${line}: insert(${table}) without rowOf( / guardedAuditSelectColumns(`];
  }
  const lineText = text.split("\n")[line - 1] ?? "";
  return D1_TABLE_HOMES.has(path) || isReadOrImport(text, index, table, lineText)
    ? []
    : [`${path}:${line}: ${table} named outside an insert, a read or an import`];
}

/** Every violation of the project DO's route (path:line: what). */
function doRouteViolations(sources: ReadonlyMap<string, string>): readonly string[] {
  const violations: string[] = [];
  for (const [path, text] of sources) {
    for (const match of text.matchAll(/INSERT INTO audit_events\b/g)) {
      if (path !== DO_STORE) {
        const line = text.slice(0, match.index).split("\n").length;
        violations.push(`${path}:${line}: INSERT INTO audit_events outside ${DO_STORE}`);
      }
    }
  }
  const store = sources.get(DO_STORE) ?? "";
  const uses = [...store.matchAll(/\bINSERT_COLUMNS \+/g)];
  if (uses.length === 0) {
    violations.push(`${DO_STORE}: no use of INSERT_COLUMNS found (the tripwire lost its anchor)`);
  }
  for (const use of uses) {
    const line = store.slice(0, use.index).split("\n").length;
    const append = store.slice(store.lastIndexOf("Sync: (", use.index), use.index + 400);
    if (!append.includes("assertAppendable(") || !append.includes("eventBindings(")) {
      violations.push(
        `${DO_STORE}:${line}: an audit_events insert without assertAppendable( + eventBindings(`,
      );
    }
  }
  return violations;
}

describe("every new audit row goes through a checked serialization point", () => {
  const sources = serverSources();

  it("finds the inserts it guards", () => {
    const d1Inserts = [...sources.values()].join("\n").match(/insert\((?:user|org)AuditEvents\)/g);
    expect(d1Inserts?.length ?? 0).toBeGreaterThan(10);
    expect(sources.get(DO_STORE)).toContain("INSERT INTO audit_events");
  });

  it("D1: every audit insert builds its row with rowOf( or guardedAuditSelectColumns(", () => {
    expect(d1RouteViolations(sources)).toEqual([]);
  });

  it("project DO: the one audit insert runs behind assertAppendable(", () => {
    expect(doRouteViolations(sources)).toEqual([]);
  });

  it("bites: an unchecked insert, an aliased table and a stray DO insert are reported", () => {
    const probe = new Map(sources);
    probe.set(
      "db.package/probe.ts",
      [
        'import { userAuditEvents } from "./schema.ts";',
        "export const raw = (db) => db.insert(userAuditEvents).values({ payload: '{}' });",
        "const alias = userAuditEvents;",
        "export const wipe = (db) => db.delete(userAuditEvents);",
        "export const read = (db) => db.select().from(userAuditEvents).where(userAuditEvents.seq);",
      ].join("\n"),
    );
    probe.set("programs/probe.ts", 'sql.exec("INSERT INTO audit_events (seq) VALUES (1)");');
    expect(d1RouteViolations(probe)).toEqual([
      "db.package/probe.ts:2: insert(userAuditEvents) without rowOf( / guardedAuditSelectColumns(",
      "db.package/probe.ts:3: userAuditEvents named outside an insert, a read or an import",
      "db.package/probe.ts:4: userAuditEvents named outside an insert, a read or an import",
    ]);
    expect(doRouteViolations(probe)).toEqual([
      "programs/probe.ts:1: INSERT INTO audit_events outside audit-store.ts",
    ]);
  });
});
