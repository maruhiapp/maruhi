// scripts/reorder-d1-dump.ts の純関数部(ファイル I/O・process を持たない — test/reorder-d1-dump.test.ts
// から import して合成ダンプで固定する。CLI 入口は reorder-d1-dump.ts)。背景と前提はそちらの冒頭コメント。

export interface ReorderSummary {
  readonly statements: number;
  readonly tables: number;
  readonly inserts: number;
  readonly indexes: number;
  readonly dropped: number;
  /** INSERT が並ぶ表の順(親 → 子)。 */
  readonly insertOrder: readonly string[];
}

export class UnclassifiedStatementsError extends Error {
  constructor(readonly statements: readonly string[]) {
    super("unclassified statements (refusing to guess an order)");
  }
}

function splitStatements(text: string): string[] {
  const statements: string[] = [];
  let buffer = "";
  for (const line of text.split("\n")) {
    if (line.trim() === "" && buffer === "") {
      continue;
    }
    buffer += (buffer === "" ? "" : "\n") + line;
    if (line.trimEnd().endsWith(";")) {
      statements.push(buffer);
      buffer = "";
    }
  }
  if (buffer.trim() !== "") {
    statements.push(buffer);
  }
  return statements;
}

function tableNameOf(createStatement: string): string {
  const match = /^CREATE TABLE (?:IF NOT EXISTS )?[`"]?(\w+)[`"]?/i.exec(createStatement);
  if (match?.[1] === undefined) {
    throw new Error(`cannot read the table name: ${createStatement.slice(0, 60)}`);
  }
  return match[1];
}

function targetTableOf(statement: string): string {
  const match = /^(?:INSERT INTO|DELETE FROM)\s+[`"]?(\w+)[`"]?/i.exec(statement);
  return match?.[1] ?? "";
}

/**
 * 外部キー依存の解決(Kahn 法): CREATE TABLE の REFERENCES から親表の集合を作り、
 * 親がすべて配置済みの表を毎周まとめて置く。自己参照は無視、外部(CREATE の無い表 —
 * sqlite_sequence 等)への参照は満たされたものと見る。1 周で 1 つも置けなければ循環。
 */
function tableOrder(tables: readonly string[]): string[] {
  const parentsOf = new Map<string, ReadonlySet<string>>();
  for (const statement of tables) {
    const name = tableNameOf(statement);
    const parents = new Set<string>();
    for (const match of statement.matchAll(/REFERENCES\s+[`"]?(\w+)[`"]?/gi)) {
      if (match[1] !== undefined && match[1] !== name) {
        parents.add(match[1]);
      }
    }
    parentsOf.set(name, parents);
  }
  const order: string[] = [];
  let remaining = [...parentsOf.keys()];
  while (remaining.length > 0) {
    const placed = new Set(order);
    const ready = remaining.filter((name) =>
      [...(parentsOf.get(name) ?? [])].every(
        (parent) => placed.has(parent) || !parentsOf.has(parent),
      ),
    );
    if (ready.length === 0) {
      throw new Error(`foreign-key cycle among: ${remaining.join(", ")}`);
    }
    order.push(...ready);
    remaining = remaining.filter((name) => !ready.includes(name));
  }
  return order;
}

const matches = (pattern: RegExp) => (statement: string) => pattern.test(statement);

/** ダンプ全文を並べ替えて返す(純関数 — ファイル I/O は CLI 側)。 */
export function reorderD1Dump(text: string): {
  readonly sql: string;
  readonly summary: ReorderSummary;
} {
  const statements = splitStatements(text);
  const pragmas = statements.filter(matches(/^PRAGMA/i));
  const tables = statements.filter(matches(/^CREATE TABLE/i));
  // `DELETE FROM sqlite_sequence;` は sqlite_sequence の INSERT の直前に置かれる
  const inserts = statements.filter(matches(/^(?:INSERT|DELETE FROM sqlite_sequence)/i));
  const indexes = statements.filter(matches(/^CREATE (?:UNIQUE )?INDEX/i));
  const dropped = statements.filter(matches(/^(?:BEGIN|COMMIT)/i));
  const unknown = statements.filter(
    (statement) =>
      !/^(?:PRAGMA|CREATE TABLE|INSERT|DELETE FROM sqlite_sequence|CREATE (?:UNIQUE )?INDEX|BEGIN|COMMIT)/i.test(
        statement,
      ),
  );
  if (unknown.length > 0) {
    throw new UnclassifiedStatementsError(unknown);
  }
  const rank = new Map(tableOrder(tables).map((name, index) => [name, index]));
  // 安定ソート: 同じ表の INSERT は元の順序(seq 順)を保つ。CREATE の無い表(sqlite_sequence)は先頭
  const insertsOrdered = inserts
    .map((statement, index) => ({
      statement,
      index,
      rank: rank.get(targetTableOf(statement)) ?? -1,
    }))
    .toSorted((a, b) => a.rank - b.rank || a.index - b.index)
    .map((entry) => entry.statement);
  return {
    sql: `${[...pragmas, ...tables, ...insertsOrdered, ...indexes].join("\n")}\n`,
    summary: {
      statements: statements.length,
      tables: tables.length,
      inserts: inserts.length,
      indexes: indexes.length,
      dropped: dropped.length,
      insertOrder: [...new Set(insertsOrdered.map(targetTableOf))],
    },
  };
}
