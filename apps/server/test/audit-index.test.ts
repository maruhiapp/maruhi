// audit_events の対象・鍵 FP 索引の部分索引化(src/do-schema.ts 末尾ステップ —
// 2026-09-02 監査ログの成長密度対策 ①)のテスト。
//
// workerd 実環境の SqlStorage で 3 点を固定する:
// (a) マイグレーション適用後のスキーマが `WHERE <列> IS NOT NULL` の部分索引を持つ
// (b) 既存の読み手(要ローテーション検出の Q1 / Q6 と §7 の target_user_id
//     フィルタ)が EXPLAIN QUERY PLAN で新索引を選択する — SQLite は WHERE 句が
//     索引述語を含意するときだけ部分索引を使うため、「等値条件は IS NOT NULL を
//     含意する」を実証で固定する(含意されなくなる書き換えは fail-open ではなく
//     フルスキャンだが、監査表は最大 10 GB — 性能退行として検出したい)
// (c) 効果の実測: 10,000 行の var.read(対象・鍵 FP が全て NULL)で、素の索引と
//     部分索引の databaseSize 差を測る(PR 本文の数値の出所)
//
// このファイルは専用の DO 名を使い、他のテストのプロジェクト DO と storage を
// 共有しない。audit-store のクエリ文は SqlStorage を薄く包んで捕捉し、同じ文を
// EXPLAIN に流す(文の複製による検証器ドリフトを避ける)。

import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import type { AuditEventInput } from "../src/audit-store.ts";
import { makeAuditStore } from "../src/audit-store.ts";

/** このファイル専用 DO の storage 上で body を実行する。 */
async function withSql<T>(body: (sql: SqlStorage) => T): Promise<T> {
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName("audit-partial-index-test"));
  return await runInDurableObject(stub, (_instance, state) => body(state.storage.sql));
}

const PARTIAL_INDEXES = {
  ae_target: "target_user_id",
  ae_target_fp: "target_key_fingerprint",
  ae_actor_fp: "actor_key_fingerprint",
} as const;

/** sqlite_master の索引定義(名前 → CREATE 文)。 */
function indexDefinitions(sql: SqlStorage): ReadonlyMap<string, string> {
  return new Map(
    sql
      .exec(
        `SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'audit_events'`,
      )
      .toArray()
      .map((row) => [String(row["name"]), String(row["sql"])]),
  );
}

interface CapturedQuery {
  readonly query: string;
  readonly bindings: readonly unknown[];
}

/**
 * 実行された SQL を捕捉する SqlStorage の包み。exec 以外は実体へ委譲する
 * (databaseSize 等の native getter は receiver を実体にして呼ぶ)。
 */
function capturing(sql: SqlStorage): {
  readonly sql: SqlStorage;
  readonly captured: CapturedQuery[];
} {
  const captured: CapturedQuery[] = [];
  const proxy = new Proxy(sql, {
    get(target, property) {
      if (property === "exec") {
        return (query: string, ...bindings: unknown[]) => {
          captured.push({ query, bindings });
          return target.exec(query, ...(bindings as (string | number | null)[]));
        };
      }
      return Reflect.get(target, property, target);
    },
  });
  return { sql: proxy, captured };
}

/** EXPLAIN QUERY PLAN の detail 列を 1 文字列に畳む。 */
function planOf(sql: SqlStorage, captured: CapturedQuery): string {
  return sql
    .exec(`EXPLAIN QUERY PLAN ${captured.query}`, ...(captured.bindings as (string | number)[]))
    .toArray()
    .map((row) => String(row["detail"]))
    .join("\n");
}

/** var.read 1 行(対象・鍵 FP が全て NULL — 支配的な行種の形)。 */
function readEvent(index: number): AuditEventInput {
  return {
    serverTs: 1_700_000_000_000 + index,
    event: "var.read",
    actorType: "user",
    actorUserId: "user-reader-0001",
    environmentId: "env-density-0001",
    variableId: `var-density-${String(index % 100).padStart(4, "0")}`,
    epoch: 1,
    version: 1,
  };
}

describe("audit_events の部分索引(do-schema.ts — 成長密度対策 ①)", () => {
  it("マイグレーション適用後の ae_target / ae_target_fp / ae_actor_fp は IS NOT NULL の部分索引", async () => {
    await withSql((sql) => {
      const definitions = indexDefinitions(sql);
      for (const [name, column] of Object.entries(PARTIAL_INDEXES)) {
        const definition = definitions.get(name);
        expect(definition, name).toBeDefined();
        expect(definition, name).toContain(`(${column}, seq)`);
        expect(definition, name).toContain(`WHERE ${column} IS NOT NULL`);
      }
      // var.read が引く索引は素のまま(述語なし)
      for (const name of ["ae_var", "ae_actor", "ae_event"]) {
        expect(definitions.get(name), name).not.toContain("WHERE");
      }
    });
  });

  it("既存の読み手は等値条件で新しい部分索引を選択する(EXPLAIN QUERY PLAN)", async () => {
    await withSql((sql) => {
      const { sql: wrapped, captured } = capturing(sql);
      const store = makeAuditStore(wrapped);
      const expectations: {
        readonly label: string;
        readonly index: string;
        readonly run: () => void;
      }[] = [
        {
          label: "Q1 membershipEventsFor (target_user_id = ?)",
          index: "ae_target",
          run: () => void store.readRotationSync.membershipEventsFor("user-x"),
        },
        {
          label: "Q6 serverGrantEventsFor (target_key_fingerprint = ?)",
          index: "ae_target_fp",
          run: () => void store.readRotationSync.serverGrantEventsFor("ab".repeat(16)),
        },
        {
          label: "Q6 serverAccessEventsBy (actor_key_fingerprint = ?)",
          index: "ae_actor_fp",
          run: () => void store.readRotationSync.serverAccessEventsBy("ab".repeat(16)),
        },
        {
          label: "§7 targetUserId filter (admin visibility)",
          index: "ae_target",
          run: () =>
            void store.queryEventsSync({
              beforeRowId: null,
              limit: 50,
              event: null,
              eventPrefix: null,
              chainSeqPresent: false,
              actorUserId: null,
              targetUserId: "user-x",
              variableId: null,
              environmentId: null,
              visibility: { kind: "admin" },
            }),
        },
        {
          label: "§7 targetUserId filter (class1-or-self visibility)",
          index: "ae_target",
          run: () =>
            void store.queryEventsSync({
              beforeRowId: null,
              limit: 50,
              event: null,
              eventPrefix: null,
              chainSeqPresent: false,
              actorUserId: null,
              targetUserId: "user-x",
              variableId: null,
              environmentId: null,
              visibility: { kind: "class1-or-self", selfUserId: "user-self" },
            }),
        },
      ];
      for (const expectation of expectations) {
        captured.length = 0;
        expectation.run();
        const query = captured.at(-1);
        expect(query, expectation.label).toBeDefined();
        if (query === undefined) throw new Error("no query captured");
        expect(planOf(sql, query), expectation.label).toContain(`USING INDEX ${expectation.index}`);
      }
    });
  });

  it("10,000 行の var.read で、部分索引は素の索引より小さい(databaseSize の実測)", async () => {
    const ROWS = 10_000;
    const measured = await withSql((sql) => {
      sql.exec("DELETE FROM audit_events");
      const store = makeAuditStore(sql);
      store.appendManySync(Array.from({ length: ROWS }, (_row, index) => readEvent(index)));
      const partial = sql.databaseSize;
      // 旧形(素の索引)へ戻して再構築 — NULL 行にも索引エントリが積まれる
      for (const [name, column] of Object.entries(PARTIAL_INDEXES)) {
        sql.exec(`DROP INDEX ${name}`);
        sql.exec(`CREATE INDEX ${name} ON audit_events (${column}, seq)`);
      }
      const full = sql.databaseSize;
      // 実スキーマ(部分索引)へ戻す = マイグレーションステップと同じ DROP → CREATE。
      // 所要時間は行数比例(既存 DO への適用時間の見積もりの出所)
      const startedAt = Date.now();
      for (const [name, column] of Object.entries(PARTIAL_INDEXES)) {
        sql.exec(`DROP INDEX ${name}`);
        sql.exec(
          `CREATE INDEX ${name} ON audit_events (${column}, seq) WHERE ${column} IS NOT NULL`,
        );
      }
      const rebuildMs = Date.now() - startedAt;
      // 既存 DO が実際に通る向き(素の索引 → 部分索引)の後の実測。解放された
      // ページが databaseSize(#134 のガードが読む指標)に戻るかを固定する
      const rebuilt = sql.databaseSize;
      sql.exec("DELETE FROM audit_events");
      return { partial, full, rebuildMs, rebuilt };
    });
    // 部分索引は NULL 行を持たないので、3 索引 × 10,000 エントリ分だけ小さい
    expect(measured.full).toBeGreaterThan(measured.partial);
    const perRow = (measured.full - measured.partial) / ROWS;
    console.log(
      `audit_events partial index: ${ROWS} var.read rows — full ${measured.full} B / partial ${measured.partial} B / delta ${measured.full - measured.partial} B (${perRow.toFixed(1)} B per row, ${(measured.partial / ROWS).toFixed(1)} B per row remaining); partial-index rebuild of ${ROWS} rows took ${measured.rebuildMs} ms and left databaseSize at ${measured.rebuilt} B`,
    );
    // migrate-in-place の向き(素の索引を DROP → 部分索引で再構築)でも使用量は
    // 戻る: 解放ページが freelist に残るなら full のまま、戻るなら partial と同等
    expect(measured.rebuilt).toBeLessThan(measured.full);
    expect(measured.rebuilt).toBeLessThanOrEqual(measured.partial);
    // 3 索引 × (NULL キー + seq)のエントリは 1 行あたり数十バイト以上
    expect(perRow).toBeGreaterThan(10);
  });
});
