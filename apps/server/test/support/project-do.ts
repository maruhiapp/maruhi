// Resets the project DO between tests (runs inside workerd).
//
// The storage isolation unit of this @cloudflare/vitest-plugin
// configuration is the worker (isolate: false —
// apps/server/vitest.config.ts), so DO SQLite carries over not only between
// tests in a file but also from other files handled by the same worker.
// A DO materializes its tables only at genesis acceptance now (Sc-7 / A-4),
// so "empty" means "never initialized": every user table is DROPped (the
// snapshot tables, the deployment-local tables, any mirror staging, and
// `schema_meta`), returning the DO to the pristine no-storage state a fresh
// DO has. A subsequent init re-materializes from the base migration, and a
// test that seeds storage directly materializes with ensureProjectDoTables.
// A reset of an already-fresh DO is a no-op (nothing to drop).

import { env, evictDurableObject, runInDurableObject } from "cloudflare:test";

import type { ProjectChainDO } from "../../src/do/chain-do.ts";

/** Returns the given project's DO to the pristine never-initialized state and evicts the instance. */
export async function resetProjectDo(projectId: string): Promise<void> {
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
  await runInDurableObject(stub, (_instance, state) => {
    // Every user table: the base / step tables, the deployment-local tables,
    // any mirror staging left mid-replication, and schema_meta. The `_cf_*` /
    // `sqlite_*` internals are left alone.
    const tables = state.storage.sql
      .exec(
        `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '\\_cf\\_%' ESCAPE '\\' AND name NOT LIKE 'sqlite_%'`,
      )
      .toArray()
      .map((row) => String(row["name"]));
    for (const table of tables) {
      state.storage.sql.exec(`DROP TABLE IF EXISTS ${table}`);
    }
  });
  await evictDurableObject(stub);
}

/**
 * Evicts the instance and drops the in-memory cache of derived ChainState
 * (for returning to a full load after directly mutating stored rows — the
 * mutation does not show through the cache).
 */
export async function evictProjectDo(projectId: string): Promise<void> {
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
  await evictDurableObject(stub);
}

/**
 * Calls an RPC method on the project DO instance itself, bypassing the RPC
 * transport: a defect then rejects with its own error (message, tag and
 * fields intact), so a test can pin which defect fired, where the HTTP
 * answer is the same 500 for any of them. workerd prints no "uncaught
 * exception" line for this direct call (it does for the RPC path).
 */
export async function callProjectDo<T>(
  projectId: string,
  call: (instance: ProjectChainDO) => Promise<T>,
): Promise<T> {
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
  return await runInDurableObject(stub, (instance) => call(instance));
}

/** Direct queries against DO SQLite (for checking stored state and the
 * audit log). */
export async function queryProjectDo(
  projectId: string,
  query: string,
  ...bindings: (string | number)[]
): Promise<Record<string, unknown>[]> {
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
  return await runInDurableObject(stub, (_instance, state) =>
    state.storage.sql.exec(query, ...bindings).toArray(),
  );
}

/** All audit event rows (seq order). */
export function readAuditEvents(projectId: string): Promise<Record<string, unknown>[]> {
  return queryProjectDo(projectId, "SELECT * FROM audit_events ORDER BY seq");
}
