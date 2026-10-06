// Resets the project DO between tests (runs inside workerd).
//
// The storage isolation unit of this @cloudflare/vitest-plugin
// configuration is the worker (isolate: false —
// apps/server/vitest.config.ts), so DO SQLite carries over not only between
// tests in a file but also from other files handled by the same worker.
// Instantiating the DO via runInDurableObject makes the constructor apply
// migrations, so here every table in PROJECT_DO_TABLES is DELETE'd by name,
// and then evictDurableObject drops the in-memory cache of derived
// ChainState too.
// PROJECT_DO_TABLES is derived from the tables declarations of the
// migration plan in src/do/do-schema.ts (the base step and every later step;
// a step that adds a table must always declare it in tables). schema_meta is
// intentionally not DELETE'd because it records the applied version.

import { env, evictDurableObject, runInDurableObject } from "cloudflare:test";

import { PROJECT_DO_LOCAL_TABLES, PROJECT_DO_TABLES } from "../../src/do/do-schema.ts";

/** Returns the given project's DO storage to empty and evicts the
 * instance. */
export async function resetProjectDo(projectId: string): Promise<void> {
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
  await runInDurableObject(stub, (_instance, state) => {
    for (const table of [...PROJECT_DO_TABLES, ...PROJECT_DO_LOCAL_TABLES]) {
      state.storage.sql.exec(`DELETE FROM ${table}`);
    }
    // A mirror replication left mid-way keeps staging tables (PF2 —
    // `<table>_mirror`, `trailer_mirror`, `audit_events_mirror_local`); drop them
    const staging = state.storage.sql
      .exec(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE '%\\_mirror%' ESCAPE '\\'",
      )
      .toArray()
      .map((row) => String(row["name"]));
    for (const table of staging) {
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
