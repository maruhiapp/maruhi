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
// migration steps in src/do-schema.ts (a step that adds a table must always
// declare it in tables). schema_meta is intentionally not DELETE'd because
// it records the applied version.

import { env, evictDurableObject, runInDurableObject } from "cloudflare:test";

import { PROJECT_DO_TABLES } from "../../src/do-schema.ts";

/** Returns the given project's DO storage to empty and evicts the
 * instance. */
export async function resetProjectDo(projectId: string): Promise<void> {
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
  await runInDurableObject(stub, (_instance, state) => {
    for (const table of PROJECT_DO_TABLES) {
      state.storage.sql.exec(`DELETE FROM ${table}`);
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
