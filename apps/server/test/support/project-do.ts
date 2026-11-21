import { env, evictDurableObject, runInDurableObject } from "cloudflare:test";

import type { ProjectChainDO } from "../../src/do/chain-do.ts";

export async function resetProjectDo(projectId: string): Promise<void> {
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
  await runInDurableObject(stub, (_instance, state) => {
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

export async function evictProjectDo(projectId: string): Promise<void> {
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
  await evictDurableObject(stub);
}

export async function callProjectDo<T>(
  projectId: string,
  call: (instance: ProjectChainDO) => Promise<T>,
): Promise<T> {
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
  return await runInDurableObject(stub, (instance) => call(instance));
}

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

export function readAuditEvents(projectId: string): Promise<Record<string, unknown>[]> {
  return queryProjectDo(projectId, "SELECT * FROM audit_events ORDER BY seq");
}
