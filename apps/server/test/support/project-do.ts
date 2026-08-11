// プロジェクト DO のテスト間リセット(workerd 内で実行)。
//
// この vitest-pool-workers 構成(cloudflareTest プラグイン 0.21.0)にはテスト間の
// ストレージ分離がなく、DO SQLite はファイル内のテスト間で持ち越される。
// runInDurableObject で DO をインスタンス化するとコンストラクタがマイグレーションを
// 適用するため、ここでは PROJECT_DO_TABLES の全テーブルを名指しで DELETE し、その後
// evictDurableObject で導出 ChainState のメモリキャッシュも消す。
// PROJECT_DO_TABLES は src/do-schema.ts のマイグレーションステップの tables 宣言から
// 導出される(テーブルを増やすステップは必ず tables に宣言する)。schema_meta は
// 適用済み version の記録のため意図的に DELETE しない。

import { env, evictDurableObject, runInDurableObject } from "cloudflare:test";

import { PROJECT_DO_TABLES } from "../../src/do-schema.ts";

/** 指定プロジェクトの DO ストレージを空へ戻し、インスタンスを退去させる。 */
export async function resetProjectDo(projectId: string): Promise<void> {
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
  await runInDurableObject(stub, (_instance, state) => {
    for (const table of PROJECT_DO_TABLES) {
      state.storage.sql.exec(`DELETE FROM ${table}`);
    }
  });
  await evictDurableObject(stub);
}

/** DO SQLite への直接クエリ(保存状態・監査ログの検証用)。 */
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

/** 監査イベントの全行(seq 順)。 */
export function readAuditEvents(projectId: string): Promise<Record<string, unknown>[]> {
  return queryProjectDo(projectId, "SELECT * FROM audit_events ORDER BY seq");
}
