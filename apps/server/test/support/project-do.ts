// プロジェクト DO のテスト間リセット(workerd 内で実行)。
//
// この vitest-pool-workers 構成(cloudflareTest プラグイン 0.21.0)にはテスト間の
// ストレージ分離がなく、DO SQLite はファイル内のテスト間で持ち越される。
// runInDurableObject で DO をインスタンス化するとコンストラクタが DDL を適用する
// ため、ここでは PROJECT_DO_TABLES の全テーブルを名指しで DELETE し、その後
// evictDurableObject で導出 ChainState のメモリキャッシュも消す。
// **テーブルを増やしたら src/do-schema.ts の PROJECT_DO_TABLES に必ず追加する**
// (この一覧が唯一のリセット対象定義)。

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
