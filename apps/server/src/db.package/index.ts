// db.package の公開面(ImportLint 境界)。
//
// ここから再エクスポートするのはリポジトリサービスの Context タグ・消費側が
// 必要とするシェイプ型・構築関数のみ。Drizzle のテーブル定義(schema.ts)・
// クエリ型は境界外に出さない(ADR-0006)。

export { D1AuditRepo, principalAuditActor } from "./audit.ts";
export {
  type DbServices,
  IdentityRepo,
  isUniqueConflict,
  makeDbServices,
  OrgRepo,
  ProjectRepo,
  RECOVERY_FETCH_LIMIT,
  RecoveryRepo,
  SessionRepo,
  type SessionRepoShape,
  TokenRepo,
  type TokenRepoShape,
} from "./repos.ts";
