// ダッシュボードが消費するワイヤ型(裁定 BR — docs/notes/session-43.md)。
//
// api-schema からの **type-only import** に限定する: 型は単一定義(HttpApi の
// Schema)に束縛しつつ、Effect / Schema の実行コードをバンドル(= TCB)へ
// 一切持ち込まない(verbatimModuleSyntax がビルド時消去を保証する)。
// ランタイムの Schema 検証は意図的に行わない — 全表示はサーバー申告
// (as reported by the server)であり、Web は検証を実装しない(ADR-0018 改訂 2・
// 4 項)。形の崩れへの防御は表示層の optional アクセスで足りる。
import type {
  AuditEventSchema,
  ChainEntrySchema,
  ChainSnapshotSchema,
  EnvironmentMetadataPullSchema,
  EnvironmentSummarySchema,
  ForbiddenReasonSchema,
  MeSchema,
  ProjectListSchema,
  RoleSchema,
  RotationFlagSchema,
} from "@maruhi/api-schema";

export type Me = typeof MeSchema.Type;
export type ProjectList = typeof ProjectListSchema.Type;
export type ChainSnapshot = typeof ChainSnapshotSchema.Type;
export type ChainEntry = typeof ChainEntrySchema.Type;
export type ChainRole = typeof RoleSchema.Type;
export type EnvironmentSummary = typeof EnvironmentSummarySchema.Type;
export type EnvironmentMetadataPull = typeof EnvironmentMetadataPullSchema.Type;
export type AuditEvent = typeof AuditEventSchema.Type;
export type RotationFlag = typeof RotationFlagSchema.Type;
/** 403 reason の閉じた列挙(裁定 CC — 比較リテラルのリネームを型で割る)。 */
export type ForbiddenReason = typeof ForbiddenReasonSchema.Type;

/** `{ events }` page shape shared by every audit read endpoint (AUDIT_SPEC §7). */
export interface AuditEventsPage {
  readonly events: ReadonlyArray<AuditEvent>;
}

/** `{ environments }` shape of the environment listing (AUTH_SPEC §12-4). */
export interface EnvironmentList {
  readonly environments: ReadonlyArray<EnvironmentSummary>;
}

/** `{ flags }` shape of the rotation-flag view (AUDIT_SPEC §7). */
export interface RotationFlagList {
  readonly flags: ReadonlyArray<RotationFlag>;
}
