// プロジェクト識別子のドメイン型。
//
// CRYPTO_SPEC §6.4(2026-08-02 追加): プロジェクト ID = genesis エントリの
// エントリハッシュ(hex 小文字 64 文字)。チェーンと ID を暗号学的に束縛する。

import { Schema } from "effect";

const PROJECT_ID_PATTERN = /^[0-9a-f]{64}$/;

/** Schema for a project id: the lowercase-hex SHA-256 hash of the genesis entry. */
export const ProjectIdSchema = Schema.String.check(
  Schema.isPattern(PROJECT_ID_PATTERN, {
    description: "project id (lowercase hex SHA-256 of the genesis entry)",
  }),
);

/** Project id: lowercase-hex SHA-256 (64 chars) of the project's genesis entry. */
export type ProjectId = typeof ProjectIdSchema.Type;

/** Runtime guard matching {@link ProjectIdSchema}. */
export function isProjectId(value: string): value is ProjectId {
  return PROJECT_ID_PATTERN.test(value);
}

// ---------------------------------------------------------------------------
// データプレーンの安定識別子(AUTH_SPEC §12-1)
//
// environment_id / variable_id はクライアント採番(AAD / HPKE info に入る値を
// 暗号化・ラップの前に確定するため — CRYPTO_SPEC §3〜§5)。形式は API 受理
// ポリシーであり、チェーン有効性の合意規則(CRYPTO_SPEC §6.1)ではない。
// ---------------------------------------------------------------------------

const RESOURCE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

/** Schema for a client-issued environment id (AUTH_SPEC §12-1). */
export const EnvironmentIdSchema = Schema.String.check(
  Schema.isPattern(RESOURCE_ID_PATTERN, {
    description: "environment id (1-64 chars of [A-Za-z0-9_-], starting alphanumeric)",
  }),
);

/** Environment id: a stable client-issued identifier (rename-safe, used in AADs). */
export type EnvironmentId = typeof EnvironmentIdSchema.Type;

/** Schema for a client-issued variable id (AUTH_SPEC §12-1). */
export const VariableIdSchema = Schema.String.check(
  Schema.isPattern(RESOURCE_ID_PATTERN, {
    description: "variable id (1-64 chars of [A-Za-z0-9_-], starting alphanumeric)",
  }),
);

/** Variable id: a stable client-issued identifier (rename-safe, used in AADs). */
export type VariableId = typeof VariableIdSchema.Type;

/** Runtime guard matching {@link EnvironmentIdSchema}. */
export function isEnvironmentId(value: string): value is EnvironmentId {
  return RESOURCE_ID_PATTERN.test(value);
}

/** Runtime guard matching {@link VariableIdSchema}. */
export function isVariableId(value: string): value is VariableId {
  return RESOURCE_ID_PATTERN.test(value);
}
