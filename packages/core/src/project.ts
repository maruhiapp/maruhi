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
