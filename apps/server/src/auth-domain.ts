// 認証まわりのサーバー内ドメイン型(AUTH_SPEC §2〜§6)。
//
// db.package(リポジトリ)と auth.package(サービス実装)が共有する。
// Drizzle の型はここに現れない(ADR-0006: サービス境界内に隔離)。

import type { OrgRole, TokenScope } from "@maruhi/core";

/**
 * プロバイダ検証済みアイデンティティ(AUTH_SPEC §3 / §4 の認証ダンスの出力)。
 * email は プロバイダ側で verified なもののみ(§3。未検証メールは保存しない)。
 */
export interface VerifiedIdentity {
  readonly provider: "github";
  readonly providerUserId: string;
  readonly providerLogin: string | null;
  readonly verifiedEmail: string | null;
}

/** getOrCreateUser の結果(AUTH_SPEC §1-5: 単一の冪等な入口)。 */
export interface ResolvedUser {
  readonly userId: string;
  readonly created: boolean;
}

/** 認証済みユーザーが属する org(AUTH_SPEC §9-1)。 */
export interface UserOrg {
  readonly orgId: string;
  readonly slug: string;
  readonly name: string;
  readonly role: OrgRole;
}

/** セッション行のドメイン表現(生値は存在しない。id はハッシュ)。 */
export interface SessionRecord {
  readonly userId: string;
  readonly authMethod: string;
  readonly expiresAtMs: number;
}

/** API トークン行のドメイン表現(生値は存在しない)。 */
export interface ApiTokenRecord {
  readonly id: string;
  readonly userId: string;
  readonly tokenHash: string;
  readonly scopes: readonly TokenScope[];
  readonly expiresAtMs: number | null;
  readonly lastUsedAtMs: number | null;
}
