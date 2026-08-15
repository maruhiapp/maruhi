// メンバーシップログの HttpApi 定義(CRYPTO_SPEC §6.4)。
// サーバー実装(apps/server)と将来の CLI クライアント導出の共有源。
//
// API 境界の不変条件(§10): このファイルのどの型も平文シークレット・DEK・
// master 秘密鍵を表現しない。チェーンエントリは署名付き公開データである。

import { ProjectIdSchema } from "@maruhi/core";
import { Schema } from "effect";
import { HttpApi, HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi";

import { authGroup } from "./auth-api.ts";
import { AuthMiddleware } from "./auth-middleware.ts";
import { ChainEntrySchema } from "./chain.ts";
import { deksGroup, environmentsGroup, variablesGroup } from "./data-api.ts";
import {
  ChainCapacityExceededError,
  ChainEntryInvalidError,
  ChainEntryTooLargeError,
  ChainHeadConflictError,
  CompositeRequiredError,
  ForbiddenError,
  ProjectAlreadyInitializedError,
  ProjectNotFoundError,
} from "./errors/index.ts";
import { PositiveInt, Sha256Hex } from "./hex.ts";
import { invitesGroup } from "./invites-api.ts";
import { leaseGroup } from "./lease-api.ts";

/** Chain head after a successful initialization or append. */
export const ChainHeadSchema = Schema.Struct({
  projectId: ProjectIdSchema,
  headSeq: PositiveInt,
  headHashHex: Sha256Hex,
});

/** Full chain as stored by the project DO (entries in seq order). */
export const ChainSnapshotSchema = Schema.Struct({
  projectId: ProjectIdSchema,
  entries: Schema.Array(ChainEntrySchema),
  headSeq: PositiveInt,
  headHashHex: Sha256Hex,
});

/**
 * Membership-log endpoints (CRYPTO_SPEC §6.4)。全エンドポイント認証必須
 * (AUTH_SPEC §11-1。AuthMiddleware が 401 / CSRF 403 を担う)。
 *
 * - `init`: submit a genesis entry; the server verifies it and derives the
 *   project id as the genesis entry hash. `orgId` は帰属先 org(§11-3。作成
 *   権限 = org member 以上)。非メンバー・スコープ外への応答は一律 404(§11-2)。
 * - `get`: fetch the stored chain for client-side verification (§6.3).
 * - `append`: append one entry; `parentHeadHashHex` is the compare-and-swap
 *   parent (§6.4)。§6.3 の「署名付き申告ヘッド」(ヘッドゴシップ)とは別物。
 *   認証主体と entry.actor の厳密一致を要求する(§11-1)。
 *   `create_environment` / `rotate_epoch` は複合エンドポイント
 *   (environments group の create / rotate — AUTH_SPEC §12-4)経由のみ受理し、
 *   ここでは CompositeRequired で拒否する(AUTH_SPEC §6。2026-08-03)。
 */
export const membershipGroup = HttpApiGroup.make("membership")
  .add(
    HttpApiEndpoint.post("init", "/projects", {
      payload: Schema.Struct({ orgId: Schema.String, entry: ChainEntrySchema }),
      success: ChainHeadSchema,
      error: [
        ProjectAlreadyInitializedError,
        ChainEntryInvalidError,
        ChainEntryTooLargeError,
        ForbiddenError,
      ],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("get", "/projects/:projectId/chain", {
      params: { projectId: ProjectIdSchema },
      success: ChainSnapshotSchema,
      error: [ProjectNotFoundError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("append", "/projects/:projectId/chain/entries", {
      params: { projectId: ProjectIdSchema },
      payload: Schema.Struct({
        // CAS の親ヘッド。不正形式は schema 境界の 400 で落とす(意図的な受理変更)
        parentHeadHashHex: Sha256Hex,
        entry: ChainEntrySchema,
      }),
      success: ChainHeadSchema,
      error: [
        ProjectNotFoundError,
        ChainHeadConflictError,
        ChainEntryInvalidError,
        ChainEntryTooLargeError,
        ChainCapacityExceededError,
        CompositeRequiredError,
        ForbiddenError,
      ],
    }).middleware(AuthMiddleware),
  );

/** The maruhi HTTP API. */
export const maruhiApi = HttpApi.make("maruhi")
  .add(membershipGroup)
  .add(authGroup)
  .add(environmentsGroup)
  .add(variablesGroup)
  .add(deksGroup)
  .add(invitesGroup)
  // 唯一の未認証グループ(資格情報 = OIDC トークン自体 — AUTH_SPEC §14-1)
  .add(leaseGroup);
