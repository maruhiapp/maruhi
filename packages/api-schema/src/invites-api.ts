// 招待 API の HttpApi 定義(AUTH_SPEC §15)。
//
// - 発行 / 一覧 / 失効はプロジェクト配下(認可 = トークンスコープ admin ×
//   チェーン role admin 以上。非メンバーへは一律 404 — §11-2)
// - 受諾はプロジェクト配下でない経路(§15-2): トークン保持が対象招待への
//   capability であり、リンクのフラグメントからトークンだけがサーバーへ渡る。
//   未知トークンは 404(InviteNotFound — プロジェクト座標を運ばない)、
//   使用不能は 410(InviteGone)
// - 全エンドポイント認証必須(AuthMiddleware が 401 / CSRF 403 を担う。
//   一覧 GET は監査を書かない = 状態を持たないため §11-4 の追加 CSRF 対象外)
// - トークン生値がワイヤに現れるのは発行応答の `token` と受諾要求の `token`
//   のみ(DB にはハッシュのみ — §15-1)

import { ProjectIdSchema } from "@maruhi/core";
import { Schema } from "effect";
import { HttpApiEndpoint, HttpApiGroup, HttpApiSchema } from "effect/unstable/httpapi";

import { AuthMiddleware } from "./auth-middleware.ts";
import {
  ForbiddenError,
  InviteGoneError,
  InviteNotFoundError,
  InvitePendingLimitError,
  InviteRateLimitedError,
  InviteSignatureInvalidError,
  ProjectNotFoundError,
} from "./errors/index.ts";
import { EncPubHex, InviteAcceptSignatureHex, PublicKeyHex, Sha256Hex } from "./hex.ts";

/** 招待で付与できる role(owner は招待経由で付与しない — AUTH_SPEC §15-1)。 */
export const InviteRoleSchema = Schema.Literals(["reader", "member", "admin"]);

/** 保存上の招待状態(期限切れは expiresAtMs からの導出 — §15-1)。 */
export const InviteStatusSchema = Schema.Literals(["pending", "accepted", "completed", "revoked"]);

/**
 * 招待トークンのワイヤ形式: `maruhi_inv_` + Base62 乱数(256-bit 相当、43 文字)。
 * PAT(§6 の `maruhi_pat_`)と同じ規律 — プレフィックスで secret scanning・
 * 種別判別に対応し、ハッシュは提示文字列全体の SHA-256。形式不正は Schema 境界の
 * 400 で落とす(トークン形式は公開情報であり存在秘匿に関与しない)。
 */
export const InviteTokenSchema = Schema.String.check(
  Schema.isPattern(/^maruhi_inv_[0-9A-Za-z]{43}$/, {
    description: "invite token (maruhi_inv_ + 43 Base62 chars)",
  }),
);

/** 受諾ブロック(status が accepted 以降 — §15-1)。 */
export const InviteAcceptanceSchema = Schema.Struct({
  inviteeUserId: Schema.String,
  inviteeEncPubHex: EncPubHex,
  inviteeSigPubHex: PublicKeyHex,
  /** CRYPTO_SPEC §6.5 の受諾署名。招待者クライアントが独立検証する */
  signatureHex: InviteAcceptSignatureHex,
  acceptedAtMs: Schema.Number,
});

/**
 * 一覧の 1 行。`tokenHashHex` と受諾ブロックは招待者クライアントの受諾署名
 * 再検証(CRYPTO_SPEC §6.5 — signed_bytes の再構成材料)と FP ワード表示に
 * 必要。トークン生値は含まれない(ハッシュから生値は導けない)。
 */
export const InvitationSummarySchema = Schema.Struct({
  id: Schema.String,
  projectId: ProjectIdSchema,
  role: InviteRoleSchema,
  status: InviteStatusSchema,
  inviterUserId: Schema.String,
  tokenHashHex: Sha256Hex,
  createdAtMs: Schema.Number,
  expiresAtMs: Schema.Number,
  acceptance: Schema.NullOr(InviteAcceptanceSchema),
});

/** 発行応答。`token` はここで一度だけ返る(以後はハッシュのみ — §15-1)。 */
export const InviteIssueResultSchema = Schema.Struct({
  id: Schema.String,
  token: InviteTokenSchema,
  role: InviteRoleSchema,
  expiresAtMs: Schema.Number,
});

/**
 * 受諾応答。最小形(§15-1: サーバー申告の表示情報を信頼させる面を作らない —
 * 招待者情報・アンカーはリンクのフラグメントが運ぶ)。
 */
export const InviteAcceptResultSchema = Schema.Struct({
  id: Schema.String,
  projectId: ProjectIdSchema,
  role: InviteRoleSchema,
});

/**
 * Invitation endpoints (AUTH_SPEC §15-2)。
 *
 * - `issue`: create one invitation; the raw token is returned exactly once.
 *   role = admin の招待の発行は owner のみ(CRYPTO_SPEC §6.2 の add_member
 *   権限表と同水準)。
 * - `accept`: single-use CAS(pending → accepted)。受諾署名(CRYPTO_SPEC §6.5)
 *   はサーバーが保存行 + 呼び出し主体から signed_bytes を再構成して検証する。
 *   鍵は形式検査のみ(メンバー鍵一意性の真実源は add_member のチェーン合意規則)。
 * - `list` / `revoke`: 管理面。revoke は pending | accepted に効く(completed /
 *   revoked へは 410)。
 */
export const invitesGroup = HttpApiGroup.make("invites")
  .add(
    HttpApiEndpoint.post("issue", "/projects/:projectId/invites", {
      params: { projectId: ProjectIdSchema },
      payload: Schema.Struct({ role: InviteRoleSchema }),
      success: InviteIssueResultSchema,
      error: [
        ProjectNotFoundError,
        ForbiddenError,
        InvitePendingLimitError,
        InviteRateLimitedError,
      ],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("accept", "/invites/accept", {
      payload: Schema.Struct({
        token: InviteTokenSchema,
        encPubHex: EncPubHex,
        sigPubHex: PublicKeyHex,
        signatureHex: InviteAcceptSignatureHex,
      }),
      success: InviteAcceptResultSchema,
      error: [InviteNotFoundError, InviteGoneError, InviteSignatureInvalidError, ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("list", "/projects/:projectId/invites", {
      params: { projectId: ProjectIdSchema },
      success: Schema.Struct({ invitations: Schema.Array(InvitationSummarySchema) }),
      error: [ProjectNotFoundError, ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.delete("revoke", "/projects/:projectId/invites/:id", {
      params: { projectId: ProjectIdSchema, id: Schema.String },
      success: HttpApiSchema.NoContent,
      error: [ProjectNotFoundError, ForbiddenError, InviteNotFoundError, InviteGoneError],
    }).middleware(AuthMiddleware),
  );
