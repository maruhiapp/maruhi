// 招待 API の HttpApi 定義(AUTH_SPEC §15 — 2026-09-13 IV 改訂)。
//
// - 発行 / 一覧 / 失効はプロジェクト配下(認可 = トークンスコープ admin ×
//   チェーン role admin 以上。非メンバーへは一律 404 — §11-2)
// - 発行はクライアントが招待 id を採番し、リンク公開鍵・検証済みヘッド・role に
//   対する**発行署名**(CRYPTO_SPEC §6.5)を発行文として渡す。サーバーは形式検査と
//   UNIQUE 違反(409)のみで発行署名を検証しない(検証者は招待者自身と受諾者)。
//   応答は期限だけで、**サーバーは招待の秘密を一切返さない**(旧 token は廃止)
// - 受諾はプロジェクト配下でない経路(§15-2): リンク鍵の保持(= リンク署名を
//   作れること)が対象招待への capability であり、リンクのフラグメントからは
//   公開鍵だけがサーバーへ渡る。未知の link_pub は 404(InviteNotFound —
//   プロジェクト座標を運ばない)、使用不能は 410(InviteGone)、署名は 422
// - 全エンドポイント認証必須(AuthMiddleware が 401 / CSRF 403 を担う。
//   一覧 GET は監査を書かない = 状態を持たないため §11-4 の追加 CSRF 対象外)

import { EnvironmentIdSchema, ProjectIdSchema } from "@maruhi/core";
import { Schema } from "effect";
import { HttpApiEndpoint, HttpApiGroup, HttpApiSchema } from "effect/unstable/httpapi";

import { AuthMiddleware } from "./auth-middleware.ts";
import { ScopeKindSchema } from "./chain.ts";
import {
  ForbiddenError,
  InviteConflictError,
  InviteGoneError,
  InviteNotFoundError,
  InvitePendingLimitError,
  InviteRateLimitedError,
  InviteSignatureInvalidError,
  ProjectNotFoundError,
} from "./errors/index.ts";
import {
  EncPubHex,
  InviteAcceptSignatureHex,
  InviteIssueSignatureHex,
  InviteLinkSignatureHex,
  PositiveInt,
  PublicKeyHex,
  Sha256Hex,
} from "./hex.ts";
import { strictPayload } from "./strict.ts";

/** 招待で付与できる role(owner は招待経由で付与しない — AUTH_SPEC §15-1)。 */
export const InviteRoleSchema = Schema.Literals(["reader", "member", "admin"]);

/** scope の環境リスト上限(CRYPTO_SPEC §6.1 / §6.2 — grant_server の scope と同じ 256)。 */
const MAX_INVITE_SCOPE_ENVIRONMENTS = 256;

/**
 * 招待の付与予定 scope(AUTH_SPEC §15-2 — 2026-09-14 ES)。形式検査のみ: kind の
 * 閉集合・`all` なら空配列・256 要素以下・重複なし・各 id は §12-1 形式。
 * **存在検査はしない**(合意規則は add_member 受理時に verifyChain が検査する)。
 * 発行 body・一覧行・受諾応答が同じ 2 フィールドを運ぶ。
 */
const inviteScopeFields = {
  scopeKind: ScopeKindSchema,
  scopeEnvironmentIds: Schema.Array(EnvironmentIdSchema),
};

/** scope の構造規則(§6.2 と同じ — all ⇒ 空・上限・重複なし)を Struct 全体へ掛ける。 */
function withInviteScopeShape<
  S extends Schema.Struct<typeof inviteScopeFields & Schema.Struct.Fields>,
>(schema: S): S {
  return schema.check(
    Schema.makeFilter((o: { scopeKind: string; scopeEnvironmentIds: readonly string[] }) => {
      if (o.scopeKind === "all" && o.scopeEnvironmentIds.length > 0) {
        return { path: ["scopeEnvironmentIds"], issue: "must be empty when scopeKind is all" };
      }
      if (o.scopeEnvironmentIds.length > MAX_INVITE_SCOPE_ENVIRONMENTS) {
        return { path: ["scopeEnvironmentIds"], issue: "at most 256 environments" };
      }
      if (new Set(o.scopeEnvironmentIds).size !== o.scopeEnvironmentIds.length) {
        return { path: ["scopeEnvironmentIds"], issue: "duplicate environment id" };
      }
      return undefined;
    }),
  ) as S;
}

/** 保存上の招待状態(期限切れは expiresAtMs からの導出 — §15-1)。 */
export const InviteStatusSchema = Schema.Literals(["pending", "accepted", "completed", "revoked"]);

/** 招待 id(クライアント採番の ULID — Crockford Base32 26 文字。発行署名が覆う)。 */
export const InviteIdSchema = Schema.String.check(
  Schema.isPattern(/^[0-9A-HJKMNP-TV-Z]{26}$/, { description: "invite id (ULID)" }),
);

/**
 * 発行文(CRYPTO_SPEC §6.5): リンク公開鍵・発行時点の招待者の検証済みヘッド・
 * 発行署名。サーバーは保存・配布するだけで検証しない。招待者クライアントは
 * `add_member` の前に自分の sig 公開鍵で再検証する(発行ピンに依存しない)。
 */
export const InviteIssuanceSchema = Schema.Struct({
  linkPubHex: PublicKeyHex,
  headHashHex: Sha256Hex,
  headSeq: PositiveInt,
  issueSignatureHex: InviteIssueSignatureHex,
});

/** 受諾ブロック(status が accepted 以降 — §15-1)。 */
export const InviteAcceptanceSchema = Schema.Struct({
  inviteeUserId: Schema.String,
  inviteeEncPubHex: EncPubHex,
  inviteeSigPubHex: PublicKeyHex,
  /** CRYPTO_SPEC §6.5 の受諾署名(受諾者のチェーン sig 鍵)。招待者クライアントが独立検証する */
  signatureHex: InviteAcceptSignatureHex,
  /** CRYPTO_SPEC §6.5 のリンク署名(リンク鍵)。同じバイト列への共同署名 */
  linkSignatureHex: InviteLinkSignatureHex,
  acceptedAtMs: Schema.Number,
});

/**
 * 一覧の 1 行。発行文と受諾ブロックは招待者クライアントの再検証(CRYPTO_SPEC
 * §6.5 — signed_bytes の再構成材料)と FP ワード表示に必要。
 */
export const InvitationSummarySchema = Schema.Struct({
  id: Schema.String,
  projectId: ProjectIdSchema,
  role: InviteRoleSchema,
  ...inviteScopeFields,
  status: InviteStatusSchema,
  inviterUserId: Schema.String,
  issuance: InviteIssuanceSchema,
  createdAtMs: Schema.Number,
  expiresAtMs: Schema.Number,
  acceptance: Schema.NullOr(InviteAcceptanceSchema),
});

/** 発行の要求(§15-2): クライアント採番の id + 発行文(role・scope を含む)。 */
export const InviteIssuePayloadSchema = withInviteScopeShape(
  Schema.Struct({
    id: InviteIdSchema,
    role: InviteRoleSchema,
    ...inviteScopeFields,
    linkPubHex: PublicKeyHex,
    headHashHex: Sha256Hex,
    headSeq: PositiveInt,
    issueSignatureHex: InviteIssueSignatureHex,
  }),
);

/** 発行応答。期限のみ(トークン相当の秘密は無い — §15-1)。 */
export const InviteIssueResultSchema = Schema.Struct({
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
  ...inviteScopeFields,
});

/**
 * Invitation endpoints (AUTH_SPEC §15-2)。
 *
 * - `issue`: create one invitation from a client-generated id and issuance
 *   statement; nothing secret is returned. role = admin の招待の発行は owner
 *   のみ(CRYPTO_SPEC §6.2 の add_member 権限表と同水準)。
 * - `accept`: single-use CAS(pending → accepted)。リンク署名と受諾署名
 *   (CRYPTO_SPEC §6.5)はサーバーが保存行 + 呼び出し主体から signed_bytes を
 *   再構成して検証する。鍵は形式検査のみ(メンバー鍵一意性の真実源は
 *   add_member のチェーン合意規則)。
 * - `list` / `revoke`: 管理面。revoke は pending | accepted に効く(completed /
 *   revoked へは 410)。
 */
export const invitesGroup = HttpApiGroup.make("invites")
  .add(
    HttpApiEndpoint.post("issue", "/projects/:projectId/invites", {
      params: { projectId: ProjectIdSchema },
      // strict 受理(§12-10 (1) — 招待の作成・受諾は §15-2 の鍵宣言クラス)
      payload: strictPayload(InviteIssuePayloadSchema),
      success: InviteIssueResultSchema,
      error: [
        ProjectNotFoundError,
        ForbiddenError,
        InviteConflictError,
        InvitePendingLimitError,
        InviteRateLimitedError,
      ],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("accept", "/invites/accept", {
      payload: strictPayload(
        Schema.Struct({
          linkPubHex: PublicKeyHex,
          encPubHex: EncPubHex,
          sigPubHex: PublicKeyHex,
          acceptSignatureHex: InviteAcceptSignatureHex,
          linkSignatureHex: InviteLinkSignatureHex,
        }),
      ),
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
