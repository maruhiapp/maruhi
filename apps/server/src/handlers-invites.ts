// 招待 API のハンドラ(AUTH_SPEC §15 — 2026-09-13 IV 改訂)。
//
// 認可の流れ:
//   - 発行 / 一覧 / 失効(プロジェクト配下): トークンスコープ admin(スコープ外
//     404 — §11-2)→ DO memberRoleFor(非メンバー 404 / チェーン role の取得)→
//     admin 水準判定(未満 403)。role=admin の招待の発行は owner のみ(§15-2)
//   - 受諾: 認証済み主体 + 鍵素材条件(§13-2 と同水準 — B1a 裁定)。リンク鍵の
//     保持(= リンク署名を作れること)が対象招待への capability(§15-1)
//
// 発行: クライアント採番の id と発行文(リンク公開鍵・検証済みヘッド・発行署名)を
// 保存する。サーバーは発行署名を検証しない(検証者は招待者自身と受諾者 —
// 二重の真実源を作らない)。応答は期限のみ — サーバーは招待の秘密を一切
// 持たず返さない。
//
// 受諾の判定順(裁定 — 理由コードごとにテストで固定): Schema 400 → 認証 401 →
// CSRF / 鍵素材条件 403 → 未知 link_pub 404 → 使用不能 410(発行文の無い旧行は
// → リンク署名 422(which=link)→ 受諾署名 422(which=accept)→ CAS
// (敗北は再読みで 410)。
//
// リンク鍵の種はサーバーを一度も通らない(ワイヤにあるのは公開鍵と署名だけ)。

import {
  ForbiddenError,
  InviteConflictError,
  InviteGoneError,
  InviteNotFoundError,
  InvitePendingLimitError,
  InviteRateLimitedError,
  InviteSignatureInvalidError,
  maruhiApi,
} from "@maruhi/api-schema";
import { auditActorOf, RequestAuth } from "@maruhi/core";
import {
  computeUserKeyFingerprint,
  decodeHex,
  encodeHex,
  type InviteAcceptSignatureContext,
  SUITE_ID,
  verifyInviteAcceptSignature,
  verifyInviteLinkSignature,
} from "@maruhi/crypto";
import { Effect } from "effect";
import { HttpServerResponse } from "effect/unstable/http";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import { ensureKeyMaterialAccess } from "./authz.ts";
import { requireProjectChainAdmin } from "./data-http.ts";
import { INVITE_TTL_MS, InviteRepo } from "./db.package/index.ts";
import type { InvitationRecord, InviteIssuance } from "./invite-domain.ts";

/**
 * 使用不能理由の導出(§15-1: 期限切れは expires_at からの導出)。判定順は
 * 状態 → 発行文の有無 → 期限に固定(revoked かつ期限切れは revoked — テストで
 * 固定)。pending かつ期限内で発行文があれば null(使用可能)。
 */
function goneReasonOf(
  record: InvitationRecord,
  nowMs: number,
): "accepted" | "completed" | "revoked" | "expired" | null {
  if (record.status !== "pending") {
    return record.status;
  }
  return record.expiresAtMs <= nowMs ? "expired" : null;
}

/** 一覧 1 行のワイヤ表現(InvitationSummarySchema)への写像。 */
function toSummary(record: InvitationRecord) {
  return {
    id: record.id,
    projectId: record.projectId,
    role: record.role,
    status: record.status,
    inviterUserId: record.inviterUserId,
    issuance: record.issuance,
    createdAtMs: record.createdAtMs,
    expiresAtMs: record.expiresAtMs,
    acceptance:
      record.acceptance === null
        ? null
        : {
            inviteeUserId: record.acceptance.inviteeUserId,
            inviteeEncPubHex: record.acceptance.inviteeEncPubHex,
            inviteeSigPubHex: record.acceptance.inviteeSigPubHex,
            signatureHex: record.acceptance.acceptSignatureHex,
            linkSignatureHex: record.acceptance.linkSignatureHex,
            acceptedAtMs: record.acceptance.acceptedAtMs,
          },
  };
}

/**
 * 受諾鍵 FP の算出(AUDIT_SPEC §3.2: invite.accepted の payload に写す)。
 * 鍵は Schema が形式(32 バイト hex)を検証済み — ここでの失敗は実装バグの
 * 検出線であり defect でよい。
 */
const fingerprintOf = (encPubHex: string, sigPubHex: string): Effect.Effect<string> =>
  Effect.promise(async () => {
    const encPub = decodeHex(encPubHex);
    const sigPub = decodeHex(sigPubHex);
    if (encPub === null || sigPub === null) {
      throw new Error("schema-validated key hex failed to decode");
    }
    const fingerprint = await computeUserKeyFingerprint(encPub, sigPub);
    if (!fingerprint.ok) {
      throw new Error("schema-validated keys failed fingerprint computation");
    }
    return encodeHex(fingerprint.value);
  });

/**
 * 受諾の両署名の検証(CRYPTO_SPEC §6.5 v2)。signed_bytes の project_id /
 * link_pub は保存行から、invitee_user_id は呼び出し主体から再構成する(ワイヤ
 * 申告値から組まない — §15-2)。リンク署名 → 受諾署名の順(判定順の固定)。
 */
function verifyAcceptanceSignatures(input: {
  readonly record: InvitationRecord;
  readonly issuance: InviteIssuance;
  readonly inviteeUserId: string;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly acceptSignatureHex: string;
  readonly linkSignatureHex: string;
}): Effect.Effect<void, InviteSignatureInvalidError> {
  return Effect.gen(function* () {
    const context: InviteAcceptSignatureContext = {
      suite: SUITE_ID,
      projectId: input.record.projectId,
      linkPubHex: input.issuance.linkPubHex,
      inviteeUserId: input.inviteeUserId,
      inviteeEncPubHex: input.encPubHex,
      inviteeSigPubHex: input.sigPubHex,
    };
    const linkVerified = yield* Effect.promise(() =>
      verifyInviteLinkSignature({ context, linkSignatureHex: input.linkSignatureHex }),
    );
    if (!linkVerified.ok) {
      return yield* Effect.fail(new InviteSignatureInvalidError({ which: "link" }));
    }
    const acceptVerified = yield* Effect.promise(() =>
      verifyInviteAcceptSignature({ context, signatureHex: input.acceptSignatureHex }),
    );
    if (!acceptVerified.ok) {
      return yield* Effect.fail(new InviteSignatureInvalidError({ which: "accept" }));
    }
  });
}

export const invitesLive = HttpApiBuilder.group(maruhiApi, "invites", (handlers) =>
  handlers
    .handle("issue", ({ params, payload, endpoint }) =>
      Effect.gen(function* () {
        const { principal, role } = yield* requireProjectChainAdmin(params.projectId, endpoint);
        // §15-2: role = admin の招待の発行は owner のみ(add_member 権限表と同水準)
        if (payload.role === "admin" && role !== "owner") {
          return yield* Effect.fail(new ForbiddenError({ reason: "insufficient-role" }));
        }
        const nowMs = Date.now();
        const invites = yield* InviteRepo;
        const decision = yield* invites.create(
          {
            id: payload.id,
            projectId: params.projectId,
            role: payload.role,
            inviterUserId: principal.userId,
            issuance: {
              linkPubHex: payload.linkPubHex,
              headHashHex: payload.headHashHex,
              headSeq: payload.headSeq,
              issueSignatureHex: payload.issueSignatureHex,
            },
          },
          nowMs,
          auditActorOf(principal),
        );
        switch (decision.kind) {
          case "created":
            // 応答に秘密は無い(§15-1)。id はクライアントが採番済み
            return { expiresAtMs: nowMs + INVITE_TTL_MS };
          case "conflict":
            return yield* Effect.fail(new InviteConflictError({ field: decision.field }));
          case "pending-limit":
            return yield* Effect.fail(new InvitePendingLimitError({ limit: decision.limit }));
          case "rate-limited":
            return yield* Effect.fail(
              new InviteRateLimitedError({ retryAfterSeconds: decision.retryAfterSeconds }),
            );
        }
      }),
    )
    .handle("accept", ({ payload }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        // B1a 裁定: 受諾は鍵宣言クラスの操作(§13-2 と同水準のトークン条件)
        yield* ensureKeyMaterialAccess(principal);
        const invites = yield* InviteRepo;
        // リンク鍵の保持が capability(§15-1)。公開鍵で解決する
        const record = yield* invites.findByLinkPub(payload.linkPubHex);
        if (record === null) {
          return yield* Effect.fail(new InviteNotFoundError());
        }
        const nowMs = Date.now();
        const gone = goneReasonOf(record, nowMs);
        if (gone !== null) {
          return yield* Effect.fail(new InviteGoneError({ reason: gone }));
        }
        yield* verifyAcceptanceSignatures({
          record,
          issuance: record.issuance,
          inviteeUserId: principal.userId,
          encPubHex: payload.encPubHex,
          sigPubHex: payload.sigPubHex,
          acceptSignatureHex: payload.acceptSignatureHex,
          linkSignatureHex: payload.linkSignatureHex,
        });
        const inviteeKeyFingerprintHex = yield* fingerprintOf(payload.encPubHex, payload.sigPubHex);
        // 単回使用の CAS(pending → accepted — §15-1)。invite.accepted は
        // リポジトリが同一 batch で記録する(AUDIT_SPEC §3.2 / §5.2)
        const won = yield* invites.acceptCas(
          {
            inviteId: record.id,
            inviteeUserId: principal.userId,
            inviteeEncPubHex: payload.encPubHex,
            inviteeSigPubHex: payload.sigPubHex,
            acceptSignatureHex: payload.acceptSignatureHex,
            linkSignatureHex: payload.linkSignatureHex,
            inviteeKeyFingerprintHex,
          },
          nowMs,
          auditActorOf(principal),
        );
        if (!won) {
          // CAS 敗北 = 並行遷移(先着受諾・失効)または期限到達。再読みで理由を
          // 導出する。pending かつ期限内で敗北することはない(CAS 条件と同値)
          // ため、goneReasonOf が null を返したら不変条件違反 = defect
          const current = yield* invites.findById(record.projectId, record.id);
          const reason = current === null ? null : goneReasonOf(current, nowMs);
          if (reason === null) {
            return yield* Effect.die(new Error("invite accept CAS lost without a gone reason"));
          }
          return yield* Effect.fail(new InviteGoneError({ reason }));
        }
        // 最小応答(§15-1: サーバー申告を信頼させる面を作らない — 招待者情報・
        // アンカーはリンクのフラグメントが運ぶ)
        return { id: record.id, projectId: record.projectId, role: record.role };
      }),
    )
    .handle("list", ({ params, endpoint }) =>
      Effect.gen(function* () {
        yield* requireProjectChainAdmin(params.projectId, endpoint);
        const invites = yield* InviteRepo;
        const records = yield* invites.listForProject(params.projectId);
        return { invitations: records.map(toSummary) };
      }),
    )
    .handle("revoke", ({ params, endpoint }) =>
      Effect.gen(function* () {
        const { principal } = yield* requireProjectChainAdmin(params.projectId, endpoint);
        const invites = yield* InviteRepo;
        const record = yield* invites.findById(params.projectId, params.id);
        if (record === null) {
          return yield* Effect.fail(new InviteNotFoundError());
        }
        // 失効は pending | accepted に効く(期限切れ pending の掃除も可 —
        // B1a 裁定)。completed / revoked は 410。invite.revoked はリポジトリが
        // 同一 batch で記録する(AUDIT_SPEC §3.2)
        const nowMs = Date.now();
        const won = yield* invites.revokeCas(
          params.projectId,
          record.id,
          { role: record.role },
          nowMs,
          auditActorOf(principal),
        );
        if (!won) {
          const current = yield* invites.findById(params.projectId, record.id);
          if (current === null || current.status === "pending" || current.status === "accepted") {
            return yield* Effect.die(new Error("invite revoke CAS lost without a terminal status"));
          }
          return yield* Effect.fail(new InviteGoneError({ reason: current.status }));
        }
        return HttpServerResponse.empty({ status: 204 });
      }),
    ),
);
