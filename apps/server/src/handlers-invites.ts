// 招待 API のハンドラ(AUTH_SPEC §15)。
//
// 認可の流れ:
//   - 発行 / 一覧 / 失効(プロジェクト配下): トークンスコープ admin(スコープ外
//     404 — §11-2)→ DO memberRoleFor(非メンバー 404 / チェーン role の取得)→
//     admin 水準判定(未満 403)。role=admin の招待の発行は owner のみ(§15-2)
//   - 受諾: 認証済み主体 + 鍵素材条件(§13-2 と同水準 — B1a 裁定)。トークン
//     保持が対象招待への capability(§15-1)
//
// 受諾の判定順(裁定 — 理由コードごとにテストで固定): Schema 400 → 認証 401 →
// CSRF / 鍵素材条件 403 → 未知トークン 404 → 使用不能 410 → 署名 422 → CAS
// (敗北は再読みで 410)。
//
// トークン生値はこのファイルのローカル変数にのみ存在し、ログ・監査・エラーへ
// 出ない(§15-1: DB にはハッシュのみ)。

import {
  ForbiddenError,
  InviteGoneError,
  InviteNotFoundError,
  InvitePendingLimitError,
  InviteRateLimitedError,
  InviteSignatureInvalidError,
  maruhiApi,
} from "@maruhi/api-schema";
import { auditActorOf, RequestAuth } from "@maruhi/core";
import type { Role } from "@maruhi/crypto";
import {
  computeUserKeyFingerprint,
  decodeHex,
  encodeHex,
  SUITE_ID,
  verifyInviteAcceptSignature,
} from "@maruhi/crypto";
import { Effect } from "effect";
import { HttpServerResponse } from "effect/unstable/http";
import type { HttpApiEndpoint } from "effect/unstable/httpapi";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import { ensureKeyMaterialAccess, ensureTokenScopeForProject } from "./authz.ts";
import { unwrapDataOutcome } from "./data-http.ts";
import type { DataOutcome } from "./data-plane.ts";
import { roleAtLeast } from "./data-plane.ts";
import { INVITE_TTL_MS, InviteRepo } from "./db.package/index.ts";
import { randomBase62, sha256Hex, ulid } from "./ids.ts";
import type { InvitationRecord } from "./invite-domain.ts";
import { projectStub, rpcCall, WorkerEnv } from "./worker-env.ts";

/** 招待トークンのワイヤ形式(api-schema の InviteTokenSchema と対)。 */
const INVITE_TOKEN_PREFIX = "maruhi_inv_";

/**
 * プロジェクト配下エンドポイント共通の前段: トークンスコープ admin(スコープ外
 * 404)→ DO の memberRoleFor(非メンバー 404 — §11-2)→ チェーン role admin
 * 以上(未満 403)。通過したら呼び出し主体の role を返す(owner 限定判定用)。
 */
const requireProjectInviteAdmin = <Endpoint extends HttpApiEndpoint.Top>(
  projectId: string,
  endpoint: Endpoint,
) =>
  Effect.gen(function* () {
    const principal = yield* (yield* RequestAuth).principal;
    yield* ensureTokenScopeForProject(principal, projectId, "admin");
    const env = yield* WorkerEnv;
    const outcome = yield* rpcCall<DataOutcome<Role>>(() =>
      projectStub(env, projectId).memberRoleFor(principal.userId),
    );
    const role = yield* unwrapDataOutcome(outcome, projectId, endpoint);
    if (!roleAtLeast(role, "admin")) {
      return yield* Effect.fail(new ForbiddenError({ reason: "insufficient-role" }));
    }
    return { principal, role };
  });

/**
 * 使用不能理由の導出(§15-1: 期限切れは expires_at からの導出)。判定順は
 * 状態 → 期限に固定(revoked かつ期限切れは revoked — テストで固定)。
 * pending かつ期限内なら null(使用可能)。
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
    tokenHashHex: record.tokenHashHex,
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

export const invitesLive = HttpApiBuilder.group(maruhiApi, "invites", (handlers) =>
  handlers
    .handle("issue", ({ params, payload, endpoint }) =>
      Effect.gen(function* () {
        const { principal, role } = yield* requireProjectInviteAdmin(params.projectId, endpoint);
        // §15-2: role = admin の招待の発行は owner のみ(add_member 権限表と同水準)
        if (payload.role === "admin" && role !== "owner") {
          return yield* Effect.fail(new ForbiddenError({ reason: "insufficient-role" }));
        }
        const rawToken = INVITE_TOKEN_PREFIX + randomBase62();
        const tokenHashHex = yield* Effect.promise(() => sha256Hex(rawToken));
        const inviteId = ulid();
        const nowMs = Date.now();
        const invites = yield* InviteRepo;
        const decision = yield* invites.create(
          {
            id: inviteId,
            projectId: params.projectId,
            tokenHashHex,
            role: payload.role,
            inviterUserId: principal.userId,
          },
          nowMs,
          auditActorOf(principal),
        );
        switch (decision.kind) {
          case "created":
            // トークン生値はこの応答で一度だけ返る(§15-1)
            return {
              id: inviteId,
              token: rawToken,
              role: payload.role,
              expiresAtMs: nowMs + INVITE_TTL_MS,
            };
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
        // トークン保持が capability(§15-1)。ハッシュで解決し、生値は保存しない
        const tokenHashHex = yield* Effect.promise(() => sha256Hex(payload.token));
        const record = yield* invites.findByTokenHash(tokenHashHex);
        if (record === null) {
          return yield* Effect.fail(new InviteNotFoundError());
        }
        const nowMs = Date.now();
        const gone = goneReasonOf(record, nowMs);
        if (gone !== null) {
          return yield* Effect.fail(new InviteGoneError({ reason: gone }));
        }
        // §15-2: signed_bytes の project_id / token_hash は保存行から、
        // invitee_user_id は呼び出し主体から再構成する(ワイヤ申告値から組まない
        // — 呼び出し主体 = 署名者の要求は署名検証そのものが強制する)。鍵は
        // Schema の形式検査のみ(真実源は add_member のチェーン合意規則)
        const verified = yield* Effect.promise(() =>
          verifyInviteAcceptSignature({
            context: {
              suite: SUITE_ID,
              projectId: record.projectId,
              inviteTokenHashHex: record.tokenHashHex,
              inviteeUserId: principal.userId,
              inviteeEncPubHex: payload.encPubHex,
              inviteeSigPubHex: payload.sigPubHex,
            },
            signatureHex: payload.signatureHex,
          }),
        );
        if (!verified.ok) {
          return yield* Effect.fail(new InviteSignatureInvalidError());
        }
        const inviteeKeyFingerprintHex = yield* fingerprintOf(payload.encPubHex, payload.sigPubHex);
        // 単回使用の CAS(pending → accepted — §15-1)。invite.accepted は
        // リポジトリが同一 batch で記録する(AUDIT_SPEC §3.2 / §5.2)
        const won = yield* invites.acceptCas(
          {
            inviteId: record.id,
            inviteeUserId: principal.userId,
            inviteeEncPubHex: payload.encPubHex,
            inviteeSigPubHex: payload.sigPubHex,
            acceptSignatureHex: payload.signatureHex,
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
        yield* requireProjectInviteAdmin(params.projectId, endpoint);
        const invites = yield* InviteRepo;
        const records = yield* invites.listForProject(params.projectId);
        return { invitations: records.map(toSummary) };
      }),
    )
    .handle("revoke", ({ params, endpoint }) =>
      Effect.gen(function* () {
        const { principal } = yield* requireProjectInviteAdmin(params.projectId, endpoint);
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
