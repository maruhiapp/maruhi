// master 鍵ラップ台帳 API のハンドラ(AUTH_SPEC §13-6〜13-10 — KL3。
// CRYPTO_SPEC §8 のクラス S / G / H のサーバー面)。
//
// 認可(§13-7):
//   - `status`: 認証済み主体すべて(セッション可 — §5 の許可列挙)。ラップ・分片・
//     秘密のパラメータを運ばない
//   - それ以外: 鍵素材クラスのトークン条件(`*` × admin — ensureKeyMaterialAccess。
//     セッション主体は AuthMiddleware の宣言層が先に 403 を返す)
//   - ハンドオフの照会 / 承認: 呼び出し主体が ward 本人か ward の保護者のときだけ
//     要求が見える。それ以外・不明・失効は一様 404(§11-2 の存在秘匿と同じ規律)
//
// サーバーはラップ・分片の中身を解釈しない(不透明な暗号文の保存・配布のみ)。
// 鍵の正しさ(保護者の enc 公開鍵がチェーン導出の鍵と一致するか)も検証しない —
// 真実源は ward クライアントの確認(CRYPTO_SPEC §8.3)であり、二重の真実源を
// 作らない。E.pub はワイヤに現れない(コードは人が運ぶ — §8.4)。

import {
  HANDOFF_REQUEST_TTL_MS,
  HandoffConflictError,
  HandoffNotFoundError,
  KeyWrapNotFoundError,
  KeyWrapPolicyError,
  KeyWrapRateLimitedError,
  maruhiApi,
  MAX_GUARDIAN_GROUPS_PER_USER,
  MAX_HANDOFF_APPROVALS_PER_REQUEST,
  MAX_PASSKEY_WRAPS_PER_USER,
} from "@maruhi/api-schema";
import { auditActorOf, RequestAuth } from "@maruhi/core";
import { Effect } from "effect";
import { HttpServerResponse } from "effect/unstable/http";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import { ensureKeyMaterialAccess } from "./authz.ts";
import {
  APPROVAL_LIMIT,
  HANDOFF_REQUEST_LIMIT,
  KEY_BLOB_FETCH_LIMIT,
  type KeyWrapRepoShape,
  KeyWrapRepo,
  RecoveryRepo,
} from "./db.package/index.ts";
import type {
  GuardianGroupRecord,
  HandoffRequestRecord,
  KeyWrapWindowDecision,
  KeyWrapWindowKind,
} from "./key-wrap-domain.ts";

/** 窓の拒否を型付き 429 へ写す。 */
function rateLimited(
  window: KeyWrapWindowKind,
  decision: KeyWrapWindowDecision,
): Effect.Effect<void, KeyWrapRateLimitedError> {
  return decision.allowed
    ? Effect.void
    : Effect.fail(
        new KeyWrapRateLimitedError({ window, retryAfterSeconds: decision.retryAfterSeconds }),
      );
}

/** passkey 行の公開パラメータ(§13-9 — サーバーは書いた JSON をそのまま返す)。 */
interface PasskeyParams {
  readonly credentialIdHex: string;
  readonly prfSaltHex: string;
  readonly rpId: "localhost";
  readonly label?: string;
}

function parsePasskeyParams(json: string): PasskeyParams {
  // 書き込みは本ファイルの passkeyRegister のみ(Schema 検証済みの値の JSON 化)。
  // 解釈できない行は実装バグ / DB 破損であり、黙って別の形で配布しない
  const parsed: unknown = JSON.parse(json);
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    typeof (parsed as { credentialIdHex?: unknown }).credentialIdHex !== "string" ||
    typeof (parsed as { prfSaltHex?: unknown }).prfSaltHex !== "string"
  ) {
    throw new Error("stored passkey wrap has malformed params");
  }
  const record = parsed as { credentialIdHex: string; prfSaltHex: string; label?: unknown };
  return {
    credentialIdHex: record.credentialIdHex,
    prfSaltHex: record.prfSaltHex,
    rpId: "localhost",
    ...(typeof record.label === "string" ? { label: record.label } : {}),
  };
}

/**
 * 分片集合の構造検査(§13-7 / §13-8): share_index が 1..n をちょうど 1 回ずつ
 * 覆う・保護者が重複しない・ward 自身を含まない・`all` は 2 人以上。
 */
function guardianPolicyViolation(input: {
  readonly wardUserId: string;
  readonly mode: "any" | "all";
  readonly shares: readonly { readonly shareIndex: number; readonly guardianUserId: string }[];
}): "share-count" | "self-guardian" | "duplicate-guardian" | null {
  const indexes = new Set(input.shares.map((s) => s.shareIndex));
  const contiguous =
    indexes.size === input.shares.length &&
    input.shares.every((s) => s.shareIndex >= 1 && s.shareIndex <= input.shares.length);
  if (!contiguous || (input.mode === "all" && input.shares.length < 2)) {
    return "share-count";
  }
  if (input.shares.some((s) => s.guardianUserId === input.wardUserId)) {
    return "self-guardian";
  }
  if (new Set(input.shares.map((s) => s.guardianUserId)).size !== input.shares.length) {
    return "duplicate-guardian";
  }
  return null;
}

/**
 * 要求の照会・承認で呼び出し主体が取れる役割(§13-7): ward 本人 = device、
 * ward の保護者 = 自分の分片。どちらでもなければ null(一様 404)。
 */
function rolesFor(
  repo: KeyWrapRepoShape,
  request: HandoffRequestRecord,
  principalUserId: string,
): Effect.Effect<readonly HandoffRole[] | null> {
  if (request.userId === principalUserId) {
    return Effect.succeed(["device"] as const);
  }
  return repo
    .sharesOfGuardian(principalUserId, request.userId)
    .pipe(
      Effect.map((shares) =>
        shares.length === 0
          ? null
          : shares.map((s) => ({ groupId: s.groupId, mode: s.mode, shareIndex: s.shareIndex })),
      ),
    );
}

type HandoffRole =
  | "device"
  | { readonly groupId: string; readonly mode: "any" | "all"; readonly shareIndex: number };

/**
 * 役割と承認 payload の整合(§13-7): device は ward 本人・share_index 0・blob 必須。
 * 保護者は自分の (group, share_index)・blob なし。照合は保存行(roles)から行い、
 * payload の申告値で認可しない。
 */
function approvalPermitted(
  roles: readonly HandoffRole[],
  payload: {
    readonly source: string;
    readonly shareIndex: number;
    readonly blob?: unknown;
  },
): boolean {
  if (payload.source === "device") {
    return roles.includes("device") && payload.shareIndex === 0 && payload.blob !== undefined;
  }
  const ownShare = roles.some(
    (role) =>
      role !== "device" &&
      role.groupId === payload.source &&
      role.shareIndex === payload.shareIndex,
  );
  return ownShare && payload.blob === undefined;
}

/** 削除系の共通応答: 消せたら 204、対象が無ければ 404。 */
function noContentOrNotFound(deleted: boolean) {
  return deleted
    ? Effect.succeed(HttpServerResponse.empty({ status: 204 }))
    : Effect.fail(new KeyWrapNotFoundError());
}

/** ward 本人か ward の保護者にだけ見える要求を解決する(それ以外は一様 404)。 */
function visibleRequest(
  repo: KeyWrapRepoShape,
  requestId: string,
  principalUserId: string,
  nowMs: number,
) {
  return Effect.gen(function* () {
    const request = yield* repo.handoffFind(requestId, nowMs);
    if (request === null) {
      return yield* Effect.fail(new HandoffNotFoundError());
    }
    const roles = yield* rolesFor(repo, request, principalUserId);
    if (roles === null) {
      return yield* Effect.fail(new HandoffNotFoundError());
    }
    return { request, roles };
  });
}

function toGroupSummary(group: GuardianGroupRecord) {
  return {
    groupId: group.groupId,
    mode: group.mode,
    createdAtMs: group.createdAtMs,
    guardians: group.shares.map((s) => ({
      shareIndex: s.shareIndex,
      guardianUserId: s.guardianUserId,
      guardianKeyFingerprintHex: s.guardianKeyFingerprintHex,
    })),
  };
}

export const keyWrapsLive = HttpApiBuilder.group(maruhiApi, "keyWraps", (handlers) =>
  handlers
    .handle("status", () =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        const repo = yield* KeyWrapRepo;
        const recovery = yield* (yield* RecoveryRepo).find(principal.userId);
        const passkeys = yield* repo.passkeyList(principal.userId);
        const groups = yield* repo.guardianList(principal.userId);
        return {
          recoveryCode:
            recovery === null
              ? { registered: false, updatedAtMs: null }
              : { registered: true, updatedAtMs: recovery.updatedAtMs },
          passkeys: passkeys.map((p) => {
            const params = parsePasskeyParams(p.params);
            return {
              wrapId: p.wrapId,
              label: params.label ?? null,
              credentialIdHex: params.credentialIdHex,
              updatedAtMs: p.updatedAtMs,
            };
          }),
          guardianGroups: groups.map(toGroupSummary),
        };
      }),
    )
    .handle("passkeyRegister", ({ payload }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* KeyWrapRepo;
        // wrap_id はクライアント採番(AAD が束縛する — CRYPTO_SPEC §8.1)
        const wrapId = payload.wrapId;
        const params: PasskeyParams = {
          credentialIdHex: payload.credentialIdHex,
          prfSaltHex: payload.prfSaltHex,
          rpId: payload.rpId,
          ...(payload.label === undefined ? {} : { label: payload.label }),
        };
        const decision = yield* repo.passkeyInsert({
          userId: principal.userId,
          wrapId,
          params: JSON.stringify(params),
          wrap: payload.wrap,
          limit: MAX_PASSKEY_WRAPS_PER_USER,
          nowMs: Date.now(),
          actor: auditActorOf(principal),
        });
        if (decision !== "created") {
          return yield* Effect.fail(
            new KeyWrapPolicyError({
              reason: decision === "limit" ? "too-many-passkeys" : "duplicate-id",
            }),
          );
        }
        return { wrapId };
      }),
    )
    .handle("passkeyGet", ({ params }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* KeyWrapRepo;
        // 未登録 404 は窓を消費しない(§13-8)
        const record = yield* repo.passkeyFind(principal.userId, params.wrapId);
        if (record === null) {
          return yield* Effect.fail(new KeyWrapNotFoundError());
        }
        if (record.wrap.suite !== "maruhi/v1") {
          return yield* Effect.die(new Error("stored passkey wrap has an unknown suite"));
        }
        yield* rateLimited(
          "blob-fetch",
          yield* repo.consumeWindow({
            userId: principal.userId,
            kind: "blob-fetch",
            limit: KEY_BLOB_FETCH_LIMIT,
            nowMs: Date.now(),
            audit: {
              event: "auth.key_wrap_fetched",
              actor: auditActorOf(principal),
              payload: { kind: "passkey-prf", wrapId: record.wrapId },
            },
          }),
        );
        const stored = parsePasskeyParams(record.params);
        return {
          wrapId: record.wrapId,
          wrap: {
            suite: "maruhi/v1" as const,
            nonceHex: record.wrap.nonceHex,
            ciphertextHex: record.wrap.ciphertextHex,
          },
          credentialIdHex: stored.credentialIdHex,
          prfSaltHex: stored.prfSaltHex,
          rpId: "localhost" as const,
          label: stored.label ?? null,
          updatedAtMs: record.updatedAtMs,
        };
      }),
    )
    .handle("passkeyDelete", ({ params }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* KeyWrapRepo;
        return yield* noContentOrNotFound(
          yield* repo.passkeyDelete(
            principal.userId,
            params.wrapId,
            Date.now(),
            auditActorOf(principal),
          ),
        );
      }),
    )
    .handle("guardianCreate", ({ payload }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* KeyWrapRepo;
        const violation = guardianPolicyViolation({
          wardUserId: principal.userId,
          mode: payload.mode,
          shares: payload.shares,
        });
        if (violation !== null) {
          return yield* Effect.fail(new KeyWrapPolicyError({ reason: violation }));
        }
        const missing = yield* repo.missingUsers(payload.shares.map((s) => s.guardianUserId));
        if (missing.length > 0) {
          return yield* Effect.fail(new KeyWrapPolicyError({ reason: "unknown-guardian" }));
        }
        // group_id はクライアント採番(AAD / 分片 info が束縛する — CRYPTO_SPEC §8.3)
        const groupId = payload.groupId;
        const decision = yield* repo.guardianCreate({
          userId: principal.userId,
          groupId,
          mode: payload.mode,
          wrap: payload.wrap,
          shares: payload.shares,
          limit: MAX_GUARDIAN_GROUPS_PER_USER,
          nowMs: Date.now(),
          actor: auditActorOf(principal),
        });
        if (decision !== "created") {
          return yield* Effect.fail(
            new KeyWrapPolicyError({
              reason: decision === "limit" ? "too-many-groups" : "duplicate-id",
            }),
          );
        }
        return { groupId };
      }),
    )
    .handle("guardianGet", ({ params }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* KeyWrapRepo;
        const group = yield* repo.guardianFind(principal.userId, params.groupId);
        if (group === null) {
          return yield* Effect.fail(new KeyWrapNotFoundError());
        }
        if (group.wrap.suite !== "maruhi/v1") {
          return yield* Effect.die(new Error("stored guardian wrap has an unknown suite"));
        }
        yield* rateLimited(
          "blob-fetch",
          yield* repo.consumeWindow({
            userId: principal.userId,
            kind: "blob-fetch",
            limit: KEY_BLOB_FETCH_LIMIT,
            nowMs: Date.now(),
            audit: {
              event: "auth.key_wrap_fetched",
              actor: auditActorOf(principal),
              payload: { kind: "guardian", groupId: group.groupId },
            },
          }),
        );
        return {
          groupId: group.groupId,
          mode: group.mode,
          wrap: {
            suite: "maruhi/v1" as const,
            nonceHex: group.wrap.nonceHex,
            ciphertextHex: group.wrap.ciphertextHex,
          },
          createdAtMs: group.createdAtMs,
        };
      }),
    )
    .handle("guardianDelete", ({ params }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* KeyWrapRepo;
        return yield* noContentOrNotFound(
          yield* repo.guardianDelete(
            principal.userId,
            params.groupId,
            Date.now(),
            auditActorOf(principal),
          ),
        );
      }),
    )
    .handle("wards", () =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* KeyWrapRepo;
        const shares = yield* repo.sharesOfGuardian(principal.userId);
        return {
          wards: shares.map((s) => ({
            wardUserId: s.wardUserId,
            wardLogin: s.wardLogin,
            groupId: s.groupId,
            mode: s.mode,
            shareIndex: s.shareIndex,
            createdAtMs: s.createdAtMs,
          })),
        };
      }),
    )
    .handle("myShare", ({ params }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* KeyWrapRepo;
        const shares = yield* repo.sharesOfGuardian(principal.userId);
        const share = shares.find((s) => s.groupId === params.groupId);
        if (share === undefined) {
          return yield* Effect.fail(new KeyWrapNotFoundError());
        }
        // 分片の取得は承認窓で数える(§13-8)— 要監視イベント
        yield* rateLimited(
          "approval",
          yield* repo.consumeWindow({
            userId: principal.userId,
            kind: "approval",
            limit: APPROVAL_LIMIT,
            nowMs: Date.now(),
            audit: {
              event: "auth.guardian_share_fetched",
              actor: auditActorOf(principal),
              targetUserId: share.wardUserId,
              payload: { groupId: share.groupId, shareIndex: share.shareIndex },
            },
          }),
        );
        return {
          groupId: share.groupId,
          wardUserId: share.wardUserId,
          mode: share.mode,
          shareIndex: share.shareIndex,
          encHex: share.encHex,
          ciphertextHex: share.ciphertextHex,
        };
      }),
    )
    .handle("handoffCreate", ({ payload }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* KeyWrapRepo;
        const nowMs = Date.now();
        // 日和見削除(失効 + 猶予を過ぎた要求)
        yield* repo.handoffSweep(nowMs);
        yield* rateLimited(
          "handoff-request",
          yield* repo.consumeWindow({
            userId: principal.userId,
            kind: "handoff-request",
            limit: HANDOFF_REQUEST_LIMIT,
            nowMs,
            // 要求の監査(auth.key_handoff_requested)は行の挿入と同一 batch
            // (handoffCreate)で記録する — 409(既存 id)を要求として記録しない
          }),
        );
        const decision = yield* repo.handoffCreate({
          requestId: payload.requestId,
          userId: principal.userId,
          ttlMs: HANDOFF_REQUEST_TTL_MS,
          nowMs,
          actor: auditActorOf(principal),
        });
        if (decision === "conflict") {
          return yield* Effect.fail(new HandoffConflictError({ reason: "request-exists" }));
        }
        return { expiresAtMs: nowMs + HANDOFF_REQUEST_TTL_MS };
      }),
    )
    .handle("handoffLookup", ({ params }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* KeyWrapRepo;
        const { request, roles } = yield* visibleRequest(
          repo,
          params.requestId,
          principal.userId,
          Date.now(),
        );
        const wardLogin = yield* repo.loginOf(request.userId);
        return {
          wardUserId: request.userId,
          wardLogin,
          expiresAtMs: request.expiresAtMs,
          roles,
        };
      }),
    )
    .handle("handoffApprove", ({ params, payload }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* KeyWrapRepo;
        const nowMs = Date.now();
        const { request, roles } = yield* visibleRequest(
          repo,
          params.requestId,
          principal.userId,
          nowMs,
        );
        if (!approvalPermitted(roles, payload)) {
          return yield* Effect.fail(new KeyWrapPolicyError({ reason: "source-mismatch" }));
        }
        yield* rateLimited(
          "approval",
          yield* repo.consumeWindow({
            userId: principal.userId,
            kind: "approval",
            limit: APPROVAL_LIMIT,
            nowMs,
            // 承認自体の監査は挿入と同一 batch(handoffApprove)で記録する。窓の
            // 消費は監査を伴わない(同じ承認を 2 度記録しない)
          }),
        );
        const decision = yield* repo.handoffApprove({
          requestId: request.requestId,
          wardUserId: request.userId,
          approverUserId: principal.userId,
          approval: {
            source: payload.source,
            shareIndex: payload.shareIndex,
            approverKeyFingerprintHex: payload.approverKeyFingerprintHex,
            encHex: payload.encHex,
            ciphertextHex: payload.ciphertextHex,
            blob: payload.blob ?? null,
          },
          limit: MAX_HANDOFF_APPROVALS_PER_REQUEST,
          nowMs,
          actor: auditActorOf(principal),
        });
        switch (decision) {
          case "created":
            return HttpServerResponse.empty({ status: 204 });
          case "conflict":
            return yield* Effect.fail(new HandoffConflictError({ reason: "already-approved" }));
          case "exceeded":
            return yield* Effect.fail(new KeyWrapPolicyError({ reason: "approvals-exceeded" }));
        }
      }),
    )
    .handle("handoffApprovals", ({ params }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* KeyWrapRepo;
        const nowMs = Date.now();
        const request = yield* repo.handoffFind(params.requestId, nowMs);
        // 承認の取得は ward 本人のみ(保護者には一様 404)
        if (request === null || request.userId !== principal.userId) {
          return yield* Effect.fail(new HandoffNotFoundError());
        }
        const approvals = yield* repo.handoffApprovals(request.requestId);
        if (approvals.length > 0) {
          yield* repo.handoffMarkCollected(
            request.requestId,
            approvals.length,
            nowMs,
            auditActorOf(principal),
          );
        }
        return {
          approvals: approvals.map((a) => ({
            source: a.source,
            shareIndex: a.shareIndex,
            approverUserId: a.approverUserId,
            approverKeyFingerprintHex: a.approverKeyFingerprintHex,
            encHex: a.encHex,
            ciphertextHex: a.ciphertextHex,
            blob:
              a.blob === null
                ? null
                : {
                    suite: "maruhi/v1" as const,
                    nonceHex: a.blob.nonceHex,
                    ciphertextHex: a.blob.ciphertextHex,
                  },
            createdAtMs: a.createdAtMs,
          })),
        };
      }),
    )
    .handle("handoffCancel", ({ params }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* KeyWrapRepo;
        const deleted = yield* repo.handoffDelete(params.requestId, principal.userId);
        if (!deleted) {
          return yield* Effect.fail(new HandoffNotFoundError());
        }
        return HttpServerResponse.empty({ status: 204 });
      }),
    ),
);
