import {
  HANDOFF_REQUEST_TTL_MS,
  HandoffConflictError,
  HandoffNotFoundError,
  KeyWrapNotFoundError,
  KeyWrapPolicyError,
  KeyWrapRateLimitedError,
  maruhiApi,
  MAX_GUARDIAN_DEVICES_PER_GUARDIAN,
  MAX_GUARDIAN_GROUPS_PER_USER,
  MAX_HANDOFF_APPROVALS_PER_REQUEST,
  MAX_PASSKEY_WRAPS_PER_USER,
} from "@maruhi/api-schema";
import type { KeyFingerprintHex } from "@maruhi/core";
import { auditActorOf, RequestAuth, type UserId } from "@maruhi/core";
import { Clock, Effect, Option, Schema } from "effect";
import { HttpServerResponse } from "effect/http";
import { HttpApiBuilder } from "effect/http-api";

import { ensureKeyMaterialAccess } from "../authz.ts";
import {
  APPROVAL_LIMIT,
  HANDOFF_REQUEST_LIMIT,
  KEY_BLOB_FETCH_LIMIT,
  type KeyWrapRepoShape,
  KeyWrapRepo,
  RecoveryRepo,
} from "../db.package/index.ts";
import type {
  GuardianGroupRecord,
  HandoffRequestRecord,
  KeyWrapWindowDecision,
  KeyWrapWindowKind,
} from "../key-wrap-domain.ts";

function rateLimited(
  window: Exclude<KeyWrapWindowKind, "device-request">,
  decision: KeyWrapWindowDecision,
): Effect.Effect<void, KeyWrapRateLimitedError> {
  return decision.allowed
    ? Effect.void
    : Effect.fail(
        new KeyWrapRateLimitedError({ window, retryAfterSeconds: decision.retryAfterSeconds }),
      );
}

interface PasskeyParams {
  readonly credentialIdHex: string;
  readonly prfSaltHex: string;
  readonly rpId: "localhost";
  readonly label?: string;
}

const PasskeyParamsSchema = Schema.Struct({
  credentialIdHex: Schema.String,
  prfSaltHex: Schema.String,
  label: Schema.optional(Schema.Unknown),
});

const decodePasskeyParams = Schema.decodeUnknownOption(Schema.fromJsonString(PasskeyParamsSchema));

function parsePasskeyParams(json: string): PasskeyParams {
  const decoded = decodePasskeyParams(json);
  if (Option.isNone(decoded)) {
    throw new Error("stored passkey wrap has malformed params");
  }
  const record = decoded.value;
  return {
    credentialIdHex: record.credentialIdHex,
    prfSaltHex: record.prfSaltHex,
    rpId: "localhost",
    ...(typeof record.label === "string" ? { label: record.label } : {}),
  };
}

interface LogicalShareIndex {
  readonly guardianOfIndex: ReadonlyMap<number, string>;
  readonly devicesOfIndex: ReadonlyMap<number, ReadonlySet<string>>;
}

function indexLogicalShares(
  shares: readonly {
    readonly shareIndex: number;
    readonly guardianUserId: UserId;
    readonly guardianKeyFingerprintHex: KeyFingerprintHex;
  }[],
): LogicalShareIndex | "duplicate-guardian" {
  const guardianOfIndex = new Map<number, string>();
  const devicesOfIndex = new Map<number, Set<string>>();
  for (const share of shares) {
    const guardian = guardianOfIndex.get(share.shareIndex);
    if (guardian !== undefined && guardian !== share.guardianUserId) {
      return "duplicate-guardian";
    }
    guardianOfIndex.set(share.shareIndex, share.guardianUserId);
    const devices = devicesOfIndex.get(share.shareIndex) ?? new Set<string>();
    if (devices.has(share.guardianKeyFingerprintHex)) {
      return "duplicate-guardian";
    }
    devices.add(share.guardianKeyFingerprintHex);
    devicesOfIndex.set(share.shareIndex, devices);
  }
  return { guardianOfIndex, devicesOfIndex };
}

function guardianPolicyViolation(input: {
  readonly wardUserId: string;
  readonly mode: "any" | "all";
  readonly shares: readonly {
    readonly shareIndex: number;
    readonly guardianUserId: UserId;
    readonly guardianKeyFingerprintHex: KeyFingerprintHex;
  }[];
}): "share-count" | "self-guardian" | "duplicate-guardian" | null {
  const indexed = indexLogicalShares(input.shares);
  if (indexed === "duplicate-guardian") {
    return indexed;
  }
  const { guardianOfIndex, devicesOfIndex } = indexed;
  const n = guardianOfIndex.size;
  const contiguous = [...guardianOfIndex.keys()].every((index) => index >= 1 && index <= n);
  const withinDeviceLimit = [...devicesOfIndex.values()].every(
    (devices) => devices.size <= MAX_GUARDIAN_DEVICES_PER_GUARDIAN,
  );
  if (!contiguous || !withinDeviceLimit || (input.mode === "all" && n < 2)) {
    return "share-count";
  }
  const guardians = [...guardianOfIndex.values()];
  if (guardians.includes(input.wardUserId)) {
    return "self-guardian";
  }
  if (new Set(guardians).size !== guardians.length) {
    return "duplicate-guardian";
  }
  return null;
}

function rolesFor(
  repo: KeyWrapRepoShape,
  request: HandoffRequestRecord,
  principalUserId: UserId,
): Effect.Effect<readonly HandoffRole[] | null> {
  if (request.userId === principalUserId) {
    return Effect.succeed([] as const);
  }
  return repo
    .sharesOfGuardian(principalUserId, request.userId)
    .pipe(Effect.map((shares) => (shares.length === 0 ? null : logicalShareRoles(shares))));
}

type HandoffRole = {
  readonly groupId: string;
  readonly mode: "any" | "all";
  readonly shareIndex: number;
};

function logicalShareRoles(
  shares: readonly {
    readonly groupId: string;
    readonly mode: "any" | "all";
    readonly shareIndex: number;
  }[],
): readonly HandoffRole[] {
  const seen = new Set<string>();
  const roles: HandoffRole[] = [];
  for (const share of shares) {
    const key = `${share.groupId}:${share.shareIndex}`;
    if (!seen.has(key)) {
      seen.add(key);
      roles.push({ groupId: share.groupId, mode: share.mode, shareIndex: share.shareIndex });
    }
  }
  return roles;
}

function approvalPermitted(
  roles: readonly HandoffRole[],
  payload: { readonly source: string; readonly shareIndex: number },
): boolean {
  return roles.some(
    (role) => role.groupId === payload.source && role.shareIndex === payload.shareIndex,
  );
}

function noContentOrNotFound(deleted: boolean) {
  return deleted
    ? Effect.succeed(HttpServerResponse.empty({ status: 204 }))
    : Effect.fail(new KeyWrapNotFoundError());
}

const visibleRequest = Effect.fn("handlers-key-wraps.visibleRequest")(function* (
  repo: KeyWrapRepoShape,
  requestId: string,
  principalUserId: UserId,
  nowMs: number,
) {
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
    .handle(
      "status",
      Effect.fn("handlers-key-wraps.status")(function* () {
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
              prfSaltHex: params.prfSaltHex,
              updatedAtMs: p.updatedAtMs,
            };
          }),
          guardianGroups: groups.map(toGroupSummary),
        };
      }),
    )
    .handle(
      "passkeyRegister",
      Effect.fn("handlers-key-wraps.passkeyRegister")(function* ({ payload }) {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* KeyWrapRepo;
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
          nowMs: yield* Clock.currentTimeMillis,
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
    .handle(
      "passkeyGet",
      Effect.fn("handlers-key-wraps.passkeyGet")(function* ({ params }) {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* KeyWrapRepo;
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
            nowMs: yield* Clock.currentTimeMillis,
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
    .handle(
      "passkeyDelete",
      Effect.fn("handlers-key-wraps.passkeyDelete")(function* ({ params }) {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* KeyWrapRepo;
        return yield* noContentOrNotFound(
          yield* repo.passkeyDelete(
            principal.userId,
            params.wrapId,
            yield* Clock.currentTimeMillis,
            auditActorOf(principal),
          ),
        );
      }),
    )
    .handle(
      "guardianCreate",
      Effect.fn("handlers-key-wraps.guardianCreate")(function* ({ payload }) {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* KeyWrapRepo;
        const shares = payload.shares;
        const violation = guardianPolicyViolation({
          wardUserId: principal.userId,
          mode: payload.mode,
          shares,
        });
        if (violation !== null) {
          return yield* Effect.fail(new KeyWrapPolicyError({ reason: violation }));
        }
        const missing = yield* repo.missingUsers(payload.shares.map((s) => s.guardianUserId));
        if (missing.length > 0) {
          return yield* Effect.fail(new KeyWrapPolicyError({ reason: "unknown-guardian" }));
        }
        const groupId = payload.groupId;
        const decision = yield* repo.guardianCreate({
          userId: principal.userId,
          groupId,
          mode: payload.mode,
          wrap: payload.wrap,
          shares,
          limit: MAX_GUARDIAN_GROUPS_PER_USER,
          nowMs: yield* Clock.currentTimeMillis,
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
    .handle(
      "guardianGet",
      Effect.fn("handlers-key-wraps.guardianGet")(function* ({ params }) {
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
            nowMs: yield* Clock.currentTimeMillis,
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
    .handle(
      "guardianDelete",
      Effect.fn("handlers-key-wraps.guardianDelete")(function* ({ params }) {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* KeyWrapRepo;
        return yield* noContentOrNotFound(
          yield* repo.guardianDelete(
            principal.userId,
            params.groupId,
            yield* Clock.currentTimeMillis,
            auditActorOf(principal),
          ),
        );
      }),
    )
    .handle(
      "wards",
      Effect.fn("handlers-key-wraps.wards")(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* KeyWrapRepo;
        const shares = yield* repo.sharesOfGuardian(principal.userId);
        const seen = new Set<string>();
        return {
          wards: shares
            .filter((s) => {
              const key = `${s.groupId}:${s.shareIndex}`;
              if (seen.has(key)) {
                return false;
              }
              seen.add(key);
              return true;
            })
            .map((s) => ({
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
    .handle(
      "myShare",
      Effect.fn("handlers-key-wraps.myShare")(function* ({ params }) {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* KeyWrapRepo;
        const shares = yield* repo.sharesOfGuardian(principal.userId);
        const deviceRows = shares.filter((s) => s.groupId === params.groupId);
        const share = deviceRows[0];
        if (share === undefined) {
          return yield* Effect.fail(new KeyWrapNotFoundError());
        }
        yield* rateLimited(
          "approval",
          yield* repo.consumeWindow({
            userId: principal.userId,
            kind: "approval",
            limit: APPROVAL_LIMIT,
            nowMs: yield* Clock.currentTimeMillis,
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
          deviceShares: deviceRows.map((row) => ({
            guardianKeyFingerprintHex: row.guardianKeyFingerprintHex,
            guardianEncPubHex: row.guardianEncPubHex,
            encHex: row.encHex,
            ciphertextHex: row.ciphertextHex,
          })),
        };
      }),
    )
    .handle(
      "handoffCreate",
      Effect.fn("handlers-key-wraps.handoffCreate")(function* ({ payload }) {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* KeyWrapRepo;
        const nowMs = yield* Clock.currentTimeMillis;
        yield* repo.handoffSweep(nowMs);
        yield* rateLimited(
          "handoff-request",
          yield* repo.consumeWindow({
            userId: principal.userId,
            kind: "handoff-request",
            limit: HANDOFF_REQUEST_LIMIT,
            nowMs,
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
    .handle(
      "handoffLookup",
      Effect.fn("handlers-key-wraps.handoffLookup")(function* ({ params }) {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* KeyWrapRepo;
        const { request, roles } = yield* visibleRequest(
          repo,
          params.requestId,
          principal.userId,
          yield* Clock.currentTimeMillis,
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
    .handle(
      "handoffApprove",
      Effect.fn("handlers-key-wraps.handoffApprove")(function* ({ params, payload }) {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* KeyWrapRepo;
        const nowMs = yield* Clock.currentTimeMillis;
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
    .handle(
      "handoffApprovals",
      Effect.fn("handlers-key-wraps.handoffApprovals")(function* ({ params }) {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const repo = yield* KeyWrapRepo;
        const nowMs = yield* Clock.currentTimeMillis;
        const request = yield* repo.handoffFind(params.requestId, nowMs);
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
            createdAtMs: a.createdAtMs,
          })),
        };
      }),
    )
    .handle(
      "handoffCancel",
      Effect.fn("handlers-key-wraps.handoffCancel")(function* ({ params }) {
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
