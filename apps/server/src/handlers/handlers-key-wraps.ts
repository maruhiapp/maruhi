// Handlers for the master-key wrap ledger API (AUTH_SPEC §13-6–13-10 —
// KL3; the server side of CRYPTO_SPEC §8's classes S / G / H).
//
// Authorization (§13-7):
//   - `status`: every authenticated principal (sessions allowed — §5's
//     allowed enumeration). Carries no wraps, segments, or secret
//     parameters
//   - Everything else: the key-material-class token condition (`*` ×
//     admin — ensureKeyMaterialAccess. A session principal gets a 403
//     earlier from AuthMiddleware's declaration layer)
//   - Handoff query / approval: a request is visible only when the
//     caller is the ward themselves or one of the ward's guardians.
//     Anything else — unknown or expired — is a uniform 404 (same
//     discipline as §11-2's existence hiding)
//
// The server does not interpret the contents of wraps or segments
// (storage and distribution of opaque ciphertext only). It also does
// not verify key correctness (whether a guardian's enc public key
// matches the chain-derived key) — the source of truth is the ward
// client's confirmation (CRYPTO_SPEC §8.3), and no duplicate source of
// truth is created. E.pub never appears on the wire (the code is
// carried by humans — §8.4).

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

/** Maps a window refusal onto a typed 429. */
function rateLimited(
  // Only the ledger's 3 windows (the device-add-request window
  // `device-request` is mapped onto its own typed 429 by the devices
  // group — handlers-devices.ts)
  window: Exclude<KeyWrapWindowKind, "device-request">,
  decision: KeyWrapWindowDecision,
): Effect.Effect<void, KeyWrapRateLimitedError> {
  return decision.allowed
    ? Effect.void
    : Effect.fail(
        new KeyWrapRateLimitedError({ window, retryAfterSeconds: decision.retryAfterSeconds }),
      );
}

/** The public parameters of a passkey row (§13-9 — the server returns the JSON it wrote verbatim). */
interface PasskeyParams {
  readonly credentialIdHex: string;
  readonly prfSaltHex: string;
  readonly rpId: "localhost";
  readonly label?: string;
}

const PasskeyParamsSchema = Schema.Struct({
  credentialIdHex: Schema.String,
  prfSaltHex: Schema.String,
  // A stored label of an unexpected shape is filtered out below (not
  // a decode failure — the same "drop a non-string label" as before)
  label: Schema.optional(Schema.Unknown),
});

const decodePasskeyParams = Schema.decodeUnknownOption(Schema.fromJsonString(PasskeyParamsSchema));

function parsePasskeyParams(json: string): PasskeyParams {
  // The only writer is this file's passkeyRegister (JSON-ifying
  // Schema-validated values). An undecodable row is an implementation
  // bug / DB corruption — do not silently redistribute it in another
  // shape
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

/**
 * Structural check of a segment set (§13-7 / §13-8 — device rows.
 * 2026-09-19 DK / design record §8 K3-10):
 * **logical segments** = distinct share_index values cover 1..n
 * exactly once each; the same share_index means the same guardian; a
 * guardian does not repeat across logical segments; the ward itself is
 * not included; `all` requires at least 2 people. Device rows are a
 * shape where multiple rows with different device-key FPs line up
 * under the same (share_index, guardian); a duplicated
 * (share_index, FP) or more than the per-guardian device-row count
 * (16 — §12-8) is `duplicate-guardian` / `share-count`.
 */
interface LogicalShareIndex {
  readonly guardianOfIndex: ReadonlyMap<number, string>;
  readonly devicesOfIndex: ReadonlyMap<number, ReadonlySet<string>>;
}

/**
 * Folds device rows into logical segments (per share_index). Two
 * guardians under the same share_index, or two rows of the same
 * (share_index, FP), is `duplicate-guardian`.
 */
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

/**
 * The roles a caller may take for a request's query / approval
 * (§13-7 — 2026-09-19 DK K4): the ward themselves may query the
 * request but holds no approval role (empty — the old device path was
 * removed; recovery of the spare key is guardians' approval only); a
 * ward's guardian = their own segment. Anything else is null (uniform
 * 404).
 */
function rolesFor(
  repo: KeyWrapRepoShape,
  request: HandoffRequestRecord,
  principalUserId: UserId,
): Effect.Effect<readonly HandoffRole[] | null> {
  if (request.userId === principalUserId) {
    return Effect.succeed([] as const);
  }
  return repo.sharesOfGuardian(principalUserId, request.userId).pipe(
    Effect.map((shares) =>
      shares.length === 0
        ? null
        : // One role per logical segment (group × share_index) —
          // device rows are folded (DK)
          logicalShareRoles(shares),
    ),
  );
}

type HandoffRole = {
  readonly groupId: string;
  readonly mode: "any" | "all";
  readonly shareIndex: number;
};

/** Column of device rows → per-logical-segment roles (the same (group, share_index) appears once). */
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

/**
 * Consistency between roles and the approval payload (§13-7): a
 * guardian may approve only their own (group, share_index). Matching
 * is done from the stored rows (roles); authorization never consults
 * the payload's declared values. Since the ward's own role set is
 * empty, they cannot approve their own request (removal of the old
 * device path — DK K4).
 */
function approvalPermitted(
  roles: readonly HandoffRole[],
  payload: { readonly source: string; readonly shareIndex: number },
): boolean {
  return roles.some(
    (role) => role.groupId === payload.source && role.shareIndex === payload.shareIndex,
  );
}

/** The shared response of deletion endpoints: 204 when removed, 404 when the target is absent. */
function noContentOrNotFound(deleted: boolean) {
  return deleted
    ? Effect.succeed(HttpServerResponse.empty({ status: 204 }))
    : Effect.fail(new KeyWrapNotFoundError());
}

/** Resolves a request visible only to the ward themselves or a ward's guardian (anything else is a uniform 404). */
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
              // Public parameters (§13-7, 2026-09-13 revision):
              // recovery needs the salt before the ceremony
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
        // wrap_id is client-assigned (the AAD binds it — CRYPTO_SPEC §8.1)
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
        // A not-registered 404 does not consume the window (§13-8)
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
        // group_id is client-assigned (the AAD / segment info binds it — CRYPTO_SPEC §8.3)
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
        // The list is one row per logical segment (group) — device
        // rows are folded (2026-09-19 DK)
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
        // The caller's own device rows (ascending FP — repo orders
        // them). Every row is a deviceShares entry (design record §8
        // K3-10). The group's attributes (ward, mode, shareIndex) come
        // from the first row
        const deviceRows = shares.filter((s) => s.groupId === params.groupId);
        const share = deviceRows[0];
        if (share === undefined) {
          return yield* Effect.fail(new KeyWrapNotFoundError());
        }
        // Segment fetches are counted in the approval window (§13-8)
        // — a watch-list event
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
        // Opportunistic deletion (requests past expiry + grace)
        yield* repo.handoffSweep(nowMs);
        yield* rateLimited(
          "handoff-request",
          yield* repo.consumeWindow({
            userId: principal.userId,
            kind: "handoff-request",
            limit: HANDOFF_REQUEST_LIMIT,
            nowMs,
            // The request's audit (auth.key_handoff_requested) is
            // recorded in the same batch as the row insert
            // (handoffCreate) — a 409 (existing id) is not recorded as
            // a request
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
            // The approval's own audit is recorded in the same batch
            // as the insert (handoffApprove). The window consumption
            // carries no audit (the same approval is not recorded
            // twice)
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
        // Fetching approvals is ward-only (guardians get the uniform
        // 404)
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
