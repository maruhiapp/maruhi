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
import type { UserId } from "@maruhi/core";
import {
  auditActorOf,
  cryptoEffect,
  type KeyFingerprintHex,
  RequestAuth,
  userKeyFingerprintHex,
} from "@maruhi/core";
import {
  decodeHex,
  type InviteAcceptSignatureContext,
  SUITE_ID,
  verifyInviteAcceptSignature,
  verifyInviteLinkSignature,
} from "@maruhi/crypto";
import { Clock, Effect } from "effect";
import { HttpServerResponse } from "effect/http";
import { HttpApiBuilder } from "effect/http-api";

import { ensureKeyMaterialAccess } from "../authz.ts";
import { requireProjectChainAdmin } from "../data.package/index.ts";
import { INVITE_TTL_MS, InviteRepo } from "../db.package/index.ts";
import type { InvitationRecord, InviteIssuance } from "../invite-domain.ts";

function goneReasonOf(
  record: InvitationRecord,
  nowMs: number,
): "accepted" | "completed" | "revoked" | "expired" | null {
  if (record.status !== "pending") {
    return record.status;
  }
  return record.expiresAtMs <= nowMs ? "expired" : null;
}

function toSummary(record: InvitationRecord) {
  return {
    id: record.id,
    projectId: record.projectId,
    role: record.role,
    scopeKind: record.scope.scopeKind,
    scopeEnvironmentIds: record.scope.scopeEnvironmentIds,
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

const fingerprintOf = Effect.fn("handlers-invites.fingerprintOf")(function* (
  encPubHex: string,
  sigPubHex: string,
): Effect.fn.Return<KeyFingerprintHex> {
  const encPub = decodeHex(encPubHex);
  const sigPub = decodeHex(sigPubHex);
  if (encPub === null || sigPub === null) {
    return yield* Effect.die(new Error("schema-validated key hex failed to decode"));
  }
  return yield* userKeyFingerprintHex(encPub, sigPub).pipe(Effect.orDie);
});

const verifyAcceptanceSignatures = Effect.fn("handlers-invites.verifyAcceptanceSignatures")(
  function* (input: {
    readonly record: InvitationRecord;
    readonly issuance: InviteIssuance;
    readonly inviteeUserId: UserId;
    readonly encPubHex: string;
    readonly sigPubHex: string;
    readonly acceptSignatureHex: string;
    readonly linkSignatureHex: string;
  }): Effect.fn.Return<void, InviteSignatureInvalidError> {
    const context: InviteAcceptSignatureContext = {
      suite: SUITE_ID,
      projectId: input.record.projectId,
      linkPubHex: input.issuance.linkPubHex,
      inviteeUserId: input.inviteeUserId,
      inviteeEncPubHex: input.encPubHex,
      inviteeSigPubHex: input.sigPubHex,
    };
    yield* cryptoEffect(() =>
      verifyInviteLinkSignature({ context, linkSignatureHex: input.linkSignatureHex }),
    ).pipe(Effect.mapError(() => new InviteSignatureInvalidError({ which: "link" })));
    yield* cryptoEffect(() =>
      verifyInviteAcceptSignature({ context, signatureHex: input.acceptSignatureHex }),
    ).pipe(Effect.mapError(() => new InviteSignatureInvalidError({ which: "accept" })));
  },
);

export const invitesLive = HttpApiBuilder.group(maruhiApi, "invites", (handlers) =>
  handlers
    .handle(
      "issue",
      Effect.fn("handlers-invites.issue")(function* ({ params, payload, endpoint }) {
        const { principal, role } = yield* requireProjectChainAdmin(params.projectId, endpoint);
        if (payload.role === "admin" && role !== "owner") {
          return yield* Effect.fail(new ForbiddenError({ reason: "insufficient-role" }));
        }
        const nowMs = yield* Clock.currentTimeMillis;
        const invites = yield* InviteRepo;
        const decision = yield* invites.create(
          {
            id: payload.id,
            projectId: params.projectId,
            role: payload.role,
            scope: {
              scopeKind: payload.scopeKind,
              scopeEnvironmentIds: payload.scopeEnvironmentIds,
            },
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
    .handle(
      "accept",
      Effect.fn("handlers-invites.accept")(function* ({ payload }) {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureKeyMaterialAccess(principal);
        const invites = yield* InviteRepo;
        const record = yield* invites.findByLinkPub(payload.linkPubHex);
        if (record === null) {
          return yield* Effect.fail(new InviteNotFoundError());
        }
        const nowMs = yield* Clock.currentTimeMillis;
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
          const current = yield* invites.findById(record.projectId, record.id);
          const reason = current === null ? null : goneReasonOf(current, nowMs);
          if (reason === null) {
            return yield* Effect.die(new Error("invite accept CAS lost without a gone reason"));
          }
          return yield* Effect.fail(new InviteGoneError({ reason }));
        }
        return {
          id: record.id,
          projectId: record.projectId,
          role: record.role,
          scopeKind: record.scope.scopeKind,
          scopeEnvironmentIds: record.scope.scopeEnvironmentIds,
        };
      }),
    )
    .handle(
      "list",
      Effect.fn("handlers-invites.list")(function* ({ params, endpoint }) {
        yield* requireProjectChainAdmin(params.projectId, endpoint);
        const invites = yield* InviteRepo;
        const records = yield* invites.listForProject(params.projectId);
        return { invitations: records.map(toSummary) };
      }),
    )
    .handle(
      "revoke",
      Effect.fn("handlers-invites.revoke")(function* ({ params, endpoint }) {
        const { principal } = yield* requireProjectChainAdmin(params.projectId, endpoint);
        const invites = yield* InviteRepo;
        const record = yield* invites.findById(params.projectId, params.id);
        if (record === null) {
          return yield* Effect.fail(new InviteNotFoundError());
        }
        const nowMs = yield* Clock.currentTimeMillis;
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
