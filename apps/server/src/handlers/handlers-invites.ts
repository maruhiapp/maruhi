// Handlers for the invite API (AUTH_SPEC §15 — 2026-09-13 IV revision).
//
// Authorization flow:
//   - Issue / list / revoke (under a project): token scope admin (out
//     of scope 404 — §11-2) → DO memberRoleFor (non-member 404 /
//     retrieves the chain role) → admin-level check (below → 403).
//     Issuing a role=admin invite is owner-only (§15-2)
//   - Accept: authenticated principal + key-material condition (same
//     level as §13-2 — B1a ruling). Holding the link key (= being able
//     to produce the link signature) is the capability to the target
//     invite (§15-1)
//
// Issue: stores the client-assigned id and the issue document (link
// public key, verified head, issue signature). The server does not
// verify the issue signature (the verifiers are the inviter and the
// acceptor — no duplicate source of truth). The response is the expiry
// only — the server holds and returns none of the invite's secrets.
//
// Accept check order (a ruling — pinned per reason code by tests):
// Schema 400 → auth 401 → CSRF / key-material condition 403 → unknown
// link_pub 404 → unusable 410 → link signature 422 (which=link)
// → accept signature 422
// (which=accept) → CAS (a loss re-reads to 410).
//
// The link key's secret never passes through the server (only the
// public key and signatures are on the wire).

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
import { requireProjectChainAdmin } from "../data/data-http.ts";
import { INVITE_TTL_MS, InviteRepo } from "../db.package/index.ts";
import type { InvitationRecord, InviteIssuance } from "../invite-domain.ts";

/**
 * Derives the unusability reason (§15-1: expiry is derived from
 * expires_at). The check order is fixed as state → expiry
 * (revoked-and-expired is revoked — pinned by tests). Returns null
 * when pending and within expiry (usable).
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

/** Maps one list row onto the wire form (InvitationSummarySchema). */
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

/**
 * Computes the acceptor key FP (AUDIT_SPEC §3.2: copied into the
 * invite.accepted payload). The key's format (32-byte hex) is already
 * Schema-validated — a failure here is a bug-detection line and may be
 * a defect.
 */
const fingerprintOf = Effect.fn("handlers-invites.fingerprintOf")(function* (
  encPubHex: string,
  sigPubHex: string,
): Effect.fn.Return<KeyFingerprintHex> {
  const encPub = decodeHex(encPubHex);
  const sigPub = decodeHex(sigPubHex);
  if (encPub === null || sigPub === null) {
    return yield* Effect.die(new Error("schema-validated key hex failed to decode"));
  }
  // A wrapped crypto failure here stays a defect, like the throw the
  // pre-bridge code raised on a failed fingerprint computation
  return yield* userKeyFingerprintHex(encPub, sigPub).pipe(Effect.orDie);
});

/**
 * Verifies both accept signatures (CRYPTO_SPEC §6.5 v2). The
 * signed_bytes' project_id / link_pub are reconstructed from the
 * stored row and invitee_user_id from the caller (not built from
 * wire-declared values — §15-2). Order: link signature → accept
 * signature (the fixed check order).
 */
const verifyAcceptanceSignatures = Effect.fn("handlers-invites.verifyAcceptanceSignatures")(
  function* (input: {
    readonly record: InvitationRecord;
    readonly issuance: InviteIssuance;
    readonly inviteeUserId: string;
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
        // §15-2: issuing a role = admin invite is owner-only (same level as the add_member permission table)
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
            // scope is format-checked only (Schema) — existence and containment are the agreed rules at add_member acceptance
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
            // The response carries no secret (§15-1). The id is already client-assigned
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
        // B1a ruling: acceptance is a key-declaration-class operation
        // (same-level token condition as §13-2)
        yield* ensureKeyMaterialAccess(principal);
        const invites = yield* InviteRepo;
        // Holding the link key is the capability (§15-1). Resolve by public key
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
        // Single-use CAS (pending → accepted — §15-1). invite.accepted
        // is recorded by the repository in the same batch (AUDIT_SPEC
        // §3.2 / §5.2)
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
          // A CAS loss = a concurrent transition (first-come acceptance
          // or revocation) or expiry reached. The reason is derived by
          // re-reading. Since a pending, unexpired row cannot lose (the
          // CAS condition is equivalent), goneReasonOf returning null
          // is an invariant violation = defect
          const current = yield* invites.findById(record.projectId, record.id);
          const reason = current === null ? null : goneReasonOf(current, nowMs);
          if (reason === null) {
            return yield* Effect.die(new Error("invite accept CAS lost without a gone reason"));
          }
          return yield* Effect.fail(new InviteGoneError({ reason }));
        }
        // Minimal response (§15-1: builds no surface that would make
        // server declarations trusted — inviter info and the anchor are
        // carried by the link fragment)
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
        // Revocation works on pending | accepted (cleaning up expired
        // pending rows also allowed — B1a ruling). completed / revoked
        // → 410. invite.revoked is recorded by the repository in the
        // same batch (AUDIT_SPEC §3.2)
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
