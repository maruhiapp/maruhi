// Repository of project invitations (AUTH_SPEC §15 — invite records
// and invite.* audit appended in the same batch).

import type { EnvironmentId, ProjectId, UserId, UserOrgAuditEventPayload } from "@maruhi/core";
import { decodeEnvironmentId, isEnvironmentId } from "@maruhi/core";
import { and, count, eq, gt, gte, inArray, min, or, sql } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Effect } from "effect";

import type {
  InvitationRecord,
  InviteAcceptInput,
  InviteCompletionTarget,
  InviteIssuance,
  InviteIssueDecision,
  InviteRole,
  InviteScope,
  InviteStatus,
} from "../invite-domain.ts";
import { type D1AuditActor, guardedAuditSelectColumns, INVITE_AUDIT_EVENTS } from "./audit.ts";
import { D1FailureError, tryD1 } from "./errors.ts";
import { invitations, orgAuditEvents } from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

// D1 access goes through the shared tryD1 adapter (errors.ts —
// ADR-0006). Every method pipes `Effect.orDie` at its boundary: the
// public repository types keep an empty error channel because the
// handlers turning D1FailureError into typed errors belong to other
// lanes. An unexpected D1 failure stays a defect = a 500, as before

// ---------------------------------------------------------------------------
// InviteRepo (AUTH_SPEC §15. Invite records and invite.* audit appended
// in the same batch)
// ---------------------------------------------------------------------------

/** The §15-1 drafted value: an invitation's validity (issuance + 7 days). */
export const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * The §15-2 drafted value: the issuance rate window (30 per hour per
 * project). The implementation shape is a lookback count of "the
 * invitations row count in the last hour" (the same shape as
 * auth.login_failed — audit.ts — with no additional window state).
 * Never exceeding 30 in any one-hour interval = it can never be looser
 * than the spec's fixed window (it lands on the stricter side by the
 * absence of a bucket-boundary reset). retryAfterSeconds is derived
 * from when the oldest in-window issuance leaves the window.
 */
const INVITE_ISSUE_WINDOW_MS = 60 * 60 * 1000;
export const INVITE_ISSUE_WINDOW_LIMIT = 30;

/** The §15-2 drafted value: the pending-invite cap (100 per project; expired ones are not counted). */
export const MAX_PENDING_INVITES_PER_PROJECT = 100;

interface InviteCreateInput {
  readonly id: string;
  readonly projectId: ProjectId;
  readonly role: InviteRole;
  /** The scope to be granted (part of the issuance text — §15-2, 2026-09-14 ES). */
  readonly scope: InviteScope;
  readonly inviterUserId: UserId;
  /** The issuance text (CRYPTO_SPEC §6.5 — the server stores it without verifying). */
  readonly issuance: InviteIssuance;
}

interface InviteRepoShape {
  /**
   * Issuance (§15-2). The acceptance policy's judgment order is pinned
   * to the spec's written order: the pending cap → the rate window
   * (lookback counting — see the note on INVITE_ISSUE_WINDOW_MS). Both
   * counts are re-evaluated inside the same `INSERT … SELECT … WHERE`
   * statement, so even concurrent issuance never exceeds the limits. On
   * acceptance, invite.created (AUDIT_SPEC §3.2) is placed in the same
   * batch as the changes()-guarded INSERT…SELECT and recorded 1:1 with
   * the creation.
   */
  readonly create: (
    input: InviteCreateInput,
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<InviteIssueDecision>;
  /** Resolution by link public key (the acceptance path — holding the link key is the capability). */
  readonly findByLinkPub: (linkPubHex: string) => Effect.Effect<InvitationRecord | null>;
  /** The id resolution under a project (the revocation path). */
  readonly findById: (projectId: ProjectId, id: string) => Effect.Effect<InvitationRecord | null>;
  /** The list (§15-2). The acceptance block included — the input of the inviter client's §6.5 independent verification. */
  readonly listForProject: (projectId: ProjectId) => Effect.Effect<readonly InvitationRecord[]>;
  /**
   * The single-use CAS of acceptance (pending → accepted — §15-1). The
   * conditional UPDATE and the invite.accepted INSERT…SELECT guarded by
   * `changes() = 1` are issued in the same batch (AUDIT_SPEC §5.2's
   * same-transaction principle). D1 documents a batch as sequential,
   * non-parallel, and a single transaction, and by that sequentiality
   * changes() refers to the result of the immediately preceding UPDATE
   * (the digestion order of RETURNING statements is not documented, so
   * this property is also pinned as actual behavior by the CAS-defeat
   * test in invites.test.ts) — on a CAS defeat the audit row stays at
   * 0 rows too. The return value is win/loss only (the caller derives
   * the defeat reason by re-reading).
   */
  readonly acceptCas: (
    input: InviteAcceptInput,
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<boolean>;
  /**
   * The revocation CAS (pending | accepted → revoked). Revoking an
   * expired pending is allowed too (an admin-operation cleanup). On
   * acceptance invite.revoked is recorded in the same batch (the same
   * changes() guard as acceptCas). Has no effect on completed / revoked
   * (the caller derives the 410 by re-reading).
   */
  readonly revokeCas: (
    projectId: ProjectId,
    id: string,
    payload: { readonly role: InviteRole },
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<boolean>;
  /**
   * The accepted → completed reconciliation at add_member acceptance
   * (§15-2. It updates a derived state; the source of truth is the
   * chain. §15-4: the evidence is chain.member_added — no independent
   * event is written). The key-match conditions (both enc / sig)
   * refine "this acceptance was fulfilled by this add_member" — an
   * accepted invite under a different key is kept as-is and stays
   * visible in the list.
   */
  readonly completeAccepted: (target: InviteCompletionTarget) => Effect.Effect<void>;
}

export class InviteRepo extends Context.Service<InviteRepo, InviteRepoShape>()("InviteRepo") {}

/** An invitation row (the shape of the select result — the Drizzle type never leaves this boundary). */
interface InvitationRow {
  readonly id: string;
  readonly projectId: ProjectId;
  readonly role: string;
  readonly scopeKind: string;
  readonly scopeEnvironments: string;
  readonly inviterUserId: UserId;
  readonly status: string;
  readonly expiresAt: number;
  readonly inviteeUserId: UserId | null;
  readonly inviteeEncPub: string | null;
  readonly inviteeSigPub: string | null;
  readonly acceptSignature: string | null;
  readonly linkSignature: string | null;
  readonly acceptedAt: number | null;
  readonly createdAt: number;
  readonly linkPub: string;
  readonly headHash: string;
  readonly headSeq: number;
  readonly issueSignature: string;
}

/** The acceptance block (only when all 6 columns are populated — status at accepted or later). */
function acceptanceOf(row: InvitationRow): InvitationRecord["acceptance"] {
  return row.inviteeUserId !== null &&
    row.inviteeEncPub !== null &&
    row.inviteeSigPub !== null &&
    row.acceptSignature !== null &&
    row.linkSignature !== null &&
    row.acceptedAt !== null
    ? {
        inviteeUserId: row.inviteeUserId,
        inviteeEncPubHex: row.inviteeEncPub,
        inviteeSigPubHex: row.inviteeSigPub,
        acceptSignatureHex: row.acceptSignature,
        linkSignatureHex: row.linkSignature,
        acceptedAtMs: row.acceptedAt,
      }
    : null;
}

/** The issuance text (CRYPTO_SPEC §6.5 — all 4 columns NOT NULL). */
function issuanceOf(row: InvitationRow): InvitationRecord["issuance"] {
  return {
    linkPubHex: row.linkPub,
    headHashHex: row.headHash,
    headSeq: row.headSeq,
    issueSignatureHex: row.issueSignature,
  };
}

/**
 * The scope column (a JSON-array string) → the domain representation.
 * The column holds a JSON.stringify of a value Schema-checked at
 * issuance, but rather than making a broken row unacceptable via a
 * throw, it falls fail-closed to an empty `listed` (= grants no
 * environment)
 */
function scopeOf(row: InvitationRow): InviteScope {
  let ids: readonly EnvironmentId[] = [];
  try {
    const parsed: unknown = JSON.parse(row.scopeEnvironments);
    if (
      Array.isArray(parsed) &&
      parsed.every((id) => typeof id === "string" && isEnvironmentId(id))
    ) {
      ids = parsed.map((id) => decodeEnvironmentId(String(id)));
    }
  } catch {
    ids = [];
  }
  return row.scopeKind === "all" && ids.length === 0
    ? { scopeKind: "all", scopeEnvironmentIds: [] }
    : { scopeKind: "listed", scopeEnvironmentIds: ids };
}

/** Row → the domain representation. */
function toInvitationRecord(row: InvitationRow): InvitationRecord {
  return {
    id: row.id,
    projectId: row.projectId,
    issuance: issuanceOf(row),
    role: row.role as InviteRole,
    scope: scopeOf(row),
    inviterUserId: row.inviterUserId,
    status: row.status as InviteStatus,
    expiresAtMs: row.expiresAt,
    createdAtMs: row.createdAt,
    acceptance: acceptanceOf(row),
  };
}

/**
 * The violated unique-constraint target (carried by
 * D1UniqueConflictError — errors.ts) → the issuance 409 field
 * (`invitations.id` / `inv_link_pub`). Any other constraint is null —
 * the caller re-raises it as D1FailureError (a defect at the boundary,
 * as the re-throw was before; never swallowed).
 */
function inviteConflictFieldOf(constraint: string | null): "id" | "linkPub" | null {
  if (constraint === "invitations.link_pub") {
    return "linkPub";
  }
  return constraint === "invitations.id" ? "id" : null;
}

/** Re-evaluates both the pending and the lookback caps inside the same INSERT statement. */
function conditionalInviteInsert(db: Db, input: InviteCreateInput, nowMs: number) {
  const pendingAvailable = sql<boolean>`(
    select count(*) from ${invitations}
    where ${invitations.projectId} = ${input.projectId}
      and ${invitations.status} = 'pending'
      and ${invitations.expiresAt} > ${nowMs}
  ) < ${MAX_PENDING_INVITES_PER_PROJECT}`;
  const windowAvailable = sql<boolean>`(
    select count(*) from ${invitations}
    where ${invitations.projectId} = ${input.projectId}
      and ${invitations.createdAt} >= ${nowMs - INVITE_ISSUE_WINDOW_MS}
  ) < ${INVITE_ISSUE_WINDOW_LIMIT}`;
  return db
    .insert(invitations)
    .select(
      db
        .select({
          id: sql<string>`${input.id}`.as("id"),
          projectId: sql<ProjectId>`${input.projectId}`.as("project_id"),
          linkPub: sql<string>`${input.issuance.linkPubHex}`.as("link_pub"),
          headHash: sql<string>`${input.issuance.headHashHex}`.as("head_hash"),
          headSeq: sql<number>`${input.issuance.headSeq}`.as("head_seq"),
          issueSignature: sql<string>`${input.issuance.issueSignatureHex}`.as("issue_signature"),
          role: sql<string>`${input.role}`.as("role"),
          scopeKind: sql<string>`${input.scope.scopeKind}`.as("scope_kind"),
          scopeEnvironments: sql<string>`${JSON.stringify(input.scope.scopeEnvironmentIds)}`.as(
            "scope_environments",
          ),
          inviterUserId: sql<UserId>`${input.inviterUserId}`.as("inviter_user_id"),
          status: sql<string>`'pending'`.as("status"),
          expiresAt: sql<number>`${nowMs + INVITE_TTL_MS}`.as("expires_at"),
          createdAt: sql<number>`${nowMs}`.as("created_at"),
        })
        .from(sql`(select 1)`)
        .where(and(pendingAvailable, windowAvailable)),
    )
    .returning({ id: invitations.id });
}

/**
 * Derives in spec order why the conditional INSERT produced 0 rows.
 * For explaining the rejection only; the admission itself is the job of
 * conditionalInviteInsert's single statement.
 */
async function inviteIssueRejection(
  db: Db,
  projectId: ProjectId,
  nowMs: number,
): Promise<Exclude<InviteIssueDecision, { readonly kind: "created" }> | null> {
  const pendingRow = await db
    .select({ n: count() })
    .from(invitations)
    .where(
      and(
        eq(invitations.projectId, projectId),
        eq(invitations.status, "pending"),
        gt(invitations.expiresAt, nowMs),
      ),
    )
    .get();
  if ((pendingRow?.n ?? 0) >= MAX_PENDING_INVITES_PER_PROJECT) {
    return { kind: "pending-limit", limit: MAX_PENDING_INVITES_PER_PROJECT };
  }
  const windowRow = await db
    .select({ n: count(), oldest: min(invitations.createdAt) })
    .from(invitations)
    .where(
      and(
        eq(invitations.projectId, projectId),
        gte(invitations.createdAt, nowMs - INVITE_ISSUE_WINDOW_MS),
      ),
    )
    .get();
  if ((windowRow?.n ?? 0) < INVITE_ISSUE_WINDOW_LIMIT) {
    return null;
  }
  const oldest = windowRow?.oldest ?? nowMs;
  const remainingMs = oldest + INVITE_ISSUE_WINDOW_MS - nowMs;
  return {
    kind: "rate-limited",
    retryAfterSeconds: Math.max(1, Math.ceil(remainingMs / 1000)),
  };
}

export function makeInviteRepo(db: Db): InviteRepoShape {
  const findWhere = async (condition: ReturnType<typeof and>) => {
    const row = await db.select().from(invitations).where(condition).get();
    return row === undefined ? null : toInvitationRecord(row);
  };
  /**
   * The INSERT…SELECT of an invite.* audit row (AUDIT_SPEC §3.2 /
   * §5.2). Inserted only when the immediately preceding conditional
   * UPDATE hit 1 row (the changes() guard). The FROM is the target
   * invitation row itself (project_id is copied from the stored row —
   * never composed from a wire-declared value). org_id is not carried:
   * invite.*'s read axis is chain role admin, not org admin (AUDIT_SPEC
   * §7).
   */
  const guardedAuditInsert = (
    input: Extract<
      UserOrgAuditEventPayload,
      { readonly event: (typeof INVITE_AUDIT_EVENTS)[number] }
    > & {
      readonly inviteId: string;
      readonly actor: D1AuditActor;
      readonly targetUserId: UserId | null;
      readonly nowMs: number;
    },
  ) =>
    db.insert(orgAuditEvents).select(
      db
        .select({
          // The shared columns (audit.ts — the same mapping as
          // recovery's fetch counting) + project_id copied from the
          // target invitation row (never composed from a wire-declared
          // value)
          ...guardedAuditSelectColumns(input),
          projectId: invitations.projectId,
        })
        .from(invitations)
        .where(and(eq(invitations.id, input.inviteId), sql`changes() = 1`)),
    );
  return {
    create: (input, nowMs, actor) =>
      tryD1(async () => {
        // The judgment and the insert are folded into a single
        // INSERT…SELECT. With a separate request's SELECT → INSERT,
        // every concurrent issuer would observe the same under-limit
        // and could exceed the cap by the degree of parallelism. The
        // audit is written under the changes() guard only when the
        // immediately preceding INSERT hit 1 row
        // A duplicate of a client-sequenced id / link_pub is a 409
        // (ahead of the acceptance policy — §15-2's judgment order). A
        // random-derived collision is effectively impossible, but a
        // reused id is never silently let through. It is detected
        // deterministically by a prior SELECT, and a concurrent
        // issuance interposing between the SELECT and the INSERT
        // surfaces as a UNIQUE constraint error = a D1UniqueConflict
        // typed error, mapped to the same 409 by the catchTag below
        const existing = await db
          .select({ id: invitations.id, linkPub: invitations.linkPub })
          .from(invitations)
          .where(
            or(eq(invitations.id, input.id), eq(invitations.linkPub, input.issuance.linkPubHex)),
          )
          .limit(1);
        const found = existing[0];
        if (found !== undefined) {
          return { kind: "conflict", field: found.id === input.id ? "id" : "linkPub" } as const;
        }
        const results = await db.batch([
          conditionalInviteInsert(db, input, nowMs),
          guardedAuditInsert({
            inviteId: input.id,
            event: "invite.created",
            actor,
            targetUserId: null,
            payload: { inviteId: input.id, role: input.role },
            nowMs,
          }),
        ]);
        if (results[0].length === 1) {
          return { kind: "created" } as const;
        }
        const rejection = await inviteIssueRejection(db, input.projectId, nowMs);
        if (rejection !== null) {
          return rejection;
        }
        // A rare race where revoke / expiry progressed between the
        // conditional INSERT and the explaining re-read and admission
        // momentarily became possible again. Falls to a typed
        // rate-limit that a fresh request can safely retry; never
        // falls back to breaking the cap
        return {
          kind: "rate-limited",
          retryAfterSeconds: 1,
        } as const;
      }).pipe(
        Effect.catchTag("D1UniqueConflict", (error) => {
          const field = inviteConflictFieldOf(error.constraint);
          return field === null
            ? Effect.fail(new D1FailureError({ cause: error.cause }))
            : Effect.succeed({ kind: "conflict", field } as const);
        }),
        Effect.orDie,
      ),
    findByLinkPub: (linkPubHex) =>
      tryD1(() => findWhere(eq(invitations.linkPub, linkPubHex))).pipe(Effect.orDie),
    findById: (projectId, id) =>
      tryD1(() =>
        findWhere(and(eq(invitations.id, id), eq(invitations.projectId, projectId))),
      ).pipe(Effect.orDie),
    listForProject: (projectId) =>
      tryD1(async () => {
        const rows = await db
          .select()
          .from(invitations)
          .where(eq(invitations.projectId, projectId))
          .orderBy(invitations.createdAt, invitations.id);
        return rows.map(toInvitationRecord);
      }).pipe(Effect.orDie),
    acceptCas: (input, nowMs, actor) =>
      tryD1(async () => {
        const results = await db.batch([
          db
            .update(invitations)
            .set({
              status: "accepted",
              inviteeUserId: input.inviteeUserId,
              inviteeEncPub: input.inviteeEncPubHex,
              inviteeSigPub: input.inviteeSigPubHex,
              acceptSignature: input.acceptSignatureHex,
              linkSignature: input.linkSignatureHex,
              acceptedAt: nowMs,
            })
            .where(
              and(
                eq(invitations.id, input.inviteId),
                eq(invitations.status, "pending"),
                gt(invitations.expiresAt, nowMs),
              ),
            )
            .returning({ id: invitations.id }),
          guardedAuditInsert({
            inviteId: input.inviteId,
            event: "invite.accepted",
            actor,
            targetUserId: input.inviteeUserId,
            payload: {
              inviteId: input.inviteId,
              inviteeKeyFingerprintHex: input.inviteeKeyFingerprintHex,
            },
            nowMs,
          }),
        ]);
        return results[0].length === 1;
      }).pipe(Effect.orDie),
    revokeCas: (projectId, id, payload, nowMs, actor) =>
      tryD1(async () => {
        const results = await db.batch([
          db
            .update(invitations)
            .set({ status: "revoked" })
            .where(
              and(
                eq(invitations.id, id),
                eq(invitations.projectId, projectId),
                inArray(invitations.status, ["pending", "accepted"]),
              ),
            )
            .returning({ id: invitations.id }),
          guardedAuditInsert({
            inviteId: id,
            event: "invite.revoked",
            actor,
            targetUserId: null,
            payload: { inviteId: id, role: payload.role },
            nowMs,
          }),
        ]);
        return results[0].length === 1;
      }).pipe(Effect.orDie),
    completeAccepted: (target) =>
      tryD1(async () => {
        await db
          .update(invitations)
          .set({ status: "completed" })
          .where(
            and(
              eq(invitations.projectId, target.projectId),
              eq(invitations.inviteeUserId, target.inviteeUserId),
              eq(invitations.status, "accepted"),
              eq(invitations.inviteeEncPub, target.inviteeEncPubHex),
              eq(invitations.inviteeSigPub, target.inviteeSigPubHex),
            ),
          );
      }).pipe(Effect.orDie),
  };
}
