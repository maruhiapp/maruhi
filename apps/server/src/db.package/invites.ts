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

export const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

const INVITE_ISSUE_WINDOW_MS = 60 * 60 * 1000;
export const INVITE_ISSUE_WINDOW_LIMIT = 30;

export const MAX_PENDING_INVITES_PER_PROJECT = 100;

interface InviteCreateInput {
  readonly id: string;
  readonly projectId: ProjectId;
  readonly role: InviteRole;
  readonly scope: InviteScope;
  readonly inviterUserId: UserId;
  readonly issuance: InviteIssuance;
}

interface InviteRepoShape {
  readonly create: (
    input: InviteCreateInput,
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<InviteIssueDecision>;
  readonly findByLinkPub: (linkPubHex: string) => Effect.Effect<InvitationRecord | null>;
  readonly findById: (projectId: ProjectId, id: string) => Effect.Effect<InvitationRecord | null>;
  readonly listForProject: (projectId: ProjectId) => Effect.Effect<readonly InvitationRecord[]>;
  readonly acceptCas: (
    input: InviteAcceptInput,
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<boolean>;
  readonly revokeCas: (
    projectId: ProjectId,
    id: string,
    payload: { readonly role: InviteRole },
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<boolean>;
  readonly completeAccepted: (target: InviteCompletionTarget) => Effect.Effect<void>;
}

export class InviteRepo extends Context.Service<InviteRepo, InviteRepoShape>()("InviteRepo") {}

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

function issuanceOf(row: InvitationRow): InvitationRecord["issuance"] {
  return {
    linkPubHex: row.linkPub,
    headHashHex: row.headHash,
    headSeq: row.headSeq,
    issueSignatureHex: row.issueSignature,
  };
}

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

function storedScopeIdsOf(scopeEnvironments: string): readonly string[] | null {
  try {
    const parsed: unknown = JSON.parse(scopeEnvironments);
    return Array.isArray(parsed) &&
      parsed.every((id) => typeof id === "string" && isEnvironmentId(id))
      ? parsed.map((id) => String(id))
      : null;
  } catch {
    return null;
  }
}

function sameEnvironmentSet(a: readonly string[], b: readonly string[]): boolean {
  const aSet = new Set(a);
  return aSet.size === new Set(b).size && b.every((id) => aSet.has(id));
}

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

function inviteConflictFieldOf(constraint: string | null): "id" | "linkPub" | null {
  if (constraint === "invitations.link_pub") {
    return "linkPub";
  }
  return constraint === "invitations.id" ? "id" : null;
}

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
          ...guardedAuditSelectColumns(input),
          projectId: invitations.projectId,
        })
        .from(invitations)
        .where(and(eq(invitations.id, input.inviteId), sql`changes() = 1`)),
    );
  return {
    create: (input, nowMs, actor) =>
      tryD1(async () => {
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
        const candidates = await db
          .select({ id: invitations.id, scopeEnvironments: invitations.scopeEnvironments })
          .from(invitations)
          .where(
            and(
              eq(invitations.projectId, target.projectId),
              eq(invitations.inviteeUserId, target.inviteeUserId),
              eq(invitations.status, "accepted"),
              eq(invitations.inviteeEncPub, target.inviteeEncPubHex),
              eq(invitations.inviteeSigPub, target.inviteeSigPubHex),
              eq(invitations.role, target.role),
              eq(invitations.scopeKind, target.scopeKind),
            ),
          );
        const matchingIds = candidates.flatMap((row) => {
          const stored = storedScopeIdsOf(row.scopeEnvironments);
          return stored !== null && sameEnvironmentSet(stored, target.scopeEnvironmentIds)
            ? [row.id]
            : [];
        });
        if (matchingIds.length === 0) {
          return;
        }
        await db
          .update(invitations)
          .set({ status: "completed" })
          .where(and(inArray(invitations.id, matchingIds), eq(invitations.status, "accepted")));
      }).pipe(Effect.orDie),
  };
}
