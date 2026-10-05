// Repository of the CLI login flow rows (AUTH_SPEC §4-1 (4)–(5)).

import type { TokenScope } from "@maruhi/core";
import { parseTokenScopes } from "@maruhi/core";
import { and, eq, gt, lte, sql } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Effect } from "effect";

import { guardedAuditSelectColumns } from "./audit.ts";
import { tryD1 } from "./errors.ts";
import { cliLoginFlows, userAuditEvents } from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

// D1 access goes through the shared tryD1 adapter (errors.ts —
// ADR-0006). Every method pipes `Effect.orDie` at its boundary: the
// public repository types keep an empty error channel because the
// handlers turning D1FailureError into typed errors belong to other
// lanes. An unexpected D1 failure stays a defect = a 500, as before

// ---------------------------------------------------------------------------
// CliFlowRepo (AUTH_SPEC §4-1 (4)–(5). The CLI login flow rows)
// ---------------------------------------------------------------------------

/**
 * The cap on concurrent unconsumed flow rows across the whole
 * deployment (the AUTH_SPEC §4-1 (4) (iii) drafted value). Reaching it
 * requires the cap's worth of simultaneous "existing account × OAuth
 * completion" runs, so it cannot be held cheaply. Recovers naturally
 * with the 15-minute TTL. Adjustable as a self-host acceptance policy.
 */
export const MAX_CONCURRENT_CLI_FLOWS = 1000;

/**
 * The headroom for keeping a row past its expiry (the AUTH_SPEC §4-1
 * (5) drafted value +5 minutes). Deleting a consumed / denied row
 * before the flowToken's expiry would let a poll misread "no row =
 * pending" and the CLI would wait forever on a completed flow.
 * Opportunistic deletion targets only rows past this headroom.
 */
const CLI_FLOW_DELETE_GRACE_MS = 5 * 60 * 1000;

/** The state of a flow row (the CAS vocabulary of §4-1 (4)–(5)). */
type CliFlowStatus = "awaiting" | "approved" | "denied" | "consumed";

/** The explicit operation on the approval page (§4-1 (4) (iv) — the two choices: approve / deny). */
type CliFlowDecision = "approved" | "denied";

interface NewCliLoginFlow {
  readonly flowId: string;
  readonly userId: string;
  readonly tokenName: string;
  readonly scopes: readonly TokenScope[];
  readonly expiresInDays: number;
  readonly userCode: string;
  /** The SHA-256 (hex) of the approval ticket (a 256-bit random). The raw value lives only on the page. */
  readonly ticketHash: string;
  readonly expiresAtMs: number;
}

/** The shape the poll's row lookup (§4-1 (5)) sees. ticket_hash is excluded (the comparison happens inside the CAS). */
interface CliLoginFlowRecord {
  readonly flowId: string;
  readonly userId: string;
  readonly status: CliFlowStatus;
  readonly tokenName: string;
  readonly scopes: readonly TokenScope[];
  readonly expiresInDays: number;
  readonly userCode: string;
  readonly expiresAtMs: number;
}

/**
 * The outcome of create-or-match (§4-1 (4) (iii)). created / matched
 * proceed to rendering the approval page. rejected is the uniform
 * error page (another user_id, expired, or a terminal state — the
 * reason is not differentiated); capacity is the cap reached (the same
 * uniform error page + the input of an operational alert).
 */
type CliFlowAdmission = "created" | "matched" | "rejected" | "capacity";

interface CliFlowRepoShape {
  /**
   * The creation CAS of a flow row (create-or-match — §4-1 (4) (iii)).
   * An opportunistic delete of rows past expiry + headroom is bundled
   * at the batch's head, and creation is done by a conditional INSERT
   * on "no row with the same flowId × the unconsumed total under the
   * cap". When the row already exists, only a re-arrival with the same
   * user_id × awaiting × within validity succeeds by replacing the
   * ticket (idempotent — matched). A different user_id is rejected
   * without rotating the ticket (closing both the takeover and the
   * ticket-invalidation attack paths).
   */
  readonly createOrMatch: (flow: NewCliLoginFlow, nowMs: number) => Effect.Effect<CliFlowAdmission>;
  /**
   * The approve / deny CAS (awaiting → approved | denied — §4-1 (4)
   * (iv)). The credential is the approval ticket (the latest one);
   * unknown, expired, and used all uniformly return false. An approval
   * (user_id settled) records `auth.login_succeeded` (authMethod
   * cli_handoff — §4-2) in the same batch under the changes() guard.
   */
  readonly decideCas: (
    flowId: string,
    ticketHash: string,
    decision: CliFlowDecision,
    nowMs: number,
  ) => Effect.Effect<boolean>;
  /** The poll's row lookup (§4-1 (5)). No row = null (the caller derives pending). */
  readonly findById: (flowId: string) => Effect.Effect<CliLoginFlowRecord | null>;
  /**
   * The single-issuance gate (the approved → consumed CAS — §4-1 (5)).
   * Only the winner (true) issues a PAT. An issuance failure after the
   * CAS succeeded ends consumed as-is (fail-closed — the caller does
   * not roll back).
   */
  readonly consumeCas: (flowId: string) => Effect.Effect<boolean>;
}

export class CliFlowRepo extends Context.Service<CliFlowRepo, CliFlowRepoShape>()("CliFlowRepo") {}

export function makeCliFlowRepo(db: Db): CliFlowRepoShape {
  return {
    createOrMatch: (flow, nowMs) =>
      tryD1(async () => {
        // The cap is counted on unconsumed rows (anything but consumed)
        // (§4-1 (4) (iii)'s "concurrent unconsumed rows"). The judgment
        // and the insert are the same INSERT…SELECT (same shape as the
        // invites admission — a concurrent creation never observes the
        // same under-limit and exceeds the cap)
        const capAvailable = sql<boolean>`(
          select count(*) from ${cliLoginFlows}
          where ${cliLoginFlows.status} != 'consumed'
        ) < ${MAX_CONCURRENT_CLI_FLOWS}`;
        const rowAbsent = sql<boolean>`not exists (
          select 1 from ${cliLoginFlows} where ${cliLoginFlows.id} = ${flow.flowId}
        )`;
        const results = await db.batch([
          // The opportunistic delete (§4-1 (4) (iii)): only rows past
          // expiry + headroom. consumed / denied rows are also kept
          // within the headroom (blocking a poll's "no row = pending"
          // misread)
          db
            .delete(cliLoginFlows)
            .where(lte(cliLoginFlows.expiresAt, nowMs - CLI_FLOW_DELETE_GRACE_MS)),
          db
            .insert(cliLoginFlows)
            .select(
              db
                .select({
                  id: sql<string>`${flow.flowId}`.as("id"),
                  userId: sql<string>`${flow.userId}`.as("user_id"),
                  status: sql<string>`'awaiting'`.as("status"),
                  tokenName: sql<string>`${flow.tokenName}`.as("token_name"),
                  scopes: sql<string>`${JSON.stringify(flow.scopes)}`.as("scopes"),
                  expiresInDays: sql<number>`${flow.expiresInDays}`.as("expires_in_days"),
                  userCode: sql<string>`${flow.userCode}`.as("user_code"),
                  ticketHash: sql<string>`${flow.ticketHash}`.as("ticket_hash"),
                  expiresAt: sql<number>`${flow.expiresAtMs}`.as("expires_at"),
                  createdAt: sql<number>`${nowMs}`.as("created_at"),
                })
                .from(sql`(select 1)`)
                .where(and(capAvailable, rowAbsent)),
            )
            .returning({ id: cliLoginFlows.id }),
        ]);
        if (results[1].length === 1) {
          return "created";
        }
        // Either the row exists (match / conflict) or the cap was hit.
        // Only a re-arrival with the same user_id × awaiting × within
        // validity succeeds by replacing the ticket (the old ticket is
        // revoked by the replacement — at any time exactly one latest
        // ticket is valid). A different user_id never matches this
        // UPDATE = the ticket is not rotated (§4-1 (4) (iii))
        const matched = await db
          .update(cliLoginFlows)
          .set({ ticketHash: flow.ticketHash })
          .where(
            and(
              eq(cliLoginFlows.id, flow.flowId),
              eq(cliLoginFlows.userId, flow.userId),
              eq(cliLoginFlows.status, "awaiting"),
              gt(cliLoginFlows.expiresAt, nowMs),
            ),
          )
          .returning({ id: cliLoginFlows.id });
        if (matched.length === 1) {
          return "matched";
        }
        const existing = await db
          .select({ id: cliLoginFlows.id })
          .from(cliLoginFlows)
          .where(eq(cliLoginFlows.id, flow.flowId))
          .get();
        // No row = what dropped the conditional INSERT was the cap
        // (capacity). A row = another user_id / expired / a terminal
        // state (uniformly rejected — never differentiated)
        return existing === undefined ? "capacity" : "rejected";
      }).pipe(Effect.orDie),
    decideCas: (flowId, ticketHash, decision, nowMs) =>
      tryD1(async () => {
        const cas = db
          .update(cliLoginFlows)
          .set({ status: decision })
          .where(
            and(
              eq(cliLoginFlows.id, flowId),
              eq(cliLoginFlows.status, "awaiting"),
              eq(cliLoginFlows.ticketHash, ticketHash),
              gt(cliLoginFlows.expiresAt, nowMs),
            ),
          )
          .returning({ id: cliLoginFlows.id });
        if (decision !== "approved") {
          // A denial carries no audit event (§4-2 — only an approval =
          // login_succeeded. The failure family follows login_failed's
          // fixed-window discipline, and an explicit denial is neither)
          return (await cas).length === 1;
        }
        // An approval = auth.login_succeeded (authMethod cli_handoff —
        // §4-2). The actor's user_id is copied from the row (the
        // changes() guard — same shape as the invites CAS)
        const results = await db.batch([
          cas,
          db.insert(userAuditEvents).select(
            db
              .select({
                ...guardedAuditSelectColumns({
                  event: "auth.login_succeeded",
                  actor: { authMethod: "cli_handoff" },
                  nowMs,
                  payload: { flowId },
                }),
                actorUserId: cliLoginFlows.userId,
              })
              .from(cliLoginFlows)
              .where(and(eq(cliLoginFlows.id, flowId), sql`changes() = 1`)),
          ),
        ]);
        return results[0].length === 1;
      }).pipe(Effect.orDie),
    findById: (flowId) =>
      tryD1(async () => {
        const row = await db
          .select({
            id: cliLoginFlows.id,
            userId: cliLoginFlows.userId,
            status: cliLoginFlows.status,
            tokenName: cliLoginFlows.tokenName,
            scopes: cliLoginFlows.scopes,
            expiresInDays: cliLoginFlows.expiresInDays,
            userCode: cliLoginFlows.userCode,
            expiresAt: cliLoginFlows.expiresAt,
          })
          .from(cliLoginFlows)
          .where(eq(cliLoginFlows.id, flowId))
          .get();
        if (row === undefined) {
          return null;
        }
        const scopes = parseTokenScopes(row.scopes);
        if (scopes === null) {
          // A column only our own write path can produce being broken =
          // an implementation bug / DB corruption
          throw new Error("stored CLI flow scopes are not a valid scope array");
        }
        return {
          flowId: row.id,
          userId: row.userId,
          status: row.status as CliFlowStatus,
          tokenName: row.tokenName,
          scopes,
          expiresInDays: row.expiresInDays,
          userCode: row.userCode,
          expiresAtMs: row.expiresAt,
        };
      }).pipe(Effect.orDie),
    consumeCas: (flowId) =>
      tryD1(async () => {
        const rows = await db
          .update(cliLoginFlows)
          .set({ status: "consumed" })
          .where(and(eq(cliLoginFlows.id, flowId), eq(cliLoginFlows.status, "approved")))
          .returning({ id: cliLoginFlows.id });
        return rows.length === 1;
      }).pipe(Effect.orDie),
  };
}
