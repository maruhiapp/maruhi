import type { TokenScope, UserId } from "@maruhi/core";
import { parseTokenScopes } from "@maruhi/core";
import { and, eq, gt, lte, sql } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Effect } from "effect";

import { guardedAuditSelectColumns } from "./audit.ts";
import { tryD1 } from "./errors.ts";
import { cliLoginFlows, userAuditEvents } from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

export const MAX_CONCURRENT_CLI_FLOWS = 1000;

const CLI_FLOW_DELETE_GRACE_MS = 5 * 60 * 1000;

type CliFlowStatus = "awaiting" | "approved" | "denied" | "consumed";

type CliFlowDecision = "approved" | "denied";

interface NewCliLoginFlow {
  readonly flowId: string;
  readonly userId: UserId;
  readonly tokenName: string;
  readonly scopes: readonly TokenScope[];
  readonly expiresInDays: number;
  readonly userCode: string;
  readonly ticketHash: string;
  readonly expiresAtMs: number;
}

interface CliLoginFlowRecord {
  readonly flowId: string;
  readonly userId: UserId;
  readonly status: CliFlowStatus;
  readonly tokenName: string;
  readonly scopes: readonly TokenScope[];
  readonly expiresInDays: number;
  readonly userCode: string;
  readonly expiresAtMs: number;
}

type CliFlowAdmission = "created" | "matched" | "rejected" | "capacity";

interface CliFlowRepoShape {
  readonly createOrMatch: (flow: NewCliLoginFlow, nowMs: number) => Effect.Effect<CliFlowAdmission>;
  readonly decideCas: (
    flowId: string,
    ticketHash: string,
    decision: CliFlowDecision,
    nowMs: number,
  ) => Effect.Effect<boolean>;
  readonly findById: (flowId: string) => Effect.Effect<CliLoginFlowRecord | null>;
  readonly consumeCas: (flowId: string) => Effect.Effect<boolean>;
}

export class CliFlowRepo extends Context.Service<CliFlowRepo, CliFlowRepoShape>()("CliFlowRepo") {}

export function makeCliFlowRepo(db: Db): CliFlowRepoShape {
  return {
    createOrMatch: (flow, nowMs) =>
      tryD1(async () => {
        const capAvailable = sql<boolean>`(
          select count(*) from ${cliLoginFlows}
          where ${cliLoginFlows.status} != 'consumed'
        ) < ${MAX_CONCURRENT_CLI_FLOWS}`;
        const rowAbsent = sql<boolean>`not exists (
          select 1 from ${cliLoginFlows} where ${cliLoginFlows.id} = ${flow.flowId}
        )`;
        const results = await db.batch([
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
          return (await cas).length === 1;
        }
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
