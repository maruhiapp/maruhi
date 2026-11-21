import { MAX_AUDIT_EVENTS_PAGE_LIMIT } from "@maruhi/api-schema";
import { cryptoEffect, scopePermissionFor, type WrappedCryptoError } from "@maruhi/core";
import type { AuditHeadRow, ChainEntry } from "@maruhi/crypto";
import { computeAuditHeadHash, computeAuditRowDigest, SUITE_ID } from "@maruhi/crypto";
import { Data, Effect } from "effect";

import { fetchAuditHead } from "../checkpoint.package/index.ts";
import type { CliServices, ProjectContextBase } from "../context.ts";
import { cryptoErrorKind } from "../crypto-error-kind.ts";
import { countNoun, displayText } from "../display.ts";
import type { CliError } from "../errors.ts";
import { cliError } from "../errors.ts";
import { toCliError } from "../failure.ts";
import { CliIo } from "../io.ts";
import { logNote } from "../notice.ts";
import type { WireAuditEvent } from "./audit-mirror.ts";
import { paginateAuditEvents } from "./audit-verify.ts";

const FETCH_PROGRESS_PAGES = 50;

interface ReconcileViolation {
  readonly category: "row-tampering" | "acceptance-policy";
  readonly detail: string;
}

const ensureEffectiveAdmin = Effect.fn("audit-reconcile.ensureEffectiveAdmin")(function* (
  context: ProjectContextBase,
): Effect.fn.Return<void, CliError> {
  const member = context.verified.state.members.get(context.session.userId);
  const role = member?.role;
  if (role !== "admin" && role !== "owner") {
    return yield* Effect.fail(
      cliError(
        "`maruhi audit reconcile` requires effective admin permission (AUDIT_SPEC §6): your chain role on this project is below admin, so the audit rows needed for the reconciliation (class-2 rows and the seq field) are not visible to you",
      ),
    );
  }
  const me = yield* context.client.auth.me({}).pipe(Effect.mapError(toCliError));
  if (me.tokenScopes !== undefined) {
    const granted = scopePermissionFor(me.tokenScopes, context.projectId);
    if (granted !== "admin") {
      return yield* Effect.fail(
        cliError(
          "`maruhi audit reconcile` requires effective admin permission (AUDIT_SPEC §6): this token's scope for the project is below admin. Re-run with an admin-scoped token",
        ),
      );
    }
  }
});

function reconcileRowProblem(
  row: WireAuditEvent,
  seenIds: ReadonlySet<string>,
  previousSeq: number | null,
): string | null {
  if (row.seq === undefined) {
    return `Audit row ${displayText(row.id)} carries no seq. The reconciliation needs the admin-visible seq field for the gap check (AUDIT_SPEC §7) — the server response is not the admin view this command verified permission for, so it contradicts itself`;
  }
  if (seenIds.has(row.id)) {
    return `Audit-log paging is not advancing (row ${displayText(row.id)} was returned twice) — the server response contradicts itself. Aborting the reconciliation`;
  }
  if (previousSeq !== null && row.seq >= previousSeq) {
    return `Audit rows are not in strictly descending seq order (seq ${row.seq} after ${previousSeq}) — the server response contradicts itself. Aborting the reconciliation`;
  }
  return null;
}

const fetchAllAuditRows = Effect.fn("audit-reconcile.fetchAllAuditRows")(function* (
  context: ProjectContextBase,
): Effect.fn.Return<readonly WireAuditEvent[], CliError, CliIo> {
  const io = yield* CliIo;
  const rows: WireAuditEvent[] = [];
  const seenIds = new Set<string>();
  let previousSeq: number | null = null;
  let pages = 0;
  yield* paginateAuditEvents({
    pageLimit: MAX_AUDIT_EVENTS_PAGE_LIMIT,
    bound: null,
    fetchPage: (before) =>
      Effect.gen(function* () {
        pages += 1;
        if (pages > 1 && (pages - 1) % FETCH_PROGRESS_PAGES === 0) {
          yield* io.log(`Fetched ${countNoun(rows.length, "audit row")} so far…`);
        }
        return yield* context.client.audit
          .events({
            params: { projectId: context.projectId },
            query: {
              limit: MAX_AUDIT_EVENTS_PAGE_LIMIT,
              ...(before === null ? {} : { before }),
            },
          })
          .pipe(
            Effect.mapError(toCliError),
            Effect.map((response) => response.events as readonly WireAuditEvent[]),
          );
      }),
    onRow: (row) => {
      const problem = reconcileRowProblem(row, seenIds, previousSeq);
      if (problem !== null) {
        return Effect.fail(cliError(problem));
      }
      seenIds.add(row.id);
      rows.push(row);
      previousSeq = row.seq ?? null;
      return Effect.void;
    },
  });
  return rows;
});

function orNull<T>(value: T | undefined): T | null {
  return value === undefined ? null : value;
}

function toHeadRow(event: WireAuditEvent, seq: number): AuditHeadRow {
  return {
    seq,
    rowId: event.id,
    serverTs: event.serverTs,
    clientTs: orNull(event.clientTs),
    event: event.event,
    actorType: event.actor.type,
    actorUserId: orNull(event.actor.userId),
    actorKeyFingerprintHex: orNull(event.actor.keyFingerprintHex),
    actorApiTokenId: orNull(event.actor.apiTokenId),
    targetUserId: orNull(event.targetUserId),
    targetKeyFingerprintHex: orNull(event.targetKeyFingerprintHex),
    environmentId: orNull(event.environmentId),
    variableId: orNull(event.variableId),
    epoch: orNull(event.epoch),
    version: orNull(event.version),
    chainSeq: orNull(event.chainSeq),
    payloadText: event.payload === undefined ? null : JSON.stringify(event.payload),
  };
}

interface RecomputedColumn {
  readonly positions: ReadonlyMap<string, number>;
  readonly finalHeadHex: string;
}

class AuditRecomputationError extends Data.TaggedError("AuditRecomputationError")<{
  readonly seq: number;
  readonly message: string;
}> {}

const recomputationError = (seq: number) =>
  Effect.mapError((error: WrappedCryptoError) => {
    const kind = cryptoErrorKind(error);
    return new AuditRecomputationError({
      seq,
      message: `recomputation failed at seq ${seq}: ${kind}`,
    });
  });

const recomputeColumn: (
  rows: readonly AuditHeadRow[],
) => Effect.Effect<RecomputedColumn, CliError> = Effect.fn("audit-reconcile.recomputeColumn")(
  function* (rows: readonly AuditHeadRow[]) {
    const positions = new Map<string, number>();
    let head = "";
    for (const row of rows) {
      const digest = yield* cryptoEffect(() => computeAuditRowDigest(row)).pipe(
        recomputationError(row.seq),
      );
      head = yield* cryptoEffect(() => computeAuditHeadHash(SUITE_ID, head, row.seq, digest)).pipe(
        recomputationError(row.seq),
      );
      if (!positions.has(head)) {
        positions.set(head, row.seq);
      }
    }
    return { positions, finalHeadHex: head };
  },
  Effect.catchTag("AuditRecomputationError", (error) =>
    Effect.fail(
      cliError(`Failed to recompute the audit-head hash column (${displayText(error.message)})`),
    ),
  ),
);

function gapViolations(sortedSeqs: readonly number[]): readonly ReconcileViolation[] {
  const violations: ReconcileViolation[] = [];
  let expected = 1;
  for (const seq of sortedSeqs) {
    if (seq !== expected) {
      violations.push({
        category: "row-tampering",
        detail: `audit seq ${expected}${seq - 1 > expected ? `..${seq - 1}` : ""} is missing (the seq numbering is gapless by construction — AUDIT_SPEC §5.1 — so a gap is the trace of deleted rows)`,
      });
      expected = seq;
    }
    expected += 1;
  }
  return violations;
}

function checkpointMirrorIndex(rows: readonly WireAuditEvent[]): ReadonlyMap<number, number[]> {
  const index = new Map<number, number[]>();
  for (const row of rows) {
    if (row.event === "chain.checkpointed" && row.chainSeq !== undefined && row.seq !== undefined) {
      index.set(row.chainSeq, [...(index.get(row.chainSeq) ?? []), row.seq]);
    }
  }
  return index;
}

interface NotarizedContext {
  readonly chainSeq: number;
  readonly position: number;
  readonly previousCheckpointChainSeq: number | null;
  readonly lastNotarized: { readonly chainSeq: number; readonly position: number } | null;
}

function regressionViolation(context: NotarizedContext): ReconcileViolation | null {
  if (context.lastNotarized === null || context.position >= context.lastNotarized.position) {
    return null;
  }
  return {
    category: "acceptance-policy",
    detail: `checkpoint at chain seq ${context.chainSeq} notarizes audit position ${context.position}, behind the position ${context.lastNotarized.position} notarized by the earlier checkpoint at chain seq ${context.lastNotarized.chainSeq} (non-regression check (b))`,
  };
}

function floorViolation(
  context: NotarizedContext,
  mirrors: ReadonlyMap<number, number[]>,
): ReconcileViolation | null {
  if (context.previousCheckpointChainSeq === null) {
    return null;
  }
  const mirrorSeqs = mirrors.get(context.previousCheckpointChainSeq) ?? [];
  const floor = mirrorSeqs[0];
  if (mirrorSeqs.length > 1) {
    return {
      category: "row-tampering",
      detail: `the checkpoint at chain seq ${context.previousCheckpointChainSeq} has ${countNoun(mirrorSeqs.length, "chain.checkpointed mirror row")} (mirrors are written exactly once per acceptance — duplicates are forged rows; run \`maruhi audit verify\`)`,
    };
  }
  if (floor === undefined) {
    return {
      category: "row-tampering",
      detail: `the checkpoint at chain seq ${context.previousCheckpointChainSeq} has no chain.checkpointed mirror row, so the position floor for the checkpoint at chain seq ${context.chainSeq} cannot be established (mirrors are written in the same transaction as acceptance — a missing mirror is evidence of a concealed deletion; run \`maruhi audit verify\`)`,
    };
  }
  if (context.position < floor) {
    return {
      category: "acceptance-policy",
      detail: `checkpoint at chain seq ${context.chainSeq} notarizes audit position ${context.position}, below the mirror row (audit seq ${floor}) of the immediately preceding checkpoint at chain seq ${context.previousCheckpointChainSeq} (position-floor check (c))`,
    };
  }
  return null;
}

function checkpointViolations(input: {
  readonly entries: readonly ChainEntry[];
  readonly positions: ReadonlyMap<string, number>;
  readonly mirrors: ReadonlyMap<number, number[]>;
}): { readonly violations: readonly ReconcileViolation[]; readonly notarized: number } {
  const violations: ReconcileViolation[] = [];
  let notarized = 0;
  let previousCheckpointChainSeq: number | null = null;
  let lastNotarized: { readonly chainSeq: number; readonly position: number } | null = null;
  for (const entry of input.entries) {
    if (entry.op !== "checkpoint") {
      continue;
    }
    const head = entry.payload.auditHeadHashHex;
    if (head !== "") {
      notarized += 1;
      const position = input.positions.get(head);
      if (position === undefined) {
        violations.push({
          category: "row-tampering",
          detail: `checkpoint at chain seq ${entry.seq} notarizes an audit head that does not appear in the column recomputed from the current rows (membership check (a))`,
        });
      } else {
        const context: NotarizedContext = {
          chainSeq: entry.seq,
          position,
          previousCheckpointChainSeq,
          lastNotarized,
        };
        violations.push(
          ...[regressionViolation(context), floorViolation(context, input.mirrors)].filter(
            (violation): violation is ReconcileViolation => violation !== null,
          ),
        );
        lastNotarized = { chainSeq: entry.seq, position };
      }
    }
    previousCheckpointChainSeq = entry.seq;
  }
  return { violations, notarized };
}

function declaredHeadViolations(
  declaredHeadHex: string,
  column: RecomputedColumn,
): readonly ReconcileViolation[] {
  if (declaredHeadHex === "" ? column.finalHeadHex === "" : column.positions.has(declaredHeadHex)) {
    return [];
  }
  return [
    {
      category: "row-tampering",
      detail:
        declaredHeadHex === ""
          ? "GET /audit-head declared an empty audit head, but the server returned audit rows (an empty declaration is only valid for an empty log)"
          : "the audit head declared by GET /audit-head does not appear in the column recomputed from the rows the server returned right after the declaration (the declaration and the rows contradict each other)",
    },
  ];
}

const CATEGORY_LABEL: Record<ReconcileViolation["category"], string> = {
  "row-tampering": "Row-tampering evidence",
  "acceptance-policy": "Acceptance-policy violation (stale-replay risk)",
};

export const auditReconcileOp = Effect.fn("audit-reconcile.auditReconcileOp")(function* (
  context: ProjectContextBase,
): Effect.fn.Return<number, CliError, CliServices> {
  const io = yield* CliIo;
  yield* ensureEffectiveAdmin(context);
  const declaredHeadHex = yield* fetchAuditHead(context.client, context.projectId);
  const rows = yield* fetchAllAuditRows(context);
  const ascending = [...rows].toSorted((a, b) => (a.seq ?? 0) - (b.seq ?? 0));
  const seqs = ascending.map((row) => row.seq ?? 0);
  const gaps = gapViolations(seqs);
  if (gaps.length > 0) {
    for (const violation of gaps) {
      yield* io.logError(
        `Reconciliation failure [${CATEGORY_LABEL[violation.category]}]: ${violation.detail}`,
      );
    }
    yield* io.logError(
      "The audit log has seq gaps, so the cumulative-hash reconciliation cannot proceed past them. The audit log is server-managed data (AUDIT_SPEC §6) and a gap is evidence of server-side row deletion",
    );
    return 1;
  }
  const column = yield* recomputeColumn(ascending.map((row) => toHeadRow(row, row.seq ?? 0)));
  const checkpoints = checkpointViolations({
    entries: context.verified.entries,
    positions: column.positions,
    mirrors: checkpointMirrorIndex(rows),
  });
  const violations = [
    ...declaredHeadViolations(declaredHeadHex, column),
    ...checkpoints.violations,
  ];
  const summary = `${countNoun(rows.length, "audit row")} recomputed, ${countNoun(checkpoints.notarized, "notarized checkpoint")} checked against the verified chain`;
  if (violations.length === 0) {
    if (checkpoints.notarized === 0) {
      yield* io.log(
        `Audit reconciliation OK (nothing notarized yet): ${summary} — seq continuity and the declared head's membership verified; the checkpoint checks (a)(b)(c) are vacuous until an effective admin issues an audit-head-attested checkpoint (run \`maruhi project checkpoint\` — AUDIT_SPEC §6)`,
      );
      return 0;
    }
    yield* io.log(
      `Audit reconciliation OK: ${summary} — membership (a) and position (b)(c) checks passed (AUDIT_SPEC §6)`,
    );
    yield* logNote(
      "rows appended after the latest notarized checkpoint are outside the notarized prefix and are not covered until the next attested checkpoint (AUDIT_SPEC §6)",
    );
    return 0;
  }
  for (const violation of violations) {
    yield* io.logError(
      `Reconciliation failure [${CATEGORY_LABEL[violation.category]}]: ${violation.detail}`,
    );
  }
  yield* io.logError(
    `Audit reconciliation found ${countNoun(violations.length, "violation")} (${summary}). Row-tampering evidence means rows in the notarized prefix were altered or deleted after notarization; acceptance-policy violations mean the server accepted attestations it must reject (CRYPTO_SPEC §6.4), leaving it able to replay stale audit heads. The signed chain is the truth — do not trust this server's audit log (AUDIT_SPEC §6)`,
  );
  return 1;
});
