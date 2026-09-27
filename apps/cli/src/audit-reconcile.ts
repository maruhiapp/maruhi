// `maruhi audit reconcile` — the admin's audit reconciliation (AUDIT_SPEC §6).
//
// The verification side of the "notarizations unverified at issuance" (§6):
// recompute the cumulative hash column from every audit row, and for each
// notarizing checkpoint on the verified chain check
//   (a) membership — the notarized head appears in the recomputed column
//   (b) non-regression — the position does not regress between notarizing
//       checkpoints
//   (c) position floor — the position is at or above the mirror row
//       (chain.checkpointed — identified by chain_seq) of the immediately
//       preceding checkpoint itself (notarized or not)
//       (not enforced on the first checkpoint, which has no predecessor —
//       the same predicate and base as the acceptance check)
// Violations are reported in two categories (§6):
//   - membership violation (a) = evidence of row tampering (post-hoc
//     alteration or deletion inside the notarized prefix)
//   - position violation (b)(c) = evidence of a server that does not enforce
//     the acceptance policy (CRYPTO_SPEC §6.4's position floor) — a state in
//     which stale replay (keep returning an old real head) is possible
//
// The precondition is effective admin (chain role admin or higher × token
// scope admin): the reconciliation includes the gap check via §7's `seq`
// (admin-visible; a gap = the trace of a deletion), and the full-row fetch is
// not complete unless admin-visible including class 2. The role is pre-judged
// from the verified view, the scope from /auth/me, and anything below ends in
// a clear error (never trips a 403 — the same pre-judgment discipline as
// checkpoint issuance).
//
// The recomputation input (AuditHeadRow.payloadText) is obtained by
// serializing the wire payload (JSON) with JSON.stringify. The stored TEXT
// was written by the server's own JSON.stringify (audit-store.ts — the server
// is the only writer), and an object with identifier-only keys is byte-stable
// across a parse → stringify round trip, so an honest server yields a
// recomputed column matching the stored column. When they disagree, the
// received rows differ from the rows the server used to compute the column =
// a self-contradicting response; the audit log is server-managed data (§6),
// so it may be treated as evidence of tampering or corruption.

import { MAX_AUDIT_EVENTS_PAGE_LIMIT } from "@maruhi/api-schema";
import { scopePermissionFor } from "@maruhi/core";
import type { AuditHeadRow, ChainEntry } from "@maruhi/crypto";
import { computeAuditHeadHash, computeAuditRowDigest, SUITE_ID } from "@maruhi/crypto";
import { Effect } from "effect";

import type { WireAuditEvent } from "./audit.ts";
import { paginateAuditEvents } from "./audit.ts";
import { fetchAuditHead } from "./checkpoint.ts";
import type { CliServices, ProjectContextBase } from "./context.ts";
import { countNoun, displayText } from "./display.ts";
import type { CliError } from "./errors.ts";
import { cliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import { logNote } from "./notice.ts";

/** Interval (in pages) of the fetch progress display — makes unresponsiveness and non-termination on huge logs visible. */
const FETCH_PROGRESS_PAGES = 50;

/** The two violation categories (AUDIT_SPEC §6's report categories) + a fetch-integrity failure. */
interface ReconcileViolation {
  readonly category: "row-tampering" | "acceptance-policy";
  readonly detail: string;
}

/**
 * Pre-judgment of effective admin (min(token scope, chain role) — AUTH_SPEC
 * §9-2). Anything below ends in a clear error without starting the
 * reconciliation (§6's reconciliation needs the admin-visible `seq` and the
 * full-row fetch; run below admin, the gap check would misread a visibility
 * hole as a deletion).
 */
function ensureEffectiveAdmin(context: ProjectContextBase): Effect.Effect<void, CliError> {
  return Effect.gen(function* () {
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
}

/**
 * Fetching every audit row (§7 paging — admin-visible, unfiltered,
 * newest-first).
 *
 * Integrity strategy (session-38 ruling AJ): the cursor is a row id, and a
 * duplicate id or a non-strictly-decreasing `seq` (within a page or across
 * pages) aborts as a self-contradicting server response. Because `seq` in an
 * admin response is a positive integer forced strictly decreasing, the total
 * row count is bounded by the first page's maximum seq and paging always
 * terminates. Rows appended during the fetch are newer than the first page's
 * cursor and never appear in later pages — the fetched set closes as a
 * snapshot of the first page's point in time (the audit-head declaration is
 * taken **before** this snapshot, so the membership check's population is
 * covered by the snapshot).
 */
/** Per-row integrity check (seq required, no duplicate ids, seq strictly decreasing). null = no problem. */
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

function fetchAllAuditRows(
  context: ProjectContextBase,
): Effect.Effect<readonly WireAuditEvent[], CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const rows: WireAuditEvent[] = [];
    const seenIds = new Set<string>();
    let previousSeq: number | null = null;
    let pages = 0;
    yield* paginateAuditEvents({
      pageLimit: MAX_AUDIT_EVENTS_PAGE_LIMIT,
      // No static page bound: onRow's strictly-decreasing seq (positive
      // integers) bounds the total row count by the first page's maximum seq
      // and carries termination (the engine doc in audit.ts)
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
}

/** Wire optionalKey (absent = stored NULL) → null in the computation input. */
function orNull<T>(value: T | undefined): T | null {
  return value === undefined ? null : value;
}

/** Wire row → the input shape of the cumulative-hash computation (AUDIT_SPEC §5.1's 17 columns). */
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
    // Reconstructing the stored TEXT (the header comment's round-trip premise). No payload = NULL
    payloadText: event.payload === undefined ? null : JSON.stringify(event.payload),
  };
}

/** The recomputation result: a position index (headHex → audit seq) and the final head. */
interface RecomputedColumn {
  readonly positions: ReadonlyMap<string, number>;
  readonly finalHeadHex: string;
}

/**
 * Recompute the cumulative hash column (§5.1 — the canonical implementation
 * is @maruhi/crypto; the audit-head.json vectors pin the same h_n as the
 * server implementation). Input is every row in seq ascending order.
 */
function recomputeColumn(rows: readonly AuditHeadRow[]): Effect.Effect<RecomputedColumn, CliError> {
  return Effect.tryPromise({
    try: async () => {
      const positions = new Map<string, number>();
      let head = "";
      for (const row of rows) {
        const digest = await computeAuditRowDigest(row);
        const next = digest.ok
          ? await computeAuditHeadHash(SUITE_ID, head, row.seq, digest.value)
          : digest;
        if (!next.ok) {
          throw new Error(`recomputation failed at seq ${row.seq}: ${next.error.kind}`);
        }
        head = next.value;
        // SHA-256 collisions do not occur in practice, but a stray duplicate keeps the first (earliest position)
        if (!positions.has(head)) {
          positions.set(head, row.seq);
        }
      }
      return { positions, finalHeadHex: head };
    },
    // The error value is only a seq and a reason code (no secrets), but per
    // the discipline it is mapped to a fixed wording of identifiers only
    catch: (error) =>
      cliError(
        `Failed to recompute the audit-head hash column (${error instanceof Error ? displayText(error.message) : "unknown"})`,
      ),
  });
}

/** Gap check (§6 — a gap = the trace of a deletion). rows are seq ascending. */
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

/** Index of the chain.checkpointed mirror rows (chain_seq → list of audit seqs). */
function checkpointMirrorIndex(rows: readonly WireAuditEvent[]): ReadonlyMap<number, number[]> {
  const index = new Map<number, number[]>();
  for (const row of rows) {
    if (row.event === "chain.checkpointed" && row.chainSeq !== undefined && row.seq !== undefined) {
      index.set(row.chainSeq, [...(index.get(row.chainSeq) ?? []), row.seq]);
    }
  }
  return index;
}

/** A notarized position and its check context (previous checkpoint · previous notarized position). */
interface NotarizedContext {
  readonly chainSeq: number;
  readonly position: number;
  readonly previousCheckpointChainSeq: number | null;
  readonly lastNotarized: { readonly chainSeq: number; readonly position: number } | null;
}

/** (b) non-regression: the position must not regress between notarizing checkpoints. null = no problem. */
function regressionViolation(context: NotarizedContext): ReconcileViolation | null {
  if (context.lastNotarized === null || context.position >= context.lastNotarized.position) {
    return null;
  }
  return {
    category: "acceptance-policy",
    detail: `checkpoint at chain seq ${context.chainSeq} notarizes audit position ${context.position}, behind the position ${context.lastNotarized.position} notarized by the earlier checkpoint at chain seq ${context.lastNotarized.chainSeq} (non-regression check (b))`,
  };
}

/**
 * (c) position floor: the position must be at or above the mirror row
 * (chain.checkpointed — identified by chain_seq) of the immediately
 * preceding checkpoint itself (notarized or not). Not enforced on the first
 * checkpoint, which has no predecessor (vacuously true). A missing or
 * duplicated mirror row is a broken §3.4 bijection = reported as
 * row-tampering evidence.
 */
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

/**
 * Membership (a) + position (b)(c) checks of the notarizing checkpoints
 * (AUDIT_SPEC §6). entries is the verified chain (seq ascending).
 */
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
        // (a) membership violation: the fact that the server asserted "the
        // cumulative hash was this" at notarization time is signed and fixed
        // on the chain. Not appearing in the recomputed column = some row
        // inside the notarized prefix was altered or deleted afterwards (§6)
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

/** Membership check of the declared head (session-38 ruling AK — detecting a false declaration that does not wait for notarization). */
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

/**
 * `maruhi audit reconcile`: the admin's audit reconciliation (AUDIT_SPEC
 * §6). Pre-judge effective admin → fetch the declared head → fetch all rows
 * → gap check → recompute the cumulative column → membership (a) + position
 * (b)(c) checks of notarizing checkpoints → report in two categories (any
 * violation = exit code 1).
 */
export function auditReconcileOp(
  context: ProjectContextBase,
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* ensureEffectiveAdmin(context);
    // The declaration is taken **before** fetching all rows (ruling AK):
    // the column at declaration time is a prefix of the fetched snapshot, so
    // the membership check's population is always covered by the snapshot
    const declaredHeadHex = yield* fetchAuditHead(context.client, context.projectId);
    const rows = yield* fetchAllAuditRows(context);
    const ascending = [...rows].toSorted((a, b) => (a.seq ?? 0) - (b.seq ?? 0));
    const seqs = ascending.map((row) => row.seq ?? 0);
    const gaps = gapViolations(seqs);
    if (gaps.length > 0) {
      // With a gap, the h_n chaining mismatches on everything past the gap,
      // and the downstream membership check would produce the misleading
      // derived report "every notarization is a violation". Report only the
      // strongest evidence (the trace of a deletion) and stop (fail-closed —
      // do not mass-produce misattributions)
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
      // Keep the success wording faithful to what was proved: with zero
      // notarizations, (a)(b)(c) are vacuously true and what was demonstrated
      // is only gap-free + declared-head membership. Do not print an
      // unconditional "checks passed"
      if (checkpoints.notarized === 0) {
        yield* io.log(
          `Audit reconciliation OK (nothing notarized yet): ${summary} — seq continuity and the declared head's membership verified; the checkpoint checks (a)(b)(c) are vacuous until an effective admin issues an audit-head-attested checkpoint (run \`maruhi project checkpoint\` — AUDIT_SPEC §6)`,
        );
        return 0;
      }
      yield* io.log(
        `Audit reconciliation OK: ${summary} — membership (a) and position (b)(c) checks passed (AUDIT_SPEC §6)`,
      );
      // §6's explicit residual: outside the notarized prefix (rows after the
      // last notarization) is not covered by this reconciliation — coverage
      // advances with the next notarization
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
}
