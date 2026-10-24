// `maruhi audit verify` (AUDIT_SPEC §6 / §7): bijection verification of the
// chain mirror (the client implementation of §1-5 "the mirror can be
// rebuilt from the chain" / §6's mitigation "the mirror can be verified by
// reconciling against the chain"). Rebuilds the expected mirror column from
// the verified chain with the server's mapping (@maruhi/core's
// chainMirrorEvents) and detects the three directions — missing, forged,
// altered; a row's fields are compared the way list's labels compare them
// (audit-mirror.ts). Its paging engine (paginateAuditEvents) is shared with
// `maruhi audit reconcile` (audit-reconcile.ts).

import { MAX_AUDIT_EVENTS_PAGE_LIMIT } from "@maruhi/api-schema";
import {
  type AuditEventRecord,
  CHAIN_MIRROR_EVENT_PREFIX,
  CHAIN_MIRROR_EVENTS,
  chainMirrorEvents,
  type ProjectId,
  type ProposalIndex,
} from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "../api.ts";
import { proposalIndexOf } from "../chain-applied.ts";
import type { CliServices, ProjectContextBase } from "../context.ts";
import { countNoun, displayText } from "../display.ts";
import type { CliError } from "../errors.ts";
import { cliError } from "../errors.ts";
import { toCliError } from "../failure.ts";
import { CliIo } from "../io.ts";
import {
  expectedRowFor,
  jsonEqual,
  mirrorMismatches,
  proposalMissingFor,
  type WireAuditEvent,
} from "./audit-mirror.ts";

// §3.4's mirror event names use the shared mapping (@maruhi/core's
// CHAIN_MIRROR_EVENTS — derived from ChainOp's total map). A hand-written
// list would miss a future op addition only here, and the contiguity check
// would wrongly convict an honest server of forgery

const VERIFY_PAGE_LIMIT = MAX_AUDIT_EVENTS_PAGE_LIMIT;

// Chain acceptance policy (10,000 entries) ÷ 200 per page = a theoretical
// maximum of 50 pages. A hard cap so a server whose cursor does not advance
// cannot loop forever. Because one paging pass per namespace draws all mirror
// rows, the cap is a single total, not per event kind
const VERIFY_MAX_PAGES = 100;

type MirrorRowSelector = "chain-namespace" | "chain-seq-present";

/**
 * The shared paging engine (used by verify and `maruhi audit reconcile`).
 * fetchPage fetches one page (newest-first); the cursor is the previous
 * page's last row's id. onRow is the per-row check + collection (a failure
 * aborts as a contradictory server response). bound is a static page-count
 * cap — null means uncapped, in which case termination is carried by the
 * caller's row check (reconcile bounds the total row count via the
 * strictly-decreasing admin-visible `seq`).
 */
export const paginateAuditEvents = Effect.fn("audit-verify.paginateAuditEvents")(function* (input: {
  readonly pageLimit: number;
  readonly fetchPage: (before: string | null) => Effect.Effect<readonly WireAuditEvent[], CliError>;
  readonly onRow: (row: WireAuditEvent) => Effect.Effect<void, CliError>;
  readonly bound: { readonly maxPages: number; readonly exceededMessage: string } | null;
}): Effect.fn.Return<void, CliError> {
  let before: string | null = null;
  for (let page = 0; input.bound === null || page < input.bound.maxPages; page += 1) {
    // The annotation breaks self-referential inference inside the generator (before → rows → before)
    const cursor: string | null = before;
    const rows: readonly WireAuditEvent[] = yield* input.fetchPage(cursor);
    for (const row of rows) {
      yield* input.onRow(row);
    }
    if (rows.length < input.pageLimit) {
      return;
    }
    before = rows[rows.length - 1]?.id ?? null;
  }
  // Leaving the loop = bound was non-null and maxPages was reached
  return yield* Effect.fail(cliError(input.bound?.exceededMessage ?? "unreachable"));
});

/**
 * Fetch all pages of one mirror-candidate filter (newest-first; cursor is a
 * row id). A re-appearing row id is refused as a contradictory server
 * response (a non-advancing cursor, duplicate row distribution) — ids are
 * opaque and cannot be ordinally compared, so progress is checked as set
 * non-duplication.
 */
const fetchMirrorRowsForSelector = Effect.fn("audit-verify.fetchMirrorRowsForSelector")(function* (
  client: MaruhiClient,
  projectId: ProjectId,
  selector: MirrorRowSelector,
): Effect.fn.Return<readonly WireAuditEvent[], CliError> {
  const rows: WireAuditEvent[] = [];
  const seen = new Set<string>();
  yield* paginateAuditEvents({
    pageLimit: VERIFY_PAGE_LIMIT,
    bound: {
      maxPages: VERIFY_MAX_PAGES,
      exceededMessage:
        "The audit log exceeded the theoretical page-count limit — the server response contradicts itself",
    },
    fetchPage: (before) =>
      client.audit
        .events({
          params: { projectId },
          query: {
            limit: VERIFY_PAGE_LIMIT,
            ...(selector === "chain-namespace"
              ? { eventPrefix: CHAIN_MIRROR_EVENT_PREFIX }
              : { chainSeqPresent: "true" as const }),
            ...(before === null ? {} : { before }),
          },
        })
        .pipe(
          Effect.mapError(toCliError),
          Effect.map((response) => response.events as readonly WireAuditEvent[]),
        ),
    onRow: (row) => {
      if (seen.has(row.id)) {
        return Effect.fail(
          cliError(
            `Audit-log paging is not advancing (${selector}, row ${displayText(row.id)} was returned twice) — the server response contradicts itself. Aborting the mirror verification`,
          ),
        );
      }
      seen.add(row.id);
      rows.push(row);
      return Effect.void;
    },
  });
  return rows;
});

/**
 * verify's full mirror candidate set. The union of two sets:
 *
 * 1. every row in the `chain.` namespace — also catches names missing from
 *    the mapping and missing chain_seq
 * 2. every row carrying chain_seq — catches forged provenance one step
 *    outside the namespace
 *
 * A genuine mirror row lands in both, so dedupe by row id. If the same id's
 * content changed between the filters, the server response contradicts
 * itself and verification cannot proceed.
 */
const fetchAllMirrorRows = Effect.fn("audit-verify.fetchAllMirrorRows")(function* (
  client: MaruhiClient,
  projectId: ProjectId,
): Effect.fn.Return<readonly WireAuditEvent[], CliError> {
  const byId = new Map<string, WireAuditEvent>();
  for (const selector of ["chain-namespace", "chain-seq-present"] as const) {
    const rows = yield* fetchMirrorRowsForSelector(client, projectId, selector);
    for (const row of rows) {
      const existing = byId.get(row.id);
      if (existing !== undefined && !jsonEqual(existing, row)) {
        return yield* Effect.fail(
          cliError(
            `Audit row ${displayText(row.id)} changed between mirror-verification queries — the server response contradicts itself`,
          ),
        );
      }
      byId.set(row.id, row);
    }
  }
  return [...byId.values()];
});

/** The result of indexing mirror rows (bundled by chain_seq, with unverifiable rows sorted out). */
interface MirrorBuckets {
  readonly byChainSeq: ReadonlyMap<number, readonly WireAuditEvent[]>;
  readonly problems: readonly string[];
  /** The count of "newer than the local chain" rows contiguous from just after head (unverified). */
  readonly aheadRows: number;
}

/**
 * The contiguity check of rows newer than head. In an honest extension (the
 * chain advanced between the sync and the page fetch), those rows' chain_seq
 * run contiguously from head+1 with no gaps — mirrors are written in the same
 * transaction as acceptance and seq is gapless (§3.4 / §5.1). At most 2 rows
 * share one chain_seq (a completed approve's `chain.approved` + the applied
 * row — §3.4). A non-contiguous seq or a seq with 3+ rows is treated as
 * evidence of "forged rows claiming nonexistent entries" (blocks
 * verification bypass via an unreachable chain_seq).
 */
function aheadContiguityProblems(ahead: readonly number[], headSeq: number): readonly string[] {
  const problems: string[] = [];
  const counts = new Map<number, number>();
  for (const chainSeq of ahead) {
    counts.set(chainSeq, (counts.get(chainSeq) ?? 0) + 1);
  }
  let expected = headSeq + 1;
  for (const chainSeq of [...counts.keys()].toSorted((a, b) => a - b)) {
    if (chainSeq !== expected) {
      problems.push(
        `chain_seq=${chainSeq}: mirror rows newer than the local chain (head seq=${headSeq}) are not contiguous from just after the head (expected ${expected}) — an honest extension is contiguous with no gaps, so this is evidence of forged rows claiming nonexistent entries`,
      );
    }
    const count = counts.get(chainSeq) ?? 0;
    if (count > 2) {
      problems.push(
        `chain_seq=${chainSeq}: ${countNoun(count, "mirror row")} newer than the local chain — no chain entry has more than 2 mirror rows (a completed approve has its own row plus the applied inner-op row — AUDIT_SPEC §3.4), so this is evidence of forged rows`,
      );
    }
    expected = chainSeq + 1;
  }
  return problems;
}

/** Indexes the fetched chain.* rows by chain_seq (a pure function before verification). */
function bucketMirrorRows(rows: readonly WireAuditEvent[], headSeq: number): MirrorBuckets {
  const byChainSeq = new Map<number, WireAuditEvent[]>();
  const problems: string[] = [];
  const ahead: number[] = [];
  for (const row of rows) {
    // chain_seq's presence is treated as the trust boundary ahead of the
    // event name. The only writer of a genuine chain_seq is chainMirrorEvents,
    // so a row outside the namespace is a forged provenance claim that no
    // real op can reconcile against
    if (!row.event.startsWith(CHAIN_MIRROR_EVENT_PREFIX)) {
      problems.push(
        `Audit row ${displayText(row.id)}: chain_seq=${row.chainSeq ?? "(missing)"} is present outside the chain.* namespace (${displayText(row.event)}) — only chain mirror rows may carry chain provenance (evidence of a forged row)`,
      );
      continue;
    }
    // Inside the namespace, an event name missing from the mapping is itself
    // evidence of forgery: a real op's mirror always lands in
    // chainMirrorEvents' image. The row cannot proceed to chain_seq
    // reconciliation, so it is confirmed as a problem here and we move on
    if (!CHAIN_MIRROR_EVENTS.includes(row.event)) {
      problems.push(
        `Audit row ${displayText(row.id)}: the mirror row claims an unknown chain op (${displayText(row.event)}) — no chain operation maps to this event name, so the row cannot mirror a real entry (evidence of a forged row)`,
      );
      continue;
    }
    if (row.chainSeq === undefined) {
      problems.push(
        `Audit row ${displayText(row.id)}: the mirror row has no chain_seq (${displayText(row.event)})`,
      );
    } else if (row.chainSeq > headSeq) {
      ahead.push(row.chainSeq);
    } else {
      byChainSeq.set(row.chainSeq, [...(byChainSeq.get(row.chainSeq) ?? []), row]);
    }
  }
  problems.push(...aheadContiguityProblems(ahead, headSeq));
  return { byChainSeq, problems, aheadRows: ahead.length };
}

/** Reconcile the observed rows against one expected row (missing / duplicate / field mismatch). */
function expectedRowProblems(
  entry: ChainEntry,
  expected: AuditEventRecord,
  rows: readonly WireAuditEvent[],
  index: ProposalIndex,
): readonly string[] {
  const observed = rows[0];
  if (observed === undefined) {
    return [
      `chain_seq=${entry.seq} (op=${entry.op}): no corresponding ${displayText(expected.event)} mirror row (a missing row — mirrors are written in the same transaction as chain acceptance, so this is evidence of a concealed deletion)`,
    ];
  }
  if (rows.length > 1) {
    return [
      `chain_seq=${entry.seq} (op=${entry.op}): ${countNoun(rows.length, `${displayText(expected.event)} mirror row`)} found (duplicates — rows ${rows.map((row) => displayText(row.id)).join(", ")})`,
    ];
  }
  // serverTs is out of scope (the observed row's value is copied onto the expected row before comparing)
  return mirrorMismatches(expectedRowFor(entry, observed, index), observed).map(
    (mismatch) => `chain_seq=${entry.seq} (audit row ${displayText(observed.id)}): ${mismatch}`,
  );
}

/**
 * One entry's bijection + mapping-match check (empty = no problem). The
 * expected set is the 1 row chainMirrorEvents returns (2 rows for a
 * completed approve); observed rows are paired to expected rows by event
 * name: an expected row with no observed row is missing, 2+ observed is a
 * duplicate, and a row with an event name outside the expected set is excess
 * (an applied row on an incomplete approve, a row claiming a different op,
 * etc.). A mismatch in any field of an applied row, including
 * `viaProposalSeq`, is listed as a mapping mismatch (AUDIT_SPEC §3.4 —
 * 2026-09-16 K5).
 */
function entryMirrorProblems(
  entry: ChainEntry,
  matched: readonly WireAuditEvent[],
  index: ProposalIndex,
): readonly string[] {
  // On a verified chain the referenced propose is always in the index (an
  // unknown-proposal is an invalid entry). A miss is a contradiction in the
  // index's construction and the expected rows cannot be built, so do not
  // drop it as a defect — report it as a verification failure with the
  // chain_seq (pullfrog round 1)
  if (proposalMissingFor(entry, index)) {
    return [
      `chain_seq=${entry.seq} (op=${entry.op}): the referenced proposal is not on the verified chain, so the expected mirror rows cannot be reconstructed — re-run \`maruhi audit verify\` after a full sync; if this persists it is a verifier inconsistency, not evidence about the audit log`,
    ];
  }
  const expectedRows = chainMirrorEvents(entry, 0, index);
  const expectedEvents = new Set<string>(expectedRows.map((row) => row.event));
  const problems = expectedRows.flatMap((expected) =>
    expectedRowProblems(
      entry,
      expected,
      matched.filter((row) => row.event === expected.event),
      index,
    ),
  );
  const unexpected = matched
    .filter((row) => !expectedEvents.has(row.event))
    .map(
      (row) =>
        `chain_seq=${entry.seq} (op=${entry.op}): unexpected mirror row ${displayText(row.id)} (${displayText(row.event)}) — the entry maps to ${expectedRows.map((expected) => displayText(expected.event)).join(" + ")} only (an applied inner-op row exists only for an approve that reached the quorum — AUDIT_SPEC §3.4), so this is evidence of a forged row`,
    );
  return [...problems, ...unexpected];
}

/**
 * `maruhi audit verify`: mirror bijection verification. Checks that every
 * entry of the verified chain (1..headSeq) and the chain.* mirror rows
 * correspond 1:1 (a completed approve adds the applied inner-op row —
 * AUDIT_SPEC §3.4) and that every field matches the mapping. Detects the
 * three directions — missing (concealed deletion), forged (a row not on the
 * chain), altered — covering even the missing case that per-row
 * reconciliation (list's labels) cannot see in principle, which is this
 * command's added value. It reads only class 1, so every member can run it.
 */
export const auditVerifyOp = Effect.fn("audit-verify.auditVerifyOp")(function* (
  context: ProjectContextBase,
): Effect.fn.Return<number, CliError, CliServices> {
  const io = yield* CliIo;
  const rows = yield* fetchAllMirrorRows(context.client, context.projectId);
  const headSeq = context.verified.state.headSeq;
  const buckets = bucketMirrorRows(rows, headSeq);
  const index = proposalIndexOf(context.verified);
  const problems = [
    ...buckets.problems,
    ...context.verified.entries.flatMap((entry) =>
      entryMirrorProblems(entry, buckets.byChainSeq.get(entry.seq) ?? [], index),
    ),
  ];
  if (problems.length === 0 && buckets.aheadRows === 0) {
    yield* io.log(
      `Mirror bijection verification OK: chain entries 1..${headSeq} \u2194 chain.* mirror rows match the mapping (one row per entry, plus the applied inner-op row of each completed approve — AUDIT_SPEC §3.4)`,
    );
    return 0;
  }
  if (buckets.aheadRows > 0) {
    // Never say "OK" while unverified rows remain (do not paper over, with
    // a successful exit, the shape where forged rows permanently sit inside
    // the unverified allowance)
    yield* io.logError(
      `Mirror verification incomplete: ${countNoun(buckets.aheadRows, "row")} newer than the local chain could not be verified in this run (this can happen when the chain grew right after the sync). Re-run \`maruhi audit verify\` — if this does not resolve, those mirror rows claim entries that do not exist on the chain (suspected forgery)`,
    );
  }
  for (const problem of problems) {
    yield* io.logError(`Mirror verification failure: ${problem}`);
  }
  if (problems.length > 0) {
    yield* io.logError(
      `Mirror verification found ${countNoun(problems.length, "problem")}. The audit log is server-managed data (AUDIT_SPEC §6) and these mismatches are evidence of server-side tampering or corruption — the distributed chain (signed and verified) is the truth; do not trust the audit log`,
    );
  }
  return 1;
});
