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
import type { CliServices } from "../cli.ts";
import type { ProjectContextBase } from "../context.ts";
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

const VERIFY_PAGE_LIMIT = MAX_AUDIT_EVENTS_PAGE_LIMIT;

const VERIFY_MAX_PAGES = 100;

type MirrorRowSelector = "chain-namespace" | "chain-seq-present";

export const paginateAuditEvents = Effect.fn("audit-verify.paginateAuditEvents")(function* (input: {
  readonly pageLimit: number;
  readonly fetchPage: (before: string | null) => Effect.Effect<readonly WireAuditEvent[], CliError>;
  readonly onRow: (row: WireAuditEvent) => Effect.Effect<void, CliError>;
  readonly bound: { readonly maxPages: number; readonly exceededMessage: string } | null;
}): Effect.fn.Return<void, CliError> {
  let before: string | null = null;
  for (let page = 0; input.bound === null || page < input.bound.maxPages; page += 1) {
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
  return yield* Effect.fail(cliError(input.bound?.exceededMessage ?? "unreachable"));
});

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

interface MirrorBuckets {
  readonly byChainSeq: ReadonlyMap<number, readonly WireAuditEvent[]>;
  readonly problems: readonly string[];
  readonly aheadRows: number;
}

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

function bucketMirrorRows(rows: readonly WireAuditEvent[], headSeq: number): MirrorBuckets {
  const byChainSeq = new Map<number, WireAuditEvent[]>();
  const problems: string[] = [];
  const ahead: number[] = [];
  for (const row of rows) {
    if (!row.event.startsWith(CHAIN_MIRROR_EVENT_PREFIX)) {
      problems.push(
        `Audit row ${displayText(row.id)}: chain_seq=${row.chainSeq ?? "(missing)"} is present outside the chain.* namespace (${displayText(row.event)}) — only chain mirror rows may carry chain provenance (evidence of a forged row)`,
      );
      continue;
    }
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
  return mirrorMismatches(expectedRowFor(entry, observed, index), observed).map(
    (mismatch) => `chain_seq=${entry.seq} (audit row ${displayText(observed.id)}): ${mismatch}`,
  );
}

function entryMirrorProblems(
  entry: ChainEntry,
  matched: readonly WireAuditEvent[],
  index: ProposalIndex,
): readonly string[] {
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
