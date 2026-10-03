// Typed errors of the mirror API (AUTH_SPEC §11-7 — PF2,
// docs/notes/pf2-design.md).

import { Schema } from "effect";

/**
 * Why a replication page is refused (judged after authorization and the
 * mark; every reason but `sequence-mismatch` discards the staging in
 * progress, so the next upload starts at sequence 0):
 *
 * - `sequence-mismatch` — the page is not the next one (0 starts over)
 * - `malformed` — a line is not a snapshot line, a row does not fit its
 *   table, or the lines are out of order (a row before its table, a line
 *   after the trailer, a header past the first page)
 * - `schema-mismatch` — the header's schema version is not this server's
 * - `unknown-table` — a table line names a table this server has not
 * - `row-count-mismatch` — a staged table's rows differ from the trailer
 * - `chain-not-extension` — the replica's chain does not extend the chain
 *   the mirror holds (a different project, a fork, or an older source)
 * - `chain-invalid` — the replica's chain does not verify (an entry that
 *   does not decode, a hash or a canonical size that does not match its
 *   entry, a signature or a rule the chain verifier refuses)
 * - `audit-not-extension` — the replica's audit log is not the one the
 *   mirror last replicated (its cumulative hash at the replicated position
 *   differs — the rows the mirror served are never rewritten)
 * - `audit-regression` — the replica's audit log is behind the one the
 *   mirror last replicated
 * - `page-too-large` — more rows or bytes than one page may carry
 */
export const MirrorSyncRejectReasonSchema = Schema.Literals([
  "sequence-mismatch",
  "malformed",
  "schema-mismatch",
  "unknown-table",
  "row-count-mismatch",
  "chain-not-extension",
  "chain-invalid",
  "audit-not-extension",
  "audit-regression",
  "page-too-large",
]);

/** 422: the replication page was refused. */
export class MirrorSyncRejectedError extends Schema.TaggedError<MirrorSyncRejectedError>()(
  "MirrorSyncRejected",
  { reason: MirrorSyncRejectReasonSchema },
  { httpApiStatus: 422 },
) {}

/** Why the project's mirror state does not admit the operation. */
export const MirrorStateReasonSchema = Schema.Literals(["already-mirror", "not-mirror"]);

/** 409: marking a mirror twice, or replicating into / promoting a project that is not a mirror. */
export class MirrorStateError extends Schema.TaggedError<MirrorStateError>()(
  "MirrorState",
  { reason: MirrorStateReasonSchema },
  { httpApiStatus: 409 },
) {}
