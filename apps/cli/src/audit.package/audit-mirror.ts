// The chain mirror checks `maruhi audit`'s subcommands share (AUDIT_SPEC
// §1-5 / §6). A chain.* row mirrors one entry of the chain, and its
// expected form is rebuilt from the verified chain with the mapping the
// server writes it with (@maruhi/core's chainMirrorEvents), which
// structurally blocks false alarms from verifier drift. list
// (audit-list.ts) and invites / self (audit-d1.ts) label each row that
// claims chain provenance; verify (audit-verify.ts) checks the whole mirror
// against the same expected rows.
//
// TCB discipline (AUDIT_SPEC §7): every field of a response is a server
// claim. chain.* rows show their reconciliation result against the verified
// chain as a label (this file), and display names come only from verified
// statements (audit-page.ts). Plaintext values and key material never pass
// through audit.package.

import type { AuditEventSchema } from "@maruhi/api-schema";
import {
  type AuditEventRecord,
  CHAIN_MIRROR_EVENT_PREFIX,
  chainMirrorEvents,
  type ProposalIndex,
} from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";

import { displayText } from "../display.ts";
import { isRecord } from "../json-record.ts";

/**
 * The wire audit event (the received shape of api-schema's
 * AuditEventSchema — the type is derived from the Schema; its shape is not
 * duplicated here). Every field is a server claim (the TCB discipline
 * above).
 */
export type WireAuditEvent = typeof AuditEventSchema.Type;

function jsonRecordEqual(left: Record<string, unknown>, right: Record<string, unknown>): boolean {
  const keys = Object.keys(left);
  return (
    keys.length === Object.keys(right).length &&
    keys.every((key) => key in right && jsonEqual(left[key], right[key]))
  );
}

/** Structural equality of JSON values (key-order independent). */
export function jsonEqual(a: unknown, b: unknown): boolean {
  if (a === b) {
    return true;
  }
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((item, index) => jsonEqual(item, b[index]));
  }
  return isRecord(a) && isRecord(b) && jsonRecordEqual(a, b);
}

function describeValue(value: unknown): string {
  return displayText(value === undefined ? "(none)" : JSON.stringify(value));
}

/**
 * Of one entry's expected mirror rows, the one with the same event name as
 * the observed row (a completed approve has two rows — `chain.approved` plus
 * the inner op's applied row — and the event names never overlap). If the
 * name matches no expected row, the first row is returned and the mismatch
 * is reported on event.
 */
export function expectedRowFor(
  entry: ChainEntry,
  observed: WireAuditEvent,
  index: ProposalIndex,
): AuditEventRecord {
  const rows = chainMirrorEvents(entry, observed.serverTs, index);
  const first = rows[0];
  if (first === undefined) {
    // chainMirrorEvents returns 1+ rows (every op has a mapping)
    throw new Error("chain mirror mapping produced no rows");
  }
  return rows.find((row) => row.event === observed.event) ?? first;
}

/**
 * Reconciliation of a chain.* mirror row against the expected row. Rebuilds
 * the expected row from the same mapping as the server (chainMirrorEvents)
 * and lists the mismatched fields (empty = match). serverTs is out of scope —
 * it is the server's acceptance time and the client has nothing to verify it
 * against. A chain.* payload derives from the signed entry (an applied row
 * derives from the proposal entry's inner op), so it is in scope.
 */
export function mirrorMismatches(
  expected: AuditEventRecord,
  observed: WireAuditEvent,
): readonly string[] {
  const reasons: string[] = [];
  const check = (label: string, want: unknown, got: unknown): void => {
    if (!jsonEqual(want, got)) {
      reasons.push(`${label}: expected ${describeValue(want)} / recorded ${describeValue(got)}`);
    }
  };
  check("event", expected.event, observed.event);
  check("client_ts", expected.clientTs, observed.clientTs);
  check("actor.type", expected.actorType, observed.actor.type);
  check("actor.user_id", expected.actorUserId, observed.actor.userId);
  check("actor.key_fingerprint", expected.actorKeyFingerprintHex, observed.actor.keyFingerprintHex);
  check("target.user_id", expected.targetUserId, observed.targetUserId);
  check(
    "target.key_fingerprint",
    expected.targetKeyFingerprintHex,
    observed.targetKeyFingerprintHex,
  );
  // The mapping never sets api_token_id on a mirror row (§3.4's actor is a
  // copy of the chain entry's). The expectation is always undefined, but the
  // check is explicit to block misleading into a fake "via token" display
  check("actor.api_token_id", expected.actorApiTokenId, observed.actor.apiTokenId);
  check("environment_id", expected.environmentId, observed.environmentId);
  check("variable_id", expected.variableId, observed.variableId);
  check("epoch", expected.epoch, observed.epoch);
  check("version", expected.version, observed.version);
  check("payload", expected.payload, observed.payload);
  return reasons;
}

/**
 * Whether an approve / withdraw's referenced proposal is missing from the
 * proposal index. Unreachable on a verified chain (the index is built from
 * the same verified chain — an unknown-proposal is an invalid entry), but
 * verify (reports it as a problem) and list (an unverified label) share the
 * same predicate.
 */
export function proposalMissingFor(entry: ChainEntry, index: ProposalIndex): boolean {
  return (
    (entry.op === "approve" || entry.op === "withdraw") && !index.has(entry.payload.proposalHashHex)
  );
}

/** A chain.* row's trust label (for display) and mismatch details. */
export interface MirrorTrust {
  readonly label: string;
  readonly mismatches: readonly string[];
}

function mirrorTrustOf(
  observed: WireAuditEvent,
  entries: ReadonlyMap<number, ChainEntry>,
  headSeq: number,
  index: ProposalIndex,
): MirrorTrust {
  if (observed.chainSeq === undefined) {
    return { label: "mirror=mismatch", mismatches: ["chain_seq: the mirror row has no chain_seq"] };
  }
  if (observed.chainSeq > headSeq) {
    // Can also happen in an honest race where the chain grew after the sync —
    // not evidence on its own, but verify decides the distinction from
    // forgery (contiguity from just after the head)
    return {
      label: "mirror=unverified (newer than the local chain — confirm with `maruhi audit verify`)",
      mismatches: [],
    };
  }
  const entry = entries.get(observed.chainSeq);
  if (entry === undefined) {
    return {
      label: "mirror=mismatch",
      mismatches: [`chain_seq: the verified chain has no entry at seq=${observed.chainSeq}`],
    };
  }
  if (proposalMissingFor(entry, index)) {
    return {
      label:
        "mirror=unverified (the referenced proposal is not on the verified chain — re-run after a full sync)",
      mismatches: [],
    };
  }
  const mismatches = mirrorMismatches(expectedRowFor(entry, observed, index), observed);
  return mismatches.length === 0
    ? { label: "mirror=OK", mismatches }
    : { label: "mirror=mismatch", mismatches };
}

/**
 * The explicit distrust label for a row that carries chain_seq while its
 * event name is outside chain.*.
 *
 * On an honest server the only writer that sets chainSeq is
 * chainMirrorEvents, so this combination shows a forged provenance claim.
 * Starting from the event name alone, a row that escaped one step outside
 * the namespace would display as a bare `chain_seq=N` and would not even
 * fall under verify's eventPrefix=chain. filter.
 */
function outsideChainNamespaceTrust(event: WireAuditEvent): MirrorTrust | null {
  if (event.chainSeq === undefined || event.event.startsWith(CHAIN_MIRROR_EVENT_PREFIX)) {
    return null;
  }
  return {
    label: "mirror=unverified (chain_seq is invalid outside the chain.* namespace)",
    mismatches: [
      `event: chain_seq is present on ${displayText(event.event)}, but only chain.* mirror rows may carry chain provenance`,
    ],
  };
}

/** Provenance judgment of a project audit row. Looks at the presence of chainSeq before the event name. */
export function projectMirrorTrustOf(
  event: WireAuditEvent,
  entries: ReadonlyMap<number, ChainEntry>,
  headSeq: number,
  index: ProposalIndex,
): MirrorTrust | null {
  return (
    outsideChainNamespaceTrust(event) ??
    (event.event.startsWith(CHAIN_MIRROR_EVENT_PREFIX)
      ? mirrorTrustOf(event, entries, headSeq, index)
      : null)
  );
}

/** The D1 path (invites / self) stores no chain provenance. If present: forgery or corruption. */
export function d1MirrorTrustOf(event: WireAuditEvent): MirrorTrust | null {
  if (event.chainSeq === undefined) {
    return null;
  }
  return {
    label: "mirror=unverified (chain_seq is invalid on this audit endpoint)",
    mismatches: [
      `chain_seq: ${event.chainSeq} is present on a D1-backed audit row, but this endpoint does not store chain provenance`,
    ],
  };
}

/** Maps trust mismatches to terminal warnings (empty = unverified but not tamper-decidable on its own). */
export function mirrorWarnings(
  event: WireAuditEvent,
  trust: MirrorTrust | null,
): readonly string[] {
  return (trust?.mismatches ?? []).map(
    (mismatch) =>
      `audit row ${event.id} makes a chain provenance claim that is invalid or does not match the verified chain — ${mismatch} (the audit log is server-managed data, so this mismatch is evidence of server-side tampering or corruption — AUDIT_SPEC §6)`,
  );
}
