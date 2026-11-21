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

export type WireAuditEvent = typeof AuditEventSchema.Type;

function jsonRecordEqual(left: Record<string, unknown>, right: Record<string, unknown>): boolean {
  const keys = Object.keys(left);
  return (
    keys.length === Object.keys(right).length &&
    keys.every((key) => key in right && jsonEqual(left[key], right[key]))
  );
}

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

export function expectedRowFor(
  entry: ChainEntry,
  observed: WireAuditEvent,
  index: ProposalIndex,
): AuditEventRecord {
  const rows = chainMirrorEvents(entry, observed.serverTs, index);
  const first = rows[0];
  if (first === undefined) {
    throw new Error("chain mirror mapping produced no rows");
  }
  return rows.find((row) => row.event === observed.event) ?? first;
}

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
  check("actor.api_token_id", expected.actorApiTokenId, observed.actor.apiTokenId);
  check("environment_id", expected.environmentId, observed.environmentId);
  check("variable_id", expected.variableId, observed.variableId);
  check("epoch", expected.epoch, observed.epoch);
  check("version", expected.version, observed.version);
  check("payload", expected.payload, observed.payload);
  return reasons;
}

export function proposalMissingFor(entry: ChainEntry, index: ProposalIndex): boolean {
  return (
    (entry.op === "approve" || entry.op === "withdraw") && !index.has(entry.payload.proposalHashHex)
  );
}

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

export function mirrorWarnings(
  event: WireAuditEvent,
  trust: MirrorTrust | null,
): readonly string[] {
  return (trust?.mismatches ?? []).map(
    (mismatch) =>
      `audit row ${event.id} makes a chain provenance claim that is invalid or does not match the verified chain — ${mismatch} (the audit log is server-managed data, so this mismatch is evidence of server-side tampering or corruption — AUDIT_SPEC §6)`,
  );
}
