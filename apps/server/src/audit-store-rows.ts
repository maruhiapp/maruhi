// The audit store's stored-row decoders, shared by the head derivation
// (audit-store.ts) and both read surfaces (audit-store-query.ts and
// audit-store-rotation-read.ts).

import { decodeKeyFingerprintHex, decodeUserId } from "@maruhi/core";
import type { AuditHeadRow } from "@maruhi/crypto";

/**
 * The fixed 17 columns of an audit row, in the column order of AUDIT_SPEC
 * §5.1: what the head derivation reads (the input of row_digest) and what
 * the generic read selects (same order as StoredAuditEventRow).
 */
export const AUDIT_ROW_COLUMNS = `seq, row_id, server_ts, client_ts, event, actor_type, actor_user_id,
  actor_key_fingerprint, actor_api_token_id, target_user_id, target_key_fingerprint,
  environment_id, variable_id, epoch, version, chain_seq, payload`;

export function toAuditHeadRow(row: Record<string, unknown>): AuditHeadRow {
  return {
    seq: Number(row["seq"]),
    rowId: textOrNull(row["row_id"]),
    serverTs: Number(row["server_ts"]),
    clientTs: numberOrNull(row["client_ts"]),
    event: String(row["event"]),
    actorType: String(row["actor_type"]),
    actorUserId: brandOrNull(row["actor_user_id"], decodeUserId),
    actorKeyFingerprintHex: brandOrNull(row["actor_key_fingerprint"], decodeKeyFingerprintHex),
    actorApiTokenId: textOrNull(row["actor_api_token_id"]),
    targetUserId: brandOrNull(row["target_user_id"], decodeUserId),
    targetKeyFingerprintHex: brandOrNull(row["target_key_fingerprint"], decodeKeyFingerprintHex),
    environmentId: textOrNull(row["environment_id"]),
    variableId: textOrNull(row["variable_id"]),
    epoch: numberOrNull(row["epoch"]),
    version: numberOrNull(row["version"]),
    chainSeq: numberOrNull(row["chain_seq"]),
    // payload is the stored TEXT bytes verbatim (no JSON normalization — §5.1)
    payloadText: textOrNull(row["payload"]),
  };
}

const textOrNull = (value: unknown): string | null => (value === null ? null : String(value));

/** A NULL-or-brand column read (the mint is the stored-row decode boundary). */
export const brandOrNull = <B>(value: unknown, decode: (s: string) => B): B | null =>
  value === null ? null : decode(String(value));
export const numberOrNull = (value: unknown): number | null =>
  value === null ? null : Number(value);

/** Defensive parse of the payload column (JSON) (a broken row is treated as null — detection is never made a defect). */
export function parsePayload(value: unknown): Readonly<Record<string, unknown>> | null {
  if (typeof value !== "string") {
    return null;
  }
  try {
    const parsed: unknown = JSON.parse(value);
    return typeof parsed === "object" && parsed !== null
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}
