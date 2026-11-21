import { decodeKeyFingerprintHex, decodeUserId } from "@maruhi/core";
import type { AuditHeadRow } from "@maruhi/crypto";

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
    payloadText: textOrNull(row["payload"]),
  };
}

const textOrNull = (value: unknown): string | null => (value === null ? null : String(value));

export const brandOrNull = <B>(value: unknown, decode: (s: string) => B): B | null => {
  if (value === null) {
    return null;
  }
  try {
    return decode(String(value));
  } catch {
    return null;
  }
};
export const numberOrNull = (value: unknown): number | null =>
  value === null ? null : Number(value);

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
