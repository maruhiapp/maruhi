// AUDIT_SPEC §5.1: the normalized form of the audit-head cumulative hash.
//
//   row_digest = lower_hex(SHA-256(LP(seq, row_id, server_ts, client_ts, event,
//                                     actor_type, actor_user_id,
//                                     actor_key_fingerprint, actor_api_token_id,
//                                     target_user_id, target_key_fingerprint,
//                                     environment_id, variable_id, epoch,
//                                     version, chain_seq, payload)))
//   h_n = lower_hex(SHA-256(LP("<suite>/audit-head", h_{n-1}, seq, row_digest)))
//     (h_0 = the empty string. h_{n-1} / row_digest go onto the LP field as
//      lowercase hex **strings** — the uniform representation pinned by audit-head.json)
//
// - NULL-allowed columns (the 13 columns other than seq / server_ts / event /
//   actor_type) are tagged byte strings: NULL = the single byte 0x00;
//   non-NULL = 0x01 + the value's bytes
//   (NULL and the empty string must not share a preimage — §5.1)
// - Numbers use the §2.1 base-10 stringification. payload uses the stored
//   TEXT's bytes as-is (no JSON normalization — §5.1)
// - The producing side is the project DO (acceptance verification and
//   GET /audit-head — AUTH_SPEC §16-2); the verifying side is the admin's
//   cross-check (AUDIT_SPEC §6 — the follow-up CLI tool). Both share this
//   single implementation. Test vectors: test-vectors/audit-head.json

import type { EnvironmentId, VariableId } from "./chain-types.ts";
import { concatBytes, encodeHex, utf8Encode } from "./bytes.ts";
import { encodeLengthPrefixed, type LengthPrefixedField } from "./encoding.ts";
import type { CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import { invalidInput, isLowercaseHexOfLength } from "./validate.ts";

const SHA256_HEX_LENGTH = 32 * 2;

/**
 * One audit-event row as stored by the project DO (AUDIT_SPEC §5.1 — the
 * fixed 17-column enumeration). `null` means the stored column is NULL,
 * which is digested distinctly from the empty string (tagged bytes).
 * `payloadText` is the stored TEXT exactly as persisted (no JSON
 * re-normalization).
 */
export interface AuditHeadRow {
  readonly seq: number;
  readonly rowId: string | null;
  readonly serverTs: number;
  readonly clientTs: number | null;
  readonly event: string;
  readonly actorType: string;
  readonly actorUserId: string | null;
  readonly actorKeyFingerprintHex: string | null;
  readonly actorApiTokenId: string | null;
  readonly targetUserId: string | null;
  readonly targetKeyFingerprintHex: string | null;
  readonly environmentId: EnvironmentId | null;
  readonly variableId: VariableId | null;
  readonly epoch: number | null;
  readonly version: number | null;
  readonly chainSeq: number | null;
  readonly payloadText: string | null;
}

function isCountingNumber(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

/** A tagged byte string (NULL = 0x00 / non-NULL = 0x01 + the value's bytes — §5.1). */
function taggedField(value: string | null): Uint8Array {
  if (value === null) {
    return Uint8Array.of(0x00);
  }
  return concatBytes(Uint8Array.of(0x01), utf8Encode(value));
}

function taggedNumberField(value: number | null, field: string): CryptoResult<Uint8Array> {
  if (value === null) {
    return { ok: true, value: Uint8Array.of(0x00) };
  }
  if (!isCountingNumber(value)) {
    return invalidInput(field);
  }
  return { ok: true, value: taggedField(String(value)) };
}

/**
 * Computes the canonical digest of one audit row (AUDIT_SPEC §5.1). Rejects
 * non-safe-integer numeric inputs (the §2.1 numeric bounds — fail-closed).
 */
export async function computeAuditRowDigest(row: AuditHeadRow): Promise<CryptoResult<string>> {
  if (!isCountingNumber(row.seq) || row.seq < 1) {
    return invalidInput("seq");
  }
  if (!isCountingNumber(row.serverTs)) {
    return invalidInput("serverTs");
  }
  const clientTs = taggedNumberField(row.clientTs, "clientTs");
  if (!clientTs.ok) {
    return clientTs;
  }
  const epoch = taggedNumberField(row.epoch, "epoch");
  if (!epoch.ok) {
    return epoch;
  }
  const version = taggedNumberField(row.version, "version");
  if (!version.ok) {
    return version;
  }
  const chainSeq = taggedNumberField(row.chainSeq, "chainSeq");
  if (!chainSeq.ok) {
    return chainSeq;
  }
  const fields: LengthPrefixedField[] = [
    row.seq,
    taggedField(row.rowId),
    row.serverTs,
    clientTs.value,
    row.event,
    row.actorType,
    taggedField(row.actorUserId),
    taggedField(row.actorKeyFingerprintHex),
    taggedField(row.actorApiTokenId),
    taggedField(row.targetUserId),
    taggedField(row.targetKeyFingerprintHex),
    taggedField(row.environmentId),
    taggedField(row.variableId),
    epoch.value,
    version.value,
    chainSeq.value,
    taggedField(row.payloadText),
  ];
  return { ok: true, value: encodeHex(await sha256(encodeLengthPrefixed(fields))) };
}

/**
 * Advances the cumulative audit-head hash by one row (AUDIT_SPEC §5.1):
 * `h_n = lower_hex(SHA-256(LP("<suite>/audit-head", h_{n-1}, seq,
 * row_digest)))`. `prevHeadHashHex` is the empty string for the first row
 * (h_0), otherwise the previous 64-char lowercase-hex head.
 */
export async function computeAuditHeadHash(
  suite: string,
  prevHeadHashHex: string,
  seq: number,
  rowDigestHex: string,
): Promise<CryptoResult<string>> {
  if (suite.length === 0) {
    return invalidInput("suite");
  }
  if (!isCountingNumber(seq) || seq < 1) {
    return invalidInput("seq");
  }
  if (prevHeadHashHex !== "" && !isLowercaseHexOfLength(prevHeadHashHex, SHA256_HEX_LENGTH)) {
    return invalidInput("prevHeadHashHex");
  }
  if (!isLowercaseHexOfLength(rowDigestHex, SHA256_HEX_LENGTH)) {
    return invalidInput("rowDigestHex");
  }
  const preimage = encodeLengthPrefixed([
    `${suite}/audit-head`,
    prevHeadHashHex,
    seq,
    rowDigestHex,
  ]);
  return { ok: true, value: encodeHex(await sha256(preimage)) };
}
