import { concatBytes, encodeHex, utf8Encode } from "./bytes.ts";
import { encodeLengthPrefixed, type LengthPrefixedField } from "./encoding.ts";
import type { CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import { invalidInput, isLowercaseHexOfLength } from "./validate.ts";

const SHA256_HEX_LENGTH = 32 * 2;

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
  readonly environmentId: string | null;
  readonly variableId: string | null;
  readonly epoch: number | null;
  readonly version: number | null;
  readonly chainSeq: number | null;
  readonly payloadText: string | null;
}

function isCountingNumber(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

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
