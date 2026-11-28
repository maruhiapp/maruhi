import { ChainEntrySchema } from "@maruhi/api-schema";
import type { ProjectId, UserId } from "@maruhi/core";
import type { ChainEntry, ChainState } from "@maruhi/crypto";
import {
  canonicalChainEntryBytes,
  computeChainEntryHash,
  verifyChainWithHistory,
} from "@maruhi/crypto";
import { Result, Schema } from "effect";

import type { ImportedIdentity } from "./db.package/index.ts";
import { projectIdOfGenesisHash } from "./ids.ts";

interface ScannedChainRow {
  readonly seq: unknown;
  readonly entryJson: unknown;
  readonly entryHashHex: unknown;
  readonly canonicalBytes: unknown;
}

interface ScannedLine {
  readonly kind?: unknown;
  readonly table?: unknown;
  readonly columns?: unknown;
  readonly values?: unknown;
}

export type SnapshotChainOutcome =
  | { readonly kind: "ok"; readonly projectId: ProjectId; readonly state: ChainState }
  | { readonly kind: "snapshot-malformed" }
  | { readonly kind: "genesis-missing" }
  | { readonly kind: "snapshot-chain-invalid" };

async function scanChainRows(body: ReadableStream): Promise<readonly ScannedChainRow[] | null> {
  const reader = body
    .pipeThrough(new DecompressionStream("gzip"))
    .pipeThrough(new TextDecoderStream())
    .getReader();
  const collector = new ChainRowCollector();
  const consider = (line: string): boolean => line === "" || collector.consider(line);
  const rows = collector.rows;
  let carry = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        return consider(carry) ? rows : null;
      }
      carry += value;
      let index = carry.indexOf("\n");
      while (index !== -1) {
        if (!consider(carry.slice(0, index))) {
          await reader.cancel();
          return null;
        }
        carry = carry.slice(index + 1);
        index = carry.indexOf("\n");
      }
    }
  } catch {
    return null;
  }
}

function scannedLine(line: string): ScannedLine | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    return null;
  }
  return typeof parsed === "object" && parsed !== null ? (parsed as ScannedLine) : null;
}

class ChainRowCollector {
  readonly rows: ScannedChainRow[] = [];
  #columns: readonly string[] | null = null;

  consider(line: string): boolean {
    const scanned = scannedLine(line);
    if (scanned === null) {
      return false;
    }
    if (scanned.table !== "chain_entries") {
      return true;
    }
    if (scanned.kind === "table") {
      this.#columns = Array.isArray(scanned.columns) ? (scanned.columns as string[]) : null;
      return this.#columns !== null;
    }
    return scanned.kind === "row" ? this.#collect(scanned.values) : true;
  }

  #collect(values: unknown): boolean {
    const columns = this.#columns;
    if (columns === null || !Array.isArray(values)) {
      return false;
    }
    const at = (name: string): unknown => (values as unknown[])[columns.indexOf(name)];
    this.rows.push({
      seq: at("seq"),
      entryJson: at("entry_json"),
      entryHashHex: at("entry_hash_hex"),
      canonicalBytes: at("canonical_bytes"),
    });
    return true;
  }
}

function decodeEntry(text: unknown): ChainEntry | null {
  if (typeof text !== "string") {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  const decoded = Schema.decodeUnknownResult(ChainEntrySchema)(parsed);
  return Result.isSuccess(decoded) ? (decoded.success as ChainEntry) : null;
}

function canonicalLength(entry: ChainEntry): number {
  try {
    return canonicalChainEntryBytes(entry).length;
  } catch {
    return -1;
  }
}

export async function verifySnapshotChain(body: ReadableStream): Promise<SnapshotChainOutcome> {
  const rows = await scanChainRows(body);
  if (rows === null) {
    return { kind: "snapshot-malformed" };
  }
  if (rows.length === 0) {
    return { kind: "genesis-missing" };
  }
  const entries: ChainEntry[] = [];
  for (const [index, row] of rows.entries()) {
    const entry = decodeEntry(row.entryJson);
    if (
      entry === null ||
      row.seq !== index + 1 ||
      entry.seq !== row.seq ||
      typeof row.entryHashHex !== "string" ||
      (await computeChainEntryHash(entry)) !== row.entryHashHex ||
      canonicalLength(entry) !== row.canonicalBytes
    ) {
      return { kind: "snapshot-chain-invalid" };
    }
    entries.push(entry);
  }
  const verified = await verifyChainWithHistory(entries);
  if (!verified.ok) {
    return { kind: "snapshot-chain-invalid" };
  }
  const genesis = rows[0]?.entryHashHex;
  return typeof genesis === "string"
    ? { kind: "ok", projectId: projectIdOfGenesisHash(genesis), state: verified.value.state }
    : { kind: "snapshot-chain-invalid" };
}

export function chainOwners(state: ChainState): readonly UserId[] {
  return [...state.members.values()]
    .filter((member) => member.role === "owner")
    .map((member) => member.userId);
}

export function identitiesOnChain(
  state: ChainState,
  file: {
    readonly exportedBy: string;
    readonly chainHeadHashHex: string;
    readonly identities: readonly ImportedIdentity[];
  },
): "identities-stale" | "identity-not-member" | "exporter-not-owner" | null {
  if (file.chainHeadHashHex !== state.headHashHex) {
    return "identities-stale";
  }
  for (const identity of file.identities) {
    const member = state.members.get(identity.userId);
    if (member === undefined) {
      return "identity-not-member";
    }
    if (identity.userId === file.exportedBy && member.role !== "owner") {
      return "exporter-not-owner";
    }
  }
  return null;
}
