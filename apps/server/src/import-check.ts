// The pre-checks of an import job (PF3 — AUTH_SPEC §11-6, docs/notes/pf3-design.md
// ruling H revision): everything that can refuse an import is asked before
// the Durable Object is touched — the snapshot's chain is scanned and
// verified with the verifier the DO runs on load, the identities companion
// is confirmed against that chain's members, and D1 is classified read-only.
// A refusal leaves the destination exactly as it was; a drill job reports
// the same checks as a rehearsal without provisioning anything.
//
// Plain async functions: the restore worker has no Effect runtime.

import { ChainEntrySchema } from "@maruhi/api-schema";
import type { ProjectId, UserId } from "@maruhi/core";
import { decodeProjectId } from "@maruhi/core";
import type { ChainEntry, ChainState } from "@maruhi/crypto";
import {
  canonicalChainEntryBytes,
  computeChainEntryHash,
  verifyChainWithHistory,
} from "@maruhi/crypto";
import { Result, Schema } from "effect";

import type { ImportedIdentity } from "./db.package/index.ts";

/** One chain_entries row as the snapshot carries it (values untyped until checked). */
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
  /** Not gzip, not JSON lines, or a chain table without its columns. */
  | { readonly kind: "snapshot-malformed" }
  /** No chain_entries rows (nothing to import). */
  | { readonly kind: "genesis-missing" }
  /** The rows do not form the chain the DO would accept (a row's hash or size, or the verifier). */
  | { readonly kind: "snapshot-chain-invalid" };

/** Streams the snapshot once and collects its chain_entries rows (the table is last — a full read, like the restore itself). */
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
    // Not gzip, or a truncated stream
    return null;
  }
}

/** One line as JSON (null = not a JSON object — a corrupted evacuation). */
function scannedLine(line: string): ScannedLine | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    return null;
  }
  return typeof parsed === "object" && parsed !== null ? (parsed as ScannedLine) : null;
}

/** Remembers the chain table's columns and collects its rows (other tables pass through). */
class ChainRowCollector {
  readonly rows: ScannedChainRow[] = [];
  #columns: readonly string[] | null = null;

  /** false = the line is not one a snapshot carries (the scan stops). */
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

/** A row's entry as the wire schema accepts it (null = not a chain entry). */
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

/**
 * The snapshot's chain, verified as the DO verifies it on load (and as a
 * mirror verifies a replica — AUTH_SPEC §11-7 `chain-invalid`): every row
 * decodes, sits at its seq, matches its stored hash and canonical size,
 * and the whole chain passes the verifier. The project id is the genesis
 * hash (the restore worker derives the DO name the same way).
 */
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
    ? { kind: "ok", projectId: decodeProjectId(genesis), state: verified.value.state }
    : { kind: "snapshot-chain-invalid" };
}

/** The user ids the verified chain lists as owners (a re-run is accepted under any of their project rows — ruling I revision). */
export function chainOwners(state: ChainState): readonly UserId[] {
  return [...state.members.values()]
    .filter((member) => member.role === "owner")
    .map((member) => member.userId);
}

/**
 * Confirms the companion against the verified chain: it was read at the
 * file's chain head (`identities-stale`), every listed id is a current
 * member (`identity-not-member`) and the exporter is an owner
 * (`exporter-not-owner`). The chain, not the file, decides who is a member.
 */
export function identitiesOnChain(
  state: ChainState,
  file: {
    readonly exportedBy: string;
    readonly chainHeadHashHex: string;
    readonly identities: readonly ImportedIdentity[];
  },
): "identities-stale" | "identity-not-member" | "exporter-not-owner" | null {
  // The companion was read at a chain head: one that is not the file's is
  // a mismatched pair (a member added or removed between the two reads)
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
