// The fold: the observation-log records -> the floor (the join of
// verified observations). The storage form's overview lives in
// floor-log.ts; the record format and strict decoding live in
// floor-log-decode.ts.

import type { EnvironmentId } from "@maruhi/core";

import { decodeLogRecord, type FloorLogRecord, type SnapshotState } from "./floor-log-decode.ts";
import {
  type ChainHeadFloor,
  emptyEnvironmentFloor,
  type EnvironmentFloor,
  type FloorConflict,
  type FloorIntent,
  joinChainHead,
  joinEnvironmentFloor,
  type ProjectFloor,
} from "./floor.ts";

// ---- fold (observation log → floor) ----

interface FoldState {
  chainHead: ChainHeadFloor | null;
  readonly environments: Map<string, EnvironmentFloor>;
  readonly conflicts: Map<string, FloorConflict>;
  readonly intents: Map<string, FloorIntent>;
}

function conflictKey(conflict: FloorConflict): string {
  // Re-derivation of the same conflict (fold runs every time) and
  // snapshot-derived duplicates are identified by coordinates + both
  // evidence values. The evidence ordering is normalized independently of
  // the join's representative selection
  const pair = [
    `${conflict.firstVersion}:${conflict.firstHashHex}`,
    `${conflict.secondVersion}:${conflict.secondHashHex}`,
  ].toSorted();
  return `${conflict.kind}|${conflict.environmentId ?? ""}|${conflict.variableId ?? ""}|${pair.join("|")}`;
}

function addConflict(state: FoldState, conflict: FloorConflict): void {
  const key = conflictKey(conflict);
  if (!state.conflicts.has(key)) {
    state.conflicts.set(key, conflict);
  }
}

function joinEnvironmentInto(
  state: FoldState,
  environmentId: EnvironmentId,
  incoming: EnvironmentFloor,
): void {
  const sink = (conflict: FloorConflict) => addConflict(state, conflict);
  state.environments.set(
    environmentId,
    joinEnvironmentFloor(environmentId, state.environments.get(environmentId), incoming, sink),
  );
}

function applyRecord(state: FoldState, record: FloorLogRecord): void {
  const sink = (conflict: FloorConflict) => addConflict(state, conflict);
  switch (record.r) {
    case "head":
      state.chainHead = joinChainHead(state.chainHead, record.head, sink);
      return;
    case "pull":
      state.chainHead = joinChainHead(state.chainHead, record.head, sink);
      joinEnvironmentInto(state, record.environmentId, record.environment);
      return;
    case "push":
      state.chainHead = joinChainHead(state.chainHead, record.head, sink);
      joinEnvironmentInto(state, record.environmentId, {
        ...emptyEnvironmentFloor(),
        variables: { [record.variableId]: record.variable },
      });
      return;
    case "meta":
      state.chainHead = joinChainHead(state.chainHead, record.head, sink);
      joinEnvironmentInto(state, record.environmentId, {
        ...emptyEnvironmentFloor(),
        observedEpoch: record.observedEpoch,
        metaVersion: record.metaVersion,
        metaSigHashHex: record.metaSigHashHex,
        manifest: record.manifest,
      });
      return;
    case "manifest":
      state.chainHead = joinChainHead(state.chainHead, record.head, sink);
      joinEnvironmentInto(state, record.environmentId, {
        ...emptyEnvironmentFloor(),
        // A manifest is a verified observation, so its epoch also joins
        // as an environment-level epoch observation (coordinate (ii))
        // (the pull baseline (i) is not moved)
        observedEpoch: record.manifest.epoch,
        manifest: record.manifest,
      });
      return;
    case "intent":
      state.intents.set(record.intent.id, record.intent);
      return;
    case "resolution":
      state.intents.delete(record.intentId);
      return;
    case "snapshot":
      // A no-op on the fold side (foldRecords chooses the base point — a double fold is harmless)
      return;
  }
}

export interface FoldOutcome {
  readonly floor: ProjectFloor;
  /** The total decodable record count (the basis position for a snapshot's `folded`). */
  readonly decodedRecords: number;
  /** The number of non-empty lines that failed to decode (torn-line self-healing — diagnostic). */
  readonly droppedLines: number;
  /** The record count accumulated after the latest snapshot record (the compaction trigger). */
  readonly recordsSinceSnapshot: number;
}

function baseStateOf(snapshot: { folded: number; state: SnapshotState } | null): FoldState {
  if (snapshot === null) {
    return { chainHead: null, environments: new Map(), conflicts: new Map(), intents: new Map() };
  }
  const state: FoldState = {
    chainHead: snapshot.state.chainHead,
    environments: new Map(Object.entries(snapshot.state.environments)),
    conflicts: new Map(),
    intents: new Map(snapshot.state.intents.map((intent) => [intent.id, intent])),
  };
  for (const conflict of snapshot.state.conflicts) {
    addConflict(state, conflict);
  }
  return state;
}

/**
 * Lines → the decodable record list + the positions of dropped non-empty
 * lines (torn-line self-healing). A position = the number of records
 * decoded just before that line — a dropped line before the fold base
 * (the snapshot's folded) sits "inside the folded prefix" and is out of
 * the warning's scope (compaction naturally retires the warning — a
 * permanently ringing noise must not share the equivocation warning's
 * band).
 */
function parseLogLines(lines: readonly string[]): {
  readonly records: FloorLogRecord[];
  readonly droppedAtRecordCount: readonly number[];
} {
  const records: FloorLogRecord[] = [];
  const droppedAtRecordCount: number[] = [];
  for (const line of lines) {
    if (line.trim() === "") {
      continue;
    }
    const record = decodeLogRecord(line);
    if (record === null) {
      // Self-healing of a torn line (an interrupted write by a crashed
      // concurrent process). A conflict's evidence line is valid JSON, so
      // it is not lost here
      droppedAtRecordCount.push(records.length);
      continue;
    }
    records.push(record);
  }
  return { records, droppedAtRecordCount };
}

/**
 * The fold base = the latest valid snapshot. When "the end position of
 * the folded prefix (folded)" exceeds the snapshot's own position
 * (corrupt), fall back to folding all records — the join's idempotence
 * and commutativity keep correctness invariant (only the cost changes —
 * §6.3).
 */
function foldBase(records: readonly FloorLogRecord[]): {
  readonly foldFrom: number;
  readonly snapshotIndex: number;
  readonly state: FoldState;
} {
  for (let index = records.length - 1; index >= 0; index -= 1) {
    const record = records[index];
    if (record?.r === "snapshot") {
      const usable = record.folded <= index;
      return {
        foldFrom: usable ? record.folded : 0,
        snapshotIndex: index,
        state: baseStateOf(usable ? record : null),
      };
    }
  }
  return { foldFrom: 0, snapshotIndex: -1, state: baseStateOf(null) };
}

export function foldRecords(lines: readonly string[]): FoldOutcome {
  const { records, droppedAtRecordCount } = parseLogLines(lines);
  const { foldFrom, snapshotIndex, state } = foldBase(records);
  for (let index = foldFrom; index < records.length; index += 1) {
    applyRecord(state, records[index] as FloorLogRecord);
  }
  return {
    floor: {
      chainHead: state.chainHead,
      environments: Object.fromEntries(state.environments),
      conflicts: [...state.conflicts.values()],
      intents: [...state.intents.values()],
    },
    decodedRecords: records.length,
    // Count only dropped lines after the fold base (before it they are
    // inside the prefix folded into the snapshot — do not ring an
    // already-warned old torn line forever)
    droppedLines: droppedAtRecordCount.filter((position) => position >= foldFrom).length,
    recordsSinceSnapshot: snapshotIndex >= 0 ? records.length - 1 - snapshotIndex : records.length,
  };
}
