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

interface FoldState {
  chainHead: ChainHeadFloor | null;
  readonly environments: Map<string, EnvironmentFloor>;
  readonly conflicts: Map<string, FloorConflict>;
  readonly intents: Map<string, FloorIntent>;
}

function conflictKey(conflict: FloorConflict): string {
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
      return;
  }
}

export interface FoldOutcome {
  readonly floor: ProjectFloor;
  readonly decodedRecords: number;
  readonly droppedLines: number;
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
      droppedAtRecordCount.push(records.length);
      continue;
    }
    records.push(record);
  }
  return { records, droppedAtRecordCount };
}

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
    droppedLines: droppedAtRecordCount.filter((position) => position >= foldFrom).length,
    recordsSinceSnapshot: snapshotIndex >= 0 ? records.length - 1 - snapshotIndex : records.length,
  };
}
