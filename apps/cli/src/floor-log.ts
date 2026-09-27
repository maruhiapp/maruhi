// The local floor's storage form: an append-only observation log + fold
// (CRYPTO_SPEC §6.3's 3-E / 3-E′ / 3-F).
//
// - The floor file is an "append-only log of verified observations (one
//   observation = one JSONL line)", and the floor is **derived** as the
//   join produced by folding the log. An overwrite-update storage form
//   (read, merge, write back) is not used — observations of concurrent
//   processes both remain in the log, and a same-coordinate conflict
//   surfaces as a typed conflict at fold time (**evidence loss via
//   overwrite goes from "forbidden" to "inexpressible"**). In M1 there
//   is no inter-process lock at all (appends only)
// - Appends go only through append mode (O_APPEND equivalent) and **wait
//   for fsync-equivalent durability** (3-E′ — the "record" standard of
//   journal-before-release / before-send)
// - Corrupt records (torn writes from a crash or power loss) are ignored
//   by fold (self-healing). Because every append is **prefixed** with a
//   newline, a torn line never corrupts later records (no tail-end
//   check — see appendRecords's JSDoc)
// - Compaction only happens by **appending a snapshot record** holding
//   "the current fold result + the end position of the folded prefix"
//   (the trigger is exceeding a threshold of the relative amount
//   accumulated after the latest snapshot record). M1 never rewrites,
//   truncates, or physically reclaims (to be designed together with
//   M2's checkpoint-baseline linking). The evidence of a same-coordinate
//   conflict is not lost by being folded into a snapshot
// - intent / resolution records (3-F) are a separate class that does not
//   enter the join's lattice — fold surfaces an unresolved intent as
//   "needs reconciliation"

import {
  type FileHandle,
  mkdir,
  open,
  readdir,
  readFile,
  rename,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";

import { isEnvironmentId, isProjectId, isVariableId } from "@maruhi/core";
import { Effect } from "effect";

import { cliError, type CliError } from "./errors.ts";
import { formatFloorConflicts } from "./floor-evidence.ts";
import {
  type AttestationEvidenceRecord,
  type ChainHeadFloor,
  emptyEnvironmentFloor,
  type EnvironmentFloor,
  type FloorConflict,
  type FloorIntent,
  type FloorIntentInput,
  type FloorIntentOutcome,
  type FloorLoadResult,
  floorRecordGet,
  type FloorStoreShape,
  joinChainHead,
  joinEnvironmentFloor,
  type ManifestCommit,
  type ManifestFloor,
  type MetadataCommit,
  type ProjectFloor,
  type PullCommit,
  type PushCommit,
  type VariableFloor,
} from "./floor.ts";

/**
 * The compaction trigger: a threshold on the number of records
 * accumulated after the latest snapshot record (a relative amount — a
 * total-file-size basis is not used because once exceeded it holds
 * forever). Bounding the fold cost is carried by this relative basis
 * itself.
 */
const DEFAULT_COMPACTION_THRESHOLD = 256;

/** The cap on full-length rewrite retries of one logical append (short write — appendAll). */
const MAX_APPEND_WRITE_ATTEMPTS = 3;

/** A snapshot record's content (= the fold result, including conflicts / intents). */
interface SnapshotState {
  readonly chainHead: ChainHeadFloor | null;
  readonly environments: Readonly<Record<string, EnvironmentFloor>>;
  readonly conflicts: readonly FloorConflict[];
  readonly intents: readonly FloorIntent[];
}

/** An observation-log record (one line = one record). */
type FloorLogRecord =
  | { readonly r: "head"; readonly head: ChainHeadFloor }
  | {
      readonly r: "pull";
      readonly head: ChainHeadFloor;
      readonly environmentId: string;
      readonly environment: EnvironmentFloor;
    }
  | {
      readonly r: "push";
      readonly head: ChainHeadFloor;
      readonly environmentId: string;
      readonly variableId: string;
      readonly variable: VariableFloor;
    }
  | {
      readonly r: "meta";
      readonly head: ChainHeadFloor;
      readonly environmentId: string;
      readonly observedEpoch: number;
      readonly metaVersion: number;
      readonly metaSigHashHex: string;
      readonly manifest: ManifestFloor;
    }
  | {
      readonly r: "manifest";
      readonly head: ChainHeadFloor;
      readonly environmentId: string;
      readonly manifest: ManifestFloor;
    }
  | { readonly r: "intent"; readonly intent: FloorIntent }
  | {
      readonly r: "resolution";
      readonly intentId: string;
      readonly outcome: FloorIntentOutcome;
    }
  | {
      /**
       * Compaction: `folded` is the end position of the folded prefix
       * (the count of already-folded decodable records before this
       * record). fold is "the snapshot's state ⊔ all records at position
       * `folded` onward" — even if a concurrent append lands
       * between the snapshot's read and write, the join's idempotence and
       * commutativity make a double fold harmless, and the position basis
       * prevents drops. If the position is corrupt it falls back to
       * folding all records (correctness is unchanged — §6.3).
       */
      readonly r: "snapshot";
      readonly folded: number;
      readonly state: SnapshotState;
    };

// ---- Strict decoding (per-record; a broken line is ignored by fold = self-healing) ----

const HEX_64 = /^[0-9a-f]{64}$/;
const INTENT_ID = /^[0-9a-f]{16}$/;

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isPositiveInteger(value: unknown): value is number {
  return isNonNegativeInteger(value) && value > 0;
}

function isHex64(value: unknown): value is string {
  return typeof value === "string" && HEX_64.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// @maruhi/core's ID guards take a string — wrap the two-stage guard from unknown here
function isEnvironmentIdValue(value: unknown): value is string {
  return typeof value === "string" && isEnvironmentId(value);
}

function isVariableIdValue(value: unknown): value is string {
  return typeof value === "string" && isVariableId(value);
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}

const isNullOr =
  (check: (value: unknown) => boolean) =>
  (value: unknown): boolean =>
    value === null || check(value);

/**
 * Bulk field-spec check. Folds the strict decode's `||` chain (one
 * condition = one branch) into data — satisfies fallow's complexity gate
 * and makes the spec's enumeration visibly a field table.
 */
function fieldsValid(
  record: Record<string, unknown>,
  spec: Readonly<Record<string, (value: unknown) => boolean>>,
): boolean {
  return Object.entries(spec).every(([key, check]) => check(record[key]));
}

/** Returns the array only when every element decodes strictly (a single corrupt item yields null). */
function decodeList<T>(value: unknown, decode: (item: unknown) => T | null): T[] | null {
  if (!Array.isArray(value)) {
    return null;
  }
  const items: T[] = [];
  for (const raw of value) {
    const item = decode(raw);
    if (item === null) {
      return null;
    }
    items.push(item);
  }
  return items;
}

function decodeChainHead(value: unknown): ChainHeadFloor | null {
  if (!isRecord(value) || !isPositiveInteger(value["seq"]) || !isHex64(value["hashHex"])) {
    return null;
  }
  return { seq: value["seq"], hashHex: value["hashHex"] };
}

/** Decoding an active variable-floor's value-side fields (the meta side is shared — decodeVariableFloor). */
function decodeActiveValueSide(
  value: Record<string, unknown>,
): Pick<
  Extract<VariableFloor, { status: "active" }>,
  "version" | "epoch" | "valueSigHashHex"
> | null {
  if (
    !isPositiveInteger(value["version"]) ||
    !isPositiveInteger(value["epoch"]) ||
    !isHex64(value["valueSigHashHex"])
  ) {
    return null;
  }
  return {
    version: value["version"],
    epoch: value["epoch"],
    valueSigHashHex: value["valueSigHashHex"],
  };
}

function decodeVariableFloor(value: unknown): VariableFloor | null {
  if (!isRecord(value)) {
    return null;
  }
  if (!isPositiveInteger(value["metaVersion"]) || !isHex64(value["metaSigHashHex"])) {
    return null;
  }
  const meta = {
    metaVersion: value["metaVersion"],
    metaSigHashHex: value["metaSigHashHex"],
  };
  // deleted / declared (layout v2's no-value-set declaration, §4.2) carry the meta side only (the value floor is empty)
  if (value["status"] === "deleted" || value["status"] === "declared") {
    return { status: value["status"], ...meta };
  }
  if (value["status"] !== "active") {
    return null;
  }
  const valueSide = decodeActiveValueSide(value);
  return valueSide === null ? null : { status: "active", ...valueSide, ...meta };
}

function decodeManifestFloor(value: unknown): ManifestFloor | null {
  if (
    !isRecord(value) ||
    !isPositiveInteger(value["manifestVersion"]) ||
    !isPositiveInteger(value["epoch"]) ||
    !isHex64(value["manifestSigHashHex"])
  ) {
    return null;
  }
  return {
    manifestVersion: value["manifestVersion"],
    epoch: value["epoch"],
    manifestSigHashHex: value["manifestSigHashHex"],
  };
}

// Record keys (environmentId / variableId) must satisfy §12-1's accepted
// form. A proper floor writes only wire-schema-verified (or CLI-assigned)
// IDs, so an out-of-form key = rejected as corruption per line. This
// structurally excludes `__proto__` (a leading `_` is out of form).
// `constructor` / `prototype` are legitimate IDs and are not refused (the
// read side is protected by floorRecordGet's own-property lookup)
function decodeVariablesRecord(value: unknown): Record<string, VariableFloor> | null {
  if (!isRecord(value)) {
    return null;
  }
  const variables: Record<string, VariableFloor> = {};
  for (const [variableId, raw] of Object.entries(value)) {
    const variable = decodeVariableFloor(raw);
    if (variable === null || !isVariableId(variableId)) {
      return null;
    }
    variables[variableId] = variable;
  }
  return variables;
}

/** The shared decode of manifest (optional) + variables (the tail shared by the new and old forms). */
function decodeManifestAndVariables(
  value: Record<string, unknown>,
): { readonly manifest?: ManifestFloor; readonly variables: Record<string, VariableFloor> } | null {
  const manifest =
    value["manifest"] === undefined ? undefined : decodeManifestFloor(value["manifest"]);
  const variables = decodeVariablesRecord(value["variables"]);
  if (manifest === null || variables === null) {
    return null;
  }
  return { ...(manifest === undefined ? {} : { manifest }), variables };
}

/** The environment floor (new form — admits the bottom coordinates: pullEpoch / observedEpoch / metaVersion = 0). */
function decodeEnvironmentFloor(value: unknown): EnvironmentFloor | null {
  if (
    !isRecord(value) ||
    !fieldsValid(value, {
      pullEpoch: isNonNegativeInteger,
      observedEpoch: isNonNegativeInteger,
      metaVersion: isNonNegativeInteger,
    })
  ) {
    return null;
  }
  const metaSigHashHex = value["metaSigHashHex"];
  const metaValid = value["metaVersion"] === 0 ? metaSigHashHex === "" : isHex64(metaSigHashHex);
  const tail = decodeManifestAndVariables(value);
  if (!metaValid || tail === null) {
    return null;
  }
  return {
    pullEpoch: value["pullEpoch"] as number,
    observedEpoch: value["observedEpoch"] as number,
    metaVersion: value["metaVersion"] as number,
    metaSigHashHex: metaSigHashHex as string,
    ...tail,
  };
}

function decodeEnvironmentsRecord(value: unknown): Record<string, EnvironmentFloor> | null {
  if (!isRecord(value)) {
    return null;
  }
  const environments: Record<string, EnvironmentFloor> = {};
  for (const [environmentId, raw] of Object.entries(value)) {
    const environment = decodeEnvironmentFloor(raw);
    if (environment === null || !isEnvironmentId(environmentId)) {
      return null;
    }
    environments[environmentId] = environment;
  }
  return environments;
}

const CONFLICT_KINDS: readonly FloorConflict["kind"][] = [
  "chain-head",
  "value",
  "variable-meta",
  "environment-meta",
  "manifest",
  "undeletion",
];

function decodeConflict(value: unknown): FloorConflict | null {
  if (
    !isRecord(value) ||
    !fieldsValid(value, {
      kind: (kind) => CONFLICT_KINDS.includes(kind as FloorConflict["kind"]),
      environmentId: isNullOr(isEnvironmentIdValue),
      variableId: isNullOr(isVariableIdValue),
      firstVersion: isNonNegativeInteger,
      firstHashHex: isString,
      secondVersion: isNonNegativeInteger,
      secondHashHex: isString,
    })
  ) {
    return null;
  }
  return {
    kind: value["kind"] as FloorConflict["kind"],
    environmentId: value["environmentId"] as string | null,
    variableId: value["variableId"] as string | null,
    firstVersion: value["firstVersion"] as number,
    firstHashHex: value["firstHashHex"] as string,
    secondVersion: value["secondVersion"] as number,
    secondHashHex: value["secondHashHex"] as string,
  };
}

const INTENT_OPS: readonly FloorIntent["op"][] = ["create_environment", "rotate_epoch", "meta-op"];
const INTENT_OUTCOMES: readonly FloorIntentOutcome[] = [
  "accepted",
  "accepted-superseded",
  "rejected",
  "not-accepted",
  "superseded",
];

function decodeIntent(value: unknown): FloorIntent | null {
  if (
    !isRecord(value) ||
    !fieldsValid(value, {
      id: (id) => isString(id) && INTENT_ID.test(id),
      op: (op) => INTENT_OPS.includes(op as FloorIntent["op"]),
      environmentId: isEnvironmentIdValue,
      epoch: isPositiveInteger,
      dekCommitmentHex: isNullOr(isHex64),
      variableId: isNullOr(isVariableIdValue),
      manifestVersion: isPositiveInteger,
      manifestSigHashHex: isHex64,
    })
  ) {
    return null;
  }
  const declaredHead = decodeChainHead(value["declaredHead"]);
  if (declaredHead === null) {
    return null;
  }
  return {
    id: value["id"] as string,
    op: value["op"] as FloorIntent["op"],
    environmentId: value["environmentId"] as string,
    epoch: value["epoch"] as number,
    dekCommitmentHex: value["dekCommitmentHex"] as string | null,
    variableId: value["variableId"] as string | null,
    manifestVersion: value["manifestVersion"] as number,
    manifestSigHashHex: value["manifestSigHashHex"] as string,
    declaredHead,
  };
}

function decodeSnapshotState(value: unknown): SnapshotState | null {
  if (!isRecord(value)) {
    return null;
  }
  const chainHead = value["chainHead"] === null ? null : decodeChainHead(value["chainHead"]);
  if (chainHead === null && value["chainHead"] !== null) {
    return null;
  }
  const environments = decodeEnvironmentsRecord(value["environments"]);
  const conflicts = decodeList(value["conflicts"], decodeConflict);
  const intents = decodeList(value["intents"], decodeIntent);
  if (environments === null || conflicts === null || intents === null) {
    return null;
  }
  return { chainHead, environments, conflicts, intents };
}

/** Decoding the shared part (head + environmentId) of environment-scoped records. */
function decodeScoped(
  value: Record<string, unknown>,
): { readonly head: ChainHeadFloor; readonly environmentId: string } | null {
  const head = decodeChainHead(value["head"]);
  if (head === null || !isEnvironmentIdValue(value["environmentId"])) {
    return null;
  }
  return { head, environmentId: value["environmentId"] as string };
}

function decodePullRecord(value: Record<string, unknown>): FloorLogRecord | null {
  const scoped = decodeScoped(value);
  const environment = decodeEnvironmentFloor(value["environment"]);
  if (scoped === null || environment === null) {
    return null;
  }
  return { r: "pull", ...scoped, environment };
}

function decodePushRecord(value: Record<string, unknown>): FloorLogRecord | null {
  const scoped = decodeScoped(value);
  const variable = decodeVariableFloor(value["variable"]);
  if (scoped === null || variable === null || !isVariableIdValue(value["variableId"])) {
    return null;
  }
  return { r: "push", ...scoped, variableId: value["variableId"] as string, variable };
}

function decodeMetaRecord(value: Record<string, unknown>): FloorLogRecord | null {
  const scoped = decodeScoped(value);
  const manifest = decodeManifestFloor(value["manifest"]);
  const valid = fieldsValid(value, {
    observedEpoch: isPositiveInteger,
    metaVersion: isPositiveInteger,
    metaSigHashHex: isHex64,
  });
  if (scoped === null || manifest === null || !valid) {
    return null;
  }
  return {
    r: "meta",
    ...scoped,
    observedEpoch: value["observedEpoch"] as number,
    metaVersion: value["metaVersion"] as number,
    metaSigHashHex: value["metaSigHashHex"] as string,
    manifest,
  };
}

function decodeManifestRecord(value: Record<string, unknown>): FloorLogRecord | null {
  const scoped = decodeScoped(value);
  const manifest = decodeManifestFloor(value["manifest"]);
  if (scoped === null || manifest === null) {
    return null;
  }
  return { r: "manifest", ...scoped, manifest };
}

function decodeHeadRecord(value: Record<string, unknown>): FloorLogRecord | null {
  const head = decodeChainHead(value["head"]);
  return head === null ? null : { r: "head", head };
}

function decodeIntentRecord(value: Record<string, unknown>): FloorLogRecord | null {
  const intent = decodeIntent(value["intent"]);
  return intent === null ? null : { r: "intent", intent };
}

function decodeResolutionRecord(value: Record<string, unknown>): FloorLogRecord | null {
  const valid = fieldsValid(value, {
    intentId: (id) => isString(id) && INTENT_ID.test(id),
    outcome: (outcome) => INTENT_OUTCOMES.includes(outcome as FloorIntentOutcome),
  });
  if (!valid) {
    return null;
  }
  return {
    r: "resolution",
    intentId: value["intentId"] as string,
    outcome: value["outcome"] as FloorIntentOutcome,
  };
}

function decodeSnapshotRecord(value: Record<string, unknown>): FloorLogRecord | null {
  const state = decodeSnapshotState(value["state"]);
  if (state === null || !isNonNegativeInteger(value["folded"])) {
    return null;
  }
  return { r: "snapshot", folded: value["folded"], state };
}

// r tag → decoder mapping (a Map — with a plain Record an r value like
// `constructor` resolves to an inherited-property function and lets a
// corrupt record through)
const RECORD_DECODERS = new Map<string, (value: Record<string, unknown>) => FloorLogRecord | null>([
  ["head", decodeHeadRecord],
  ["pull", decodePullRecord],
  ["push", decodePushRecord],
  ["meta", decodeMetaRecord],
  ["manifest", decodeManifestRecord],
  ["intent", decodeIntentRecord],
  ["resolution", decodeResolutionRecord],
  ["snapshot", decodeSnapshotRecord],
]);

/** Strict decoding of one line. null = undecodable (fold ignores it — self-healing). */
function decodeLogRecord(line: string): FloorLogRecord | null {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return null;
  }
  if (!isRecord(value) || !isString(value["r"])) {
    return null;
  }
  const decode = RECORD_DECODERS.get(value["r"]);
  return decode === undefined ? null : decode(value);
}

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
  environmentId: string,
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

interface FoldOutcome {
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

function foldRecords(lines: readonly string[]): FoldOutcome {
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

// ---- File store ----

function isFileMissingError(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    (error as NodeJS.ErrnoException).code === "ENOENT"
  );
}

/**
 * Writes payload to an O_APPEND-opened handle as one logical append and
 * waits through datasync (the physical discipline for appends to the
 * floor log / evidence log).
 *
 * One logical append = one write syscall (the unit O_APPEND's atomicity
 * covers). On a short write, **do not splice on the remainder**: a second
 * splicing write would interleave with another process's append, and one
 * record would split into two invalid fragments lost silently (a shape
 * that must never return success). Since readers discard the fragment as
 * a torn line already isolated by newline-prefixing, rewrite the
 * **whole** payload from the start. If it runs out still unwritten
 * (including a 0-byte write), throw.
 */
async function appendAll(handle: FileHandle, payload: Buffer, logName: string): Promise<void> {
  for (let attempt = 1; ; attempt += 1) {
    const result = await handle.write(payload, 0, payload.length);
    if (result.bytesWritten === payload.length) {
      break;
    }
    if (result.bytesWritten === 0 || attempt >= MAX_APPEND_WRITE_ATTEMPTS) {
      throw new Error(
        `short write on the ${logName} (${result.bytesWritten}/${payload.length} bytes)`,
      );
    }
  }
  await handle.datasync();
}

function encodeRecord(record: FloorLogRecord): string {
  return `${JSON.stringify(record)}\n`;
}

function randomIntentId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** The commit functions' return value: the environment's floor from the folded floor (bottom if unobserved). */
function environmentOf(floor: ProjectFloor, environmentId: string): EnvironmentFloor {
  return floorRecordGet(floor.environments, environmentId) ?? emptyEnvironmentFloor();
}

export interface FileFloorStoreOptions {
  /** The compaction trigger (record count after the latest snapshot). A test override. */
  readonly compactionThreshold?: number;
}

/** File-backed append-only floor store rooted at `dir` (production and tests share this). */
export function makeFileFloorStore(dir: string, options?: FileFloorStoreOptions): FloorStoreShape {
  const compactionThreshold = options?.compactionThreshold ?? DEFAULT_COMPACTION_THRESHOLD;

  const pathOf = (projectId: string): string => {
    // projectId is supposed to be a genesis hash (hex-64), but the form
    // is enforced before it goes into a file name (prevents untrusted
    // strings from mixing into path assembly)
    if (!isProjectId(projectId)) {
      throw new Error(`invalid project id for floor path: ${projectId}`);
    }
    return join(dir, `${projectId}.jsonl`);
  };
  /**
   * Appending (O_APPEND equivalent) + fsync-equivalent durability
   * (3-E′).
   *
   * Every write is **prefixed** with a newline: even if a concurrent
   * process's torn line (an unfinished write without a newline) landed
   * right before, our record is always isolated as a fresh line (fold
   * ignores empty lines). The "read the tail byte to decide" shape is not
   * used because it races a torn line slipping in between the check and
   * the O_APPEND write (once interrupted, our complete record would be
   * concatenated onto that line and lost, silently breaking
   * journal-before-release). write loops until every byte is written,
   * guarding against short writes (datasync is the durability standard —
   * 3-E′).
   */
  const appendRecords = async (
    projectId: string,
    records: readonly FloorLogRecord[],
  ): Promise<void> => {
    const path = pathOf(projectId);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const handle = await open(path, "a", 0o600);
    try {
      const payload = Buffer.from(`\n${records.map(encodeRecord).join("")}`, "utf8");
      // If it runs out still unwritten it throws as a failure (mutate
      // converts it to a floor error and the caller never treats it as
      // "persisted"). Duplicate records are harmless via the join's
      // idempotence
      await appendAll(handle, payload, "floor log");
    } finally {
      await handle.close();
    }
  };

  const readAndFold = async (projectId: string): Promise<FoldOutcome> => {
    const raw = await readFile(pathOf(projectId), "utf8");
    return foldRecords(raw.split("\n"));
  };

  /** Append → fold. If fold produced a conflict it is a typed error (the evidence remains in the log). */
  const mutate = (
    projectId: string,
    records: readonly FloorLogRecord[],
  ): Effect.Effect<ProjectFloor, CliError> =>
    Effect.tryPromise({
      try: async () => {
        await appendRecords(projectId, records);
        let outcome = await readAndFold(projectId);
        if (outcome.recordsSinceSnapshot > compactionThreshold) {
          // Compaction = only appending a snapshot record (never a
          // rewrite). Two concurrent snapshots are harmless (fold bases
          // on the latest one, and the position basis + join idempotence
          // keep even a double fold correct)
          await appendRecords(projectId, [
            {
              r: "snapshot",
              folded: outcome.decodedRecords,
              state: {
                chainHead: outcome.floor.chainHead,
                environments: outcome.floor.environments,
                conflicts: outcome.floor.conflicts,
                intents: outcome.floor.intents,
              },
            },
          ]);
          outcome = await readAndFold(projectId);
        }
        return outcome.floor;
      },
      catch: () =>
        cliError(
          `Cannot write the local floor log: ${join(dir, `${projectId}.jsonl`)} (aborting because rollback detection cannot continue)`,
        ),
    }).pipe(
      Effect.flatMap((floor) =>
        floor.conflicts.length > 0
          ? Effect.fail(cliError(formatFloorConflicts(projectId, floor.conflicts)))
          : Effect.succeed(floor),
      ),
    );

  const attestedPathOf = (projectId: string): string => {
    if (!isProjectId(projectId)) {
      throw new Error(`invalid project id for attested-head path: ${projectId}`);
    }
    return join(dir, `${projectId}.attested.json`);
  };

  const evidencePathOf = (projectId: string): string => {
    if (!isProjectId(projectId)) {
      throw new Error(`invalid project id for attestation-evidence path: ${projectId}`);
    }
    return join(dir, `${projectId}.attestation-evidence.jsonl`);
  };

  /**
   * Appending evidence (the same discipline as the floor log: O_APPEND
   * + newline prefixing + waiting through datasync). It is kept separate
   * from the floor log's appendRecords because that one is specific to
   * the floor record type — the append's physical discipline
   * (full-length rewrite on short write + datasync) is carried by the
   * shared appendAll.
   */
  const appendJsonLine = async (path: string, value: AttestationEvidenceRecord): Promise<void> => {
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const handle = await open(path, "a", 0o600);
    try {
      const payload = Buffer.from(`\n${JSON.stringify(value)}\n`, "utf8");
      await appendAll(handle, payload, "attestation-evidence log");
    } finally {
      await handle.close();
    }
  };

  return {
    load: (projectId) =>
      Effect.tryPromise({
        try: async (): Promise<FloorLoadResult> => {
          let raw: string;
          try {
            raw = await readFile(pathOf(projectId), "utf8");
          } catch (error) {
            if (!isFileMissingError(error)) {
              throw error;
            }
            return { floor: null, state: "missing", droppedRecords: 0 };
          }
          const outcome = foldRecords(raw.split("\n"));
          if (outcome.decodedRecords === 0) {
            if (raw.trim() !== "") {
              // Non-empty yet not a single record decodable = wholesale corruption
              return { floor: null, state: "corrupt", droppedRecords: outcome.droppedLines };
            }
            // An empty file may also be a remnant dropped between
            // open("a") and write (= never created)
            return { floor: null, state: "missing", droppedRecords: 0 };
          }
          return { floor: outcome.floor, state: "loaded", droppedRecords: outcome.droppedLines };
        },
        catch: () =>
          cliError(`Cannot read the local floor log: ${join(dir, `${projectId}.jsonl`)}`),
      }),
    commitHead: (projectId, head) => Effect.asVoid(mutate(projectId, [{ r: "head", head }])),
    commitPull: (projectId, commit: PullCommit) =>
      mutate(projectId, [
        {
          r: "pull",
          head: commit.chainHead,
          environmentId: commit.environmentId,
          environment: commit.environment,
        },
      ]).pipe(Effect.map((floor) => environmentOf(floor, commit.environmentId))),
    commitPush: (projectId, commit: PushCommit) =>
      mutate(projectId, [
        {
          r: "push",
          head: commit.chainHead,
          environmentId: commit.environmentId,
          variableId: commit.variableId,
          variable: commit.variable,
        },
      ]).pipe(Effect.map((floor) => environmentOf(floor, commit.environmentId))),
    commitMetadata: (projectId, commit: MetadataCommit) =>
      mutate(projectId, [
        {
          r: "meta",
          head: commit.chainHead,
          environmentId: commit.environmentId,
          observedEpoch: commit.observedEpoch,
          metaVersion: commit.metaVersion,
          metaSigHashHex: commit.metaSigHashHex,
          manifest: commit.manifest,
        },
      ]).pipe(Effect.map((floor) => environmentOf(floor, commit.environmentId))),
    commitManifest: (projectId, commit: ManifestCommit) =>
      mutate(projectId, [
        {
          r: "manifest",
          head: commit.chainHead,
          environmentId: commit.environmentId,
          manifest: commit.manifest,
        },
      ]).pipe(Effect.map((floor) => environmentOf(floor, commit.environmentId))),
    appendIntent: (projectId, input: FloorIntentInput) => {
      const intent: FloorIntent = { id: randomIntentId(), ...input };
      return mutate(projectId, [{ r: "intent", intent }]).pipe(Effect.map(() => intent.id));
    },
    resolveIntent: (projectId, intentId, outcome) =>
      // A resolution is a ledger record that closes an intent (outside
      // the join's lattice). Do not fail it on an existing-conflict check
      // — recording a resolution only ever works toward more evidence
      Effect.asVoid(
        Effect.tryPromise({
          try: () => appendRecords(projectId, [{ r: "resolution", intentId, outcome }]),
          catch: () =>
            cliError(
              `Cannot write the local floor log: ${join(dir, `${projectId}.jsonl`)} (aborting because rollback detection cannot continue)`,
            ),
        }),
      ),
    listProjectIds: () =>
      Effect.tryPromise({
        try: async () => {
          let names: readonly string[];
          try {
            names = await readdir(dir);
          } catch (error) {
            if (isFileMissingError(error)) {
              return [];
            }
            throw error;
          }
          // Only the body (`<id>.jsonl`). `<id>.attestation-evidence.jsonl`
          // etc. fall out for not matching the ID form (hex 64)
          const ids = new Set<string>();
          for (const name of names) {
            const match = /^(.+)\.jsonl$/.exec(name);
            if (match?.[1] !== undefined && isProjectId(match[1])) {
              ids.add(match[1]);
            }
          }
          return [...ids].toSorted();
        },
        catch: () => cliError(`Cannot list the local floor directory: ${dir}`),
      }),
    loadAttestedHead: (projectId) =>
      Effect.tryPromise({
        try: async () => {
          let raw: string;
          try {
            raw = await readFile(attestedPathOf(projectId), "utf8");
          } catch (error) {
            if (isFileMissingError(error)) {
              return null;
            }
            throw error;
          }
          // Corruption becomes null (tracking the previous attestation
          // is best-effort — the consequence of losing it is a
          // resubmission of the same seq, which the server's idempotent
          // 204 absorbs)
          let value: unknown;
          try {
            value = JSON.parse(raw);
          } catch {
            return null;
          }
          return decodeChainHead(isRecord(value) ? value["head"] : undefined);
        },
        catch: () => cliError(`Cannot read the attested-head file: ${attestedPathOf(projectId)}`),
      }),
    saveAttestedHead: (projectId, head) =>
      Effect.tryPromise({
        try: async () => {
          await mkdir(dir, { recursive: true, mode: 0o700 });
          // tmp → rename substitution (never show a partial write to a
          // reader). Tracking is a separate, overwritable class (not a
          // verified observation — floor.ts's doc)
          const path = attestedPathOf(projectId);
          const tmp = `${path}.tmp`;
          await writeFile(tmp, `${JSON.stringify({ v: 1, head })}\n`, { mode: 0o600 });
          await rename(tmp, path);
        },
        catch: () => cliError(`Cannot write the attested-head file: ${attestedPathOf(projectId)}`),
      }),
    appendAttestationEvidence: (projectId, evidence) =>
      Effect.tryPromise({
        try: async () => {
          const path = evidencePathOf(projectId);
          await appendJsonLine(path, evidence);
          return path;
        },
        catch: () =>
          cliError(`Cannot write the attestation-evidence log: ${evidencePathOf(projectId)}`),
      }),
  };
}
