// The floor log record wire format (FloorLogRecord) and its strict
// per-record decoding — a broken line is ignored by fold (self-healing).
// The storage form's overview lives in floor-log.ts.

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
