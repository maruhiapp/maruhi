// The floor log record wire format (FloorLogRecord) and its strict
// per-record decoding — a broken line is ignored by fold (self-healing).
// The storage form's overview lives in floor-log.ts.
//
// Records are decoded with Schema: each record kind is a Struct
// discriminated on the literal `r` field, combined with Schema.Union. A
// line that matches no member is undecodable (fold ignores it). Unknown
// fields drop out of the Struct result, matching the previous
// hand-written decoders' tolerance; required fields and field forms are
// all strict.

import { EnvironmentIdSchema, isEnvironmentId, isVariableId, VariableIdSchema } from "@maruhi/core";
import { Result, Schema } from "effect";

import type { ChainHeadFloor } from "./floor.ts";

const HEX_64 = /^[0-9a-f]{64}$/;
const INTENT_ID = /^[0-9a-f]{16}$/;

/** A signed-bytes hash (64 lowercase hex). */
const HashHex = Schema.String.check(Schema.isPattern(HEX_64));

/** A safe integer >= 1 (the positive form the wire carries for versions / epochs). */
const PositiveInt = Schema.Int.check(Schema.isGreaterThanOrEqualTo(1));

/** An intent / resolution id (16 lowercase hex — randomIntentId's output form). */
const IntentId = Schema.String.check(Schema.isPattern(INTENT_ID));

const ChainHeadFloorSchema = Schema.Struct({
  seq: PositiveInt,
  hashHex: HashHex,
});

const VariableMetaSide = {
  metaVersion: PositiveInt,
  metaSigHashHex: HashHex,
} as const;

/**
 * One variable's floor (the meta side is shared; deleted / declared —
 * layout v3's no-value-set declaration, §4.2 — carry the meta side only).
 */
const VariableFloorSchema = Schema.Union([
  Schema.Struct({
    status: Schema.Literal("active"),
    version: PositiveInt,
    epoch: PositiveInt,
    valueSigHashHex: HashHex,
    ...VariableMetaSide,
  }),
  Schema.Struct({ status: Schema.Literal("declared"), ...VariableMetaSide }),
  Schema.Struct({ status: Schema.Literal("deleted"), ...VariableMetaSide }),
]);

const ManifestFloorSchema = Schema.Struct({
  manifestVersion: PositiveInt,
  epoch: PositiveInt,
  manifestSigHashHex: HashHex,
});

// Record keys (environmentId / variableId) must satisfy §12-1's accepted
// form. A Record's key schema only *selects* which own keys decode (an
// out-of-form key would be silently dropped, not rejected as corruption),
// so keys are decoded as strings and the form check runs on the decoded
// key set. This structurally excludes `__proto__` (a leading `_` is out
// of form). `constructor` / `prototype` are legitimate IDs and are not
// refused (the read side is protected by floorRecordGet's own-property
// lookup)
const keysAreIds = (isId: (key: string) => boolean, label: string) =>
  Schema.makeFilter((record: Readonly<Record<string, unknown>>) =>
    Object.keys(record).every(isId)
      ? undefined
      : `every ${label} key must satisfy the id form (§12-1)`,
  );

const VariablesSchema = Schema.Record(Schema.String, VariableFloorSchema).check(
  keysAreIds(isVariableId, "variable"),
);

/**
 * The environment floor (admits the bottom coordinates: pullEpoch /
 * observedEpoch / metaVersion = 0). The meta hash is paired with
 * metaVersion: empty at bottom (0), a 64-hex hash once observed.
 */
const EnvironmentFloorSchema = Schema.Struct({
  pullEpoch: Schema.Natural,
  observedEpoch: Schema.Natural,
  metaVersion: Schema.Natural,
  metaSigHashHex: Schema.String,
  manifest: Schema.optionalKey(ManifestFloorSchema),
  variables: VariablesSchema,
}).check(
  Schema.makeFilter((floor) =>
    (floor.metaVersion === 0 ? floor.metaSigHashHex === "" : HEX_64.test(floor.metaSigHashHex))
      ? undefined
      : {
          path: ["metaSigHashHex"],
          issue: "metaSigHashHex must be empty when metaVersion is 0 and a 64-hex hash otherwise",
        },
  ),
);

const EnvironmentsSchema = Schema.Record(Schema.String, EnvironmentFloorSchema).check(
  keysAreIds(isEnvironmentId, "environment"),
);

const ConflictSchema = Schema.Struct({
  kind: Schema.Literals([
    "chain-head",
    "value",
    "variable-meta",
    "environment-meta",
    "manifest",
    "undeletion",
  ]),
  environmentId: Schema.NullOr(EnvironmentIdSchema),
  variableId: Schema.NullOr(VariableIdSchema),
  firstVersion: Schema.Natural,
  firstHashHex: Schema.String,
  secondVersion: Schema.Natural,
  secondHashHex: Schema.String,
});

const IntentSchema = Schema.Struct({
  id: IntentId,
  op: Schema.Literals(["create_environment", "rotate_epoch", "meta-op"]),
  environmentId: EnvironmentIdSchema,
  epoch: PositiveInt,
  dekCommitmentHex: Schema.NullOr(HashHex),
  variableId: Schema.NullOr(VariableIdSchema),
  manifestVersion: PositiveInt,
  manifestSigHashHex: HashHex,
  declaredHead: ChainHeadFloorSchema,
});

const SnapshotStateSchema = Schema.Struct({
  chainHead: Schema.NullOr(ChainHeadFloorSchema),
  environments: EnvironmentsSchema,
  conflicts: Schema.Array(ConflictSchema),
  intents: Schema.Array(IntentSchema),
});

/** A snapshot record's content (= the fold result, including conflicts / intents). */
export type SnapshotState = typeof SnapshotStateSchema.Type;

/** The shared coordinates (head + environmentId) of environment-scoped records. */
const Scoped = {
  head: ChainHeadFloorSchema,
  environmentId: EnvironmentIdSchema,
} as const;

const FloorLogRecordSchema = Schema.Union([
  Schema.Struct({ r: Schema.Literal("head"), head: ChainHeadFloorSchema }),
  Schema.Struct({
    r: Schema.Literal("pull"),
    ...Scoped,
    environment: EnvironmentFloorSchema,
  }),
  Schema.Struct({
    r: Schema.Literal("push"),
    ...Scoped,
    variableId: VariableIdSchema,
    variable: VariableFloorSchema,
  }),
  Schema.Struct({
    r: Schema.Literal("meta"),
    ...Scoped,
    observedEpoch: PositiveInt,
    metaVersion: PositiveInt,
    metaSigHashHex: HashHex,
    manifest: ManifestFloorSchema,
  }),
  Schema.Struct({
    r: Schema.Literal("manifest"),
    ...Scoped,
    manifest: ManifestFloorSchema,
  }),
  Schema.Struct({ r: Schema.Literal("intent"), intent: IntentSchema }),
  Schema.Struct({
    r: Schema.Literal("resolution"),
    intentId: IntentId,
    outcome: Schema.Literals([
      "accepted",
      "accepted-superseded",
      "rejected",
      "not-accepted",
      "superseded",
    ]),
  }),
  Schema.Struct({
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
    r: Schema.Literal("snapshot"),
    folded: Schema.Natural,
    state: SnapshotStateSchema,
  }),
]);

/** An observation-log record (one line = one record). */
export type FloorLogRecord = typeof FloorLogRecordSchema.Type;

/** Decodes `value` with `schema`; null = undecodable (the caller's corrupt/ignore contract). */
const decodeOrNull =
  <S extends Schema.ConstraintDecoder<unknown>>(schema: S) =>
  (value: unknown): S["Type"] | null => {
    const decoded = Schema.decodeUnknownResult(schema)(value);
    return Result.isSuccess(decoded) ? decoded.success : null;
  };

/** Strict decoding of one line. null = undecodable (fold ignores it — self-healing). */
export const decodeLogRecord: (line: string) => FloorLogRecord | null = decodeOrNull(
  Schema.fromJsonString(FloorLogRecordSchema),
);

/** Strict decoding of a chain head (null = undecodable). */
export const decodeChainHead: (value: unknown) => ChainHeadFloor | null =
  decodeOrNull(ChainHeadFloorSchema);
