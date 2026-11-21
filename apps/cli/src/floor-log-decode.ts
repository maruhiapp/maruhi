import { isEnvironmentId, isVariableId, EnvironmentIdSchema, VariableIdSchema } from "@maruhi/core";
import { Result, Schema } from "effect";

import type { ChainHeadFloor } from "./floor.ts";

const HEX_64 = /^[0-9a-f]{64}$/;
const INTENT_ID = /^[0-9a-f]{16}$/;

const HashHex = Schema.String.check(Schema.isPattern(HEX_64));

const PositiveInt = Schema.Int.check(Schema.isGreaterThanOrEqualTo(1));
const EnvironmentIdField = EnvironmentIdSchema;
const VariableIdField = VariableIdSchema;

const IntentId = Schema.String.check(Schema.isPattern(INTENT_ID));

const ChainHeadFloorSchema = Schema.Struct({
  seq: PositiveInt,
  hashHex: HashHex,
});

const VariableMetaSide = {
  metaVersion: PositiveInt,
  metaSigHashHex: HashHex,
} as const;

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

const keysAreIds = (isId: (key: string) => boolean, label: string) =>
  Schema.makeFilter((record: Readonly<Record<string, unknown>>) =>
    Object.keys(record).every(isId)
      ? undefined
      : `every ${label} key must satisfy the id form (§12-1)`,
  );

const VariablesSchema = Schema.Record(Schema.String, VariableFloorSchema).check(
  keysAreIds(isVariableId, "variable"),
);

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
  environmentId: Schema.NullOr(EnvironmentIdField),
  variableId: Schema.NullOr(VariableIdField),
  firstVersion: Schema.Natural,
  firstHashHex: Schema.String,
  secondVersion: Schema.Natural,
  secondHashHex: Schema.String,
});

const IntentSchema = Schema.Union([
  Schema.Struct({
    id: IntentId,
    op: Schema.Literals(["create_environment", "rotate_epoch", "meta-op"]),
    environmentId: EnvironmentIdField,
    epoch: PositiveInt,
    dekCommitmentHex: Schema.NullOr(HashHex),
    variableId: Schema.NullOr(VariableIdField),
    manifestVersion: PositiveInt,
    manifestSigHashHex: HashHex,
    declaredHead: ChainHeadFloorSchema,
  }),
  Schema.Struct({
    id: IntentId,
    op: Schema.Literal("delete_environment"),
    environmentId: EnvironmentIdField,
    declaredHead: ChainHeadFloorSchema,
  }),
]);

const SnapshotStateSchema = Schema.Struct({
  chainHead: Schema.NullOr(ChainHeadFloorSchema),
  environments: EnvironmentsSchema,
  conflicts: Schema.Array(ConflictSchema),
  intents: Schema.Array(IntentSchema),
});

export type SnapshotState = typeof SnapshotStateSchema.Type;

const Scoped = {
  head: ChainHeadFloorSchema,
  environmentId: EnvironmentIdField,
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
    variableId: VariableIdField,
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
    r: Schema.Literal("snapshot"),
    folded: Schema.Natural,
    state: SnapshotStateSchema,
  }),
]);

export type FloorLogRecord = typeof FloorLogRecordSchema.Type;

const decodeOrNull =
  <S extends Schema.ConstraintDecoder<unknown>>(schema: S) =>
  (value: unknown): S["Type"] | null => {
    const decoded = Schema.decodeUnknownResult(schema)(value);
    return Result.isSuccess(decoded) ? decoded.success : null;
  };

export const decodeLogRecord: (line: string) => FloorLogRecord | null = decodeOrNull(
  Schema.fromJsonString(FloorLogRecordSchema),
);

export const decodeChainHead: (value: unknown) => ChainHeadFloor | null =
  decodeOrNull(ChainHeadFloorSchema);
