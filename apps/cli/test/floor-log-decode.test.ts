// Pins the floor-log record decoder's accept / reject boundary
// (CRYPTO_SPEC §6.3 — a line that does not decode strictly is ignored by
// fold, so what counts as "undecodable" is spec behavior).
//
// Each case is one JSON line and the expected outcome: accepted (decoded
// to the given record) or rejected (null). Valid lines are built from the
// floor.ts types; every reject case mutates exactly one field of a valid
// line so the case pins that field's form.

import { describe, expect, expectTypeOf, it } from "vitest";

import {
  decodeLogRecord,
  type FloorLogRecord,
  type SnapshotState,
} from "../src/floor-log-decode.ts";
import type {
  ChainHeadFloor,
  EnvironmentFloor,
  FloorConflict,
  FloorIntent,
  FloorIntentOutcome,
  ManifestFloor,
  ProjectFloor,
  VariableFloor,
} from "../src/floor.ts";

const HASH_A = "11".repeat(32);
const HASH_B = "22".repeat(32);
const HASH_C = "33".repeat(32);
const INTENT_ID = "0123456789abcdef";
const UNSAFE_INTEGER_JSON = "9007199254740993";
/** A sentinel token replaced in the JSON text, so a literal the JS number type cannot hold survives. */
const UNSAFE_TOKEN = "__UNSAFE_INTEGER__";

const head: ChainHeadFloor = { seq: 7, hashHex: HASH_A };
const manifest: ManifestFloor = { manifestVersion: 3, epoch: 2, manifestSigHashHex: HASH_B };
const activeVariable: VariableFloor = {
  status: "active",
  version: 4,
  epoch: 2,
  valueSigHashHex: HASH_C,
  metaVersion: 1,
  metaSigHashHex: HASH_A,
};
const declaredVariable: VariableFloor = {
  status: "declared",
  metaVersion: 1,
  metaSigHashHex: HASH_B,
};
const deletedVariable: VariableFloor = {
  status: "deleted",
  metaVersion: 2,
  metaSigHashHex: HASH_C,
};
const environment: EnvironmentFloor = {
  pullEpoch: 2,
  observedEpoch: 2,
  metaVersion: 1,
  metaSigHashHex: HASH_A,
  manifest,
  variables: { va: activeVariable, vb: declaredVariable, vc: deletedVariable },
};
const conflict: FloorConflict = {
  kind: "value",
  environmentId: "prod",
  variableId: "va",
  firstVersion: 4,
  firstHashHex: HASH_A,
  secondVersion: 4,
  secondHashHex: HASH_B,
};
const intent: FloorIntent = {
  id: INTENT_ID,
  op: "rotate_epoch",
  environmentId: "prod",
  epoch: 3,
  dekCommitmentHex: HASH_C,
  variableId: null,
  manifestVersion: 4,
  manifestSigHashHex: HASH_A,
  declaredHead: head,
};

/** One valid record per `r` kind (CRYPTO_SPEC §6.3's observation / ledger / snapshot records). */
const VALID = {
  head: { r: "head", head },
  pull: { r: "pull", head, environmentId: "prod", environment },
  push: { r: "push", head, environmentId: "prod", variableId: "va", variable: activeVariable },
  meta: {
    r: "meta",
    head,
    environmentId: "prod",
    observedEpoch: 2,
    metaVersion: 1,
    metaSigHashHex: HASH_A,
    manifest,
  },
  manifest: { r: "manifest", head, environmentId: "prod", manifest },
  intent: { r: "intent", intent },
  resolution: { r: "resolution", intentId: INTENT_ID, outcome: "accepted" },
  snapshot: {
    r: "snapshot",
    folded: 12,
    state: {
      chainHead: head,
      environments: { prod: environment },
      conflicts: [conflict],
      intents: [intent],
    },
  },
} as const;

type Path = readonly (string | number)[];

/** Sets `value` at `path` in a deep copy of `base` (`undefined` deletes the key). */
function withField(base: unknown, path: Path, value: unknown): unknown {
  const copy = structuredClone(base) as Record<string | number, unknown>;
  let target = copy;
  for (const key of path.slice(0, -1)) {
    target = target[key] as Record<string | number, unknown>;
  }
  const last = path.at(-1);
  if (last === undefined) {
    return value;
  }
  if (value === undefined) {
    delete target[last];
  } else {
    target[last] = value;
  }
  return copy;
}

/** Defines a JSON property named `__proto__` (an own key, as JSON.parse produces it). */
function withProtoKey(record: Record<string, unknown>, value: unknown): Record<string, unknown> {
  const copy: Record<string, unknown> = { ...record };
  Object.defineProperty(copy, "__proto__", {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
  return copy;
}

const line = (value: unknown): string =>
  JSON.stringify(value).replace(`"${UNSAFE_TOKEN}"`, UNSAFE_INTEGER_JSON);

const at = (base: unknown, path: Path, value: unknown): string =>
  line(withField(base, path, value));

describe("decodeLogRecord — one valid line per r kind", () => {
  it.each(Object.entries(VALID))("accepts a valid %s record unchanged", (_kind, record) => {
    expect(decodeLogRecord(line(record))).toEqual(record);
  });

  it("accepts every variable status inside a push record", () => {
    for (const variable of [activeVariable, declaredVariable, deletedVariable]) {
      const record = { ...VALID.push, variable };
      expect(decodeLogRecord(line(record))).toEqual(record);
    }
  });

  it("accepts nullable intent / conflict fields as null", () => {
    const nullIntent = { ...intent, dekCommitmentHex: null, variableId: null };
    const nullConflict = { ...conflict, kind: "chain-head", environmentId: null, variableId: null };
    const record = {
      ...VALID.snapshot,
      state: {
        chainHead: null,
        environments: {},
        conflicts: [nullConflict],
        intents: [nullIntent],
      },
    };
    expect(decodeLogRecord(line(record))).toEqual(record);
  });

  it("accepts an environment floor without a manifest", () => {
    const record = withField(VALID.pull, ["environment", "manifest"], undefined);
    expect(decodeLogRecord(line(record))).toEqual(record);
  });

  it("accepts an environment deletion intent (no manifest coordinates — CRYPTO_SPEC §6.2)", () => {
    const deletion: FloorIntent = {
      id: INTENT_ID,
      op: "delete_environment",
      environmentId: "prod",
      declaredHead: head,
    };
    const record = { r: "intent", intent: deletion };
    expect(decodeLogRecord(line(record))).toEqual(record);
    // A deletion intent still binds the declared head (the slot it reconciles against)
    expect(
      decodeLogRecord(line(withField(record, ["intent", "declaredHead"], undefined))),
    ).toBeNull();
  });
});

describe("decodeLogRecord — accept / reject table", () => {
  const bottomEnvironment = {
    ...environment,
    pullEpoch: 0,
    observedEpoch: 0,
    metaVersion: 0,
    metaSigHashHex: "",
  };

  it.each<[string, string, boolean]>([
    // ---- record keys (§12-1's id form) ----
    [
      "variables key out of form (leading -)",
      at(VALID.pull, ["environment", "variables", "-bad"], activeVariable),
      false,
    ],
    [
      "variables key out of form (dot)",
      at(VALID.pull, ["environment", "variables", "a.b"], activeVariable),
      false,
    ],
    [
      "variables key empty",
      at(VALID.pull, ["environment", "variables", ""], activeVariable),
      false,
    ],
    [
      "variables key over 64 chars",
      at(VALID.pull, ["environment", "variables", "v".repeat(65)], activeVariable),
      false,
    ],
    [
      "variables key __proto__",
      line(
        withField(
          VALID.pull,
          ["environment", "variables"],
          withProtoKey(environment.variables, activeVariable),
        ),
      ),
      false,
    ],
    [
      "variables key constructor (a legitimate id)",
      at(VALID.pull, ["environment", "variables", "constructor"], activeVariable),
      true,
    ],
    [
      "environments key out of form",
      at(VALID.snapshot, ["state", "environments", "_prod"], environment),
      false,
    ],
    [
      "environments key __proto__",
      line(
        withField(
          VALID.snapshot,
          ["state", "environments"],
          withProtoKey({ prod: environment }, environment),
        ),
      ),
      false,
    ],
    [
      "environments key prototype (a legitimate id)",
      at(VALID.snapshot, ["state", "environments", "prototype"], environment),
      true,
    ],
    ["environmentId out of form", at(VALID.manifest, ["environmentId"], "_prod"), false],
    ["variableId out of form", at(VALID.push, ["variableId"], "bad id"), false],
    [
      "intent environmentId out of form",
      at(VALID.intent, ["intent", "environmentId"], "-x"),
      false,
    ],
    [
      "conflict variableId out of form",
      at(VALID.snapshot, ["state", "conflicts", 0, "variableId"], "a/b"),
      false,
    ],

    // ---- integers: safe, sign, integrality ----
    ["head.seq a non-safe integer", at(VALID.head, ["head", "seq"], UNSAFE_TOKEN), false],
    ["head.seq negative", at(VALID.head, ["head", "seq"], -1), false],
    ["head.seq zero (positive required)", at(VALID.head, ["head", "seq"], 0), false],
    ["head.seq a non-integer", at(VALID.head, ["head", "seq"], 1.5), false],
    ["head.seq a numeric string", at(VALID.head, ["head", "seq"], "7"), false],
    [
      "variable version a non-safe integer",
      at(VALID.push, ["variable", "version"], UNSAFE_TOKEN),
      false,
    ],
    ["variable epoch a non-integer", at(VALID.push, ["variable", "epoch"], 2.5), false],
    ["variable metaVersion zero", at(VALID.push, ["variable", "metaVersion"], 0), false],
    ["manifest epoch negative", at(VALID.manifest, ["manifest", "epoch"], -2), false],
    ["meta observedEpoch zero (positive required)", at(VALID.meta, ["observedEpoch"], 0), false],
    ["meta metaVersion a non-safe integer", at(VALID.meta, ["metaVersion"], UNSAFE_TOKEN), false],
    ["environment pullEpoch zero (bottom)", at(VALID.pull, ["environment", "pullEpoch"], 0), true],
    ["environment pullEpoch negative", at(VALID.pull, ["environment", "pullEpoch"], -1), false],
    [
      "environment observedEpoch a non-integer",
      at(VALID.pull, ["environment", "observedEpoch"], 0.5),
      false,
    ],
    [
      "environment pullEpoch a non-safe integer",
      at(VALID.pull, ["environment", "pullEpoch"], UNSAFE_TOKEN),
      false,
    ],
    ["intent epoch zero", at(VALID.intent, ["intent", "epoch"], 0), false],
    [
      "intent manifestVersion a non-integer",
      at(VALID.intent, ["intent", "manifestVersion"], 4.25),
      false,
    ],
    [
      "conflict firstVersion zero",
      at(VALID.snapshot, ["state", "conflicts", 0, "firstVersion"], 0),
      true,
    ],
    [
      "conflict secondVersion negative",
      at(VALID.snapshot, ["state", "conflicts", 0, "secondVersion"], -1),
      false,
    ],
    ["snapshot folded zero", at(VALID.snapshot, ["folded"], 0), true],
    ["snapshot folded negative", at(VALID.snapshot, ["folded"], -1), false],
    ["snapshot folded a non-integer", at(VALID.snapshot, ["folded"], 1.5), false],
    ["snapshot folded a non-safe integer", at(VALID.snapshot, ["folded"], UNSAFE_TOKEN), false],

    // ---- metaVersion 0 <-> metaSigHashHex "" pairing (environment floor) ----
    ["metaVersion 0 with an empty hash", at(VALID.pull, ["environment"], bottomEnvironment), true],
    ["metaVersion >0 with a 64-hex hash", at(VALID.pull, ["environment", "metaVersion"], 5), true],
    ["metaVersion 0 with a 64-hex hash", at(VALID.pull, ["environment", "metaVersion"], 0), false],
    [
      "metaVersion >0 with an empty hash",
      at(VALID.pull, ["environment", "metaSigHashHex"], ""),
      false,
    ],
    [
      "metaVersion >0 with a non-hex hash",
      at(VALID.pull, ["environment", "metaSigHashHex"], "zz".repeat(32)),
      false,
    ],
    [
      "metaVersion 0 with an empty hash inside a snapshot",
      at(VALID.snapshot, ["state", "environments", "prod"], bottomEnvironment),
      true,
    ],
    [
      "metaVersion 0 with a 64-hex hash inside a snapshot",
      at(VALID.snapshot, ["state", "environments", "prod", "metaVersion"], 0),
      false,
    ],
    ["meta record metaSigHashHex empty", at(VALID.meta, ["metaSigHashHex"], ""), false],

    // ---- hash / id string forms ----
    ["head.hashHex uppercase", at(VALID.head, ["head", "hashHex"], "AB".repeat(32)), false],
    ["head.hashHex 63 chars", at(VALID.head, ["head", "hashHex"], HASH_A.slice(1)), false],
    [
      "variable valueSigHashHex missing on active",
      at(VALID.push, ["variable", "valueSigHashHex"], undefined),
      false,
    ],
    ["variable status unknown", at(VALID.push, ["variable", "status"], "archived"), false],
    ["intent id 15 hex", at(VALID.intent, ["intent", "id"], INTENT_ID.slice(1)), false],
    [
      "intent dekCommitmentHex not hex",
      at(VALID.intent, ["intent", "dekCommitmentHex"], "x"),
      false,
    ],
    ["intent op unknown", at(VALID.intent, ["intent", "op"], "drop_environment"), false],
    [
      "resolution intentId uppercase",
      at(VALID.resolution, ["intentId"], INTENT_ID.toUpperCase()),
      false,
    ],
    ["resolution outcome unknown", at(VALID.resolution, ["outcome"], "maybe"), false],
    [
      "conflict kind unknown",
      at(VALID.snapshot, ["state", "conflicts", 0, "kind"], "epoch"),
      false,
    ],
    [
      "conflict firstHashHex any string",
      at(VALID.snapshot, ["state", "conflicts", 0, "firstHashHex"], ""),
      true,
    ],
    ["environment manifest null", at(VALID.pull, ["environment", "manifest"], null), false],
    ["snapshot chainHead missing", at(VALID.snapshot, ["state", "chainHead"], undefined), false],

    // ---- the r discriminant ----
    ["r unknown", at(VALID.head, ["r"], "bogus"), false],
    ["r constructor", at(VALID.head, ["r"], "constructor"), false],
    ["r __proto__", at(VALID.head, ["r"], "__proto__"), false],
    ["r toString", at(VALID.head, ["r"], "toString"), false],
    ["r missing", at(VALID.head, ["r"], undefined), false],
    ["r a number", at(VALID.head, ["r"], 1), false],
    ["r of a different kind than the fields", at(VALID.head, ["r"], "manifest"), false],

    // ---- arrays where objects belong / objects where arrays belong ----
    ["the line an array", line([VALID.head]), false],
    ["the line an empty array", "[]", false],
    ["the line null", "null", false],
    ["the line a string", '"head"', false],
    ["the line a number", "42", false],
    ["head an array", at(VALID.head, ["head"], [7, HASH_A]), false],
    ["environment an array", at(VALID.pull, ["environment"], []), false],
    ["variables an empty array", at(VALID.pull, ["environment", "variables"], []), false],
    [
      "variables a non-empty array",
      at(VALID.pull, ["environment", "variables"], [activeVariable]),
      false,
    ],
    ["variable an array", at(VALID.push, ["variable"], [activeVariable]), false],
    ["environments an empty array", at(VALID.snapshot, ["state", "environments"], []), false],
    ["snapshot state an array", at(VALID.snapshot, ["state"], []), false],
    ["intent an array", at(VALID.intent, ["intent"], [intent]), false],
    ["conflicts an object", at(VALID.snapshot, ["state", "conflicts"], {}), false],
    ["intents an object", at(VALID.snapshot, ["state", "intents"], { 0: intent }), false],
    [
      "a single corrupt conflict item",
      at(VALID.snapshot, ["state", "conflicts", 1], { kind: "value" }),
      false,
    ],

    // ---- torn JSON ----
    ["a torn line (truncated)", line(VALID.pull).slice(0, -5), false],
    ["a torn line (unterminated object)", '{"r":"head"', false],
    ["an empty line", "", false],
    ["a whitespace-only line", "   ", false],
    ["two records on one line", `${line(VALID.head)}${line(VALID.head)}`, false],
  ])("%s", (_name, input, accepted) => {
    const decoded = decodeLogRecord(input);
    if (accepted) {
      expect(decoded).toEqual(JSON.parse(input));
    } else {
      expect(decoded).toBeNull();
    }
  });
});

describe("decodeLogRecord — extra keys are tolerated and dropped", () => {
  it.each<[string, Path]>([
    ["at the top level", ["extra"]],
    ["in the head", ["head", "extra"]],
    ["in the environment floor", ["environment", "extra"]],
    ["in a variable floor", ["environment", "variables", "va", "extra"]],
    ["in the manifest floor", ["environment", "manifest", "extra"]],
  ])("an extra key %s", (_where, path) => {
    expect(decodeLogRecord(at(VALID.pull, path, "ignored"))).toEqual(VALID.pull);
  });

  it("extra keys inside a snapshot's state, conflicts and intents", () => {
    let record: unknown = VALID.snapshot;
    for (const path of [
      ["state", "extra"],
      ["state", "conflicts", 0, "extra"],
      ["state", "intents", 0, "extra"],
      ["state", "intents", 0, "declaredHead", "extra"],
    ]) {
      record = withField(record, path, 1);
    }
    expect(decodeLogRecord(line(record))).toEqual(VALID.snapshot);
  });

  it("a declared variable carrying value-side fields decodes to the meta side only", () => {
    const record = withField(VALID.push, ["variable"], { ...activeVariable, status: "declared" });
    expect(decodeLogRecord(line(record))).toEqual({
      ...VALID.push,
      variable: { ...declaredVariable, metaSigHashHex: HASH_A },
    });
  });
});

// The decoded types are derived from the Schema; these checks anchor them
// to floor.ts's hand-written domain types (mutual assignability), so a
// drift on either side fails `tsc`.
describe("decoded types stay anchored to floor.ts", () => {
  type Of<R extends FloorLogRecord["r"]> = Extract<FloorLogRecord, { readonly r: R }>;

  it("SnapshotState <-> ProjectFloor", () => {
    expectTypeOf<SnapshotState>().toExtend<ProjectFloor>();
    expectTypeOf<ProjectFloor>().toExtend<SnapshotState>();
  });

  it("record fields <-> the floor.ts types they carry", () => {
    expectTypeOf<Of<"head">["head"]>().toExtend<ChainHeadFloor>();
    expectTypeOf<ChainHeadFloor>().toExtend<Of<"head">["head"]>();
    expectTypeOf<Of<"pull">["environment"]>().toExtend<EnvironmentFloor>();
    expectTypeOf<EnvironmentFloor>().toExtend<Of<"pull">["environment"]>();
    expectTypeOf<Of<"push">["variable"]>().toExtend<VariableFloor>();
    expectTypeOf<VariableFloor>().toExtend<Of<"push">["variable"]>();
    expectTypeOf<Of<"manifest">["manifest"]>().toExtend<ManifestFloor>();
    expectTypeOf<ManifestFloor>().toExtend<Of<"manifest">["manifest"]>();
    expectTypeOf<Of<"intent">["intent"]>().toExtend<FloorIntent>();
    expectTypeOf<FloorIntent>().toExtend<Of<"intent">["intent"]>();
    expectTypeOf<Of<"resolution">["outcome"]>().toExtend<FloorIntentOutcome>();
    expectTypeOf<FloorIntentOutcome>().toExtend<Of<"resolution">["outcome"]>();
    expectTypeOf<SnapshotState["conflicts"][number]>().toExtend<FloorConflict>();
    expectTypeOf<FloorConflict>().toExtend<SnapshotState["conflicts"][number]>();
  });
});
