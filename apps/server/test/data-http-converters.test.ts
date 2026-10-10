// toMetaStatementInput shaping (AUTH_SPEC §12-5).
//
// The runtime request struct still carries the wire-declared coordinates
// (environmentId / variableId), which are not part of WireMetaStatement. The
// converter must copy only the stored-input fields so those coordinates never
// reach the DO (the DO reconstructs the signed target from the storage
// coordinates, never from the wire's declared values — §12-5).

import { describe, expect, it } from "vitest";

import { toMetaStatementInput } from "../src/data/data-http.ts";

const wireBase = {
  suite: "maruhi/v1" as const,
  environmentId: "env-app-0001",
  variableId: "var-database-url",
  name: "DATABASE_URL",
  prevMetaSigHashHex: "",
  chainHeadHashHex: "ab".repeat(32),
  chainHeadSeq: 1,
  signatureHex: "00".repeat(64),
};

describe("toMetaStatementInput (§12-5 coordinate stripping)", () => {
  it("drops the wire-declared coordinates from the stored input", () => {
    const input = toMetaStatementInput({
      ...wireBase,
      status: "active",
      metaVersion: 1,
    });
    expect(input).not.toHaveProperty("environmentId");
    expect(input).not.toHaveProperty("variableId");
    expect(Object.keys(input).toSorted()).toEqual([
      "chainHeadHashHex",
      "chainHeadSeq",
      "metaVersion",
      "name",
      "prevMetaSigHashHex",
      "signatureHex",
      "status",
      "suite",
    ]);
  });

  it("nests the layout-v3 schema fields and still drops the coordinates", () => {
    const input = toMetaStatementInput({
      ...wireBase,
      status: "active",
      metaVersion: 1,
      layoutVersion: 3,
      varType: "url",
      required: true,
      description: "the database url",
      maxAgeDays: 30,
    });
    expect(input).not.toHaveProperty("environmentId");
    expect(input).not.toHaveProperty("variableId");
    expect(input).not.toHaveProperty("varType");
    expect(input.layoutVersion).toBe(3);
    expect(input.schema).toEqual({
      varType: "url",
      required: true,
      description: "the database url",
      maxAgeDays: 30,
    });
  });

  it("omits maxAgeDays from the nested schema when the wire omits it", () => {
    const input = toMetaStatementInput({
      ...wireBase,
      status: "declared",
      metaVersion: 1,
      layoutVersion: 3,
      varType: "",
      required: false,
      description: "",
    });
    expect(input.schema).toEqual({ varType: "", required: false, description: "" });
    expect(input.schema).not.toHaveProperty("maxAgeDays");
  });
});
