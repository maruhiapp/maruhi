import { Option, Schema } from "effect";
import { describe, expect, it } from "vite-plus/test";

import { MirrorPageSchema, ProposedVariableSchema } from "../src/index.ts";

const decodePage = Schema.decodeUnknownOption(MirrorPageSchema);
const decodeProposedVariable = Schema.decodeUnknownOption(ProposedVariableSchema);

const pageWith = (sourceMutationSeq: unknown) => ({
  sequence: 0,
  lines: ["line"],
  sourceMutationSeq,
});

describe("MirrorPageSchema sourceMutationSeq", () => {
  it("accepts 0 and a large safe integer", () => {
    expect(Option.isSome(decodePage(pageWith(0)))).toBe(true);
    expect(Option.isSome(decodePage(pageWith(Number.MAX_SAFE_INTEGER)))).toBe(true);
  });

  it("rejects a negative value", () => {
    expect(Option.isNone(decodePage(pageWith(-1)))).toBe(true);
  });

  it("rejects a fractional value", () => {
    expect(Option.isNone(decodePage(pageWith(1.5)))).toBe(true);
  });

  it("rejects an integer above the safe range", () => {
    expect(Option.isNone(decodePage(pageWith(Number.MAX_SAFE_INTEGER + 1)))).toBe(true);
  });
});

const wrap = {
  recipientUserId: "user-member-0002",
  recipientEncPubHex: "cd".repeat(32),
  encHex: "cd".repeat(32),
  ciphertextHex: "ab".repeat(17),
};

const proposedVariableWith = (wraps: readonly unknown[]) => ({
  variableId: "var-0001",
  baseVersion: 1,
  wraps,
});

describe("ProposedVariableSchema wraps", () => {
  it("accepts one wrap and the 10,000-wrap cap", () => {
    expect(Option.isSome(decodeProposedVariable(proposedVariableWith([wrap])))).toBe(true);
    expect(
      Option.isSome(decodeProposedVariable(proposedVariableWith(Array(10_000).fill(wrap)))),
    ).toBe(true);
  });

  it("rejects an empty wraps array", () => {
    expect(Option.isNone(decodeProposedVariable(proposedVariableWith([])))).toBe(true);
  });

  it("rejects a wraps array above the 10,000 cap", () => {
    expect(
      Option.isNone(decodeProposedVariable(proposedVariableWith(Array(10_001).fill(wrap)))),
    ).toBe(true);
  });
});
