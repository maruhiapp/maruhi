import { Option, Schema } from "effect";
import { describe, expect, it } from "vitest";

import { ChainEntrySchema, ChainInvalidReasonSchema, maruhiApi } from "../src/index.ts";

const decodeEntry = Schema.decodeUnknownOption(ChainEntrySchema);
const decodeReason = Schema.decodeUnknownOption(ChainInvalidReasonSchema);

// 形状は test-vectors/chain-entries.json の seq 1(genesis)と同じ。値はダミー
const genesisEntry = {
  suite: "maruhi/v1",
  seq: 1,
  prevHashHex: "0".repeat(64),
  op: "genesis",
  actor: { userId: "user-owner-0001", keyFingerprintHex: "ab".repeat(16) },
  payload: { encPubHex: "cd".repeat(32), sigPubHex: "ef".repeat(32) },
  timestampMs: 1754006400000,
  signatureHex: "12".repeat(64),
};

describe("ChainEntrySchema", () => {
  it("decodes a well-formed genesis entry", () => {
    const decoded = decodeEntry(genesisEntry);
    expect(Option.isSome(decoded)).toBe(true);
    if (Option.isSome(decoded)) {
      expect(decoded.value.op).toBe("genesis");
      expect(decoded.value.seq).toBe(1);
    }
  });

  it("decodes a rotate_epoch entry with its numeric epoch", () => {
    const decoded = decodeEntry({
      suite: "maruhi/v1",
      seq: 4,
      prevHashHex: "1".repeat(64),
      op: "rotate_epoch",
      actor: { userId: "user-owner-0001", keyFingerprintHex: "ab".repeat(16) },
      payload: { environmentId: "env-prod-0001", newEpoch: 2, reason: "scheduled" },
      timestampMs: 1754006403000,
      signatureHex: "12".repeat(64),
    });
    expect(Option.isSome(decoded)).toBe(true);
    if (Option.isSome(decoded) && decoded.value.op === "rotate_epoch") {
      expect(decoded.value.payload.newEpoch).toBe(2);
    }
  });

  it("rejects a fingerprint of the wrong length", () => {
    const bad = {
      ...genesisEntry,
      actor: { userId: "user-owner-0001", keyFingerprintHex: "ab".repeat(15) },
    };
    expect(Option.isNone(decodeEntry(bad))).toBe(true);
  });

  it("rejects uppercase hex (canonical form is lowercase)", () => {
    const bad = { ...genesisEntry, signatureHex: "AB".repeat(64) };
    expect(Option.isNone(decodeEntry(bad))).toBe(true);
  });

  it("rejects an unknown op", () => {
    const bad = { ...genesisEntry, op: "transfer_ownership" };
    expect(Option.isNone(decodeEntry(bad))).toBe(true);
  });

  it("rejects a payload that does not match the op", () => {
    const bad = { ...genesisEntry, payload: { targetUserId: "user-x" } };
    expect(Option.isNone(decodeEntry(bad))).toBe(true);
  });
});

describe("ChainInvalidReasonSchema", () => {
  it("accepts known verifyChain reason codes", () => {
    expect(Option.isSome(decodeReason("epoch-out-of-sequence"))).toBe(true);
    expect(Option.isSome(decodeReason("bad-signature"))).toBe(true);
  });

  it("rejects unknown reason codes", () => {
    expect(Option.isNone(decodeReason("cosmic-rays"))).toBe(true);
  });
});

describe("maruhiApi", () => {
  it("exposes the membership group", () => {
    expect(Object.keys(maruhiApi.groups)).toContain("membership");
  });
});
