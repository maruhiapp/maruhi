import type { KeyFingerprintHex } from "@maruhi/core";
import { Option, Schema } from "effect";
import { describe, expect, expectTypeOf, it } from "vitest";

import { ChainEntrySchema, ChainInvalidReasonSchema, maruhiApi } from "../src/index.ts";

const decodeEntry = Schema.decodeUnknownOption(ChainEntrySchema);
const decodeReason = Schema.decodeUnknownOption(ChainInvalidReasonSchema);

// Same shape as seq 1 (genesis) of test-vectors/chain-entries.json. Dummy values
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

  it("decodes a rotate_epoch entry with its numeric epoch and commitment", () => {
    const decoded = decodeEntry({
      suite: "maruhi/v1",
      seq: 4,
      prevHashHex: "1".repeat(64),
      op: "rotate_epoch",
      actor: { userId: "user-owner-0001", keyFingerprintHex: "ab".repeat(16) },
      payload: {
        environmentId: "env-prod-0001",
        newEpoch: 2,
        reason: "scheduled",
        dekCommitmentHex: "34".repeat(32),
      },
      timestampMs: 1754006403000,
      signatureHex: "12".repeat(64),
    });
    expect(Option.isSome(decoded)).toBe(true);
    if (Option.isSome(decoded) && decoded.value.op === "rotate_epoch") {
      expect(decoded.value.payload.newEpoch).toBe(2);
      expect(decoded.value.payload.dekCommitmentHex).toBe("34".repeat(32));
    }
  });

  it("decodes a create_environment entry with its epoch-1 commitment", () => {
    const decoded = decodeEntry({
      suite: "maruhi/v1",
      seq: 3,
      prevHashHex: "1".repeat(64),
      op: "create_environment",
      actor: { userId: "user-owner-0001", keyFingerprintHex: "ab".repeat(16) },
      payload: { environmentId: "env-prod-0001", dekCommitmentHex: "34".repeat(32) },
      timestampMs: 1754006402000,
      signatureHex: "12".repeat(64),
    });
    expect(Option.isSome(decoded)).toBe(true);
    if (Option.isSome(decoded) && decoded.value.op === "create_environment") {
      expect(decoded.value.payload.dekCommitmentHex).toBe("34".repeat(32));
    }
  });

  it("rejects a rotate_epoch entry without a commitment (4-field payload since 0.4-draft)", () => {
    const bad = {
      suite: "maruhi/v1",
      seq: 4,
      prevHashHex: "1".repeat(64),
      op: "rotate_epoch",
      actor: { userId: "user-owner-0001", keyFingerprintHex: "ab".repeat(16) },
      payload: { environmentId: "env-prod-0001", newEpoch: 2, reason: "scheduled" },
      timestampMs: 1754006403000,
      signatureHex: "12".repeat(64),
    };
    expect(Option.isNone(decodeEntry(bad))).toBe(true);
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

  it("mints the KeyFingerprintHex brand in the actor and key positions (the wire is a mint site)", () => {
    expectTypeOf<
      (typeof ChainEntrySchema.Type)["actor"]["keyFingerprintHex"]
    >().toEqualTypeOf<KeyFingerprintHex>();
    const revokeDevice = decodeEntry({
      ...genesisEntry,
      seq: 2,
      op: "revoke_device",
      payload: { targetUserId: "user-member-0002", deviceFingerprintsHex: ["cd".repeat(16)] },
    });
    expect(Option.isSome(revokeDevice)).toBe(true);
    if (Option.isSome(revokeDevice) && revokeDevice.value.op === "revoke_device") {
      expectTypeOf(revokeDevice.value.payload.deviceFingerprintsHex).toEqualTypeOf<
        readonly KeyFingerprintHex[]
      >();
    }
  });

  it("rejects a fingerprint that is not 16 bytes of lowercase hex", () => {
    for (const keyFingerprintHex of ["AB".repeat(16), "ab".repeat(15), "octocat"]) {
      const bad = { ...genesisEntry, actor: { ...genesisEntry.actor, keyFingerprintHex } };
      expect(Option.isNone(decodeEntry(bad)), keyFingerprintHex).toBe(true);
    }
    const badRevoke = {
      ...genesisEntry,
      op: "revoke_server",
      payload: { serverKeyFingerprintHex: "AB".repeat(16) },
    };
    expect(Option.isNone(decodeEntry(badRevoke))).toBe(true);
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
