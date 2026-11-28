import { describe, expect, it } from "vite-plus/test";

import {
  type ChainRow,
  checkpointRowsMatchLatest,
  epochAt,
  foldChainAnchors,
} from "../src/do/chain-anchors.ts";

let nextSeq = 0;

function row(op: string, payload: unknown, overrides: Partial<ChainRow> = {}): ChainRow {
  nextSeq += 1;
  return {
    seq: nextSeq,
    entryJson: JSON.stringify({ op, payload }),
    entryHashHex: `hash-${nextSeq}`,
    ...overrides,
  };
}

function chain(build: () => ChainRow[]): ChainRow[] {
  nextSeq = 0;
  return build();
}

const tuple = (environmentId: string, epoch: number, manifestVersion: number) => ({
  environmentId,
  epoch,
  manifestVersion,
  manifestSigHashHex: `sig-${manifestVersion}`,
  valuesDigestHex: `values-${manifestVersion}`,
});

describe("foldChainAnchors", () => {
  it("folds an empty chain to empty, complete anchors", () => {
    const anchors = foldChainAnchors([]);
    expect(anchors.complete).toBe(true);
    expect(anchors.headSeq).toBe(0);
    expect(anchors.latest.size).toBe(0);
    expect(anchors.grantScopes.size).toBe(0);
  });

  it("tracks an environment's epochs, its first deletion and its rotation count", () => {
    const anchors = foldChainAnchors(
      chain(() => [
        row("genesis", {}),
        row("create_environment", { environmentId: "env_a" }),
        row("rotate_epoch", { environmentId: "env_a", newEpoch: 2 }),
        row("rotate_epoch", { environmentId: "env_a", newEpoch: 3 }),
        row("delete_environment", { environmentId: "env_a" }),
        row("delete_environment", { environmentId: "env_a" }),
      ]),
    );
    expect(anchors.complete).toBe(true);
    expect(anchors.headSeq).toBe(6);
    expect(anchors.epochStarts.get("env_a")).toEqual([
      [2, 1],
      [3, 2],
      [4, 3],
    ]);
    expect(anchors.rotateCounts.get("env_a")).toBe(2);
    expect(anchors.deletedSeq.get("env_a")).toBe(5);
    expect(epochAt(anchors, "env_a", 1)).toBeUndefined();
    expect(epochAt(anchors, "env_a", 3)).toBe(2);
    expect(epochAt(anchors, "env_a", 4)).toBe(3);
    expect(epochAt(anchors, "env_a", 5)).toBeUndefined();
  });

  it("collects the membership ops with their targets", () => {
    const anchors = foldChainAnchors(
      chain(() => [
        row("add_member", { targetUserId: "user_1", encPubHex: "aa" }),
        row("remove_member", { targetUserId: "user_1" }),
        row("revoke_device", { targetUserId: "user_2", deviceFingerprintsHex: ["f1", "f2"] }),
      ]),
    );
    expect(anchors.complete).toBe(true);
    expect(anchors.addMemberSweeps).toEqual([{ seq: 1, targetUserId: "user_1", encPubHex: "aa" }]);
    expect(anchors.removedMembers).toEqual([{ seq: 2, targetUserId: "user_1" }]);
    expect(anchors.revokedDevices).toEqual([
      { seq: 3, targetUserId: "user_2", fingerprints: ["f1", "f2"] },
    ]);
  });

  it("keeps the latest checkpoint tuple per environment and drops it at deletion", () => {
    const anchors = foldChainAnchors(
      chain(() => [
        row("create_environment", { environmentId: "env_a" }),
        row("create_environment", { environmentId: "env_b" }),
        row("checkpoint", { environments: [tuple("env_a", 1, 1), tuple("env_b", 1, 1)] }),
        row("checkpoint", { environments: [tuple("env_a", 1, 2)] }),
        row("delete_environment", { environmentId: "env_b" }),
        row("checkpoint", { environments: [tuple("env_b", 1, 3)] }),
      ]),
    );
    expect(anchors.complete).toBe(true);
    expect([...anchors.latest.keys()]).toEqual(["env_a"]);
    expect(anchors.latest.get("env_a")).toEqual({
      seq: 4,
      entryHashHex: "hash-4",
      epoch: 1,
      manifestVersion: 2,
      manifestSigHashHex: "sig-2",
      valuesDigestHex: "values-2",
    });
  });

  it("marks a manifest version bound to two different tuples as a conflict", () => {
    const anchors = foldChainAnchors(
      chain(() => [
        row("create_environment", { environmentId: "env_a" }),
        row("checkpoint", { environments: [tuple("env_a", 1, 1)] }),
        row("checkpoint", { environments: [{ ...tuple("env_a", 1, 1), manifestSigHashHex: "x" }] }),
        row("checkpoint", { environments: [tuple("env_a", 1, 2)] }),
      ]),
    );
    expect(anchors.tupleFor.get("env_a\n1")).toBe("conflict");
    expect(anchors.tupleFor.get("env_a\n2")).toEqual({ epoch: 1, sig: "sig-2" });
  });

  it("reads a grant's scope from a direct grant and from an approved proposal", () => {
    const anchors = foldChainAnchors(
      chain(() => [
        row("grant_server", { scopeEnvironmentIds: ["env_a"] }),
        row("propose", {
          inner: { op: "grant_server", payload: { scopeEnvironmentIds: ["env_b"] } },
        }),
        row("propose", {
          inner: { op: "add_member", payload: { scopeEnvironmentIds: ["env_c"] } },
        }),
        row("approve", { proposalHashHex: "hash-2" }),
        row("approve", { proposalHashHex: "hash-3" }),
        row("approve", { proposalHashHex: "unknown" }),
      ]),
    );
    expect(anchors.complete).toBe(true);
    expect([...anchors.grantScopes.entries()]).toEqual([
      [1, ["env_a"]],
      [4, ["env_b"]],
    ]);
  });

  it("turns incomplete on an unreadable entry or an unknown op, and keeps folding", () => {
    for (const bad of [
      { seq: 2, entryJson: "{", entryHashHex: "hash-2" },
      {
        seq: 2,
        entryJson: JSON.stringify({ op: "from_the_future", payload: {} }),
        entryHashHex: "hash-2",
      },
      { seq: 2, entryJson: JSON.stringify({ payload: {} }), entryHashHex: "hash-2" },
      {
        seq: 2,
        entryJson: JSON.stringify({ op: "checkpoint", payload: {} }),
        entryHashHex: "hash-2",
      },
    ]) {
      const anchors = foldChainAnchors([
        {
          seq: 1,
          entryJson: JSON.stringify({
            op: "create_environment",
            payload: { environmentId: "env_a" },
          }),
          entryHashHex: "hash-1",
        },
        bad,
        {
          seq: 3,
          entryJson: JSON.stringify({
            op: "rotate_epoch",
            payload: { environmentId: "env_a", newEpoch: 2 },
          }),
          entryHashHex: "hash-3",
        },
      ]);
      expect(anchors.complete).toBe(false);
      expect(anchors.headSeq).toBe(3);
      expect(anchors.hashBySeq.get(2)).toBe("hash-2");
      expect(anchors.epochStarts.get("env_a")).toEqual([
        [1, 1],
        [3, 2],
      ]);
    }
  });

  it("takes no hash and no proposal key from a propose row without an entry hash, and stays complete", () => {
    const anchors = foldChainAnchors(
      chain(() => [
        row(
          "propose",
          { inner: { op: "grant_server", payload: { scopeEnvironmentIds: ["env_a"] } } },
          { entryHashHex: null },
        ),
        row("approve", { proposalHashHex: "null" }),
      ]),
    );
    expect(anchors.complete).toBe(true);
    expect([...anchors.hashBySeq.keys()]).toEqual([2]);
    expect(anchors.grantScopes.size).toBe(0);
    expect(anchors.headSeq).toBe(2);
  });

  it("takes no tuple from a checkpoint row without an entry hash, and turns incomplete", () => {
    const anchors = foldChainAnchors(
      chain(() => [
        row("create_environment", { environmentId: "env_a" }),
        row("checkpoint", { environments: [tuple("env_a", 1, 1)] }, { entryHashHex: null }),
      ]),
    );
    expect(anchors.complete).toBe(false);
    expect(anchors.latest.size).toBe(0);
    expect(anchors.tupleFor.size).toBe(0);
  });

  it("stays complete on grant, propose and approve entries whatever their payload", () => {
    const anchors = foldChainAnchors(
      chain(() => [
        row("grant_server", {}),
        row("grant_server", { scopeEnvironmentIds: "env_a" }),
        row("grant_server", { scopeEnvironmentIds: ["env_a", 3] }),
        row("propose", {}),
        row("propose", { inner: 5 }),
        row("propose", { inner: { op: "grant_server" } }),
        row("propose", {
          inner: { op: "grant_server", payload: { scopeEnvironmentIds: ["env_a", 3] } },
        }),
        row("approve", {}),
        row("approve", { proposalHashHex: "hash-7" }),
      ]),
    );
    expect(anchors.complete).toBe(true);
    expect(anchors.grantScopes.size).toBe(0);
  });

  it.each([
    "genesis",
    "change_role",
    "revoke_server",
    "set_approval_policy",
    "add_device",
    "withdraw",
  ])("stays complete on a %s entry", (op) => {
    expect(foldChainAnchors(chain(() => [row(op, {})])).complete).toBe(true);
  });

  it.each([
    [
      "a rotation before the environment's creation",
      "rotate_epoch",
      { environmentId: "env_b", newEpoch: 2 },
    ],
    ["a rotation without a new epoch", "rotate_epoch", { environmentId: "env_a" }],
    ["an environment op without an environment id", "delete_environment", {}],
    ["a member op without a target", "remove_member", {}],
    ["an added member without an encryption key", "add_member", { targetUserId: "user_1" }],
    ["a device revocation without fingerprints", "revoke_device", { targetUserId: "user_1" }],
    [
      "a device revocation with a fingerprint that is not a string",
      "revoke_device",
      { targetUserId: "user_1", deviceFingerprintsHex: ["f1", 2] },
    ],
    ["a checkpoint tuple that is not a record", "checkpoint", { environments: [7] }],
    [
      "a checkpoint tuple with a missing field",
      "checkpoint",
      { environments: [{ environmentId: "env_a", epoch: 1, manifestVersion: 1 }] },
    ],
  ])("turns incomplete on %s", (_name, op, payload) => {
    const anchors = foldChainAnchors(
      chain(() => [row("create_environment", { environmentId: "env_a" }), row(op, payload)]),
    );
    expect(anchors.complete).toBe(false);
    expect(anchors.latest.size).toBe(0);
  });

  it("turns incomplete on an entry whose payload is not a record", () => {
    const anchors = foldChainAnchors([
      { seq: 1, entryJson: JSON.stringify({ op: "genesis", payload: [] }), entryHashHex: "hash-1" },
    ]);
    expect(anchors.complete).toBe(false);
  });

  it("starts an environment's epochs again when it is created again", () => {
    const anchors = foldChainAnchors(
      chain(() => [
        row("create_environment", { environmentId: "env_a" }),
        row("rotate_epoch", { environmentId: "env_a", newEpoch: 2 }),
        row("create_environment", { environmentId: "env_a" }),
      ]),
    );
    expect(anchors.epochStarts.get("env_a")).toEqual([[3, 1]]);
  });

  it("drops a deleted environment's tuple only from a checkpoint after the deletion", () => {
    const anchors = foldChainAnchors(
      chain(() => [
        row("create_environment", { environmentId: "env_a" }),
        row("delete_environment", { environmentId: "env_a" }),
        row("checkpoint", { environments: [tuple("env_a", 1, 1)] }, { seq: 2 }),
      ]),
    );
    expect([...anchors.latest.keys()]).toEqual(["env_a"]);
  });

  it("marks a manifest version bound to two epochs as a conflict", () => {
    const anchors = foldChainAnchors(
      chain(() => [
        row("create_environment", { environmentId: "env_a" }),
        row("checkpoint", { environments: [tuple("env_a", 1, 1)] }),
        row("checkpoint", { environments: [tuple("env_a", 2, 1)] }),
      ]),
    );
    expect(anchors.tupleFor.get("env_a\n1")).toBe("conflict");
  });
});

describe("checkpointRowsMatchLatest", () => {
  const latest = new Map([
    [
      "env_a",
      {
        seq: 4,
        entryHashHex: "hash-4",
        epoch: 1,
        manifestVersion: 2,
        manifestSigHashHex: "sig-2",
        valuesDigestHex: "values-2",
      },
    ],
  ]);
  const matching = {
    environment_id: "env_a",
    chain_seq: 4,
    entry_hash_hex: "hash-4",
    epoch: 1,
    manifest_version: 2,
    manifest_sig_hash_hex: "sig-2",
    values_digest_hex: "values-2",
  };

  it("accepts rows that equal the latest tuples, one row per tuple", () => {
    expect(checkpointRowsMatchLatest([matching], latest)).toBe(true);
    expect(
      checkpointRowsMatchLatest(
        [{ ...matching, chain_seq: "4", epoch: "1", manifest_version: "2" }],
        latest,
      ),
    ).toBe(true);
    expect(checkpointRowsMatchLatest([], new Map())).toBe(true);
  });

  it("refuses a row that differs in any bound column", () => {
    for (const column of Object.keys(matching).filter((key) => key !== "environment_id")) {
      expect(checkpointRowsMatchLatest([{ ...matching, [column]: "other" }], latest)).toBe(false);
    }
  });

  it("refuses a row the chain has no tuple for, and a tuple that has no row", () => {
    expect(
      checkpointRowsMatchLatest([matching, { ...matching, environment_id: "env_b" }], latest),
    ).toBe(false);
    expect(checkpointRowsMatchLatest([], latest)).toBe(false);
  });
});
