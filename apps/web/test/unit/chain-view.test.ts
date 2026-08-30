// chain-view(S5 の表示用畳み込み — 検証ではない)のユニットテスト。
// 入力は api-schema のワイヤ型に適合するフィクスチャ(型は tsc が拘束する)。
import { describe, expect, it } from "vitest";

import { deriveReportedView } from "../../src/dashboard/chain-view.ts";
import type { ChainEntry } from "../../src/dashboard/types.ts";

const HEX64 = "12".repeat(32);
const SIG = "34".repeat(64);
const FP = "56".repeat(16);

let seqCounter = 0;

function base(): {
  suite: string;
  seq: number;
  prevHashHex: string;
  actor: { userId: string; keyFingerprintHex: string };
  timestampMs: number;
  signatureHex: string;
} {
  seqCounter += 1;
  return {
    suite: "maruhi/v1",
    seq: seqCounter,
    prevHashHex: HEX64,
    actor: { userId: "user_owner", keyFingerprintHex: FP },
    timestampMs: 1_756_000_000_000 + seqCounter,
    signatureHex: SIG,
  };
}

const genesis: ChainEntry = {
  ...base(),
  op: "genesis",
  payload: { encPubHex: HEX64, sigPubHex: HEX64 },
};

function addMember(userId: string, role: "owner" | "admin" | "member" | "reader"): ChainEntry {
  return {
    ...base(),
    op: "add_member",
    payload: { targetUserId: userId, encPubHex: HEX64, sigPubHex: HEX64, role },
  };
}

describe("deriveReportedView", () => {
  it("returns empty sets for an empty entry list", () => {
    expect(deriveReportedView([])).toEqual({ members: [], servers: [] });
  });

  it("folds genesis into an owner member", () => {
    const view = deriveReportedView([genesis]);
    expect(view.members).toEqual([{ userId: "user_owner", role: "owner", sinceSeq: genesis.seq }]);
  });

  it("applies add / change_role / remove in reported order", () => {
    const add = addMember("user_a", "reader");
    const change: ChainEntry = {
      ...base(),
      op: "change_role",
      payload: { targetUserId: "user_a", newRole: "admin" },
    };
    const addB = addMember("user_b", "member");
    const removeB: ChainEntry = {
      ...base(),
      op: "remove_member",
      payload: { targetUserId: "user_b" },
    };
    const view = deriveReportedView([genesis, add, change, addB, removeB]);
    expect(view.members.map((m) => [m.userId, m.role])).toEqual([
      ["user_owner", "owner"],
      ["user_a", "admin"],
    ]);
    // role を更新したエントリの seq が sinceSeq に反映される
    expect(view.members[1]?.sinceSeq).toBe(change.seq);
  });

  it("ignores change_role for an unknown member (as reported — no invention)", () => {
    const change: ChainEntry = {
      ...base(),
      op: "change_role",
      payload: { targetUserId: "user_ghost", newRole: "admin" },
    };
    expect(deriveReportedView([genesis, change]).members).toHaveLength(1);
  });

  it("folds grant_server / revoke_server into the server set", () => {
    const grant: ChainEntry = {
      ...base(),
      op: "grant_server",
      payload: {
        serverEncPubHex: HEX64,
        serverKeyFingerprintHex: FP,
        scopeEnvironmentIds: ["production"],
        leasePolicy: [],
      },
    };
    const granted = deriveReportedView([genesis, grant]);
    expect(granted.servers).toEqual([
      { keyFingerprintHex: FP, scopeEnvironmentIds: ["production"], sinceSeq: grant.seq },
    ]);
    const revoke: ChainEntry = {
      ...base(),
      op: "revoke_server",
      payload: { serverKeyFingerprintHex: FP },
    };
    expect(deriveReportedView([genesis, grant, revoke]).servers).toEqual([]);
  });

  it("ignores a hostile op name without touching the prototype chain", () => {
    // 敵対的サーバーが op: "__proto__" 等を名乗ってもプロトタイプ鎖の値を
    // 呼び出して throw しない(PR #107 pullfrog 指摘の回帰テスト)
    const hostile = { ...base(), op: "__proto__", payload: {} } as unknown as ChainEntry;
    const view = deriveReportedView([genesis, hostile]);
    expect(view.members).toHaveLength(1);
  });

  it("leaves membership untouched for data-plane ops", () => {
    const createEnv: ChainEntry = {
      ...base(),
      op: "create_environment",
      payload: { environmentId: "production", dekCommitmentHex: HEX64 },
    };
    const rotate: ChainEntry = {
      ...base(),
      op: "rotate_epoch",
      payload: {
        environmentId: "production",
        newEpoch: 2,
        reason: "manual",
        dekCommitmentHex: HEX64,
      },
    };
    const view = deriveReportedView([genesis, createEnv, rotate]);
    expect(view.members).toHaveLength(1);
    expect(view.servers).toEqual([]);
  });
});
