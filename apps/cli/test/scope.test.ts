// scope.ts / deks.ts の scope 規則の単体テスト(2026-09-15 ES K4 — 設計録 §10)。
//
// 固定する性質:
//  1. 受信側規則(CRYPTO_SPEC §6.3 — K4-F): 自分宛 DEK の唯一の取得口 environmentKeysFor
//     は、環境 ∉ 自分の scope なら**取得も開封もせず**型付きエラーで止まる
//  2. 義務の環境集合の具体化(K4-J): `all` は義務 seq 時点で存在した環境に限る
//     (後に作成された環境は含まない)
//  3. 包含述語(K4-I): §6.2 の集合代数(`all` = U、`listed ⊉ all`、listed 同士は部分集合)

import type { ProjectId } from "@maruhi/core";
import { Effect } from "effect";
import { beforeAll, describe, expect, it } from "vitest";

import type { MaruhiClient } from "../src/api.ts";
import { environmentKeysFor } from "../src/deks.ts";
import { environmentsOfScopeAt, sameScope, scopeChangeAt, scopeContains } from "../src/scope.ts";
import { type VerifiedProject, verifyChainSnapshot } from "../src/sync.ts";
import {
  addScopedMemberOp,
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  genesisOp,
  makeTestUser,
  removeMemberOp,
  type TestUser,
} from "./support/crypto.ts";

let owner: TestUser;
let dev: TestUser;
let built: BuiltChain;
let verified: VerifiedProject;

async function verify(chain: BuiltChain): Promise<VerifiedProject> {
  return Effect.runPromise(
    verifyChainSnapshot({
      projectId: chain.projectId as ProjectId,
      entries: chain.entries,
      claimedHeadSeq: chain.entries.length,
      claimedHeadHashHex: chain.hashes[chain.hashes.length - 1] ?? "",
    }),
  );
}

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  dev = await makeTestUser("user-dev-2222");
  const dek = crypto.getRandomValues(new Uint8Array(32));
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp("env-dev", dek) },
    { actor: owner, operation: createEnvironmentOp("env-prod", dek) },
    { actor: owner, operation: addScopedMemberOp(dev, "member", ["env-dev"]) },
    { actor: owner, operation: removeMemberOp(dev) },
    { actor: owner, operation: createEnvironmentOp("env-later", dek) },
  ]);
  verified = await verify(built);
});

describe("受信側の scope 規則(CRYPTO_SPEC §6.3 — K4-F)", () => {
  it("環境 ∉ 自分の scope なら DEK を取得せず型付きエラーで止まる(サーバーへの要求ゼロ)", async () => {
    const chain = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp("env-dev", new Uint8Array(32)) },
      { actor: owner, operation: createEnvironmentOp("env-prod", new Uint8Array(32)) },
      { actor: owner, operation: addScopedMemberOp(dev, "member", ["env-dev"]) },
    ]);
    const view = await verify(chain);
    let listMineCalls = 0;
    const client = {
      deks: {
        listMine: () => {
          listMineCalls += 1;
          return Effect.die(new Error("must not be called"));
        },
      },
    } as unknown as MaruhiClient;
    // flip: 失敗(CliError)を成功側へ倒して取り出す(成功したらテスト失敗)
    const failure = await Effect.runPromise(
      Effect.flip(
        environmentKeysFor({
          client,
          verified: view,
          environmentId: "env-prod",
          recipient: { userId: dev.userId, encPubHex: dev.encPubHex, encKeyPair: dev.encKeyPair },
        }),
      ),
    );
    expect(failure.message).toContain("is outside your environment scope");
    expect(failure.message).toContain("is not used (CRYPTO_SPEC §6.3");
    expect(failure.message).toContain("your scope: env-dev");
    expect(listMineCalls).toBe(0);
  });
});

describe("義務の環境集合の具体化(K4-J)", () => {
  it("all は義務 seq 時点で存在した環境に限る(後に作成された環境は含まない)", () => {
    // seq 5 = remove_member。env-later は seq 6 で作成
    expect(environmentsOfScopeAt(verified, { kind: "all" }, 5)).toEqual(["env-dev", "env-prod"]);
    expect(environmentsOfScopeAt(verified, { kind: "all" }, 6)).toEqual([
      "env-dev",
      "env-later",
      "env-prod",
    ]);
    expect(
      environmentsOfScopeAt(verified, { kind: "listed", environmentIds: ["env-prod"] }, 5),
    ).toEqual(["env-prod"]);
  });

  it("all → listed の縮小は U \\ X をその時点の環境集合に具体化する", () => {
    const change = scopeChangeAt(
      verified,
      { kind: "all" },
      { kind: "listed", environmentIds: ["env-dev"] },
      5,
    );
    expect(change.narrowed).toEqual(["env-prod"]);
    expect(change.widened).toEqual([]);
  });
});

describe("包含述語(CRYPTO_SPEC §6.2 の集合代数 — K4-I)", () => {
  const all = { kind: "all" } as const;
  const devOnly = { kind: "listed", environmentIds: ["env-dev"] } as const;
  const both = { kind: "listed", environmentIds: ["env-dev", "env-prod"] } as const;
  const none = { kind: "listed", environmentIds: [] } as const;

  it("all ⊇ 任意、listed ⊉ all、listed 同士は部分集合、空 listed は何にでも包含される", () => {
    expect(scopeContains(all, all)).toBe(true);
    expect(scopeContains(all, both)).toBe(true);
    expect(scopeContains(devOnly, all)).toBe(false);
    expect(scopeContains(both, devOnly)).toBe(true);
    expect(scopeContains(devOnly, both)).toBe(false);
    expect(scopeContains(none, none)).toBe(true);
    expect(scopeContains(devOnly, none)).toBe(true);
    expect(scopeContains(none, devOnly)).toBe(false);
  });

  it("sameScope は集合として比較する(順序を問わず、all と listed{} は別)", () => {
    expect(sameScope(both, { kind: "listed", environmentIds: ["env-prod", "env-dev"] })).toBe(true);
    expect(sameScope(all, none)).toBe(false);
    expect(sameScope({ scopeKind: "all", scopeEnvironmentIds: [] }, all)).toBe(true);
  });
});
