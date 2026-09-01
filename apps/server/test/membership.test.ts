// メンバーシップログのサーバー保存(CRYPTO_SPEC §6.4)+ 認可(AUTH_SPEC §11)の
// 統合テスト — genesis 受理・正常系ベクター再生・差分ロードキャッシュ。
// vitest-pool-workers(workerd 実環境)で SELF 経由の HttpApi と DO SQLite / D1 を検証する。
//
// 共有 fixture・ベクター再生ヘルパは support/membership-scenario.ts(認可・
// negative・受理ポリシーは membership-authz / membership-negatives-* /
// membership-policy の各ファイル — 分割の動機はシナリオモジュール冒頭を参照)。

import type { ChainEntry } from "@maruhi/crypto";
import { env, evictDurableObject, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { bearer } from "./support/auth.ts";
import { toWireEntry, vectorEntries, vectorProjectId } from "./support/chain-vectors.ts";
import { signEntryAt } from "./support/data-crypto.ts";
import {
  appendEntry,
  getChain,
  initChain,
  registerMembershipScenario,
  replayVectorChain,
  tokenFor,
  VECTOR_ORG,
} from "./support/membership-scenario.ts";

registerMembershipScenario();

describe("environment", () => {
  it("runs inside workerd", () => {
    expect(navigator.userAgent).toBe("Cloudflare-Workers");
  });
});

describe("POST /projects (genesis 受理 + org 連携 §11-3)", () => {
  it("accepts the vector genesis, derives project id = genesis entry hash, records the org row", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    const response = await initChain(toWireEntry(genesis));
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      projectId: vectorProjectId,
      headSeq: 1,
      headHashHex: genesis.entry_hash_hex,
    });
    // D1 の projects 行(org 帰属メタデータ)が追従する
    const row = await env.DB.prepare("SELECT org_id FROM projects WHERE id = ?")
      .bind(vectorProjectId)
      .first<{ org_id: string }>();
    expect(row?.org_id).toBe(VECTOR_ORG);
  });

  it("rejects a duplicate genesis submission with 409", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    await initChain(toWireEntry(genesis));
    const second = await initChain(toWireEntry(genesis));
    expect(second.status).toBe(409);
    const body = (await second.json()) as { projectId: string };
    expect(body.projectId).toBe(vectorProjectId);
  });

  it("repairs a missing projects row idempotently for the genesis actor (§11-3)", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    await initChain(toWireEntry(genesis));
    // DO 受理後・D1 行挿入前のクラッシュを模擬: 行だけを消す
    await env.DB.prepare("DELETE FROM projects WHERE id = ?").bind(vectorProjectId).run();
    const retried = await initChain(toWireEntry(genesis));
    expect(retried.status).toBe(200);
    await expect(retried.json()).resolves.toEqual({
      projectId: vectorProjectId,
      headSeq: 1,
      headHashHex: genesis.entry_hash_hex,
    });
    const row = await env.DB.prepare("SELECT org_id FROM projects WHERE id = ?")
      .bind(vectorProjectId)
      .first<{ org_id: string }>();
    expect(row?.org_id).toBe(VECTOR_ORG);
  });

  it("rejects init into an org the caller is not a member of (403 org-membership-required)", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    const response = await initChain(toWireEntry(genesis), { orgId: "org-not-mine" });
    expect(response.status).toBe(403);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("org-membership-required");
  });

  it("rejects init whose genesis actor is not the authenticated user (403 actor-mismatch §11-1)", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    const response = await initChain(toWireEntry(genesis), {
      headers: bearer(tokenFor("user-member-0002")),
    });
    expect(response.status).toBe(403);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("actor-mismatch");
  });

  it("rejects a non-genesis entry with 422 (bad-seq)", async () => {
    const entry2 = vectorEntries[1];
    if (entry2 === undefined) throw new Error("missing vector entry 2");
    const response = await initChain(toWireEntry(entry2));
    expect(response.status).toBe(422);
    const body = (await response.json()) as { seq: number; reason: string };
    expect(body.reason).toBe("bad-seq");
  });
});

describe("チェーン再生(正常系ベクター seq 1〜12。create/rotate は複合経由)", () => {
  it("accepts the full vector chain with interleaved boundary checkpoints, append-only", async () => {
    // 複合(vector seq 3 / 4 / 8 / 10 / 11)ごとに境界 checkpoint(H+2)が
    // 挿入される(§12-4 — 2026-08-27)。ベクターの 12 op はこの順序で全受理される
    const { head } = await replayVectorChain(12);

    const response = await getChain(vectorProjectId);
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      projectId: string;
      entries: ChainEntry[];
      headSeq: number;
      headHashHex: string;
    };
    const expectedOps = [
      "genesis",
      "add_member",
      "create_environment",
      "checkpoint",
      "rotate_epoch",
      "checkpoint",
      "remove_member",
      "add_member",
      "change_role",
      "create_environment",
      "checkpoint",
      "grant_server",
      "rotate_epoch",
      "checkpoint",
      "create_environment",
      "checkpoint",
      "revoke_server",
    ];
    expect(body.projectId).toBe(vectorProjectId);
    expect(body.headSeq).toBe(expectedOps.length);
    expect(body.headHashHex).toBe(head.hashHex);
    expect(body.entries.map((entry) => entry.seq)).toEqual(expectedOps.map((_, i) => i + 1));
    expect(body.entries.map((entry) => entry.op)).toEqual(expectedOps);
    // checkpoint を除いた op 列はベクター本編と一致する(同じ操作列の受理)
    expect(
      body.entries.filter((entry) => entry.op !== "checkpoint").map((entry) => entry.op),
    ).toEqual(vectorEntries.map((v) => v.op));

    // DO SQLite の実データを直接確認する(append-only 保存とハッシュ列)。最初の
    // 複合の checkpoint 挿入まで(seq 1〜3)はベクターの固定バイトのまま受理される
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(vectorProjectId));
    await runInDurableObject(stub, (_instance, state) => {
      const rows = state.storage.sql
        .exec("SELECT seq, entry_hash_hex FROM chain_entries ORDER BY seq")
        .toArray();
      expect(rows.length).toBe(expectedOps.length);
      expect(rows.slice(0, 3).map((row) => row["entry_hash_hex"])).toEqual(
        vectorEntries.slice(0, 3).map((v) => v.entry_hash_hex),
      );
    });
  });
});

const readChain = async () => {
  const response = await getChain(vectorProjectId);
  expect(response.status).toBe(200);
  return (await response.json()) as {
    projectId: string;
    entries: ChainEntry[];
    headSeq: number;
    headHashHex: string;
  };
};

describe("チェーンの差分ロードキャッシュ(chain-store.ts StateCache.chain)", () => {
  it("追記→読み取り→追記の往復がフルロードと同一結果を返す(複合追記の増分反映込み)", async () => {
    // seq 1〜12 の再生は「追記(増分反映)→ 読み取り(差分ロード)」を毎手で
    // 往復し、複合受理(create/rotate + 境界 checkpoint の 2 エントリ insertSync
    // 経路)もキャッシュに反映する
    const { members } = await replayVectorChain(12);
    const warm = await readChain();

    // DO 退去 = インスタンスメモリのキャッシュ破棄。次の読み取りはフルロードに
    // フォールバックし、ウォームキャッシュの結果と完全一致しなければならない
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(vectorProjectId));
    await evictDurableObject(stub);
    const cold = await readChain();
    expect(cold).toEqual(warm);

    // フォールバック後も追記を受理でき、以降の読み取りへ増分反映される
    const target = members.find((userId) => userId !== "user-owner-0001");
    if (target === undefined) throw new Error("vector chain has no removable member");
    const { entry } = await signEntryAt({
      seq: warm.headSeq + 1,
      prevHashHex: warm.headHashHex,
      actorUserId: "user-owner-0001",
      operation: { op: "remove_member", payload: { targetUserId: target } },
    });
    const appended = await appendEntry(vectorProjectId, warm.headHashHex, entry);
    expect(appended.status).toBe(200);
    const after = await readChain();
    expect(after.headSeq).toBe(warm.headSeq + 1);
    expect(after.entries.slice(0, warm.headSeq)).toEqual(warm.entries);
    expect(after.entries[warm.headSeq]).toEqual(entry);

    // もう一度キャッシュを破棄してもフルロードが同一結果に到達する
    await evictDurableObject(stub);
    const coldAfter = await readChain();
    expect(coldAfter).toEqual(after);
  });
});
