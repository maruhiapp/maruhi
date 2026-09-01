// メンバーシップログの受理ポリシー(CRYPTO_SPEC §6.4 サイズ上限)の統合テスト。
// 共有 fixture・ベクター再生ヘルパは support/membership-scenario.ts(分割の
// 動機はシナリオモジュール冒頭を参照)。

import type { ChainEntry } from "@maruhi/crypto";
import { env, evictDurableObject, runInDurableObject, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { chainCapacityExceeded } from "../src/chain-accept.ts";
import {
  MAX_CHAIN_ENTRIES,
  MAX_CHAIN_TOTAL_CANONICAL_BYTES,
  MAX_ENTRY_CANONICAL_BYTES,
  MAX_REQUEST_BODY_BYTES,
} from "../src/policy.ts";
import { BASE, JSON_HEADERS } from "./support/auth.ts";
import { vectorEntries, vectorProjectId } from "./support/chain-vectors.ts";
import { signEntryAt } from "./support/data-crypto.ts";
import {
  appendEntry,
  initChain,
  registerMembershipScenario,
  replayVectorChain,
} from "./support/membership-scenario.ts";

registerMembershipScenario();

describe("受理ポリシー(§6.4 サイズ上限)", () => {
  it("rejects an entry whose canonical bytes exceed 1 MiB with 413", async () => {
    await replayVectorChain(1);
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    // §6.1 のフィールド上限(1024 B)には違反するが、正規化は可能な巨大エントリ。
    // 受理ポリシー(1 MiB)の検査は verifyChain より先に行われるため 413 になる
    // (op は汎用 append の対象のもの — rotate_epoch は複合経由になったため
    // remove_member の巨大 targetUserId で構成する)
    const oversized: ChainEntry = {
      suite: "maruhi/v1",
      seq: 2,
      prevHashHex: genesis.entry_hash_hex,
      op: "remove_member",
      actor: { userId: "user-owner-0001", keyFingerprintHex: "ab".repeat(16) },
      payload: { targetUserId: "u".repeat(1_200_000) },
      timestampMs: 1754006400000,
      signatureHex: "12".repeat(64),
    };
    const response = await appendEntry(vectorProjectId, genesis.entry_hash_hex, oversized);
    expect(response.status).toBe(413);
    const body = (await response.json()) as { limitBytes: number };
    expect(body.limitBytes).toBe(MAX_ENTRY_CANONICAL_BYTES);
  });

  it("rejects a raw request body over the transport cap with a plain 413", async () => {
    const response = await SELF.fetch(`${BASE}/projects`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: `{"entry":"${"x".repeat(MAX_REQUEST_BODY_BYTES + 1024)}"}`,
    });
    expect(response.status).toBe(413);
  });

  it("enforces the transport cap on the measured stream, not the Content-Length header", async () => {
    // Content-Length を申告しないストリームボディ(chunked 相当)でも、実測で
    // 上限を強制して 413 になること(ヘッダー偽装・欠落による迂回の防止)
    const chunk = new TextEncoder().encode("x".repeat(64 * 1024));
    const chunkCount = Math.ceil((MAX_REQUEST_BODY_BYTES + 1024 * 1024) / chunk.length);
    let sent = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (sent >= chunkCount) {
          controller.close();
          return;
        }
        sent += 1;
        controller.enqueue(chunk);
      },
    });
    const response = await SELF.fetch(`${BASE}/projects`, {
      method: "POST",
      headers: JSON_HEADERS,
      body,
    });
    expect(response.status).toBe(413);
  });

  it("rejects an oversized genesis at init with 413 (worker-side pre-check)", async () => {
    const oversizedGenesis: ChainEntry = {
      suite: "maruhi/v1",
      seq: 1,
      prevHashHex: "0".repeat(64),
      op: "genesis",
      actor: { userId: "u".repeat(600_000), keyFingerprintHex: "ab".repeat(16) },
      payload: { encPubHex: "cd".repeat(32), sigPubHex: "ef".repeat(32) },
      timestampMs: 1754006400000,
      signatureHex: "12".repeat(64),
    };
    // actor.userId をもう 1 フィールド分肥大させ、正規化 1 MiB を超えさせる
    const second: ChainEntry = {
      ...oversizedGenesis,
      actor: { ...oversizedGenesis.actor, userId: "u".repeat(600_000) + "v".repeat(500_000) },
    };
    // サイズの先行検査は actor 一致(403)より先に働く(資源保護が優先)
    const response = await initChain(second);
    expect(response.status).toBe(413);
    const body = (await response.json()) as { limitBytes: number };
    expect(body.limitBytes).toBe(MAX_ENTRY_CANONICAL_BYTES);
  });

  it("rejects an append once cumulative canonical bytes would exceed the cap", async () => {
    // 有効な 2 エントリのチェーンを作り、蓄積バイト数だけを上限相当へ引き上げる
    // (§11-2 によりメンバーシップ判定 = チェーン導出が受理判定より先に走るため、
    // 保存チェーン自体は検証可能でなければならない)
    await replayVectorChain(2);
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(vectorProjectId));
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec(
        "UPDATE chain_entries SET canonical_bytes = ? WHERE seq = 1",
        MAX_CHAIN_TOTAL_CANONICAL_BYTES,
      );
    });
    // 保存行の直接改変(append-only 不変条件の外)はインスタンスの差分ロード
    // キャッシュに映らないため、DO 再起動相当の退去でフルロードに戻す
    await evictDurableObject(stub);
    const entry2 = vectorEntries[1];
    if (entry2 === undefined) throw new Error("missing vector entries");
    const { entry } = await signEntryAt({
      seq: 3,
      prevHashHex: entry2.entry_hash_hex,
      actorUserId: "user-owner-0001",
      operation: { op: "remove_member", payload: { targetUserId: "user-member-0002" } },
    });
    const response = await appendEntry(vectorProjectId, entry2.entry_hash_hex, entry);
    expect(response.status).toBe(422);
    const body = (await response.json()) as { maxTotalBytes: number };
    expect(body.maxTotalBytes).toBe(MAX_CHAIN_TOTAL_CANONICAL_BYTES);
  });

  it("caps the total entry count (§6.4 receipt policy, unit-level)", () => {
    // 10,000 本の有効チェーンの実生成は非現実的なため、判定関数を直接検証する
    // (プラミングは累積バイト数のテストが同じ分岐を通している)
    expect(chainCapacityExceeded(MAX_CHAIN_ENTRIES, 0, 10)).toBe(true);
    expect(chainCapacityExceeded(MAX_CHAIN_ENTRIES - 1, 0, 10)).toBe(false);
    expect(chainCapacityExceeded(1, MAX_CHAIN_TOTAL_CANONICAL_BYTES, 1)).toBe(true);
  });
});
