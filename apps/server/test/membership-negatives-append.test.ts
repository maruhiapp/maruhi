// サーバー側検証(CRYPTO_SPEC §6.4 = verifyChain 再実行)— 認可系 negative
// ベクターのうち、汎用 append 経由(checkpoint の wire schema 拒否を含む)の
// 拒否テスト。複合エンドポイント経由の negative は
// membership-negatives-composite.test.ts。
// 共有 fixture・ベクター再生ヘルパは support/membership-scenario.ts(分割の
// 動機はシナリオモジュール冒頭を参照)。

import type { ChainEntry } from "@maruhi/crypto";
import { describe, expect, it } from "vitest";

import {
  toWireEntry,
  vectorAuthzNegatives,
  vectorEntries,
  vectorProjectId,
} from "./support/chain-vectors.ts";
import { resignEntryAt } from "./support/data-crypto.ts";
import {
  appendEntry,
  registerMembershipScenario,
  replayNegativePrefix,
  replayVectorChain,
} from "./support/membership-scenario.ts";

registerMembershipScenario();

/**
 * checkpoint op の汎用 append テスト(2026-08-28 — PR-M2 で standalone 受理へ
 * 移行): 固定長 hex の形式違反は api-schema の hex Schema が先に 400 で拒否する
 * (create-env-commitment-* の複合期待と同じ分担)。それ以外の合意規則 negative
 * (role / audit role / unknown / epoch / regression と検査順序)は crypto 層の
 * 4 実行環境テストが理由コードごと固定済みで、前提チェーン(checkpoint-baseline
 * 派生チェーン — タプル内容がダミー)は §16-2 の内容突合を通らず API では再生
 * できないため、ここでは繰り返さない。API 受理面(認可 2 水準・内容突合 5 理由・
 * 原子性・スナップショット保存)は data-checkpoint.test.ts が実データで固定する。
 */
function registerCheckpointAppendGuardTest(negative: (typeof vectorAuthzNegatives)[number]): void {
  const schemaRejected = [
    "checkpoint-manifest-hash-uppercase-hex",
    "checkpoint-values-digest-bad-length",
    "checkpoint-format-precedes-role",
  ].includes(negative.name);
  if (!schemaRejected) {
    return;
  }
  it(`rejects ${negative.name} at the wire schema (400)`, async () => {
    await replayVectorChain(1);
    const response = await appendEntry(
      vectorProjectId,
      negative.entry.prev_hash_hex,
      toWireEntry(negative.entry),
    );
    expect(response.status).toBe(400);
  });
}

describe("サーバー側検証(§6.4)— 認可系 negative ベクター(汎用 append 経由)", () => {
  for (const negative of vectorAuthzNegatives) {
    const op = negative.entry.op;
    if (op === "checkpoint") {
      registerCheckpointAppendGuardTest(negative);
      continue;
    }
    if (op === "create_environment" || op === "rotate_epoch") {
      continue;
    }
    // actor が非メンバーのケースは §11-2 の存在秘匿(404)が verifyChain より先に働く
    const expectsConcealment = negative.expected_reason === "actor-not-member";
    const label = expectsConcealment
      ? `rejects ${negative.name} with 404 (§11-2 concealment)`
      : `rejects ${negative.name} with 422 (${negative.expected_reason})`;
    it(label, async () => {
      const { head } = await replayNegativePrefix(negative);
      // 実ヘッドで再署名する(境界 checkpoint 挿入分のずれを吸収 — 複合側と同じ)
      const { entry } = await resignEntryAt(
        toWireEntry(negative.entry),
        head.seq + 1,
        head.hashHex,
      );
      const response = await appendEntry(vectorProjectId, entry.prevHashHex, entry);
      if (expectsConcealment) {
        expect(response.status).toBe(404);
        return;
      }
      expect(response.status).toBe(422);
      const body = (await response.json()) as { seq: number; reason: string };
      expect(body.reason).toBe(negative.expected_reason);
      expect(body.seq).toBe(entry.seq);
    });
  }

  it("rejects a tampered payload with 422 (bad-signature)", async () => {
    // ベクター negative "tampered-payload-role" の再構成: entry 2 の payload の
    // role を書き換え、署名は元のまま → 署名検証で拒否される
    await replayVectorChain(1);
    const genesis = vectorEntries[0];
    const entry2 = vectorEntries[1];
    if (genesis === undefined || entry2 === undefined) throw new Error("missing vectors");
    const wire = toWireEntry(entry2);
    if (wire.op !== "add_member") throw new Error("vector entry 2 should be add_member");
    const tampered: ChainEntry = {
      ...wire,
      payload: { ...wire.payload, role: "admin" },
    };
    const response = await appendEntry(vectorProjectId, genesis.entry_hash_hex, tampered);
    expect(response.status).toBe(422);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("bad-signature");
  });
});
