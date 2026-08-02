// メンバーシップログのサーバー保存(CRYPTO_SPEC §6.4)の統合テスト。
// vitest-pool-workers(workerd 実環境)で SELF 経由の HttpApi と DO SQLite を検証する。
//
// テストベクター(packages/crypto/test-vectors/chain-entries.json)の再利用:
// - 正常系 seq 1〜9 をサーバー経由の受理テストとして再生する
// - 認可系 negative(kind: "authorization")14 件を追記拒否テストとして再生する

import type { ChainEntry } from "@maruhi/crypto";
import { env, runInDurableObject, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import {
  MAX_CHAIN_ENTRIES,
  MAX_CHAIN_TOTAL_CANONICAL_BYTES,
  MAX_ENTRY_CANONICAL_BYTES,
  MAX_REQUEST_BODY_BYTES,
} from "../src/policy.ts";
import {
  toWireEntry,
  vectorAuthzNegatives,
  vectorEntries,
  vectorProjectId,
} from "./support/chain-vectors.ts";

const BASE = "https://example.com";
const JSON_HEADERS = { "content-type": "application/json" };

const initChain = (entry: ChainEntry): Promise<Response> =>
  SELF.fetch(`${BASE}/projects`, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({ entry }),
  });

const appendEntry = (
  projectId: string,
  parentHeadHashHex: string,
  entry: ChainEntry,
): Promise<Response> =>
  SELF.fetch(`${BASE}/projects/${projectId}/chain/entries`, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({ parentHeadHashHex, entry }),
  });

const getChain = (projectId: string): Promise<Response> =>
  SELF.fetch(`${BASE}/projects/${projectId}/chain`);

/** ベクターの seq 1..upTo をサーバーへ再生する(init + append)。 */
async function replayVectorChain(upTo: number): Promise<void> {
  for (const vector of vectorEntries) {
    if (vector.seq > upTo) {
      break;
    }
    if (vector.seq === 1) {
      const response = await initChain(toWireEntry(vector));
      expect(response.status).toBe(200);
    } else {
      const response = await appendEntry(
        vectorProjectId,
        vector.prev_hash_hex,
        toWireEntry(vector),
      );
      expect(response.status).toBe(200);
    }
  }
}

// この vitest-pool-workers 構成(cloudflareTest プラグイン 0.20.1)にはテスト間の
// ストレージ分離がなく、DO SQLite はファイル内のテスト間で持ち越される。
// ベクターチェーンのプロジェクト ID は genesis ハッシュで固定(全テストで同一)
// なので、テストごとに明示的に空へ戻す
beforeEach(async () => {
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(vectorProjectId));
  await runInDurableObject(stub, (_instance, state) => {
    // DO の ChainStore layer は最初のメソッド呼び出しまで遅延構築されるため、
    // テーブルが未作成のこともある(スキーマは src/chain-do.ts と同一)
    state.storage.sql.exec(
      `CREATE TABLE IF NOT EXISTS chain_entries (
         seq INTEGER PRIMARY KEY,
         entry_json TEXT NOT NULL,
         entry_hash_hex TEXT NOT NULL,
         canonical_bytes INTEGER NOT NULL
       )`,
    );
    state.storage.sql.exec("DELETE FROM chain_entries");
  });
});

describe("environment", () => {
  it("runs inside workerd", () => {
    expect(navigator.userAgent).toBe("Cloudflare-Workers");
  });
});

describe("POST /projects (genesis 受理)", () => {
  it("accepts the vector genesis and derives project id = genesis entry hash", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    const response = await initChain(toWireEntry(genesis));
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      projectId: vectorProjectId,
      headSeq: 1,
      headHashHex: genesis.entry_hash_hex,
    });
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

  it("rejects a non-genesis entry with 422 (bad-seq)", async () => {
    const entry2 = vectorEntries[1];
    if (entry2 === undefined) throw new Error("missing vector entry 2");
    const response = await initChain(toWireEntry(entry2));
    expect(response.status).toBe(422);
    const body = (await response.json()) as { seq: number; reason: string };
    expect(body.reason).toBe("bad-seq");
  });
});

describe("チェーン再生(正常系ベクター seq 1〜9)", () => {
  it("accepts the full vector chain and stores it append-only", async () => {
    await replayVectorChain(9);

    const response = await getChain(vectorProjectId);
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      projectId: string;
      entries: ChainEntry[];
      headSeq: number;
      headHashHex: string;
    };
    const last = vectorEntries[vectorEntries.length - 1];
    expect(body.projectId).toBe(vectorProjectId);
    expect(body.headSeq).toBe(9);
    expect(body.headHashHex).toBe(last?.entry_hash_hex);
    expect(body.entries.map((entry) => entry.seq)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    expect(body.entries.map((entry) => entry.op)).toEqual(vectorEntries.map((v) => v.op));

    // DO SQLite の実データを直接確認する(append-only 保存とハッシュ列)
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(vectorProjectId));
    await runInDurableObject(stub, (_instance, state) => {
      const rows = state.storage.sql
        .exec("SELECT seq, entry_hash_hex FROM chain_entries ORDER BY seq")
        .toArray();
      expect(rows.length).toBe(9);
      expect(rows.map((row) => row["entry_hash_hex"])).toEqual(
        vectorEntries.map((v) => v.entry_hash_hex),
      );
    });
  });
});

describe("GET /projects/:projectId/chain", () => {
  it("returns 404 for a project that was never initialized", async () => {
    const response = await getChain("ab".repeat(32));
    expect(response.status).toBe(404);
  });

  it("returns 400 for a malformed project id", async () => {
    const response = await getChain("not-a-project-id");
    expect(response.status).toBe(400);
  });
});

describe("CAS(§6.4 楽観ロック)", () => {
  it("rejects an append whose parent head is stale and reports the current head", async () => {
    await replayVectorChain(2);
    const entry3 = vectorEntries[2];
    const entry2 = vectorEntries[1];
    const genesis = vectorEntries[0];
    if (entry3 === undefined || entry2 === undefined || genesis === undefined) {
      throw new Error("missing vector entries");
    }

    // 親を genesis ハッシュ(1 つ古いヘッド)にすると拒否され、現ヘッドが返る
    const stale = await appendEntry(vectorProjectId, genesis.entry_hash_hex, toWireEntry(entry3));
    expect(stale.status).toBe(409);
    const body = (await stale.json()) as { currentHeadSeq: number; currentHeadHashHex: string };
    expect(body.currentHeadSeq).toBe(2);
    expect(body.currentHeadHashHex).toBe(entry2.entry_hash_hex);

    // 正しい親で再試行すると受理される(クライアントの再同期・再試行の流れ)
    const retried = await appendEntry(vectorProjectId, entry2.entry_hash_hex, toWireEntry(entry3));
    expect(retried.status).toBe(200);
  });

  it("rejects an append to an uninitialized project with 404", async () => {
    const entry2 = vectorEntries[1];
    if (entry2 === undefined) throw new Error("missing vector entry 2");
    const response = await appendEntry("cd".repeat(32), "0".repeat(64), toWireEntry(entry2));
    expect(response.status).toBe(404);
  });
});

describe("サーバー側検証(§6.4 = verifyChain 再実行)— 認可系 negative ベクター", () => {
  for (const negative of vectorAuthzNegatives) {
    it(`rejects ${negative.name} with 422 (${negative.expected_reason})`, async () => {
      const failingSeq = negative.entry.seq;
      await replayVectorChain(failingSeq - 1);
      const response = await appendEntry(
        vectorProjectId,
        negative.entry.prev_hash_hex,
        toWireEntry(negative.entry),
      );
      expect(response.status).toBe(422);
      const body = (await response.json()) as { seq: number; reason: string };
      expect(body.reason).toBe(negative.expected_reason);
      expect(body.seq).toBe(failingSeq);
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

describe("受理ポリシー(§6.4 サイズ上限)", () => {
  it("rejects an entry whose canonical bytes exceed 1 MiB with 413", async () => {
    await replayVectorChain(1);
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    // §6.1 のフィールド上限(1024 B)には違反するが、正規化は可能な巨大エントリ。
    // 受理ポリシー(1 MiB)の検査は verifyChain より先に行われるため 413 になる
    const oversized: ChainEntry = {
      suite: "maruhi/v1",
      seq: 2,
      prevHashHex: genesis.entry_hash_hex,
      op: "rotate_epoch",
      actor: { userId: "user-owner-0001", keyFingerprintHex: "ab".repeat(16) },
      payload: {
        environmentId: "e".repeat(600_000),
        newEpoch: 2,
        reason: "r".repeat(600_000),
      },
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
    const response = await initChain(second);
    expect(response.status).toBe(413);
    const body = (await response.json()) as { limitBytes: number };
    expect(body.limitBytes).toBe(MAX_ENTRY_CANONICAL_BYTES);
  });

  it("rejects an append once the chain holds the maximum number of entries", async () => {
    // 10,000 エントリの実チェーン再生は現実的でないため、DO SQLite に直接
    // 満杯状態を作って受理ポリシーの判定だけを検証する
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(vectorProjectId));
    const headHash = "ab".repeat(32);
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec(
        `WITH RECURSIVE seqs(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seqs WHERE n < ?)
         INSERT INTO chain_entries (seq, entry_json, entry_hash_hex, canonical_bytes)
         SELECT n, '{}', CASE n WHEN ? THEN ? ELSE 'ff' END, 10 FROM seqs`,
        MAX_CHAIN_ENTRIES,
        MAX_CHAIN_ENTRIES,
        headHash,
      );
    });
    const entry2 = vectorEntries[1];
    if (entry2 === undefined) throw new Error("missing vector entry 2");
    const response = await appendEntry(vectorProjectId, headHash, toWireEntry(entry2));
    expect(response.status).toBe(422);
    const body = (await response.json()) as { maxEntries: number };
    expect(body.maxEntries).toBe(MAX_CHAIN_ENTRIES);
  });

  it("rejects an append once cumulative canonical bytes would exceed the cap", async () => {
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(vectorProjectId));
    const headHash = "cd".repeat(32);
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec(
        "INSERT INTO chain_entries (seq, entry_json, entry_hash_hex, canonical_bytes) VALUES (1, '{}', ?, ?)",
        headHash,
        MAX_CHAIN_TOTAL_CANONICAL_BYTES,
      );
    });
    const entry2 = vectorEntries[1];
    if (entry2 === undefined) throw new Error("missing vector entry 2");
    const response = await appendEntry(vectorProjectId, headHash, toWireEntry(entry2));
    expect(response.status).toBe(422);
    const body = (await response.json()) as { maxTotalBytes: number };
    expect(body.maxTotalBytes).toBe(MAX_CHAIN_TOTAL_CANONICAL_BYTES);
  });
});
