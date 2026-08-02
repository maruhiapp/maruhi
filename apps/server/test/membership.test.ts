// メンバーシップログのサーバー保存(CRYPTO_SPEC §6.4)+ 認可(AUTH_SPEC §11)の統合テスト。
// vitest-pool-workers(workerd 実環境)で SELF 経由の HttpApi と DO SQLite / D1 を検証する。
//
// テストベクター(packages/crypto/test-vectors/chain-entries.json)の再利用:
// - 正常系 seq 1〜9 をサーバー経由の受理テストとして再生する(actor ごとの実 PAT 認証)
// - 認可系 negative 14 件を追記拒否テストとして再生する。ただし actor が非メンバーの
//   ケースは、§11-2(存在秘匿)により verifyChain の 422 より先に 404 になる
//
// 認証は実発行経路(device 交換)で PAT を取得する。ベクターの固定 user_id は
// D1 への直接シード(users + linked_identities)で整合させる(AUTH_SPEC §11-1 裁定)。

import type { TokenScope } from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { env, runInDurableObject, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { chainCapacityExceeded } from "../src/chain-do.ts";
import {
  MAX_CHAIN_ENTRIES,
  MAX_CHAIN_TOTAL_CANONICAL_BYTES,
  MAX_ENTRY_CANONICAL_BYTES,
  MAX_REQUEST_BODY_BYTES,
} from "../src/policy.ts";
import {
  BASE,
  bearer,
  deviceToken,
  JSON_HEADERS,
  loginSession,
  resetAuthDb,
  seedOrgMember,
  seedUser,
  sessionHeaders,
} from "./support/auth.ts";
import {
  toWireEntry,
  vectorAuthzNegatives,
  vectorEntries,
  vectorProjectId,
} from "./support/chain-vectors.ts";
import { resetProjectDo } from "./support/project-do.ts";

const VECTOR_ORG = "org-vector-0001";
const GITHUB_IDS: Record<string, number> = {
  "user-owner-0001": 9001,
  "user-member-0002": 9002,
  "user-admin-0003": 9003,
};

let tokens: Record<string, string> = {};

function tokenFor(userId: string): string {
  const token = tokens[userId];
  if (token === undefined) {
    throw new Error(`no seeded token for ${userId}`);
  }
  return token;
}

const initChain = (
  entry: ChainEntry,
  options?: { readonly headers?: Record<string, string>; readonly orgId?: string },
): Promise<Response> =>
  SELF.fetch(`${BASE}/projects`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...(options?.headers ?? bearer(tokenFor("user-owner-0001"))) },
    body: JSON.stringify({ orgId: options?.orgId ?? VECTOR_ORG, entry }),
  });

const appendEntry = (
  projectId: string,
  parentHeadHashHex: string,
  entry: ChainEntry,
  headers?: Record<string, string>,
): Promise<Response> =>
  SELF.fetch(`${BASE}/projects/${projectId}/chain/entries`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...(headers ?? bearer(tokenFor(entry.actor.userId))) },
    body: JSON.stringify({ parentHeadHashHex, entry }),
  });

const getChain = (projectId: string, headers?: Record<string, string>): Promise<Response> =>
  SELF.fetch(`${BASE}/projects/${projectId}/chain`, {
    headers: headers ?? bearer(tokenFor("user-owner-0001")),
  });

/** ベクターの seq 1..upTo をサーバーへ再生する(init + append。actor ごとの PAT)。 */
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
// ストレージ分離がなく、DO SQLite / D1 はファイル内のテスト間で持ち越される。
// テストごとに明示的に空へ戻し、ベクターユーザーをシードして PAT を取り直す
beforeEach(async () => {
  await resetProjectDo(vectorProjectId);
  await resetAuthDb();
  tokens = {};
  for (const [userId, githubId] of Object.entries(GITHUB_IDS)) {
    await seedUser(userId, githubId);
    tokens[userId] = await deviceToken(githubId);
  }
  await seedOrgMember(VECTOR_ORG, "user-owner-0001", "member");
});

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

describe("チェーン API の認可(AUTH_SPEC §11)", () => {
  it("rejects unauthenticated requests with 401", async () => {
    const genesis = vectorEntries[0];
    const entry2 = vectorEntries[1];
    if (genesis === undefined || entry2 === undefined) throw new Error("missing vectors");
    const get = await SELF.fetch(`${BASE}/projects/${vectorProjectId}/chain`);
    expect(get.status).toBe(401);
    const init = await initChain(toWireEntry(genesis), { headers: {} });
    expect(init.status).toBe(401);
    const append = await appendEntry(vectorProjectId, "0".repeat(64), toWireEntry(entry2), {});
    expect(append.status).toBe(401);
  });

  it("conceals the project from authenticated non-members with 404 (§11-2)", async () => {
    await replayVectorChain(1);
    await seedUser("user-stranger-0009", 9009);
    const strangerToken = await deviceToken(9009);

    const get = await getChain(vectorProjectId, bearer(strangerToken));
    expect(get.status).toBe(404);

    // 署名は検証されるより先にメンバーシップで拒否される(現ヘッド情報も返さない)
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    const forged: ChainEntry = {
      suite: "maruhi/v1",
      seq: 2,
      prevHashHex: genesis.entry_hash_hex,
      op: "rotate_epoch",
      actor: { userId: "user-stranger-0009", keyFingerprintHex: "ab".repeat(16) },
      payload: { environmentId: "env-prod-0001", newEpoch: 2, reason: "x" },
      timestampMs: 1754006400000,
      signatureHex: "12".repeat(64),
    };
    const append = await appendEntry(
      vectorProjectId,
      "f".repeat(64),
      forged,
      bearer(strangerToken),
    );
    expect(append.status).toBe(404);
  });

  it("removed members are concealed too: the §11-2 mapping of actor-not-member", async () => {
    // seq 4 で user-member-0002 は削除される。以降の追記はチェーン検証(422)では
    // なく、メンバーシップ判定の 404 で拒否される(存在秘匿が優先)
    const nonmember = vectorAuthzNegatives.find((n) => n.name === "authz-nonmember-actor");
    if (nonmember === undefined) throw new Error("missing authz-nonmember-actor vector");
    await replayVectorChain(nonmember.entry.seq - 1);
    const response = await appendEntry(
      vectorProjectId,
      nonmember.entry.prev_hash_hex,
      toWireEntry(nonmember.entry),
    );
    expect(response.status).toBe(404);
  });

  it("rejects an append whose entry actor differs from the principal (403 actor-mismatch §11-1)", async () => {
    await replayVectorChain(2);
    const entry3 = vectorEntries[2];
    if (entry3 === undefined) throw new Error("missing vector entry 3");
    // entry3 の actor は user-member-0002。owner のトークンで送ると一致しない
    const response = await appendEntry(
      vectorProjectId,
      entry3.prev_hash_hex,
      toWireEntry(entry3),
      bearer(tokenFor("user-owner-0001")),
    );
    expect(response.status).toBe(403);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("actor-mismatch");
  });

  it("enforces token scopes: read scope can get but cannot append (§9-2)", async () => {
    await replayVectorChain(2);
    const readOnly: readonly TokenScope[] = [{ project: vectorProjectId, permission: "read" }];
    const readToken = await deviceToken(9002, readOnly);

    const get = await getChain(vectorProjectId, bearer(readToken));
    expect(get.status).toBe(200);

    const entry3 = vectorEntries[2];
    if (entry3 === undefined) throw new Error("missing vector entry 3");
    const append = await appendEntry(
      vectorProjectId,
      entry3.prev_hash_hex,
      toWireEntry(entry3),
      bearer(readToken),
    );
    expect(append.status).toBe(403);
    const body = (await append.json()) as { reason: string };
    expect(body.reason).toBe("insufficient-permission");
  });

  it("conceals projects outside the token's scope with 404 (§11-2)", async () => {
    await replayVectorChain(1);
    const otherScope: readonly TokenScope[] = [{ project: "ff".repeat(32), permission: "admin" }];
    const scopedToken = await deviceToken(9001, otherScope);
    const response = await getChain(vectorProjectId, bearer(scopedToken));
    expect(response.status).toBe(404);
  });

  it("conceals everything from an empty-scope token (§11-2)", async () => {
    await replayVectorChain(1);
    const emptyScopeToken = await deviceToken(9001, []);
    const response = await getChain(vectorProjectId, bearer(emptyScopeToken));
    expect(response.status).toBe(404);
  });

  it("distinguishes write from admin ops (§6 の op→必要権限表)", async () => {
    // seq 3 は rotate_epoch(write 要求)、actor は user-member-0002。
    // write スコープのトークンで通り、同じトークンでは add_member(admin 要求)が
    // 403 になる — 全 op を write(または admin)に潰す退行をここで判別する
    await replayVectorChain(2);
    const writeScope: readonly TokenScope[] = [{ project: "*", permission: "write" }];
    const memberWrite = await deviceToken(9002, writeScope);
    const entry3 = vectorEntries[2];
    if (entry3 === undefined) throw new Error("missing vector entry 3");
    const rotate = await appendEntry(
      vectorProjectId,
      entry3.prev_hash_hex,
      toWireEntry(entry3),
      bearer(memberWrite),
    );
    expect(rotate.status).toBe(200);

    // seq 4 は remove_member(admin 要求)、actor は user-owner-0001
    const ownerWrite = await deviceToken(9001, writeScope);
    const entry4 = vectorEntries[3];
    if (entry4 === undefined) throw new Error("missing vector entry 4");
    const removal = await appendEntry(
      vectorProjectId,
      entry4.prev_hash_hex,
      toWireEntry(entry4),
      bearer(ownerWrite),
    );
    expect(removal.status).toBe(403);
    const body = (await removal.json()) as { reason: string };
    expect(body.reason).toBe("insufficient-permission");
  });

  it("requires admin scope for init (genesis = プロジェクト作成)", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    const writeScope: readonly TokenScope[] = [{ project: "*", permission: "write" }];
    const ownerWrite = await deviceToken(9001, writeScope);
    const response = await initChain(toWireEntry(genesis), { headers: bearer(ownerWrite) });
    expect(response.status).toBe(403);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("insufficient-permission");
  });

  it("accepts session-cookie auth with the CSRF header and rejects writes without it (§5)", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    const session = await loginSession(9001);

    // CSRF ヘッダーなしの書き込みは 403
    const headers = sessionHeaders(session);
    const withoutCsrf: Record<string, string> = { cookie: headers["cookie"] ?? "" };
    const rejected = await initChain(toWireEntry(genesis), {
      headers: { ...JSON_HEADERS, ...withoutCsrf },
    });
    expect(rejected.status).toBe(403);

    // CSRF ヘッダー付きは受理される(セッション = 本人のフルパワー)
    const accepted = await initChain(toWireEntry(genesis), {
      headers: { ...JSON_HEADERS, ...headers },
    });
    expect(accepted.status).toBe(200);
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

  it("allows every chain-derived member including reader to fetch (§6.2)", async () => {
    await replayVectorChain(6);
    // seq 5 で user-admin-0003 が reader として追加され、seq 6 で change_role される。
    // どの時点でもチェーン導出メンバーであれば取得できる
    const response = await getChain(vectorProjectId, bearer(tokenFor("user-admin-0003")));
    expect(response.status).toBe(200);
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
    // actor が非メンバーのケースは §11-2 の存在秘匿(404)が verifyChain より先に働く
    const expectsConcealment = negative.expected_reason === "actor-not-member";
    const label = expectsConcealment
      ? `rejects ${negative.name} with 404 (§11-2 concealment)`
      : `rejects ${negative.name} with 422 (${negative.expected_reason})`;
    it(label, async () => {
      const failingSeq = negative.entry.seq;
      await replayVectorChain(failingSeq - 1);
      const response = await appendEntry(
        vectorProjectId,
        negative.entry.prev_hash_hex,
        toWireEntry(negative.entry),
      );
      if (expectsConcealment) {
        expect(response.status).toBe(404);
        return;
      }
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
    const entry2 = vectorEntries[1];
    const entry3 = vectorEntries[2];
    if (entry2 === undefined || entry3 === undefined) throw new Error("missing vector entries");
    const response = await appendEntry(vectorProjectId, entry2.entry_hash_hex, toWireEntry(entry3));
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
