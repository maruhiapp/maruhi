// リカバリーブロブ API の統合テスト(AUTH_SPEC §13。CRYPTO_SPEC §8 のサーバー面)。
// vitest-pool-workers(workerd 実環境)で SELF 経由の実経路を検証する。
//
// ブロブはサーバーから見て不透明な暗号文なので、内容は任意の hex フィクスチャで
// よい(復号可能性はクライアント側 = CLI のテストが担う)。

import { env, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { RECOVERY_FETCH_LIMIT } from "../src/db.package/index.ts";
import {
  BASE,
  bearer,
  deviceToken,
  JSON_HEADERS,
  loginSession,
  resetAuthDb,
  sessionHeaders,
} from "./support/auth.ts";

beforeEach(async () => {
  await resetAuthDb();
});

const NONCE_HEX = "0f".repeat(12);
const CIPHERTEXT_HEX = "ab".repeat(64);

function wrapBody(ciphertextHex: string = CIPHERTEXT_HEX): string {
  return JSON.stringify({ suite: "maruhi/v1", nonceHex: NONCE_HEX, ciphertextHex });
}

async function putWrap(headers: Record<string, string>, ciphertextHex?: string): Promise<Response> {
  return SELF.fetch(`${BASE}/auth/recovery`, {
    method: "PUT",
    headers: { ...JSON_HEADERS, ...headers },
    body: wrapBody(ciphertextHex),
  });
}

describe("PUT /auth/recovery(§13-1 / §13-2)", () => {
  it("registers a blob for a device-flow token (default * × admin scope)", async () => {
    const token = await deviceToken(501);
    const put = await putWrap(bearer(token));
    expect(put.status).toBe(204);

    const get = await SELF.fetch(`${BASE}/auth/recovery`, { headers: bearer(token) });
    expect(get.status).toBe(200);
    const body = (await get.json()) as Record<string, unknown>;
    expect(body["suite"]).toBe("maruhi/v1");
    expect(body["nonceHex"]).toBe(NONCE_HEX);
    expect(body["ciphertextHex"]).toBe(CIPHERTEXT_HEX);
    expect(typeof body["updatedAtMs"]).toBe("number");
  });

  it("registers a blob for a session principal (CSRF ヘッダー込み)", async () => {
    const session = await loginSession(502);
    const put = await putWrap(sessionHeaders(session));
    expect(put.status).toBe(204);
    // 取得もセッション主体は CSRF ヘッダー必須(§13-2 — 状態を持つ GET)
    const get = await SELF.fetch(`${BASE}/auth/recovery`, {
      headers: sessionHeaders(session),
    });
    expect(get.status).toBe(200);
  });

  it("session GET without the CSRF header is rejected and does not consume the window", async () => {
    const session = await loginSession(507);
    expect((await putWrap(sessionHeaders(session))).status).toBe(204);
    // Lax クッキーだけが同送されるクロスサイト遷移の形(カスタムヘッダーなし)
    const get = await SELF.fetch(`${BASE}/auth/recovery`, {
      headers: { cookie: sessionHeaders(session)["cookie"] ?? "" },
    });
    expect(get.status).toBe(403);
    const body = (await get.json()) as Record<string, unknown>;
    expect(body["reason"]).toBe("csrf-header-required");
    const row = await env.DB.prepare("SELECT fetch_count FROM recovery_wraps").first<{
      fetch_count: number;
    }>();
    expect(row?.fetch_count).toBe(0);
  });

  it("re-registration replaces the previous blob (再発行 = 置換。§13-1)", async () => {
    const token = await deviceToken(503);
    expect((await putWrap(bearer(token))).status).toBe(204);
    const reissued = "cd".repeat(64);
    expect((await putWrap(bearer(token), reissued)).status).toBe(204);

    const get = await SELF.fetch(`${BASE}/auth/recovery`, { headers: bearer(token) });
    const body = (await get.json()) as Record<string, unknown>;
    // 旧ブロブは残らない(user 単位で高々 1 行)
    expect(body["ciphertextHex"]).toBe(reissued);
  });

  it("rejects a project-scoped admin token with 403 (§13-2 の鍵素材管理条件)", async () => {
    const token = await deviceToken(504, [{ project: "f0".repeat(32), permission: "admin" }]);
    const put = await putWrap(bearer(token));
    expect(put.status).toBe(403);
  });

  it("rejects a * × write token with 403 (admin 未満)", async () => {
    const token = await deviceToken(505, [{ project: "*", permission: "write" }]);
    const put = await putWrap(bearer(token));
    expect(put.status).toBe(403);
  });

  it("rejects malformed wraps with 400 (nonce 長・hex 形式は Schema 検証)", async () => {
    const token = await deviceToken(506);
    const bad = await SELF.fetch(`${BASE}/auth/recovery`, {
      method: "PUT",
      headers: { ...JSON_HEADERS, ...bearer(token) },
      body: JSON.stringify({ suite: "maruhi/v1", nonceHex: "0f", ciphertextHex: CIPHERTEXT_HEX }),
    });
    expect(bad.status).toBe(400);
  });

  it("requires authentication (401)", async () => {
    const put = await SELF.fetch(`${BASE}/auth/recovery`, {
      method: "PUT",
      headers: JSON_HEADERS,
      body: wrapBody(),
    });
    expect(put.status).toBe(401);
  });
});

describe("GET /auth/recovery(§13-2 / §13-3)", () => {
  it("returns 404 when no blob is registered", async () => {
    const token = await deviceToken(511);
    const get = await SELF.fetch(`${BASE}/auth/recovery`, { headers: bearer(token) });
    expect(get.status).toBe(404);
  });

  it("rejects a scope-limited token with 403 (要監視操作の遮断)", async () => {
    const token = await deviceToken(512, [{ project: "*", permission: "read" }]);
    const get = await SELF.fetch(`${BASE}/auth/recovery`, { headers: bearer(token) });
    expect(get.status).toBe(403);
  });

  it("rate-limits blob fetches per fixed window and reissue resets it (§13-3)", async () => {
    const token = await deviceToken(513);
    expect((await putWrap(bearer(token))).status).toBe(204);

    for (let i = 0; i < RECOVERY_FETCH_LIMIT; i += 1) {
      const ok = await SELF.fetch(`${BASE}/auth/recovery`, { headers: bearer(token) });
      expect(ok.status).toBe(200);
    }
    const limited = await SELF.fetch(`${BASE}/auth/recovery`, { headers: bearer(token) });
    expect(limited.status).toBe(429);
    const body = (await limited.json()) as Record<string, unknown>;
    expect(body["_tag"]).toBe("RecoveryRateLimited");
    expect(typeof body["retryAfterSeconds"]).toBe("number");
    expect(body["retryAfterSeconds"] as number).toBeGreaterThan(0);

    // 再発行(置換)は取得窓をリセットする(新ブロブに旧試行履歴を引き継がない)
    expect((await putWrap(bearer(token), "ef".repeat(64))).status).toBe(204);
    const afterReissue = await SELF.fetch(`${BASE}/auth/recovery`, { headers: bearer(token) });
    expect(afterReissue.status).toBe(200);
  });

  it("counts concurrent fetches atomically: exactly the limit succeeds and the count matches (B9)", async () => {
    const token = await deviceToken(516);
    expect((await putWrap(bearer(token))).status).toBe(204);
    // 上限越えの同時リクエスト: 計数は条件付き相対 UPDATE(1 文)なので、
    // どの並び方でも成功はちょうど上限件・保存 count は上限で止まる
    const responses = await Promise.all(
      Array.from({ length: RECOVERY_FETCH_LIMIT + 3 }, () =>
        SELF.fetch(`${BASE}/auth/recovery`, { headers: bearer(token) }),
      ),
    );
    const succeeded = responses.filter((response) => response.status === 200).length;
    const limited = responses.filter((response) => response.status === 429).length;
    expect(succeeded).toBe(RECOVERY_FETCH_LIMIT);
    expect(limited).toBe(3);
    const row = await env.DB.prepare("SELECT fetch_count FROM recovery_wraps").first<{
      fetch_count: number;
    }>();
    expect(row?.fetch_count).toBe(RECOVERY_FETCH_LIMIT);
    // 監査行(auth.recovery_blob_fetched)は許可された取得と 1:1(§5.2 の同一
    // トランザクション原則を保ったまま)
    const audit = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM user_audit_events WHERE event = 'auth.recovery_blob_fetched'",
    ).first<{ n: number }>();
    expect(audit?.n).toBe(RECOVERY_FETCH_LIMIT);
  });

  it("rejects an unknown stored suite without consuming the fetch window", async () => {
    const token = await deviceToken(515);
    expect((await putWrap(bearer(token))).status).toBe(204);
    // v1 の書き込み経路では作れない行を直接作る(将来バージョンの書き込み /
    // DB 破損の想定)。黙って v1 として配布しない(500)+ 窓を消費しない
    await env.DB.prepare("UPDATE recovery_wraps SET suite = 'maruhi/v2'").run();
    const broken = await SELF.fetch(`${BASE}/auth/recovery`, { headers: bearer(token) });
    expect(broken.status).toBe(500);
    const row = await env.DB.prepare("SELECT fetch_count FROM recovery_wraps").first<{
      fetch_count: number;
    }>();
    expect(row?.fetch_count).toBe(0);
  });

  it("does not count 404s toward the fetch window (未登録は計数外)", async () => {
    const token = await deviceToken(514);
    for (let i = 0; i < RECOVERY_FETCH_LIMIT + 2; i += 1) {
      const notFound = await SELF.fetch(`${BASE}/auth/recovery`, { headers: bearer(token) });
      expect(notFound.status).toBe(404);
    }
    // 登録後は上限いっぱいまで取得できる(404 が窓を消費していない)
    expect((await putWrap(bearer(token))).status).toBe(204);
    const first = await SELF.fetch(`${BASE}/auth/recovery`, { headers: bearer(token) });
    expect(first.status).toBe(200);
  });
});

describe("GET /auth/recovery/status(§13-2)", () => {
  it("reports registration state to any authenticated principal (ブロブは運ばない)", async () => {
    const token = await deviceToken(521, [{ project: "*", permission: "read" }]);
    const before = await SELF.fetch(`${BASE}/auth/recovery/status`, { headers: bearer(token) });
    expect(before.status).toBe(200);
    expect(await before.json()).toEqual({ registered: false, updatedAtMs: null });

    // 登録は同一ユーザーのセッション経由で行う(同名 device flow トークンの
    // 再発行はローテーションで既存トークンを失効させてしまうため)
    const session = await loginSession(521);
    expect((await putWrap(sessionHeaders(session))).status).toBe(204);

    const after = await SELF.fetch(`${BASE}/auth/recovery/status`, { headers: bearer(token) });
    expect(after.status).toBe(200);
    const body = (await after.json()) as Record<string, unknown>;
    expect(body["registered"]).toBe(true);
    expect(typeof body["updatedAtMs"]).toBe("number");
    expect(Object.keys(body).toSorted()).toEqual(["registered", "updatedAtMs"]);
  });

  it("requires authentication (401)", async () => {
    const get = await SELF.fetch(`${BASE}/auth/recovery/status`);
    expect(get.status).toBe(401);
  });
});
