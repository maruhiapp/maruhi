// トークン管理 API + 既定 TTL(AUTH_SPEC §6 — W3a)の統合テスト。
//
// - TTL は発行時固定(§6: セッション §5 のスライディングと意図的に非対称)
// - 一覧は本人のメタデータのみ(生値・token_hash は構造ごと返さない)
// - 指定失効の判定順(裁定 CG): 401 → 403(呼び出し資格のみ)→ 一様 404
// - 旧無期限行(expires_at NULL)は検証で fail-closed に 401(裁定 CE)。
//   移行 SQL(token_ttl_reanchor)は TEST_MIGRATIONS の実物を再実行して検証する

import { applyD1Migrations, env, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import {
  BASE,
  bearer,
  deviceToken,
  JSON_HEADERS,
  loginSession,
  resetAuthDb,
  sessionHeaders,
} from "./support/auth.ts";

const DAY_MS = 24 * 60 * 60 * 1000;
const SESSION_COOKIE = "__Host-maruhi_session";

interface ExchangeBody {
  readonly token: string;
  readonly tokenId: string;
  readonly userId: string;
  readonly expiresAtMs: number;
}

/** device 交換の完全応答(support の deviceToken は生値のみ返すため別に持つ)。 */
async function exchange(
  githubId: number,
  extra?: Readonly<Record<string, unknown>>,
): Promise<ExchangeBody> {
  const response = await SELF.fetch(`${BASE}/auth/device/exchange`, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({ githubAccessToken: `gho_test${githubId}`, ...extra }),
  });
  if (response.status !== 200) {
    throw new Error(`device exchange failed: ${response.status}`);
  }
  return (await response.json()) as ExchangeBody;
}

interface TokenRow {
  readonly id: string;
  readonly expires_at: number | null;
  readonly created_at: number;
}

async function tokenRow(id: string): Promise<TokenRow> {
  const row = await env.DB.prepare("SELECT id, expires_at, created_at FROM api_tokens WHERE id = ?")
    .bind(id)
    .first<TokenRow>();
  if (row === null) {
    throw new Error("expected token row");
  }
  return row;
}

beforeEach(async () => {
  await resetAuthDb();
});

describe("既定 TTL(AUTH_SPEC §6 — L-2 の解消)", () => {
  it("fixes expires_at to created_at + 90 days at issuance and reports it in the response", async () => {
    const issued = await exchange(801);
    const row = await tokenRow(issued.tokenId);
    expect(row.expires_at).toBe(row.created_at + 90 * DAY_MS);
    expect(issued.expiresAtMs).toBe(row.expires_at);
  });

  it("honors an explicit expiresInDays within 1..365 (裁定 CF)", async () => {
    const one = await exchange(802, { tokenName: "short", expiresInDays: 1 });
    const oneRow = await tokenRow(one.tokenId);
    expect(oneRow.expires_at).toBe(oneRow.created_at + DAY_MS);

    const max = await exchange(802, { tokenName: "long", expiresInDays: 365 });
    const maxRow = await tokenRow(max.tokenId);
    expect(maxRow.expires_at).toBe(maxRow.created_at + 365 * DAY_MS);
  });

  it("rejects out-of-range or non-integer expiresInDays at the wire schema", async () => {
    for (const expiresInDays of [0, 366, 1.5, -1]) {
      const response = await SELF.fetch(`${BASE}/auth/device/exchange`, {
        method: "POST",
        headers: JSON_HEADERS,
        body: JSON.stringify({ githubAccessToken: "gho_test803", expiresInDays }),
      });
      expect(response.status, `expiresInDays=${expiresInDays}`).toBe(400);
    }
    // 形式不正はトークン発行に至らない
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM api_tokens").first<{
      n: number;
    }>();
    expect(count?.n).toBe(0);
  });

  it("treats a legacy NULL expires_at as expired (fail-closed) and re-login self-heals (裁定 CE)", async () => {
    const issued = await exchange(804);
    await env.DB.prepare("UPDATE api_tokens SET expires_at = NULL WHERE id = ?")
      .bind(issued.tokenId)
      .run();
    const denied = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(issued.token) });
    expect(denied.status).toBe(401);

    // 再ログイン(同名ローテーション)は expires_at 付きの行を発行して復旧する
    const reissued = await exchange(804);
    const row = await tokenRow(reissued.tokenId);
    expect(row.expires_at).not.toBeNull();
    const ok = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(reissued.token) });
    expect(ok.status).toBe(200);
  });

  it("re-anchors legacy NULL rows to apply-time + 90 days (migration token_ttl_reanchor)", async () => {
    const issued = await exchange(805);
    await env.DB.prepare("UPDATE api_tokens SET expires_at = NULL WHERE id = ?")
      .bind(issued.tokenId)
      .run();
    // 実物の移行 SQL を TEST_MIGRATIONS から取り出して再実行する(SQL の複製を
    // テストに持たない)。既適用の記録とは無関係に UPDATE 文として冪等に効く
    const migration = env.TEST_MIGRATIONS.find((entry) =>
      entry.name.includes("token_ttl_reanchor"),
    );
    if (migration === undefined) {
      throw new Error("expected the token_ttl_reanchor migration in TEST_MIGRATIONS");
    }
    const before = Date.now();
    for (const query of migration.queries) {
      await env.DB.prepare(query).run();
    }
    const row = await tokenRow(issued.tokenId);
    expect(row.expires_at).not.toBeNull();
    // unixepoch() は秒精度なので ±1s の丸めを許す
    expect(row.expires_at ?? 0).toBeGreaterThanOrEqual(before - 1000 + 90 * DAY_MS);
    expect(row.expires_at ?? 0).toBeLessThanOrEqual(Date.now() + 1000 + 90 * DAY_MS);
    // 再アンカー後のトークンは再び使える(90 日の再ログイン猶予)
    const ok = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(issued.token) });
    expect(ok.status).toBe(200);
  });
});

describe("GET /auth/tokens(一覧 — AUTH_SPEC §6)", () => {
  it("returns the caller's own token metadata for a session principal, without raw values or hashes", async () => {
    const session = await loginSession(811);
    const issued = await exchange(811, { tokenName: "inventory" });
    // 他人のトークンは現れない
    await exchange(812, { tokenName: "someone-else" });

    const response = await SELF.fetch(`${BASE}/auth/tokens`, {
      headers: { cookie: `${SESSION_COOKIE}=${session}` },
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { tokens: Record<string, unknown>[] };
    expect(body.tokens).toHaveLength(1);
    const entry = body.tokens[0] as Record<string, unknown>;
    expect(entry["id"]).toBe(issued.tokenId);
    expect(entry["name"]).toBe("inventory");
    expect(entry["tokenPrefix"]).toBe(issued.token.slice(0, "maruhi_pat_".length + 4));
    expect(entry["scopes"]).toEqual([{ project: "*", permission: "admin" }]);
    expect(typeof entry["createdAtMs"]).toBe("number");
    expect(entry["expiresAtMs"]).toBe(issued.expiresAtMs);
    // 生値・ハッシュは構造ごと存在しない(§6: 返さない)
    expect(Object.keys(entry).toSorted()).toEqual([
      "createdAtMs",
      "expiresAtMs",
      "id",
      "lastUsedAtMs",
      "name",
      "scopes",
      "tokenPrefix",
    ]);
    expect(JSON.stringify(body)).not.toContain(issued.token);
  });

  it("lists expired tokens too (inventory view — only verification rejects them)", async () => {
    const session = await loginSession(813);
    const issued = await exchange(813, { tokenName: "expired" });
    await env.DB.prepare("UPDATE api_tokens SET expires_at = 1 WHERE id = ?")
      .bind(issued.tokenId)
      .run();
    const response = await SELF.fetch(`${BASE}/auth/tokens`, {
      headers: { cookie: `${SESSION_COOKIE}=${session}` },
    });
    const body = (await response.json()) as { tokens: { id: string; expiresAtMs: number }[] };
    expect(body.tokens.map((token) => token.id)).toContain(issued.tokenId);
  });

  it("allows a token principal only with a * × admin scope (裁定 CH)", async () => {
    const wildcard = await deviceToken(814, undefined, "wildcard");
    const allowed = await SELF.fetch(`${BASE}/auth/tokens`, { headers: bearer(wildcard) });
    expect(allowed.status).toBe(200);

    const scoped = await deviceToken(
      814,
      [{ project: "ab".repeat(32), permission: "admin" }],
      "scoped",
    );
    const denied = await SELF.fetch(`${BASE}/auth/tokens`, { headers: bearer(scoped) });
    expect(denied.status).toBe(403);
    const body = (await denied.json()) as { reason?: string };
    expect(body.reason).toBe("insufficient-permission");
  });
});

describe("DELETE /auth/tokens/:tokenId(指定失効 — AUTH_SPEC §6)", () => {
  it("lets a session principal revoke an owned token (with CSRF) and records the audit event", async () => {
    const session = await loginSession(821);
    const issued = await exchange(821, { tokenName: "target" });
    const response = await SELF.fetch(`${BASE}/auth/tokens/${issued.tokenId}`, {
      method: "DELETE",
      headers: sessionHeaders(session),
    });
    expect(response.status).toBe(204);
    // 失効の実効: 対象トークンは以後 401
    const denied = await SELF.fetch(`${BASE}/auth/me`, { headers: bearer(issued.token) });
    expect(denied.status).toBe(401);
    // 監査(AUDIT_SPEC §3.1): actor = 実行主体(セッション — トークン id なし)、
    // payload.tokenId = 失効対象
    const audit = await env.DB.prepare(
      "SELECT actor_user_id, actor_api_token_id, payload FROM user_audit_events WHERE event = 'auth.token_revoked'",
    ).first<{ actor_user_id: string; actor_api_token_id: string | null; payload: string }>();
    expect(audit?.actor_user_id).toBe(issued.userId);
    expect(audit?.actor_api_token_id).toBeNull();
    expect(JSON.parse(audit?.payload ?? "{}")).toEqual({
      tokenId: issued.tokenId,
      authMethod: "github_oauth",
    });
  });

  it("requires the CSRF header for a session principal (write via cookie)", async () => {
    const session = await loginSession(822);
    const issued = await exchange(822, { tokenName: "target" });
    const response = await SELF.fetch(`${BASE}/auth/tokens/${issued.tokenId}`, {
      method: "DELETE",
      headers: { cookie: `${SESSION_COOKIE}=${session}` },
    });
    expect(response.status).toBe(403);
    const body = (await response.json()) as { reason?: string };
    expect(body.reason).toBe("csrf-header-required");
  });

  it("returns a uniform 404 for another user's and a nonexistent token id (存在秘匿)", async () => {
    const session = await loginSession(823);
    const foreign = await exchange(824, { tokenName: "foreign" });

    const foreignResponse = await SELF.fetch(`${BASE}/auth/tokens/${foreign.tokenId}`, {
      method: "DELETE",
      headers: sessionHeaders(session),
    });
    const missingResponse = await SELF.fetch(`${BASE}/auth/tokens/01ARZ3NDEKTSV4RRFFQ69G5FAV`, {
      method: "DELETE",
      headers: sessionHeaders(session),
    });
    expect(foreignResponse.status).toBe(404);
    expect(missingResponse.status).toBe(404);
    // 応答本文まで一様(id の実在有無を区別できない)
    expect(await foreignResponse.json()).toEqual(await missingResponse.json());
    // 他人のトークンは消えていない・監査も記録されない(黙って成功させない規律)
    const row = await env.DB.prepare("SELECT id FROM api_tokens WHERE id = ?")
      .bind(foreign.tokenId)
      .first();
    expect(row).not.toBeNull();
    const audits = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM user_audit_events WHERE event = 'auth.token_revoked'",
    ).first<{ n: number }>();
    expect(audits?.n).toBe(0);
  });

  it("allows a * × admin token to revoke a sibling token, and denies a scoped token before target resolution (裁定 CG)", async () => {
    const wildcard = await deviceToken(825, undefined, "wildcard");
    const sibling = await exchange(825, { tokenName: "sibling" });
    const scoped = await deviceToken(
      825,
      [{ project: "cd".repeat(32), permission: "admin" }],
      "scoped",
    );

    // スコープ限定トークンは対象の実在に関わらず 403(呼び出し資格のみから計算)
    const deniedExisting = await SELF.fetch(`${BASE}/auth/tokens/${sibling.tokenId}`, {
      method: "DELETE",
      headers: bearer(scoped),
    });
    const deniedMissing = await SELF.fetch(`${BASE}/auth/tokens/no-such-token`, {
      method: "DELETE",
      headers: bearer(scoped),
    });
    expect(deniedExisting.status).toBe(403);
    expect(deniedMissing.status).toBe(403);
    expect(await deniedExisting.json()).toEqual(await deniedMissing.json());

    const revoked = await SELF.fetch(`${BASE}/auth/tokens/${sibling.tokenId}`, {
      method: "DELETE",
      headers: bearer(wildcard),
    });
    expect(revoked.status).toBe(204);
    // 監査 actor はワイルドカードトークン(実行主体)、対象は payload.tokenId
    const audit = await env.DB.prepare(
      "SELECT actor_api_token_id, payload FROM user_audit_events WHERE event = 'auth.token_revoked'",
    ).first<{ actor_api_token_id: string | null; payload: string }>();
    expect(audit?.actor_api_token_id).not.toBeNull();
    expect(audit?.actor_api_token_id).not.toBe(sibling.tokenId);
    expect(JSON.parse(audit?.payload ?? "{}")).toEqual({ tokenId: sibling.tokenId });
  });
});

// beforeEach の resetAuthDb が migrations を適用済みであることの明示(応答の
// 前提を暗黙にしない — applyD1Migrations は冪等)
it("keeps migrations idempotent for this suite", async () => {
  await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
});
