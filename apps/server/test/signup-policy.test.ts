// サインアップ制御の統合テスト(AUTH_SPEC §3 — 2026-09-01 H1)。
//
// 検査の骨子:
// - 既定(deployment_settings に行なし)= 'open' = 従来挙動と完全に同一
//   (従来挙動そのものの回帰は auth.test.ts が担う — 本ファイルは advisory と
//   ゲートの H1 追加面のみを見る)
// - 塞ぐのは「不在 → 作成」だけ(既存ユーザーのログインはどのポリシーでも不変)
// - 拒否時に users / linked_identities / organizations / memberships の行を
//   作らない(fail-closed)+ auth.signup_denied の記録
// - サインアップ招待コードの消費はアカウント作成と同一トランザクション
//   (成功 = used、拒否・既存ユーザー・open = pending のまま)

import { env, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import {
  BASE,
  cliBrowserLeg,
  loginSession,
  readCookieValue,
  resetAuthDb,
  seedSignupInvite,
  seedUser,
  SESSION_COOKIE,
  setSignupPolicy,
  SIGNUP_CODE_COOKIE,
  signupAttempt,
  startCliFlow,
} from "./support/auth.ts";

beforeEach(async () => {
  await resetAuthDb();
});

/** 主要テーブルの行数(拒否 = 行を作らない fail-closed の検査)。 */
async function authRowCounts(): Promise<{
  users: number;
  identities: number;
  orgs: number;
  memberships: number;
}> {
  const count = async (table: string): Promise<number> => {
    const row = await env.DB.prepare(`SELECT COUNT(*) AS n FROM ${table}`).first<{ n: number }>();
    return row?.n ?? -1;
  };
  return {
    users: await count("users"),
    identities: await count("linked_identities"),
    orgs: await count("organizations"),
    memberships: await count("memberships"),
  };
}

/** auth.signup_denied の記録行(payload は JSON)。 */
async function signupDeniedEvents(): Promise<{ reason: string }[]> {
  const rows = await env.DB.prepare(
    "SELECT payload FROM user_audit_events WHERE event = 'auth.signup_denied' ORDER BY seq",
  ).all<{ payload: string }>();
  return rows.results.map((row) => {
    const payload = JSON.parse(row.payload) as { reason: string };
    return { reason: payload.reason };
  });
}

describe("GET /auth/config の signupPolicy advisory(§3 / §4)", () => {
  it("returns 'open' by default (no settings row)", async () => {
    const response = await SELF.fetch(`${BASE}/auth/config`);
    expect(response.status).toBe(200);
    const body = (await response.json()) as { signupPolicy?: string };
    expect(body.signupPolicy).toBe("open");
  });

  it("reflects the stored policy", async () => {
    await setSignupPolicy("invite");
    const invite = (await (await SELF.fetch(`${BASE}/auth/config`)).json()) as {
      signupPolicy?: string;
    };
    expect(invite.signupPolicy).toBe("invite");
    await setSignupPolicy("closed");
    const closed = (await (await SELF.fetch(`${BASE}/auth/config`)).json()) as {
      signupPolicy?: string;
    };
    expect(closed.signupPolicy).toBe("closed");
  });

  it("treats an unknown stored value as 'closed' (fail-closed — 運営の typo を open に化けさせない)", async () => {
    await setSignupPolicy("evreyone-welcome");
    const body = (await (await SELF.fetch(`${BASE}/auth/config`)).json()) as {
      signupPolicy?: string;
    };
    expect(body.signupPolicy).toBe("closed");
    // ゲート側も同じ読み(新規作成は拒否される)
    const callback = await signupAttempt(700);
    expect(callback.status).toBe(403);
    expect((await authRowCounts()).users).toBe(0);
  });
});

describe("signupPolicy = closed(§3 — 新規作成の全拒否)", () => {
  beforeEach(async () => {
    await setSignupPolicy("closed");
  });

  it("denies a new identity after OAuth completes, creating no rows, and records auth.signup_denied", async () => {
    const callback = await signupAttempt(701);
    expect(callback.status).toBe(403);
    const html = await callback.text();
    expect(html).toContain("Sign-ups are closed");
    expect(html).toContain("no account was\n        created");
    // スクリプトなし配信規律(§15-3 と同じ — cli-pages の応答点を共用)
    expect(callback.headers.get("content-security-policy")).toContain("script-src 'none'");
    // セッションは発行されない・行も作られない(fail-closed)
    expect(readCookieValue(callback.headers.getSetCookie(), SESSION_COOKIE)).toBeNull();
    expect(await authRowCounts()).toEqual({ users: 0, identities: 0, orgs: 0, memberships: 0 });
    expect(await signupDeniedEvents()).toEqual([{ reason: "policy-closed" }]);
    // 拒否は外部 provider ID を記録しない(AUDIT_SPEC §1-2)
    const denied = await env.DB.prepare(
      "SELECT actor_user_id, payload FROM user_audit_events WHERE event = 'auth.signup_denied'",
    ).first<{ actor_user_id: string | null; payload: string }>();
    expect(denied?.actor_user_id).toBeNull();
    expect(denied?.payload).not.toContain("701");
  });

  it("does not affect an existing user's login (§3 — 塞ぐのは新規作成のみ)", async () => {
    await seedUser("user-closed-001", 702);
    const session = await loginSession(702);
    expect(session).toMatch(/^[0-9a-f]{64}$/);
    expect(await signupDeniedEvents()).toEqual([]);
  });
});

describe("signupPolicy = invite(§3 — サインアップ招待コード)", () => {
  beforeEach(async () => {
    await setSignupPolicy("invite");
  });

  it("denies a new identity without a code (invite-required)", async () => {
    const callback = await signupAttempt(710);
    expect(callback.status).toBe(403);
    expect(await callback.text()).toContain("Sign-ups are invite-only");
    expect(await authRowCounts()).toEqual({ users: 0, identities: 0, orgs: 0, memberships: 0 });
    expect(await signupDeniedEvents()).toEqual([{ reason: "invite-required" }]);
  });

  it("creates the account with a valid code and consumes it in the same transaction", async () => {
    const invite = await seedSignupInvite();
    const callback = await signupAttempt(711, { signupCode: invite.code });
    expect(callback.status).toBe(302);
    // セッション付与 + state 失効 + サインアップコードクッキー失効(単回)
    const setCookies = callback.headers.getSetCookie();
    expect(readCookieValue(setCookies, SESSION_COOKIE)).toMatch(/^[0-9a-f]{64}$/);
    const signupCookie = setCookies.find((cookie) => cookie.startsWith(`${SIGNUP_CODE_COOKIE}=`));
    expect(signupCookie).toContain("Max-Age=0");
    // コードは消費済みで、作成されたユーザーに束縛される
    const user = await env.DB.prepare(
      "SELECT user_id FROM linked_identities WHERE provider = 'github' AND provider_user_id = '711'",
    ).first<{ user_id: string }>();
    const row = await env.DB.prepare(
      "SELECT status, used_by_user_id, used_at FROM signup_invites WHERE id = ?",
    )
      .bind(invite.id)
      .first<{ status: string; used_by_user_id: string | null; used_at: number | null }>();
    expect(row?.status).toBe("used");
    expect(row?.used_by_user_id).toBe(user?.user_id);
    expect(row?.used_at).not.toBeNull();
    // 監査: auth.user_created の payload が消費した招待 id を運ぶ(AUDIT_SPEC §3.1)
    const created = await env.DB.prepare(
      "SELECT payload FROM user_audit_events WHERE event = 'auth.user_created'",
    ).first<{ payload: string }>();
    expect(JSON.parse(created?.payload ?? "{}")).toMatchObject({ signupInviteId: invite.id });
    expect(await signupDeniedEvents()).toEqual([]);
  });

  it("rejects an unknown code at start, before any GitHub redirect (§3 の事前検証)", async () => {
    const start = await SELF.fetch(
      `${BASE}/auth/github/start?signup_code=maruhi_sgn_${"0".repeat(43)}`,
      { redirect: "manual" },
    );
    expect(start.status).toBe(400);
    expect(await start.text()).toContain("can&#39;t be used");
    // リダイレクトも state クッキーも発行されない(OAuth ダンスを開始しない)
    expect(start.headers.get("location")).toBeNull();
    expect(start.headers.getSetCookie()).toHaveLength(0);
  });

  it("rejects an expired code at start", async () => {
    const invite = await seedSignupInvite({ expiresAtMs: Date.now() - 1000 });
    const start = await SELF.fetch(`${BASE}/auth/github/start?signup_code=${invite.code}`, {
      redirect: "manual",
    });
    expect(start.status).toBe(400);
  });

  it("a used code cannot be reused (start pre-validation and callback CAS both deny)", async () => {
    const invite = await seedSignupInvite();
    expect((await signupAttempt(712, { signupCode: invite.code })).status).toBe(302);
    // start の事前検証が先に落とす
    const start = await SELF.fetch(`${BASE}/auth/github/start?signup_code=${invite.code}`, {
      redirect: "manual",
    });
    expect(start.status).toBe(400);
    // start と callback の間に消費された場合(並行消費の再現)も callback 側で拒否
    const secondInvite = await seedSignupInvite();
    const callback = await signupAttempt(713, {
      signupCode: secondInvite.code,
      betweenSteps: async () => {
        await env.DB.prepare("UPDATE signup_invites SET status = 'used' WHERE id = ?")
          .bind(secondInvite.id)
          .run();
      },
    });
    expect(callback.status).toBe(403);
    expect(await callback.text()).toContain("can&#39;t be used");
    expect(await signupDeniedEvents()).toEqual([{ reason: "invite-invalid" }]);
    // 2 人目の行は作られていない(1 人目のぶんだけ)
    expect((await authRowCounts()).users).toBe(1);
  });

  it("an existing user's login does not consume a presented code", async () => {
    await seedUser("user-invite-001", 714);
    const invite = await seedSignupInvite();
    const callback = await signupAttempt(714, { signupCode: invite.code });
    expect(callback.status).toBe(302);
    const row = await env.DB.prepare("SELECT status FROM signup_invites WHERE id = ?")
      .bind(invite.id)
      .first<{ status: string }>();
    expect(row?.status).toBe("pending");
  });

  it("applies the policy at acceptance time: a flip to closed between start and callback denies (§3)", async () => {
    const invite = await seedSignupInvite();
    const callback = await signupAttempt(715, {
      signupCode: invite.code,
      betweenSteps: () => setSignupPolicy("closed"),
    });
    expect(callback.status).toBe(403);
    expect(await callback.text()).toContain("Sign-ups are closed");
    // コードは燃えていない(消費 CAS は受理時点ポリシー 'invite' を条件に含む)
    const row = await env.DB.prepare("SELECT status FROM signup_invites WHERE id = ?")
      .bind(invite.id)
      .first<{ status: string }>();
    expect(row?.status).toBe("pending");
    expect(await authRowCounts()).toEqual({ users: 0, identities: 0, orgs: 0, memberships: 0 });
  });

  it("rate-limits code-carrying starts per source IP (§3 — plain starts stay unlimited)", async () => {
    const invite = await seedSignupInvite();
    const attempt = (): Promise<Response> =>
      SELF.fetch(`${BASE}/auth/github/start?signup_code=${invite.code}`, {
        headers: { "cf-connecting-ip": "203.0.113.77" },
        redirect: "manual",
      });
    const responses: Response[] = [];
    for (let batch = 0; batch < 2; batch += 1) {
      responses.push(...(await Promise.all(Array.from({ length: 11 }, attempt))));
    }
    const limited = responses.find((response) => response.status === 429);
    if (limited === undefined) {
      throw new Error("expected a 429 within two full rate-limit windows");
    }
    const body = (await limited.json()) as Record<string, unknown>;
    expect(body["_tag"]).toBe("AuthRateLimited");
    // プレーンな start(ログイン導線)は同じ IP でも制限されない
    const plain = await SELF.fetch(`${BASE}/auth/github/start`, {
      headers: { "cf-connecting-ip": "203.0.113.77" },
      redirect: "manual",
    });
    expect(plain.status).toBe(302);
  }, 60_000);

  it("adapts the CLI signup-guidance page wording (§4-1 (4) (ii) の文言追随)", async () => {
    const started = await startCliFlow();
    const callback = await cliBrowserLeg(started.verificationUrl, 716);
    expect(callback.status).toBe(200);
    const html = await callback.text();
    expect(html).toContain("No maruhi account yet");
    expect(html).toContain("invite-only");
    // プレーンなサインアップリンクは案内しない(invite-required へ誘導するだけ)
    expect(html).not.toContain(`href="https://example.com/auth/github/start"`);
    // 案内は副作用ゼロ(フロー行もアカウントも作らない)
    expect((await authRowCounts()).users).toBe(0);
  });
});

describe("signupPolicy = open(既定 — 現行挙動との同一性)", () => {
  it("creates an account without a code (default, no settings row)", async () => {
    const callback = await signupAttempt(720);
    expect(callback.status).toBe(302);
    expect((await authRowCounts()).users).toBe(1);
    expect(await signupDeniedEvents()).toEqual([]);
  });

  it("does not consume a presented (valid) code — the gate does not ask for one", async () => {
    const invite = await seedSignupInvite();
    const callback = await signupAttempt(721, { signupCode: invite.code });
    expect(callback.status).toBe(302);
    expect((await authRowCounts()).users).toBe(1);
    const row = await env.DB.prepare("SELECT status FROM signup_invites WHERE id = ?")
      .bind(invite.id)
      .first<{ status: string }>();
    expect(row?.status).toBe("pending");
  });
});
