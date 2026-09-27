// Integration tests for the sign-up controls (AUTH_SPEC §3 — H1).
//
// The skeleton of the checks:
// - the default (no row in deployment_settings) = 'open' = exactly
//   the same as the previous behavior (regressions of the previous
//   behavior itself are covered by auth.test.ts — this file only
//   exercises the advisory and the gate's H1-added surface)
// - what it blocks is only "absent → create" (an existing user's
//   login is unchanged under any policy)
// - on rejection, no rows are created in users / linked_identities /
//   organizations / memberships (fail-closed) + auth.signup_denied
//   is recorded
// - consuming a sign-up invite code is in the same transaction as
//   account creation (success = used; rejection / existing user /
//   open = stays pending)

import { env, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import {
  BASE,
  CLI_STATE_COOKIE,
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
  STATE_COOKIE,
} from "./support/auth.ts";

beforeEach(async () => {
  await resetAuthDb();
});

async function countRows(table: string): Promise<number> {
  const row = await env.DB.prepare(`SELECT COUNT(*) AS n FROM ${table}`).first<{ n: number }>();
  return row?.n ?? -1;
}

/** The row counts of the main tables (checks the rejection = fail-closed creates no rows). */
async function authRowCounts(): Promise<{
  users: number;
  identities: number;
  orgs: number;
  memberships: number;
}> {
  return {
    users: await countRows("users"),
    identities: await countRows("linked_identities"),
    orgs: await countRows("organizations"),
    memberships: await countRows("memberships"),
  };
}

/** The auth.signup_denied record rows (payload is JSON). */
async function signupDeniedEvents(): Promise<{ reason: string }[]> {
  const rows = await env.DB.prepare(
    "SELECT payload FROM user_audit_events WHERE event = 'auth.signup_denied' ORDER BY seq",
  ).all<{ payload: string }>();
  return rows.results.map((row) => {
    const payload = JSON.parse(row.payload) as { reason: string };
    return { reason: payload.reason };
  });
}

describe("GET /auth/config's signupPolicy advisory (§3 / §4)", () => {
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

  it("treats an unknown stored value as 'closed' (fail-closed — an operator typo must not flip to open)", async () => {
    await setSignupPolicy("evreyone-welcome");
    const body = (await (await SELF.fetch(`${BASE}/auth/config`)).json()) as {
      signupPolicy?: string;
    };
    expect(body.signupPolicy).toBe("closed");
    // The gate reads it the same way (new sign-ups are rejected)
    const callback = await signupAttempt(700);
    expect(callback.status).toBe(403);
    expect((await authRowCounts()).users).toBe(0);
  });
});

describe("signupPolicy = closed (§3 — reject every new sign-up)", () => {
  beforeEach(async () => {
    await setSignupPolicy("closed");
  });

  it("denies a new identity after OAuth completes, creating no rows, and records auth.signup_denied", async () => {
    const callback = await signupAttempt(701);
    expect(callback.status).toBe(403);
    const html = await callback.text();
    expect(html).toContain("Sign-ups are closed");
    // The rejection page states explicitly that no account was
    // created (§3 — surfaced as the outcome row in DP4)
    expect(html).toContain("No account was created.");
    // The scriptless-serving discipline (same as §15-3 — shares the
    // cli-pages response point)
    expect(callback.headers.get("content-security-policy")).toContain("script-src 'none'");
    // No session is issued and no rows are created (fail-closed)
    expect(readCookieValue(callback.headers.getSetCookie(), SESSION_COOKIE)).toBeNull();
    expect(await authRowCounts()).toEqual({ users: 0, identities: 0, orgs: 0, memberships: 0 });
    expect(await signupDeniedEvents()).toEqual([{ reason: "policy-closed" }]);
    // The rejection does not record the external provider ID (AUDIT_SPEC §1-2)
    const denied = await env.DB.prepare(
      "SELECT actor_user_id, payload FROM user_audit_events WHERE event = 'auth.signup_denied'",
    ).first<{ actor_user_id: string | null; payload: string }>();
    expect(denied?.actor_user_id).toBeNull();
    expect(denied?.payload).not.toContain("701");
  });

  it("does not affect an existing user's login (§3 — only new sign-ups are blocked)", async () => {
    await seedUser("user-closed-001", 702);
    const session = await loginSession(702);
    expect(session).toMatch(/^[0-9a-f]{64}$/);
    expect(await signupDeniedEvents()).toEqual([]);
  });
});

describe("signupPolicy = invite (§3 — sign-up invite codes)", () => {
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
    // A session is granted + the state is revoked + the signup-code
    // cookie is expired (single-use)
    const setCookies = callback.headers.getSetCookie();
    expect(readCookieValue(setCookies, SESSION_COOKIE)).toMatch(/^[0-9a-f]{64}$/);
    const signupCookie = setCookies.find((cookie) => cookie.startsWith(`${SIGNUP_CODE_COOKIE}=`));
    expect(signupCookie).toContain("Max-Age=0");
    // The code is consumed and bound to the created user
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
    // Audit: auth.user_created's payload carries the consumed invite id (AUDIT_SPEC §3.1)
    const created = await env.DB.prepare(
      "SELECT payload FROM user_audit_events WHERE event = 'auth.user_created'",
    ).first<{ payload: string }>();
    expect(JSON.parse(created?.payload ?? "{}")).toMatchObject({ signupInviteId: invite.id });
    expect(await signupDeniedEvents()).toEqual([]);
  });

  it("rejects an unknown code at start, before any GitHub redirect (§3's pre-validation)", async () => {
    const start = await SELF.fetch(
      `${BASE}/auth/github/start?signup_code=maruhi_sgn_${"0".repeat(43)}`,
      { redirect: "manual" },
    );
    expect(start.status).toBe(400);
    expect(await start.text()).toContain("can&#39;t be used");
    // Neither a redirect nor a state cookie is issued (the OAuth dance never starts)
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
    // start's pre-validation rejects first
    const start = await SELF.fetch(`${BASE}/auth/github/start?signup_code=${invite.code}`, {
      redirect: "manual",
    });
    expect(start.status).toBe(400);
    // If it was consumed between start and callback (reproducing a
    // concurrent consumption), the callback side also rejects
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
    // The second user's rows are not created (only the first's)
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

  it("a cookie carried into a different flow is not treated as a presented code (state-bound)", async () => {
    const invite = await seedSignupInvite();
    // Obtain the cookie via a start with a code (this flow is
    // abandoned and the code is unused)
    const abandoned = await SELF.fetch(`${BASE}/auth/github/start?signup_code=${invite.code}`, {
      redirect: "manual",
    });
    expect(abandoned.status).toBe(302);
    const staleCookie = readCookieValue(abandoned.headers.getSetCookie(), SIGNUP_CODE_COOKIE);
    expect(staleCookie).not.toBeNull();
    // The cookie carries only the hash (the raw value appears on the
    // wire just once, at start — the cookie store never holds it.
    // AUTH_SPEC §3)
    expect(staleCookie).not.toContain(invite.code);
    expect(staleCookie).toMatch(/^[0-9a-f]{32}\.[0-9a-f]{64}$/);
    // Carry it over into a later **unrelated** flow in the same
    // browser (a plain start = a different state)
    const plain = await SELF.fetch(`${BASE}/auth/github/start`, { redirect: "manual" });
    const state = new URL(plain.headers.get("location") ?? "").searchParams.get("state") ?? "";
    const callback = await SELF.fetch(`${BASE}/auth/github/callback?code=code-717&state=${state}`, {
      headers: {
        cookie: `${STATE_COOKIE}=${state}; ${SIGNUP_CODE_COOKIE}=${staleCookie ?? ""}`,
      },
      redirect: "manual",
    });
    // A cookie whose state mismatches folds to "not presented" — no
    // consumption happens on carry-over
    expect(callback.status).toBe(403);
    expect(await callback.text()).toContain("Sign-ups are invite-only");
    const row = await env.DB.prepare("SELECT status FROM signup_invites WHERE id = ?")
      .bind(invite.id)
      .first<{ status: string }>();
    expect(row?.status).toBe("pending");
    // The leftover cookie is singly expired at this endpoint too
    const expired = callback.headers
      .getSetCookie()
      .find((cookie) => cookie.startsWith(`${SIGNUP_CODE_COOKIE}=`));
    expect(expired).toContain("Max-Age=0");
  });

  it("the CLI browser leg never reads a signup code but expires a leftover cookie (ruling DH + the single-use discipline)", async () => {
    const invite = await seedSignupInvite();
    const abandoned = await SELF.fetch(`${BASE}/auth/github/start?signup_code=${invite.code}`, {
      redirect: "manual",
    });
    const staleCookie = readCookieValue(abandoned.headers.getSetCookie(), SIGNUP_CODE_COOKIE);
    // Send the leftover cookie along on the CLI browser leg (codes do not ride the CLI path)
    const started = await startCliFlow();
    const verify = await SELF.fetch(started.verificationUrl, { redirect: "manual" });
    expect(verify.status).toBe(302);
    const state = new URL(verify.headers.get("location") ?? "").searchParams.get("state") ?? "";
    const bound = readCookieValue(verify.headers.getSetCookie(), CLI_STATE_COOKIE);
    const callback = await SELF.fetch(`${BASE}/auth/github/callback?code=code-718&state=${state}`, {
      headers: {
        cookie: `${CLI_STATE_COOKIE}=${bound ?? ""}; ${SIGNUP_CODE_COOKIE}=${staleCookie ?? ""}`,
      },
      redirect: "manual",
    });
    // No account → the sign-up guidance (invite wording). The code is
    // not consumed
    expect(callback.status).toBe(200);
    expect(await callback.text()).toContain("invite-only");
    const row = await env.DB.prepare("SELECT status FROM signup_invites WHERE id = ?")
      .bind(invite.id)
      .first<{ status: string }>();
    expect(row?.status).toBe("pending");
    const expired = callback.headers
      .getSetCookie()
      .find((cookie) => cookie.startsWith(`${SIGNUP_CODE_COOKIE}=`));
    expect(expired).toContain("Max-Age=0");
  });

  it("applies the policy at acceptance time: a flip to closed between start and callback denies (§3)", async () => {
    const invite = await seedSignupInvite();
    const callback = await signupAttempt(715, {
      signupCode: invite.code,
      betweenSteps: () => setSignupPolicy("closed"),
    });
    expect(callback.status).toBe(403);
    expect(await callback.text()).toContain("Sign-ups are closed");
    // The code is not burned (the consumption CAS is conditioned on
    // the acceptance-time policy being 'invite')
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
    // A plain start (the login path) is not limited even from the same IP
    const plain = await SELF.fetch(`${BASE}/auth/github/start`, {
      headers: { "cf-connecting-ip": "203.0.113.77" },
      redirect: "manual",
    });
    expect(plain.status).toBe(302);
  }, 60_000);

  it("adapts the CLI signup-guidance page wording (follows §4-1 (4) (ii)'s copy)", async () => {
    const started = await startCliFlow();
    const callback = await cliBrowserLeg(started.verificationUrl, 716);
    expect(callback.status).toBe(200);
    const html = await callback.text();
    expect(html).toContain("No maruhi account yet");
    expect(html).toContain("invite-only");
    // No plain sign-up link is shown (it only steers toward invite-required)
    expect(html).not.toContain(`href="https://example.com/auth/github/start"`);
    // The guidance is side-effect free (creates neither a flow row
    // nor an account)
    expect((await authRowCounts()).users).toBe(0);
  });
});

describe("signupPolicy = open (the default — identical to current behavior)", () => {
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
