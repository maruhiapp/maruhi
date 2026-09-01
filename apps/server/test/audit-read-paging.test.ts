// 監査イベント読み取り API(AUDIT_SPEC §6 / §7 — C1)の統合テスト。
// 可視性クラス・フィルタは audit-read.test.ts(共有ヘルパは
// support/audit-read-scenario.ts)。
//
// 固定する性質:
//  1. ページング境界: seq 降順・limit ≤ 200(超過は Schema の 400)・before
//     カーソルの前進。admin 未満のページはクラス 2 の行を跨いでも limit 件
//     埋まる(件数の非漏洩)
//  2. invite.*(D1): 権限軸は当該プロジェクトのチェーン role admin のみ —
//     org admin であることは閲覧権限を与えず(404)、invite.* 以外の org 系
//     イベント・他プロジェクトの行は混入しない
//  3. self(D1): 本人の行のみ。トークン条件は §13-2 と同水準(`*` × admin)

import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { INVITE_AUDIT_EVENTS } from "../src/db.package/index.ts";
import type { WireAuditEvent } from "./support/audit-read-scenario.ts";
import {
  eventNames,
  fetchEvents,
  scopedToken,
  seedProjectActivity,
} from "./support/audit-read-scenario.ts";
import { BASE, bearer, loginSession, sessionHeaders } from "./support/auth.ts";
import {
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
  STRANGER,
  tokenOf,
} from "./support/data-fixture.ts";
import { fixture, registerDataScenario, token } from "./support/data-scenario.ts";

registerDataScenario();

describe("ページング境界(§7: seq 降順・limit ≤ 200・カーソル前進)", () => {
  it("seq 降順で返り、before カーソルの連結が全件と一致する", async () => {
    await seedProjectActivity();
    const full = await fetchEvents(token(OWNER), { limit: "200" });
    expect(full.events.length).toBeGreaterThan(8);
    const seqs = full.events.map((event) => event.seq ?? 0);
    expect(seqs.every((seq) => seq > 0)).toBe(true);
    expect(seqs).toEqual([...seqs].toSorted((a, b) => b - a));
    const paged: WireAuditEvent[] = [];
    let before: string | null = null;
    // カーソルが前進しない退行でハングしないための硬い上限(全件 < 4 × 50)
    for (let pages = 0; ; pages += 1) {
      expect(pages).toBeLessThan(50);
      const page = await fetchEvents(token(OWNER), {
        limit: "4",
        ...(before === null ? {} : { before }),
      });
      paged.push(...page.events);
      if (page.events.length < 4) {
        break;
      }
      before = page.events[page.events.length - 1]?.id ?? null;
    }
    expect(paged).toEqual(full.events);
  });

  it("admin 未満のページはクラス 2 の行を跨いでも limit 件埋まる(穴・件数の非漏洩)", async () => {
    await seedProjectActivity();
    const full = await fetchEvents(token(READER), { limit: "200" });
    // クラス 2 の行(dek.registered ×3 + 他人の var.read)が可視列の途中に
    // 挟まっている状態で、2 件ページの連結が全可視列と一致し、最終ページ以外は
    // きっちり 2 件になる(= 隠れた行がページを短くしない)
    const paged: WireAuditEvent[] = [];
    let before: string | null = null;
    // カーソルが前進しない退行でハングしないための硬い上限
    for (let pages = 0; ; pages += 1) {
      expect(pages).toBeLessThan(50);
      const page = await fetchEvents(token(READER), {
        limit: "2",
        ...(before === null ? {} : { before }),
      });
      if (paged.length + page.events.length < full.events.length) {
        expect(page.events.length).toBe(2);
      }
      paged.push(...page.events);
      if (page.events.length < 2) {
        break;
      }
      before = page.events[page.events.length - 1]?.id ?? null;
    }
    expect(paged).toEqual(full.events);
  });

  it("limit の範囲外・不正なカーソルは Schema の 400", async () => {
    await seedProjectActivity();
    // before は 32 桁小文字 hex の row id のみ(数値 seq・短い/大文字の hex は
    // Schema で拒否 — AUDIT_SPEC §7 の不透明カーソル)
    for (const query of [
      "limit=0",
      "limit=201",
      "limit=1.5",
      "limit=abc",
      "before=0",
      "before=x",
      `before=${"a".repeat(31)}`,
      `before=${"A".repeat(32)}`,
    ]) {
      const response = await requestJson("GET", `/audit/events?${query}`, token(OWNER));
      expect(response.status, query).toBe(400);
    }
  });

  it("可視性の外・不明な row id のカーソルは空ページ(存在オラクルにしない)", async () => {
    await seedProjectActivity();
    // OWNER として READER 非可視の行(他人が actor の var.read — クラス 2)の
    // id を取得し、READER のカーソルとして差す
    const admin = await fetchEvents(token(OWNER), { limit: "200" });
    const hidden = admin.events.find(
      (event) => event.event === "var.read" && event.actor.userId === MEMBER,
    );
    expect(hidden).toBeDefined();
    const probe = await fetchEvents(token(READER), { before: hidden?.id ?? "" });
    // 「実在するが非可視」は「存在しない id」と同じ応答(空ページ)— 空でない
    // 応答や 4xx の差が出ると id の実在オラクルになる
    expect(probe.status).toBe(200);
    expect(probe.events).toEqual([]);
    const unknown = await fetchEvents(token(READER), { before: "0".repeat(32) });
    expect(unknown.status).toBe(200);
    expect(unknown.events).toEqual([]);
    // 可視な行の id なら続きが返る(カーソルとして機能していることの対照)
    const visible = await fetchEvents(token(READER), { limit: "1" });
    expect(visible.events.length).toBe(1);
    const rest = await fetchEvents(token(READER), { before: visible.events[0]?.id ?? "" });
    expect(rest.events.length).toBeGreaterThan(0);
  });
});

async function issueInvite(role: string): Promise<string> {
  const response = await requestJson("POST", "/invites", token(OWNER), { role });
  expect(response.status).toBe(200);
  return ((await response.json()) as { id: string }).id;
}

async function fetchInvites(
  bearerToken: string,
  query: Record<string, string> = {},
): Promise<{ status: number; events: readonly WireAuditEvent[] }> {
  const search = new URLSearchParams(query).toString();
  const response = await requestJson(
    "GET",
    `/audit/invites${search === "" ? "" : `?${search}`}`,
    bearerToken,
  );
  if (response.status !== 200) {
    return { status: response.status, events: [] };
  }
  return {
    status: 200,
    events: ((await response.json()) as { events: readonly WireAuditEvent[] }).events,
  };
}

describe("invite.* の読み取り(§7 の例外規定 — D1)", () => {
  it("チェーン role admin は invite ライフサイクルを新しい順に読める", async () => {
    const inviteId = await issueInvite("member");
    const revoked = await requestJson("DELETE", `/invites/${inviteId}`, token(OWNER));
    expect(revoked.status).toBe(204);
    const { status, events } = await fetchInvites(token(OWNER));
    expect(status).toBe(200);
    expect(eventNames(events)).toEqual(["invite.revoked", "invite.created"]);
    for (const event of events) {
      expect(event.projectId).toBe(projectId);
      expect(INVITE_AUDIT_EVENTS).toContain(event.event);
      expect(event.payload?.["inviteId"]).toBe(inviteId);
    }
    // ページング(before カーソル = row id)。D1 応答は seq を誰にも運ばない
    // (グローバル連番はテナント横断の序数 — AUDIT_SPEC §7)
    for (const event of events) {
      expect(event.seq).toBeUndefined();
      expect(event.id).toMatch(/^[0-9a-f]{32}$/);
    }
    const first = await fetchInvites(token(OWNER), { limit: "1" });
    expect(eventNames(first.events)).toEqual(["invite.revoked"]);
    const second = await fetchInvites(token(OWNER), {
      limit: "1",
      before: first.events[0]?.id ?? "",
    });
    expect(eventNames(second.events)).toEqual(["invite.created"]);
  });

  it("チェーン role admin 未満は 403、org admin でも非メンバーは 404(権限軸の独立)", async () => {
    await issueInvite("member");
    expect((await fetchInvites(token(MEMBER))).status).toBe(403);
    expect((await fetchInvites(token(READER))).status).toBe(403);
    // STRANGER を org admin にしても、プロジェクトのチェーン非メンバーには 404
    // (org admin であることは invite.* の閲覧権限を与えない — §7)
    await env.DB.prepare(
      "INSERT INTO memberships (org_id, user_id, role) VALUES ('org-data-0001', ?, 'admin')",
    )
      .bind(STRANGER)
      .run();
    expect((await fetchInvites(token(STRANGER))).status).toBe(404);
  });

  it("row_id を持たない歴史行(デプロイ間隙の旧コード書き込み)は補填して返す(500 にしない)", async () => {
    const inviteId = await issueInvite("member");
    // マイグレーション適用後・新 worker 配信前の旧コードが書く形(row_id なし)
    // を直接シードする。補填(読み取り前段の遅延 backfill)が無いと id の
    // Schema encode が失敗し、このページは恒久に 500/400 になる(pullfrog 指摘)
    await env.DB.prepare(
      "INSERT INTO org_audit_events (server_ts, event, actor_type, actor_user_id, project_id, payload) VALUES (99, 'invite.created', 'user', ?, ?, '{\"inviteId\":\"legacy\"}')",
    )
      .bind(OWNER, projectId)
      .run();
    const { status, events } = await fetchInvites(token(OWNER), { limit: "200" });
    expect(status).toBe(200);
    const ids = events.map((event) => event.id);
    for (const id of ids) {
      expect(id).toMatch(/^[0-9a-f]{32}$/);
    }
    expect(new Set(ids).size).toBe(ids.length);
    const inviteIds = events.map((event) => event.payload?.["inviteId"]);
    expect(inviteIds).toEqual(expect.arrayContaining(["legacy", inviteId]));
  });

  it("row_id 補填はページで観測した行に限定される(B8: 全 NULL 行への UPDATE をしない)", async () => {
    await issueInvite("member");
    // NULL row_id の歴史行を 2 行シードする。limit=1 の読み取りページに載るのは
    // 新しい方(seq 大)だけ — 補填の UPDATE がページ外の NULL 行へ波及しない
    // ことを、残った行の row_id が NULL のままであることで固定する
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO org_audit_events (server_ts, event, actor_type, actor_user_id, project_id, payload) VALUES (98, 'invite.created', 'user', ?, ?, '{\"inviteId\":\"legacy-old\"}')",
      ).bind(OWNER, projectId),
      env.DB.prepare(
        "INSERT INTO org_audit_events (server_ts, event, actor_type, actor_user_id, project_id, payload) VALUES (99, 'invite.created', 'user', ?, ?, '{\"inviteId\":\"legacy-new\"}')",
      ).bind(OWNER, projectId),
    ]);
    const { status, events } = await fetchInvites(token(OWNER), { limit: "1" });
    expect(status).toBe(200);
    expect(events[0]?.payload?.["inviteId"]).toBe("legacy-new");
    const rows = await env.DB.prepare(
      "SELECT row_id AS rowId, payload FROM org_audit_events WHERE row_id IS NULL",
    ).all<{ rowId: string | null; payload: string }>();
    // ページ外の NULL 行(legacy-old)は補填されずに残る = 1 読み取りの書き込みは
    // 観測ページに有界。次にその行を含むページが読まれたときに補填される
    expect(rows.results.map((row) => row.payload)).toEqual(['{"inviteId":"legacy-old"}']);
  });

  it("invite.* 以外の org 系イベント・他プロジェクトの行は混入しない(述語の純度)", async () => {
    const inviteId = await issueInvite("member");
    // 同じ project_id を持つ org 系イベント(org admin 軸の領分)と、他
    // プロジェクトの invite 行を直接シードして、どちらも応答に現れないことを固定
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO org_audit_events (server_ts, event, actor_type, actor_user_id, org_id, project_id) VALUES (1, 'org.project_created', 'user', ?, 'org-data-0001', ?)",
      ).bind(OWNER, projectId),
      env.DB.prepare(
        "INSERT INTO org_audit_events (server_ts, event, actor_type, actor_user_id, project_id, payload) VALUES (2, 'invite.created', 'user', ?, 'project-other', '{\"inviteId\":\"other\"}')",
      ).bind(OWNER),
    ]);
    const { events } = await fetchInvites(token(OWNER), { limit: "200" });
    expect(eventNames(events)).toEqual(["invite.created"]);
    expect(events[0]?.payload?.["inviteId"]).toBe(inviteId);
  });
});

describe("user 系の本人閲覧(§3.1 / §6 — self)", () => {
  it("セッション主体は自分のアカウントイベントを新しい順に読める(他人の行は見えない)", async () => {
    const session = await loginSession(9001);
    const response = await SELF.fetch(`${BASE}/auth/audit/events?limit=200`, {
      headers: sessionHeaders(session),
    });
    expect(response.status).toBe(200);
    const { events } = (await response.json()) as { events: readonly WireAuditEvent[] };
    expect(events.length).toBeGreaterThan(0);
    // 新しい順(server_ts 非増加)。seq は D1 応答に載せない(§7)ため、行の
    // 同一性は不透明な row id で確認する
    const times = events.map((event) => event.serverTs);
    expect(times).toEqual([...times].toSorted((a, b) => b - a));
    const ids = events.map((event) => event.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const event of events) {
      expect(event.seq).toBeUndefined();
    }
    // 実発行経路の証跡: CLI ハンドオフ(setup)+ 今回の Web ログイン
    expect(eventNames(events)).toEqual(
      expect.arrayContaining(["auth.token_created", "auth.login_succeeded"]),
    );
    // 本人の行のみ(§6): actor か target が本人でない行は 1 行も現れない
    for (const event of events) {
      expect(event.actor.userId === OWNER || event.targetUserId === OWNER).toBe(true);
    }
  });

  it("スコープ限定トークンには 403(§13-2 と同水準)、`*` × admin トークンは可", async () => {
    const limited = await scopedToken(9001, "self-limited", [
      { project: projectId, permission: "admin" },
    ]);
    const denied = await SELF.fetch(`${BASE}/auth/audit/events`, {
      headers: bearer(limited),
    });
    expect(denied.status).toBe(403);
    const allowed = await SELF.fetch(`${BASE}/auth/audit/events`, {
      headers: bearer(tokenOf(fixture.tokens, OWNER)),
    });
    expect(allowed.status).toBe(200);
  });
});
