// 監査イベント読み取り API(AUDIT_SPEC §6 / §7 — C1)の統合テスト。
//
// 固定する性質:
//  1. 可視性クラス(§6): admin 未満はクラス 1 の行 + 本人が actor の行のみ。
//     クラス 2(var.read / dek.registered / dek.deleted)は結果・ページング・
//     カーソルのどこにも現れない(「存在しないかのように振る舞う」)。admin
//     可視は「チェーン role admin × トークンスコープ admin」(min 規律 —
//     read スコープの admin ユーザーにも開示しない)
//  2. actor_user_id フィルタの他人指定は admin 未満に対して 403(§6 の
//     「他人が actor の行の横断検索はクラス 2」)。本人指定は許可
//  3. ページング境界: seq 降順・limit ≤ 200(超過は Schema の 400)・before
//     カーソルの前進。admin 未満のページはクラス 2 の行を跨いでも limit 件
//     埋まる(件数の非漏洩)
//  4. invite.*(D1): 権限軸は当該プロジェクトのチェーン role admin のみ —
//     org admin であることは閲覧権限を与えず(404)、invite.* 以外の org 系
//     イベント・他プロジェクトの行は混入しない
//  5. self(D1): 本人の行のみ。トークン条件は §13-2 と同水準(`*` × admin)

import type { TokenScope } from "@maruhi/core";
import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { CLASS1_EVENTS } from "../src/audit-store.ts";
import { INVITE_AUDIT_EVENTS } from "../src/db.package/index.ts";
import { BASE, bearer, JSON_HEADERS, loginSession, sessionHeaders } from "./support/auth.ts";
import {
  ALL_MEMBERS,
  createEnvironmentOk,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
  STRANGER,
  tokenOf,
} from "./support/data-fixture.ts";
import {
  createVariableOk,
  ENV,
  fixture,
  registerDataScenario,
  token,
  VAR,
} from "./support/data-scenario.ts";

registerDataScenario();

interface WireAuditEvent {
  readonly id: string;
  readonly seq?: number;
  readonly serverTs: number;
  readonly clientTs?: number;
  readonly event: string;
  readonly actor: {
    readonly type: "user" | "server" | "system";
    readonly userId?: string;
    readonly keyFingerprintHex?: string;
    readonly apiTokenId?: string;
  };
  readonly targetUserId?: string;
  readonly targetKeyFingerprintHex?: string;
  readonly environmentId?: string;
  readonly variableId?: string;
  readonly epoch?: number;
  readonly version?: number;
  readonly chainSeq?: number;
  readonly projectId?: string;
  readonly payload?: Readonly<Record<string, unknown>>;
}

async function fetchEvents(
  bearerToken: string,
  query: Record<string, string> = {},
): Promise<{ status: number; events: readonly WireAuditEvent[] }> {
  const search = new URLSearchParams(query).toString();
  const response = await requestJson(
    "GET",
    `/audit/events${search === "" ? "" : `?${search}`}`,
    bearerToken,
  );
  if (response.status !== 200) {
    return { status: response.status, events: [] };
  }
  const body = (await response.json()) as { events: readonly WireAuditEvent[] };
  return { status: 200, events: body.events };
}

/** 環境 + 変数 + 読み取り(READER / MEMBER の pull)まで進めた標準シナリオ。 */
async function seedProjectActivity(): Promise<void> {
  const dek = await createEnvironmentOk(fixture, ENV, "App");
  await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
  const readerPull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
  expect(readerPull.status).toBe(200);
  const memberPull = await requestJson("GET", `/environments/${ENV}/pull`, token(MEMBER));
  expect(memberPull.status).toBe(200);
}

const eventNames = (events: readonly WireAuditEvent[]): readonly string[] =>
  events.map((event) => event.event);

describe("可視性クラス(§6)の強制", () => {
  it("admin 未満はクラス 1 + 本人が actor の行のみを見る(クラス 2 は件数にも漏れない)", async () => {
    await seedProjectActivity();
    const { status, events } = await fetchEvents(token(READER), { limit: "200" });
    expect(status).toBe(200);
    // クラス 1 の行は全部見える
    expect(eventNames(events)).toEqual(
      expect.arrayContaining([
        "chain.genesis",
        "chain.member_added",
        "chain.environment_created",
        "env.created",
        "var.created",
      ]),
    );
    // 本人の var.read は見える(クラスに依らず本人閲覧可)
    expect(
      events.some((event) => event.event === "var.read" && event.actor.userId === READER),
    ).toBe(true);
    // 他人の var.read・dek.registered(クラス 2)は 1 行も現れない
    expect(events.some((event) => event.event === "dek.registered")).toBe(false);
    expect(
      events.some((event) => event.event === "var.read" && event.actor.userId !== READER),
    ).toBe(false);
    // 可視条件そのもの(allowlist ∨ 本人)を全行で検査する。admin 未満の
    // 応答は seq(無欠番採番の序数)を運ばず、行識別子は不透明な row id のみ
    // (AUDIT_SPEC §7 — 序数からのクラス 2 件数推論の遮断)
    for (const event of events) {
      expect(CLASS1_EVENTS.includes(event.event) || event.actor.userId === READER).toBe(true);
      expect(event.seq).toBeUndefined();
      expect(event.id).toMatch(/^[0-9a-f]{32}$/);
    }
  });

  it("チェーン role admin × admin スコープは全行を見る", async () => {
    await seedProjectActivity();
    const { status, events } = await fetchEvents(token(OWNER), { limit: "200" });
    expect(status).toBe(200);
    // クラス 2: 全メンバー宛の dek.registered と両者の var.read が見える
    const dekTargets = events
      .filter((event) => event.event === "dek.registered")
      .map((event) => event.targetUserId)
      .toSorted();
    expect(dekTargets).toEqual([...ALL_MEMBERS].toSorted());
    const readActors = events
      .filter((event) => event.event === "var.read")
      .map((event) => event.actor.userId)
      .toSorted();
    expect(readActors).toEqual([MEMBER, READER].toSorted());
    // admin 可視の応答には保存 seq が載る(§6 の「欠番 = 削除の痕跡」検知の材料)
    for (const event of events) {
      expect(event.seq).toBeGreaterThan(0);
    }
  });

  it("read スコープのトークンでは admin ユーザーも他人のクラス 2 を見ない(min(スコープ, role))", async () => {
    await seedProjectActivity();
    // OWNER(チェーン role owner)の read スコープ限定トークン。同名ローテーション
    // (AUTH_SPEC §6)で fixture のトークンを失効させないよう別名にする
    const readToken = await scopedToken(9001, "read-only-audit", [
      { project: projectId, permission: "read" },
    ]);
    const { status, events } = await fetchEvents(readToken, { limit: "200" });
    expect(status).toBe(200);
    // 他人が actor のクラス 2(READER / MEMBER の var.read)は見えない —
    // admin スコープのトークン(前のテスト)では見えるのと対
    expect(events.some((event) => event.event === "var.read")).toBe(false);
    // 本人が actor の行(dek.registered — 署名者 = OWNER)はクラスに依らず
    // 本人閲覧可のまま(§6)
    expect(
      events.some((event) => event.event === "dek.registered" && event.actor.userId === OWNER),
    ).toBe(true);
  });

  it("非メンバーには 404(存在秘匿 — §11-2)", async () => {
    await seedProjectActivity();
    const { status } = await fetchEvents(token(STRANGER));
    expect(status).toBe(404);
  });
});

async function scopedToken(
  githubId: number,
  name: string,
  scopes: readonly TokenScope[],
): Promise<string> {
  const response = await SELF.fetch(`${BASE}/auth/device/exchange`, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({ githubAccessToken: `gho_test${githubId}`, tokenName: name, scopes }),
  });
  expect(response.status).toBe(200);
  return ((await response.json()) as { token: string }).token;
}

describe("フィルタ(§7 の語彙)と actor フィルタの権限", () => {
  it("event / environmentId / variableId / targetUserId で絞れる", async () => {
    await seedProjectActivity();
    const byEvent = await fetchEvents(token(OWNER), { event: "var.created" });
    expect(eventNames(byEvent.events)).toEqual(["var.created"]);
    const byVariable = await fetchEvents(token(OWNER), {
      environmentId: ENV,
      variableId: VAR,
      limit: "200",
    });
    expect(byVariable.events.length).toBeGreaterThan(0);
    for (const event of byVariable.events) {
      expect(event.environmentId).toBe(ENV);
      expect(event.variableId).toBe(VAR);
    }
    const byTarget = await fetchEvents(token(OWNER), { targetUserId: READER, limit: "200" });
    expect(eventNames(byTarget.events)).toEqual(
      expect.arrayContaining(["chain.member_added", "dek.registered"]),
    );
    for (const event of byTarget.events) {
      expect(event.targetUserId).toBe(READER);
    }
  });

  it("admin 未満の actorUserId フィルタは本人のみ(他人指定は 403)", async () => {
    await seedProjectActivity();
    // 本人指定は許可され、本人の行(クラス 2 の var.read 含む)だけが返る
    const self = await fetchEvents(token(MEMBER), { actorUserId: MEMBER, limit: "200" });
    expect(self.status).toBe(200);
    expect(self.events.length).toBeGreaterThan(0);
    for (const event of self.events) {
      expect(event.actor.userId).toBe(MEMBER);
    }
    expect(self.events.some((event) => event.event === "var.read")).toBe(true);
    // 他人指定はデータ非依存の 403(§6: 他人が actor の行の横断検索はクラス 2)
    const other = await fetchEvents(token(MEMBER), { actorUserId: READER });
    expect(other.status).toBe(403);
    // admin は他人指定で横断検索できる
    const admin = await fetchEvents(token(OWNER), { actorUserId: READER, limit: "200" });
    expect(admin.status).toBe(200);
    expect(admin.events.some((event) => event.event === "var.read")).toBe(true);
    for (const event of admin.events) {
      expect(event.actor.userId).toBe(READER);
    }
  });

  it("admin 未満のクラス 2 イベント種別フィルタは本人の行だけを返す(空でも 403 にしない)", async () => {
    await seedProjectActivity();
    // READER の dek.registered は存在しない(署名者は OWNER)— 空で返る
    const hidden = await fetchEvents(token(READER), { event: "dek.registered" });
    expect(hidden.status).toBe(200);
    expect(hidden.events).toEqual([]);
    // 本人の var.read はイベント種別フィルタでも見える
    const own = await fetchEvents(token(READER), { event: "var.read" });
    expect(own.status).toBe(200);
    expect(own.events.length).toBeGreaterThan(0);
    for (const event of own.events) {
      expect(event.actor.userId).toBe(READER);
    }
  });
});

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
    // 実発行経路の証跡: device 交換(setup)+ 今回の Web ログイン
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
