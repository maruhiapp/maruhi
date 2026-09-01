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
//
// ページング境界・invite.*・self の読み取りは audit-read-paging.test.ts
// (共有ヘルパは support/audit-read-scenario.ts。分割の動機は
// support/membership-scenario.ts 冒頭を参照)。

import { describe, expect, it } from "vitest";

import { isClass1Event } from "../src/audit-store.ts";
import {
  eventNames,
  fetchEvents,
  scopedToken,
  seedProjectActivity,
} from "./support/audit-read-scenario.ts";
import {
  ALL_MEMBERS,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
  STRANGER,
} from "./support/data-fixture.ts";
import { ENV, registerDataScenario, token, VAR } from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

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
      expect(isClass1Event(event.event) || event.actor.userId === READER).toBe(true);
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

  it("eventPrefix は名前空間ごと絞る(ミラー検証の全取得 — deepsec R1)", async () => {
    await seedProjectActivity();
    const { status, events } = await fetchEvents(token(OWNER), {
      eventPrefix: "chain.",
      limit: "200",
    });
    expect(status).toBe(200);
    expect(events.length).toBeGreaterThan(0);
    // 名前空間の全行が返り、外の行(env.* / var.* / dek.*)は 1 行も混じらない
    for (const event of events) {
      expect(event.event.startsWith("chain.")).toBe(true);
    }
    const all = await fetchEvents(token(OWNER), { limit: "200" });
    expect(events.length).toBe(all.events.filter((e) => e.event.startsWith("chain.")).length);
  });

  it("写像に無い chain.* 行も admin 未満に届く(§6 は名前空間全体をクラス 1 とする — R1)", async () => {
    // verify は admin を要求しない(全メンバーが実行できる)。可視性述語が
    // 写像済みの名前だけを許すと、偽造行はサーバー側で落ちて reader の verify に
    // 1 行も届かず、R1 で閉じたはずの偽造方向の被覆漏れが非 admin では残る
    // (pullfrog / Cursor Security Reviewer 指摘)
    await seedProjectActivity();
    await queryProjectDo(
      projectId,
      "INSERT INTO audit_events (seq, row_id, server_ts, event, actor_type, chain_seq) VALUES ((SELECT MAX(seq) + 1 FROM audit_events), ?, ?, 'chain.role_granted', 'user', 2)",
      "ab".repeat(16),
      Date.now(),
    );
    for (const viewer of [READER, MEMBER, OWNER]) {
      const { status, events } = await fetchEvents(token(viewer), {
        eventPrefix: "chain.",
        limit: "200",
      });
      expect(status).toBe(200);
      expect(eventNames(events)).toContain("chain.role_granted");
    }
    // クラス 2(他人の var.read / dek.registered)は admin 未満に見えないまま —
    // 名前空間の前置許可がクラス 2 の穴になっていないこと
    const readerAll = await fetchEvents(token(READER), { limit: "200" });
    expect(readerAll.events.some((event) => event.event === "dek.registered")).toBe(false);
    for (const event of readerAll.events) {
      expect(isClass1Event(event.event) || event.actor.userId === READER).toBe(true);
    }
  });

  it("chain_seq を名乗る非 chain.* 行も全メンバーの検証用フィルタへ届く(S1)", async () => {
    await seedProjectActivity();
    await queryProjectDo(
      projectId,
      "INSERT INTO audit_events (seq, row_id, server_ts, event, actor_type, actor_user_id, chain_seq) VALUES ((SELECT MAX(seq) + 1 FROM audit_events), ?, ?, 'member.add', 'user', ?, 2)",
      "cd".repeat(16),
      Date.now(),
      OWNER,
    );
    await queryProjectDo(
      projectId,
      "INSERT INTO audit_events (seq, row_id, server_ts, event, actor_type, actor_user_id) VALUES ((SELECT MAX(seq) + 1 FROM audit_events), ?, ?, 'member.add', 'user', ?)",
      "ef".repeat(16),
      Date.now(),
      OWNER,
    );

    for (const viewer of [READER, MEMBER, OWNER]) {
      const { status, events } = await fetchEvents(token(viewer), {
        chainSeqPresent: "true",
        limit: "200",
      });
      expect(status).toBe(200);
      expect(events.length).toBeGreaterThan(0);
      expect(events.every((event) => event.chainSeq !== undefined)).toBe(true);
      expect(eventNames(events)).toContain("member.add");
    }

    const readerAll = await fetchEvents(token(READER), { limit: "200" });
    const claims = readerAll.events.filter((event) => event.event === "member.add");
    expect(claims).toHaveLength(1);
    expect(claims[0]?.chainSeq).toBe(2);
  });

  it("chainSeqPresent は literal true 以外を wire schema で拒否する", async () => {
    await seedProjectActivity();
    const response = await requestJson("GET", "/audit/events?chainSeqPresent=false", token(OWNER));
    expect(response.status).toBe(400);
  });

  it("eventPrefix はワイルドカード意味論を持たない(LIKE ではなく前置比較)", async () => {
    await seedProjectActivity();
    // LIKE 実装なら "%" は全一致・"_" は 1 文字ワイルドカードとして働いてしまう
    for (const eventPrefix of ["%", "_hain.", "chain%"]) {
      const { status, events } = await fetchEvents(token(OWNER), { eventPrefix, limit: "200" });
      expect(status).toBe(200);
      expect(events).toHaveLength(0);
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
