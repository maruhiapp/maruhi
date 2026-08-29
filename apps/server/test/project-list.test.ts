// プロジェクト一覧 API(AUTH_SPEC §11-5 — W2a)の統合テスト。
// vitest-pool-workers(workerd 実環境)で SELF 経由の HttpApi と D1 / DO を検証する。
//
// このスイートが固定するもの(session-42 裁定 BL):
// - 本人 membership のみ(存在秘匿 §11-2 との整合: 他人のプロジェクトは status を
//   含め一切現れない。非メンバーは空一覧)
// - チェーン受理への追随: add_member で出現(role 込み)・change_role で role が
//   追随(投影が role を持たないことの実挙動証明)・remove_member で消える
// - ghost 行の読取時排除 + 削除(一覧の正しさが投影 delete の成否に依存しない —
//   裁定 BI-c の要)
// - lazy upsert(§11-5 (4)): 投影行の欠落がチェーン取得成功で自己修復する
//   (投影導入前プロジェクトの無人バックフィルと同一経路)
// - トークンスコープの交差(スコープ外 = 不出現)・セッション主体の許可(§5)
// - カーソルページング(候補基準・project_id 昇順・サーバー固定 100 件)

import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { PROJECT_LIST_PAGE_SIZE } from "../src/policy.ts";
import { BASE, bearer, deviceToken, loginSession, sessionHeaders } from "./support/auth.ts";
import { vectorKeyOf } from "./support/data-crypto.ts";
import {
  appendOperation,
  MEMBER,
  OWNER,
  projectId,
  READER,
  STRANGER,
} from "./support/data-fixture.ts";
import { fixture, registerDataScenario, token } from "./support/data-scenario.ts";

registerDataScenario();

interface WireMembership {
  readonly projectId: string;
  readonly role: "owner" | "admin" | "member" | "reader";
}

interface WireProjectList {
  readonly projects: readonly WireMembership[];
  readonly nextAfter?: string;
}

function listRequest(headers: Record<string, string>, after?: string): Promise<Response> {
  const suffix = after === undefined ? "" : `?after=${after}`;
  return SELF.fetch(`${BASE}/projects${suffix}`, { headers });
}

async function listOk(headers: Record<string, string>, after?: string): Promise<WireProjectList> {
  const response = await listRequest(headers, after);
  expect(response.status).toBe(200);
  return (await response.json()) as WireProjectList;
}

/** 投影行の直接操作(失効窓・ページングの再現用 — 実装は D1 を候補索引に使う)。 */
async function projectionRowsOf(userId: string): Promise<readonly string[]> {
  const rows = await env.DB.prepare(
    "SELECT project_id FROM project_members WHERE user_id = ? ORDER BY project_id",
  )
    .bind(userId)
    .all<{ project_id: string }>();
  return rows.results.map((row) => row.project_id);
}

async function insertProjectionRow(targetProjectId: string, userId: string): Promise<void> {
  await env.DB.prepare(
    "INSERT OR IGNORE INTO project_members (project_id, user_id, created_at) VALUES (?, ?, 0)",
  )
    .bind(targetProjectId, userId)
    .run();
}

async function deleteProjectionRow(targetProjectId: string, userId: string): Promise<void> {
  await env.DB.prepare("DELETE FROM project_members WHERE project_id = ? AND user_id = ?")
    .bind(targetProjectId, userId)
    .run();
}

/** ProjectIdSchema 適合(hex 小文字 64)の合成プロジェクト ID(昇順に並ぶ)。 */
function fakeProjectId(index: number): string {
  return index.toString(16).padStart(64, "0");
}

describe("プロジェクト一覧(AUTH_SPEC §11-5)", () => {
  it("本人の membership のみを返す(チェーン導出 role 込み・非メンバーは空)", async () => {
    const owner = await listOk(bearer(token(OWNER)));
    expect(owner.projects).toEqual([{ projectId, role: "owner" }]);
    expect(owner.nextAfter).toBeUndefined();
    const member = await listOk(bearer(token(MEMBER)));
    expect(member.projects).toEqual([{ projectId, role: "member" }]);
    const reader = await listOk(bearer(token(READER)));
    expect(reader.projects).toEqual([{ projectId, role: "reader" }]);
    // 非メンバー: 空一覧(存在秘匿 §11-2 — 他人のプロジェクトの存在情報を運ばない)
    const stranger = await listOk(bearer(token(STRANGER)));
    expect(stranger.projects).toEqual([]);
  });

  it("チェーン受理に追随する: remove_member で消え・add_member で出現し・change_role で role が動く", async () => {
    // remove_member → 一覧から消える(タスク指定の固定テスト)
    await appendOperation(fixture, OWNER, {
      op: "remove_member",
      payload: { targetUserId: READER },
    });
    expect((await listOk(bearer(token(READER)))).projects).toEqual([]);
    // 受理経路の投影 delete(§11-5 (3))も行を消している
    expect(await projectionRowsOf(READER)).toEqual([]);
    // add_member(同一鍵での再追加)→ 出現(受理経路の投影 upsert — §11-5 (2))
    const keys = vectorKeyOf(READER);
    await appendOperation(fixture, OWNER, {
      op: "add_member",
      payload: {
        targetUserId: READER,
        encPubHex: keys.enc_pub_hex,
        sigPubHex: keys.sig_pub_hex,
        role: "member",
      },
    });
    expect((await listOk(bearer(token(READER)))).projects).toEqual([{ projectId, role: "member" }]);
    // change_role → role が追随(投影は role を持たず、DO の現在値が応答になる)
    await appendOperation(fixture, OWNER, {
      op: "change_role",
      payload: { targetUserId: READER, newRole: "admin" },
    });
    expect((await listOk(bearer(token(READER)))).projects).toEqual([{ projectId, role: "admin" }]);
    // 他メンバーの一覧は不変
    expect((await listOk(bearer(token(OWNER)))).projects).toEqual([{ projectId, role: "owner" }]);
  });

  it("stale ghost 行は応答から排除し、読取時に削除して収束する(裁定 BI-c)", async () => {
    // remove_member 受理後に投影行だけを復元する = 受理経路の delete が失敗した
    // 失効窓の再現。一覧の正しさは delete の成否に依存しない
    await appendOperation(fixture, OWNER, {
      op: "remove_member",
      payload: { targetUserId: MEMBER },
    });
    await insertProjectionRow(projectId, MEMBER);
    const removed = await listOk(bearer(token(MEMBER)));
    expect(removed.projects).toEqual([]);
    // 読取時確認が stale 行を削除している(チェーン truth への収束)
    expect(await projectionRowsOf(MEMBER)).toEqual([]);
  });

  it("投影行の欠落はチェーン取得成功の lazy upsert で自己修復する(§11-5 (4) — 移行経路)", async () => {
    // add_member 時の D1 障害(missing 窓)/ 投影導入前プロジェクトの再現
    await deleteProjectionRow(projectId, MEMBER);
    expect((await listOk(bearer(token(MEMBER)))).projects).toEqual([]);
    // チェーン取得(既存エンドポイント — 応答は不変)が投影行を立てる
    const chain = await SELF.fetch(`${BASE}/projects/${projectId}/chain`, {
      headers: bearer(token(MEMBER)),
    });
    expect(chain.status).toBe(200);
    expect((await listOk(bearer(token(MEMBER)))).projects).toEqual([{ projectId, role: "member" }]);
  });

  it("トークンスコープと交差する(スコープ外 = 不出現・水準は read で足りる)", async () => {
    // 対象プロジェクトを覆う read スコープ → 出現
    const scoped = await deviceToken(
      9002,
      [{ project: projectId, permission: "read" }],
      "scoped-in",
    );
    expect((await listOk(bearer(scoped))).projects).toEqual([{ projectId, role: "member" }]);
    // 別プロジェクト限定スコープ → メンバーであっても不出現(存在情報ゼロの 200)
    const other = fakeProjectId(1);
    const outOfScope = await deviceToken(
      9002,
      [{ project: other, permission: "admin" }],
      "scoped-out",
    );
    expect((await listOk(bearer(outOfScope))).projects).toEqual([]);
  });

  it("セッション主体で一覧できる(§5 の許可列挙 — S4 の消費経路)", async () => {
    const session = await loginSession(9001);
    const viaSession = await listOk(sessionHeaders(session));
    expect(viaSession.projects).toEqual([{ projectId, role: "owner" }]);
  });

  it("候補基準のカーソルページング(project_id 昇順・固定 100 件・nextAfter 連鎖)", async () => {
    // 実プロジェクトより昇順で前に並ぶ合成 ID をページ上限ぶん挿入する
    // (DO 側は未初期化 = ghost — ページングと読取時収束の合成検証)。
    // 実プロジェクト ID が偶然 fake の範囲に入らないことを前提に固定 ID を使う
    expect(projectId > fakeProjectId(PROJECT_LIST_PAGE_SIZE)).toBe(true);
    for (let index = 1; index <= PROJECT_LIST_PAGE_SIZE; index += 1) {
      await insertProjectionRow(fakeProjectId(index), OWNER);
    }
    // ページ 1: 候補 100 件(全部 ghost)→ 応答は空 + nextAfter = 候補末尾
    const first = await listOk(bearer(token(OWNER)));
    expect(first.projects).toEqual([]);
    expect(first.nextAfter).toBe(fakeProjectId(PROJECT_LIST_PAGE_SIZE));
    // ページ 2: 実プロジェクトが現れ、終端(nextAfter なし)
    const second = await listOk(bearer(token(OWNER)), first.nextAfter);
    expect(second.projects).toEqual([{ projectId, role: "owner" }]);
    expect(second.nextAfter).toBeUndefined();
    // ghost 候補はページ 1 の読取時にすべて削除済み(実行行だけが残る)
    expect(await projectionRowsOf(OWNER)).toEqual([projectId]);
  });
});
