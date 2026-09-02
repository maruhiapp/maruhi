// プロジェクト数 / org の受理上限(AUTH_SPEC §11-3 — 2026-09-02 H2)の統合テスト。
// vitest-pool-workers(workerd 実環境)で SELF 経由の HttpApi と D1 / DO を検証する。
//
// 上限件数の init を実経路で回すのは重い(1 init = チェーン検証 + D1 batch)ため、
// 判定材料の `projects` 行は D1 へ直接シードして境界(到達・拒否・解放)を作る。
// 判定の純関数(projectQuotaExceeded)は数値のみで固定する(quotas.ts の他の
// *Exceeded と同じ形)。

import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { MAX_ACTIVE_PROJECTS_PER_ORG } from "../src/policy.ts";
import { projectQuotaExceeded } from "../src/quotas.ts";
import { seedOrgMember } from "./support/auth.ts";
import { toWireEntry, vectorEntries, vectorProjectId } from "./support/chain-vectors.ts";
import {
  getChain,
  initChain,
  registerMembershipScenario,
  VECTOR_ORG,
} from "./support/membership-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerMembershipScenario();

const genesisEntry = () => {
  const genesis = vectorEntries[0];
  if (genesis === undefined) throw new Error("missing genesis vector");
  return toWireEntry(genesis);
};

/** 判定材料だけを作る: 当該 org に `count` 件のダミー projects 行(ID は 64 hex)。 */
async function seedProjectRows(orgId: string, count: number): Promise<void> {
  const statements = Array.from({ length: count }, (_, index) =>
    env.DB.prepare("INSERT INTO projects (id, org_id, created_at) VALUES (?, ?, ?)").bind(
      `${"f".repeat(56)}${index.toString(16).padStart(8, "0")}`,
      orgId,
      1754006400000 + index,
    ),
  );
  await env.DB.batch(statements);
}

async function projectRowsInOrg(orgId: string): Promise<number> {
  const row = await env.DB.prepare("SELECT count(*) AS n FROM projects WHERE org_id = ?")
    .bind(orgId)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

describe("projectQuotaExceeded(純関数 — §11-3)", () => {
  it("rejects the (limit + 1)-th project and admits up to the limit", () => {
    expect(projectQuotaExceeded(MAX_ACTIVE_PROJECTS_PER_ORG)).toBe(true);
    expect(projectQuotaExceeded(MAX_ACTIVE_PROJECTS_PER_ORG - 1)).toBe(false);
    expect(projectQuotaExceeded(0)).toBe(false);
  });
});

describe("POST /projects × プロジェクト数 / org 上限(§11-3 — H2)", () => {
  it("rejects a fresh genesis with 429 ProjectLimit at the limit and leaves the DO uninitialized", async () => {
    await seedProjectRows(VECTOR_ORG, MAX_ACTIVE_PROJECTS_PER_ORG);
    const response = await initChain(genesisEntry());
    expect(response.status).toBe(429);
    await expect(response.json()).resolves.toEqual({
      _tag: "ProjectLimit",
      limit: MAX_ACTIVE_PROJECTS_PER_ORG,
    });
    // DO は何も書いていない(admitFresh = false は report-only): チェーン取得は
    // 未初期化 = 404(§11-2)、DO の chain テーブルは空
    const chain = await getChain(vectorProjectId);
    expect(chain.status).toBe(404);
    const entries = await queryProjectDo(
      vectorProjectId,
      "SELECT count(*) AS n FROM chain_entries",
    );
    expect(entries[0]?.["n"]).toBe(0);
    // D1 側も不変(projects 行・org.project_created の監査行とも増えない)
    expect(await projectRowsInOrg(VECTOR_ORG)).toBe(MAX_ACTIVE_PROJECTS_PER_ORG);
    const audit = await env.DB.prepare(
      "SELECT count(*) AS n FROM org_audit_events WHERE event = 'org.project_created' AND project_id = ?",
    )
      .bind(vectorProjectId)
      .first<{ n: number }>();
    expect(audit?.n ?? 0).toBe(0);
  });

  it("admits the genesis again once a slot is freed (the limit counts current rows)", async () => {
    await seedProjectRows(VECTOR_ORG, MAX_ACTIVE_PROJECTS_PER_ORG);
    expect((await initChain(genesisEntry())).status).toBe(429);
    await env.DB.prepare("DELETE FROM projects WHERE id = ?")
      .bind(`${"f".repeat(56)}00000000`)
      .run();
    const response = await initChain(genesisEntry());
    expect(response.status).toBe(200);
    expect(await projectRowsInOrg(VECTOR_ORG)).toBe(MAX_ACTIVE_PROJECTS_PER_ORG);
  });

  it("admits exactly up to the limit (limit - 1 rows + this genesis = limit)", async () => {
    await seedProjectRows(VECTOR_ORG, MAX_ACTIVE_PROJECTS_PER_ORG - 1);
    const response = await initChain(genesisEntry());
    expect(response.status).toBe(200);
    expect(await projectRowsInOrg(VECTOR_ORG)).toBe(MAX_ACTIVE_PROJECTS_PER_ORG);
  });

  it("does not block the §11-3 repair path at the limit (already-initialized + missing row)", async () => {
    // 正常に init → DO 受理後・D1 行挿入前のクラッシュを模擬(行だけ消す)→
    // その間に org が上限まで埋まった状況で再 init
    expect((await initChain(genesisEntry())).status).toBe(200);
    await env.DB.prepare("DELETE FROM projects WHERE id = ?").bind(vectorProjectId).run();
    await seedProjectRows(VECTOR_ORG, MAX_ACTIVE_PROJECTS_PER_ORG);
    expect(await projectRowsInOrg(VECTOR_ORG)).toBe(MAX_ACTIVE_PROJECTS_PER_ORG);
    const retried = await initChain(genesisEntry());
    expect(retried.status).toBe(200);
    const genesis = vectorEntries[0];
    await expect(retried.json()).resolves.toEqual({
      projectId: vectorProjectId,
      headSeq: 1,
      headHashHex: genesis?.entry_hash_hex,
    });
    const row = await env.DB.prepare("SELECT org_id FROM projects WHERE id = ?")
      .bind(vectorProjectId)
      .first<{ org_id: string }>();
    expect(row?.org_id).toBe(VECTOR_ORG);
    // 修復は上限を 1 超過させる(DO に実在するプロジェクトを D1 に見せる方を
    // 優先 — §11-3 の受容)
    expect(await projectRowsInOrg(VECTOR_ORG)).toBe(MAX_ACTIVE_PROJECTS_PER_ORG + 1);
  });

  it("keeps the duplicate-genesis 409 ahead of the limit (already-initialized is decided first)", async () => {
    expect((await initChain(genesisEntry())).status).toBe(200);
    await seedProjectRows(VECTOR_ORG, MAX_ACTIVE_PROJECTS_PER_ORG - 1);
    expect(await projectRowsInOrg(VECTOR_ORG)).toBe(MAX_ACTIVE_PROJECTS_PER_ORG);
    const second = await initChain(genesisEntry());
    expect(second.status).toBe(409);
  });

  it("keeps the org-membership 403 ahead of the limit (no limit information leaks to non-members)", async () => {
    await seedOrgMember("org-not-mine", "user-member-0002", "owner");
    await seedProjectRows("org-not-mine", MAX_ACTIVE_PROJECTS_PER_ORG);
    const response = await initChain(genesisEntry(), { orgId: "org-not-mine" });
    expect(response.status).toBe(403);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("org-membership-required");
  });
});
