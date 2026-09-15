// ES K3 — 招待行の scope(AUTH_SPEC §15 — 形式検査のみ。K2 で実装済みの挙動を固定する。
// 設計録 docs/notes/es-design.md §9 の項目 4)。
//   - 発行 body の scope は形式検査のみ(存在検査なし — 未存在の環境 id でも 200)
//   - 一覧行と受諾応答に scope が載る
//   - 包含検査は add_member 受理時の合意規則(ここでは足さない)

import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { BASE, bearer, JSON_HEADERS } from "./support/auth.ts";
import { OWNER, projectId, STRANGER, tokenOf } from "./support/data-fixture.ts";
import {
  acceptAs,
  fixture,
  inviteRow,
  issueInviteRequest,
  makeInviteeKeys,
  makeIssuePayload,
  mustRow,
  registerInviteScenario,
  wirePayloadOf,
} from "./support/invites-scenario.ts";

registerInviteScenario();

describe("招待行の scope(§15 — 形式検査のみ)", () => {
  it("listed の発行は環境の存在を検査せず受理し、一覧行と受諾応答に scope を載せる", async () => {
    const payload = await makeIssuePayload(fixture, OWNER, "member", {
      scopeKind: "listed",
      scopeEnvironmentIds: ["env-never-created-0001", "env-dev-0002"],
    });
    const issued = await issueInviteRequest(fixture, OWNER, "member", payload);
    expect(issued.status).toBe(200);
    const row = mustRow(await inviteRow(payload.id));
    expect(row.scope_kind).toBe("listed");
    expect(JSON.parse(String(row.scope_environments))).toEqual([
      "env-never-created-0001",
      "env-dev-0002",
    ]);

    const list = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      headers: bearer(tokenOf(fixture.tokens, OWNER)),
    });
    expect(list.status).toBe(200);
    const listed = (await list.json()) as {
      invitations: { id: string; scopeKind: string; scopeEnvironmentIds: string[] }[];
    };
    expect(listed.invitations.find((invite) => invite.id === payload.id)).toMatchObject({
      scopeKind: "listed",
      scopeEnvironmentIds: ["env-never-created-0001", "env-dev-0002"],
    });

    const keys = await makeInviteeKeys();
    const accepted = await acceptAs(fixture, STRANGER, keys, payload);
    expect(accepted.status).toBe(200);
    expect(await accepted.json()).toMatchObject({
      id: payload.id,
      role: "member",
      scopeKind: "listed",
      scopeEnvironmentIds: ["env-never-created-0001", "env-dev-0002"],
    });
  });

  it("all の発行に非空の scopeEnvironmentIds を付けると形式検査の 400(§15 の kind 規則 — 署名検証より前)", async () => {
    // 発行署名の生成側(@maruhi/crypto)は all + 非空を構造不正として拒むため、
    // 有効な all の発行文を作ってからワイヤ body だけを改変して送る
    const payload = await makeIssuePayload(fixture, OWNER, "member");
    const response = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      method: "POST",
      headers: { ...JSON_HEADERS, ...bearer(tokenOf(fixture.tokens, OWNER)) },
      body: JSON.stringify({ ...wirePayloadOf(payload), scopeEnvironmentIds: ["env-dev-0002"] }),
    });
    expect(response.status).toBe(400);
  });
});
