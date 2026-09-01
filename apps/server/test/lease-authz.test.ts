// ワークロードリースの認可と存在秘匿(AUTH_SPEC §14-1 / §11-2 — 一律 404)の
// 統合テスト。スイート全体の分担は lease.test.ts 冒頭、共有ヘルパは
// support/lease-scenario.ts を参照。
//
// このスイートが固定するもの(§14-1): grant なし・ポリシー不一致・スコープ外・
// 環境なし・未初期化プロジェクトが**すべて同じ 404** であること(理由が漏れない)。

import { describe, expect, it } from "vitest";

import {
  appendOperation,
  createEnvironmentOk,
  deleteEnvironmentRequest,
  OWNER,
  projectId,
} from "./support/data-fixture.ts";
import { ENV, fixture, registerDataScenario } from "./support/data-scenario.ts";
import type { LeasePolicy } from "./support/lease-scenario.ts";
import {
  backfillServerWrap,
  defaultPolicy,
  grantServer,
  requestLease,
  workloadKeyPair,
} from "./support/lease-scenario.ts";
import { LEASE_AUDIENCE, LEASE_SUBJECT, makeOidcToken } from "./support/lease.ts";
import { OIDC_ISSUER } from "./support/oidc-issuer.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

async function expect404(input: {
  readonly leasePolicy?: LeasePolicy;
  readonly scope?: readonly string[];
  readonly tokenOptions?: Parameters<typeof makeOidcToken>[0];
  readonly environmentId?: string;
  readonly skipGrant?: boolean;
}): Promise<void> {
  const dek = await createEnvironmentOk(fixture, ENV, "App");
  if (input.skipGrant !== true) {
    const scope = input.scope ?? [ENV];
    await grantServer({
      scope,
      ...(input.leasePolicy === undefined ? {} : { leasePolicy: input.leasePolicy }),
    });
    // 開示スコープ外の環境へのサーバー宛ラップは登録自体が 422(§12-6)。
    // スコープ外ケースでは「ラップは無いが grant はある」状態が正しい前提
    if (scope.includes(ENV)) {
      await backfillServerWrap(1, dek);
    }
  }
  const workload = await workloadKeyPair();
  const response = await requestLease({
    oidcToken: await makeOidcToken(input.tokenOptions),
    ephemeralPubHex: workload.publicKeyHex,
    ...(input.environmentId === undefined ? {} : { environmentId: input.environmentId }),
  });
  expect(response.status).toBe(404);
}

describe("ワークロードリース: 認可と存在秘匿(§14-1 / §11-2 — 一律 404)", () => {
  it("hides a project with no server grant", async () => {
    await expect404({ skipGrant: true });
  });

  it("hides an empty lease policy (grant allows wrap registration only — CRYPTO_SPEC §6.2)", async () => {
    await expect404({ leasePolicy: [] });
  });

  it("fails closed when a matching policy element has no claim constraints", async () => {
    await expect404({
      leasePolicy: [
        {
          issuerUrl: OIDC_ISSUER,
          audience: LEASE_AUDIENCE,
          claimConstraints: [],
        },
      ],
    });
  });

  it("hides an issuer mismatch in the policy", async () => {
    await expect404({
      leasePolicy: [
        {
          issuerUrl: "https://gitlab.example",
          audience: LEASE_AUDIENCE,
          claimConstraints: [{ claimName: "sub", claimValue: LEASE_SUBJECT }],
        },
      ],
    });
  });

  it("hides an audience mismatch in the policy", async () => {
    await expect404({
      leasePolicy: [
        {
          issuerUrl: OIDC_ISSUER,
          audience: "https://other.example",
          claimConstraints: [{ claimName: "sub", claimValue: LEASE_SUBJECT }],
        },
      ],
    });
  });

  it("hides a claim-constraint mismatch (different branch)", async () => {
    await expect404({
      tokenOptions: { subject: "repo:maruhi-test/demo:ref:refs/heads/feature-x" },
    });
  });

  it("hides an environment outside the disclosure scope", async () => {
    await expect404({ scope: ["env-other-0002"] });
  });

  it("hides an unknown project entirely (and writes no audit row)", async () => {
    const workload = await workloadKeyPair();
    const other = "f".repeat(64);
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
      project: other,
    });
    expect(response.status).toBe(404);
    // 未初期化 DO に監査行を作らない(未認証経路からの肥大 DoS の遮断)
    const rows = await queryProjectDo(other, "SELECT COUNT(*) AS n FROM audit_events");
    expect(rows[0]?.["n"]).toBe(0);
  });

  it("hides a deleted environment that is still inside the disclosure scope", async () => {
    // 判定順コメントが列挙する 5 つの 404 分岐のうち、これだけ未検証だった
    // (pullfrog 指摘)。スコープには入っているが tombstone 済みの環境
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await grantServer({ scope: [ENV] });
    await backfillServerWrap(1, dek);
    const deleted = await deleteEnvironmentRequest(fixture, ENV, OWNER);
    expect(deleted.status).toBe(204);
    const workload = await workloadKeyPair();
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(404);
  });

  it("returns a byte-identical 404 body for every cause (存在秘匿の中核)", async () => {
    // 各ケースがステータスコードしか見ていないと、将来どれか 1 分岐に
    // フィールドが増えても検出できない(pullfrog 指摘)。本 PR の中核主張なので
    // ボディまで同一であることを 1 本で固定する。
    //
    // **4 分岐を別々に踏ませる**: 空 lease_policy にすると policy-mismatch が
    // 先に成立して scope-out-of-range / environment-not-found に到達せず、
    // 同じ経路の body を 2 回集めるだけになる(pullfrog 指摘)。実在するポリシーを
    // 張り、トークンとリクエスト環境の側で分岐を撃ち分ける。踏んだ分岐は
    // lease_denied の reason で事後確認する(黙って縮退したら落ちる)
    const workload = await workloadKeyPair();
    const bodyOf = async (
      input: {
        readonly environmentId?: string;
        readonly subject?: string;
        readonly project?: string;
      } = {},
    ): Promise<string> => {
      const response = await requestLease({
        oidcToken: await makeOidcToken(
          input.subject === undefined ? {} : { subject: input.subject },
        ),
        ephemeralPubHex: workload.publicKeyHex,
        ...(input.environmentId === undefined ? {} : { environmentId: input.environmentId }),
        ...(input.project === undefined ? {} : { project: input.project }),
      });
      expect(response.status).toBe(404);
      return response.text();
    };

    // (a) 未知プロジェクト。**別 DO** を引くので監査は残らない(下の突合対象外)
    const unknownProject = "f".repeat(64);
    const bodies = [await bodyOf({ project: unknownProject })];

    // (b) grant なし
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    bodies.push(await bodyOf());

    // 実在ポリシー + スコープに「ENV と、未作成の環境 ID」を入れる
    const uncreated = "env-in-scope-uncreated";
    await grantServer({ scope: [ENV, uncreated] });
    await backfillServerWrap(1, dek);

    // (c) ポリシー不一致(別ブランチの subject)
    bodies.push(await bodyOf({ subject: "repo:maruhi-test/demo:ref:refs/heads/feature-x" }));
    // (d) スコープ外の環境(ポリシーは一致する)
    bodies.push(await bodyOf({ environmentId: "env-out-of-scope-0009" }));
    // (e) スコープ内だが未作成の環境
    bodies.push(await bodyOf({ environmentId: uncreated }));

    // ボディが運ぶのは呼び出し元自身の入力(projectId)の反響のみ。(a) だけは
    // 入力した ID が違うので、その 1 点を除いて全ケースが同一であることを見る
    expect(JSON.parse(bodies[0] ?? "{}")).toEqual({
      _tag: "ProjectNotFound",
      projectId: unknownProject,
    });
    expect(new Set(bodies.slice(1)).size).toBe(1);
    expect(JSON.parse(bodies[1] ?? "{}")).toEqual({ _tag: "ProjectNotFound", projectId });

    // 4 分岐を本当に別々に踏んだことを監査で裏取りする
    const denied = await queryProjectDo(
      projectId,
      "SELECT payload FROM audit_events WHERE event = 'server.lease_denied' ORDER BY seq",
    );
    const reasons = denied.map(
      (row) => (JSON.parse(String(row["payload"])) as { reason: string }).reason,
    );
    expect(reasons).toEqual([
      "no-grant",
      "policy-mismatch",
      "scope-out-of-range",
      "environment-not-found",
    ]);
  });

  it("authorizes when any policy element matches (existential — §14-1)", async () => {
    // 一致しない要素が先頭にあっても、後続の一致する要素で認可される
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await grantServer({
      scope: [ENV],
      leasePolicy: [
        {
          issuerUrl: OIDC_ISSUER,
          audience: LEASE_AUDIENCE,
          claimConstraints: [{ claimName: "sub", claimValue: "repo:other/repo:ref:refs/heads/x" }],
        },
        ...defaultPolicy(),
      ],
    });
    await backfillServerWrap(1, dek);
    const workload = await workloadKeyPair();
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(200);
  });

  it("requires every claim constraint of the matching element (AND)", async () => {
    await expect404({
      leasePolicy: [
        {
          issuerUrl: OIDC_ISSUER,
          audience: LEASE_AUDIENCE,
          claimConstraints: [
            { claimName: "sub", claimValue: LEASE_SUBJECT },
            { claimName: "environment", claimValue: "production" },
          ],
        },
      ],
    });
  });

  it("never coerces non-string claims into a match", async () => {
    await expect404({
      leasePolicy: [
        {
          issuerUrl: OIDC_ISSUER,
          audience: LEASE_AUDIENCE,
          claimConstraints: [{ claimName: "run_number", claimValue: "42" }],
        },
      ],
      tokenOptions: { claims: { run_number: 42 } },
    });
  });

  it("stops leasing after revoke_server (§7 の失効)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const fpHex = await grantServer({ scope: [ENV] });
    await backfillServerWrap(1, dek);
    const workload = await workloadKeyPair();
    expect(
      (
        await requestLease({
          oidcToken: await makeOidcToken(),
          ephemeralPubHex: workload.publicKeyHex,
        })
      ).status,
    ).toBe(200);

    await appendOperation(fixture, OWNER, {
      op: "revoke_server",
      payload: { serverKeyFingerprintHex: fpHex },
    });
    const after = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(after.status).toBe(404);
  });

  it("records lease_denied with the reason and claims_digest, but no external identifier", async () => {
    await expect404({ leasePolicy: [] });
    const rows = await queryProjectDo(
      projectId,
      "SELECT actor_type, actor_user_id, actor_key_fingerprint, payload FROM audit_events WHERE event = 'server.lease_denied'",
    );
    expect(rows.length).toBe(1);
    // actor は system(外部ワークロードは maruhi 上の識別を持たない — §3.5)
    expect(rows[0]?.["actor_type"]).toBe("system");
    expect(rows[0]?.["actor_user_id"]).toBeNull();
    expect(rows[0]?.["actor_key_fingerprint"]).toBeNull();
    const payload = JSON.parse(String(rows[0]?.["payload"])) as Record<string, unknown>;
    expect(payload["reason"]).toBe("policy-mismatch");
    expect(typeof payload["claimsDigest"]).toBe("string");
    // 外部識別子(sub / repo 名)は書かない(§14-4 / AUDIT_SPEC §1-2)
    expect(JSON.stringify(payload)).not.toContain("maruhi-test/demo");
  });
});
