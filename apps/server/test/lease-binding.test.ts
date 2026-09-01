// ワークロードリースの先着束縛(AUTH_SPEC §14-1 — 2026-08-15 裁定)と
// 発信元 IP の request-level レート制限(deepsec M5)の統合テスト。
// スイート全体の分担は lease.test.ts 冒頭、共有ヘルパは
// support/lease-scenario.ts を参照。
//
// このスイートが固定するもの(§14-1): 同一トークン + 別鍵の拒否・同一鍵の
// 冪等リトライ・保持期間と時刻検証の受理窓の整合・期限切れ束縛の GC。

import { encodeHex } from "@maruhi/crypto";
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { OIDC_CLOCK_SKEW_MS } from "../src/oidc.package/index.ts";
import { LEASE_BINDING_RETENTION_MARGIN_MS } from "../src/policy.ts";
import { JSON_HEADERS } from "./support/auth.ts";
import { createEnvironmentOk, projectId } from "./support/data-fixture.ts";
import { ENV, fixture, registerDataScenario } from "./support/data-scenario.ts";
import type { LeaseBody } from "./support/lease-scenario.ts";
import {
  backfillServerWrap,
  claimsDigestOf,
  grantServer,
  malleateSignatureSegment,
  openLease,
  readyProject,
  requestLease,
  requireFirst,
  workloadKeyPair,
} from "./support/lease-scenario.ts";
import { makeOidcToken } from "./support/lease.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

describe("ワークロードリース: 先着束縛(§14-1 — 2026-08-15 裁定)", () => {
  it("rejects the same token presented with a different ephemeral key (401 token-replayed)", async () => {
    await readyProject();
    const legit = await workloadKeyPair();
    const oidcToken = await makeOidcToken();
    expect((await requestLease({ oidcToken, ephemeralPubHex: legit.publicKeyHex })).status).toBe(
      200,
    );

    // 盗まれたトークンのコピー + 攻撃者自身の一時鍵(裁定前はこれが通っていた)
    const thief = await workloadKeyPair();
    const replay = await requestLease({ oidcToken, ephemeralPubHex: thief.publicKeyHex });
    expect(replay.status).toBe(401);
    expect(await replay.json()).toMatchObject({ reason: "token-replayed" });

    // 監査(AUDIT_SPEC §3.5): lease_denied が残り、claims_digest は正規発行と
    // 同一 = 所有者は「どのワークロードのトークンが盗まれたか」を突合できる
    const denied = await queryProjectDo(
      projectId,
      "SELECT payload FROM audit_events WHERE event = 'server.lease_denied'",
    );
    expect(denied.length).toBe(1);
    const payload = JSON.parse(String(denied[0]?.["payload"])) as Record<string, unknown>;
    expect(payload["reason"]).toBe("token-replayed");
    expect(payload["claimsDigest"]).toBe(await claimsDigestOf());

    // 拒否はレート窓を消費しない(発行 1 回分のまま — §14-3)
    const windows = await queryProjectDo(
      projectId,
      "SELECT count FROM lease_windows WHERE kind = 'issued'",
    );
    expect(windows[0]?.["count"]).toBe(1);
  });

  it("allows an idempotent retry: the same token + same ephemeral key succeeds again", async () => {
    // 応答喪失後の正規リトライ。トークンをランタイム再発行できない事前発行型
    // issuer(GitLab 等)を将来足しても再試行が壊れないための冪等性(§14-1)
    const { dek } = await readyProject();
    const workload = await workloadKeyPair();
    const oidcToken = await makeOidcToken();
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const response = await requestLease({ oidcToken, ephemeralPubHex: workload.publicKeyHex });
      expect(response.status).toBe(200);
      // リトライの応答も開封可能な本物のリースであること(空応答の冪等ではない)
      const body = (await response.json()) as LeaseBody;
      const opened = await openLease({
        lease: requireFirst(body.leases, "lease"),
        workloadKeyPair: workload.pair,
        claimsDigestHex: await claimsDigestOf(),
      });
      expect(opened.ok && encodeHex(opened.value)).toBe(encodeHex(dek));
    }
    // 束縛行は 1 行のまま(上書きしない)
    const bindings = await queryProjectDo(projectId, "SELECT COUNT(*) AS n FROM lease_bindings");
    expect(bindings[0]?.["n"]).toBe(1);
  });

  it("rejects a replayed token uniformly, regardless of the target environment's existence", async () => {
    // 判定は環境存在より前(§14-3): 束縛済みトークンのコピー保持者に
    // 「401 か 404 か」の差で環境の実在を教えない
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const uncreated = "env-in-scope-uncreated";
    await grantServer({ scope: [ENV, uncreated] });
    await backfillServerWrap(1, dek);
    const legit = await workloadKeyPair();
    const oidcToken = await makeOidcToken();
    expect((await requestLease({ oidcToken, ephemeralPubHex: legit.publicKeyHex })).status).toBe(
      200,
    );

    const thief = await workloadKeyPair();
    for (const environmentId of [ENV, uncreated]) {
      const replay = await requestLease({
        oidcToken,
        ephemeralPubHex: thief.publicKeyHex,
        environmentId,
      });
      expect(replay.status).toBe(401);
      expect(await replay.json()).toMatchObject({ reason: "token-replayed" });
    }
  });

  it("locks a token to one ephemeral key across environments (project-wide binding — クライアント義務)", async () => {
    // 束縛はトークン単位でプロジェクト DO を跨がず共有される(environmentId は
    // キーに含まない)。エンドポイントは環境単位なので、1 トークンで N 環境を
    // リースするジョブは**全リクエストで同じ一時鍵**を提示しなければならない。
    // これは A3 の義務(トークンあたり一時鍵は 1 つ・リクエストごとに
    // ローテーションしない — AUTH_SPEC §14-1)。ランタイム再発行できない
    // 事前発行型 issuer(GitLab 等)で特に効くため、緩いうちに固定する。
    const SECOND = "env-second-0002";
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    const dek2 = await createEnvironmentOk(fixture, SECOND, "App2");
    await grantServer({ scope: [ENV, SECOND] });
    await backfillServerWrap(1, dek1, ENV);
    await backfillServerWrap(1, dek2, SECOND);

    const oidcToken = await makeOidcToken();
    const workload = await workloadKeyPair();
    // 同一トークン + 同一鍵なら複数環境をリースできる
    for (const environmentId of [ENV, SECOND]) {
      const response = await requestLease({
        oidcToken,
        ephemeralPubHex: workload.publicKeyHex,
        environmentId,
      });
      expect(response.status).toBe(200);
    }
    // 別環境で鍵をローテーションすると 401(束縛はトークン単位・鍵固定であり、
    // 未束縛環境への「自分の鍵でのリース」を許さない = 盗難トークンで別環境を
    // 引く経路も同時に塞ぐ)
    const rotated = await workloadKeyPair();
    const replay = await requestLease({
      oidcToken,
      ephemeralPubHex: rotated.publicKeyHex,
      environmentId: SECOND,
    });
    expect(replay.status).toBe(401);
    expect(await replay.json()).toMatchObject({ reason: "token-replayed" });
  });

  it("keeps the binding alive as long as time validation can accept the token (PyPI 監査の同型の穴の回避)", async () => {
    // exp が過去でも skew(±60 秒)内なら時刻検証は通る。束縛の保持期間が
    // 受理窓より短いと、その差分だけがリプレイ窓になる(policy.ts の保持余裕を
    // skew から導出している理由 — docs/notes/session-24.md §2 の先例)
    await readyProject();
    const expSeconds = Math.floor(Date.now() / 1000) - 30; // 過去だが skew 内
    const oidcToken = await makeOidcToken({ expSeconds });
    const legit = await workloadKeyPair();
    expect((await requestLease({ oidcToken, ephemeralPubHex: legit.publicKeyHex })).status).toBe(
      200,
    );

    // 束縛行の生存期限 = exp + 保持余裕(余裕 ≥ skew は導出で保証)
    const rows = await queryProjectDo(projectId, "SELECT expires_at FROM lease_bindings");
    expect(rows[0]?.["expires_at"]).toBe(expSeconds * 1000 + LEASE_BINDING_RETENTION_MARGIN_MS);
    expect(LEASE_BINDING_RETENTION_MARGIN_MS).toBeGreaterThanOrEqual(OIDC_CLOCK_SKEW_MS);

    // 受理窓の残りでのリプレイは束縛に当たって拒否される
    const thief = await workloadKeyPair();
    const replay = await requestLease({ oidcToken, ephemeralPubHex: thief.publicKeyHex });
    expect(replay.status).toBe(401);
    expect(await replay.json()).toMatchObject({ reason: "token-replayed" });
  });

  it("garbage-collects expired bindings when a lease is issued", async () => {
    await readyProject();
    await queryProjectDo(
      projectId,
      "INSERT INTO lease_bindings (binding_key_hex, ephemeral_pub_hex, expires_at) VALUES ('aa', 'bb', ?)",
      Date.now() - 1000,
    );
    const workload = await workloadKeyPair();
    expect(
      (
        await requestLease({
          oidcToken: await makeOidcToken(),
          ephemeralPubHex: workload.publicKeyHex,
        })
      ).status,
    ).toBe(200);
    // 期限切れ行は発行時に GC され、残るのは今回の束縛だけ
    const rows = await queryProjectDo(projectId, "SELECT binding_key_hex FROM lease_bindings");
    expect(rows.length).toBe(1);
    expect(rows[0]?.["binding_key_hex"]).not.toBe("aa");
  });

  it("binds on the signed material, not the raw token: a malleated signature segment cannot dodge the binding", async () => {
    // 🚨 リグレッションガード(2026-08-15 pullfrog 指摘): 束縛キーが生トークンの
    // ハッシュだと、署名で保護されない第 3 セグメントの base64url 末尾を
    // 「デコード結果が同一になる別文字」へ差し替えるだけで、署名検証・
    // claims_digest を一切変えずにハッシュだけ変えられ、束縛照合が空振りして
    // リプレイが通る。束縛キーを signing input(header.payload)のハッシュに
    // することでこの経路が閉じることを固定する。
    await readyProject();
    const oidcToken = await makeOidcToken();
    const legit = await workloadKeyPair();
    expect((await requestLease({ oidcToken, ephemeralPubHex: legit.publicKeyHex })).status).toBe(
      200,
    );

    const malleated = malleateSignatureSegment(oidcToken);
    // 前提の確認: 変異トークンは生文字列としては別物(素朴なハッシュは別値になる)
    expect(malleated).not.toBe(oidcToken);

    const thief = await workloadKeyPair();
    const replay = await requestLease({
      oidcToken: malleated,
      ephemeralPubHex: thief.publicKeyHex,
    });
    // 変異は署名検証を通過する(= signature-invalid ではない)が、signing input が
    // 不変なので束縛に当たって token-replayed になる。ここが 200 に戻ると、
    // まさに 1 文字編集でのリプレイ回避が復活したことを意味する
    expect(replay.status).toBe(401);
    expect(await replay.json()).toMatchObject({ reason: "token-replayed" });
  });
});

// 実在しないプロジェクト ID への連投(deepsec M5 検査用): 制限が projectStub より
// 手前にあるため DO は生成されない。Schema(base64url + `.` の文字集合)は通し、
// OIDC 検証段で落ちる形 — 制限判定はハンドラ内(Schema 通過後)なので、Schema で
// 弾かれる形だとそもそも計数されない
function rateLimitedLeaseAttempt(): Promise<Response> {
  return SELF.fetch(`https://maruhi.test/projects/${"ab".repeat(32)}/environments/${ENV}/lease`, {
    method: "POST",
    headers: { ...JSON_HEADERS, "cf-connecting-ip": "198.51.100.9" },
    body: JSON.stringify({ oidcToken: "aaaa.bbbb.cccc", ephemeralPubHex: "cd".repeat(32) }),
  });
}

describe("ワークロードリース: 発信元 IP の request-level レート制限(deepsec M5)", () => {
  it("固定 IP からの連投は OIDC 検証・DO 生成に到達する前に 429 になる", async () => {
    // 判定は IP のみでプロジェクト状態と無関係なので、429 の露出は存在秘匿
    // (§11-2)を壊さない
    // 窓は wall-clock 整列の固定窓(60/60s): 逐次送信だと遅いランナーでは
    // 1 窓に 61 発が収まらずフレークする。並列バーストで 2 窓 + 2 発
    // (124 リクエスト)を数秒に収める — 分境界がバースト中に落ちても、
    // どちらかの窓が必ず 62 発を受けて 429 を返す
    const responses: Response[] = [];
    for (let batch = 0; batch < 4; batch += 1) {
      responses.push(
        ...(await Promise.all(Array.from({ length: 31 }, () => rateLimitedLeaseAttempt()))),
      );
    }
    let limited: Response | null = null;
    for (const response of responses) {
      if (response.status === 429 && limited === null) {
        limited = response;
      } else if (response.status !== 429) {
        // 制限にかからない分は通常の認証段拒否(401 malformed-token)
        expect(response.status).toBe(401);
      }
    }
    expect(limited).not.toBeNull();
    // RFC 9110 の Retry-After ヘッダーも運ぶ(maruhi CLI 以外のクライアントの
    // バックオフ材料 — index.ts の withRetryAfterHeader)
    expect(limited?.headers.get("retry-after")).toMatch(/^\d+$/);
    const body = (await limited?.json()) as Record<string, unknown>;
    expect(body["_tag"]).toBe("LeaseRateLimited");
    expect(body["scope"]).toBe("source-address");
    expect(body["retryAfterSeconds"] as number).toBeGreaterThan(0);
    // 124 リクエストのバーストはスイート全体の負荷次第で既定 15s を越える
    // (実測 — フルスイート実行時)。fixture の beforeEach が PAT を実経路
    // (CLI ログインハンドオフ = 6 往復/ユーザー)で発行するようになった分も
    // この計測に含まれる。ハング検出の有界性は保ったまま延長する
  }, 120_000);
});
