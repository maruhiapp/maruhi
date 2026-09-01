// ワークロードリースの 503 と監査(AUTH_SPEC §14-3 / AUDIT_SPEC §3.5)・
// サーバー鍵未設定のデプロイメント・受理ポリシーの統合テスト。
// スイート全体の分担は lease.test.ts 冒頭、共有ヘルパは
// support/lease-scenario.ts を参照。
//
// このスイートが固定するもの:
// - 監査(AUDIT_SPEC §3.5): server.dek_unwrapped / server.lease_issued /
//   server.lease_denied の粒度と、var.read を**記録しない**こと

import { Effect } from "effect";
import { describe, expect, it } from "vitest";

import { AuditStore } from "../src/audit-store.ts";
import { ChainStore } from "../src/chain-store.ts";
import { DataStore } from "../src/data-store.ts";
import { MAX_LEASES_PER_WINDOW } from "../src/policy.ts";
import { leaseProgram } from "../src/programs-lease.ts";
import { makeServerKey, ServerKey } from "../src/server-key.ts";
import {
  createEnvironmentOk,
  MEMBER,
  projectId,
  rotateEnvironmentOk,
} from "./support/data-fixture.ts";
import {
  createVariableOk,
  ENV,
  fixture,
  registerDataScenario,
  VAR,
} from "./support/data-scenario.ts";
import {
  backfillServerWrap,
  grantServer,
  readyProject,
  requestLease,
  workloadKeyPair,
} from "./support/lease-scenario.ts";
import { LEASE_AUDIENCE, LEASE_SUBJECT, makeOidcToken } from "./support/lease.ts";
import { OIDC_ISSUER } from "./support/oidc-issuer.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

/** 変数 1 本 + エポック 2 まで進め、grant と全エポックのバックフィルを済ませる。 */
async function twoEpochProject(): Promise<{ readonly fpHex: string }> {
  const dek1 = await createEnvironmentOk(fixture, ENV, "App");
  await createVariableOk(dek1, VAR, "DATABASE_URL", "postgres://alpha");
  const dek2 = await rotateEnvironmentOk(fixture, MEMBER, ENV, 2);
  const fpHex = await grantServer({ scope: [ENV] });
  await backfillServerWrap(1, dek1);
  await backfillServerWrap(2, dek2);
  return { fpHex };
}

describe("ワークロードリース: 503 と監査(§14-3 / AUDIT_SPEC §3.5)", () => {
  it("returns 503 server-wraps-missing when the grant is valid but the re-wrap is pending", async () => {
    // grant はあるがバックフィルしていない = CRYPTO_SPEC §7 の再ラップ未了。
    // これを不透明な失敗にしない(A1 の裁定: リースが最後の砦)
    await createEnvironmentOk(fixture, ENV, "App");
    await grantServer({ scope: [ENV] });
    const workload = await workloadKeyPair();
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ reason: "server-wraps-missing" });
  });

  it("returns 503 when the grant backfill covered only some of the existing epochs", async () => {
    // 有効 grant がある環境のローテーション複合は、サーバー鍵を含むラップ完全
    // 集合を要求する(§12-4)ため、rotate 経由で欠落は作れない。現実的な発生源は
    // 「既存エポックのある環境へ grant したあと、バックフィルが一部で漏れた」
    // ケース(A1 の裁定 4: 照合手段は 409 のみで、リースが最後の砦)
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    await rotateEnvironmentOk(fixture, MEMBER, ENV, 2);
    await grantServer({ scope: [ENV] });
    // epoch 1 だけバックフィルし、現エポック 2 を落とす
    await backfillServerWrap(1, dek1);
    const workload = await workloadKeyPair();
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ reason: "server-wraps-missing" });
  });

  it("records dek_unwrapped per epoch, actor = the server key", async () => {
    const { fpHex } = await twoEpochProject();
    const workload = await workloadKeyPair();
    expect(
      (
        await requestLease({
          oidcToken: await makeOidcToken(),
          ephemeralPubHex: workload.publicKeyHex,
        })
      ).status,
    ).toBe(200);

    const unwrapped = await queryProjectDo(
      projectId,
      "SELECT epoch, actor_type, actor_key_fingerprint, environment_id FROM audit_events WHERE event = 'server.dek_unwrapped' ORDER BY epoch",
    );
    expect(unwrapped.map((row) => row["epoch"])).toEqual([1, 2]);
    expect(unwrapped[0]?.["actor_type"]).toBe("server");
    expect(unwrapped[0]?.["actor_key_fingerprint"]).toBe(fpHex);
    expect(unwrapped[0]?.["environment_id"]).toBe(ENV);
  });

  it("records lease_issued once per environment with the derived grant_chain_seq", async () => {
    const { fpHex } = await twoEpochProject();
    const workload = await workloadKeyPair();
    await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });

    const issued = await queryProjectDo(
      projectId,
      "SELECT variable_id, actor_key_fingerprint, payload FROM audit_events WHERE event = 'server.lease_issued'",
    );
    // 環境単位 1 行(変数粒度の選択がない — §3.5)
    expect(issued.length).toBe(1);
    expect(issued[0]?.["variable_id"]).toBeNull();
    expect(issued[0]?.["actor_key_fingerprint"]).toBe(fpHex);
    const payload = JSON.parse(String(issued[0]?.["payload"])) as Record<string, unknown>;
    // grant_chain_seq はチェーン導出の grant_seq(サーバー側で再実装しない)。
    // **値で固定する**: 本 PR で新設した導出値であり、型だけ見ていると誤った
    // seq(再 grant 前の古い seq 等)が載っても素通りする(pullfrog 指摘)
    const granted = await queryProjectDo(
      projectId,
      "SELECT chain_seq FROM audit_events WHERE event = 'chain.server_granted'",
    );
    expect(granted.length).toBe(1);
    expect(payload["grantChainSeq"]).toBe(granted[0]?.["chain_seq"]);
    expect(typeof payload["claimsDigest"]).toBe("string");
    expect(payload["epochs"]).toEqual([1, 2]);
  });

  it("records no var.read for a lease (§14-4)", async () => {
    await twoEpochProject();
    const before = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'var.read'",
    );
    const workload = await workloadKeyPair();
    await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    // var.read は人間 actor の読み取りの証跡であり、ワークロードへの開示は
    // server.* 系が担う(AUDIT_SPEC §3.3 / §14-4)
    const after = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'var.read'",
    );
    expect(after[0]?.["n"]).toBe(before[0]?.["n"]);
  });
});

describe("ワークロードリース: サーバー鍵未設定のデプロイメント(§14-3)", () => {
  // DO は自分の env から keypair を導出する(chain-do.ts)ため、worker へ別 env を
  // 渡しても DO 側は変わらない。ここはプログラム単位で「鍵なしなら**チェーンを
  // 読む前に**落ちる」ことを検査する — 順序が崩れると「未知 = 404 / 実在 = 503」の
  // 差ができ、未認証のリース面がプロジェクトの存在確認に使えてしまう(§11-2)
  it("fails before touching the chain store (順序が存在秘匿を決める)", async () => {
    let chainLoads = 0;
    const chainStore = ChainStore.of({
      load: Effect.sync(() => {
        chainLoads += 1;
        throw new Error("chain must not be read when the server key is unconfigured");
      }),
      insertSync: () => {
        throw new Error("unreachable");
      },
    });
    const outcome = await Effect.runPromise(
      leaseProgram(
        ENV,
        "00".repeat(32),
        {
          issuer: OIDC_ISSUER,
          subject: LEASE_SUBJECT,
          audiences: [LEASE_AUDIENCE],
          claims: {},
          claimsDigestHex: "00".repeat(32),
          bindingKeyHex: "11".repeat(32),
          bindingExpiresAtMs: Date.now() + 300_000,
        },
        { current: null, chain: null },
      ).pipe(
        Effect.match({
          onSuccess: () => ({ ok: true as const }),
          onFailure: (rejection) => ({ ok: false as const, rejection }),
        }),
        // makeServerKey(undefined) = 未設定デプロイメント。DataStore / AuditStore は
        // 到達しないため、この経路では参照されないことも同時に固定される
        Effect.provideService(ServerKey, makeServerKey(undefined)),
        Effect.provideService(ChainStore, chainStore),
        Effect.provideService(DataStore, undefined as never),
        Effect.provideService(AuditStore, undefined as never),
      ),
    );
    expect(outcome).toEqual({
      ok: false,
      rejection: { kind: "unavailable", reason: "server-key-unconfigured" },
    });
    expect(chainLoads).toBe(0);
  });
});

describe("ワークロードリース: 受理ポリシー(§14-3)", () => {
  it("rejects an oversized OIDC token at the schema boundary (400)", async () => {
    const workload = await workloadKeyPair();
    const oversized = `${"a".repeat(20_000)}.${"b".repeat(16)}.${"c".repeat(16)}`;
    const response = await requestLease({
      oidcToken: oversized,
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(400);
  });

  it("rejects a malformed ephemeral public key at the schema boundary (400)", async () => {
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: "not-hex",
    });
    expect(response.status).toBe(400);
  });

  it("returns 429 with retryAfterSeconds once the project window is exhausted", async () => {
    const { dek } = await readyProject();
    expect(dek.length).toBe(32);
    const workload = await workloadKeyPair();
    // 窓を直接埋める(300 回の実リクエストは実行時間に見合わない)。カウンタは
    // DO SQLite の lease_windows 行であり、実装と同じ read-modify-write を通す
    await queryProjectDo(
      projectId,
      "INSERT INTO lease_windows (kind, window_start, count) VALUES ('issued', ?, ?) ON CONFLICT(kind) DO UPDATE SET window_start = excluded.window_start, count = excluded.count",
      Date.now(),
      MAX_LEASES_PER_WINDOW,
    );
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(429);
    const body = (await response.json()) as { retryAfterSeconds: number };
    // 窓は直前に window_start = now で仕込んだので、残りは窓長(1 時間)近傍と
    // 決まっている。> 0 だけだと桁違いの退行を捕まえられない(pullfrog 指摘)
    expect(body.retryAfterSeconds).toBeGreaterThan(3500);
    expect(body.retryAfterSeconds).toBeLessThanOrEqual(3600);
  });

  it("does not consume the window when the lease cannot be issued (503 stays diagnosable)", async () => {
    // 窓を 503 経路で消費すると、バックフィル漏れのプロジェクトの CI が再試行の
    // たびに枠を食い、300 回目以降は「直せる診断」の 503 が無関係な 429 に
    // 化ける(pullfrog 指摘)。消費は実際に発行したときだけ
    await createEnvironmentOk(fixture, ENV, "App");
    await grantServer({ scope: [ENV] }); // バックフィルしない = server-wraps-missing
    const workload = await workloadKeyPair();
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const response = await requestLease({
        oidcToken: await makeOidcToken(),
        ephemeralPubHex: workload.publicKeyHex,
      });
      expect(response.status).toBe(503);
    }
    const rows = await queryProjectDo(
      projectId,
      "SELECT count FROM lease_windows WHERE kind = 'issued'",
    );
    expect(rows.length).toBe(0);
  });

  it("consumes exactly one window slot per issued lease", async () => {
    await readyProject();
    const workload = await workloadKeyPair();
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const response = await requestLease({
        oidcToken: await makeOidcToken(),
        ephemeralPubHex: workload.publicKeyHex,
      });
      expect(response.status).toBe(200);
    }
    const rows = await queryProjectDo(
      projectId,
      "SELECT count FROM lease_windows WHERE kind = 'issued'",
    );
    expect(rows[0]?.["count"]).toBe(2);
  });

  it("does not let an unauthorized caller consume the project's lease window", async () => {
    // ポリシー不一致(404)は発行の窓を消費しない — 消費すると第三者が
    // 正当なワークロードのリースを枯らせてしまう
    await createEnvironmentOk(fixture, ENV, "App");
    await grantServer({ scope: [ENV], leasePolicy: [] });
    const workload = await workloadKeyPair();
    await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    const rows = await queryProjectDo(
      projectId,
      "SELECT count FROM lease_windows WHERE kind = 'issued'",
    );
    expect(rows.length).toBe(0);
  });
});
