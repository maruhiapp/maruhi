// ワークロードリース API(AUTH_SPEC §14 = CRYPTO_SPEC §9.1)の統合テスト —
// 発行(§14-2)と OIDC 検証段(§14-1 の 401)。
// vitest-pool-workers(workerd 実環境)で SELF 経由の HttpApi と DO SQLite を検証する。
//
// リース系スイートの分担(共有ヘルパは support/lease-scenario.ts。分割の動機は
// support/membership-scenario.ts 冒頭を参照):
// - lease.test.ts(本ファイル): 発行と OIDC 検証。リースラップが info に
//   claims_digest を束縛し、別ワークロード文脈では開けないこと(CRYPTO_SPEC
//   §9.1)。応答に平文値・DEK が現れないこと
// - lease-authz.test.ts: 認可と存在秘匿(§14-1 / §11-2 — 一律 404)
// - lease-policy.test.ts: 503 と監査(§14-3 / AUDIT_SPEC §3.5)・サーバー鍵
//   未設定・受理ポリシー
// - lease-binding.test.ts: 先着束縛(§14-1)と発信元 IP レート制限(deepsec M5)

import { decryptVariable, encodeHex } from "@maruhi/crypto";
import { beforeEach, describe, expect, it } from "vitest";

import { hexBytes } from "./support/data-crypto.ts";
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
import type { LeaseBody } from "./support/lease-scenario.ts";
import {
  backfillServerWrap,
  claimsDigestOf,
  grantServer,
  openLease,
  readyProject,
  requestLease,
  requireFirst,
  workloadKeyPair,
} from "./support/lease-scenario.ts";
import { LEASE_AUDIENCE, makeOidcToken } from "./support/lease.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

describe("ワークロードリース: 発行(AUTH_SPEC §14-2 / CRYPTO_SPEC §9.1)", () => {
  it("issues a lease the workload can open with the same epoch DEK (the server never decrypts a value)", async () => {
    const { dek } = await readyProject();
    const workload = await workloadKeyPair();
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as LeaseBody;

    // 応答はチェーンを同梱する(非メンバーはチェーン API から 404 — §11-2)。
    // 長さはフィクスチャから正確に決まるので値で固定する(pullfrog 指摘)
    const stored = await queryProjectDo(projectId, "SELECT COUNT(*) AS n FROM chain_entries");
    expect(body.chain.length).toBe(stored[0]?.["n"]);
    expect(body.headSeq).toBe(body.chain.length);
    expect(body.currentEpoch).toBe(1);

    // 最新の環境マニフェスト + issuer 情報を同梱する(§14-2 — ワークロードの
    // 検証義務 §9.1 (5) の材料。2026-08-18)
    expect(
      (body as { manifest?: { manifestVersion: number; epoch: number; issuerUserId: string } })
        .manifest,
    ).toMatchObject({ manifestVersion: 2, epoch: 1 });

    // リースラップは登録署名も署名者情報も持たない(サーバー生成・応答スコープ
    // であり、チェーン上の署名者が存在しえない — §9.1)
    expect(body.leases.length).toBe(1);
    const lease = requireFirst(body.leases, "lease");
    expect(Object.keys(lease).toSorted()).toEqual(["ciphertextHex", "encHex", "epoch", "suite"]);

    const opened = await openLease({
      lease,
      workloadKeyPair: workload.pair,
      claimsDigestHex: await claimsDigestOf(),
    });
    expect(opened.ok).toBe(true);
    // リースした DEK は元のエポック DEK そのもの(サーバーは仲介しただけ)
    expect(opened.ok && encodeHex(opened.value)).toBe(encodeHex(dek));
  });

  it("bundles the stored checkpoint-time value snapshot (§14-2 — PR-M3)", async () => {
    await readyProject();
    const workload = await workloadKeyPair();
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as LeaseBody & {
      readonly checkpointSnapshot?: {
        readonly chainSeq: number;
        readonly entryHashHex: string;
        readonly values: readonly unknown[];
      };
    };
    // 供給源は checkpoint 受理時の保存行そのもの(§16-2 — 環境作成の境界
    // checkpoint が誕生時からの基準。作成後の変数はその列挙に含まれない)
    const stored = await queryProjectDo(
      projectId,
      "SELECT chain_seq, entry_hash_hex FROM environment_checkpoints WHERE environment_id = ?",
      ENV,
    );
    expect(body.checkpointSnapshot).toBeDefined();
    expect(body.checkpointSnapshot?.chainSeq).toBe(stored[0]?.["chain_seq"]);
    expect(body.checkpointSnapshot?.entryHashHex).toBe(stored[0]?.["entry_hash_hex"]);
    expect(body.checkpointSnapshot?.values).toEqual([]);
  });

  it("returns values as ciphertext the workload decrypts with the leased DEK", async () => {
    await readyProject();
    const workload = await workloadKeyPair();
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    const body = (await response.json()) as LeaseBody;
    const opened = await openLease({
      lease: requireFirst(body.leases, "lease"),
      workloadKeyPair: workload.pair,
      claimsDigestHex: await claimsDigestOf(),
    });
    if (!opened.ok) {
      throw new Error("lease unwrap failed");
    }
    const variable = requireFirst(body.variables, "variable");
    expect(variable.variableId).toBe(VAR);
    const plaintext = await decryptVariable({
      dek: opened.value,
      nonce: hexBytes(variable.value.nonceHex),
      ciphertext: hexBytes(variable.value.ciphertextHex),
      context: { projectId, environmentId: ENV, epoch: 1, variableId: VAR, version: 1 },
    });
    expect(plaintext.ok && new TextDecoder().decode(plaintext.value)).toBe("postgres://alpha");
  });

  it("binds the lease to the workload context: another job's claims_digest cannot open it", async () => {
    await readyProject();
    const workload = await workloadKeyPair();
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    const body = (await response.json()) as LeaseBody;
    const opened = await openLease({
      lease: requireFirst(body.leases, "lease"),
      workloadKeyPair: workload.pair,
      // 同一 issuer / audience の別 subject(別ブランチ)= 別ワークロード文脈
      claimsDigestHex: await claimsDigestOf("repo:maruhi-test/demo:ref:refs/heads/feature-x"),
    });
    expect(opened.ok).toBe(false);
  });

  it("leases every epoch the response's latest values use, plus the current epoch (§14-2)", async () => {
    // epoch 1 に値を作り、rotate で epoch 2 へ。値は未再暗号化のまま epoch 1
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek1, VAR, "DATABASE_URL", "postgres://alpha");
    const dek2 = await rotateEnvironmentOk(fixture, MEMBER, ENV, 2);
    await grantServer({ scope: [ENV] });
    await backfillServerWrap(1, dek1);
    await backfillServerWrap(2, dek2);

    const workload = await workloadKeyPair();
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as LeaseBody;
    expect(body.leases.map((lease) => lease.epoch).toSorted()).toEqual([1, 2]);
  });
});

describe("ワークロードリース: OIDC 検証(§14-1 の認証段 — 401)", () => {
  beforeEach(async () => {
    await readyProject();
  });

  const cases: readonly {
    readonly name: string;
    readonly token: () => Promise<string>;
    readonly reason: string;
  }[] = [
    {
      name: "unsupported issuer",
      token: () => makeOidcToken({ issuer: "https://evil.example" }),
      reason: "unsupported-issuer",
    },
    {
      name: "unsupported alg (header says RS256 but the key is EC)",
      token: () => makeOidcToken({ alg: "RS256" }),
      reason: "unsupported-alg",
    },
    {
      name: "unknown kid",
      token: () => makeOidcToken({ kid: "rotated-away" }),
      reason: "unknown-key",
    },
    {
      name: "tampered signature",
      token: () => makeOidcToken({ tamperSignature: true }),
      reason: "signature-invalid",
    },
    {
      name: "expired token",
      token: () => makeOidcToken({ expSeconds: Math.floor(Date.now() / 1000) - 600 }),
      reason: "token-expired",
    },
    {
      name: "iat in the future beyond the skew",
      token: () => makeOidcToken({ iatSeconds: Math.floor(Date.now() / 1000) + 600 }),
      reason: "token-not-yet-valid",
    },
    {
      name: "missing exp",
      token: () => makeOidcToken({ omit: ["exp"] }),
      reason: "missing-claim",
    },
  ];

  for (const testCase of cases) {
    it(`rejects ${testCase.name} with 401 ${testCase.reason}`, async () => {
      const workload = await workloadKeyPair();
      const response = await requestLease({
        oidcToken: await testCase.token(),
        ephemeralPubHex: workload.publicKeyHex,
      });
      expect(response.status).toBe(401);
      expect(await response.json()).toMatchObject({ reason: testCase.reason });
    });
  }

  it("rejects a multi-audience token with ambiguous-audience, not missing-claim", async () => {
    // `aud` は存在する(複数あるだけ)。運用者が理由コードを頼りに存在する
    // claim を探しに行かないよう別語彙にしてある(pullfrog 指摘)
    const workload = await workloadKeyPair();
    const response = await requestLease({
      oidcToken: await makeOidcToken({ audience: [LEASE_AUDIENCE, "https://other.example"] }),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ reason: "ambiguous-audience" });
  });

  it("records no lease_denied for tokens that fail signature verification (AUDIT_SPEC §3.5)", async () => {
    const workload = await workloadKeyPair();
    await requestLease({
      oidcToken: await makeOidcToken({ tamperSignature: true }),
      ephemeralPubHex: workload.publicKeyHex,
    });
    const rows = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'server.lease_denied'",
    );
    expect(rows[0]?.["n"]).toBe(0);
  });

  it("rejects a token whose alg is outside the allowlist even with a valid signature", async () => {
    // `none` は Schema の compact JWS 形(3 セグメント)を満たしたうえで
    // alg 許可リストで落ちる — ヘッダーの alg を信じる実装はここで割れる
    const workload = await workloadKeyPair();
    const response = await requestLease({
      oidcToken: await makeOidcToken({ alg: "none" }),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ reason: "unsupported-alg" });
  });
});
