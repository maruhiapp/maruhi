// ワークロードリース API(AUTH_SPEC §14 = CRYPTO_SPEC §9.1)の統合テスト。
// vitest-pool-workers(workerd 実環境)で SELF 経由の HttpApi と DO SQLite を検証する。
//
// このスイートが固定するもの:
// - 判定順(§14-3): OIDC 検証(401)→ ポリシー / スコープ(一律 404)→
//   レート制限(429)→ サーバー宛ラップの存在(503 server-wraps-missing)
// - 存在秘匿(§14-1): grant なし・ポリシー不一致・スコープ外・環境なし・
//   未初期化プロジェクトが**すべて同じ 404** であること(理由が漏れない)
// - リースラップは info に claims_digest を束縛し、別ワークロード文脈では
//   開けないこと(CRYPTO_SPEC §9.1)。応答に平文値・DEK が現れないこと
// - 監査(AUDIT_SPEC §3.5): server.dek_unwrapped / server.lease_issued /
//   server.lease_denied の粒度と、var.read を**記録しない**こと

import type { LeasedDek } from "@maruhi/api-schema";
import {
  computeLeaseClaimsDigest,
  decryptVariable,
  generateEncryptionKeyPair,
  exportEncryptionPublicKey,
  encodeHex,
  unwrapLeaseDek,
} from "@maruhi/crypto";
import { SELF } from "cloudflare:test";
import { Effect } from "effect";
import { beforeEach, describe, expect, it } from "vitest";

import { AuditStore } from "../src/audit-store.ts";
import { ChainStore } from "../src/chain-store.ts";
import { DataStore } from "../src/data-store.ts";
import { MAX_LEASES_PER_WINDOW } from "../src/policy.ts";
import { leaseProgram } from "../src/programs-lease.ts";
import { makeServerKey, ServerKey } from "../src/server-key.ts";
import { JSON_HEADERS } from "./support/auth.ts";
import { hexBytes, wrapDekToServer } from "./support/data-crypto.ts";
import {
  appendOperation,
  createEnvironmentOk,
  OWNER,
  projectId,
  requestJson,
  rotateEnvironmentOk,
  MEMBER,
} from "./support/data-fixture.ts";
import {
  createVariableOk,
  ENV,
  fixture,
  registerDataScenario,
  token,
  VAR,
} from "./support/data-scenario.ts";
import { deploymentKey, LEASE_AUDIENCE, LEASE_SUBJECT, makeOidcToken } from "./support/lease.ts";
import { OIDC_ISSUER } from "./support/oidc-issuer.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

/** ワークロードの一時鍵(ジョブごとにメモリ内生成される想定 — §9.1)。 */
async function workloadKeyPair() {
  const pair = await generateEncryptionKeyPair();
  const publicKey = await exportEncryptionPublicKey(pair.publicKey);
  return { pair, publicKeyHex: encodeHex(publicKey) };
}

/** 既定のリースポリシー(issuer / audience 一致 + sub の完全一致制約 1 件)。 */
function defaultPolicy(subject = LEASE_SUBJECT) {
  return [
    {
      issuerUrl: OIDC_ISSUER,
      audience: LEASE_AUDIENCE,
      claimConstraints: [{ claimName: "sub", claimValue: subject }],
    },
  ];
}

type LeasePolicy = ReturnType<typeof defaultPolicy>;

/** owner が grant_server を追記する(実導出のデプロイメント鍵宛)。 */
async function grantServer(input: {
  readonly scope: readonly string[];
  readonly leasePolicy?: LeasePolicy;
}): Promise<string> {
  const key = await deploymentKey();
  await appendOperation(fixture, OWNER, {
    op: "grant_server",
    payload: {
      serverEncPubHex: key.encPubHex,
      serverKeyFingerprintHex: key.fingerprintHex,
      scopeEnvironmentIds: input.scope,
      leasePolicy: input.leasePolicy ?? defaultPolicy(),
    },
  });
  return key.fingerprintHex;
}

/** owner がサーバー宛ラップをバックフィルする(§12-6 の grant 直後経路)。 */
async function backfillServerWrap(epoch: number, dek: Uint8Array): Promise<void> {
  const key = await deploymentKey();
  const wrap = await wrapDekToServer({
    projectId,
    environmentId: ENV,
    epoch,
    dek,
    serverKeyFingerprintHex: key.fingerprintHex,
    serverEncPubHex: key.encPubHex,
    signerUserId: OWNER,
  });
  const response = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
    deks: [wrap],
  });
  expect(response.status).toBe(204);
}

interface LeaseBody {
  readonly projectId: string;
  readonly environmentId: string;
  readonly currentEpoch: number;
  readonly chain: readonly unknown[];
  readonly headSeq: number;
  readonly headHashHex: string;
  readonly variables: readonly {
    readonly variableId: string;
    readonly value: {
      readonly nonceHex: string;
      readonly ciphertextHex: string;
      readonly aad: unknown;
    };
  }[];
  readonly leases: readonly LeasedDek[];
}

async function requestLease(input: {
  readonly oidcToken: string;
  readonly ephemeralPubHex: string;
  readonly environmentId?: string;
  readonly project?: string;
}): Promise<Response> {
  const target = input.project ?? projectId;
  return SELF.fetch(
    `https://maruhi.test/projects/${target}/environments/${input.environmentId ?? ENV}/lease`,
    {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({
        oidcToken: input.oidcToken,
        ephemeralPubHex: input.ephemeralPubHex,
      }),
    },
  );
}

/** grant + バックフィル + 変数 1 本まで整えた「リース可能な状態」を作る。 */
async function readyProject(): Promise<{ readonly dek: Uint8Array }> {
  const dek = await createEnvironmentOk(fixture, ENV, "App");
  await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
  await grantServer({ scope: [ENV] });
  await backfillServerWrap(1, dek);
  return { dek };
}

/** 応答から必須要素を取り出す(以降のアサーションから optional 連鎖を排する)。 */
function requireFirst<T>(items: readonly T[], what: string): T {
  const first = items[0];
  if (first === undefined) {
    throw new Error(`lease response has no ${what}`);
  }
  return first;
}

/** ワークロード側の claims_digest を計算する(サーバーと独立の再計算 — §9.1)。 */
async function claimsDigestOf(subject = LEASE_SUBJECT): Promise<string> {
  const digest = await computeLeaseClaimsDigest({
    issuerUrl: OIDC_ISSUER,
    subject,
    audience: LEASE_AUDIENCE,
  });
  if (!digest.ok) {
    throw new Error("claims digest computation failed");
  }
  return digest.value;
}

/** リースラップを一時鍵で開く(§9.1 の受信側手順)。 */
async function openLease(input: {
  readonly lease: LeasedDek;
  readonly workloadKeyPair: Awaited<ReturnType<typeof workloadKeyPair>>["pair"];
  readonly claimsDigestHex: string;
}) {
  return unwrapLeaseDek({
    workloadKeyPair: input.workloadKeyPair,
    wrapped: {
      enc: hexBytes(input.lease.encHex),
      ciphertext: hexBytes(input.lease.ciphertextHex),
    },
    context: {
      projectId,
      environmentId: ENV,
      epoch: input.lease.epoch,
      claimsDigestHex: input.claimsDigestHex,
    },
  });
}

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

    // 応答はチェーンを同梱する(非メンバーはチェーン API から 404 — §11-2)
    expect(body.chain.length).toBeGreaterThan(0);
    expect(body.headSeq).toBeGreaterThan(0);
    expect(body.currentEpoch).toBe(1);

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

describe("ワークロードリース: 認可と存在秘匿(§14-1 / §11-2 — 一律 404)", () => {
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

  it("hides a project with no server grant", async () => {
    await expect404({ skipGrant: true });
  });

  it("hides an empty lease policy (grant allows wrap registration only — CRYPTO_SPEC §6.2)", async () => {
    await expect404({ leasePolicy: [] });
  });

  it("hides an issuer mismatch in the policy", async () => {
    await expect404({
      leasePolicy: [
        {
          issuerUrl: "https://gitlab.example",
          audience: LEASE_AUDIENCE,
          claimConstraints: [],
        },
      ],
    });
  });

  it("hides an audience mismatch in the policy", async () => {
    await expect404({
      leasePolicy: [
        { issuerUrl: OIDC_ISSUER, audience: "https://other.example", claimConstraints: [] },
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

  it("records dek_unwrapped per epoch and lease_issued once per environment, and no var.read", async () => {
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek1, VAR, "DATABASE_URL", "postgres://alpha");
    const dek2 = await rotateEnvironmentOk(fixture, MEMBER, ENV, 2);
    const fpHex = await grantServer({ scope: [ENV] });
    await backfillServerWrap(1, dek1);
    await backfillServerWrap(2, dek2);
    const readsBefore = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'var.read'",
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

    const unwrapped = await queryProjectDo(
      projectId,
      "SELECT epoch, actor_type, actor_key_fingerprint, environment_id FROM audit_events WHERE event = 'server.dek_unwrapped' ORDER BY epoch",
    );
    expect(unwrapped.map((row) => row["epoch"])).toEqual([1, 2]);
    expect(unwrapped[0]?.["actor_type"]).toBe("server");
    expect(unwrapped[0]?.["actor_key_fingerprint"]).toBe(fpHex);
    expect(unwrapped[0]?.["environment_id"]).toBe(ENV);

    const issued = await queryProjectDo(
      projectId,
      "SELECT environment_id, variable_id, actor_key_fingerprint, payload FROM audit_events WHERE event = 'server.lease_issued'",
    );
    // 環境単位 1 行(変数粒度の選択がない — §3.5)
    expect(issued.length).toBe(1);
    expect(issued[0]?.["variable_id"]).toBeNull();
    expect(issued[0]?.["actor_key_fingerprint"]).toBe(fpHex);
    const payload = JSON.parse(String(issued[0]?.["payload"])) as Record<string, unknown>;
    // grant_chain_seq はチェーン導出の grant_seq(サーバー側で再実装しない)
    expect(typeof payload["grantChainSeq"]).toBe("number");
    expect(typeof payload["claimsDigest"]).toBe("string");
    expect(payload["epochs"]).toEqual([1, 2]);

    // var.read は増えない(人間 actor の読み取りの証跡 — §14-4 / AUDIT_SPEC §3.3)
    const readsAfter = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'var.read'",
    );
    expect(readsAfter[0]?.["n"]).toBe(readsBefore[0]?.["n"]);
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
    expect(body.retryAfterSeconds).toBeGreaterThan(0);
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
