// ワークロードリース API(AUTH_SPEC §14 = CRYPTO_SPEC §9.1)の統合テスト。
// vitest-pool-workers(workerd 実環境)で SELF 経由の HttpApi と DO SQLite を検証する。
//
// このスイートが固定するもの:
// - 判定順(§14-3): OIDC 検証(401)→ ポリシー / スコープ(一律 404)→
//   先着束縛(401 token-replayed)→ 環境存在(404)→ レート制限(429)→
//   サーバー宛ラップの存在(503 server-wraps-missing)
// - 先着束縛(§14-1 — 2026-08-15 裁定): 同一トークン + 別鍵の拒否・同一鍵の
//   冪等リトライ・保持期間と時刻検証の受理窓の整合・期限切れ束縛の GC
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
import { OIDC_CLOCK_SKEW_MS } from "../src/oidc.package/index.ts";
import { LEASE_BINDING_RETENTION_MARGIN_MS, MAX_LEASES_PER_WINDOW } from "../src/policy.ts";
import { leaseProgram } from "../src/programs-lease.ts";
import { makeServerKey, ServerKey } from "../src/server-key.ts";
import { JSON_HEADERS } from "./support/auth.ts";
import { hexBytes, wrapDekToServer } from "./support/data-crypto.ts";
import {
  appendOperation,
  createEnvironmentOk,
  deleteEnvironmentRequest,
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
async function backfillServerWrap(
  epoch: number,
  dek: Uint8Array,
  environmentId: string = ENV,
): Promise<void> {
  const key = await deploymentKey();
  const wrap = await wrapDekToServer({
    projectId,
    environmentId,
    epoch,
    dek,
    serverKeyFingerprintHex: key.fingerprintHex,
    serverEncPubHex: key.encPubHex,
    signerUserId: OWNER,
  });
  const response = await requestJson("POST", `/environments/${environmentId}/deks`, token(OWNER), {
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

/** サーバーの decodeBase64Url と同じ寛容デコード(atob 経由)で得る binary string。 */
function decodeBase64UrlToBinary(segment: string): string {
  const padded = segment
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(segment.length + ((4 - (segment.length % 4)) % 4), "=");
  return atob(padded);
}

/**
 * 署名セグメントの末尾 1 文字を「サーバーと同じ寛容デコードで同一バイト列に
 * なる別文字」へ差し替える(base64url 末尾グループの未使用ビットの可鍛性)。
 * 変異トークンは署名対象(header.payload)も署名バイト列も変えないため署名検証を
 * 通過するが、生文字列としては別物になる。先着束縛が生トークンをハッシュして
 * いた場合に破れることを示すための攻撃者操作の再現。
 */
function malleateSignatureSegment(compactJws: string): string {
  const parts = compactJws.split(".");
  const [header, payload, sig] = parts;
  if (parts.length !== 3 || header === undefined || payload === undefined || sig === undefined) {
    throw new Error("not a compact JWS");
  }
  const target = decodeBase64UrlToBinary(sig);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const lastIndex = sig.length - 1;
  for (const candidate of alphabet) {
    if (candidate === sig[lastIndex]) {
      continue;
    }
    const mutated = sig.slice(0, lastIndex) + candidate;
    if (decodeBase64UrlToBinary(mutated) === target) {
      return `${header}.${payload}.${mutated}`;
    }
  }
  throw new Error("no byte-identical alternative for the final signature character");
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
  });
});
