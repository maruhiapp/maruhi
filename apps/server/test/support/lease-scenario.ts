// ワークロードリース統合テストの共有ヘルパ(旧 lease.test.ts の冒頭ヘルパの
// 分割先 — 分割の動機は membership-scenario.ts 冒頭を参照)。
//
// data-scenario.ts の fixture(registerDataScenario)を前提とする: 各テスト
// ファイルは registerDataScenario() を呼んでから describe を書き、ここの
// ヘルパは data-scenario の live binding(fixture)を参照する。

import type { LeasedDek } from "@maruhi/api-schema";
import {
  computeLeaseClaimsDigest,
  encodeHex,
  exportEncryptionPublicKey,
  generateEncryptionKeyPair,
  unwrapLeaseDek,
} from "@maruhi/crypto";
import { SELF } from "cloudflare:test";
import { expect } from "vitest";

import { JSON_HEADERS } from "./auth.ts";
import { hexBytes, wrapDekToServer } from "./data-crypto.ts";
import {
  appendOperation,
  createEnvironmentOk,
  OWNER,
  projectId,
  requestJson,
} from "./data-fixture.ts";
import { createVariableOk, ENV, fixture, token, VAR } from "./data-scenario.ts";
import { deploymentKey, LEASE_AUDIENCE, LEASE_SUBJECT } from "./lease.ts";
import { OIDC_ISSUER } from "./oidc-issuer.ts";

/** ワークロードの一時鍵(ジョブごとにメモリ内生成される想定 — §9.1)。 */
export async function workloadKeyPair() {
  const pair = await generateEncryptionKeyPair();
  const publicKey = await exportEncryptionPublicKey(pair.publicKey);
  return { pair, publicKeyHex: encodeHex(publicKey) };
}

/** 既定のリースポリシー(issuer / audience 一致 + sub の完全一致制約 1 件)。 */
export function defaultPolicy(subject = LEASE_SUBJECT) {
  return [
    {
      issuerUrl: OIDC_ISSUER,
      audience: LEASE_AUDIENCE,
      claimConstraints: [{ claimName: "sub", claimValue: subject }],
    },
  ];
}

export type LeasePolicy = ReturnType<typeof defaultPolicy>;

/** owner が grant_server を追記する(実導出のデプロイメント鍵宛)。 */
export async function grantServer(input: {
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
export async function backfillServerWrap(
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

export interface LeaseBody {
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

export async function requestLease(input: {
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
export async function readyProject(): Promise<{ readonly dek: Uint8Array }> {
  const dek = await createEnvironmentOk(fixture, ENV, "App");
  await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
  await grantServer({ scope: [ENV] });
  await backfillServerWrap(1, dek);
  return { dek };
}

/** 応答から必須要素を取り出す(以降のアサーションから optional 連鎖を排する)。 */
export function requireFirst<T>(items: readonly T[], what: string): T {
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
export function malleateSignatureSegment(compactJws: string): string {
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
export async function claimsDigestOf(subject = LEASE_SUBJECT): Promise<string> {
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
export async function openLease(input: {
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
