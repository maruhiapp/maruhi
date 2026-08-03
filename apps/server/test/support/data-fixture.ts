// データプレーン統合テストの共通フィクスチャ(workerd 内で実行)。
//
// ベース構成: テスト時署名の 3 エントリチェーン(owner / member / reader)を
// API 経由で再生し、各ユーザーの実 PAT を取得する。チェーンの延長
// (rotate_epoch / add_member)もすべて API 経由で行う。

import type { ChainOperation } from "@maruhi/crypto";
import { SELF } from "cloudflare:test";
import { expect } from "vitest";

import {
  BASE,
  bearer,
  deviceToken,
  JSON_HEADERS,
  resetAuthDb,
  seedOrgMember,
  seedUser,
} from "./auth.ts";
import type { WireWrappedDek } from "./data-crypto.ts";
import {
  addMemberOperation,
  buildChain,
  genesisOperation,
  makeDek,
  signEntryAt,
  wrapDekForAll,
} from "./data-crypto.ts";
import { resetProjectDo } from "./project-do.ts";

export const OWNER = "user-owner-0001";
export const MEMBER = "user-member-0002";
export const READER = "user-admin-0003";
export const STRANGER = "user-stranger-0009";
const DATA_ORG = "org-data-0001";

const GITHUB_IDS: Record<string, number> = {
  [OWNER]: 9001,
  [MEMBER]: 9002,
  [READER]: 9003,
  [STRANGER]: 9009,
};

/** ベースチェーン: genesis(owner)→ add_member(member)→ add_member(reader)。 */
const baseChain = await buildChain([
  { actorUserId: OWNER, operation: genesisOperation(OWNER) },
  { actorUserId: OWNER, operation: addMemberOperation(MEMBER, "member") },
  { actorUserId: OWNER, operation: addMemberOperation(READER, "reader") },
]);

export const projectId = baseChain.projectId;

/** 全メンバー(DEK ラップの完全集合の既定受信者)。 */
export const ALL_MEMBERS = [OWNER, MEMBER, READER] as const;

export interface DataFixture {
  readonly tokens: Record<string, string>;
  /** チェーンの現ヘッド(appendOperation が進める)。 */
  head: { seq: number; hashHex: string };
}

/** DO / D1 のリセット + ユーザー・PAT のシード + ベースチェーンの API 再生。 */
export async function setupDataProject(): Promise<DataFixture> {
  await resetProjectDo(projectId);
  await resetAuthDb();
  const tokens: Record<string, string> = {};
  for (const [userId, githubId] of Object.entries(GITHUB_IDS)) {
    await seedUser(userId, githubId);
    tokens[userId] = await deviceToken(githubId);
  }
  await seedOrgMember(DATA_ORG, OWNER, "member");

  const [genesis, ...rest] = baseChain.entries;
  const init = await SELF.fetch(`${BASE}/projects`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...bearer(tokenOf(tokens, OWNER)) },
    body: JSON.stringify({ orgId: DATA_ORG, entry: genesis }),
  });
  expect(init.status).toBe(200);
  let prevHash = baseChain.hashes[0] ?? "";
  for (const [index, entry] of rest.entries()) {
    const response = await SELF.fetch(`${BASE}/projects/${projectId}/chain/entries`, {
      method: "POST",
      headers: { ...JSON_HEADERS, ...bearer(tokenOf(tokens, entry.actor.userId)) },
      body: JSON.stringify({ parentHeadHashHex: prevHash, entry }),
    });
    expect(response.status).toBe(200);
    prevHash = baseChain.hashes[index + 1] ?? "";
  }
  return {
    tokens,
    head: { seq: baseChain.entries.length, hashHex: prevHash },
  };
}

export function tokenOf(tokens: Record<string, string>, userId: string): string {
  const token = tokens[userId];
  if (token === undefined) {
    throw new Error(`no token for ${userId}`);
  }
  return token;
}

/** チェーンへ 1 エントリをテスト時署名 + API 追記で足し、fixture のヘッドを進める。 */
export async function appendOperation(
  fixture: DataFixture,
  actorUserId: string,
  operation: ChainOperation,
): Promise<void> {
  const { entry, hash } = await signEntryAt({
    seq: fixture.head.seq + 1,
    prevHashHex: fixture.head.hashHex,
    actorUserId,
    operation,
  });
  const response = await SELF.fetch(`${BASE}/projects/${projectId}/chain/entries`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...bearer(tokenOf(fixture.tokens, actorUserId)) },
    body: JSON.stringify({ parentHeadHashHex: fixture.head.hashHex, entry }),
  });
  expect(response.status).toBe(200);
  fixture.head = { seq: entry.seq, hashHex: hash };
}

// ---------------------------------------------------------------------------
// データプレーン API の小さなラッパ
// ---------------------------------------------------------------------------

export const dataUrl = (path: string): string => `${BASE}/projects/${projectId}${path}`;

export function requestJson(
  method: string,
  path: string,
  token: string,
  body?: unknown,
): Promise<Response> {
  return SELF.fetch(dataUrl(path), {
    method,
    headers: { ...JSON_HEADERS, ...bearer(token) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

/** 環境作成(エポック 1 の完全ラップ集合を実 crypto で同梱)。DEK を返す。 */
export async function createEnvironmentOk(
  fixture: DataFixture,
  environmentId: string,
  name: string,
): Promise<Uint8Array> {
  const dek = makeDek();
  const deks = await wrapDekForAll({
    projectId,
    environmentId,
    epoch: 1,
    dek,
    recipientUserIds: ALL_MEMBERS,
    signerUserId: OWNER,
  });
  const response = await requestJson("POST", "/environments", tokenOf(fixture.tokens, OWNER), {
    environmentId,
    name,
    deks,
  });
  expect(response.status).toBe(200);
  return dek;
}

/** 環境作成リクエストを任意のラップ集合で送る(negative テスト用)。 */
export function createEnvironmentWith(
  fixture: DataFixture,
  environmentId: string,
  name: string,
  deks: readonly WireWrappedDek[],
): Promise<Response> {
  return requestJson("POST", "/environments", tokenOf(fixture.tokens, OWNER), {
    environmentId,
    name,
    deks,
  });
}
