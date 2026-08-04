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
import type { WireEnvironmentMetaStatement, WireWrappedDek } from "./data-crypto.ts";
import {
  addMemberOperation,
  buildChain,
  commitmentOf,
  createEnvironmentOperation,
  genesisOperation,
  makeDek,
  metaSignedBytesHashOf,
  rotateEpochOperation,
  signEntryAt,
  signMetaStatementAs,
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
  /**
   * 環境ごとの最新ステートメント + author(rename / 削除の prev 連鎖の材料 —
   * 受理成功時に helper が進める)。
   */
  readonly envStatements: Map<
    string,
    { statement: WireEnvironmentMetaStatement; authorUserId: string }
  >;
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
    envStatements: new Map(),
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

/** 複合結果(§12-4)からヘッドを進める。 */
function advanceHead(fixture: DataFixture, body: { headSeq: number; headHashHex: string }): void {
  fixture.head = { seq: body.headSeq, hashHex: body.headHashHex };
}

/**
 * 環境作成の複合同梱ステートメント(metaVersion 1)をテスト時署名で作る。
 * 宣言ヘッドは追記前の現ヘッド(= 同梱エントリの prev — §12-4)。
 */
export async function createEnvironmentStatement(input: {
  readonly authorUserId: string;
  readonly environmentId: string;
  readonly name: string;
  readonly head: { readonly seq: number; readonly hashHex: string };
}): Promise<WireEnvironmentMetaStatement> {
  return signMetaStatementAs(input.authorUserId, projectId, {
    suite: "maruhi/v1",
    environmentId: input.environmentId,
    name: input.name,
    status: "active" as const,
    metaVersion: 1,
    prevMetaSigHashHex: "",
    chainHeadHashHex: input.head.hashHex,
    chainHeadSeq: input.head.seq,
  });
}

/**
 * 複合の環境作成リクエスト(§12-4)を組み立てて送る: create_environment
 * エントリ(コミットメント込み)+ EnvironmentMetaStatement(metaVersion 1。
 * 宣言ヘッド = 追記前の現ヘッド)をテスト時署名し、親ヘッド CAS 付きで
 * ラップ集合と同時に POST する。200 ならフィクスチャのヘッドを進める。
 */
export async function createEnvironmentComposite(
  fixture: DataFixture,
  input: {
    readonly environmentId: string;
    readonly name: string;
    readonly deks: readonly WireWrappedDek[];
    readonly dekCommitmentHex: string;
    readonly actorUserId?: string;
    /** CAS 失敗テスト用の親ヘッド上書き。 */
    readonly parentHeadHashHex?: string;
    /** 複合内整合の negative 用のステートメント上書き。 */
    readonly statement?: WireEnvironmentMetaStatement;
  },
): Promise<Response> {
  const actorUserId = input.actorUserId ?? OWNER;
  const { entry } = await signEntryAt({
    seq: fixture.head.seq + 1,
    prevHashHex: input.parentHeadHashHex ?? fixture.head.hashHex,
    actorUserId,
    operation: createEnvironmentOperation(input.environmentId, input.dekCommitmentHex),
  });
  const statement =
    input.statement ??
    (await createEnvironmentStatement({
      authorUserId: actorUserId,
      environmentId: input.environmentId,
      name: input.name,
      head: {
        seq: fixture.head.seq,
        hashHex: input.parentHeadHashHex ?? fixture.head.hashHex,
      },
    }));
  const response = await requestJson(
    "POST",
    "/environments",
    tokenOf(fixture.tokens, actorUserId),
    {
      parentHeadHashHex: input.parentHeadHashHex ?? fixture.head.hashHex,
      entry,
      statement,
      deks: input.deks,
    },
  );
  if (response.status === 200) {
    advanceHead(
      fixture,
      (await response.clone().json()) as { headSeq: number; headHashHex: string },
    );
    fixture.envStatements.set(input.environmentId, { statement, authorUserId: actorUserId });
  }
  return response;
}

/**
 * 環境の次ステートメント(rename / 削除)をテスト時署名で作る: prev = 記録済み
 * 最新ステートメントの signed_bytes ハッシュ、metaVersion = 最新 + 1、宣言
 * ヘッド = 現ヘッド。
 */
async function nextEnvironmentStatement(
  fixture: DataFixture,
  input: {
    readonly environmentId: string;
    readonly name: string;
    readonly status: "active" | "deleted";
    readonly authorUserId: string;
  },
): Promise<WireEnvironmentMetaStatement> {
  const last = fixture.envStatements.get(input.environmentId);
  if (last === undefined) {
    throw new Error(`no recorded statement for environment ${input.environmentId}`);
  }
  const prevMetaSigHashHex = await metaSignedBytesHashOf(
    projectId,
    last.statement,
    last.authorUserId,
  );
  return signMetaStatementAs(input.authorUserId, projectId, {
    suite: "maruhi/v1",
    environmentId: input.environmentId,
    name: input.name,
    status: input.status,
    metaVersion: last.statement.metaVersion + 1,
    prevMetaSigHashHex,
    chainHeadHashHex: fixture.head.hashHex,
    chainHeadSeq: fixture.head.seq,
  });
}

/** 環境 rename(ステートメント付き PATCH)。204 なら記録を進める。 */
export async function renameEnvironmentRequest(
  fixture: DataFixture,
  environmentId: string,
  name: string,
  actorUserId: string,
): Promise<Response> {
  const statement = await nextEnvironmentStatement(fixture, {
    environmentId,
    name,
    status: "active",
    authorUserId: actorUserId,
  });
  const response = await requestJson(
    "PATCH",
    `/environments/${environmentId}`,
    tokenOf(fixture.tokens, actorUserId),
    { statement },
  );
  if (response.status === 204) {
    fixture.envStatements.set(environmentId, { statement, authorUserId: actorUserId });
  }
  return response;
}

/** 環境削除(status deleted のステートメント付き DELETE)。204 なら記録を進める。 */
export async function deleteEnvironmentRequest(
  fixture: DataFixture,
  environmentId: string,
  actorUserId: string,
): Promise<Response> {
  const last = fixture.envStatements.get(environmentId);
  if (last === undefined) {
    throw new Error(`no recorded statement for environment ${environmentId}`);
  }
  // deleted の name は直前 active 名を保持する(§4.2)
  const statement = await nextEnvironmentStatement(fixture, {
    environmentId,
    name: last.statement.name,
    status: "deleted",
    authorUserId: actorUserId,
  });
  const response = await requestJson(
    "DELETE",
    `/environments/${environmentId}`,
    tokenOf(fixture.tokens, actorUserId),
    { statement },
  );
  if (response.status === 204) {
    fixture.envStatements.set(environmentId, { statement, authorUserId: actorUserId });
  }
  return response;
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
  const response = await createEnvironmentComposite(fixture, {
    environmentId,
    name,
    deks,
    dekCommitmentHex: await commitmentOf(projectId, environmentId, 1, dek),
  });
  expect(response.status).toBe(200);
  return dek;
}

/**
 * 環境作成リクエストを任意のラップ集合で送る(negative テスト用)。
 * コミットメントは使い捨て DEK から計算する(内容はサーバー検証不能 — §5.2 の
 * 照合は受信者の責務であり、受理判定に影響しない)。
 */
export async function createEnvironmentWith(
  fixture: DataFixture,
  environmentId: string,
  name: string,
  deks: readonly WireWrappedDek[],
): Promise<Response> {
  return createEnvironmentComposite(fixture, {
    environmentId,
    name,
    deks,
    dekCommitmentHex: await commitmentOf(projectId, environmentId, 1, makeDek()),
  });
}

/**
 * 複合のローテーションリクエスト(§12-4)を組み立てて送る: rotate_epoch
 * エントリ(新エポックのコミットメント込み)+ ラップ集合。200 ならヘッドを進める。
 */
export async function rotateEnvironmentComposite(
  fixture: DataFixture,
  input: {
    readonly environmentId: string;
    readonly newEpoch: number;
    readonly deks: readonly WireWrappedDek[];
    readonly dekCommitmentHex: string;
    readonly actorUserId?: string;
    readonly parentHeadHashHex?: string;
    /** URL とエントリ payload の不一致テスト用(既定はエントリと同じ環境)。 */
    readonly urlEnvironmentId?: string;
  },
): Promise<Response> {
  const actorUserId = input.actorUserId ?? MEMBER;
  const { entry } = await signEntryAt({
    seq: fixture.head.seq + 1,
    prevHashHex: input.parentHeadHashHex ?? fixture.head.hashHex,
    actorUserId,
    operation: rotateEpochOperation(input.environmentId, input.newEpoch, input.dekCommitmentHex),
  });
  const response = await requestJson(
    "POST",
    `/environments/${input.urlEnvironmentId ?? input.environmentId}/rotate`,
    tokenOf(fixture.tokens, actorUserId),
    {
      parentHeadHashHex: input.parentHeadHashHex ?? fixture.head.hashHex,
      entry,
      deks: input.deks,
    },
  );
  if (response.status === 200) {
    advanceHead(
      fixture,
      (await response.clone().json()) as { headSeq: number; headHashHex: string },
    );
  }
  return response;
}

/** ローテーション(新エポックの完全ラップ集合込み)。新エポックの DEK を返す。 */
export async function rotateEnvironmentOk(
  fixture: DataFixture,
  actorUserId: string,
  environmentId: string,
  newEpoch: number,
): Promise<Uint8Array> {
  const dek = makeDek();
  const deks = await wrapDekForAll({
    projectId,
    environmentId,
    epoch: newEpoch,
    dek,
    recipientUserIds: ALL_MEMBERS,
    signerUserId: actorUserId,
  });
  const response = await rotateEnvironmentComposite(fixture, {
    environmentId,
    newEpoch,
    deks,
    dekCommitmentHex: await commitmentOf(projectId, environmentId, newEpoch, dek),
    actorUserId,
  });
  expect(response.status).toBe(200);
  return dek;
}
