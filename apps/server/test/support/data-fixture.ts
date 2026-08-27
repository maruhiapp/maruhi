// データプレーン統合テストの共通フィクスチャ(workerd 内で実行)。
//
// ベース構成: テスト時署名の 3 エントリチェーン(owner / member / reader)を
// API 経由で再生し、各ユーザーの実 PAT を取得する。チェーンの延長
// (rotate_epoch / add_member)もすべて API 経由で行う。

import type { ChainEntry, ChainOperation, EnvValuesDigestEntry } from "@maruhi/crypto";
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
import type {
  WireDigestEntry,
  WireEnvironmentManifest,
  WireEnvironmentMetaStatement,
  WireWrappedDek,
} from "./data-crypto.ts";
import {
  addMemberOperation,
  buildChain,
  checkpointOperation,
  commitmentOf,
  createEnvironmentOperation,
  digestOf,
  genesisOperation,
  makeDek,
  manifestSignedBytesHashOf,
  metaSignedBytesHashOf,
  rotateEpochOperation,
  signEntryAt,
  signEnvManifestAs,
  signMetaStatementAs,
  valuesDigestOf,
  wrapDekForAll,
} from "./data-crypto.ts";
import { evictProjectDo, queryProjectDo, resetProjectDo } from "./project-do.ts";

export const OWNER = "user-owner-0001";
export const MEMBER = "user-member-0002";
// reader ロールのメンバー。署名鍵は 3 本目のベクター鍵(user-admin-0003)を
// 借用する(data-crypto.ts の VECTOR_KEY_ALIASES — 鍵とユーザー ID の束縛は
// チェーンの add_member が行うため、鍵集合の名義とは独立でよい)
export const READER = "user-reader-0003";
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

/**
 * 環境ごとのマニフェスト追跡(§4.3 の prev 連鎖・CAS・ダイジェスト集合の材料 —
 * 受理成功時に helper が進める)。entries は tombstone 込みの全変数の最新形。
 */
export interface EnvManifestState {
  manifest: WireEnvironmentManifest;
  issuerUserId: string;
  epoch: number;
  entries: readonly WireDigestEntry[];
}

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
  /** 環境ごとの最新マニフェスト(prev 連鎖・CAS・ダイジェスト集合の材料)。 */
  readonly manifests: Map<string, EnvManifestState>;
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
    manifests: new Map(),
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
 * 次のマニフェスト(§4.3)をテスト時署名で作る: manifestVersion = 記録済み
 * 最新 + 1(未記録 = 1)、prev = 記録済み最新の signed_bytes ハッシュ、
 * ダイジェスト = entries の正規形。宣言ヘッドは呼び出し側指定(複合 = 追記前の
 * 現ヘッド、メタ操作 = 現ヘッド)。
 */
export async function nextEnvironmentManifest(
  fixture: DataFixture,
  input: {
    readonly environmentId: string;
    readonly epoch: number;
    readonly entries: readonly WireDigestEntry[];
    readonly envMeta: { readonly metaVersion: number; readonly sigHashHex: string };
    readonly issuerUserId: string;
    readonly head: { readonly seq: number; readonly hashHex: string };
  },
): Promise<WireEnvironmentManifest> {
  const last = fixture.manifests.get(input.environmentId);
  const prevManifestSigHashHex =
    last === undefined
      ? ""
      : await manifestSignedBytesHashOf(projectId, last.manifest, last.issuerUserId);
  return signEnvManifestAs(input.issuerUserId, projectId, {
    suite: "maruhi/v1",
    environmentId: input.environmentId,
    epoch: input.epoch,
    manifestVersion: (last?.manifest.manifestVersion ?? 0) + 1,
    variablesDigestHex: await digestOf(input.entries),
    envMetaVersion: input.envMeta.metaVersion,
    envMetaSigHashHex: input.envMeta.sigHashHex,
    prevManifestSigHashHex,
    chainHeadHashHex: input.head.hashHex,
    chainHeadSeq: input.head.seq,
  });
}

/** 記録済みの環境メタステートメントの最新形(マニフェストの envMeta 期待値)。 */
export async function envMetaOf(
  fixture: DataFixture,
  environmentId: string,
): Promise<{ metaVersion: number; sigHashHex: string }> {
  const last = fixture.envStatements.get(environmentId);
  if (last === undefined) {
    throw new Error(`no recorded statement for environment ${environmentId}`);
  }
  return {
    metaVersion: last.statement.metaVersion,
    sigHashHex: await metaSignedBytesHashOf(projectId, last.statement, last.authorUserId),
  };
}

/**
 * 変数のメタ操作(作成・rename・削除)に同梱するマニフェストを署名する:
 * 記録済みのダイジェスト集合に当該変数のエントリを適用した形。成功時に
 * 記録を進めるための EnvManifestState も返す。
 */
export async function manifestForVariableOp(
  fixture: DataFixture,
  input: {
    readonly environmentId: string;
    readonly issuerUserId: string;
    readonly entry: WireDigestEntry;
  },
): Promise<{ manifest: WireEnvironmentManifest; state: EnvManifestState }> {
  const last = fixture.manifests.get(input.environmentId);
  if (last === undefined) {
    throw new Error(`no recorded manifest for environment ${input.environmentId}`);
  }
  const entries = [
    ...last.entries.filter((candidate) => candidate.variableId !== input.entry.variableId),
    input.entry,
  ];
  const manifest = await nextEnvironmentManifest(fixture, {
    environmentId: input.environmentId,
    epoch: last.epoch,
    entries,
    envMeta: await envMetaOf(fixture, input.environmentId),
    issuerUserId: input.issuerUserId,
    head: fixture.head,
  });
  return {
    manifest,
    state: { manifest, issuerUserId: input.issuerUserId, epoch: last.epoch, entries },
  };
}

/**
 * チェーン末尾の境界 checkpoint エントリと当該環境のスナップショット行を取り除き、
 * checkpoint タプルを持たない旧世代(境界 checkpoint 導入前)チェーンの形を再現する
 * (マニフェスト移行経路テスト用)。実運用の移行対象はマニフェスト・checkpoint
 * 導入前に作られた環境で、そのチェーンにはタプルが存在しない — 現 API は複合で
 * 必ず checkpoint を挿入するため、テストでは append-only の不変条件の外で直接
 * 取り除く(membership の canonical_bytes 改変と同じ扱い)。改変後は DO を退去
 * させてフルロードへ戻し、fixture のヘッドを新しい末尾へ巻き戻す。
 */
export async function stripTrailingCheckpoint(
  fixture: DataFixture,
  environmentId: string,
): Promise<void> {
  const tail = await queryProjectDo(
    projectId,
    "SELECT seq, entry_json FROM chain_entries ORDER BY seq DESC LIMIT 1",
  );
  const tailSeq = Number(tail[0]?.["seq"]);
  const tailEntry = JSON.parse(String(tail[0]?.["entry_json"])) as { op?: string };
  if (tailEntry.op !== "checkpoint") {
    throw new Error("chain tail is not a boundary checkpoint entry");
  }
  await queryProjectDo(projectId, "DELETE FROM chain_entries WHERE seq = ?", tailSeq);
  await queryProjectDo(
    projectId,
    "DELETE FROM environment_checkpoints WHERE environment_id = ?",
    environmentId,
  );
  await queryProjectDo(
    projectId,
    "DELETE FROM checkpoint_snapshot_values WHERE environment_id = ?",
    environmentId,
  );
  await evictProjectDo(projectId);
  const newTail = await queryProjectDo(
    projectId,
    "SELECT seq, entry_hash_hex FROM chain_entries ORDER BY seq DESC LIMIT 1",
  );
  fixture.head = {
    seq: Number(newTail[0]?.["seq"]),
    hashHex: String(newTail[0]?.["entry_hash_hex"]),
  };
}

/**
 * 保存済みの値レベル最新形(active 変数の latest_version + 値署名 signed_bytes
 * ハッシュ — §6.2 の values_digest 列挙)を DO の SQLite から直接読む。サーバーの
 * checkpointValueEntries と同じ問い合わせ(rotate の境界 checkpoint 突合基準)。
 */
async function storedCheckpointValues(
  environmentId: string,
): Promise<readonly EnvValuesDigestEntry[]> {
  const rows = await queryProjectDo(
    projectId,
    `SELECT v.variable_id, vv.version, vv.signed_bytes_hash_hex
     FROM variables v
     JOIN variable_versions vv
       ON vv.environment_id = v.environment_id
      AND vv.variable_id = v.variable_id
      AND vv.version = v.latest_version
     WHERE v.environment_id = ? AND v.deleted_at IS NULL
     ORDER BY v.variable_id`,
    environmentId,
  );
  return rows.map((row) => ({
    variableId: String(row["variable_id"]),
    version: Number(row["version"]),
    valueSigHashHex: String(row["signed_bytes_hash_hex"]),
  }));
}

/**
 * 境界 checkpoint(H+2 — §12-4)をテスト時署名で作る: prev = H+1 複合エントリの
 * ハッシュ、タプル = 同梱マニフェストの座標 + signed_bytes ハッシュ(issuer =
 * actor — §12-5 (1))+ values のダイジェスト。
 */
async function signBoundaryCheckpointEntry(input: {
  readonly actorUserId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly manifest: WireEnvironmentManifest;
  readonly compositeSeq: number;
  readonly compositeHashHex: string;
  readonly values: readonly EnvValuesDigestEntry[];
}): Promise<ChainEntry> {
  const { entry } = await signEntryAt({
    seq: input.compositeSeq + 1,
    prevHashHex: input.compositeHashHex,
    actorUserId: input.actorUserId,
    operation: checkpointOperation({
      environmentId: input.environmentId,
      epoch: input.epoch,
      manifestVersion: input.manifest.manifestVersion,
      manifestSigHashHex: await manifestSignedBytesHashOf(
        projectId,
        input.manifest,
        input.actorUserId,
      ),
      valuesDigestHex: await valuesDigestOf(input.values),
    }),
  });
  return entry;
}

/**
 * 複合の環境作成リクエスト(§12-4)を組み立てて送る: create_environment
 * エントリ(コミットメント込み)+ EnvironmentMetaStatement(metaVersion 1。
 * 宣言ヘッド = 追記前の現ヘッド)+ EnvironmentManifest(manifestVersion 1・
 * 変数空集合・epoch 1)+ 境界 checkpoint(H+2)をテスト時署名し、親ヘッド CAS
 * 付きでラップ集合と同時に POST する。200 ならフィクスチャのヘッドを進める。
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
    /** 複合内整合の negative 用のマニフェスト上書き。 */
    readonly manifest?: WireEnvironmentManifest;
    /** 複合内整合の negative 用の境界 checkpoint 上書き。 */
    readonly checkpoint?: ChainEntry;
  },
): Promise<Response> {
  const actorUserId = input.actorUserId ?? OWNER;
  const { entry, hash: entryHash } = await signEntryAt({
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
  // manifestVersion 1(変数空集合・epoch 1)。envMeta は同梱ステートメント自身
  const manifest =
    input.manifest ??
    (await signEnvManifestAs(actorUserId, projectId, {
      suite: "maruhi/v1",
      environmentId: input.environmentId,
      epoch: 1,
      manifestVersion: 1,
      variablesDigestHex: await digestOf([]),
      envMetaVersion: statement.metaVersion,
      envMetaSigHashHex: await metaSignedBytesHashOf(projectId, statement, actorUserId),
      prevManifestSigHashHex: "",
      chainHeadHashHex: input.parentHeadHashHex ?? fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    }));
  // 境界 checkpoint(H+2 — §12-4): 作成 = 変数空集合の values_digest
  const checkpoint =
    input.checkpoint ??
    (await signBoundaryCheckpointEntry({
      actorUserId,
      environmentId: input.environmentId,
      epoch: 1,
      manifest,
      compositeSeq: fixture.head.seq + 1,
      compositeHashHex: entryHash,
      values: [],
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
      manifest,
      checkpoint,
    },
  );
  if (response.status === 200) {
    advanceHead(
      fixture,
      (await response.clone().json()) as { headSeq: number; headHashHex: string },
    );
    fixture.envStatements.set(input.environmentId, { statement, authorUserId: actorUserId });
    fixture.manifests.set(input.environmentId, {
      manifest,
      issuerUserId: actorUserId,
      epoch: 1,
      entries: [],
    });
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

/** 環境 rename(ステートメント + マニフェスト付き PATCH)。204 なら記録を進める。 */
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
  // 環境 rename のマニフェストは新しい envMetaSigHashHex を写す(§12-4)
  const last = fixture.manifests.get(environmentId);
  if (last === undefined) {
    throw new Error(`no recorded manifest for environment ${environmentId}`);
  }
  const manifest = await nextEnvironmentManifest(fixture, {
    environmentId,
    epoch: last.epoch,
    entries: last.entries,
    envMeta: {
      metaVersion: statement.metaVersion,
      sigHashHex: await metaSignedBytesHashOf(projectId, statement, actorUserId),
    },
    issuerUserId: actorUserId,
    head: fixture.head,
  });
  const response = await requestJson(
    "PATCH",
    `/environments/${environmentId}`,
    tokenOf(fixture.tokens, actorUserId),
    { statement, manifest },
  );
  if (response.status === 204) {
    fixture.envStatements.set(environmentId, { statement, authorUserId: actorUserId });
    fixture.manifests.set(environmentId, {
      manifest,
      issuerUserId: actorUserId,
      epoch: last.epoch,
      entries: last.entries,
    });
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
    /** 複合内整合の negative 用のマニフェスト上書き。 */
    readonly manifest?: WireEnvironmentManifest;
    /** 複合内整合の negative 用の境界 checkpoint 上書き。 */
    readonly checkpoint?: ChainEntry;
    /**
     * values_digest の材料上書き(既定 = DO 保存行の実列挙。並行 push の不一致
     * negative 等で使う)。
     */
    readonly checkpointValues?: readonly EnvValuesDigestEntry[];
  },
): Promise<Response> {
  const actorUserId = input.actorUserId ?? MEMBER;
  const { entry, hash: entryHash } = await signEntryAt({
    seq: fixture.head.seq + 1,
    prevHashHex: input.parentHeadHashHex ?? fixture.head.hashHex,
    actorUserId,
    operation: rotateEpochOperation(input.environmentId, input.newEpoch, input.dekCommitmentHex),
  });
  // 新エポックを焼き込んだマニフェスト(メタ集合は不変 — §4.3)。宣言ヘッドは
  // 追記前の現ヘッド(§12-4)。未記録の環境(negative テストの未作成環境等)は
  // 空集合 + ダミー envMeta で形だけ満たす(受理段の先行検査で落ちる前提)
  const last = fixture.manifests.get(input.environmentId);
  const manifest =
    input.manifest ??
    (await nextEnvironmentManifest(fixture, {
      // URL とエントリの不一致 negative では worker のマニフェスト座標検査
      // (manifestEnvironmentId)より先に DO の entry-vs-URL 検査へ到達させる
      // ため、マニフェストは URL 側の座標で署名する
      environmentId: input.urlEnvironmentId ?? input.environmentId,
      epoch: input.newEpoch,
      entries: last?.entries ?? [],
      envMeta: fixture.envStatements.has(input.environmentId)
        ? await envMetaOf(fixture, input.environmentId)
        : { metaVersion: 1, sigHashHex: "ab".repeat(32) },
      issuerUserId: actorUserId,
      head: {
        seq: fixture.head.seq,
        hashHex: input.parentHeadHashHex ?? fixture.head.hashHex,
      },
    }));
  // 境界 checkpoint(H+2 — §12-4): rotate = 保存済みの値レベル最新形の列挙
  // (未再暗号化 = 旧エポックの現在値 — §12-7 の正当な状態)
  const checkpoint =
    input.checkpoint ??
    (await signBoundaryCheckpointEntry({
      actorUserId,
      environmentId: input.environmentId,
      epoch: input.newEpoch,
      manifest,
      compositeSeq: fixture.head.seq + 1,
      compositeHashHex: entryHash,
      values: input.checkpointValues ?? (await storedCheckpointValues(input.environmentId)),
    }));
  const response = await requestJson(
    "POST",
    `/environments/${input.urlEnvironmentId ?? input.environmentId}/rotate`,
    tokenOf(fixture.tokens, actorUserId),
    {
      parentHeadHashHex: input.parentHeadHashHex ?? fixture.head.hashHex,
      entry,
      deks: input.deks,
      manifest,
      checkpoint,
    },
  );
  if (response.status === 200) {
    advanceHead(
      fixture,
      (await response.clone().json()) as { headSeq: number; headHashHex: string },
    );
    fixture.manifests.set(input.environmentId, {
      manifest,
      issuerUserId: actorUserId,
      epoch: input.newEpoch,
      entries: last?.entries ?? [],
    });
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
