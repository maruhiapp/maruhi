// メンバーシップログ統合テストの共有シナリオ(旧 membership.test.ts の冒頭
// ヘルパの分割先 — data-scenario.ts と同じ「共有 fixture + register」パターン)。
//
// 分割の動機(2026-09-01): vitest-pool-workers は同一 workerd インスタンス内で
// SELF.fetch を重ねるほどリクエスト処理が累積的に遅くなる(ファイル先頭 7ms →
// 1,500 リクエスト後 400ms 超の実測。wrangler dev の同一ワーカーでは劣化なし)。
// ファイルごとに workerd が作り直されるため、describe 単位でファイルを割ると
// 劣化がリセットされ、ファイル間はコア数ぶん並列にもなる。ヘルパの意味論は
// 旧 membership.test.ts と同一。
//
// テストベクター(packages/crypto/test-vectors/chain-entries.json)の再利用:
// - 正常系 seq 1〜12 をサーバー経由の受理テストとして再生する(actor ごとの実 PAT
//   認証。create_environment / rotate_epoch は複合エンドポイント経由 — §12-4)。
//   複合は境界 checkpoint(H+2 — 2026-08-27 PR-F3b)を挿入するため、最初の複合
//   以降はベクターの固定 seq / prev からヘッドがずれる。以降のエントリは op /
//   payload / actor を保って実ヘッドで再署名して追従する(バイト固定は crypto 層の
//   4 実行環境テストが担い、ここでは同じ op 列の API 受理を固定する)
// - 認可系 negative 全件を拒否テストとして再生する(同じく実ヘッドで再署名)
//
// 認証は実発行経路(CLI ログインハンドオフ)で PAT を取得する。ベクターの固定 user_id は
// D1 への直接シード(users + linked_identities)で整合させる(AUTH_SPEC §11-1 裁定)。

import type { ChainEntry } from "@maruhi/crypto";
import { computeChainEntryHash } from "@maruhi/crypto";
import { vectorEnvironmentDeks } from "@maruhi/crypto/test-support";
import { SELF } from "cloudflare:test";
import { beforeEach, expect } from "vitest";

import {
  BASE,
  bearer,
  cliToken,
  JSON_HEADERS,
  resetAuthDb,
  seedOrgMember,
  seedUser,
} from "./auth.ts";
import {
  toWireEntry,
  vectorEntries,
  vectorExtendedChains,
  vectorProjectId,
} from "./chain-vectors.ts";
import type { WireEnvironmentManifest } from "./data-crypto.ts";
import {
  checkpointOperation,
  digestOf,
  hexBytes,
  makeDek,
  manifestSignedBytesHashOf,
  metaSignedBytesHashOf,
  resignEntryAt,
  signEntryAt,
  signEnvManifestAs,
  signMetaStatementAs,
  valuesDigestOf,
  wrapDekForAll,
  wrapDekToServer,
} from "./data-crypto.ts";
import { resetProjectDo } from "./project-do.ts";

export const VECTOR_ORG = "org-vector-0001";

const GITHUB_IDS: Record<string, number> = {
  "user-owner-0001": 9001,
  "user-member-0002": 9002,
  "user-admin-0003": 9003,
};

let tokens: Record<string, string> = {};

export function tokenFor(userId: string): string {
  const token = tokens[userId];
  if (token === undefined) {
    throw new Error(`no seeded token for ${userId}`);
  }
  return token;
}

export const initChain = (
  entry: ChainEntry,
  options?: { readonly headers?: Record<string, string>; readonly orgId?: string },
): Promise<Response> =>
  SELF.fetch(`${BASE}/projects`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...(options?.headers ?? bearer(tokenFor("user-owner-0001"))) },
    body: JSON.stringify({ orgId: options?.orgId ?? VECTOR_ORG, entry }),
  });

export const appendEntry = (
  projectId: string,
  parentHeadHashHex: string,
  entry: ChainEntry,
  headers?: Record<string, string>,
): Promise<Response> =>
  SELF.fetch(`${BASE}/projects/${projectId}/chain/entries`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...(headers ?? bearer(tokenFor(entry.actor.userId))) },
    body: JSON.stringify({ parentHeadHashHex, entry }),
  });

export const getChain = (projectId: string, headers?: Record<string, string>): Promise<Response> =>
  SELF.fetch(`${BASE}/projects/${projectId}/chain`, {
    headers: headers ?? bearer(tokenFor("user-owner-0001")),
  });

/**
 * ベクターの (environment, epoch) のダミー DEK(実計算のコミットメントと対)。
 * negative の不正座標(存在しないエポック等)にはベクター DEK がないため乱数で
 * 代替する — それらの拒否はラップ内容に依存しない(合意規則・判定順で落ちる)。
 */
function vectorDek(environmentId: string, epoch: number): Uint8Array {
  const dekHex = vectorEnvironmentDeks[environmentId]?.[String(epoch)]?.dek_hex;
  return dekHex === undefined ? makeDek() : hexBytes(dekHex);
}

/** 有効 grant の追跡(replayVectorChain 用): FP → enc 公開鍵 + 開示スコープ。 */
interface TrackedServerGrant {
  readonly encPubHex: string;
  readonly scope: readonly string[];
}

/**
 * 環境ごとの最新マニフェスト追跡(複合の manifestVersion CAS / prev 連鎖の
 * 材料 — §12-5)。replayVectorChain の開始でクリアする(各テストは replay から
 * 始まる)。envMeta は複合作成の同梱ステートメント(metaVersion 1)で固定。
 */
const replayManifests = new Map<
  string,
  {
    manifest: WireEnvironmentManifest;
    issuerUserId: string;
    envMeta: { metaVersion: number; sigHashHex: string };
  }
>();

/**
 * 複合のラップ集合(現メンバー全員 + 開示スコープ内の有効 grant のサーバー鍵宛 —
 * AUTH_SPEC §12-4 の完全集合)。
 */
async function compositeWraps(
  entry: ChainEntry & { readonly op: "create_environment" | "rotate_epoch" },
  environmentId: string,
  epoch: number,
  dek: Uint8Array,
  recipients: readonly string[],
  serverRecipients: readonly { readonly fpHex: string; readonly encPubHex: string }[],
) {
  const deks = await wrapDekForAll({
    projectId: vectorProjectId,
    environmentId,
    epoch,
    dek,
    recipientUserIds: recipients,
    signerUserId: entry.actor.userId,
  });
  for (const server of serverRecipients) {
    deks.push(
      await wrapDekToServer({
        projectId: vectorProjectId,
        environmentId,
        epoch,
        dek,
        serverKeyFingerprintHex: server.fpHex,
        serverEncPubHex: server.encPubHex,
        signerUserId: entry.actor.userId,
      }),
    );
  }
  return deks;
}

/**
 * 複合の同梱ステートメント(作成のみ)+ envMeta + マニフェスト(§12-4 / §12-5):
 * 宣言ヘッドは追記前の現ヘッド、epoch は同梱エントリが確立するエポック。
 * negative(未作成環境への rotate 等)で追跡が無い場合はダミー envMeta の v1
 * (拒否は先行検査で確定する)。作成複合はワイヤ形が manifestVersion 1・prev 空を
 * 固定する(negative の重複作成でも同じ形で送り、拒否は合意規則が担う)。
 */
async function compositeManifestParts(
  entry: ChainEntry & { readonly op: "create_environment" | "rotate_epoch" },
  environmentId: string,
  epoch: number,
) {
  const tracked = replayManifests.get(environmentId);
  const statement =
    entry.op === "create_environment"
      ? await signMetaStatementAs(entry.actor.userId, vectorProjectId, {
          suite: "maruhi/v1" as const,
          environmentId,
          name: environmentId,
          status: "active" as const,
          metaVersion: 1,
          prevMetaSigHashHex: "",
          chainHeadHashHex: entry.prevHashHex,
          chainHeadSeq: entry.seq - 1,
        })
      : null;
  const envMeta =
    statement !== null
      ? {
          metaVersion: 1,
          sigHashHex: await metaSignedBytesHashOf(vectorProjectId, statement, entry.actor.userId),
        }
      : (tracked?.envMeta ?? { metaVersion: 1, sigHashHex: "ab".repeat(32) });
  const chainlike =
    entry.op === "create_environment"
      ? { manifestVersion: 1, prevManifestSigHashHex: "" }
      : {
          manifestVersion: (tracked?.manifest.manifestVersion ?? 0) + 1,
          prevManifestSigHashHex:
            tracked === undefined
              ? ""
              : await manifestSignedBytesHashOf(
                  vectorProjectId,
                  tracked.manifest,
                  tracked.issuerUserId,
                ),
        };
  const manifest = await signEnvManifestAs(entry.actor.userId, vectorProjectId, {
    suite: "maruhi/v1",
    environmentId,
    epoch,
    ...chainlike,
    variablesDigestHex: await digestOf([]),
    envMetaVersion: envMeta.metaVersion,
    envMetaSigHashHex: envMeta.sigHashHex,
    chainHeadHashHex: entry.prevHashHex,
    chainHeadSeq: entry.seq - 1,
  });
  return { statement, envMeta, manifest };
}

/**
 * create_environment / rotate_epoch のベクターエントリを複合エンドポイント
 * (AUTH_SPEC §12-4)へ送る。汎用 append は 2 op を CompositeRequired で拒否する
 * ため、再生・negative とも複合経由になる。ラップ集合はベクターのダミー DEK を
 * 現メンバー集合(recipients)へ実 HPKE でラップし、actor 自身が署名する。
 */
export async function submitComposite(
  entry: ChainEntry & { readonly op: "create_environment" | "rotate_epoch" },
  recipients: readonly string[],
  headers?: Record<string, string>,
  serverRecipients?: readonly { readonly fpHex: string; readonly encPubHex: string }[],
): Promise<Response> {
  const environmentId = entry.payload.environmentId;
  const epoch = entry.op === "create_environment" ? 1 : entry.payload.newEpoch;
  const dek = vectorDek(environmentId, epoch);
  const deks = await compositeWraps(
    entry,
    environmentId,
    epoch,
    dek,
    recipients,
    serverRecipients ?? [],
  );
  const url =
    entry.op === "create_environment"
      ? `${BASE}/projects/${vectorProjectId}/environments`
      : `${BASE}/projects/${vectorProjectId}/environments/${environmentId}/rotate`;
  const { statement, envMeta, manifest } = await compositeManifestParts(
    entry,
    environmentId,
    epoch,
  );
  // 境界 checkpoint(H+2 — §12-4 の必須同梱)。メンバーシップ系テストはデータ
  // プレーンの変数を作らないため values_digest は常に空集合の列挙
  const { entry: checkpoint } = await signEntryAt({
    seq: entry.seq + 1,
    prevHashHex: await computeChainEntryHash(entry),
    actorUserId: entry.actor.userId,
    operation: checkpointOperation({
      environmentId,
      epoch,
      manifestVersion: manifest.manifestVersion,
      manifestSigHashHex: await manifestSignedBytesHashOf(
        vectorProjectId,
        manifest,
        entry.actor.userId,
      ),
      valuesDigestHex: await valuesDigestOf([]),
    }),
  });
  const body =
    entry.op === "create_environment"
      ? { parentHeadHashHex: entry.prevHashHex, entry, statement, deks, manifest, checkpoint }
      : { parentHeadHashHex: entry.prevHashHex, entry, deks, manifest, checkpoint };
  const response = await SELF.fetch(url, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...(headers ?? bearer(tokenFor(entry.actor.userId))) },
    body: JSON.stringify(body),
  });
  if (response.status === 200) {
    replayManifests.set(environmentId, {
      manifest,
      issuerUserId: entry.actor.userId,
      envMeta,
    });
  }
  return response;
}

/** 再生の op を追いながら現メンバー / 有効 grant を更新する(複合のラップ集合の導出)。 */
function trackReplayState(
  entry: ReturnType<typeof toWireEntry>,
  members: string[],
  serverGrants: Map<string, TrackedServerGrant>,
): void {
  if (entry.op === "add_member") {
    members.push(entry.payload.targetUserId);
  } else if (entry.op === "remove_member") {
    const index = members.indexOf(entry.payload.targetUserId);
    if (index >= 0) {
      members.splice(index, 1);
    }
  } else if (entry.op === "grant_server") {
    serverGrants.set(entry.payload.serverKeyFingerprintHex, {
      encPubHex: entry.payload.serverEncPubHex,
      scope: entry.payload.scopeEnvironmentIds,
    });
  } else if (entry.op === "revoke_server") {
    serverGrants.delete(entry.payload.serverKeyFingerprintHex);
  }
}

/** 再生後の実ヘッド(複合の境界 checkpoint 挿入でベクターの固定 seq とずれる)。 */
export interface ReplayHead {
  readonly seq: number;
  readonly hashHex: string;
}

export interface ReplayResult {
  readonly members: readonly string[];
  readonly head: ReplayHead;
}

/**
 * ベクターの seq 1..upTo をサーバーへ再生する(init + append + 複合。actor ごとの
 * PAT)。複合のラップ集合が要る現メンバー集合は op を追いながら導出する。
 *
 * 2026-08-27(PR-F3b): 複合は境界 checkpoint(H+2)を挿入するため、最初の複合
 * 以降のヘッドはベクターの固定 seq / prev からずれる。以降のエントリは op /
 * payload / actor を保ったまま実ヘッドで再署名して追従する(正規チェーンの
 * バイト固定は crypto 層の 4 実行環境テストが担い、ここでは「同じ op 列を API が
 * 受理する」ことを固定する)。
 */
export async function replayVectorChain(upTo: number): Promise<ReplayResult> {
  const members: string[] = [];
  const serverGrants = new Map<string, TrackedServerGrant>();
  let head: ReplayHead = { seq: 0, hashHex: "" };
  // マニフェスト追跡は再生ごとにやり直す(beforeEach が DO を消すため)
  replayManifests.clear();
  for (const vector of vectorEntries) {
    if (vector.seq > upTo) {
      break;
    }
    const wire = toWireEntry(vector);
    if (wire.op === "genesis") {
      const response = await initChain(wire);
      expect(response.status).toBe(200);
      members.push(wire.actor.userId);
      head = { seq: 1, hashHex: vector.entry_hash_hex };
      continue;
    }
    // ヘッドがベクターどおりならエントリは原本バイトのまま(再署名は決定的に同一)
    const { entry, hash } =
      head.seq === vector.seq - 1 && head.hashHex === vector.prev_hash_hex
        ? { entry: wire, hash: vector.entry_hash_hex }
        : await resignEntryAt(wire, head.seq + 1, head.hashHex);
    if (entry.op === "create_environment" || entry.op === "rotate_epoch") {
      const environmentId = entry.payload.environmentId;
      const serverRecipients = [...serverGrants.entries()]
        .filter(([, grant]) => grant.scope.includes(environmentId))
        .map(([fpHex, grant]) => ({ fpHex, encPubHex: grant.encPubHex }));
      const response = await submitComposite(entry, members, undefined, serverRecipients);
      expect(response.status).toBe(200);
      const body = (await response.json()) as { headSeq: number; headHashHex: string };
      head = { seq: body.headSeq, hashHex: body.headHashHex };
      continue;
    }
    const response = await appendEntry(vectorProjectId, entry.prevHashHex, entry);
    expect(response.status).toBe(200);
    head = { seq: entry.seq, hashHex: hash };
    trackReplayState(entry, members, serverGrants);
  }
  return { members, head };
}

/**
 * 認可 negative の前提チェーンを再生する: chain 指定つきは正規チェーンの
 * base_seq までを再生した後、派生チェーン(extended_chains)のエントリを
 * 汎用 append で受理させる(受理されること自体も §6.2 の許容側の固定。実ヘッドが
 * ベクターとずれた分は再署名で追従する — replayVectorChain と同じ規律)。
 */
export async function replayNegativePrefix(negative: {
  readonly entry: { readonly seq: number };
  readonly chain?: string;
}): Promise<ReplayResult> {
  if (negative.chain === undefined) {
    return replayVectorChain(negative.entry.seq - 1);
  }
  const extended = vectorExtendedChains[negative.chain];
  if (extended === undefined) {
    throw new Error(`missing extended chain ${negative.chain}`);
  }
  const base = await replayVectorChain(extended.base_seq);
  let head = base.head;
  for (const vector of extended.entries) {
    const { entry, hash } = await resignEntryAt(toWireEntry(vector), head.seq + 1, head.hashHex);
    const response = await appendEntry(vectorProjectId, entry.prevHashHex, entry);
    expect(response.status).toBe(200);
    head = { seq: entry.seq, hashHex: hash };
  }
  return { members: base.members, head };
}

/**
 * 各テストファイルの冒頭で 1 回呼ぶ: フィクスチャの beforeEach を登録する。
 *
 * この vitest-pool-workers 構成にはテスト間のストレージ分離がなく、DO SQLite /
 * D1 はファイル内のテスト間で持ち越される。テストごとに明示的に空へ戻し、
 * ベクターユーザーをシードして PAT を取り直す。
 */
export function registerMembershipScenario(): void {
  beforeEach(async () => {
    await resetProjectDo(vectorProjectId);
    await resetAuthDb();
    tokens = {};
    for (const [userId, githubId] of Object.entries(GITHUB_IDS)) {
      await seedUser(userId, githubId);
      tokens[userId] = await cliToken(githubId);
    }
    await seedOrgMember(VECTOR_ORG, "user-owner-0001", "member");
  });
}
