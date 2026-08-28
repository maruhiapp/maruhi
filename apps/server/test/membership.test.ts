// メンバーシップログのサーバー保存(CRYPTO_SPEC §6.4)+ 認可(AUTH_SPEC §11)の統合テスト。
// vitest-pool-workers(workerd 実環境)で SELF 経由の HttpApi と DO SQLite / D1 を検証する。
//
// テストベクター(packages/crypto/test-vectors/chain-entries.json)の再利用:
// - 正常系 seq 1〜12 をサーバー経由の受理テストとして再生する(actor ごとの実 PAT
//   認証。create_environment / rotate_epoch は複合エンドポイント経由 — §12-4)。
//   複合は境界 checkpoint(H+2 — 2026-08-27 PR-F3b)を挿入するため、最初の複合
//   以降はベクターの固定 seq / prev からヘッドがずれる。以降のエントリは op /
//   payload / actor を保って実ヘッドで再署名して追従する(バイト固定は crypto 層の
//   4 実行環境テストが担い、ここでは同じ op 列の API 受理を固定する)
// - 認可系 negative 全件を拒否テストとして再生する(同じく実ヘッドで再署名)。
//   サーバー受理面では判定順により合意規則の理由コードがそのまま出ないケースが
//   ある(role 403 先行・未作成環境 404 先行・形式違反 400 先行 —
//   compositeExpectations の対応表)
//
// 認証は実発行経路(device 交換)で PAT を取得する。ベクターの固定 user_id は
// D1 への直接シード(users + linked_identities)で整合させる(AUTH_SPEC §11-1 裁定)。

import type { TokenScope } from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { computeChainEntryHash } from "@maruhi/crypto";
import { vectorEnvironmentDeks } from "@maruhi/crypto/test-support";
import { env, evictDurableObject, runInDurableObject, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { chainCapacityExceeded } from "../src/chain-accept.ts";
import {
  MAX_CHAIN_ENTRIES,
  MAX_CHAIN_TOTAL_CANONICAL_BYTES,
  MAX_ENTRY_CANONICAL_BYTES,
  MAX_REQUEST_BODY_BYTES,
} from "../src/policy.ts";
import {
  BASE,
  bearer,
  deviceToken,
  JSON_HEADERS,
  loginSession,
  resetAuthDb,
  seedOrgMember,
  seedUser,
  sessionHeaders,
} from "./support/auth.ts";
import {
  toWireEntry,
  vectorAuthzNegatives,
  vectorEntries,
  vectorExtendedChains,
  vectorProjectId,
} from "./support/chain-vectors.ts";
import type { WireEnvironmentManifest } from "./support/data-crypto.ts";
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
} from "./support/data-crypto.ts";
import { resetProjectDo } from "./support/project-do.ts";

const VECTOR_ORG = "org-vector-0001";
const GITHUB_IDS: Record<string, number> = {
  "user-owner-0001": 9001,
  "user-member-0002": 9002,
  "user-admin-0003": 9003,
};

let tokens: Record<string, string> = {};

function tokenFor(userId: string): string {
  const token = tokens[userId];
  if (token === undefined) {
    throw new Error(`no seeded token for ${userId}`);
  }
  return token;
}

const initChain = (
  entry: ChainEntry,
  options?: { readonly headers?: Record<string, string>; readonly orgId?: string },
): Promise<Response> =>
  SELF.fetch(`${BASE}/projects`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...(options?.headers ?? bearer(tokenFor("user-owner-0001"))) },
    body: JSON.stringify({ orgId: options?.orgId ?? VECTOR_ORG, entry }),
  });

const appendEntry = (
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

const getChain = (projectId: string, headers?: Record<string, string>): Promise<Response> =>
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

/**
 * create_environment / rotate_epoch のベクターエントリを複合エンドポイント
 * (AUTH_SPEC §12-4)へ送る。汎用 append は 2 op を CompositeRequired で拒否する
 * ため、再生・negative とも複合経由になる。ラップ集合はベクターのダミー DEK を
 * 現メンバー集合(recipients)へ実 HPKE でラップし、actor 自身が署名する。
 */
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
 * 宣言ヘッドは追記前の現ヘッド、epoch は同梱エントリが確立するエポック。膜
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

async function submitComposite(
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
  // 境界 checkpoint(H+2 — §12-4 の必須同梱)。本ファイルはデータプレーンの変数を
  // 作らないため values_digest は常に空集合の列挙
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
interface ReplayHead {
  readonly seq: number;
  readonly hashHex: string;
}

interface ReplayResult {
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
async function replayVectorChain(upTo: number): Promise<ReplayResult> {
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
async function replayNegativePrefix(negative: {
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

// この vitest-pool-workers 構成(cloudflareTest プラグイン 0.21.0)にはテスト間の
// ストレージ分離がなく、DO SQLite / D1 はファイル内のテスト間で持ち越される。
// テストごとに明示的に空へ戻し、ベクターユーザーをシードして PAT を取り直す
beforeEach(async () => {
  await resetProjectDo(vectorProjectId);
  await resetAuthDb();
  tokens = {};
  for (const [userId, githubId] of Object.entries(GITHUB_IDS)) {
    await seedUser(userId, githubId);
    tokens[userId] = await deviceToken(githubId);
  }
  await seedOrgMember(VECTOR_ORG, "user-owner-0001", "member");
});

describe("environment", () => {
  it("runs inside workerd", () => {
    expect(navigator.userAgent).toBe("Cloudflare-Workers");
  });
});

describe("POST /projects (genesis 受理 + org 連携 §11-3)", () => {
  it("accepts the vector genesis, derives project id = genesis entry hash, records the org row", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    const response = await initChain(toWireEntry(genesis));
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      projectId: vectorProjectId,
      headSeq: 1,
      headHashHex: genesis.entry_hash_hex,
    });
    // D1 の projects 行(org 帰属メタデータ)が追従する
    const row = await env.DB.prepare("SELECT org_id FROM projects WHERE id = ?")
      .bind(vectorProjectId)
      .first<{ org_id: string }>();
    expect(row?.org_id).toBe(VECTOR_ORG);
  });

  it("rejects a duplicate genesis submission with 409", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    await initChain(toWireEntry(genesis));
    const second = await initChain(toWireEntry(genesis));
    expect(second.status).toBe(409);
    const body = (await second.json()) as { projectId: string };
    expect(body.projectId).toBe(vectorProjectId);
  });

  it("repairs a missing projects row idempotently for the genesis actor (§11-3)", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    await initChain(toWireEntry(genesis));
    // DO 受理後・D1 行挿入前のクラッシュを模擬: 行だけを消す
    await env.DB.prepare("DELETE FROM projects WHERE id = ?").bind(vectorProjectId).run();
    const retried = await initChain(toWireEntry(genesis));
    expect(retried.status).toBe(200);
    await expect(retried.json()).resolves.toEqual({
      projectId: vectorProjectId,
      headSeq: 1,
      headHashHex: genesis.entry_hash_hex,
    });
    const row = await env.DB.prepare("SELECT org_id FROM projects WHERE id = ?")
      .bind(vectorProjectId)
      .first<{ org_id: string }>();
    expect(row?.org_id).toBe(VECTOR_ORG);
  });

  it("rejects init into an org the caller is not a member of (403 org-membership-required)", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    const response = await initChain(toWireEntry(genesis), { orgId: "org-not-mine" });
    expect(response.status).toBe(403);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("org-membership-required");
  });

  it("rejects init whose genesis actor is not the authenticated user (403 actor-mismatch §11-1)", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    const response = await initChain(toWireEntry(genesis), {
      headers: bearer(tokenFor("user-member-0002")),
    });
    expect(response.status).toBe(403);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("actor-mismatch");
  });

  it("rejects a non-genesis entry with 422 (bad-seq)", async () => {
    const entry2 = vectorEntries[1];
    if (entry2 === undefined) throw new Error("missing vector entry 2");
    const response = await initChain(toWireEntry(entry2));
    expect(response.status).toBe(422);
    const body = (await response.json()) as { seq: number; reason: string };
    expect(body.reason).toBe("bad-seq");
  });
});

describe("チェーン再生(正常系ベクター seq 1〜12。create/rotate は複合経由)", () => {
  it("accepts the full vector chain with interleaved boundary checkpoints, append-only", async () => {
    // 複合(vector seq 3 / 4 / 8 / 10 / 11)ごとに境界 checkpoint(H+2)が
    // 挿入される(§12-4 — 2026-08-27)。ベクターの 12 op はこの順序で全受理される
    const { head } = await replayVectorChain(12);

    const response = await getChain(vectorProjectId);
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      projectId: string;
      entries: ChainEntry[];
      headSeq: number;
      headHashHex: string;
    };
    const expectedOps = [
      "genesis",
      "add_member",
      "create_environment",
      "checkpoint",
      "rotate_epoch",
      "checkpoint",
      "remove_member",
      "add_member",
      "change_role",
      "create_environment",
      "checkpoint",
      "grant_server",
      "rotate_epoch",
      "checkpoint",
      "create_environment",
      "checkpoint",
      "revoke_server",
    ];
    expect(body.projectId).toBe(vectorProjectId);
    expect(body.headSeq).toBe(expectedOps.length);
    expect(body.headHashHex).toBe(head.hashHex);
    expect(body.entries.map((entry) => entry.seq)).toEqual(expectedOps.map((_, i) => i + 1));
    expect(body.entries.map((entry) => entry.op)).toEqual(expectedOps);
    // checkpoint を除いた op 列はベクター本編と一致する(同じ操作列の受理)
    expect(
      body.entries.filter((entry) => entry.op !== "checkpoint").map((entry) => entry.op),
    ).toEqual(vectorEntries.map((v) => v.op));

    // DO SQLite の実データを直接確認する(append-only 保存とハッシュ列)。最初の
    // 複合の checkpoint 挿入まで(seq 1〜3)はベクターの固定バイトのまま受理される
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(vectorProjectId));
    await runInDurableObject(stub, (_instance, state) => {
      const rows = state.storage.sql
        .exec("SELECT seq, entry_hash_hex FROM chain_entries ORDER BY seq")
        .toArray();
      expect(rows.length).toBe(expectedOps.length);
      expect(rows.slice(0, 3).map((row) => row["entry_hash_hex"])).toEqual(
        vectorEntries.slice(0, 3).map((v) => v.entry_hash_hex),
      );
    });
  });
});

describe("チェーンの差分ロードキャッシュ(chain-store.ts StateCache.chain)", () => {
  const readChain = async () => {
    const response = await getChain(vectorProjectId);
    expect(response.status).toBe(200);
    return (await response.json()) as {
      projectId: string;
      entries: ChainEntry[];
      headSeq: number;
      headHashHex: string;
    };
  };

  it("追記→読み取り→追記の往復がフルロードと同一結果を返す(複合追記の増分反映込み)", async () => {
    // seq 1〜12 の再生は「追記(増分反映)→ 読み取り(差分ロード)」を毎手で
    // 往復し、複合受理(create/rotate + 境界 checkpoint の 2 エントリ insertSync
    // 経路)もキャッシュに反映する
    const { members } = await replayVectorChain(12);
    const warm = await readChain();

    // DO 退去 = インスタンスメモリのキャッシュ破棄。次の読み取りはフルロードに
    // フォールバックし、ウォームキャッシュの結果と完全一致しなければならない
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(vectorProjectId));
    await evictDurableObject(stub);
    const cold = await readChain();
    expect(cold).toEqual(warm);

    // フォールバック後も追記を受理でき、以降の読み取りへ増分反映される
    const target = members.find((userId) => userId !== "user-owner-0001");
    if (target === undefined) throw new Error("vector chain has no removable member");
    const { entry } = await signEntryAt({
      seq: warm.headSeq + 1,
      prevHashHex: warm.headHashHex,
      actorUserId: "user-owner-0001",
      operation: { op: "remove_member", payload: { targetUserId: target } },
    });
    const appended = await appendEntry(vectorProjectId, warm.headHashHex, entry);
    expect(appended.status).toBe(200);
    const after = await readChain();
    expect(after.headSeq).toBe(warm.headSeq + 1);
    expect(after.entries.slice(0, warm.headSeq)).toEqual(warm.entries);
    expect(after.entries[warm.headSeq]).toEqual(entry);

    // もう一度キャッシュを破棄してもフルロードが同一結果に到達する
    await evictDurableObject(stub);
    const coldAfter = await readChain();
    expect(coldAfter).toEqual(after);
  });
});

describe("チェーン API の認可(AUTH_SPEC §11)", () => {
  it("rejects unauthenticated requests with 401", async () => {
    const genesis = vectorEntries[0];
    const entry2 = vectorEntries[1];
    if (genesis === undefined || entry2 === undefined) throw new Error("missing vectors");
    const get = await SELF.fetch(`${BASE}/projects/${vectorProjectId}/chain`);
    expect(get.status).toBe(401);
    const init = await initChain(toWireEntry(genesis), { headers: {} });
    expect(init.status).toBe(401);
    const append = await appendEntry(vectorProjectId, "0".repeat(64), toWireEntry(entry2), {});
    expect(append.status).toBe(401);
  });

  it("conceals the project from authenticated non-members with 404 (§11-2)", async () => {
    await replayVectorChain(1);
    await seedUser("user-stranger-0009", 9009);
    const strangerToken = await deviceToken(9009);

    const get = await getChain(vectorProjectId, bearer(strangerToken));
    expect(get.status).toBe(404);

    // 署名は検証されるより先にメンバーシップで拒否される(現ヘッド情報も返さない)
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    const forged: ChainEntry = {
      suite: "maruhi/v1",
      seq: 2,
      prevHashHex: genesis.entry_hash_hex,
      op: "remove_member",
      actor: { userId: "user-stranger-0009", keyFingerprintHex: "ab".repeat(16) },
      payload: { targetUserId: "user-owner-0001" },
      timestampMs: 1754006400000,
      signatureHex: "12".repeat(64),
    };
    const append = await appendEntry(
      vectorProjectId,
      "f".repeat(64),
      forged,
      bearer(strangerToken),
    );
    expect(append.status).toBe(404);
  });

  it("removed members are concealed too: the §11-2 mapping of actor-not-member(複合経由)", async () => {
    // seq 5 で user-member-0002 は削除される。以降の書き込み(rotate は複合経由)は
    // チェーン検証(422)ではなく、メンバーシップ判定の 404 で拒否される(存在秘匿)
    const nonmember = vectorAuthzNegatives.find((n) => n.name === "authz-nonmember-actor");
    if (nonmember === undefined) throw new Error("missing authz-nonmember-actor vector");
    const { head } = await replayVectorChain(nonmember.entry.seq - 1);
    const { entry } = await resignEntryAt(toWireEntry(nonmember.entry), head.seq + 1, head.hashHex);
    if (entry.op !== "rotate_epoch") throw new Error("expected a rotate_epoch negative");
    const response = await submitComposite(entry, ["user-owner-0001", "user-admin-0003"]);
    expect(response.status).toBe(404);
  });

  it("rejects an append whose entry actor differs from the principal (403 actor-mismatch §11-1)", async () => {
    await replayVectorChain(4);
    const entry5 = vectorEntries[4];
    if (entry5 === undefined) throw new Error("missing vector entry 5");
    // entry5(remove_member)の actor は user-owner-0001。member のトークンで
    // 送ると一致しない
    const response = await appendEntry(
      vectorProjectId,
      entry5.prev_hash_hex,
      toWireEntry(entry5),
      bearer(tokenFor("user-member-0002")),
    );
    expect(response.status).toBe(403);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("actor-mismatch");
  });

  it("enforces token scopes: read scope can get but cannot append (§9-2)", async () => {
    await replayVectorChain(1);
    const readOnly: readonly TokenScope[] = [{ project: vectorProjectId, permission: "read" }];
    const readToken = await deviceToken(9001, readOnly);

    const get = await getChain(vectorProjectId, bearer(readToken));
    expect(get.status).toBe(200);

    const entry2 = vectorEntries[1];
    if (entry2 === undefined) throw new Error("missing vector entry 2");
    const append = await appendEntry(
      vectorProjectId,
      entry2.prev_hash_hex,
      toWireEntry(entry2),
      bearer(readToken),
    );
    expect(append.status).toBe(403);
    const body = (await append.json()) as { reason: string };
    expect(body.reason).toBe("insufficient-permission");
  });

  it("conceals projects outside the token's scope with 404 (§11-2)", async () => {
    await replayVectorChain(1);
    const otherScope: readonly TokenScope[] = [{ project: "ff".repeat(32), permission: "admin" }];
    const scopedToken = await deviceToken(9001, otherScope);
    const response = await getChain(vectorProjectId, bearer(scopedToken));
    expect(response.status).toBe(404);
  });

  it("conceals everything from an empty-scope token (§11-2)", async () => {
    await replayVectorChain(1);
    const emptyScopeToken = await deviceToken(9001, []);
    const response = await getChain(vectorProjectId, bearer(emptyScopeToken));
    expect(response.status).toBe(404);
  });

  it("distinguishes write from admin ops (§6 の op→必要権限表)", async () => {
    // seq 3(create_environment)・seq 4(rotate_epoch)は複合エンドポイント経由の
    // write 要求で、write スコープのトークンで通る。同じ write スコープでは
    // remove_member(admin 要求。汎用 append)が 403 になる — 全 op を
    // write(または admin)に潰す退行をここで判別する
    await replayVectorChain(2);
    const writeScope: readonly TokenScope[] = [{ project: "*", permission: "write" }];
    const memberWrite = await deviceToken(9002, writeScope);
    const vector3 = vectorEntries[2];
    const vector4 = vectorEntries[3];
    if (vector3 === undefined || vector4 === undefined) throw new Error("missing vectors");
    const entry3 = toWireEntry(vector3);
    if (entry3.op !== "create_environment") {
      throw new Error("unexpected vector ops");
    }
    const members = ["user-owner-0001", "user-member-0002"];
    const created = await submitComposite(entry3, members, {
      ...JSON_HEADERS,
      ...bearer(memberWrite),
    });
    expect(created.status).toBe(200);
    // 作成複合の境界 checkpoint(H+2)がヘッドを進めるため、rotate は実ヘッドで
    // 再署名する(op / payload / actor はベクターのまま)
    const createdHead = (await created.json()) as { headSeq: number; headHashHex: string };
    const { entry: entry4 } = await resignEntryAt(
      toWireEntry(vector4),
      createdHead.headSeq + 1,
      createdHead.headHashHex,
    );
    if (entry4.op !== "rotate_epoch") {
      throw new Error("unexpected vector ops");
    }
    const rotated = await submitComposite(entry4, members, {
      ...JSON_HEADERS,
      ...bearer(memberWrite),
    });
    expect(rotated.status).toBe(200);

    // seq 5 は remove_member(admin 要求)、actor は user-owner-0001
    const ownerWrite = await deviceToken(9001, writeScope);
    const entry5 = vectorEntries[4];
    if (entry5 === undefined) throw new Error("missing vector entry 5");
    const removal = await appendEntry(
      vectorProjectId,
      entry5.prev_hash_hex,
      toWireEntry(entry5),
      bearer(ownerWrite),
    );
    expect(removal.status).toBe(403);
    const body = (await removal.json()) as { reason: string };
    expect(body.reason).toBe("insufficient-permission");
  });

  it("requires admin scope for init (genesis = プロジェクト作成)", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    const writeScope: readonly TokenScope[] = [{ project: "*", permission: "write" }];
    const ownerWrite = await deviceToken(9001, writeScope);
    const response = await initChain(toWireEntry(genesis), { headers: bearer(ownerWrite) });
    expect(response.status).toBe(403);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("insufficient-permission");
  });

  it("accepts session-cookie auth with the CSRF header and rejects writes without it (§5)", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    const session = await loginSession(9001);

    // CSRF ヘッダーなしの書き込みは 403
    const headers = sessionHeaders(session);
    const withoutCsrf: Record<string, string> = { cookie: headers["cookie"] ?? "" };
    const rejected = await initChain(toWireEntry(genesis), {
      headers: { ...JSON_HEADERS, ...withoutCsrf },
    });
    expect(rejected.status).toBe(403);

    // CSRF ヘッダー付きは受理される(セッション = 本人のフルパワー)
    const accepted = await initChain(toWireEntry(genesis), {
      headers: { ...JSON_HEADERS, ...headers },
    });
    expect(accepted.status).toBe(200);
  });
});

describe("GET /projects/:projectId/chain", () => {
  it("returns 404 for a project that was never initialized", async () => {
    const response = await getChain("ab".repeat(32));
    expect(response.status).toBe(404);
  });

  it("returns 400 for a malformed project id", async () => {
    const response = await getChain("not-a-project-id");
    expect(response.status).toBe(400);
  });

  it("allows every chain-derived member including reader to fetch (§6.2)", async () => {
    await replayVectorChain(6);
    // seq 5 で user-admin-0003 が reader として追加され、seq 6 で change_role される。
    // どの時点でもチェーン導出メンバーであれば取得できる
    const response = await getChain(vectorProjectId, bearer(tokenFor("user-admin-0003")));
    expect(response.status).toBe(200);
  });
});

describe("CAS(§6.4 楽観ロック)", () => {
  it("rejects an append whose parent head is stale and reports the current head", async () => {
    await replayVectorChain(2);
    const entry2 = vectorEntries[1];
    const genesis = vectorEntries[0];
    if (entry2 === undefined || genesis === undefined) {
      throw new Error("missing vector entries");
    }
    // テスト時署名の remove_member(seq 3。汎用 append の対象 op)で CAS を検査する
    // (ベクター seq 3 は create_environment になり複合経由 — data.test.ts が担う)
    const { entry } = await signEntryAt({
      seq: 3,
      prevHashHex: entry2.entry_hash_hex,
      actorUserId: "user-owner-0001",
      operation: { op: "remove_member", payload: { targetUserId: "user-member-0002" } },
    });

    // 親を genesis ハッシュ(1 つ古いヘッド)にすると拒否され、現ヘッドが返る
    const stale = await appendEntry(vectorProjectId, genesis.entry_hash_hex, entry);
    expect(stale.status).toBe(409);
    const body = (await stale.json()) as { currentHeadSeq: number; currentHeadHashHex: string };
    expect(body.currentHeadSeq).toBe(2);
    expect(body.currentHeadHashHex).toBe(entry2.entry_hash_hex);

    // 正しい親で再試行すると受理される(クライアントの再同期・再試行の流れ)
    const retried = await appendEntry(vectorProjectId, entry2.entry_hash_hex, entry);
    expect(retried.status).toBe(200);
  });

  it("rejects a malformed parentHeadHashHex with 400 (schema — CAS 意味論より前)", async () => {
    await replayVectorChain(2);
    const entry2 = vectorEntries[1];
    if (entry2 === undefined) throw new Error("missing vector entries");
    const { entry } = await signEntryAt({
      seq: 3,
      prevHashHex: entry2.entry_hash_hex,
      actorUserId: "user-owner-0001",
      operation: { op: "remove_member", payload: { targetUserId: "user-member-0002" } },
    });
    // CAS の比較対象の形式は Sha256Hex(64 文字小文字 hex)で固定する(意図的な
    // 受理変更): 不正形式は 409(現ヘッド情報付き)へ到達せず schema 境界の 400
    for (const bad of ["ab".repeat(31), "AB".repeat(32), "not-hex"]) {
      const response = await appendEntry(vectorProjectId, bad, entry);
      expect(response.status).toBe(400);
    }
  });

  it("rejects an append to an uninitialized project with 404", async () => {
    const entry2 = vectorEntries[1];
    if (entry2 === undefined) throw new Error("missing vector entry 2");
    const response = await appendEntry("cd".repeat(32), "0".repeat(64), toWireEntry(entry2));
    expect(response.status).toBe(404);
  });
});

// create_environment / rotate_epoch の negative は複合エンドポイント経由になり、
// サーバーの判定順(§12-3 / §12-4)が合意規則(verifyChain)より先に働くケースが
// ある。ベクターの expected_reason(合意規則の理由コード)は crypto 層の 4 実行
// 環境テストが固定し、ここではサーバー受理面での期待(status + 種別)を固定する:
// - role 不足は DO の requireRole が verifyChain より先(403 insufficient-role)
// - 未知環境への rotate はデータ行の不在が先(404 EnvironmentNotFound —
//   行はチェーンと原子的に作られるため意味論は unknown-environment と一致)
// - dek_commitment_hex の形式違反は api-schema の hex Schema が先(400)
interface CompositeExpectation {
  readonly status: number;
  readonly reason?: string;
}

const compositeExpectations: Readonly<Record<string, CompositeExpectation>> = {
  // 削除済みメンバーは §11-2 の存在秘匿(上の専用テストと同じ 404)
  "authz-nonmember-actor": { status: 404 },
  "authz-reader-rotate-epoch": { status: 403, reason: "insufficient-role" },
  "authz-rotate-role-precedes-unknown": { status: 403, reason: "insufficient-role" },
  "authz-create-env-reader": { status: 403, reason: "insufficient-role" },
  "authz-create-env-role-precedes-duplicate": { status: 403, reason: "insufficient-role" },
  "authz-rotate-unknown-environment": { status: 404 },
  "authz-rotate-unknown-precedes-epoch": { status: 404 },
  "authz-create-env-duplicate": { status: 422, reason: "duplicate-environment" },
  "authz-epoch-rollback": { status: 422, reason: "epoch-out-of-sequence" },
  "authz-epoch-duplicate": { status: 422, reason: "epoch-out-of-sequence" },
  "authz-epoch-jump": { status: 422, reason: "epoch-out-of-sequence" },
  "authz-epoch-first-jump": { status: 422, reason: "epoch-out-of-sequence" },
  "create-env-commitment-uppercase-hex": { status: 400 },
  "create-env-commitment-bad-length": { status: 400 },
  "rotate-commitment-uppercase-hex": { status: 400 },
  "create-env-commitment-format-precedes-role": { status: 400 },
  "authz-field-too-long": { status: 422, reason: "invalid-payload" },
  "authz-actor-key-mismatch": { status: 422, reason: "actor-key-mismatch" },
};

/**
 * checkpoint op の汎用 append テスト(2026-08-28 — PR-M2 で standalone 受理へ
 * 移行): 固定長 hex の形式違反は api-schema の hex Schema が先に 400 で拒否する
 * (create-env-commitment-* の複合期待と同じ分担)。それ以外の合意規則 negative
 * (role / audit role / unknown / epoch / regression と検査順序)は crypto 層の
 * 4 実行環境テストが理由コードごと固定済みで、前提チェーン(checkpoint-baseline
 * 派生チェーン — タプル内容がダミー)は §16-2 の内容突合を通らず API では再生
 * できないため、ここでは繰り返さない。API 受理面(認可 2 水準・内容突合 5 理由・
 * 原子性・スナップショット保存)は data-checkpoint.test.ts が実データで固定する。
 */
function registerCheckpointAppendGuardTest(negative: (typeof vectorAuthzNegatives)[number]): void {
  const schemaRejected = [
    "checkpoint-manifest-hash-uppercase-hex",
    "checkpoint-values-digest-bad-length",
    "checkpoint-format-precedes-role",
  ].includes(negative.name);
  if (!schemaRejected) {
    return;
  }
  it(`rejects ${negative.name} at the wire schema (400)`, async () => {
    await replayVectorChain(1);
    const response = await appendEntry(
      vectorProjectId,
      negative.entry.prev_hash_hex,
      toWireEntry(negative.entry),
    );
    expect(response.status).toBe(400);
  });
}

describe("サーバー側検証(§6.4 = verifyChain 再実行)— 認可系 negative ベクター", () => {
  for (const negative of vectorAuthzNegatives) {
    const op = negative.entry.op;
    if (op === "checkpoint") {
      registerCheckpointAppendGuardTest(negative);
      continue;
    }
    const isComposite = op === "create_environment" || op === "rotate_epoch";
    if (isComposite) {
      const expectation = compositeExpectations[negative.name];
      if (expectation === undefined) {
        throw new Error(`missing composite expectation for ${negative.name}`);
      }
      it(`rejects ${negative.name} via the composite endpoint with ${expectation.status}${expectation.reason === undefined ? "" : ` (${expectation.reason})`}`, async () => {
        const { members, head } = await replayVectorChain(negative.entry.seq - 1);
        // 実ヘッドで再署名する(境界 checkpoint 挿入分の seq / prev のずれを吸収。
        // op / payload / actor ブロックはベクター negative のまま)
        const { entry } = await resignEntryAt(
          toWireEntry(negative.entry),
          head.seq + 1,
          head.hashHex,
        );
        if (entry.op !== "create_environment" && entry.op !== "rotate_epoch") {
          throw new Error("unexpected op");
        }
        const response = await submitComposite(entry, members);
        expect(response.status).toBe(expectation.status);
        if (expectation.reason !== undefined) {
          const body = (await response.json()) as { reason: string };
          expect(body.reason).toBe(expectation.reason);
        }
      });
      continue;
    }
    // actor が非メンバーのケースは §11-2 の存在秘匿(404)が verifyChain より先に働く
    const expectsConcealment = negative.expected_reason === "actor-not-member";
    const label = expectsConcealment
      ? `rejects ${negative.name} with 404 (§11-2 concealment)`
      : `rejects ${negative.name} with 422 (${negative.expected_reason})`;
    it(label, async () => {
      const { head } = await replayNegativePrefix(negative);
      // 実ヘッドで再署名する(境界 checkpoint 挿入分のずれを吸収 — 上の複合と同じ)
      const { entry } = await resignEntryAt(
        toWireEntry(negative.entry),
        head.seq + 1,
        head.hashHex,
      );
      const response = await appendEntry(vectorProjectId, entry.prevHashHex, entry);
      if (expectsConcealment) {
        expect(response.status).toBe(404);
        return;
      }
      expect(response.status).toBe(422);
      const body = (await response.json()) as { seq: number; reason: string };
      expect(body.reason).toBe(negative.expected_reason);
      expect(body.seq).toBe(entry.seq);
    });
  }

  it("rejects a tampered payload with 422 (bad-signature)", async () => {
    // ベクター negative "tampered-payload-role" の再構成: entry 2 の payload の
    // role を書き換え、署名は元のまま → 署名検証で拒否される
    await replayVectorChain(1);
    const genesis = vectorEntries[0];
    const entry2 = vectorEntries[1];
    if (genesis === undefined || entry2 === undefined) throw new Error("missing vectors");
    const wire = toWireEntry(entry2);
    if (wire.op !== "add_member") throw new Error("vector entry 2 should be add_member");
    const tampered: ChainEntry = {
      ...wire,
      payload: { ...wire.payload, role: "admin" },
    };
    const response = await appendEntry(vectorProjectId, genesis.entry_hash_hex, tampered);
    expect(response.status).toBe(422);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("bad-signature");
  });
});

describe("受理ポリシー(§6.4 サイズ上限)", () => {
  it("rejects an entry whose canonical bytes exceed 1 MiB with 413", async () => {
    await replayVectorChain(1);
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    // §6.1 のフィールド上限(1024 B)には違反するが、正規化は可能な巨大エントリ。
    // 受理ポリシー(1 MiB)の検査は verifyChain より先に行われるため 413 になる
    // (op は汎用 append の対象のもの — rotate_epoch は複合経由になったため
    // remove_member の巨大 targetUserId で構成する)
    const oversized: ChainEntry = {
      suite: "maruhi/v1",
      seq: 2,
      prevHashHex: genesis.entry_hash_hex,
      op: "remove_member",
      actor: { userId: "user-owner-0001", keyFingerprintHex: "ab".repeat(16) },
      payload: { targetUserId: "u".repeat(1_200_000) },
      timestampMs: 1754006400000,
      signatureHex: "12".repeat(64),
    };
    const response = await appendEntry(vectorProjectId, genesis.entry_hash_hex, oversized);
    expect(response.status).toBe(413);
    const body = (await response.json()) as { limitBytes: number };
    expect(body.limitBytes).toBe(MAX_ENTRY_CANONICAL_BYTES);
  });

  it("rejects a raw request body over the transport cap with a plain 413", async () => {
    const response = await SELF.fetch(`${BASE}/projects`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: `{"entry":"${"x".repeat(MAX_REQUEST_BODY_BYTES + 1024)}"}`,
    });
    expect(response.status).toBe(413);
  });

  it("enforces the transport cap on the measured stream, not the Content-Length header", async () => {
    // Content-Length を申告しないストリームボディ(chunked 相当)でも、実測で
    // 上限を強制して 413 になること(ヘッダー偽装・欠落による迂回の防止)
    const chunk = new TextEncoder().encode("x".repeat(64 * 1024));
    const chunkCount = Math.ceil((MAX_REQUEST_BODY_BYTES + 1024 * 1024) / chunk.length);
    let sent = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (sent >= chunkCount) {
          controller.close();
          return;
        }
        sent += 1;
        controller.enqueue(chunk);
      },
    });
    const response = await SELF.fetch(`${BASE}/projects`, {
      method: "POST",
      headers: JSON_HEADERS,
      body,
    });
    expect(response.status).toBe(413);
  });

  it("rejects an oversized genesis at init with 413 (worker-side pre-check)", async () => {
    const oversizedGenesis: ChainEntry = {
      suite: "maruhi/v1",
      seq: 1,
      prevHashHex: "0".repeat(64),
      op: "genesis",
      actor: { userId: "u".repeat(600_000), keyFingerprintHex: "ab".repeat(16) },
      payload: { encPubHex: "cd".repeat(32), sigPubHex: "ef".repeat(32) },
      timestampMs: 1754006400000,
      signatureHex: "12".repeat(64),
    };
    // actor.userId をもう 1 フィールド分肥大させ、正規化 1 MiB を超えさせる
    const second: ChainEntry = {
      ...oversizedGenesis,
      actor: { ...oversizedGenesis.actor, userId: "u".repeat(600_000) + "v".repeat(500_000) },
    };
    // サイズの先行検査は actor 一致(403)より先に働く(資源保護が優先)
    const response = await initChain(second);
    expect(response.status).toBe(413);
    const body = (await response.json()) as { limitBytes: number };
    expect(body.limitBytes).toBe(MAX_ENTRY_CANONICAL_BYTES);
  });

  it("rejects an append once cumulative canonical bytes would exceed the cap", async () => {
    // 有効な 2 エントリのチェーンを作り、蓄積バイト数だけを上限相当へ引き上げる
    // (§11-2 によりメンバーシップ判定 = チェーン導出が受理判定より先に走るため、
    // 保存チェーン自体は検証可能でなければならない)
    await replayVectorChain(2);
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(vectorProjectId));
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec(
        "UPDATE chain_entries SET canonical_bytes = ? WHERE seq = 1",
        MAX_CHAIN_TOTAL_CANONICAL_BYTES,
      );
    });
    // 保存行の直接改変(append-only 不変条件の外)はインスタンスの差分ロード
    // キャッシュに映らないため、DO 再起動相当の退去でフルロードに戻す
    await evictDurableObject(stub);
    const entry2 = vectorEntries[1];
    if (entry2 === undefined) throw new Error("missing vector entries");
    const { entry } = await signEntryAt({
      seq: 3,
      prevHashHex: entry2.entry_hash_hex,
      actorUserId: "user-owner-0001",
      operation: { op: "remove_member", payload: { targetUserId: "user-member-0002" } },
    });
    const response = await appendEntry(vectorProjectId, entry2.entry_hash_hex, entry);
    expect(response.status).toBe(422);
    const body = (await response.json()) as { maxTotalBytes: number };
    expect(body.maxTotalBytes).toBe(MAX_CHAIN_TOTAL_CANONICAL_BYTES);
  });

  it("caps the total entry count (§6.4 receipt policy, unit-level)", () => {
    // 10,000 本の有効チェーンの実生成は非現実的なため、判定関数を直接検証する
    // (プラミングは累積バイト数のテストが同じ分岐を通している)
    expect(chainCapacityExceeded(MAX_CHAIN_ENTRIES, 0, 10)).toBe(true);
    expect(chainCapacityExceeded(MAX_CHAIN_ENTRIES - 1, 0, 10)).toBe(false);
    expect(chainCapacityExceeded(1, MAX_CHAIN_TOTAL_CANONICAL_BYTES, 1)).toBe(true);
  });
});
