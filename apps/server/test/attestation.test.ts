// ヘッド申告の受理・保存・配布(CRYPTO_SPEC §6.4 / §6.6、AUTH_SPEC §16-1)の
// 統合テスト(@cloudflare/vitest-plugin — workerd 実環境)。session-27 §13-5 の申告項:
// 単調受理(後退 409・冪等 204)・remove 時の行削除・現メンバーのみ配布・
// 受理時刻非配布・reader の read スコープ提出可・レート制限。
//
// チェーンは attestation に必要な最小形(genesis → add_member member →
// add_member reader — 環境・複合は不要)をベクター鍵のテスト時署名で作る。

import type { TokenScope } from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { importSigningKeyPair, signHeadAttestation } from "@maruhi/crypto";
import { vectorKeys } from "@maruhi/crypto/test-support";
import { env, runInDurableObject, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { MAX_ATTESTATIONS_PER_MEMBER_PER_WINDOW } from "../src/policy.ts";
import {
  BASE,
  bearer,
  cliToken,
  JSON_HEADERS,
  resetAuthDb,
  seedOrgMember,
  seedUser,
} from "./support/auth.ts";
import { toWireEntry, vectorEntries, vectorProjectId } from "./support/chain-vectors.ts";
import { hexBytes, resignEntryAt, signEntryAt } from "./support/data-crypto.ts";
import { resetProjectDo } from "./support/project-do.ts";

const ORG = "org-attest-0001";
const OWNER = "user-owner-0001";
const MEMBER = "user-member-0002";
const READER = "user-admin-0003"; // change_role を追記しないため reader のまま使う
const GITHUB_IDS: Record<string, number> = { [OWNER]: 9001, [MEMBER]: 9002, [READER]: 9003 };

let tokens: Record<string, string> = {};

function tokenFor(userId: string): string {
  const token = tokens[userId];
  if (token === undefined) {
    throw new Error(`no seeded token for ${userId}`);
  }
  return token;
}

interface Head {
  readonly seq: number;
  readonly hashHex: string;
}

/** genesis → add_member(member)→ add_member(reader)の最小チェーンを立てる。 */
async function setupChain(): Promise<Head> {
  const genesis = vectorEntries[0];
  const addMember = vectorEntries[1];
  const addReader = vectorEntries[5]; // add_member user-admin-0003 role reader
  if (genesis === undefined || addMember === undefined || addReader === undefined) {
    throw new Error("missing vector entries");
  }
  const init = await SELF.fetch(`${BASE}/projects`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...bearer(tokenFor(OWNER)) },
    body: JSON.stringify({ orgId: ORG, entry: toWireEntry(genesis) }),
  });
  expect(init.status).toBe(200);
  const second = await appendEntry(genesis.entry_hash_hex, toWireEntry(addMember));
  expect(second.status).toBe(200);
  const reader = await resignEntryAt(toWireEntry(addReader), 3, addMember.entry_hash_hex);
  const third = await appendEntry(addMember.entry_hash_hex, reader.entry);
  expect(third.status).toBe(200);
  return { seq: 3, hashHex: reader.hash };
}

const appendEntry = (
  parentHeadHashHex: string,
  entry: ChainEntry,
  headers?: Record<string, string>,
): Promise<Response> =>
  SELF.fetch(`${BASE}/projects/${vectorProjectId}/chain/entries`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...(headers ?? bearer(tokenFor(entry.actor.userId))) },
    body: JSON.stringify({ parentHeadHashHex, entry }),
  });

/** attester の鍵で §6.6 の申告を署名する(project_id = genesis ハッシュ)。 */
async function signAttestation(attesterUserId: string, head: Head): Promise<string> {
  const keys = vectorKeys[attesterUserId];
  if (keys === undefined) {
    throw new Error(`no vector keys for ${attesterUserId}`);
  }
  const pair = await importSigningKeyPair({
    publicKey: hexBytes(keys.sig_pub_hex),
    privateSeed: hexBytes(keys.sig_sk_seed_hex),
  });
  if (!pair.ok) {
    throw new Error("key import failed");
  }
  const signed = await signHeadAttestation({
    context: {
      suite: "maruhi/v1",
      projectId: vectorProjectId,
      attesterUserId,
      chainHeadHashHex: head.hashHex,
      chainHeadSeq: head.seq,
    },
    signingKey: pair.value.privateKey,
  });
  if (!signed.ok) {
    throw new Error("attestation signing failed");
  }
  return signed.value;
}

const putAttestation = (
  body: Record<string, unknown>,
  headers: Record<string, string>,
  projectId: string = vectorProjectId,
): Promise<Response> =>
  SELF.fetch(`${BASE}/projects/${projectId}/head-attestation`, {
    method: "PUT",
    headers: { ...JSON_HEADERS, ...headers },
    body: JSON.stringify(body),
  });

async function submitAttestation(
  attesterUserId: string,
  head: Head,
  headers?: Record<string, string>,
): Promise<Response> {
  const signatureHex = await signAttestation(attesterUserId, head);
  return putAttestation(
    { suite: "maruhi/v1", chainHeadHashHex: head.hashHex, chainHeadSeq: head.seq, signatureHex },
    headers ?? bearer(tokenFor(attesterUserId)),
  );
}

interface WireAttestation {
  readonly suite: string;
  readonly attesterUserId: string;
  readonly attesterKeyFingerprintHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
}

async function fetchAttestations(asUserId: string = OWNER): Promise<readonly WireAttestation[]> {
  const response = await SELF.fetch(`${BASE}/projects/${vectorProjectId}/chain`, {
    headers: bearer(tokenFor(asUserId)),
  });
  expect(response.status).toBe(200);
  const body = (await response.json()) as { attestations?: readonly WireAttestation[] };
  expect(body.attestations).toBeDefined();
  return body.attestations ?? [];
}

beforeEach(async () => {
  await resetProjectDo(vectorProjectId);
  await resetAuthDb();
  tokens = {};
  for (const [userId, githubId] of Object.entries(GITHUB_IDS)) {
    await seedUser(userId, githubId);
    tokens[userId] = await cliToken(githubId);
  }
  await seedOrgMember(ORG, OWNER, "member");
});

describe("PUT /projects/:projectId/head-attestation(受理 — §6.4 / §16-1)", () => {
  it("reader が read スコープのトークンで提出でき、配布に attester 情報付きで載る(受理時刻は載らない)", async () => {
    const head = await setupChain();
    const readOnly: readonly TokenScope[] = [{ project: vectorProjectId, permission: "read" }];
    const readToken = await cliToken(GITHUB_IDS[READER] ?? 0, readOnly);
    const response = await submitAttestation(READER, head, bearer(readToken));
    expect(response.status).toBe(204);

    const attestations = await fetchAttestations();
    expect(attestations).toHaveLength(1);
    const readerKeys = vectorKeys[READER];
    expect(attestations[0]).toMatchObject({
      suite: "maruhi/v1",
      attesterUserId: READER,
      attesterKeyFingerprintHex: readerKeys?.key_fingerprint_hex,
      chainHeadHashHex: head.hashHex,
      chainHeadSeq: head.seq,
    });
    // 受理時刻は配布しない(§16-1 — 行動情報の限定)。ワイヤに時刻系キーが
    // 一切現れないことをキー集合で固定する
    expect(Object.keys(attestations[0] ?? {}).toSorted()).toEqual([
      "attesterKeyFingerprintHex",
      "attesterUserId",
      "chainHeadHashHex",
      "chainHeadSeq",
      "signatureHex",
      "suite",
    ]);
  });

  it("seq は単調前進のみ: 前進 = 上書き・同一 seq = 冪等 204・後退 = 409(保存済み seq)", async () => {
    const head = await setupChain();
    const head2 = { seq: 2, hashHex: vectorEntries[1]?.entry_hash_hex ?? "" };
    expect((await submitAttestation(OWNER, head2)).status).toBe(204);
    // 前進(head 3)は upsert — メンバーごと最新 1 行
    expect((await submitAttestation(OWNER, head)).status).toBe(204);
    // 同一 seq の再提出は冪等 204(リトライ安全 — 黙って握り潰す 200 ではなく
    // 同一内容の再送として成功)
    expect((await submitAttestation(OWNER, head)).status).toBe(204);
    // 後退は 409 + 保存済み seq(床破損・並行 CLI の徴候を静かに握り潰さない)
    const regressed = await submitAttestation(OWNER, head2);
    expect(regressed.status).toBe(409);
    expect(await regressed.json()).toMatchObject({
      _tag: "AttestationRegression",
      storedSeq: 3,
    });
    // 保存はメンバーごと最新 1 行のみ
    const attestations = await fetchAttestations();
    expect(attestations).toHaveLength(1);
    expect(attestations[0]?.chainHeadSeq).toBe(3);
  });

  it("受理検証: 署名壊れ = 422 signature-invalid、未知ヘッド = 422 chain-head-unknown", async () => {
    const head = await setupChain();
    const good = await signAttestation(OWNER, head);
    const tampered = `${good.slice(0, -2)}${good.endsWith("00") ? "01" : "00"}`;
    const badSignature = await putAttestation(
      {
        suite: "maruhi/v1",
        chainHeadHashHex: head.hashHex,
        chainHeadSeq: head.seq,
        signatureHex: tampered,
      },
      bearer(tokenFor(OWNER)),
    );
    expect(badSignature.status).toBe(422);
    expect(await badSignature.json()).toMatchObject({ reason: "signature-invalid" });

    // seq は自チェーン内だがハッシュ不一致(有効署名)= chain-head-unknown
    const bogusHead = { seq: head.seq, hashHex: "ab".repeat(32) };
    const mismatch = await submitAttestation(OWNER, bogusHead);
    expect(mismatch.status).toBe(422);
    expect(await mismatch.json()).toMatchObject({ reason: "chain-head-unknown" });

    // seq が現ヘッドより先(有効署名)も chain-head-unknown(§6.4 — サーバーに
    // 再同期分岐はない)
    const future = await submitAttestation(OWNER, { seq: 9, hashHex: "cd".repeat(32) });
    expect(future.status).toBe(422);
    expect(await future.json()).toMatchObject({ reason: "chain-head-unknown" });
  });

  it("他人の user_id では検証が成立しない(呼び出し主体 = attester の構造的強制)", async () => {
    const head = await setupChain();
    // MEMBER の鍵で署名した申告を OWNER のトークンで提出する — サーバーは
    // 署名対象の attester_user_id に呼び出し主体(OWNER)を用いるため署名不一致
    const signatureHex = await signAttestation(MEMBER, head);
    const response = await putAttestation(
      { suite: "maruhi/v1", chainHeadHashHex: head.hashHex, chainHeadSeq: head.seq, signatureHex },
      bearer(tokenFor(OWNER)),
    );
    expect(response.status).toBe(422);
    expect(await response.json()).toMatchObject({ reason: "signature-invalid" });
  });

  it("非メンバー・未初期化プロジェクトへの提出は一律 404(§11-2)", async () => {
    await setupChain();
    await seedUser("user-outsider-0042", 9042);
    const outsiderToken = await cliToken(9042);
    const head = { seq: 1, hashHex: vectorEntries[0]?.entry_hash_hex ?? "" };
    const signatureHex = await signAttestation(OWNER, head);
    const body = {
      suite: "maruhi/v1",
      chainHeadHashHex: head.hashHex,
      chainHeadSeq: head.seq,
      signatureHex,
    };
    expect((await putAttestation(body, bearer(outsiderToken))).status).toBe(404);
    expect((await putAttestation(body, bearer(tokenFor(OWNER)), "cd".repeat(32))).status).toBe(404);
  });

  it("メンバーあたり固定窓(60/時)を超過すると 429(他メンバーの窓は独立)", async () => {
    const head = await setupChain();
    // 窓は DO の SQLite 行 — 60 回の実 PUT の代わりに満杯の窓を直接シードする
    // (窓の意味論そのもの — 判定・巻き戻し — は data-store の実装を通る)
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(vectorProjectId));
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec(
        "INSERT INTO attestation_windows (attester_user_id, window_start, count) VALUES (?, ?, ?)",
        OWNER,
        Date.now(),
        MAX_ATTESTATIONS_PER_MEMBER_PER_WINDOW,
      );
    });
    const limited = await submitAttestation(OWNER, head);
    expect(limited.status).toBe(429);
    const body = (await limited.json()) as { retryAfterSeconds: number };
    expect(body.retryAfterSeconds).toBeGreaterThan(0);
    // 窓はメンバー単位 — 他メンバーは影響を受けない
    expect((await submitAttestation(MEMBER, head)).status).toBe(204);
  });
});

describe("配布と remove 時の掃除(§6.4 / §16-1)", () => {
  it("remove_member 受理で対象の申告行が削除され、以後の提出も 404(非メンバー)", async () => {
    const head = await setupChain();
    expect((await submitAttestation(MEMBER, head)).status).toBe(204);
    expect((await submitAttestation(OWNER, head)).status).toBe(204);
    expect((await fetchAttestations()).map((a) => a.attesterUserId).toSorted()).toEqual([
      MEMBER,
      OWNER,
    ]);

    const removal = await signEntryAt({
      seq: 4,
      prevHashHex: head.hashHex,
      actorUserId: OWNER,
      operation: { op: "remove_member", payload: { targetUserId: MEMBER } },
    });
    expect((await appendEntry(head.hashHex, removal.entry)).status).toBe(200);

    // 行は受理副作用で削除済み(現メンバーのみ配布 — チェーン導出真実への収束)
    expect((await fetchAttestations()).map((a) => a.attesterUserId)).toEqual([OWNER]);
    // 削除済みメンバーの再提出は §11-2 の一律 404
    const resubmit = await submitAttestation(MEMBER, { seq: 4, hashHex: removal.hash });
    expect(resubmit.status).toBe(404);
  });
});
