// サーバー側検証(CRYPTO_SPEC §6.4 = verifyChain 再実行)— 認可系 negative
// ベクターのうち、汎用 append 経由(checkpoint の wire schema 拒否を含む)の
// 拒否テスト。複合エンドポイント経由の negative は
// membership-negatives-composite.test.ts。
// 共有 fixture・ベクター再生ヘルパは support/membership-scenario.ts(分割の
// 動機はシナリオモジュール冒頭を参照)。

import type { ChainEntry } from "@maruhi/crypto";
import { describe, expect, it } from "vitest";

import {
  DEVICE_OPS,
  prefixReplayable,
  toWireEntry,
  vectorAuthzNegatives,
  vectorEntries,
  vectorProjectId,
} from "./support/chain-vectors.ts";
import { resignEntryAt } from "./support/data-crypto.ts";
import {
  appendEntry,
  registerMembershipScenario,
  remapProposalRef,
  replayNegativePrefix,
  replayVectorChain,
} from "./support/membership-scenario.ts";

registerMembershipScenario();

/**
 * checkpoint op の汎用 append テスト: 固定長 hex の形式違反は api-schema の
 * hex Schema が先に 400 で拒否する
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

/**
 * ES / PF1(2026-09-14)の構造 negative のうち、api-schema の閉集合リテラル
 * (scope_kind / ops / 内側 op)・固定長 hex(proposal_hash_hex)・内側 payload の
 * 必須フィールドが verifyChain より先に 400 で拒否するもの(create-env-commitment-* /
 * checkpoint-* の hex Schema と同じ分担)。合意規則としての `invalid-payload` は
 * crypto 層の 4 実行環境テストが理由コードごと固定する
 */
/**
 * 構造 negative のうち、テスト時の署名 API(signChainEntry)が受け付けない形
 * (負の expires_at_ms は §2.1 の符号化対象外)。構造検査は署名検証に先行するため、
 * 再署名せずに送っても理由コードは構造段のもの(invalid-payload)で確定する
 */
const UNSIGNABLE_STRUCTURE_NEGATIVES: ReadonlySet<string> = new Set(["propose-expires-negative"]);

const WIRE_SCHEMA_REJECTED: ReadonlySet<string> = new Set([
  "scope-kind-unknown",
  "policy-ops-rotate",
  "policy-ops-unknown-op",
  "propose-inner-op-unknown",
  "propose-inner-op-nested",
  "propose-inner-shape-precedes-role",
  "approve-hash-uppercase",
  "approve-hash-bad-length",
  // 端末鍵(DK): 閉集合リテラル(role_cap / ops)・固定長 hex(公開鍵・FP)は api-schema が先に 400
  "add-device-role-cap-unknown",
  "add-device-enc-pub-bad-length",
  "add-device-sig-pub-uppercase-hex",
  "add-device-format-precedes-actor",
  "revoke-device-fp-bad-length",
  "policy-ops-add-device",
  "policy-ops-revoke-device",
]);

/**
 * 端末鍵の 2 op(CRYPTO_SPEC §6.2 — 2026-09-19 DK)の negative と、`set_approval_policy` の
 * ops に端末 op を書く negative: サーバーは K3 まで 2 op を受理しない
 * (DeviceOpsNotAccepted 422 — 設計録 dk-design.md §7 K2-6。ES K2-10 の先例)ので、
 * 合意規則の理由コードではなく受理ガードでの拒否を固定する(wire schema が先に拒む形は
 * 400)。前提チェーン(端末 op を含む派生チェーン)は再生できないため、正規ヘッド 24 の
 * 直後へ原本(再署名なし)を送る — ガードは署名検証・合意規則より前に立つ。K3 で受理
 * ガードを外すときに本関数ごと外し、通常の 422 (expected_reason) 経路へ戻す
 */
function registerDeviceOpsGuardTest(negative: AuthzNegative): void {
  const schemaRejected = WIRE_SCHEMA_REJECTED.has(negative.name);
  const label = schemaRejected
    ? "at the wire schema (400)"
    : "with 422 (DeviceOpsNotAccepted — K3)";
  it(`rejects ${negative.name} ${label}`, async () => {
    const { head } = await replayVectorChain(vectorEntries.length);
    const response = await appendEntry(vectorProjectId, head.hashHex, {
      ...toWireEntry(negative.entry),
      seq: head.seq + 1,
      prevHashHex: head.hashHex,
    });
    if (schemaRejected) {
      expect(response.status).toBe(400);
      return;
    }
    expect(response.status).toBe(422);
    const body = (await response.json()) as { _tag: string; op: string };
    expect(body["_tag"]).toBe("DeviceOpsNotAccepted");
    expect(body.op).toBe(negative.entry.op);
  });
}

/** 端末 op を `set_approval_policy` の ops に書く negative(構造検査 — 前提チェーンは端末派生)。 */
const POLICY_OPS_DEVICE_NEGATIVES: ReadonlySet<string> = new Set([
  "policy-ops-add-device",
  "policy-ops-revoke-device",
]);

type AuthzNegative = (typeof vectorAuthzNegatives)[number];

/** 前提チェーンを再生し、seq / prev だけ実ヘッドへ付け替えた原本(再署名なし)を送る。 */
async function appendUnsignedAtHead(negative: AuthzNegative): Promise<Response> {
  const { head } = await replayNegativePrefix(negative);
  return appendEntry(vectorProjectId, head.hashHex, {
    ...toWireEntry(negative.entry),
    seq: head.seq + 1,
    prevHashHex: head.hashHex,
  });
}

/**
 * 署名 API が拒む形(負の expires_at_ms)は再署名できない。構造検査は署名検証に
 * 先行する(§6.3 の検証段順)ので、原本を送れば理由コードは構造段のもので確定する
 */
function registerStructureBeforeSignatureTest(negative: AuthzNegative): void {
  it(`rejects ${negative.name} with 422 (${negative.expected_reason}) before the signature`, async () => {
    const response = await appendUnsignedAtHead(negative);
    expect(response.status).toBe(422);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe(negative.expected_reason);
  });
}

function registerWireSchemaRejectTest(negative: AuthzNegative): void {
  it(`rejects ${negative.name} at the wire schema (400)`, async () => {
    const response = await appendUnsignedAtHead(negative);
    expect(response.status).toBe(400);
  });
}

/** 合意規則(verifyChain)での拒否 — 実ヘッドで再署名して送り、理由コードと seq を固定する。 */
function registerConsensusRejectTest(negative: AuthzNegative): void {
  // actor が非メンバーのケースは §11-2 の存在秘匿(404)が verifyChain より先に働く
  const expectsConcealment = negative.expected_reason === "actor-not-member";
  const label = expectsConcealment
    ? `rejects ${negative.name} with 404 (§11-2 concealment)`
    : `rejects ${negative.name} with 422 (${negative.expected_reason})`;
  it(label, async () => {
    const { head } = await replayNegativePrefix(negative);
    // 実ヘッドで再署名する(境界 checkpoint 挿入分のずれを吸収 — 複合側と同じ)。
    // approve / withdraw の参照先は再生時の実 hash へ付け替える
    const { entry } = await resignEntryAt(
      remapProposalRef(toWireEntry(negative.entry)),
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

/**
 * 認可 negative の分割(pullfrog 第 3 巡): 判定が広がっても suite が静かに空に
 * ならないよう、各分岐の件数を厳密に固定する。K5(2026-09-16)で受理ガードを
 * 外し、四眼 op の negative と四眼 op を含む派生チェーンを前提とする negative は
 * すべて通常の経路(合意規則の 422 / wire schema の 400 / 署名前の構造段)へ戻した
 * (K2-10 の `skipped` 58 + `fourEyesGuard` 7 = 65 件の内訳: consensus +57、
 * wireSchema +7、structureBeforeSignature +1)。
 *
 * 2026-09-20 DK K2(認可 negative +57): 端末 op の negative(41)+ ops に端末 op を書く
 * negative(2)は受理ガード(`deviceOpsGuard` — wire schema が先の 7 件を含む)、
 * checkpoint(+1)/ create・rotate(+3)は既存の分岐(複合側は端末派生チェーンを
 * skip — membership-negatives-composite.test.ts)、端末派生チェーンを前提とする残り
 * (10)は再生できないため `skipped`(合意規則は crypto 層の 4 実行環境テストが固定)。
 * K3 で受理ガードを外すときは `skipped` を 0 にし、`deviceOpsGuard` の分を `consensus` /
 * `wireSchema` へ戻す(ES K2-10 → K5 と同じ手順)
 */
const EXPECTED_PARTITION = {
  checkpoint: 21,
  composite: 27,
  deviceOpsGuard: 43,
  skipped: 10,
  structureBeforeSignature: 1,
  wireSchema: 8,
  consensus: 104,
} as const;

type PartitionBucket = keyof typeof EXPECTED_PARTITION;

/**
 * negative の分岐(判定順は固定): checkpoint → 複合(create / rotate)→ 端末鍵(DK)の
 * 2 op と ops に端末 op を書く negative(K3 までサーバーが受理しない — DeviceOpsNotAccepted
 * 422。設計録 dk-design.md §7 K2-6。(a) 受理ガード / wire schema での拒否を固定、(b) 前提
 * チェーン自体が端末 op の受理を要するものは再生できないため `skipped`。K3 で両分岐ごと
 * 外す)→ 四眼(PF1)の 4 op と四眼 op を含む派生チェーンは K5 からサーバーが再生・受理する
 * (propose の受理ポリシーは固定時刻のベクターを拒まない — expires_at_ms は上界の内側で、
 * 失効済みの提案は pending 上限の計算から除外されるだけ。設計録 es-design.md §11 K5-C)
 */
function bucketOf(negative: AuthzNegative): PartitionBucket {
  const op = negative.entry.op;
  if (op === "checkpoint") {
    return "checkpoint";
  }
  if (op === "create_environment" || op === "rotate_epoch") {
    return "composite";
  }
  if (DEVICE_OPS.has(op) || POLICY_OPS_DEVICE_NEGATIVES.has(negative.name)) {
    return "deviceOpsGuard";
  }
  if (!prefixReplayable(negative)) {
    return "skipped";
  }
  if (UNSIGNABLE_STRUCTURE_NEGATIVES.has(negative.name)) {
    return "structureBeforeSignature";
  }
  return WIRE_SCHEMA_REJECTED.has(negative.name) ? "wireSchema" : "consensus";
}

/** 分岐ごとの登録(複合は membership-negatives-composite.test.ts、skipped は crypto 層のみ)。 */
const REGISTER_BY_BUCKET: Record<PartitionBucket, (negative: AuthzNegative) => void> = {
  checkpoint: registerCheckpointAppendGuardTest,
  composite: () => undefined,
  deviceOpsGuard: registerDeviceOpsGuardTest,
  skipped: () => undefined,
  structureBeforeSignature: registerStructureBeforeSignatureTest,
  wireSchema: registerWireSchemaRejectTest,
  consensus: registerConsensusRejectTest,
};

describe("サーバー側検証(§6.4)— 認可系 negative ベクター(汎用 append 経由)", () => {
  const partition: Record<PartitionBucket, number> = {
    checkpoint: 0,
    composite: 0,
    deviceOpsGuard: 0,
    skipped: 0,
    structureBeforeSignature: 0,
    wireSchema: 0,
    consensus: 0,
  };
  for (const negative of vectorAuthzNegatives) {
    const bucket = bucketOf(negative);
    partition[bucket] += 1;
    REGISTER_BY_BUCKET[bucket](negative);
  }

  it("partitions the authz negatives as expected (K5 — 四眼 op を含めて全件を再生する。DK K2 — 端末 op は受理ガード)", () => {
    expect(partition).toEqual(EXPECTED_PARTITION);
    expect(Object.values(partition).reduce((a, b) => a + b, 0)).toBe(vectorAuthzNegatives.length);
  });

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
