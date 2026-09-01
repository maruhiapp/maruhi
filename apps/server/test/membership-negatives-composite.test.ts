// サーバー側検証(CRYPTO_SPEC §6.4 = verifyChain 再実行)— 認可系 negative
// ベクターのうち、複合エンドポイント経由(create_environment / rotate_epoch)の
// 拒否テスト。汎用 append 経由の negative は membership-negatives-append.test.ts。
// 共有 fixture・ベクター再生ヘルパは support/membership-scenario.ts(分割の
// 動機はシナリオモジュール冒頭を参照)。

import { describe, expect, it } from "vitest";

import { toWireEntry, vectorAuthzNegatives } from "./support/chain-vectors.ts";
import { resignEntryAt } from "./support/data-crypto.ts";
import {
  registerMembershipScenario,
  replayVectorChain,
  submitComposite,
} from "./support/membership-scenario.ts";

registerMembershipScenario();

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
  // 削除済みメンバーは §11-2 の存在秘匿(membership-authz.test.ts の専用テストと
  // 同じ 404)
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

describe("サーバー側検証(§6.4)— 認可系 negative ベクター(複合経由)", () => {
  for (const negative of vectorAuthzNegatives) {
    const op = negative.entry.op;
    if (op !== "create_environment" && op !== "rotate_epoch") {
      continue;
    }
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
  }
});
