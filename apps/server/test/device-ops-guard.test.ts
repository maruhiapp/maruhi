// 端末鍵の 2 op(CRYPTO_SPEC §6.2 — 2026-09-19 DK)の受理ガード: サーバーは K3 の
// 受理副作用(ミラー 2 行・失効の要ローテーション検出・申告行の削除・端末数の受理
// ポリシー)まで `add_device` / `revoke_device` を受理しない(設計録 dk-design.md §7
// K2-6 — ES K2-10 の原則「サーバーが受理する op の集合 = 受理副作用が実装済みの op の
// 集合」)。worker ハンドラ(DeviceOpsNotAccepted 422)と DO の appendProgram
// (device-ops-not-accepted)の多層ガードを、有効な署名のエントリで固定する —
// ガードが合意規則より前に立つ(= 正しく署名した本人の端末追加でも拒否される)こと。
// K3 で受理ガードを外すときに本ファイルごと外す(membership-negatives-append.test.ts の
// deviceOpsGuard 分岐と同時)。

import { env, runInDurableObject } from "cloudflare:test";
import { Cause, Effect, Exit, Layer } from "effect";
import { describe, expect, it } from "vitest";

import { auditStoreLayer } from "../src/audit-store.ts";
import { appendProgram } from "../src/chain-do.ts";
import type { StateCache } from "../src/chain-store.ts";
import { chainStoreLayer } from "../src/chain-store.ts";
import type { DataRejection } from "../src/data-plane.ts";
import { dataStoreLayer } from "../src/data-store.ts";
import { makeStorageMeter, StorageMeter } from "../src/storage-guard.ts";
import { signEntryAt } from "./support/data-crypto.ts";
import { OWNER, projectId, requestJson, tokenOf } from "./support/data-fixture.ts";
import { fixture, registerDataScenario } from "./support/data-scenario.ts";

registerDataScenario();

/** 未登録のダミー鍵(実際の鍵素材ではない — CLAUDE.md)。 */
const FRESH_ENC_PUB_HEX = "5a".repeat(32);
const FRESH_SIG_PUB_HEX = "6a".repeat(32);

const signedEntry = (operation: Parameters<typeof signEntryAt>[0]["operation"]) =>
  signEntryAt({
    seq: fixture.head.seq + 1,
    prevHashHex: fixture.head.hashHex,
    actorUserId: OWNER,
    operation,
  });

const addDevice = () =>
  signedEntry({
    op: "add_device",
    payload: {
      encPubHex: FRESH_ENC_PUB_HEX,
      sigPubHex: FRESH_SIG_PUB_HEX,
      roleCap: "owner",
      scopeKind: "all",
      scopeEnvironmentIds: [],
    },
  });

const revokeDevice = () =>
  signedEntry({
    op: "revoke_device",
    payload: { targetUserId: OWNER, deviceFingerprintsHex: ["ab".repeat(16)] },
  });

function rejectionOf(exit: Exit.Exit<unknown, unknown>): DataRejection | null {
  if (Exit.isSuccess(exit)) {
    return null;
  }
  const error = Cause.squash(exit.cause) as { rejection?: DataRejection };
  return error.rejection ?? null;
}

describe("端末 op の受理ガード(DK K2 — K3 まで DeviceOpsNotAccepted)", () => {
  it("rejects a validly signed add_device / revoke_device at the worker with 422 DeviceOpsNotAccepted", async () => {
    for (const build of [addDevice, revokeDevice]) {
      const { entry } = await build();
      const response = await requestJson("POST", "/chain/entries", tokenOf(fixture.tokens, OWNER), {
        parentHeadHashHex: fixture.head.hashHex,
        entry,
      });
      expect(response.status).toBe(422);
      const body = (await response.json()) as { _tag: string; op: string };
      expect(body["_tag"]).toBe("DeviceOpsNotAccepted");
      expect(body.op).toBe(entry.op);
    }
  });

  it("rejects the same entries in the DO appendProgram (multi-layer guard, before verification)", async () => {
    const entries = [(await addDevice()).entry, (await revokeDevice()).entry];
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
    await runInDurableObject(stub, async (_instance, state) => {
      const cache: StateCache = { current: null, chain: null };
      const layers = Layer.mergeAll(
        chainStoreLayer(state.storage.sql, cache),
        dataStoreLayer(state.storage.sql),
        auditStoreLayer(state.storage.sql),
        Layer.succeed(
          StorageMeter,
          makeStorageMeter(() => 0),
        ),
      );
      for (const entry of entries) {
        const exit = await Effect.runPromiseExit(
          appendProgram(fixture.head.hashHex, entry, OWNER, cache).pipe(Effect.provide(layers)),
        );
        expect(rejectionOf(exit)).toEqual({ kind: "device-ops-not-accepted", op: entry.op });
      }
    });
  });
});
