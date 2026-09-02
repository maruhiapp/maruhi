// DO ストレージ総量ガード(AUTH_SPEC §12-8 — 2026-09-02 H2)のテスト。
//
// 8〜9 GB の実生成は非現実的なため 2 層で固定する:
// 1. 判定の純関数(storageGuardDecision — 閾値の境界)
// 2. 受理経路の結線: 実プロジェクト DO の SqlStorage(fixture が API 経由で作った
//    チェーン・環境・変数)に対し、実測量だけを固定値に差し替えた StorageMeter で
//    **実プログラム**を走らせ、「拒否が効く面」が limit-exceeded(project-storage-
//    bytes)で止まり、「拒否下でも受理し続ける面」(読み取り・削除・失効・
//    ローテーション・申告・checkpoint・設定)がガードを通過する(= 別の理由で
//    拒否されるか成功する)ことを固定する。ガードは各プログラムの先頭(メンバー
//    シップの直後・意味論的検査の前)に置かれているため、「limit-exceeded 以外の
//    結果」はガードが呼ばれていない(または admit した)ことの証拠になる。
//
// 警告(8 GB)の運用ログは静的メッセージ・DO インスタンス(= meter)ごと 1 回。

import {
  auditGroup,
  DataLimitExceededError,
  deksGroup,
  environmentsGroup,
  membershipGroup,
  schemaPolicyGroup,
  variablesGroup,
} from "@maruhi/api-schema";
import type { ChainEntry } from "@maruhi/crypto";
import { env, runInDurableObject } from "cloudflare:test";
import { Cause, Effect, Exit, Layer } from "effect";
import type { HttpApiEndpoint } from "effect/unstable/httpapi";
import { describe, expect, it, vi } from "vitest";

import { putHeadAttestationProgram } from "../src/attestation-accept.ts";
import type { AuditStore } from "../src/audit-store.ts";
import { auditStoreLayer } from "../src/audit-store.ts";
import { appendProgram, snapshotProgram } from "../src/chain-do.ts";
import type { ChainStore, StateCache } from "../src/chain-store.ts";
import { chainStoreLayer } from "../src/chain-store.ts";
import {
  createEnvironmentCompositeProgram,
  rotateEpochCompositeProgram,
} from "../src/composite-programs.ts";
import {
  toManifestInput,
  toMetaStatementInput,
  toValueInput,
  unwrapDataOutcome,
} from "../src/data-http.ts";
import type { DataActor, DataRejection } from "../src/data-plane.ts";
import type { DataStore } from "../src/data-store.ts";
import { dataStoreLayer } from "../src/data-store.ts";
import { DO_STORAGE_REJECT_BYTES, DO_STORAGE_WARN_BYTES } from "../src/policy.ts";
import { auditHeadProgram } from "../src/programs-audit.ts";
import {
  deleteDekWrapsProgram,
  listMyDekWrapsProgram,
  registerDekWrapsProgram,
} from "../src/programs-dek.ts";
import {
  deleteEnvironmentProgram,
  listEnvironmentsProgram,
  pullEnvironmentMetadataProgram,
  pullEnvironmentProgram,
  renameEnvironmentProgram,
} from "../src/programs-environment.ts";
import { dismissRotationFlagsProgram } from "../src/programs-rotation.ts";
import { getSchemaPolicyProgram, setSchemaPolicyProgram } from "../src/programs-schema-policy.ts";
import {
  activateVariableProgram,
  createVariableProgram,
  deleteVariableProgram,
  pushVersionProgram,
  renameVariableProgram,
} from "../src/programs-variable.ts";
import { makeStorageMeter, StorageMeter, storageGuardDecision } from "../src/storage-guard.ts";
import { signEntryAt } from "./support/data-crypto.ts";
import { createEnvironmentOk, OWNER, projectId, READER, STRANGER } from "./support/data-fixture.ts";
import {
  aadFor,
  createVariableOk,
  ENV,
  fixture,
  registerDataScenario,
  unsignedManifest,
  unsignedPayload,
  unsignedVariableStatement,
  VAR,
} from "./support/data-scenario.ts";

registerDataScenario();

const actor = (userId: string): DataActor => ({ userId });

/** DO 内プログラムが要求するサービス(chain-do.ts の DoServices からリース専用の ServerKey を除いたもの)。 */
type DoProgram<A, E> = Effect.Effect<A, E, ChainStore | DataStore | AuditStore | StorageMeter>;
type Runner = <A, E>(program: DoProgram<A, E>) => Promise<Exit.Exit<A, E>>;

/**
 * 実測量を固定した meter の下で、実プロジェクト DO の SqlStorage に対して
 * プログラムを走らせる(chain-do.ts のコンストラクタと同じ layer 構成 + meter の
 * 差し替え)。StateCache は呼び出しごとに空 = 保存行からのフルロード。
 */
async function runInProject<A>(
  databaseSizeBytes: number,
  body: (run: Runner) => Promise<A>,
): Promise<A> {
  const meter = makeStorageMeter(() => databaseSizeBytes);
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
  return await runInDurableObject(stub, async (_instance, state) => {
    const cache: StateCache = { current: null, chain: null };
    const layers = Layer.mergeAll(
      chainStoreLayer(state.storage.sql, cache),
      dataStoreLayer(state.storage.sql),
      auditStoreLayer(state.storage.sql),
      Layer.succeed(StorageMeter, meter),
    );
    const run: Runner = (program) => Effect.runPromiseExit(program.pipe(Effect.provide(layers)));
    return await body(run);
  });
}

/** Exit → 拒否理由(成功・defect は null)。 */
function rejectionOf(exit: Exit.Exit<unknown, unknown>): DataRejection | null {
  if (Exit.isSuccess(exit)) {
    return null;
  }
  const error = Cause.squash(exit.cause) as { rejection?: DataRejection };
  return error.rejection ?? null;
}

const STORAGE_REJECTION: DataRejection = {
  kind: "limit-exceeded",
  resource: "project-storage-bytes",
  limit: DO_STORAGE_REJECT_BYTES,
};

// ワイヤ形のダミー(support の wire 型は suite を string で持つ)→ DO 入力へ。
// ガードは署名検証より前に立つため、内容はゼロ署名のダミーで足りる
const dummyValueInput = (version: number) =>
  toValueInput({ ...unsignedPayload(aadFor(1, version)), suite: "maruhi/v1" });
const dummyVariableStatement = (variableId: string, name: string) =>
  toMetaStatementInput({ ...unsignedVariableStatement(variableId, name), suite: "maruhi/v1" });
const dummyManifest = () => toManifestInput(unsignedManifest());
const dummyEnvStatement = (name: string, status: "active" | "deleted" = "active") =>
  toMetaStatementInput({
    suite: "maruhi/v1",
    name,
    status,
    metaVersion: 2,
    prevMetaSigHashHex: "ab".repeat(32),
    chainHeadHashHex: fixture.head.hashHex,
    chainHeadSeq: fixture.head.seq,
    signatureHex: "00".repeat(64),
  });
const dummyWrap = {
  suite: "maruhi/v1" as const,
  epoch: 1,
  recipientUserId: STRANGER,
  recipientEncPubHex: "ab".repeat(32),
  encHex: "cd".repeat(32),
  ciphertextHex: "ef".repeat(48),
  signatureHex: "00".repeat(64),
};

const signedEntry = (operation: Parameters<typeof signEntryAt>[0]["operation"]) =>
  signEntryAt({
    seq: fixture.head.seq + 1,
    prevHashHex: fixture.head.hashHex,
    actorUserId: OWNER,
    operation,
  });

describe("storageGuardDecision(純関数 — §12-8 の 2 段閾値)", () => {
  it("admits below the warning threshold, warns from it, rejects from the rejection threshold", () => {
    expect(storageGuardDecision(0)).toBe("admit");
    expect(storageGuardDecision(DO_STORAGE_WARN_BYTES - 1)).toBe("admit");
    expect(storageGuardDecision(DO_STORAGE_WARN_BYTES)).toBe("warn");
    expect(storageGuardDecision(DO_STORAGE_REJECT_BYTES - 1)).toBe("warn");
    expect(storageGuardDecision(DO_STORAGE_REJECT_BYTES)).toBe("reject");
    expect(storageGuardDecision(10_000_000_000)).toBe("reject");
  });

  it("keeps the rejection threshold under the 10 GB platform floor in either unit", () => {
    // 10 GB(10 進)/ 10 GiB(2 進)のどちらの解釈でも拒否閾値は床の下(§12-8)
    expect(DO_STORAGE_REJECT_BYTES).toBeLessThan(10_000_000_000);
    expect(DO_STORAGE_REJECT_BYTES).toBeLessThan(10 * 1024 ** 3);
    expect(DO_STORAGE_WARN_BYTES).toBeLessThan(DO_STORAGE_REJECT_BYTES);
  });

  it("takes thresholds as parameters (self-hosted adjustment surface)", () => {
    expect(storageGuardDecision(50, { warnBytes: 40, rejectBytes: 60 })).toBe("warn");
    expect(storageGuardDecision(60, { warnBytes: 40, rejectBytes: 60 })).toBe("reject");
  });
});

describe("エラー契約 — 拒否が効く面の全エンドポイントが 422 DataLimitExceeded を宣言している", () => {
  it("maps project-storage-bytes within the contract (never a 500) on every guarded surface", () => {
    const guarded = {
      "variables.create": variablesGroup.endpoints.create,
      "variables.push": variablesGroup.endpoints.push,
      "variables.activate": variablesGroup.endpoints.activate,
      "variables.rename": variablesGroup.endpoints.rename,
      "environments.create": environmentsGroup.endpoints.create,
      "environments.rename": environmentsGroup.endpoints.rename,
      "deks.register": deksGroup.endpoints.register,
      // add_member / grant_server の拒否面(本改訂で宣言を追加)
      "membership.append": membershipGroup.endpoints.append,
      // schemaPolicy 変更(本改訂で宣言を追加)
      "schemaPolicy.set": schemaPolicyGroup.endpoints.set,
      // 監査ヘッド派生列の実体化を要する読み取り(本改訂で宣言を追加)と、
      // 非空公証の境界 checkpoint を同梱しうる rotate(既存宣言)
      "audit.auditHead": auditGroup.endpoints.auditHead,
      "environments.rotate": environmentsGroup.endpoints.rotate,
    };
    for (const [label, endpoint] of Object.entries(guarded)) {
      const error = Effect.runSync(
        Effect.flip(
          unwrapDataOutcome(
            { kind: "rejected", rejection: STORAGE_REJECTION },
            projectId,
            endpoint as HttpApiEndpoint.Top,
          ),
        ),
      );
      expect(error, label).toBeInstanceOf(DataLimitExceededError);
      expect(error, label).toMatchObject({
        resource: "project-storage-bytes",
        limit: DO_STORAGE_REJECT_BYTES,
      });
    }
  });
});

describe("受理経路の結線 — 拒否閾値以上の DO(§12-8)", () => {
  it("rejects every content-growth surface with limit-exceeded project-storage-bytes", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // 対象の鍵はダミーでよい(ガードは verifyChain より前に立つ)
    const addMember = await signedEntry({
      op: "add_member",
      payload: {
        targetUserId: STRANGER,
        encPubHex: "ab".repeat(32),
        sigPubHex: "cd".repeat(32),
        role: "member",
      },
    });
    const grantServer = await signedEntry({
      op: "grant_server",
      payload: {
        serverEncPubHex: "ab".repeat(32),
        serverKeyFingerprintHex: "cd".repeat(16),
        scopeEnvironmentIds: [ENV],
        leasePolicy: [],
      },
    });
    const createEnv = await signedEntry({
      op: "create_environment",
      payload: { environmentId: "env-new", dekCommitmentHex: "ab".repeat(32) },
    });
    const checkpoint = await signedEntry({
      op: "checkpoint",
      payload: { environments: [], auditHeadHashHex: "" },
    });
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await runInProject(DO_STORAGE_REJECT_BYTES, async (run) => {
        const cache: StateCache = { current: null, chain: null };
        const outcomes = {
          push: rejectionOf(
            await run(pushVersionProgram(actor(OWNER), ENV, VAR, dummyValueInput(2), false, cache)),
          ),
          reencryptionPush: rejectionOf(
            await run(pushVersionProgram(actor(OWNER), ENV, VAR, dummyValueInput(2), true, cache)),
          ),
          createVariable: rejectionOf(
            await run(
              createVariableProgram(
                actor(OWNER),
                ENV,
                {
                  variableId: "var-new",
                  statement: dummyVariableStatement("var-new", "NEW"),
                  value: dummyValueInput(1),
                  manifest: dummyManifest(),
                },
                cache,
              ),
            ),
          ),
          declareVariable: rejectionOf(
            await run(
              createVariableProgram(
                actor(OWNER),
                ENV,
                {
                  variableId: "var-declared",
                  statement: dummyVariableStatement("var-declared", "DECLARED"),
                  manifest: dummyManifest(),
                },
                cache,
              ),
            ),
          ),
          activate: rejectionOf(
            await run(
              activateVariableProgram(
                actor(OWNER),
                ENV,
                VAR,
                {
                  value: dummyValueInput(1),
                  statement: dummyVariableStatement(VAR, "DATABASE_URL"),
                  manifest: dummyManifest(),
                },
                cache,
              ),
            ),
          ),
          renameVariable: rejectionOf(
            await run(
              renameVariableProgram(
                actor(OWNER),
                ENV,
                VAR,
                dummyVariableStatement(VAR, "RENAMED"),
                dummyManifest(),
                cache,
              ),
            ),
          ),
          renameEnvironment: rejectionOf(
            await run(
              renameEnvironmentProgram(
                actor(OWNER),
                ENV,
                dummyEnvStatement("Renamed"),
                dummyManifest(),
                cache,
              ),
            ),
          ),
          registerWraps: rejectionOf(
            await run(registerDekWrapsProgram(actor(OWNER), ENV, [dummyWrap], cache)),
          ),
          createEnvironment: rejectionOf(
            await run(
              createEnvironmentCompositeProgram(
                actor(OWNER),
                {
                  parentHeadHashHex: fixture.head.hashHex,
                  entry: createEnv.entry as ChainEntry & { readonly op: "create_environment" },
                  statement: dummyEnvStatement("New"),
                  deks: [],
                  manifest: dummyManifest(),
                  checkpoint: checkpoint.entry as ChainEntry & { readonly op: "checkpoint" },
                },
                cache,
              ),
            ),
          ),
          addMember: rejectionOf(
            await run(appendProgram(fixture.head.hashHex, addMember.entry, OWNER, cache)),
          ),
          grantServer: rejectionOf(
            await run(appendProgram(fixture.head.hashHex, grantServer.entry, OWNER, cache)),
          ),
          // 成長面ではないが、退出・解放・是正に要らず監査行を積む設定変更
          setSchemaPolicy: rejectionOf(
            await run(setSchemaPolicyProgram(actor(OWNER), "enabled", cache)),
          ),
        };
        for (const [surface, rejection] of Object.entries(outcomes)) {
          expect(rejection, surface).toEqual(STORAGE_REJECTION);
        }
      });
      // 拒否域の運用ログは静的メッセージで meter ごと 1 回(12 回の拒否で 1 行)
      expect(errorSpy).toHaveBeenCalledTimes(1);
      const [message] = errorSpy.mock.calls[0] ?? [];
      expect(typeof message).toBe("string");
      expect(message).not.toContain(projectId);
      expect(message).not.toContain(OWNER);
    } finally {
      errorSpy.mockRestore();
    }
    // 何も書いていない: 変数は 1 つ・version は 1 のまま・チェーンは不変
    const versions = await runInProject(0, async (run) => {
      const pulled = await run(
        pullEnvironmentProgram(actor(READER), ENV, { current: null, chain: null }),
      );
      return Exit.isSuccess(pulled) ? pulled.value.variables.map((v) => v.version) : null;
    });
    expect(versions).toEqual([1]);
  });

  it("keeps reads, deletions, revocations, rotation, attestation, checkpoint and settings open", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // 親ヘッド不一致の失効系エントリ: ガードが呼ばれていれば limit-exceeded、
    // 呼ばれていなければ chain-head-conflict(ガードは ensureParentHead の前)
    const staleParent = "00".repeat(32);
    const removeMember = await signedEntry({
      op: "remove_member",
      payload: { targetUserId: READER },
    });
    const changeRole = await signedEntry({
      op: "change_role",
      payload: { targetUserId: READER, newRole: "member" },
    });
    const revokeServer = await signedEntry({
      op: "revoke_server",
      payload: { serverKeyFingerprintHex: "cd".repeat(16) },
    });
    const checkpoint = await signedEntry({
      op: "checkpoint",
      payload: { environments: [], auditHeadHashHex: "" },
    });
    const rotate = await signedEntry({
      op: "rotate_epoch",
      payload: {
        environmentId: "env-other",
        newEpoch: 2,
        reason: "scheduled",
        dekCommitmentHex: "ab".repeat(32),
      },
    });
    await runInProject(DO_STORAGE_REJECT_BYTES, async (run) => {
      const cache: StateCache = { current: null, chain: null };
      // (a) 読み取り — 成功する(値付き pull は var.read の監査追記を伴うが受理)
      const pulled = await run(pullEnvironmentProgram(actor(READER), ENV, cache));
      expect(Exit.isSuccess(pulled)).toBe(true);
      expect(
        Exit.isSuccess(await run(pullEnvironmentMetadataProgram(actor(READER), ENV, cache))),
      ).toBe(true);
      expect(Exit.isSuccess(await run(listEnvironmentsProgram(actor(READER), cache)))).toBe(true);
      expect(Exit.isSuccess(await run(snapshotProgram(READER, cache)))).toBe(true);
      expect(Exit.isSuccess(await run(listMyDekWrapsProgram(actor(READER), ENV, cache)))).toBe(
        true,
      );
      // (b) 削除系 — ガードを通過し、別の理由(ダミー入力)で拒否される
      expect(
        rejectionOf(
          await run(
            deleteVariableProgram(
              actor(OWNER),
              ENV,
              VAR,
              dummyVariableStatement(VAR, "WRONG_NAME"),
              dummyManifest(),
              cache,
            ),
          ),
        ),
      ).toEqual({ kind: "payload-mismatch", field: "name" });
      expect(
        rejectionOf(
          await run(
            deleteEnvironmentProgram(
              actor(OWNER),
              ENV,
              dummyEnvStatement("Wrong", "deleted"),
              cache,
            ),
          ),
        ),
      ).toEqual({ kind: "payload-mismatch", field: "name" });
      expect(
        rejectionOf(
          await run(
            deleteDekWrapsProgram(
              actor(OWNER),
              ENV,
              [{ epoch: 7, recipientUserId: STRANGER }],
              cache,
            ),
          ),
        ),
      ).toEqual({ kind: "dek-wrap-not-found", epoch: 7, recipientUserId: STRANGER });
      // (c) 失効・権限縮小系 + (g) checkpoint — ガード非通過(chain-head-conflict)
      for (const entry of [
        removeMember.entry,
        changeRole.entry,
        revokeServer.entry,
        checkpoint.entry,
      ]) {
        const rejection = rejectionOf(await run(appendProgram(staleParent, entry, OWNER, cache)));
        expect(rejection?.kind, entry.op).toBe("chain-head-conflict");
      }
      // (d) ローテーション複合 — 複合内整合検査(environmentId 不一致)まで進む
      expect(
        rejectionOf(
          await run(
            rotateEpochCompositeProgram(
              actor(OWNER),
              ENV,
              {
                parentHeadHashHex: fixture.head.hashHex,
                entry: rotate.entry as ChainEntry & { readonly op: "rotate_epoch" },
                deks: [],
                manifest: dummyManifest(),
                checkpoint: checkpoint.entry as ChainEntry & { readonly op: "checkpoint" },
              },
              cache,
            ),
          ),
        ),
      ).toEqual({ kind: "payload-mismatch", field: "environmentId" });
      // (f) ヘッド申告 — 署名検証まで進む(ダミー署名は attestation-rejected)
      expect(
        rejectionOf(
          await run(
            putHeadAttestationProgram(
              OWNER,
              {
                suite: "maruhi/v1",
                chainHeadHashHex: fixture.head.hashHex,
                chainHeadSeq: fixture.head.seq,
                signatureHex: "00".repeat(64),
              },
              cache,
            ),
          ),
        )?.kind,
      ).toBe("attestation-rejected");
      // (h) 取り下げ — 成功する(フラグ数に有界な監査行)。schemaPolicy の変更は
      // 拒否対象(上の成長面テスト)、取得は読み取りで通る
      expect(Exit.isSuccess(await run(dismissRotationFlagsProgram(actor(OWNER), [], cache)))).toBe(
        true,
      );
      expect(Exit.isSuccess(await run(getSchemaPolicyProgram(actor(READER), cache)))).toBe(true);
      // (c) の実受理: 正しい親ヘッドの remove_member は拒否閾値以上でも受理される
      const removed = await run(
        appendProgram(fixture.head.hashHex, removeMember.entry, OWNER, cache),
      );
      expect(Exit.isSuccess(removed)).toBe(true);
      const snapshot = await run(snapshotProgram(OWNER, cache));
      expect(Exit.isSuccess(snapshot) && snapshot.value.headSeq).toBe(fixture.head.seq + 1);
    });
  });
});

describe("監査ヘッド派生列の実体化(§12-8 (a) の例外 — AUDIT_SPEC §5.1 の遅延実体化)", () => {
  it("rejects the audit-head read only while the derived column lags behind the audit log", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      // 監査行はあるが派生列は未実体化(まだ誰も監査ヘッドを読んでいない)→
      // 実体化 = 監査行数比例の書き込みを要するため、拒否閾値以上では拒否
      await runInProject(DO_STORAGE_REJECT_BYTES, async (run) => {
        const cache: StateCache = { current: null, chain: null };
        expect(rejectionOf(await run(auditHeadProgram(actor(OWNER), cache)))).toEqual(
          STORAGE_REJECTION,
        );
        // 非空公証の standalone checkpoint も同じ入力で止まる(親ヘッド不一致より
        // 前 = requireRole(admin) の後に立つ)。空公証(CLI の既定)は通る —
        // 上のテストの chain-head-conflict がそれ
        const notarizing = await signedEntry({
          op: "checkpoint",
          payload: { environments: [], auditHeadHashHex: "ab".repeat(32) },
        });
        expect(
          rejectionOf(
            await run(appendProgram(fixture.head.hashHex, notarizing.entry, OWNER, cache)),
          ),
        ).toEqual(STORAGE_REJECTION);
      });
      // 閾値未満で一度読む = 実体化される
      const materialized = await runInProject(0, async (run) =>
        Exit.isSuccess(await run(auditHeadProgram(actor(OWNER), { current: null, chain: null }))),
      );
      expect(materialized).toBe(true);
      // 列が最新なら拒否閾値以上でも読み取りのみ = 通る
      const current = await runInProject(DO_STORAGE_REJECT_BYTES, async (run) =>
        Exit.isSuccess(await run(auditHeadProgram(actor(OWNER), { current: null, chain: null }))),
      );
      expect(current).toBe(true);
      // 監査行が増える(値付き pull の var.read — 拒否下でも受理される読み取り)と
      // 列が再び遅れ、次の監査ヘッド読みは実体化を要するため再び拒否される
      await runInProject(DO_STORAGE_REJECT_BYTES, async (run) => {
        const cache: StateCache = { current: null, chain: null };
        expect(Exit.isSuccess(await run(pullEnvironmentProgram(actor(READER), ENV, cache)))).toBe(
          true,
        );
        expect(rejectionOf(await run(auditHeadProgram(actor(OWNER), cache)))).toEqual(
          STORAGE_REJECTION,
        );
      });
    } finally {
      errorSpy.mockRestore();
    }
  });
});

describe("警告閾値(§12-8 — 運用ログ)", () => {
  it("admits growth writes in the warning band and logs one static line per meter", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await runInProject(DO_STORAGE_WARN_BYTES, async (run) => {
        const cache: StateCache = { current: null, chain: null };
        // ガードは admit 相当で通過し、ダミー値は後段(値署名)で落ちる
        for (let i = 0; i < 3; i += 1) {
          const rejection = rejectionOf(
            await run(pushVersionProgram(actor(OWNER), ENV, VAR, dummyValueInput(2), false, cache)),
          );
          expect(rejection?.kind).toBe("value-rejected");
        }
      });
      expect(warnSpy).toHaveBeenCalledTimes(1);
      const [message] = warnSpy.mock.calls[0] ?? [];
      expect(typeof message).toBe("string");
      expect(message).not.toContain(projectId);
      expect(errorSpy).not.toHaveBeenCalled();
    } finally {
      warnSpy.mockRestore();
      errorSpy.mockRestore();
    }
  });

  it("stays silent below the warning threshold", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      await runInProject(DO_STORAGE_WARN_BYTES - 1, async (run) => {
        const rejection = rejectionOf(
          await run(
            pushVersionProgram(actor(OWNER), ENV, VAR, dummyValueInput(2), false, {
              current: null,
              chain: null,
            }),
          ),
        );
        expect(rejection?.kind).toBe("value-rejected");
      });
      expect(warnSpy).not.toHaveBeenCalled();
    } finally {
      warnSpy.mockRestore();
    }
  });
});
