// 複合リクエストの Effect プログラム(AUTH_SPEC §12-4 / CRYPTO_SPEC §6.4 の複合受理)。
//
// - 環境作成 = `create_environment` チェーンエントリ(エポック 1 の DEK
//   コミットメント込み — §5.2/§6.2)+ EnvironmentMetaStatement(metaVersion 1 —
//   §4.2。宣言ヘッドは追記前の現ヘッド = 同梱エントリの prev)+ エポック 1 の
//   ラップ完全集合
// - ローテーション = `rotate_epoch` エントリ(新エポックのコミットメント込み)+
//   新エポックのラップ完全集合(従来の「汎用チェーン追記 + DEK 登録 API」の
//   2 往復を置換。現在値の再暗号化は後続の通常 push — §12-7)
//
// チェーン追記(親ヘッド CAS + verifyChain 再実行)とデータ登録を単一の同期
// ブロックで原子的に受理し、「エポックはあるがラップがない」「コミットメントは
// あるが環境行がない」中間状態を作らない。全検査は書き込みフェーズの前に完了する
// (data-programs.ts と同じ規律)。DO の Semaphore(1) permit 下で実行される前提。
//
// ラップ集合の受理条件(§12-6)の判定基準状態は「同梱エントリ適用後のチェーン
// 状態」(§12-4 — 追記前状態で判定すると新エポック宛ラップの正当な rotate 複合が
// 全拒否になる)。エントリ自体の受理は verifyChain(§6.4 = 合意規則の再検証)が
// 権威で、duplicate-environment / unknown-environment / エポック順序 / role /
// コミットメント形式はすべてそこで判定される。

import type { ChainEntry, ChainMember, ChainState } from "@maruhi/crypto";
import { Effect } from "effect";

import type { AuditEventInput } from "./audit-store.ts";
import { AuditStore } from "./audit-store.ts";
import {
  ensureParentHead,
  insertAcceptedEntrySync,
  verifyAcceptableEntry,
} from "./chain-accept.ts";
import type { StateCache } from "./chain-store.ts";
import { ChainStore, deriveStoredState, updateStateCache } from "./chain-store.ts";
import type { DataActor, DekWrapInput, MetaStatementInput } from "./data-plane.ts";
import { dataEvent, loadInitializedChain, rejectData, requireRole } from "./data-plane.ts";
import type { DataWriteOps } from "./data-store.ts";
import { DataStore } from "./data-store.ts";
import { dekRegisteredEvent, ensureWrapSetAcceptable } from "./dek-wraps.ts";
import { ensureEnvironmentQuota, requireActiveEnvironment } from "./quotas.ts";
import { ensureMetaStatementSignature, ensureNfcName } from "./verify-meta.ts";

/** 複合受理の結果(RPC 境界を渡る)。 */
export interface EnvironmentChainResultValue {
  readonly environmentId: string;
  readonly currentEpoch: number;
  readonly headSeq: number;
  readonly headHashHex: string;
}

/**
 * 複合共通の前段: 未初期化 / メンバーシップ / role 下限(いずれも member —
 * §12-3 の環境作成・rotate_epoch の水準)の検査と、チェーン全体のロード。
 */
const loadChainForComposite = (callerUserId: string, cache: StateCache) =>
  Effect.gen(function* () {
    const chain = yield* loadInitializedChain;
    // history は追記前チェーンの履歴索引: 同梱ステートメントの宣言ヘッド実在
    // 検査は追記前のチェーンに対して行う(§12-4 — 同梱エントリ自身をヘッドに
    // 宣言する形は受理しない)
    const { state, history } = yield* deriveStoredState(chain, cache);
    const member = yield* requireRole(state, callerUserId, "member");
    return { chain, state, history, member, projectId: chain.genesisHashHex };
  });

/**
 * 複合同梱ラップの検査(§12-4 / §12-6): 全ラップの epoch = 同梱エントリが確立する
 * エポック(複合内整合検査)、現メンバー集合との完全一致(個数一致 = 完全一致 —
 * 受信者・重複は ensureWrapSetAcceptable が検査済み)、登録署名・行数上限。
 * 判定基準状態は同梱エントリ適用後(appliedState)。
 */
const ensureCompositeWrapSet = (input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly appliedState: ChainState;
  readonly member: ChainMember;
  readonly establishedEpoch: number;
  readonly deks: readonly DekWrapInput[];
}) =>
  Effect.gen(function* () {
    // 複合内整合検査(§12-4): 全ラップの epoch = 同梱エントリが確立するエポック。
    // ensureWrapSetAcceptable の範囲検査(1〜現エポック)より狭い等値検査で、
    // 過去エポック宛ラップの紛れ込み(rotate 複合への epoch 1 宛等)も拒否する
    for (const wrap of input.deks) {
      if (wrap.epoch !== input.establishedEpoch) {
        return yield* rejectData({ kind: "dek-wrap-rejected", reason: "epoch-out-of-range" });
      }
    }
    yield* ensureWrapSetAcceptable(
      input.projectId,
      input.environmentId,
      input.appliedState,
      input.member,
      input.establishedEpoch,
      input.deks,
    );
    // 完全一致(§12-6 の初回登録)を個数で明示要求する: checkWrapSets は
    // リクエストに現れたエポックしか見ないため、空集合が素通りしないように。
    // 受信者・重複は検査済みなので個数一致 = 完全一致(理由コードの判定順も
    // 旧・環境作成プログラムと同じ「個別検査 → 完全性」を保つ)
    if (input.deks.length !== input.appliedState.members.size) {
      return yield* rejectData({ kind: "dek-wrap-rejected", reason: "recipient-missing" });
    }
  });

/** 複合の書き込みフェーズで共有する依存とパラメータ(同期関数群の引数)。 */
interface CompositeWriteContext {
  readonly chainStore: {
    readonly insertSync: (entry: ChainEntry, entryHashHex: string, canonicalBytes: number) => void;
  };
  readonly dataStore: { readonly write: DataWriteOps };
  readonly audit: {
    readonly appendSync: (event: AuditEventInput) => void;
    readonly appendManySync: (events: readonly AuditEventInput[]) => void;
  };
  readonly actor: DataActor;
  readonly member: ChainMember;
  readonly environmentId: string;
  readonly nowMs: number;
}

/** 同梱ラップの挿入 + dek.registered(1 受信者 1 行 — AUDIT_SPEC §3.3)。 */
function insertCompositeWrapsSync(
  context: CompositeWriteContext,
  deks: readonly DekWrapInput[],
): void {
  for (const wrap of deks) {
    context.dataStore.write.insertWrap(context.environmentId, wrap, context.member, context.nowMs);
  }
  context.audit.appendManySync(
    deks.map((wrap) =>
      dekRegisteredEvent(context.actor, context.member, context.nowMs, context.environmentId, wrap),
    ),
  );
}

/** 書き込みフェーズの依存(ChainStore / AuditStore)を束ねて CompositeWriteContext を作る。 */
const makeWriteContext = (input: {
  readonly dataStore: { readonly write: DataWriteOps };
  readonly actor: DataActor;
  readonly member: ChainMember;
  readonly environmentId: string;
}) =>
  Effect.gen(function* () {
    const chainStore = yield* ChainStore;
    const audit = yield* AuditStore;
    return {
      chainStore,
      dataStore: input.dataStore,
      audit,
      actor: input.actor,
      member: input.member,
      environmentId: input.environmentId,
      nowMs: Date.now(),
    } satisfies CompositeWriteContext;
  });

function compositeResult(
  environmentId: string,
  currentEpoch: number,
  appliedState: ChainState,
): EnvironmentChainResultValue {
  return {
    environmentId,
    currentEpoch,
    headSeq: appliedState.headSeq,
    headHashHex: appliedState.headHashHex,
  };
}

export const createEnvironmentCompositeProgram = (
  actor: DataActor,
  input: {
    readonly parentHeadHashHex: string;
    readonly entry: ChainEntry & { readonly op: "create_environment" };
    readonly statement: MetaStatementInput;
    readonly deks: readonly DekWrapInput[];
  },
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { chain, history, member, projectId } = yield* loadChainForComposite(actor.userId, cache);
    yield* ensureParentHead(chain, input.parentHeadHashHex);
    // 複合内の宣言ヘッド(§12-4): 同梱ステートメントの宣言ヘッドは追記前の
    // 現ヘッド(= 同梱エントリの prev)と厳密一致。CAS 通過後なので現ヘッド =
    // parentHeadHashHex。ヘッド CAS 失敗の再試行ではエントリとステートメントの
    // 両方を再署名する(クライアント側 — env-create.ts)
    if (
      input.statement.chainHeadHashHex !== chain.headHashHex ||
      input.statement.chainHeadSeq !== chain.headSeq
    ) {
      return yield* rejectData({ kind: "payload-mismatch", field: "statementChainHead" });
    }
    // 受理 4 手順のうち検査 3 手順(サイズ → 容量 → verifyChain — §6.4 の合意
    // 規則 = duplicate-environment / エポック順序 / role / コミットメント形式を
    // 含む)は汎用チェーン API と共有(chain-accept.ts)
    const { canonicalBytes, applied } = yield* verifyAcceptableEntry(chain, input.entry);
    const appliedState = applied.state;
    const environmentId = input.entry.payload.environmentId;
    const store = yield* DataStore;
    // ID の一意性はチェーン合意規則(duplicate-environment — verifyChain)が
    // 担う。データプレーンに残る検査は表示名の一意性と数量ポリシーのみ
    yield* ensureEnvironmentQuota;
    yield* ensureNfcName(input.statement.name);
    if (yield* store.environmentNameTaken(input.statement.name, null)) {
      return yield* rejectData({
        kind: "environment-conflict",
        environmentId,
        reason: "duplicate-name",
      });
    }
    // ステートメント検証は追記前の履歴に対して行う(§12-4)。メタステートメントは
    // 環境の存在を検査しないため、宣言ヘッド時点に環境が未存在でも受理される
    // (値署名との意図された非対称)。author = 呼び出し主体・宣言ヘッド時点の
    // member 以上は verifyDistributedMetaStatement が検査する
    const metaSignedBytesHashHex = yield* ensureMetaStatementSignature({
      projectId,
      environmentId,
      target: { kind: "environment" },
      history,
      member,
      statement: input.statement,
    });
    // 同梱エントリ適用後の現エポックは常に 1(create_environment — §12-4)
    yield* ensureCompositeWrapSet({
      projectId,
      environmentId,
      appliedState,
      member,
      establishedEpoch: 1,
      deks: input.deks,
    });
    const writeContext = yield* makeWriteContext({
      dataStore: store,
      actor,
      member,
      environmentId,
    });
    // 書き込みフェーズ: 単一の同期ブロック = 同一タスクで原子コミット
    // (チェーンエントリ + ミラー + 環境行 + ステートメント行 + ラップ + 監査を
    // 分割しない — §12-4)
    yield* Effect.sync(() => {
      insertAcceptedEntrySync(
        writeContext,
        input.entry,
        applied,
        canonicalBytes,
        writeContext.nowMs,
      );
      store.write.insertEnvironment(environmentId, input.statement.name, writeContext.nowMs);
      store.write.insertEnvironmentMetaStatement(
        environmentId,
        input.statement,
        metaSignedBytesHashHex,
        { userId: member.userId, keyFingerprintHex: member.keyFingerprintHex },
        writeContext.nowMs,
      );
      // env.created はステートメント author の鍵 FP を写す(AUDIT_SPEC §3.3)
      writeContext.audit.appendSync(
        dataEvent(actor, writeContext.nowMs, "env.created", {
          environmentId,
          payload: { name: input.statement.name },
          actorKeyFingerprintHex: member.keyFingerprintHex,
        }),
      );
      insertCompositeWrapsSync(writeContext, input.deks);
    });
    updateStateCache(cache, applied);
    return compositeResult(environmentId, 1, appliedState);
  });

export const rotateEpochCompositeProgram = (
  actor: DataActor,
  environmentId: string,
  input: {
    readonly parentHeadHashHex: string;
    readonly entry: ChainEntry & { readonly op: "rotate_epoch" };
    readonly deks: readonly DekWrapInput[];
  },
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { chain, member, projectId } = yield* loadChainForComposite(actor.userId, cache);
    // 複合内整合検査(§12-4): URL 座標と同梱エントリの environment_id の一致。
    // 各部分の独立検証だけで別環境のエントリ × 別環境のラップの組を受理しない
    if (input.entry.payload.environmentId !== environmentId) {
      return yield* rejectData({ kind: "payload-mismatch", field: "environmentId" });
    }
    // 削除済み(tombstone)環境への rotate は 404(§12-4 — §7 の「全環境」は
    // 削除済みを含まない。黙って受理して守るもののないエポックを進めない)
    yield* requireActiveEnvironment(environmentId);
    yield* ensureParentHead(chain, input.parentHeadHashHex);
    const { canonicalBytes, applied } = yield* verifyAcceptableEntry(chain, input.entry);
    const appliedState = applied.state;
    // 同梱エントリ適用後の現エポック = new_epoch(エポック順序は verifyChain 検証済み)
    yield* ensureCompositeWrapSet({
      projectId,
      environmentId,
      appliedState,
      member,
      establishedEpoch: input.entry.payload.newEpoch,
      deks: input.deks,
    });
    const writeContext = yield* makeWriteContext({
      dataStore: yield* DataStore,
      actor,
      member,
      environmentId,
    });
    yield* Effect.sync(() => {
      insertAcceptedEntrySync(
        writeContext,
        input.entry,
        applied,
        canonicalBytes,
        writeContext.nowMs,
      );
      insertCompositeWrapsSync(writeContext, input.deks);
    });
    updateStateCache(cache, applied);
    return compositeResult(environmentId, input.entry.payload.newEpoch, appliedState);
  });
