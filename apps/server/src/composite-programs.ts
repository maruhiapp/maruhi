// 複合リクエストの Effect プログラム(AUTH_SPEC §12-4 / CRYPTO_SPEC §6.4 の複合受理)。
//
// - 環境作成 = `create_environment` チェーンエントリ(エポック 1 の DEK
//   コミットメント込み — §5.2/§6.2)+ 表示名 + エポック 1 のラップ完全集合
//   (PR-1 の意図的中間状態: EnvironmentMetaStatement の同梱は PR-3)
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

import type { ChainInvalidError } from "@maruhi/core";
import type { ChainEntry, ChainMember, ChainState } from "@maruhi/crypto";
import { Effect } from "effect";

import type { AuditEventInput } from "./audit-store.ts";
import { AuditStore, chainMirrorEvent } from "./audit-store.ts";
import type { StateCache, StoredChain } from "./chain-store.ts";
import {
  canonicalBytesOf,
  ChainStore,
  deriveStoredState,
  updateStateCache,
  verifyChainEffect,
} from "./chain-store.ts";
import type { DataActor, DataRejectedError, DekWrapInput, InitializedChain } from "./data-plane.ts";
import { dataEvent, loadInitializedChain, rejectData, requireRole } from "./data-plane.ts";
import {
  dekRegisteredEvent,
  ensureEnvironmentQuota,
  ensureWrapSetAcceptable,
} from "./data-programs.ts";
import type { DataWriteOps } from "./data-store.ts";
import { DataStore } from "./data-store.ts";
import {
  MAX_CHAIN_ENTRIES,
  MAX_CHAIN_TOTAL_CANONICAL_BYTES,
  MAX_ENTRY_CANONICAL_BYTES,
} from "./policy.ts";

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
    const state = yield* deriveStoredState(chain, cache);
    const member = yield* requireRole(state, callerUserId, "member");
    return { chain, state, member, projectId: chain.genesisHashHex };
  });

/** CAS(§6.4): 親ヘッド不一致は現ヘッド情報付きで拒否(worker が 409 に写す)。 */
function ensureCompositeParentHead(
  chain: InitializedChain,
  parentHeadHashHex: string,
): Effect.Effect<void, DataRejectedError> {
  if (parentHeadHashHex !== chain.headHashHex) {
    return Effect.fail(
      rejectData({
        kind: "chain-head-conflict",
        currentHeadSeq: chain.headSeq,
        currentHeadHashHex: chain.headHashHex,
      }),
    );
  }
  return Effect.void;
}

/**
 * 同梱エントリのサイズ・容量ポリシー(§6.4)と全チェーン再検証。受理される
 * 場合は「エントリ適用後の状態」(§12-4 のラップ判定基準)を返す。
 */
const verifyCompositeEntry = (chain: StoredChain, entry: ChainEntry) =>
  Effect.gen(function* () {
    const canonicalBytes = yield* canonicalBytesOf(entry).pipe(
      Effect.catchTag("ChainInvalid", (error: ChainInvalidError) =>
        Effect.fail(
          rejectData({ kind: "chain-entry-invalid", seq: error.seq, reason: error.reason }),
        ),
      ),
    );
    if (canonicalBytes > MAX_ENTRY_CANONICAL_BYTES) {
      return yield* rejectData({
        kind: "chain-entry-too-large",
        limitBytes: MAX_ENTRY_CANONICAL_BYTES,
      });
    }
    if (
      chain.entries.length + 1 > MAX_CHAIN_ENTRIES ||
      chain.totalCanonicalBytes + canonicalBytes > MAX_CHAIN_TOTAL_CANONICAL_BYTES
    ) {
      return yield* rejectData({
        kind: "chain-capacity-exceeded",
        maxEntries: MAX_CHAIN_ENTRIES,
        maxTotalBytes: MAX_CHAIN_TOTAL_CANONICAL_BYTES,
      });
    }
    // §6.4: 受理時にチェーン全体を再検証する(prev_hash 連続性・署名・合意規則 =
    // duplicate-environment / unknown-environment / エポック順序 / role /
    // dek_commitment_hex の形式)
    const appliedState = yield* verifyChainEffect([...chain.entries, entry]).pipe(
      Effect.catchTag("ChainInvalid", (error: ChainInvalidError) =>
        Effect.fail(
          rejectData({ kind: "chain-entry-invalid", seq: error.seq, reason: error.reason }),
        ),
      ),
    );
    return { canonicalBytes, appliedState };
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
  readonly audit: { readonly appendSync: (event: AuditEventInput) => void };
  readonly actor: DataActor;
  readonly member: ChainMember;
  readonly environmentId: string;
  readonly nowMs: number;
}

/** チェーンエントリ + ミラー(AUDIT_SPEC §3.4。dek_commitment を payload に写す)。 */
function insertCompositeEntrySync(
  context: CompositeWriteContext,
  entry: ChainEntry,
  canonicalBytes: number,
  appliedState: ChainState,
): void {
  context.chainStore.insertSync(entry, appliedState.headHashHex, canonicalBytes);
  context.audit.appendSync(chainMirrorEvent(entry, context.nowMs));
}

/** 同梱ラップの挿入 + dek.registered(1 受信者 1 行 — AUDIT_SPEC §3.3)。 */
function insertCompositeWrapsSync(
  context: CompositeWriteContext,
  deks: readonly DekWrapInput[],
): void {
  for (const wrap of deks) {
    context.dataStore.write.insertWrap(context.environmentId, wrap, context.member, context.nowMs);
    context.audit.appendSync(
      dekRegisteredEvent(context.actor, context.member, context.nowMs, context.environmentId, wrap),
    );
  }
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
    readonly name: string;
    readonly deks: readonly DekWrapInput[];
  },
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { chain, member, projectId } = yield* loadChainForComposite(actor.userId, cache);
    yield* ensureCompositeParentHead(chain, input.parentHeadHashHex);
    const { canonicalBytes, appliedState } = yield* verifyCompositeEntry(chain, input.entry);
    const environmentId = input.entry.payload.environmentId;
    const store = yield* DataStore;
    // ID の一意性はチェーン合意規則(duplicate-environment — verifyChain)が
    // 担う。データプレーンに残る検査は表示名の一意性と数量ポリシーのみ
    yield* ensureEnvironmentQuota;
    if (yield* store.environmentNameTaken(input.name, null)) {
      return yield* rejectData({
        kind: "environment-conflict",
        environmentId,
        reason: "duplicate-name",
      });
    }
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
    // (チェーンエントリ + ミラー + 環境行 + ラップ + 監査を分割しない — §12-4)
    yield* Effect.sync(() => {
      insertCompositeEntrySync(writeContext, input.entry, canonicalBytes, appliedState);
      store.write.insertEnvironment(environmentId, input.name, writeContext.nowMs);
      writeContext.audit.appendSync(
        dataEvent(actor, writeContext.nowMs, "env.created", {
          environmentId,
          payload: { name: input.name },
        }),
      );
      insertCompositeWrapsSync(writeContext, input.deks);
    });
    updateStateCache(cache, appliedState);
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
    const store = yield* DataStore;
    const environment = yield* store.findEnvironment(environmentId);
    if (environment === null || environment.deletedAtMs !== null) {
      return yield* rejectData({ kind: "environment-not-found", environmentId });
    }
    yield* ensureCompositeParentHead(chain, input.parentHeadHashHex);
    const { canonicalBytes, appliedState } = yield* verifyCompositeEntry(chain, input.entry);
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
      dataStore: store,
      actor,
      member,
      environmentId,
    });
    yield* Effect.sync(() => {
      insertCompositeEntrySync(writeContext, input.entry, canonicalBytes, appliedState);
      insertCompositeWrapsSync(writeContext, input.deks);
    });
    updateStateCache(cache, appliedState);
    return compositeResult(environmentId, input.entry.payload.newEpoch, appliedState);
  });
