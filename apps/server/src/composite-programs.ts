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
// (programs-* のデータプレーンプログラムと同じ規律)。DO の Semaphore(1) permit
// 下で実行される前提。
//
// ラップ集合の受理条件(§12-6)の判定基準状態は「同梱エントリ適用後のチェーン
// 状態」(§12-4 — 追記前状態で判定すると新エポック宛ラップの正当な rotate 複合が
// 全拒否になる)。エントリ自体の受理は verifyChain(§6.4 = 合意規則の再検証)が
// 権威で、duplicate-environment / unknown-environment / エポック順序 / role /
// コミットメント形式はすべてそこで判定される。

import type { ChainEntry, ChainMember, ChainState } from "@maruhi/crypto";
import { Effect } from "effect";

import type { AuditEventInput, AuditRotationRead } from "./audit-store.ts";
import { AuditStore } from "./audit-store.ts";
import {
  ensureParentHead,
  insertAcceptedEntryPairSync,
  verifyAcceptableEntryPair,
} from "./chain-accept.ts";
import type { StateCache } from "./chain-store.ts";
import { ChainStore, deriveStoredState, updateStateCache } from "./chain-store.ts";
import { ensureAuditHeadAcceptable, ensureCheckpointValuesDigest } from "./checkpoint-accept.ts";
import type {
  DataActor,
  DekWrapInput,
  EnvManifestInput,
  MetaStatementInput,
} from "./data-plane.ts";
import { dataEvent, loadInitializedChain, rejectData, requireRole } from "./data-plane.ts";
import type { DataWriteOps } from "./data-store.ts";
import { DataStore } from "./data-store.ts";
import {
  dekRegisteredEvent,
  ensureWrapSetAcceptable,
  expectedWrapRecipientCount,
} from "./dek-wraps.ts";
import { ensureEnvironmentQuota, requireActiveEnvironment } from "./quotas.ts";
import { acceptEnvManifest, manifestDigestEntries, storedEnvMeta } from "./verify-manifest.ts";
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
    // 旧・環境作成プログラムと同じ「個別検査 → 完全性」を保つ)。対象は
    // 現メンバー集合 + 開示スコープ内の有効 grant_server のサーバー鍵
    // (§12-4 — 2026-08-12 改訂。dek-wraps.ts の期待数定義を共有する)
    if (input.deks.length !== expectedWrapRecipientCount(input.appliedState, input.environmentId)) {
      return yield* rejectData({ kind: "dek-wrap-rejected", reason: "recipient-missing" });
    }
  });

/**
 * 境界 checkpoint の同梱物一致検査(AUTH_SPEC §12-4 — 2026-08-27 セッション 33):
 * 当該環境 1 タプルのみ・座標一致・epoch = 同梱エントリが確立するエポック・
 * manifestVersion = 同梱マニフェストの版。タプルの manifest_sig_hash と同梱
 * マニフェストのハッシュ一致は、両エントリ適用後の履歴に対する acceptEnvManifest
 * のチェックポイント束縛検査(CRYPTO_SPEC §4.3 (2))が一意に担う(§6.4 の
 * 「同梱物一致検査との分担は実装 PR で一意化」)。
 */
const ensureBoundaryCheckpointShape = (input: {
  readonly checkpoint: ChainEntry & { readonly op: "checkpoint" };
  readonly environmentId: string;
  readonly establishedEpoch: number;
  readonly manifestVersion: number;
}) =>
  Effect.gen(function* () {
    const environments = input.checkpoint.payload.environments;
    const tuple = environments[0];
    if (environments.length !== 1 || tuple === undefined) {
      return yield* rejectData({ kind: "payload-mismatch", field: "checkpointEnvironment" });
    }
    if (tuple.environmentId !== input.environmentId) {
      return yield* rejectData({ kind: "payload-mismatch", field: "checkpointEnvironment" });
    }
    if (tuple.epoch !== input.establishedEpoch) {
      return yield* rejectData({ kind: "payload-mismatch", field: "checkpointEpoch" });
    }
    if (tuple.manifestVersion !== input.manifestVersion) {
      return yield* rejectData({ kind: "payload-mismatch", field: "checkpointManifestVersion" });
    }
    // 非空 audit_head_hash は §16-2 の規則(実効権限 admin + §6.4 の存在・位置
    // 検査)で受理する — role 半分と内容検査は呼び出し側の
    // ensureCheckpointAuditHead(checkpoint-accept.ts と共有)が担う(2026-08-28
    // PR-M2 — F3b の暫定 fail-closed〔payload-mismatch: checkpointAuditHead〕を置換)
    return tuple;
  });

/**
 * 境界 checkpoint の監査ヘッド公証(§16-2 — standalone 経路と同一規則):
 * 非空ならチェーン role admin 以上(不足 403。スコープ半分は worker が
 * 先行検査済み)+ §6.4 の存在・位置検査。空文字列 = 公証なしは何もしない。
 */
const ensureCheckpointAuditHead = (input: {
  readonly checkpoint: ChainEntry & { readonly op: "checkpoint" };
  readonly state: ChainState;
  readonly callerUserId: string;
}) =>
  Effect.gen(function* () {
    if (input.checkpoint.payload.auditHeadHashHex === "") {
      return;
    }
    yield* requireRole(input.state, input.callerUserId, "admin");
    yield* ensureAuditHeadAcceptable(input.checkpoint.payload.auditHeadHashHex);
  });

// 境界 checkpoint の values_digest 内容突合(CRYPTO_SPEC §6.4 — 突合基準は
// 「複合の適用後の保存状態」。複合は値を変更しないため、受理時点の保存値 =
// 適用後の保存値)と監査ヘッド検査は standalone 経路と共有する
// (checkpoint-accept.ts — §16-2 の「保存規律は経路によらず同一」)。

/** 複合の書き込みフェーズで共有する依存とパラメータ(同期関数群の引数)。 */
interface CompositeWriteContext {
  readonly chainStore: {
    readonly insertSync: (entry: ChainEntry, entryHashHex: string, canonicalBytes: number) => void;
  };
  readonly dataStore: { readonly write: DataWriteOps };
  readonly audit: {
    readonly appendSync: (event: AuditEventInput) => void;
    readonly appendManySync: (events: readonly AuditEventInput[]) => void;
    // 受理副作用(chain-accept.ts)の検出入力。複合の op(create_environment /
    // rotate_epoch)では読まれないが、受理経路の型面を 1 つに保つ
    readonly readRotationSync: AuditRotationRead;
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
    readonly manifest: EnvManifestInput;
    /** 境界 checkpoint(H+2 — AUTH_SPEC §12-4。2026-08-27 セッション 33)。 */
    readonly checkpoint: ChainEntry & { readonly op: "checkpoint" };
  },
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { chain, state, history, member, projectId } = yield* loadChainForComposite(
      actor.userId,
      cache,
    );
    yield* ensureParentHead(chain, input.parentHeadHashHex);
    // 複合内の宣言ヘッド(§12-4): 同梱ステートメント・マニフェストの宣言ヘッドは
    // 追記前の現ヘッド(= 同梱エントリの prev)と厳密一致。CAS 通過後なので
    // 現ヘッド = parentHeadHashHex。ヘッド CAS 失敗の再試行ではエントリと
    // ステートメントとマニフェストの全部を再署名する(クライアント側 — env-create.ts)
    if (
      input.statement.chainHeadHashHex !== chain.headHashHex ||
      input.statement.chainHeadSeq !== chain.headSeq
    ) {
      return yield* rejectData({ kind: "payload-mismatch", field: "statementChainHead" });
    }
    if (
      input.manifest.chainHeadHashHex !== chain.headHashHex ||
      input.manifest.chainHeadSeq !== chain.headSeq
    ) {
      return yield* rejectData({ kind: "payload-mismatch", field: "manifestChainHead" });
    }
    // 複合内整合検査(§12-4): マニフェストの epoch = 同梱エントリが確立する
    // エポック(作成 = 1)。ラップの epoch 検査と同じ複合内の早期拒否で、
    // エポック整合の完全検証は acceptEnvManifest(適用後履歴)が行う
    if (input.manifest.epoch !== 1) {
      return yield* rejectData({ kind: "payload-mismatch", field: "manifestEpoch" });
    }
    const environmentId = input.entry.payload.environmentId;
    // 境界 checkpoint の同梱物一致(§12-4): 当該環境 1 タプル・epoch 1・
    // manifestVersion 1(ワイヤは Literal 1 だがタプル側も突合する)
    const checkpointTuple = yield* ensureBoundaryCheckpointShape({
      checkpoint: input.checkpoint,
      environmentId,
      establishedEpoch: 1,
      manifestVersion: input.manifest.manifestVersion,
    });
    // 非空 audit_head_hash の実効権限 admin + 存在・位置検査(§16-2 —
    // standalone 経路と同一規則)
    yield* ensureCheckpointAuditHead({
      checkpoint: input.checkpoint,
      state,
      callerUserId: actor.userId,
    });
    // 受理検査(サイズ → 容量 → verifyChain — §6.4 の合意規則 =
    // duplicate-environment / エポック順序 / role / コミットメント形式 /
    // checkpoint の合意規則を含む)は汎用チェーン API と共有(chain-accept.ts)。
    // create = H+1、境界 checkpoint = H+2 の 2 エントリを 1 回の全チェーン
    // 再検証で受理判定する
    const { firstCanonicalBytes, secondCanonicalBytes, applied } = yield* verifyAcceptableEntryPair(
      chain,
      input.entry,
      input.checkpoint,
    );
    const appliedState = applied.state;
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
    // 同梱マニフェストの受理(§12-4 / §12-5): manifestVersion 1・変数空集合・
    // epoch 1。エポック整合は両エントリ適用後の履歴(applied.history)に対する
    // チェックポイント束縛(§4.3 (2) — H+2 の境界 checkpoint タプルとの完全一致。
    // タプルのハッシュが同梱マニフェストと食い違えば checkpoint-binding-mismatch
    // で拒否 = §12-4 のハッシュ一致検査を兼ねる)で判定する
    const manifestSignedBytesHashHex = yield* acceptEnvManifest({
      projectId,
      environmentId,
      history: applied.history,
      member,
      manifest: input.manifest,
      entries: [],
      envMeta: { metaVersion: input.statement.metaVersion, sigHashHex: metaSignedBytesHashHex },
    });
    // 境界 checkpoint の values_digest(§6.4 — 作成 = 変数空集合の列挙)
    yield* ensureCheckpointValuesDigest(checkpointTuple, []);
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
    // (チェーンエントリ + ミラー + 環境行 + ステートメント行 + マニフェスト +
    // ラップ + 監査を分割しない — §12-4)
    yield* Effect.sync(() => {
      insertAcceptedEntryPairSync(
        writeContext,
        input.entry,
        input.checkpoint,
        applied,
        firstCanonicalBytes,
        secondCanonicalBytes,
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
      store.write.upsertEnvironmentManifest(
        environmentId,
        input.manifest,
        manifestSignedBytesHashHex,
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
      // 値スナップショットの原子保存(§6.4 / §16-2): 作成は空列挙 + タプル座標
      store.write.upsertCheckpointSnapshot(
        environmentId,
        {
          chainSeq: input.checkpoint.seq,
          entryHashHex: appliedState.headHashHex,
          epoch: checkpointTuple.epoch,
          manifestVersion: checkpointTuple.manifestVersion,
          manifestSigHashHex: checkpointTuple.manifestSigHashHex,
          valuesDigestHex: checkpointTuple.valuesDigestHex,
        },
        [],
        writeContext.nowMs,
      );
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
    readonly manifest: EnvManifestInput;
    /** 境界 checkpoint(H+2 — AUTH_SPEC §12-4。2026-08-27 セッション 33)。 */
    readonly checkpoint: ChainEntry & { readonly op: "checkpoint" };
  },
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { chain, state, member, projectId } = yield* loadChainForComposite(actor.userId, cache);
    // 複合内整合検査(§12-4): URL 座標と同梱エントリの environment_id の一致。
    // 各部分の独立検証だけで別環境のエントリ × 別環境のラップの組を受理しない
    if (input.entry.payload.environmentId !== environmentId) {
      return yield* rejectData({ kind: "payload-mismatch", field: "environmentId" });
    }
    // 削除済み(tombstone)環境への rotate は 404(§12-4 — §7 の「全環境」は
    // 削除済みを含まない。黙って受理して守るもののないエポックを進めない)
    yield* requireActiveEnvironment(environmentId);
    yield* ensureParentHead(chain, input.parentHeadHashHex);
    // 複合内の宣言ヘッド(§12-4)とエポック(= new_epoch)の整合検査。
    // ヘッド CAS 失敗の再試行ではエントリとマニフェストの両方を再署名する
    if (
      input.manifest.chainHeadHashHex !== chain.headHashHex ||
      input.manifest.chainHeadSeq !== chain.headSeq
    ) {
      return yield* rejectData({ kind: "payload-mismatch", field: "manifestChainHead" });
    }
    if (input.manifest.epoch !== input.entry.payload.newEpoch) {
      return yield* rejectData({ kind: "payload-mismatch", field: "manifestEpoch" });
    }
    // 境界 checkpoint の同梱物一致(§12-4): 当該環境 1 タプル・epoch = new_epoch・
    // manifestVersion = 同梱マニフェストの版
    const checkpointTuple = yield* ensureBoundaryCheckpointShape({
      checkpoint: input.checkpoint,
      environmentId,
      establishedEpoch: input.entry.payload.newEpoch,
      manifestVersion: input.manifest.manifestVersion,
    });
    // 非空 audit_head_hash の実効権限 admin + 存在・位置検査(§16-2 —
    // standalone 経路と同一規則)
    yield* ensureCheckpointAuditHead({
      checkpoint: input.checkpoint,
      state,
      callerUserId: actor.userId,
    });
    // rotate = H+1、境界 checkpoint = H+2 の 2 エントリ受理検査(chain-accept.ts)
    const { firstCanonicalBytes, secondCanonicalBytes, applied } = yield* verifyAcceptableEntryPair(
      chain,
      input.entry,
      input.checkpoint,
    );
    const appliedState = applied.state;
    // 同梱マニフェストの受理(§12-5 (4): エポック整合は両エントリ適用後の履歴に
    // 対するチェックポイント束縛 — §4.3 (2)。H+2 のタプルとの完全一致 = §12-4 の
    // ハッシュ一致検査を兼ねる)。メタ集合は不変(エポック前進の反映だけの
    // 再発行 — §4.3)なので entries は保存済みの最新形そのまま。
    // マニフェスト導入前に作成された環境の最初の rotate は保存行なし(最新 0)
    // から manifestVersion 1 を確立する(移行経路 — session-27 §14 PR-M1)
    const manifestSignedBytesHashHex = yield* acceptEnvManifest({
      projectId,
      environmentId,
      history: applied.history,
      member,
      manifest: input.manifest,
      entries: yield* manifestDigestEntries(environmentId, null),
      envMeta: yield* storedEnvMeta(environmentId),
    });
    // 境界 checkpoint の values_digest(§6.4 — 突合基準は複合の適用後状態。
    // 複合は値を変更しないため受理時点の保存値と同一。rotate では未再暗号化 =
    // 旧エポックの現在値の列挙 — §12-7 の正当な状態。宣言ヘッド確定後の並行
    // push が挟まると不一致 = 422 で、クライアントは再 pull + 有界再試行)
    const snapshotValues = yield* Effect.flatMap(DataStore, (store) =>
      store.checkpointValueEntries(environmentId),
    );
    yield* ensureCheckpointValuesDigest(checkpointTuple, snapshotValues);
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
      insertAcceptedEntryPairSync(
        writeContext,
        input.entry,
        input.checkpoint,
        applied,
        firstCanonicalBytes,
        secondCanonicalBytes,
        writeContext.nowMs,
      );
      writeContext.dataStore.write.upsertEnvironmentManifest(
        environmentId,
        input.manifest,
        manifestSignedBytesHashHex,
        { userId: member.userId, keyFingerprintHex: member.keyFingerprintHex },
        writeContext.nowMs,
      );
      insertCompositeWrapsSync(writeContext, input.deks);
      // 値スナップショットの原子保存(§6.4 / §16-2): 受理時点の現在値の列挙
      // (突合済み)+ タプル座標を最新包含 checkpoint として upsert する
      writeContext.dataStore.write.upsertCheckpointSnapshot(
        environmentId,
        {
          chainSeq: input.checkpoint.seq,
          entryHashHex: appliedState.headHashHex,
          epoch: checkpointTuple.epoch,
          manifestVersion: checkpointTuple.manifestVersion,
          manifestSigHashHex: checkpointTuple.manifestSigHashHex,
          valuesDigestHex: checkpointTuple.valuesDigestHex,
        },
        snapshotValues,
        writeContext.nowMs,
      );
    });
    updateStateCache(cache, applied);
    return compositeResult(environmentId, input.entry.payload.newEpoch, appliedState);
  });
