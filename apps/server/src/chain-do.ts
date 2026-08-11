// プロジェクト DO: メンバーシップチェーンの append-only 保存(CRYPTO_SPEC §6.4)、
// データプレーン(環境・変数・暗号文・ラップ済み DEK — AUTH_SPEC §12)、監査ログ
// (AUDIT_SPEC §5.1)を 1 DO に併置する(§4 のクエリがクロスストア join なしで
// 成立し、チェーン追記とミラー追記が同じ直列化の下で書ける)。
//
// - サーバー側検証: 追記受理時に verifyChain(@maruhi/crypto)を再実行する。
//   クライアント検証(§6.3)がサーバー不信の防衛、この検証が不正クライアントの
//   防衛であり、両方必須(§6.4)
// - 直列化 + CAS: 追記リクエストは親ヘッドハッシュを持ち、現ヘッドと不一致なら
//   拒否する。DO 内の操作は Semaphore(1) で直列化する — DO の input gate は
//   ストレージ以外の await(verifyChain 内の crypto.subtle)中に開くため、
//   ゲート任せでは追記同士が交錯しうる。データプレーンの変更も同じ permit を
//   共有する(並行 push の欠損・交錯防止)。**読み取りも同じ permit で直列化する**:
//   permit 外で読むと「メンバーシップ判定(チェーン導出)→ データ読み」の間に
//   remove_member の受理が割り込み、削除直後のメンバーへ値を配布しうる
//   (§11-2 違反の TOCTOU。Bugbot 指摘 2026-08-02)。permit 下では全操作が
//   チェーン書き込みに対して線形化される。PRIMARY KEY 制約が最終防衛
// - 受理ポリシー: チェーンは §6.4(1 MiB / 10,000 エントリ / 32 MiB)、データは
//   §12-8(policy.ts)
// - ストレージ(DO SQLite)は Effect サービス(ChainStore / DataStore /
//   AuditStore)の背後に隔離する。DDL は do-schema.ts(コンストラクタで適用)

import type { ChainInvalidError } from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { DurableObject } from "cloudflare:workers";
import { Data, Effect, Layer, ManagedRuntime, Semaphore } from "effect";

import { AuditStore, auditStoreLayer, chainMirrorEvent } from "./audit-store.ts";
import type { StateCache, StoredChain } from "./chain-store.ts";
import {
  canonicalBytesOf,
  ChainStore,
  chainStoreLayer,
  deriveStoredState,
  updateStateCache,
  verifyChainEffect,
} from "./chain-store.ts";
import type { EnvironmentChainResultValue } from "./composite-programs.ts";
import {
  createEnvironmentCompositeProgram,
  rotateEpochCompositeProgram,
} from "./composite-programs.ts";
import type {
  DataActor,
  DataOutcome,
  DataRejectedError,
  DataRejection,
  DekWrapInput,
  DekWrapRefInput,
  EnvironmentMetadataPullValue,
  EnvironmentPullValue,
  EnvironmentSummaryValue,
  MetaStatementInput,
  RecipientDekValue,
  ValueInput,
  VariableVersionValue,
} from "./data-plane.ts";
import { rejectData } from "./data-plane.ts";
import {
  createVariableProgram,
  deleteDekWrapsProgram,
  deleteEnvironmentProgram,
  deleteVariableProgram,
  listEnvironmentsProgram,
  listMyDekWrapsProgram,
  pullEnvironmentMetadataProgram,
  pullEnvironmentProgram,
  pushVersionProgram,
  registerDekWrapsProgram,
  renameEnvironmentProgram,
  renameVariableProgram,
} from "./data-programs.ts";
import { DataStore, dataStoreLayer } from "./data-store.ts";
import { ensureProjectDoTables } from "./do-schema.ts";
import {
  MAX_CHAIN_ENTRIES,
  MAX_CHAIN_TOTAL_CANONICAL_BYTES,
  MAX_ENTRY_CANONICAL_BYTES,
} from "./policy.ts";

export interface Env {
  readonly PROJECT_CHAIN: DurableObjectNamespace<ProjectChainDO>;
  readonly DB: D1Database;
  /** GitHub OAuth App の client_id(Workers Secret / .dev.vars。公開情報だが登録経路は secret に統一 — AUTH_SPEC §3-2)。 */
  readonly GITHUB_CLIENT_ID: string;
  /** GitHub OAuth App の client_secret(Workers Secret / .dev.vars。ダミー値のみコミット可)。 */
  readonly GITHUB_CLIENT_SECRET: string;
}

// ---------------------------------------------------------------------------
// 型付きエラー(DO 内部)と RPC 境界の outcome 型
//
// チェーン API の拒否も DataRejection(data-plane.ts)で運ぶ: タグ付きエラー →
// outcome の写像は toDataOutcome の 1 本、拒否 → api-schema エラーの写像は
// worker 側の rejectionErrors(data-http.ts — Record 形で網羅が型強制される)の
// 1 表に集約される。init だけは「初期化済み(冪等修復の判定材料)」という
// 拒否でない分岐を持つため専用 outcome を残す。
// ---------------------------------------------------------------------------

class AlreadyInitializedError extends Data.TaggedError("AlreadyInitialized")<{
  readonly genesisActorUserId: string;
  readonly headSeq: number;
  readonly headHashHex: string;
}> {}
class ProjectIdMismatchError extends Data.TaggedError("ProjectIdMismatch")<object> {}

/** チェーンヘッド(受理成功の RPC 値)。 */
export interface ChainHeadValue {
  readonly headSeq: number;
  readonly headHashHex: string;
}

/** チェーン全体のスナップショット(取得成功の RPC 値)。 */
export interface ChainSnapshotValue {
  readonly entries: readonly ChainEntry[];
  readonly headSeq: number;
  readonly headHashHex: string;
}

/** RPC 境界(structured clone)を渡る初期化結果。 */
export type InitOutcome =
  | { readonly kind: "initialized"; readonly headSeq: number; readonly headHashHex: string }
  | {
      /**
       * 初期化済み。genesis actor と現ヘッドを返すのは、worker 側の冪等修復
       * (AUTH_SPEC §11-3: projects 行欠損 + 要求者 = genesis actor なら成功扱い)
       * の判定材料のため。
       */
      readonly kind: "already-initialized";
      readonly genesisActorUserId: string;
      readonly headSeq: number;
      readonly headHashHex: string;
    }
  | { readonly kind: "project-id-mismatch" }
  | { readonly kind: "rejected"; readonly rejection: DataRejection };

/** RPC 境界を渡る追記結果。 */
export type AppendOutcome = DataOutcome<ChainHeadValue>;

/** RPC 境界を渡るチェーン取得結果。 */
export type SnapshotOutcome = DataOutcome<ChainSnapshotValue>;

// ---------------------------------------------------------------------------
// Effect プログラム(チェーン検証・受理判定の本体)
// ---------------------------------------------------------------------------

/** ChainInvalid(検証・エンコーダ失敗)→ chain-entry-invalid 拒否。 */
const rejectChainInvalid = (error: ChainInvalidError): DataRejectedError =>
  rejectData({ kind: "chain-entry-invalid", seq: error.seq, reason: error.reason });

function checkEntrySize(entry: ChainEntry): Effect.Effect<number, DataRejectedError> {
  return canonicalBytesOf(entry).pipe(
    Effect.mapError(rejectChainInvalid),
    Effect.flatMap((bytes) =>
      bytes > MAX_ENTRY_CANONICAL_BYTES
        ? Effect.fail(
            rejectData({ kind: "chain-entry-too-large", limitBytes: MAX_ENTRY_CANONICAL_BYTES }),
          )
        : Effect.succeed(bytes),
    ),
  );
}

/** §6.2 / §11-2: チェーン導出メンバー(reader 含む)でなければ拒否する。 */
function ensureChainMember(
  members: ReadonlyMap<string, unknown>,
  userId: string,
): Effect.Effect<void, DataRejectedError> {
  return members.has(userId) ? Effect.void : Effect.fail(rejectData({ kind: "not-member" }));
}

/**
 * チェーン追記の受理と同時に §3.4 のミラーイベントを記録する。単一の同期
 * ブロック(= 同一イベントループタスク)で両方を書き、クラッシュしても
 * 「チェーンだけ書けてミラーが欠ける」不整合を作らない(ミラーは v1 バック
 * フィルなし — AUDIT_SPEC §3.4 — なので欠落は恒久化する)。
 */
const insertWithMirror = (entry: ChainEntry, entryHashHex: string, canonicalBytes: number) =>
  Effect.gen(function* () {
    const store = yield* ChainStore;
    const audit = yield* AuditStore;
    yield* Effect.sync(() => {
      store.insertSync(entry, entryHashHex, canonicalBytes);
      audit.appendSync(chainMirrorEvent(entry, Date.now()));
    });
  });

const initProgram = (expectedProjectId: string, entry: ChainEntry, cache: StateCache) =>
  Effect.gen(function* () {
    const store = yield* ChainStore;
    const chain = yield* store.load;
    if (chain.headSeq > 0) {
      const genesisActor = chain.entries[0]?.actor.userId;
      if (genesisActor === undefined || chain.headHashHex === null) {
        // headSeq > 0 なら両値は不変条件として存在する。欠けているのはストレージ
        // 破損であり、空文字で成功応答に変換せず defect として落とす
        return yield* Effect.die(new Error("initialized chain is missing genesis or head"));
      }
      return yield* new AlreadyInitializedError({
        genesisActorUserId: genesisActor,
        headSeq: chain.headSeq,
        headHashHex: chain.headHashHex,
      });
    }
    const canonicalBytes = yield* checkEntrySize(entry);
    // genesis 以外・不正署名などは verifyChain が §6.3 の理由コードで拒否する
    const verified = yield* verifyChainEffect([entry]).pipe(Effect.mapError(rejectChainInvalid));
    // プロジェクト ID = genesis エントリハッシュ(§6.4)。ルーティングした DO と
    // エントリの束縛が崩れていたら受理しない(worker 側バグへの防衛)
    if (verified.state.headHashHex !== expectedProjectId) {
      return yield* new ProjectIdMismatchError();
    }
    yield* insertWithMirror(entry, verified.state.headHashHex, canonicalBytes);
    updateStateCache(cache, verified);
    return { headSeq: verified.state.headSeq, headHashHex: verified.state.headHashHex };
  });

/**
 * CAS(§6.4): 未初期化を拒否し、親ヘッドが現ヘッドと一致しなければ現ヘッド情報
 * 付きで拒否する。クライアントは最新チェーンを取得・再検証して再試行する。
 */
function ensureParentHead(
  chain: StoredChain,
  parentHeadHashHex: string,
): Effect.Effect<void, DataRejectedError> {
  if (chain.headSeq === 0 || chain.headHashHex === null) {
    return Effect.fail(rejectData({ kind: "not-initialized" }));
  }
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
 * 受理ポリシー(§6.4): チェーン全体のエントリ数・累積バイト数の上限。
 * 判定は数値のみに依存する純関数(エントリ数上限のユニットテストのために公開。
 * 10,000 本の有効チェーンを統合テストで実生成するのは非現実的なため)。
 */
export function chainCapacityExceeded(
  entryCount: number,
  totalCanonicalBytes: number,
  addedCanonicalBytes: number,
): boolean {
  return (
    entryCount + 1 > MAX_CHAIN_ENTRIES ||
    totalCanonicalBytes + addedCanonicalBytes > MAX_CHAIN_TOTAL_CANONICAL_BYTES
  );
}

function ensureChainCapacity(
  chain: StoredChain,
  canonicalBytes: number,
): Effect.Effect<void, DataRejectedError> {
  if (chainCapacityExceeded(chain.entries.length, chain.totalCanonicalBytes, canonicalBytes)) {
    return Effect.fail(
      rejectData({
        kind: "chain-capacity-exceeded",
        maxEntries: MAX_CHAIN_ENTRIES,
        maxTotalBytes: MAX_CHAIN_TOTAL_CANONICAL_BYTES,
      }),
    );
  }
  return Effect.void;
}

/**
 * 読み取り・追記に共通する前段: 未初期化の検査と、チェーン導出メンバーシップの
 * 検査(§6.2 / §11-2)。非メンバーには CAS の現ヘッド情報・受理ポリシーの判定
 * 結果を含む一切を返さない(worker が not-member を 404 に写す)。
 */
const loadChainForMember = (callerUserId: string, cache: StateCache) =>
  Effect.gen(function* () {
    const store = yield* ChainStore;
    const chain = yield* store.load;
    if (chain.headSeq === 0 || chain.headHashHex === null) {
      return yield* rejectData({ kind: "not-initialized" });
    }
    const { state } = yield* deriveStoredState(chain, cache);
    yield* ensureChainMember(state.members, callerUserId);
    return {
      entries: chain.entries,
      headSeq: chain.headSeq,
      headHashHex: chain.headHashHex,
      genesisHashHex: chain.genesisHashHex,
      totalCanonicalBytes: chain.totalCanonicalBytes,
    };
  });

const appendProgram = (
  parentHeadHashHex: string,
  entry: ChainEntry,
  callerUserId: string,
  cache: StateCache,
): Effect.Effect<ChainHeadValue, DataRejectedError, ChainStore | AuditStore> =>
  Effect.gen(function* () {
    // AUTH_SPEC §6 / §12-4: create_environment / rotate_epoch は複合エンドポイント
    // 経由のみ。worker ハンドラが先行拒否するが、汎用 append の呼び出し経路が
    // 将来増えても「エポック / 環境はチェーンにあるがラップ・環境行がない」状態を
    // 作れないよう、受理判定の権威である DO 側にも同じガードを置く(多層防御)
    if (entry.op === "create_environment" || entry.op === "rotate_epoch") {
      return yield* rejectData({ kind: "composite-required", op: entry.op });
    }
    const chain = yield* loadChainForMember(callerUserId, cache);
    yield* ensureParentHead(chain, parentHeadHashHex);
    const canonicalBytes = yield* checkEntrySize(entry);
    yield* ensureChainCapacity(chain, canonicalBytes);
    // §6.4: 追記受理時にチェーン全体を再検証する(prev_hash 連続性・署名・操作権限)
    const verified = yield* verifyChainEffect([...chain.entries, entry]).pipe(
      Effect.mapError(rejectChainInvalid),
    );
    yield* insertWithMirror(entry, verified.state.headHashHex, canonicalBytes);
    updateStateCache(cache, verified);
    return { headSeq: verified.state.headSeq, headHashHex: verified.state.headHashHex };
  });

const snapshotProgram = (
  callerUserId: string,
  cache: StateCache,
): Effect.Effect<ChainSnapshotValue, DataRejectedError, ChainStore> =>
  Effect.map(loadChainForMember(callerUserId, cache), (chain) => ({
    entries: chain.entries,
    headSeq: chain.headSeq,
    headHashHex: chain.headHashHex,
  }));

// ---------------------------------------------------------------------------
// Durable Object(ManagedRuntime パターン。spike-b の確立形)
// ---------------------------------------------------------------------------

type DoServices = ChainStore | DataStore | AuditStore;

/** データプレーンの拒否を RPC outcome へ畳む(成功は ok 側)。 */
const toDataOutcome = <T, R>(
  program: Effect.Effect<T, DataRejectedError, R>,
): Effect.Effect<DataOutcome<T>, never, R> =>
  program.pipe(
    Effect.map((value): DataOutcome<T> => ({ kind: "ok", value })),
    Effect.catchTag("DataRejected", (error): Effect.Effect<DataOutcome<T>> =>
      Effect.succeed({ kind: "rejected", rejection: error.rejection }),
    ),
  );

export class ProjectChainDO extends DurableObject<Env> {
  readonly #runtime: ManagedRuntime.ManagedRuntime<DoServices, never>;
  // 全操作(変更 + 読み取り)の直列化(冒頭コメント参照)
  readonly #opLock = Semaphore.makeUnsafe(1);
  // チェーン導出状態 + parse 済みチェーンのキャッシュ(chain-store.ts 参照)
  readonly #stateCache: StateCache = { current: null, chain: null };

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ensureProjectDoTables(ctx.storage);
    this.#runtime = ManagedRuntime.make(
      Layer.mergeAll(
        chainStoreLayer(ctx.storage.sql, this.#stateCache),
        dataStoreLayer(ctx.storage.sql),
        auditStoreLayer(ctx.storage.sql),
      ),
    );
  }

  /**
   * データプレーンのプログラムを permit 下で outcome に畳んで実行する。
   * 読み取りも permit を取る: メンバーシップ判定とデータ読みをチェーン書き込みに
   * 対して原子化する(冒頭コメントの TOCTOU 対策)。
   */
  #runData<T>(program: Effect.Effect<T, DataRejectedError, DoServices>): Promise<DataOutcome<T>> {
    return this.#runtime.runPromise(this.#opLock.withPermit(toDataOutcome(program)));
  }

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  init(expectedProjectId: string, entry: ChainEntry): Promise<InitOutcome> {
    // 拒否(DataRejected)は toDataOutcome と同じ rejected 形へ畳む。init 固有の
    // 「初期化済み」(拒否ではない — 冪等修復の判定材料)と worker 側バグ検出の
    // project-id-mismatch だけが専用分岐を持つ
    return this.#runtime.runPromise(
      this.#opLock.withPermit(
        initProgram(expectedProjectId, entry, this.#stateCache).pipe(
          Effect.map((head): InitOutcome => ({
            kind: "initialized",
            headSeq: head.headSeq,
            headHashHex: head.headHashHex,
          })),
          Effect.catchTags({
            AlreadyInitialized: (error): Effect.Effect<InitOutcome> =>
              Effect.succeed({
                kind: "already-initialized",
                genesisActorUserId: error.genesisActorUserId,
                headSeq: error.headSeq,
                headHashHex: error.headHashHex,
              }),
            ProjectIdMismatch: (): Effect.Effect<InitOutcome> =>
              Effect.succeed({ kind: "project-id-mismatch" }),
            DataRejected: (error): Effect.Effect<InitOutcome> =>
              Effect.succeed({ kind: "rejected", rejection: error.rejection }),
          }),
        ),
      ),
    );
  }

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  append(
    parentHeadHashHex: string,
    entry: ChainEntry,
    callerUserId: string,
  ): Promise<AppendOutcome> {
    return this.#runData(appendProgram(parentHeadHashHex, entry, callerUserId, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  snapshotFor(callerUserId: string): Promise<SnapshotOutcome> {
    return this.#runData(snapshotProgram(callerUserId, this.#stateCache));
  }

  // --- データプレーン RPC(AUTH_SPEC §12) -------------------------------

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  createEnvironment(
    actor: DataActor,
    input: {
      readonly parentHeadHashHex: string;
      readonly entry: ChainEntry & { readonly op: "create_environment" };
      readonly statement: MetaStatementInput;
      readonly deks: readonly DekWrapInput[];
    },
  ): Promise<DataOutcome<EnvironmentChainResultValue>> {
    // 複合受理(§12-4): チェーン追記(CAS + verifyChain)とデータ登録を同一
    // permit・同一同期ブロックで原子化する(§6.4 の複合受理)
    return this.#runData(createEnvironmentCompositeProgram(actor, input, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  rotateEpoch(
    actor: DataActor,
    environmentId: string,
    input: {
      readonly parentHeadHashHex: string;
      readonly entry: ChainEntry & { readonly op: "rotate_epoch" };
      readonly deks: readonly DekWrapInput[];
    },
  ): Promise<DataOutcome<EnvironmentChainResultValue>> {
    return this.#runData(
      rotateEpochCompositeProgram(actor, environmentId, input, this.#stateCache),
    );
  }

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  renameEnvironment(
    actor: DataActor,
    environmentId: string,
    statement: MetaStatementInput,
  ): Promise<DataOutcome<void>> {
    return this.#runData(
      renameEnvironmentProgram(actor, environmentId, statement, this.#stateCache),
    );
  }

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  deleteEnvironment(
    actor: DataActor,
    environmentId: string,
    statement: MetaStatementInput,
  ): Promise<DataOutcome<void>> {
    return this.#runData(
      deleteEnvironmentProgram(actor, environmentId, statement, this.#stateCache),
    );
  }

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  listEnvironments(actor: DataActor): Promise<DataOutcome<readonly EnvironmentSummaryValue[]>> {
    return this.#runData(listEnvironmentsProgram(actor, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  createVariable(
    actor: DataActor,
    environmentId: string,
    input: {
      readonly variableId: string;
      readonly statement: MetaStatementInput;
      readonly value: ValueInput;
    },
  ): Promise<DataOutcome<VariableVersionValue>> {
    return this.#runData(createVariableProgram(actor, environmentId, input, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  pushVersion(
    actor: DataActor,
    environmentId: string,
    variableId: string,
    value: ValueInput,
  ): Promise<DataOutcome<VariableVersionValue>> {
    return this.#runData(
      pushVersionProgram(actor, environmentId, variableId, value, this.#stateCache),
    );
  }

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  renameVariable(
    actor: DataActor,
    environmentId: string,
    variableId: string,
    statement: MetaStatementInput,
  ): Promise<DataOutcome<void>> {
    return this.#runData(
      renameVariableProgram(actor, environmentId, variableId, statement, this.#stateCache),
    );
  }

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  deleteVariable(
    actor: DataActor,
    environmentId: string,
    variableId: string,
    statement: MetaStatementInput,
  ): Promise<DataOutcome<void>> {
    return this.#runData(
      deleteVariableProgram(actor, environmentId, variableId, statement, this.#stateCache),
    );
  }

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  pullEnvironment(
    actor: DataActor,
    environmentId: string,
  ): Promise<DataOutcome<EnvironmentPullValue>> {
    return this.#runData(pullEnvironmentProgram(actor, environmentId, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  pullEnvironmentMetadata(
    actor: DataActor,
    environmentId: string,
  ): Promise<DataOutcome<EnvironmentMetadataPullValue>> {
    return this.#runData(pullEnvironmentMetadataProgram(actor, environmentId, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  registerDekWraps(
    actor: DataActor,
    environmentId: string,
    wraps: readonly DekWrapInput[],
  ): Promise<DataOutcome<void>> {
    return this.#runData(registerDekWrapsProgram(actor, environmentId, wraps, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  listMyDekWraps(
    actor: DataActor,
    environmentId: string,
  ): Promise<DataOutcome<readonly RecipientDekValue[]>> {
    return this.#runData(listMyDekWrapsProgram(actor, environmentId, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  deleteDekWraps(
    actor: DataActor,
    environmentId: string,
    refs: readonly DekWrapRefInput[],
  ): Promise<DataOutcome<void>> {
    return this.#runData(deleteDekWrapsProgram(actor, environmentId, refs, this.#stateCache));
  }
}
