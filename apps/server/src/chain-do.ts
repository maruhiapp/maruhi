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

import type { ChainEntry, Role } from "@maruhi/crypto";
import { DurableObject } from "cloudflare:workers";
import { Data, Effect, Layer, ManagedRuntime, Semaphore } from "effect";

import type { HeadAttestationSubmissionInput } from "./attestation-accept.ts";
import { putHeadAttestationProgram } from "./attestation-accept.ts";
import { AuditStore, auditStoreLayer } from "./audit-store.ts";
import { ensureParentHead, verifyAcceptableEntry } from "./chain-accept.ts";
import { commitAcceptedEntry } from "./chain-commit.ts";
import type { StateCache } from "./chain-store.ts";
import { ChainStore, chainStoreLayer, deriveStoredState, updateStateCache } from "./chain-store.ts";
import { standaloneCheckpointProgram } from "./checkpoint-accept.ts";
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
  EnvManifestInput,
  MetaStatementInput,
  RecipientDekValue,
  ValueInput,
  VariableVersionValue,
} from "./data-plane.ts";
import { rejectData, requireMemberState } from "./data-plane.ts";
import type { StoredHeadAttestation } from "./data-store.ts";
import { DataStore, dataStoreLayer } from "./data-store.ts";
import { ensureProjectDoTables } from "./do-schema.ts";
import type { AuditEventsQueryInput, AuditEventValue } from "./programs-audit.ts";
import { auditEventsProgram, auditHeadProgram } from "./programs-audit.ts";
import {
  deleteDekWrapsProgram,
  listMyDekWrapsProgram,
  registerDekWrapsProgram,
} from "./programs-dek.ts";
import {
  deleteEnvironmentProgram,
  listEnvironmentsProgram,
  pullEnvironmentMetadataProgram,
  pullEnvironmentProgram,
  renameEnvironmentProgram,
} from "./programs-environment.ts";
import type { LeaseOutcome, LeaseTokenFacts, LeaseValue } from "./programs-lease.ts";
import { leaseProgram } from "./programs-lease.ts";
import type { RotationDismissTargetInput } from "./programs-rotation.ts";
import { dismissRotationFlagsProgram, rotationFlagsProgram } from "./programs-rotation.ts";
import {
  createVariableProgram,
  deleteVariableProgram,
  pushVersionProgram,
  renameVariableProgram,
} from "./programs-variable.ts";
import type { EffectiveRotationFlag } from "./rotation-detect.ts";
import { makeServerKey, ServerKey } from "./server-key.ts";

export interface Env {
  readonly PROJECT_CHAIN: DurableObjectNamespace<ProjectChainDO>;
  readonly DB: D1Database;
  /** GitHub OAuth App の client_id(Workers Secret / .dev.vars。公開情報だが登録経路は secret に統一 — AUTH_SPEC §3-2)。 */
  readonly GITHUB_CLIENT_ID: string;
  /** GitHub OAuth App の client_secret(Workers Secret / .dev.vars。ダミー値のみコミット可)。 */
  readonly GITHUB_CLIENT_SECRET: string;
  /**
   * デプロイメント keypair の入力鍵材料(Workers Secret / .dev.vars。32 バイト
   * hex — CRYPTO_SPEC §9)。keypair は RFC 9180 DeriveKeyPair で起動時に導出する
   * (server-key.ts)。未設定 = 選択的開示なしの純粋 E2EE デプロイメント(既定)。
   * secret を欠いたデプロイでは実行時に undefined。
   */
  readonly SERVER_ENC_KEY_IKM?: string;
  /**
   * 未認証 CLI ログイン start の発信元 IP レート制限(AUTH_SPEC §4-1 (1) —
   * wrangler.jsonc の ratelimits。無記録 start なので DB 保護ではなく CPU 保護)。
   * 旧設定のままの self-host デプロイでは undefined になりうるため optional
   * (不在は制限なしで従来挙動)。
   */
  readonly CLI_START_RATE_LIMIT?: RateLimit;
  /**
   * 未認証 CLI ログイン poll の発信元 IP レート制限(AUTH_SPEC §4-1 (5) —
   * ポーリング間隔の下限 5 秒 = 12 回/分を正常系が下回るよう、start より緩い
   * 上限にする。超過ポーリングの 429 拒否は仕様が明示的に許す)。
   */
  readonly CLI_POLL_RATE_LIMIT?: RateLimit;
  /**
   * 未認証 OAuth callback の発信元 IP レート制限(deepsec R7)。callback は
   * リクエストごとに GitHub の token endpoint を叩き、OAuth App 単位の共有
   * クォータを消費する。state は cookie と query の二重送信(サーバー側状態
   * なし)なので、非ブラウザの発信元は両方を自分で用意できて検査を通せる —
   * 頻度を縛るのはこの binding だけ。ブラウザの対話ログイン(CLI ブラウザ脚
   * 含む)は共有 egress で束になるため、start より緩い上限にする
   * (docs/SELF_HOSTING.md の WAF 推奨値と同じ 30/min)。
   */
  readonly OAUTH_CALLBACK_RATE_LIMIT?: RateLimit;
  /**
   * lease 発行の発信元 IP レート制限(deepsec M5)。DO は名前指定で暗黙生成
   * されるため、有効な OIDC token だけで任意の project ID の DO を量産できる —
   * projectStub 到達前の request-level 制限で生成レートを有界にする。
   */
  readonly LEASE_RATE_LIMIT?: RateLimit;
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

/**
 * チェーン全体のスナップショット(取得成功の RPC 値)。attestations は
 * **現メンバーの最新ヘッド申告のみ**(AUTH_SPEC §16-1 — remove 時の行削除
 * 〔chain-accept.ts〕に加えて配布側でも現メンバー集合で絞る独立の防衛層)。
 */
export interface ChainSnapshotValue {
  readonly entries: readonly ChainEntry[];
  readonly headSeq: number;
  readonly headHashHex: string;
  readonly attestations: readonly StoredHeadAttestation[];
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

/** §6.2 / §11-2: チェーン導出メンバー(reader 含む)でなければ拒否する。 */
function ensureChainMember(
  members: ReadonlyMap<string, unknown>,
  userId: string,
): Effect.Effect<void, DataRejectedError> {
  return members.has(userId) ? Effect.void : Effect.fail(rejectData({ kind: "not-member" }));
}

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
    // 空チェーンへの受理 4 手順(容量検査は空チェーンでは自明に通る)。
    // genesis 以外・不正署名などは verifyChain が §6.3 の理由コードで拒否する
    const { canonicalBytes, applied } = yield* verifyAcceptableEntry(chain, entry);
    // プロジェクト ID = genesis エントリハッシュ(§6.4)。ルーティングした DO と
    // エントリの束縛が崩れていたら受理しない(worker 側バグへの防衛)
    if (applied.state.headHashHex !== expectedProjectId) {
      return yield* new ProjectIdMismatchError();
    }
    yield* commitAcceptedEntry(entry, applied, canonicalBytes);
    updateStateCache(cache, applied);
    return { headSeq: applied.state.headSeq, headHashHex: applied.state.headHashHex };
  });

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
      members: state.members,
    };
  });

const appendProgram = (
  parentHeadHashHex: string,
  entry: ChainEntry,
  callerUserId: string,
  cache: StateCache,
): Effect.Effect<ChainHeadValue, DataRejectedError, ChainStore | AuditStore | DataStore> =>
  Effect.gen(function* () {
    // AUTH_SPEC §6 / §12-4: create_environment / rotate_epoch は複合エンドポイント
    // 経由のみ。worker ハンドラが先行拒否するが、汎用 append の呼び出し経路が
    // 将来増えても「エポック / 環境はチェーンにあるがラップ・環境行がない」状態を
    // 作れないよう、受理判定の権威である DO 側にも同じガードを置く(多層防御)
    if (entry.op === "create_environment" || entry.op === "rotate_epoch") {
      return yield* rejectData({ kind: "composite-required", op: entry.op });
    }
    // standalone(周期)checkpoint(AUTH_SPEC §16-2 — 2026-08-28 PR-M2):
    // 汎用 append が受理するが、受理検証(受理時点状態との内容突合)と
    // スナップショットの原子保存を伴う専用経路へ分岐する
    if (entry.op === "checkpoint") {
      return yield* standaloneCheckpointProgram(parentHeadHashHex, entry, callerUserId, cache);
    }
    const chain = yield* loadChainForMember(callerUserId, cache);
    yield* ensureParentHead(chain, parentHeadHashHex);
    // 受理 4 手順(サイズ → 容量 → verifyChain → insert + ミラー)は複合経路と
    // 共有(chain-accept.ts)
    const { canonicalBytes, applied } = yield* verifyAcceptableEntry(chain, entry);
    yield* commitAcceptedEntry(entry, applied, canonicalBytes);
    updateStateCache(cache, applied);
    return { headSeq: applied.state.headSeq, headHashHex: applied.state.headHashHex };
  });

const snapshotProgram = (
  callerUserId: string,
  cache: StateCache,
): Effect.Effect<ChainSnapshotValue, DataRejectedError, ChainStore | DataStore> =>
  Effect.gen(function* () {
    const chain = yield* loadChainForMember(callerUserId, cache);
    // 申告の同梱(AUTH_SPEC §16-1): 現メンバーの最新申告のみ。remove_member
    // 受理時の行削除(chain-accept.ts)が真実源への収束を担い、ここでの現
    // メンバー絞り込みは独立の防衛層(§6.6 (1) のクライアント検査とも一致)
    const dataStore = yield* DataStore;
    const attestations = (yield* dataStore.listHeadAttestations).filter((attestation) =>
      chain.members.has(attestation.attesterUserId),
    );
    return {
      entries: chain.entries,
      headSeq: chain.headSeq,
      headHashHex: chain.headHashHex,
      attestations,
    };
  });

/**
 * 呼び出し主体のチェーン導出 role(招待 API — AUTH_SPEC §15-2 — の認可入力)。
 * 下限は reader(= メンバーであること): 非メンバーは not-member で拒否され
 * worker が 404 に写す(§11-2)。admin / owner の水準判定は worker 側が行う
 * (role=admin の招待は owner のみ、等のエンドポイント別規則)。
 */
const memberRoleProgram = (
  callerUserId: string,
  cache: StateCache,
): Effect.Effect<Role, DataRejectedError, ChainStore> =>
  Effect.map(requireMemberState(callerUserId, "reader", cache), (context) => context.member.role);

// ---------------------------------------------------------------------------
// Durable Object(ManagedRuntime パターン。spike-b の確立形)
// ---------------------------------------------------------------------------

type DoServices = ChainStore | DataStore | AuditStore | ServerKey;

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
        // リースの開封 + 再ラップは DO 内で行う(programs-lease.ts の冒頭:
        // 監査の原子性)。worker 側の ServerKey とは別インスタンスだが、
        // 同じ Workers Secret から同じ keypair を導出する
        Layer.sync(ServerKey, () => makeServerKey(env.SERVER_ENC_KEY_IKM)),
      ),
    );
  }

  /**
   * タスク失敗時のインスタンスメモリ無効化。DO ストレージはタスク単位で
   * ロールバックされるが、インスタンスメモリ(parse 済みチェーン・導出状態・
   * 監査採番)は残る。書き込みフェーズ途中の defect でキャッシュだけが前進した
   * まま残ると、ロールバック済みストレージと食い違う phantom 状態を配って
   * しまう(最悪、phantom ヘッドへの後続追記で保存チェーンに欠番が恒久化し、
   * 再起動後の全操作が defect になる)ため、失敗経路では必ず破棄して次の
   * ロード / 追記を保存状態からの再読込に戻す。受理拒否(DataRejected)は
   * 書き込みフェーズ前に確定するため対象外(キャッシュは前進していない)。
   */
  #invalidateCachesOnDefect<A, E>(
    program: Effect.Effect<A, E, DoServices>,
  ): Effect.Effect<A, E, DoServices> {
    const cache = this.#stateCache;
    return program.pipe(
      Effect.catchDefect((defect) =>
        Effect.gen(function* () {
          const audit = yield* AuditStore;
          cache.chain = null;
          cache.current = null;
          audit.resetSeqCacheSync();
          return yield* Effect.die(defect);
        }),
      ),
    );
  }

  /**
   * データプレーンのプログラムを permit 下で outcome に畳んで実行する。
   * 読み取りも permit を取る: メンバーシップ判定とデータ読みをチェーン書き込みに
   * 対して原子化する(冒頭コメントの TOCTOU 対策)。
   */
  #runData<T>(program: Effect.Effect<T, DataRejectedError, DoServices>): Promise<DataOutcome<T>> {
    return this.#runtime.runPromise(
      this.#opLock.withPermit(this.#invalidateCachesOnDefect(toDataOutcome(program))),
    );
  }

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  init(expectedProjectId: string, entry: ChainEntry): Promise<InitOutcome> {
    // 拒否(DataRejected)は toDataOutcome と同じ rejected 形へ畳む。init 固有の
    // 「初期化済み」(拒否ではない — 冪等修復の判定材料)と worker 側バグ検出の
    // project-id-mismatch だけが専用分岐を持つ
    return this.#runtime.runPromise(
      this.#opLock.withPermit(
        this.#invalidateCachesOnDefect(
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

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  putHeadAttestation(
    callerUserId: string,
    input: HeadAttestationSubmissionInput,
  ): Promise<DataOutcome<void>> {
    return this.#runData(putHeadAttestationProgram(callerUserId, input, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  memberRoleFor(callerUserId: string): Promise<DataOutcome<Role>> {
    return this.#runData(memberRoleProgram(callerUserId, this.#stateCache));
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
      readonly manifest: EnvManifestInput;
      readonly checkpoint: ChainEntry & { readonly op: "checkpoint" };
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
      readonly manifest: EnvManifestInput;
      readonly checkpoint: ChainEntry & { readonly op: "checkpoint" };
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
    manifest: EnvManifestInput,
  ): Promise<DataOutcome<void>> {
    return this.#runData(
      renameEnvironmentProgram(actor, environmentId, statement, manifest, this.#stateCache),
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
      readonly manifest: EnvManifestInput;
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
    reencryption: boolean,
  ): Promise<DataOutcome<VariableVersionValue>> {
    return this.#runData(
      pushVersionProgram(actor, environmentId, variableId, value, reencryption, this.#stateCache),
    );
  }

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  renameVariable(
    actor: DataActor,
    environmentId: string,
    variableId: string,
    statement: MetaStatementInput,
    manifest: EnvManifestInput,
  ): Promise<DataOutcome<void>> {
    return this.#runData(
      renameVariableProgram(
        actor,
        environmentId,
        variableId,
        statement,
        manifest,
        this.#stateCache,
      ),
    );
  }

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  deleteVariable(
    actor: DataActor,
    environmentId: string,
    variableId: string,
    statement: MetaStatementInput,
    manifest: EnvManifestInput,
  ): Promise<DataOutcome<void>> {
    return this.#runData(
      deleteVariableProgram(
        actor,
        environmentId,
        variableId,
        statement,
        manifest,
        this.#stateCache,
      ),
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

  // --- 要ローテーションフラグ RPC(AUDIT_SPEC §4.1 / §7 — Wave 2 B2) ----

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  rotationFlags(actor: DataActor): Promise<DataOutcome<readonly EffectiveRotationFlag[]>> {
    return this.#runData(rotationFlagsProgram(actor, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  dismissRotationFlags(
    actor: DataActor,
    targets: readonly RotationDismissTargetInput[],
  ): Promise<DataOutcome<void>> {
    return this.#runData(dismissRotationFlagsProgram(actor, targets, this.#stateCache));
  }

  // --- 監査イベント読み取り RPC(AUDIT_SPEC §6 / §7 — C1) ---------------

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  auditEvents(
    actor: DataActor,
    query: AuditEventsQueryInput,
  ): Promise<DataOutcome<readonly AuditEventValue[]>> {
    return this.#runData(auditEventsProgram(actor, query, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  auditHeadFor(actor: DataActor): Promise<DataOutcome<{ readonly auditHeadHashHex: string }>> {
    return this.#runData(auditHeadProgram(actor, this.#stateCache));
  }

  // --- ワークロードリース RPC(AUTH_SPEC §14) ---------------------------

  /**
   * リースの認可・開封・再ラップ・監査(programs-lease.ts)。OIDC 検証は
   * worker 側で完了済みで、ここへ来るのは検証済みトークンの事実だけである
   * (認証と認可の分離 — §14-3 の「認証失敗のみ 401」を構造で保つ)。
   *
   * 他の RPC と違い DataOutcome ではなく LeaseOutcome を返す: リースの拒否
   * 語彙(404 / 429 / 503)はデータプレーンの DataRejection と重ならず、
   * 無理に畳むと worker 側の写像表が両方の意味を持つことになるため。
   */
  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  issueLease(
    environmentId: string,
    ephemeralPubHex: string,
    facts: LeaseTokenFacts,
  ): Promise<LeaseOutcome> {
    return this.#runtime.runPromise(
      this.#opLock.withPermit(
        this.#invalidateCachesOnDefect(
          leaseProgram(environmentId, ephemeralPubHex, facts, this.#stateCache).pipe(
            Effect.match({
              onSuccess: (value: LeaseValue): LeaseOutcome => ({ kind: "ok", value }),
              onFailure: (rejection): LeaseOutcome => ({ kind: "rejected", rejection }),
            }),
          ),
        ),
      ),
    );
  }
}
