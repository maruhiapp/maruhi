// プロジェクトのメンバーシップチェーンを append-only 保存するプロジェクト DO
// (CRYPTO_SPEC §6.4)。
//
// - サーバー側検証: 追記受理時に verifyChain(@maruhi/crypto)を再実行する。
//   クライアント検証(§6.3)がサーバー不信の防衛、この検証が不正クライアントの
//   防衛であり、両方必須(§6.4)
// - 直列化 + CAS: 追記リクエストは親ヘッドハッシュを持ち、現ヘッドと不一致なら
//   拒否する。DO 内の変更操作は Semaphore(1) で直列化する — DO の input gate は
//   ストレージ以外の await(verifyChain 内の crypto.subtle)中に開くため、
//   ゲート任せでは追記同士が交錯しうる。seq の PRIMARY KEY 制約が最終防衛
// - 受理ポリシー(§6.4): エントリ 1 MiB / チェーン 10,000 エントリ・累積 32 MiB
// - ストレージ(DO SQLite)は Effect サービス(ChainStore)の背後に隔離する。
//   Drizzle(ADR-0006)はこの単一 append-only テーブルには見送り(設計判断は
//   docs/notes/session-05.md): マイグレーション生成の利得がない規模で、依存を
//   増やさず素の SQL を境界内に閉じる。D1 スキーマ導入時に再評価する

import { ChainInvalidError, toWrappedCryptoError } from "@maruhi/core";
import type { ChainEntry, ChainInvalidReason, ChainState } from "@maruhi/crypto";
import { canonicalChainEntryBytes, verifyChain } from "@maruhi/crypto";
import { DurableObject } from "cloudflare:workers";
import { Context, Data, Effect, Layer, ManagedRuntime, Semaphore } from "effect";

import {
  MAX_CHAIN_ENTRIES,
  MAX_CHAIN_TOTAL_CANONICAL_BYTES,
  MAX_ENTRY_CANONICAL_BYTES,
} from "./policy.ts";

export interface Env {
  readonly PROJECT_CHAIN: DurableObjectNamespace<ProjectChainDO>;
  readonly DB: D1Database;
  /** GitHub OAuth App の client_id(wrangler vars。セルフホストは自分の App の値)。 */
  readonly GITHUB_CLIENT_ID: string;
  /** GitHub OAuth App の client_secret(Workers Secret / .dev.vars。ダミー値のみコミット可)。 */
  readonly GITHUB_CLIENT_SECRET: string;
}

// ---------------------------------------------------------------------------
// ChainStore: DO SQLite を隔離する Effect サービス
// ---------------------------------------------------------------------------

interface StoredChain {
  readonly entries: readonly ChainEntry[];
  /** 0 = 未初期化 */
  readonly headSeq: number;
  readonly headHashHex: string | null;
  readonly totalCanonicalBytes: number;
}

interface ChainStoreShape {
  readonly load: Effect.Effect<StoredChain>;
  readonly insert: (
    entry: ChainEntry,
    entryHashHex: string,
    canonicalBytes: number,
  ) => Effect.Effect<void>;
}

class ChainStore extends Context.Service<ChainStore, ChainStoreShape>()("ChainStore") {}

const chainStoreLayer = (sql: SqlStorage): Layer.Layer<ChainStore> =>
  Layer.sync(ChainStore, () => {
    sql.exec(
      `CREATE TABLE IF NOT EXISTS chain_entries (
         seq INTEGER PRIMARY KEY,
         entry_json TEXT NOT NULL,
         entry_hash_hex TEXT NOT NULL,
         canonical_bytes INTEGER NOT NULL
       )`,
    );
    return {
      load: Effect.sync(() => {
        const rows = sql
          .exec(
            "SELECT seq, entry_json, entry_hash_hex, canonical_bytes FROM chain_entries ORDER BY seq",
          )
          .toArray();
        const entries = rows.map((row) => JSON.parse(String(row["entry_json"])) as ChainEntry);
        const last = rows[rows.length - 1];
        let totalCanonicalBytes = 0;
        for (const row of rows) {
          totalCanonicalBytes += Number(row["canonical_bytes"]);
        }
        return {
          entries,
          headSeq: last === undefined ? 0 : Number(last["seq"]),
          headHashHex: last === undefined ? null : String(last["entry_hash_hex"]),
          totalCanonicalBytes,
        };
      }),
      insert: (entry, entryHashHex, canonicalBytes) =>
        Effect.sync(() => {
          sql.exec(
            "INSERT INTO chain_entries (seq, entry_json, entry_hash_hex, canonical_bytes) VALUES (?, ?, ?, ?)",
            entry.seq,
            JSON.stringify(entry),
            entryHashHex,
            canonicalBytes,
          );
        }),
    };
  });

// ---------------------------------------------------------------------------
// 型付きエラー(DO 内部)と RPC 境界の outcome 型
// ---------------------------------------------------------------------------

class AlreadyInitializedError extends Data.TaggedError("AlreadyInitialized")<{
  readonly genesisActorUserId: string;
  readonly headSeq: number;
  readonly headHashHex: string;
}> {}
class NotInitializedError extends Data.TaggedError("NotInitialized")<object> {}
class NotMemberError extends Data.TaggedError("NotMember")<object> {}
class HeadConflictError extends Data.TaggedError("HeadConflict")<{
  readonly currentHeadSeq: number;
  readonly currentHeadHashHex: string;
}> {}
class EntryTooLargeError extends Data.TaggedError("EntryTooLarge")<{
  readonly limitBytes: number;
}> {}
class CapacityExceededError extends Data.TaggedError("CapacityExceeded")<{
  readonly maxEntries: number;
  readonly maxTotalBytes: number;
}> {}
class ProjectIdMismatchError extends Data.TaggedError("ProjectIdMismatch")<object> {}

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
  | { readonly kind: "chain-invalid"; readonly seq: number; readonly reason: ChainInvalidReason }
  | { readonly kind: "entry-too-large"; readonly limitBytes: number }
  | { readonly kind: "project-id-mismatch" };

/** RPC 境界を渡る追記結果。 */
export type AppendOutcome =
  | { readonly kind: "appended"; readonly headSeq: number; readonly headHashHex: string }
  | { readonly kind: "not-initialized" }
  | { readonly kind: "not-member" }
  | {
      readonly kind: "head-conflict";
      readonly currentHeadSeq: number;
      readonly currentHeadHashHex: string;
    }
  | { readonly kind: "chain-invalid"; readonly seq: number; readonly reason: ChainInvalidReason }
  | { readonly kind: "entry-too-large"; readonly limitBytes: number }
  | {
      readonly kind: "capacity-exceeded";
      readonly maxEntries: number;
      readonly maxTotalBytes: number;
    };

/** RPC 境界を渡るチェーン取得結果。 */
export type SnapshotOutcome =
  | {
      readonly kind: "snapshot";
      readonly entries: readonly ChainEntry[];
      readonly headSeq: number;
      readonly headHashHex: string;
    }
  | { readonly kind: "not-initialized" }
  | { readonly kind: "not-member" };

// ---------------------------------------------------------------------------
// Effect プログラム(検証・受理判定の本体)
// ---------------------------------------------------------------------------

/** verifyChain を Effect に持ち上げ、ChainInvalid 以外の(契約上起こらない)失敗は defect にする。 */
function verifyChainEffect(
  entries: readonly ChainEntry[],
): Effect.Effect<ChainState, ChainInvalidError> {
  return Effect.flatMap(
    Effect.promise(() => verifyChain(entries)),
    (result) => {
      if (result.ok) {
        return Effect.succeed(result.value);
      }
      const wrapped = toWrappedCryptoError(result.error);
      // verifyChain は契約上 ChainInvalid しか返さない。それ以外は実装バグ
      return wrapped instanceof ChainInvalidError ? Effect.fail(wrapped) : Effect.die(wrapped);
    },
  );
}

/**
 * 正規化バイト列の長さ。Schema 検証済みエントリでは失敗しないが、エンコーダの
 * 例外は invalid-payload に封じ込める(DO を defect で落とさない)。
 */
function canonicalBytesOf(entry: ChainEntry): Effect.Effect<number, ChainInvalidError> {
  return Effect.try({
    try: () => canonicalChainEntryBytes(entry).length,
    catch: () => new ChainInvalidError({ seq: entry.seq, reason: "invalid-payload" }),
  });
}

function checkEntrySize(
  entry: ChainEntry,
): Effect.Effect<number, ChainInvalidError | EntryTooLargeError> {
  return Effect.flatMap(canonicalBytesOf(entry), (bytes) =>
    bytes > MAX_ENTRY_CANONICAL_BYTES
      ? Effect.fail(new EntryTooLargeError({ limitBytes: MAX_ENTRY_CANONICAL_BYTES }))
      : Effect.succeed(bytes),
  );
}

/**
 * チェーン導出状態のキャッシュ(DO インスタンスメモリ)。保存済みチェーンは
 * 受理時に検証済みなので、同一ヘッドへの再導出を省く(§6.2 の認可・§11-2 の
 * メンバーシップ判定を読み取りごとの O(n) 署名検証にしないため)。
 */
interface StateCache {
  current: { readonly headHashHex: string; readonly state: ChainState } | null;
}

/** 保存済みチェーンから ChainState を導出する。検証失敗は実装バグ(defect)。 */
function deriveStoredState(chain: StoredChain, cache: StateCache): Effect.Effect<ChainState> {
  const cached = cache.current;
  if (cached !== null && cached.headHashHex === chain.headHashHex) {
    return Effect.succeed(cached.state);
  }
  return verifyChainEffect(chain.entries).pipe(
    Effect.orDie,
    Effect.tap((state) =>
      Effect.sync(() => {
        cache.current = { headHashHex: state.headHashHex, state };
      }),
    ),
  );
}

/** §6.2 / §11-2: チェーン導出メンバー(reader 含む)でなければ拒否する。 */
function ensureChainMember(state: ChainState, userId: string): Effect.Effect<void, NotMemberError> {
  return state.members.has(userId) ? Effect.void : Effect.fail(new NotMemberError());
}

const initProgram = (expectedProjectId: string, entry: ChainEntry, cache: StateCache) =>
  Effect.gen(function* () {
    const store = yield* ChainStore;
    const chain = yield* store.load;
    if (chain.headSeq > 0) {
      const genesisActor = chain.entries[0]?.actor.userId ?? "";
      return yield* new AlreadyInitializedError({
        genesisActorUserId: genesisActor,
        headSeq: chain.headSeq,
        headHashHex: chain.headHashHex ?? "",
      });
    }
    const canonicalBytes = yield* checkEntrySize(entry);
    // genesis 以外・不正署名などは verifyChain が §6.3 の理由コードで拒否する
    const state = yield* verifyChainEffect([entry]);
    // プロジェクト ID = genesis エントリハッシュ(§6.4)。ルーティングした DO と
    // エントリの束縛が崩れていたら受理しない(worker 側バグへの防衛)
    if (state.headHashHex !== expectedProjectId) {
      return yield* new ProjectIdMismatchError();
    }
    yield* store.insert(entry, state.headHashHex, canonicalBytes);
    cache.current = { headHashHex: state.headHashHex, state };
    return { headSeq: state.headSeq, headHashHex: state.headHashHex };
  });

/**
 * CAS(§6.4): 未初期化を拒否し、親ヘッドが現ヘッドと一致しなければ現ヘッド情報
 * 付きで拒否する。クライアントは最新チェーンを取得・再検証して再試行する。
 */
function ensureParentHead(
  chain: StoredChain,
  parentHeadHashHex: string,
): Effect.Effect<void, NotInitializedError | HeadConflictError> {
  if (chain.headSeq === 0 || chain.headHashHex === null) {
    return Effect.fail(new NotInitializedError());
  }
  if (parentHeadHashHex !== chain.headHashHex) {
    return Effect.fail(
      new HeadConflictError({
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
): Effect.Effect<void, CapacityExceededError> {
  if (chainCapacityExceeded(chain.entries.length, chain.totalCanonicalBytes, canonicalBytes)) {
    return Effect.fail(
      new CapacityExceededError({
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
      return yield* new NotInitializedError();
    }
    const state = yield* deriveStoredState(chain, cache);
    yield* ensureChainMember(state, callerUserId);
    return {
      entries: chain.entries,
      headSeq: chain.headSeq,
      headHashHex: chain.headHashHex,
      totalCanonicalBytes: chain.totalCanonicalBytes,
    };
  });

const appendProgram = (
  parentHeadHashHex: string,
  entry: ChainEntry,
  callerUserId: string,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const store = yield* ChainStore;
    const chain = yield* loadChainForMember(callerUserId, cache);
    yield* ensureParentHead(chain, parentHeadHashHex);
    const canonicalBytes = yield* checkEntrySize(entry);
    yield* ensureChainCapacity(chain, canonicalBytes);
    // §6.4: 追記受理時にチェーン全体を再検証する(prev_hash 連続性・署名・操作権限)
    const state = yield* verifyChainEffect([...chain.entries, entry]);
    yield* store.insert(entry, state.headHashHex, canonicalBytes);
    cache.current = { headHashHex: state.headHashHex, state };
    return { headSeq: state.headSeq, headHashHex: state.headHashHex };
  });

const snapshotProgram = (callerUserId: string, cache: StateCache) =>
  Effect.gen(function* () {
    const chain = yield* loadChainForMember(callerUserId, cache);
    return { entries: chain.entries, headSeq: chain.headSeq, headHashHex: chain.headHashHex };
  });

// ---------------------------------------------------------------------------
// Durable Object(ManagedRuntime パターン。spike-b の確立形)
// ---------------------------------------------------------------------------

export class ProjectChainDO extends DurableObject<Env> {
  readonly #runtime: ManagedRuntime.ManagedRuntime<ChainStore, never>;
  // 変更操作の直列化(冒頭コメント参照)。読み取り(snapshotFor)は permit 不要
  readonly #writeLock = Semaphore.makeUnsafe(1);
  // チェーン導出状態のキャッシュ(deriveStoredState 参照)
  readonly #stateCache: StateCache = { current: null };

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.#runtime = ManagedRuntime.make(chainStoreLayer(ctx.storage.sql));
  }

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  init(expectedProjectId: string, entry: ChainEntry): Promise<InitOutcome> {
    return this.#runtime.runPromise(
      this.#writeLock.withPermit(
        initProgram(expectedProjectId, entry, this.#stateCache).pipe(
          Effect.map(
            (head): InitOutcome => ({
              kind: "initialized",
              headSeq: head.headSeq,
              headHashHex: head.headHashHex,
            }),
          ),
          Effect.catchTags({
            AlreadyInitialized: (error): Effect.Effect<InitOutcome> =>
              Effect.succeed({
                kind: "already-initialized",
                genesisActorUserId: error.genesisActorUserId,
                headSeq: error.headSeq,
                headHashHex: error.headHashHex,
              }),
            ChainInvalid: (error): Effect.Effect<InitOutcome> =>
              Effect.succeed({ kind: "chain-invalid", seq: error.seq, reason: error.reason }),
            EntryTooLarge: (error): Effect.Effect<InitOutcome> =>
              Effect.succeed({ kind: "entry-too-large", limitBytes: error.limitBytes }),
            ProjectIdMismatch: (): Effect.Effect<InitOutcome> =>
              Effect.succeed({ kind: "project-id-mismatch" }),
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
    return this.#runtime.runPromise(
      this.#writeLock.withPermit(
        appendProgram(parentHeadHashHex, entry, callerUserId, this.#stateCache).pipe(
          Effect.map(
            (head): AppendOutcome => ({
              kind: "appended",
              headSeq: head.headSeq,
              headHashHex: head.headHashHex,
            }),
          ),
          Effect.catchTags({
            NotInitialized: (): Effect.Effect<AppendOutcome> =>
              Effect.succeed({ kind: "not-initialized" }),
            NotMember: (): Effect.Effect<AppendOutcome> => Effect.succeed({ kind: "not-member" }),
            HeadConflict: (error): Effect.Effect<AppendOutcome> =>
              Effect.succeed({
                kind: "head-conflict",
                currentHeadSeq: error.currentHeadSeq,
                currentHeadHashHex: error.currentHeadHashHex,
              }),
            ChainInvalid: (error): Effect.Effect<AppendOutcome> =>
              Effect.succeed({ kind: "chain-invalid", seq: error.seq, reason: error.reason }),
            EntryTooLarge: (error): Effect.Effect<AppendOutcome> =>
              Effect.succeed({ kind: "entry-too-large", limitBytes: error.limitBytes }),
            CapacityExceeded: (error): Effect.Effect<AppendOutcome> =>
              Effect.succeed({
                kind: "capacity-exceeded",
                maxEntries: error.maxEntries,
                maxTotalBytes: error.maxTotalBytes,
              }),
          }),
        ),
      ),
    );
  }

  // fallow-ignore-next-line unused-class-member -- DO RPC メソッド(worker がスタブ経由で呼ぶ)
  snapshotFor(callerUserId: string): Promise<SnapshotOutcome> {
    return this.#runtime.runPromise(
      snapshotProgram(callerUserId, this.#stateCache).pipe(
        Effect.map(
          (chain): SnapshotOutcome => ({
            kind: "snapshot",
            entries: chain.entries,
            headSeq: chain.headSeq,
            headHashHex: chain.headHashHex,
          }),
        ),
        Effect.catchTags({
          NotInitialized: (): Effect.Effect<SnapshotOutcome> =>
            Effect.succeed({ kind: "not-initialized" }),
          NotMember: (): Effect.Effect<SnapshotOutcome> => Effect.succeed({ kind: "not-member" }),
        }),
      ),
    );
  }
}
