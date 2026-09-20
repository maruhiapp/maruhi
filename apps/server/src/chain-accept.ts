// チェーンエントリ受理の共有実装(CRYPTO_SPEC §6.4)。
//
// 「正規化サイズ検査 → チェーン容量 → verifyChain 再実行 → insert + 監査ミラー」の
// 受理 4 手順は、汎用チェーン API(chain-do.ts の init / append)と複合リクエスト
// (composite-programs.ts の create / rotate)の全経路がここを通る。上限意味論の
// 修正が片側にしか当たらないズレを構造的に防ぐ。エラーは DataRejection で運び、
// 呼び出し側には outcome への畳み込みだけを残す。

import type { ChainInvalidError, ChainMirrorSubject, ProposalIndex } from "@maruhi/core";
import { chainMirrorEvents, indexProposals } from "@maruhi/core";
import type { ChainEntry, ChainOperation, ProposableOperation } from "@maruhi/crypto";
import { Effect } from "effect";

import type { AuditEventInput, AuditRotationRead } from "./audit-store.ts";
import type { StoredChain, VerifiedChainView } from "./chain-store.ts";
import { canonicalBytesOf, verifyChainEffect } from "./chain-store.ts";
import type { DataRejectedError } from "./data-plane.ts";
import { rejectData } from "./data-plane.ts";
import type { StaleWrapRef } from "./data-store.ts";
import {
  MAX_CHAIN_ENTRIES,
  MAX_CHAIN_TOTAL_CANONICAL_BYTES,
  MAX_ENTRY_CANONICAL_BYTES,
} from "./policy.ts";
import {
  detectDeviceRevocation,
  detectMemberRemoval,
  detectRoleChange,
  detectServerRevocation,
} from "./rotation-detect.ts";

/** ChainInvalid(検証・エンコーダ失敗)→ chain-entry-invalid 拒否。 */
const rejectChainInvalid = (error: ChainInvalidError): DataRejectedError =>
  rejectData({ kind: "chain-entry-invalid", seq: error.seq, reason: error.reason });

/** §6.4: 1 エントリの正規化サイズ検査。通過したら正規化バイト数を返す。 */
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
 * CAS(§6.4): 親ヘッドが現ヘッドと一致しなければ現ヘッド情報付きで拒否
 * (worker が 409 に写す)。未初期化の検査は呼び出し側の前段(loadChainForMember /
 * loadInitializedChain)が済ませている前提で、ここでは head の一致のみを見る。
 */
export function ensureParentHead(
  chain: { readonly headSeq: number; readonly headHashHex: string },
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
 * 受理検査(サイズ → 容量 → §6.4 の全チェーン再検証 = prev_hash 連続性・署名・
 * 合意規則)。受理される場合は正規化バイト数と「エントリ適用後の検証済み
 * ビュー」を返す(複合のラップ判定基準状態 — AUTH_SPEC §12-4 — と、受理後の
 * StateCache 更新の入力)。
 */
export const verifyAcceptableEntry = (
  chain: StoredChain,
  entry: ChainEntry,
): Effect.Effect<
  { readonly canonicalBytes: number; readonly applied: VerifiedChainView },
  DataRejectedError
> =>
  Effect.gen(function* () {
    const canonicalBytes = yield* checkEntrySize(entry);
    yield* ensureChainCapacity(chain, canonicalBytes);
    const applied = yield* verifyChainEffect([...chain.entries, entry]).pipe(
      Effect.mapError(rejectChainInvalid),
    );
    return { canonicalBytes, applied };
  });

/**
 * 複合の 2 エントリ受理検査(AUTH_SPEC §12-4: H+1 = create / rotate、
 * H+2 = 境界 `checkpoint`)。サイズ検査は各エントリ、
 * 容量検査は 2 エントリ分の合算、verifyChain(§6.4 の合意規則 — checkpoint の
 * エポック厳密一致は「エントリ時点 = H+1 適用後」基準で自然に成立する —
 * CRYPTO_SPEC §6.2)は両エントリを適用した全チェーンに対して 1 回。返す
 * `applied` は両エントリ適用後の検証済みビュー(境界 checkpoint タプルを含む
 * 履歴 = 同梱マニフェストのチェックポイント束縛検証 — §4.3 (2) — の入力)。
 */
export const verifyAcceptableEntryPair = (
  chain: StoredChain,
  first: ChainEntry,
  second: ChainEntry,
): Effect.Effect<
  {
    readonly firstCanonicalBytes: number;
    readonly secondCanonicalBytes: number;
    readonly applied: VerifiedChainView;
  },
  DataRejectedError
> =>
  Effect.gen(function* () {
    const firstCanonicalBytes = yield* checkEntrySize(first);
    const secondCanonicalBytes = yield* checkEntrySize(second);
    if (
      chain.entries.length + 2 > MAX_CHAIN_ENTRIES ||
      chain.totalCanonicalBytes + firstCanonicalBytes + secondCanonicalBytes >
        MAX_CHAIN_TOTAL_CANONICAL_BYTES
    ) {
      return yield* Effect.fail(
        rejectData({
          kind: "chain-capacity-exceeded",
          maxEntries: MAX_CHAIN_ENTRIES,
          maxTotalBytes: MAX_CHAIN_TOTAL_CANONICAL_BYTES,
        }),
      );
    }
    const applied = yield* verifyChainEffect([...chain.entries, first, second]).pipe(
      Effect.mapError(rejectChainInvalid),
    );
    return { firstCanonicalBytes, secondCanonicalBytes, applied };
  });

/** insertAcceptedEntrySync が書き込みに使うストア面(構造的部分型)。 */
export interface ChainAcceptStores {
  readonly chainStore: {
    readonly insertSync: (entry: ChainEntry, entryHashHex: string, canonicalBytes: number) => void;
  };
  readonly audit: {
    readonly appendSync: (event: AuditEventInput) => void;
    readonly appendManySync: (events: readonly AuditEventInput[]) => void;
    readonly readRotationSync: AuditRotationRead;
  };
  readonly dataStore: {
    readonly write: {
      readonly deleteStaleMemberWraps: (
        recipientUserId: string,
        keepEncPubHex: string,
      ) => readonly StaleWrapRef[];
      readonly deleteHeadAttestation: (attesterUserId: string) => void;
      readonly deleteDeviceHeadAttestation: (
        attesterUserId: string,
        keyFingerprintHex: string,
      ) => void;
    };
  };
}

/**
 * 完成した approve が適用した提案(内側 op と提案エントリの seq)。DO の append の
 * 戻り値で worker へ渡し、worker は直接追記の add_member / remove_member と同じ
 * D1 後処理(招待の completed 突合・membership 投影)を内側 op に対して行う
 * (設計録 es-design.md §11 K5-H)。
 */
export interface AppliedProposal {
  readonly proposalSeq: number;
  readonly inner: ProposableOperation;
}

/**
 * 受理後のチェーン(受理済みエントリを含む)の提案索引(AUDIT_SPEC §3.4 の
 * approve / withdraw 行と適用行の入力)。導出は core の indexProposals をサーバーと
 * CLI で共有する(K5-F)。
 */
export function proposalIndexOf(
  entries: readonly ChainEntry[],
  applied: VerifiedChainView,
): ProposalIndex {
  // entryHashAt は索引オブジェクトのメソッド(this 束縛)なので引数で包む
  return indexProposals(
    entries,
    (seq) => applied.history.entryHashAt(seq),
    new Set(applied.state.pendingProposals.keys()),
  );
}

/** 提案できない op だけを運ぶ経路(複合の create / rotate + 境界 checkpoint)用の空索引。 */
const NO_PROPOSALS: ProposalIndex = new Map();

/**
 * 受理済みエントリの挿入 + §3.4 の監査ミラー + op 別の受理副作用(同期)。
 * チェーン挿入・ミラー追記・副作用を同一同期ブロック(= 同一タスク)で原子
 * コミットするために、呼び出し側の書き込みフェーズ内から呼ぶ。serverTs(nowMs)は
 * 必ず引数で受け取り、取得タイミング(全検査後・書き込みフェーズ直前)を全経路で
 * 統一する。副作用をここに置くのは、受理経路が将来増えても「remove を受理したのに
 * フラグが出ない」「再追加を受理したのに旧鍵ラップが残る」形を構造的に防ぐため
 * (受理 4 手順の共有と同じ理由)。
 *
 * 四眼(K5): 完成した approve は `chain.approved`(completed = true)に続けて内側 op の
 * 適用行(同じ chain_seq・actor = 提案者・viaProposalSeq)を書き、そのうえで内側 op の
 * 副作用を approve の seq を起点に走らせる(CRYPTO_SPEC §6.4「内側 op を直接受理した
 * 場合と同一に、当該 approve エントリの受理タスク内で」)。戻り値は適用した提案
 * (未完成・四眼以外は null)。
 *
 * 端末鍵(K3): `subject` は `add_device` の載せた端末 FP(受理側が計算 — chain-commit.ts)。
 * `revoke_device` は当該端末の申告行の削除 + 要ローテーション検出変種(AUDIT_SPEC §4.1)。
 */
export function insertAcceptedEntrySync(
  stores: ChainAcceptStores,
  entry: ChainEntry,
  applied: VerifiedChainView,
  canonicalBytes: number,
  nowMs: number,
  proposals: ProposalIndex,
  subject: ChainMirrorSubject = {},
): AppliedProposal | null {
  stores.chainStore.insertSync(entry, applied.state.headHashHex, canonicalBytes);
  const rows = chainMirrorEvents(entry, nowMs, proposals, subject);
  stores.audit.appendManySync(rows);
  applyAcceptanceSideEffectsSync(stores, entry, entry.seq, nowMs);
  if (entry.op !== "approve") {
    return null;
  }
  const proposal = proposals.get(entry.payload.proposalHashHex);
  if (proposal === undefined || proposal.completedAtSeq !== entry.seq) {
    return null;
  }
  // 適用行はミラーの 2 行目として既に書かれている(chainMirrorEvents)。副作用は
  // 内側 op に対して、適用 seq = この approve の seq で走らせる(裁定 P7 — 義務の
  // 起点は適用時点。要ローテーション検出の triggerChainSeq も同じ)
  applyAcceptanceSideEffectsSync(stores, proposal.entry.payload.inner, entry.seq, nowMs);
  return { proposalSeq: proposal.entry.seq, inner: proposal.entry.payload.inner };
}

/**
 * 複合の 2 エントリ(H+1 / H+2 — verifyAcceptableEntryPair 通過済み)の挿入 +
 * ミラー + 副作用(同期・seq 順)。H+1 のエントリハッシュは H+2 の prev_hash
 * (verifyChain が連鎖一致を検証済み)、H+2 のハッシュは両エントリ適用後の
 * ヘッドハッシュ。checkpoint のスナップショット保存(§6.4)はエントリ単体から
 * 導出できない(受理時点の保存状態の再構成物)ため、ここではなく呼び出し側の
 * 書き込みフェーズが同じ同期ブロック内で行う。この経路が運ぶ op(create /
 * rotate / checkpoint)は提案できない(CRYPTO_SPEC §6.2)ので提案索引は空でよい。
 */
export function insertAcceptedEntryPairSync(
  stores: ChainAcceptStores,
  first: ChainEntry,
  second: ChainEntry,
  applied: VerifiedChainView,
  firstCanonicalBytes: number,
  secondCanonicalBytes: number,
  nowMs: number,
): void {
  stores.chainStore.insertSync(first, second.prevHashHex, firstCanonicalBytes);
  stores.audit.appendManySync(chainMirrorEvents(first, nowMs, NO_PROPOSALS));
  applyAcceptanceSideEffectsSync(stores, first, first.seq, nowMs);
  stores.chainStore.insertSync(second, applied.state.headHashHex, secondCanonicalBytes);
  stores.audit.appendManySync(chainMirrorEvents(second, nowMs, NO_PROPOSALS));
  applyAcceptanceSideEffectsSync(stores, second, second.seq, nowMs);
}

/**
 * op 別の受理副作用(ミラー追記の後・同一タスク内)。入力は op + payload
 * (署名済みエントリ、または完成した approve が適用した内側 op)と適用 seq。
 *
 * - `add_member`: 再追加の旧鍵宛ラップ掃除(AUTH_SPEC §12-6 — §6.3 の
 *   「ラップ先 = 現メンバー鍵と厳密一致」不変条件へのストレージ収束)。
 *   削除は dek.deleted(actor = system + 原因 payload — AUDIT_SPEC §3.3)
 * - `remove_member` / `change_role`(降格・scope 縮小 — 2026-09-14 ES)/
 *   `revoke_server`: 要ローテーション検出(AUDIT_SPEC §4.1)。検出はミラー追記の
 *   **後**に読む — 対象の在籍 / grant 区間・アクセス窓は直前に書いたミラー行
 *   (四眼経由では適用行 — 同じイベント名・同じ target 索引)で閉じている
 * - `remove_member` はさらに対象のヘッド申告行を削除する(CRYPTO_SPEC §6.4 /
 *   AUTH_SPEC §16-1 — 現メンバーのみ配布へのストレージ収束。§12-6 の旧鍵
 *   ラップ掃除と同型)
 * - `revoke_device`(2026-09-19 DK — CRYPTO_SPEC §6.4): 失効した各端末の申告行の
 *   削除(AUTH_SPEC §16-1)+ 要ローテーション検出の `revoke_device` 変種(AUDIT_SPEC
 *   §4.1 — 端末の有効区間 ∩ 人のアクセス窓 ∩ 端末 scope)。`add_device` の副作用は
 *   ミラーのみ(バックフィルはクライアント — §7)
 * - 四眼の 4 op 自身(`set_approval_policy` / `propose` / `approve` / `withdraw`)に
 *   固有の副作用はない(完成した approve の内側 op は呼び出し側が本関数を再度呼ぶ)
 */
function applyAcceptanceSideEffectsSync(
  stores: ChainAcceptStores,
  operation: ChainOperation,
  seq: number,
  nowMs: number,
): void {
  if (operation.op === "add_member") {
    const stale = stores.dataStore.write.deleteStaleMemberWraps(
      operation.payload.targetUserId,
      operation.payload.encPubHex,
    );
    if (stale.length > 0) {
      stores.audit.appendManySync(
        stale.map((ref) => ({
          event: "dek.deleted",
          serverTs: nowMs,
          actorType: "system" as const,
          targetUserId: operation.payload.targetUserId,
          environmentId: ref.environmentId,
          epoch: ref.epoch,
          payload: { cause: "member-readded", triggerChainSeq: seq },
        })),
      );
    }
    return;
  }
  if (operation.op === "remove_member") {
    stores.dataStore.write.deleteHeadAttestation(operation.payload.targetUserId);
    appendDetected(
      stores,
      detectMemberRemoval({
        read: stores.audit.readRotationSync,
        targetUserId: operation.payload.targetUserId,
        triggerChainSeq: seq,
        nowMs,
      }),
    );
    return;
  }
  if (operation.op === "change_role") {
    appendDetected(
      stores,
      detectRoleChange({
        read: stores.audit.readRotationSync,
        targetUserId: operation.payload.targetUserId,
        triggerChainSeq: seq,
        nowMs,
      }),
    );
    return;
  }
  if (operation.op === "revoke_server") {
    appendDetected(
      stores,
      detectServerRevocation({
        read: stores.audit.readRotationSync,
        serverKeyFingerprintHex: operation.payload.serverKeyFingerprintHex,
        triggerChainSeq: seq,
        nowMs,
      }),
    );
    return;
  }
  if (operation.op === "revoke_device") {
    for (const fingerprintHex of operation.payload.deviceFingerprintsHex) {
      stores.dataStore.write.deleteDeviceHeadAttestation(
        operation.payload.targetUserId,
        fingerprintHex,
      );
    }
    appendDetected(
      stores,
      detectDeviceRevocation({
        read: stores.audit.readRotationSync,
        targetUserId: operation.payload.targetUserId,
        deviceFingerprintsHex: operation.payload.deviceFingerprintsHex,
        triggerChainSeq: seq,
        nowMs,
      }),
    );
  }
}

function appendDetected(stores: ChainAcceptStores, events: readonly AuditEventInput[]): void {
  if (events.length > 0) {
    stores.audit.appendManySync(events);
  }
}
