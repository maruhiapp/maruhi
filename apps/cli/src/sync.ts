// クライアント同期検査(CRYPTO_SPEC §6.3)。
//
// 同期のたびにチェーン全体を取得し、verifyChain(prev_hash 連続性・署名・
// §6.2 認可規則 = 鍵一意性を含む)で全再検証した上で、genesis エントリハッシュの
// 再計算がプロジェクト ID と一致することを確認する(§6.4 の束縛 — サーバーによる
// チェーン差し替えの機械的検出)。v1 はローカルキャッシュ・差分検証を持たない
// (毎回全取得・全再検証が最簡 — 差分検証を入れる場合は session-10 §5 の
// 鍵索引再構築の注意に従うこと)。
//
// 併せて §5.1 の配布時検証が使う「チェーン履歴で user_id に束縛された鍵」の索引
// (genesis / add_member の payload。削除済みメンバーの当時の鍵も含む)を作る。
// ヘッドゴシップ(§6.3)は Phase 2 — 本セッションのスコープ外。

import type { ProjectId } from "@maruhi/core";
import type { ChainEntry, ChainHistoryIndex, ChainState } from "@maruhi/crypto";
import {
  computeChainEntryHash,
  computeUserKeyFingerprint,
  decodeHex,
  encodeHex,
  verifyChainWithHistory,
} from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";

/** One key set the chain history binds to a user id (genesis / add_member payload). */
export interface KeyBinding {
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly keyFingerprintHex: string;
}

/**
 * A fully verified project chain (§6.3) plus the §5.1 signer-key history
 * index and the §4.1 chain-history index (seq → hash / tenure / エポック有効
 * 区間の照会 — 値署名の宣言ヘッド時点検証の入力)。
 */
export interface VerifiedProject {
  readonly projectId: ProjectId;
  readonly state: ChainState;
  /** History queries over this verified snapshot (CRYPTO_SPEC §6.3 / §4.1). */
  readonly history: ChainHistoryIndex;
  /**
   * Every key set ever bound to each user id (append-only history — §5.1)。
   * DEK ラップの配布時検証(deks.ts — ヘッド束縛を持たない §5.1 の意味論)用。
   * 値署名の鍵選択・tenure 照会は history 側を使う(dedupe で tenure を
   * 消さない — session-14 裁定 A)。
   */
  readonly keyHistory: ReadonlyMap<string, readonly KeyBinding[]>;
  /**
   * 検証済みチェーンのエントリ列(seq 順)。導出状態に現れない履歴事実
   * (例: 最後の revoke_server の seq — server revoke の中断復旧の基準)を
   * 参照する読み取り専用ビュー。
   */
  readonly entries: readonly ChainEntry[];
}

function bindingKey(binding: KeyBinding): string {
  return `${binding.encPubHex}:${binding.sigPubHex}`;
}

/**
 * verifyChain 通過後には成り立つはずの前提(hex の正規形・鍵長)が破れたとき
 * の内部矛盾。鍵索引からの黙った欠落は §5.1 検証で「署名者がチェーン履歴に
 * 存在しません」という偽装様のエラーに化けるため、ここで型付きの失敗にする。
 */
class ChainDerivationError extends Error {}

async function buildKeyHistory(
  entries: readonly ChainEntry[],
): Promise<ReadonlyMap<string, readonly KeyBinding[]>> {
  const history = new Map<string, KeyBinding[]>();
  const seen = new Set<string>();
  const add = (userId: string, binding: KeyBinding) => {
    const dedupe = `${userId}#${bindingKey(binding)}`;
    if (seen.has(dedupe)) {
      return;
    }
    seen.add(dedupe);
    const list = history.get(userId);
    if (list === undefined) {
      history.set(userId, [binding]);
    } else {
      list.push(binding);
    }
  };
  for (const entry of entries) {
    // 鍵を登録する op は genesis と add_member のみ(§6.2)。verifyChain 通過後
    // なので hex は正規形、genesis の actor FP は payload 鍵と一致検証済み
    if (entry.op === "genesis") {
      add(entry.actor.userId, {
        encPubHex: entry.payload.encPubHex,
        sigPubHex: entry.payload.sigPubHex,
        keyFingerprintHex: entry.actor.keyFingerprintHex,
      });
    } else if (entry.op === "add_member") {
      const enc = decodeHex(entry.payload.encPubHex);
      const sig = decodeHex(entry.payload.sigPubHex);
      if (enc === null || sig === null) {
        throw new ChainDerivationError(
          `Cannot decode the public-key hex in add_member (seq=${entry.seq})`,
        );
      }
      const fingerprint = await computeUserKeyFingerprint(enc, sig);
      if (!fingerprint.ok) {
        throw new ChainDerivationError(
          `Cannot compute the key fingerprint for add_member (seq=${entry.seq})`,
        );
      }
      add(entry.payload.targetUserId, {
        encPubHex: entry.payload.encPubHex,
        sigPubHex: entry.payload.sigPubHex,
        keyFingerprintHex: encodeHex(fingerprint.value),
      });
    }
  }
  return history;
}

/**
 * Fully verifies one distributed chain snapshot (§6.3), checks the genesis
 * hash against the project id (§6.4), and cross-checks the server's claimed
 * head against the locally derived one.
 *
 * syncProject(チェーン API からの取得)と lease 応答の同梱チェーン
 * (AUTH_SPEC §14-2 — 非メンバーへの唯一の配布経路)の**両方**がここを通る。
 * 検証実装を 2 系統に割ると、片方だけが genesis 固定・ヘッド整合を失う
 * 静かな退行になる(values.ts の decryptVerifiedValue と同じ理由)。
 */
export function verifyChainSnapshot(input: {
  readonly projectId: ProjectId;
  readonly entries: readonly ChainEntry[];
  /** サーバー申告のヘッド(信用せず、導出ヘッドとの一致を検査する)。 */
  readonly claimedHeadSeq: number;
  readonly claimedHeadHashHex: string;
}): Effect.Effect<VerifiedProject, CliError> {
  return Effect.gen(function* () {
    const { projectId, entries } = input;
    const verified = yield* Effect.tryPromise({
      try: () => verifyChainWithHistory(entries),
      catch: () => cliError("Chain verification failed to run (crypto error)"),
    });
    if (!verified.ok) {
      const { seq, reason } =
        verified.error.kind === "ChainInvalid"
          ? verified.error
          : { seq: 0, reason: "invalid-payload" };
      return yield* Effect.fail(
        cliError(
          `Chain verification failed (seq=${seq}, reason=${reason}). The server may be distributing an invalid chain`,
        ),
      );
    }
    const { state, history } = verified.value;

    // §6.4: プロジェクト ID = genesis エントリハッシュ。サーバーが別チェーンを
    // 同じ ID で配布する差し替えをここで機械的に検出する
    const genesis = entries[0];
    if (genesis === undefined) {
      return yield* Effect.fail(cliError("The chain is empty"));
    }
    const genesisHash = yield* Effect.tryPromise({
      try: () => computeChainEntryHash(genesis),
      catch: () => cliError("Failed to compute the genesis hash (crypto error)"),
    });
    if (genesisHash !== projectId) {
      return yield* Effect.fail(
        cliError(
          `The genesis hash does not match the project ID (suspected server-side chain replacement): expected=${projectId} actual=${genesisHash}`,
        ),
      );
    }

    // サーバー申告のヘッドと導出ヘッドの整合(申告値は信用しない)
    if (state.headSeq !== input.claimedHeadSeq || state.headHashHex !== input.claimedHeadHashHex) {
      return yield* Effect.fail(
        cliError(
          "The server-declared chain head does not match the fetched entries (the response contradicts itself)",
        ),
      );
    }

    const keyHistory = yield* Effect.tryPromise({
      try: () => buildKeyHistory(entries),
      catch: (error) =>
        cliError(
          `Chain-derivation inconsistency: ${
            error instanceof ChainDerivationError ? error.message : String(error)
          } (cannot build the key index from the verified chain)`,
        ),
    });
    return { projectId, state, history, keyHistory, entries } satisfies VerifiedProject;
  });
}

/**
 * Fetches and fully verifies the project chain (§6.3) through
 * {@link verifyChainSnapshot}.
 */
export function syncProject(
  client: MaruhiClient,
  projectId: ProjectId,
): Effect.Effect<VerifiedProject, CliError> {
  return Effect.gen(function* () {
    const snapshot = yield* client.membership
      .get({ params: { projectId } })
      .pipe(Effect.mapError(toCliError));
    return yield* verifyChainSnapshot({
      projectId,
      entries: snapshot.entries,
      claimedHeadSeq: snapshot.headSeq,
      claimedHeadHashHex: snapshot.headHashHex,
    });
  });
}

/**
 * 再同期後の新スナップショットが旧検証済みビューの**延長**であることの検査
 * (§6.3-2b の再同期分岐)。syncProject が全体検証と genesis 一致を済ませて
 * いる前提で、(1) 新ヘッドが旧ヘッド以上、(2) 旧 verified head の seq/hash が
 * 新スナップショット内で一致、を要求する。別の整合チェーンへの差し替え・
 * 旧 head の欠落・同 seq のハッシュ不一致はすべてここで落ちる。
 */
function ensureExtensionOf(
  previous: VerifiedProject,
  next: VerifiedProject,
): Effect.Effect<VerifiedProject, CliError> {
  if (
    next.state.headSeq < previous.state.headSeq ||
    next.history.entryHashAt(previous.state.headSeq) !== previous.state.headHashHex
  ) {
    return Effect.fail(
      cliError(
        `The re-synced chain is not an extension of the verified view (seq=${previous.state.headSeq}) (evidence of server-side chain replacement / divergence)`,
      ),
    );
  }
  return Effect.succeed(next);
}

/** 延長検査付き再同期(§6.3-2b / session-14 裁定 G)。 */
export function resyncExtended(
  resync: Effect.Effect<VerifiedProject, CliError>,
  previous: VerifiedProject,
): Effect.Effect<VerifiedProject, CliError> {
  return Effect.flatMap(resync, (next) => ensureExtensionOf(previous, next));
}
