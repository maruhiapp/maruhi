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
}

function bindingKey(binding: KeyBinding): string {
  return `${binding.encPubHex}:${binding.sigPubHex}`;
}

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
      const enc = decodeHex(entry.payload.encPubHex) ?? new Uint8Array(0);
      const sig = decodeHex(entry.payload.sigPubHex) ?? new Uint8Array(0);
      const fingerprint = await computeUserKeyFingerprint(enc, sig);
      if (fingerprint.ok) {
        add(entry.payload.targetUserId, {
          encPubHex: entry.payload.encPubHex,
          sigPubHex: entry.payload.sigPubHex,
          keyFingerprintHex: encodeHex(fingerprint.value),
        });
      }
    }
  }
  return history;
}

/**
 * Fetches and fully verifies the project chain (§6.3), checks the genesis
 * hash against the project id (§6.4), and cross-checks the server's claimed
 * head against the locally derived one.
 */
export function syncProject(
  client: MaruhiClient,
  projectId: ProjectId,
): Effect.Effect<VerifiedProject, CliError> {
  return Effect.gen(function* () {
    const snapshot = yield* client.membership
      .get({ params: { projectId } })
      .pipe(Effect.mapError(toCliError));

    const entries: readonly ChainEntry[] = snapshot.entries;
    const verified = yield* Effect.promise(() => verifyChainWithHistory(entries));
    if (!verified.ok) {
      const { seq, reason } =
        verified.error.kind === "ChainInvalid"
          ? verified.error
          : { seq: 0, reason: "invalid-payload" };
      return yield* Effect.fail(
        cliError(
          `チェーン検証に失敗しました(seq=${seq}, reason=${reason})。サーバーが不正なチェーンを配布している可能性があります`,
        ),
      );
    }
    const { state, history } = verified.value;

    // §6.4: プロジェクト ID = genesis エントリハッシュ。サーバーが別チェーンを
    // 同じ ID で配布する差し替えをここで機械的に検出する
    const genesis = entries[0];
    if (genesis === undefined) {
      return yield* Effect.fail(cliError("チェーンが空です"));
    }
    const genesisHash = yield* Effect.promise(() => computeChainEntryHash(genesis));
    if (genesisHash !== projectId) {
      return yield* Effect.fail(
        cliError(
          `genesis ハッシュがプロジェクト ID と一致しません(サーバーによるチェーン差し替えの疑い): expected=${projectId} actual=${genesisHash}`,
        ),
      );
    }

    // サーバー申告のヘッドと導出ヘッドの整合(申告値は信用しない)
    if (state.headSeq !== snapshot.headSeq || state.headHashHex !== snapshot.headHashHex) {
      return yield* Effect.fail(
        cliError(
          "サーバー申告のチェーンヘッドが取得エントリと一致しません(応答が自己矛盾しています)",
        ),
      );
    }

    const keyHistory = yield* Effect.promise(() => buildKeyHistory(entries));
    return { projectId, state, history, keyHistory } satisfies VerifiedProject;
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
        `再同期したチェーンが検証済みビュー(seq=${previous.state.headSeq})の延長ではありません(サーバーによるチェーン差し替え / 分岐の証拠)`,
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
