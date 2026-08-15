// バックフィルの共有核(CRYPTO_SPEC §7 / AUTH_SPEC §12-6)。
//
// 「1 環境の全エポック(1〜現エポック)の DEK を自分宛ラップから検証・開封し、
// 対象受信者へ再ラップして登録する。409(登録済みスロット)は一括 → エポック
// 単位に落として収束させる」構造は、grant 直後のサーバー宛バックフィル
// (server-grant)と add_member 後の新メンバー宛バックフィル(member)で同一。
// エポック単位 409 の解決だけが異なる(登録済み扱い / 修復経路での置換)ため、
// そこを注入点にする。

import { DekWrapExistsError, type WrappedDek } from "@maruhi/api-schema";
import type { SigningKeyPair } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { wrapAndSignFor, type WrapRecipient } from "./dek-wrap.ts";
import { type DekRecipient, environmentKeysFor } from "./deks.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import type { VerifiedProject } from "./sync.ts";

/** 登録試行の結果(409 = 既存スロット)。 */
export type RegisterOutcome = { readonly kind: "ok" } | { readonly kind: "exists" };

/** エポック単位 409 の解決(呼び出し側の意味論)。 */
export type SlotConflictResolution = "already-registered" | "repaired";

export interface BackfillEnvironmentOutcome {
  readonly registered: number;
  readonly alreadyRegistered: number;
  /** `onSlotConflict` が "repaired" を返した数(member add の修復経路)。 */
  readonly repaired: number;
}

/**
 * 1 環境の全エポックの DEK を対象受信者へラップして登録する。自分宛ラップの
 * 検証・開封(§5.1 + §5.2)→ 再ラップ + 登録署名(§5.1)→ 一括登録 → 409 なら
 * エポック単位(バッチは原子的受理のため、部分登録済みの再実行では一括が 409 に
 * なる)。エポック単位の 409 は `onSlotConflict` が解決する(既定 = 登録済み)。
 */
export function backfillEnvironmentFor(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  /** 自分(DEK 保持者 = ラップ実行者 — §7)の受信情報。 */
  readonly recipient: DekRecipient;
  /** ラップの宛先(サーバー鍵 / 新メンバー)。 */
  readonly wrapRecipient: WrapRecipient;
  /** ラップ生成失敗の文言に使う宛先ラベル(例: 「サーバー宛」)。 */
  readonly recipientLabel: string;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  /**
   * エポック単位 409 の解決(省略 = 登録済み扱い)。member add の再追加修復は
   * ここで削除 → 再登録を行う(§12-6 の修復経路)。
   */
  readonly onSlotConflict?: (wrap: WrappedDek) => Effect.Effect<SlotConflictResolution, CliError>;
}): Effect.Effect<BackfillEnvironmentOutcome, CliError> {
  return Effect.gen(function* () {
    const keys = yield* environmentKeysFor({
      client: input.client,
      verified: input.verified,
      environmentId: input.environmentId,
      recipient: input.recipient,
    });
    const wraps: WrappedDek[] = [];
    for (let epoch = 1; epoch <= keys.currentEpoch; epoch += 1) {
      const dek = keys.deksByEpoch.get(epoch);
      if (dek === undefined) {
        // §7: 全メンバーは全エポックの DEK を受け取る。欠けは毒ラップ・欠落の
        // 兆候なので黙って飛ばさない(§12-6 の修復経路を案内)
        return yield* Effect.fail(
          cliError(
            `環境 ${input.environmentId} の epoch ${epoch} の DEK ラップが自分宛に存在しません(§7 の全エポック配布と矛盾)。修復経路(ラップの再登録)で解消してから再実行してください`,
          ),
        );
      }
      const built = yield* Effect.tryPromise({
        try: () =>
          wrapAndSignFor({
            projectId: input.verified.projectId,
            environmentId: input.environmentId,
            epoch,
            dek,
            recipient: input.wrapRecipient,
            signerUserId: input.signerUserId,
            signingKeyPair: input.signingKeyPair,
          }),
        catch: () =>
          cliError(`${input.recipientLabel} DEK ラップ生成が失敗しました(暗号処理エラー)`),
      });
      if (built.kind === "failed") {
        return yield* Effect.fail(
          cliError(`${input.recipientLabel} DEK ラップ生成に失敗しました(${built.reason})`),
        );
      }
      wraps.push(built.wrap);
    }

    const register = registerWraps(input.client, input.verified.projectId, input.environmentId);

    // 一括 → 409 ならエポック単位に落として収束させる
    const batch = yield* register(wraps);
    if (batch.kind === "ok") {
      return { registered: wraps.length, alreadyRegistered: 0, repaired: 0 };
    }
    let registered = 0;
    let alreadyRegistered = 0;
    let repaired = 0;
    for (const wrap of wraps) {
      const single = yield* register([wrap]);
      if (single.kind === "ok") {
        registered += 1;
        continue;
      }
      const resolution =
        input.onSlotConflict === undefined
          ? ("already-registered" as const)
          : yield* input.onSlotConflict(wrap);
      if (resolution === "repaired") {
        repaired += 1;
      } else {
        alreadyRegistered += 1;
      }
    }
    return { registered, alreadyRegistered, repaired };
  });
}

/**
 * DEK ラップ登録の試行(409 = DekWrapExists は「既存スロット」として値で返す —
 * 再実行の収束・修復判断の入力)。
 */
export function registerWraps(
  client: MaruhiClient,
  projectId: string,
  environmentId: string,
): (deks: readonly WrappedDek[]) => Effect.Effect<RegisterOutcome, CliError> {
  return (deks) =>
    client.deks.register({ params: { projectId, environmentId }, payload: { deks } }).pipe(
      Effect.map(() => ({ kind: "ok" }) as const),
      Effect.catch((error) =>
        error instanceof DekWrapExistsError
          ? Effect.succeed({ kind: "exists" } as const)
          : Effect.fail(toCliError(error)),
      ),
    );
}
