// 配布されたラップ済み DEK の検証と復号(CRYPTO_SPEC §5.1 / §5.2 / §12-7)。
//
// 検証の座標は申告値を信用せず自前で組み立てる: projectId = 検証済み genesis
// ハッシュ、environmentId = リクエストに使った ID、recipient = 自分の
// user_id + 自分の enc 公開鍵。署名者の鍵は「検証済みチェーン履歴で
// signerUserId に束縛された sig 鍵のうち FP が一致するもの」(削除済み
// メンバーの当時の鍵も可 — チェーンは append-only)。
// wrap の epoch は申告値だが、登録署名(§5.1)と HPKE info(§5)の両方に
// 束縛されるため、別エポックへの移植は検証・復号失敗に落ちる。
//
// §5.2(2026-08-03): unwrap した DEK は、チェーン導出の (environment, epoch)
// コミットメントと照合するまでいかなる暗号操作(復号・暗号化)にも使わない。
// 不一致は毒ラップ(共謀サーバーによる偽 DEK 注入の遮断 — §14.2-1)。

import type { RecipientDek } from "@maruhi/api-schema";
import type { EncryptionKeyPair, EnvironmentChainState } from "@maruhi/crypto";
import {
  decodeHex,
  importSigningPublicKey,
  SUITE_ID,
  unwrapDek,
  verifyDekCommitment,
  verifyDekWrapSignature,
} from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import type { VerifiedProject } from "./sync.ts";

/** The caller as a DEK recipient (own coordinates for §5.1 verification). */
export interface DekRecipient {
  readonly userId: string;
  readonly encPubHex: string;
  readonly encKeyPair: EncryptionKeyPair;
}

function signerKeyFor(verified: VerifiedProject, wrap: RecipientDek): Uint8Array | null {
  const bindings = verified.keyHistory.get(wrap.signerUserId) ?? [];
  const match = bindings.find(
    (binding) => binding.keyFingerprintHex === wrap.signerKeyFingerprintHex,
  );
  return match === undefined ? null : decodeHex(match.sigPubHex);
}

/** 1 ラップの検証・開封結果(タグ付き Result — instanceof 判別をしない)。 */
type UnwrapResult =
  | { readonly kind: "ok"; readonly dek: Uint8Array }
  | { readonly kind: "rejected"; readonly message: string };

async function verifyAndUnwrapOne(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly recipient: DekRecipient;
  readonly wrap: RecipientDek;
  /** チェーン導出の当該 (environment, epoch) のコミットメント(§5.2)。 */
  readonly expectedCommitmentHex: string;
}): Promise<UnwrapResult> {
  const { verified, environmentId, recipient, wrap } = input;
  const signerKeyBytes = signerKeyFor(verified, wrap);
  if (signerKeyBytes === null) {
    return {
      kind: "rejected",
      message: `署名者がチェーン履歴に存在しません(signer=${displayText(wrap.signerUserId)}, fp=${wrap.signerKeyFingerprintHex})`,
    };
  }
  const signerKey = await importSigningPublicKey(signerKeyBytes);
  if (!signerKey.ok) {
    return { kind: "rejected", message: "署名者の公開鍵を読み込めません" };
  }
  const verifiedSignature = await verifyDekWrapSignature({
    context: {
      suite: wrap.suite,
      projectId: verified.projectId,
      environmentId,
      epoch: wrap.epoch,
      recipientUserId: recipient.userId,
      recipientEncPubHex: recipient.encPubHex,
      encHex: wrap.encHex,
      ciphertextHex: wrap.ciphertextHex,
      signerUserId: wrap.signerUserId,
    },
    signatureHex: wrap.signatureHex,
    signerPublicKey: signerKey.value,
  });
  if (!verifiedSignature.ok) {
    return {
      kind: "rejected",
      message: `DEK ラップの登録署名が検証できません(epoch=${wrap.epoch}, signer=${displayText(wrap.signerUserId)})`,
    };
  }
  const enc = decodeHex(wrap.encHex);
  const ciphertext = decodeHex(wrap.ciphertextHex);
  if (enc === null || ciphertext === null) {
    return { kind: "rejected", message: `DEK ラップの形式が不正です(epoch=${wrap.epoch})` };
  }
  const dek = await unwrapDek({
    recipientKeyPair: recipient.encKeyPair,
    wrapped: { enc, ciphertext },
    context: {
      projectId: verified.projectId,
      environmentId,
      epoch: wrap.epoch,
      recipientUserId: recipient.userId,
    },
  });
  if (!dek.ok) {
    return {
      kind: "rejected",
      message: `DEK を復号できません(epoch=${wrap.epoch}, signer=${displayText(wrap.signerUserId)})。ラップが自分の鍵宛でないか、破損しています`,
    };
  }
  // §5.2 / §6.3: コミットメント照合に成功するまで DEK を使用しない。座標は
  // 自前の検証済み値(genesis ハッシュ・リクエストの環境 ID)から組み立てる
  const commitment = await verifyDekCommitment({
    context: {
      suite: SUITE_ID,
      projectId: verified.projectId,
      environmentId,
      epoch: wrap.epoch,
    },
    dek: dek.value,
    expectedCommitmentHex: input.expectedCommitmentHex,
  });
  if (!commitment.ok) {
    return {
      kind: "rejected",
      message: `DEK がチェーン上のコミットメントと一致しません(epoch=${wrap.epoch}, signer=${displayText(wrap.signerUserId)})。毒ラップ(偽 DEK)の可能性があります — 管理者による修復(ラップ削除 → 再登録)が必要です`,
    };
  }
  return { kind: "ok", dek: dek.value };
}

/** チェーン導出の環境状態(§6.2)。未作成の環境の配布はサーバー応答とチェーンの矛盾。 */
export function requireChainEnvironment(
  verified: VerifiedProject,
  environmentId: string,
): Effect.Effect<EnvironmentChainState, CliError> {
  const environment = verified.state.environments.get(environmentId);
  if (environment === undefined) {
    return Effect.fail(
      cliError(
        `環境 ${environmentId} がチェーン上に存在しません(create_environment 未観測)。作成直後の可能性があります — 再実行して解消しない場合、サーバー応答とチェーンが矛盾しています`,
      ),
    );
  }
  return Effect.succeed(environment);
}

/**
 * Verifies every distributed wrap (§5.1) and unwraps it, indexing DEKs by
 * epoch (§12-7: latest versions may span epochs, so all epochs are needed).
 * Any failure aborts — silently skipping a wrap would hide tampering.
 *
 * ファントムエポック対策(レビューループ 1 [中]): wrap の epoch はチェーン
 * 導出の現エポック以下でなければならない。§12-6 の「1〜現エポック」は
 * サーバー側強制であり、サーバー不信の下ではこのクライアント検査が本線
 * (チェーンに rotate_epoch がないエポックの DEK を受理すると、共謀サーバーが
 * 正規メンバー署名済みの攻撃者 DEK で偽値を注入できる)。
 */
function verifyAndUnwrapDeks(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly recipient: DekRecipient;
  readonly deks: readonly RecipientDek[];
}): Effect.Effect<ReadonlyMap<number, Uint8Array>, CliError> {
  return Effect.gen(function* () {
    // 環境の存在自体がチェーン導出(§6.2。「未観測なら 1」の既定値は廃止):
    // チェーンに無い環境の配布はファントム環境として全体を拒否する
    const environment = yield* requireChainEnvironment(input.verified, input.environmentId);
    const chainEpoch = environment.currentEpoch;
    const byEpoch = new Map<number, Uint8Array>();
    for (const wrap of input.deks) {
      if (wrap.suite !== SUITE_ID) {
        // Schema の Literal ピンで現状は到達しないが、検証座標に申告 suite を
        // 使う以上、CLI 側でも明示的に固定する(将来の union 化への防衛)
        return yield* Effect.fail(cliError(`未知のスイートの DEK ラップです(${wrap.suite})`));
      }
      if (wrap.epoch > chainEpoch) {
        return yield* Effect.fail(
          cliError(
            `チェーン上の現エポック(${chainEpoch})を超えるエポック ${wrap.epoch} の DEK ラップが配布されました。直後にローテーションが行われた可能性があります — 再実行して解消しない場合、サーバー応答とチェーンが矛盾しています`,
          ),
        );
      }
      if (byEpoch.has(wrap.epoch)) {
        return yield* Effect.fail(
          cliError(`同一エポックの DEK ラップが重複しています(epoch=${wrap.epoch})`),
        );
      }
      // チェーン導出のコミットメント(§5.2)。1 ≤ epoch ≤ 現エポックの全エポックは
      // create / rotate エントリがコミットメントを掲載済み(§6.2 の合意規則)
      const expectedCommitmentHex = environment.dekCommitments.get(wrap.epoch);
      if (expectedCommitmentHex === undefined) {
        return yield* Effect.fail(
          cliError(
            `エポック ${wrap.epoch} のコミットメントがチェーン上に存在しません(チェーン導出の不整合)`,
          ),
        );
      }
      const result = yield* Effect.tryPromise({
        try: () =>
          verifyAndUnwrapOne({
            verified: input.verified,
            environmentId: input.environmentId,
            recipient: input.recipient,
            wrap,
            expectedCommitmentHex,
          }),
        catch: () =>
          cliError(`DEK ラップの検証が失敗しました(epoch=${wrap.epoch} — 暗号処理エラー)`),
      });
      if (result.kind === "rejected") {
        return yield* Effect.fail(cliError(result.message));
      }
      byEpoch.set(wrap.epoch, result.dek);
    }
    return byEpoch;
  });
}

/**
 * 検証済みビュー由来の環境鍵集合: チェーン導出の現エポックと、
 * 同じビューで検証・開封した自分宛 DEK の対。
 */
export interface EnvironmentKeys {
  readonly currentEpoch: number;
  readonly deksByEpoch: ReadonlyMap<number, Uint8Array>;
}

/**
 * Derives the environment keys — the chain-derived current epoch and the
 * caller's verified, unwrapped DEKs — from one verified view, so that "the
 * epoch and the DEK set come from the same verified view" is enforced by
 * construction instead of by convention.
 *
 * 取得経路の優先順: cached(このセッションで検証済みの既知集合)に現エポックが
 * あれば再取得しない → prefetched(値付き pull の同梱ラップ — §12-7 の二重取得
 * 解消)があればそれを検証・開封 → どちらも無ければ listMine を取得して検証・
 * 開封する。検証(§5.1 登録署名 + §5.2 コミットメント照合)は全経路で必須。
 */
export function environmentKeysFor(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly recipient: DekRecipient;
  /** 値付き pull の同梱ラップ(verified と同じビューで検証する前提の生ワイヤ形)。 */
  readonly prefetched?: readonly RecipientDek[] | null | undefined;
  /** このセッションで検証・開封済みの既知集合(現エポックがあれば再取得しない)。 */
  readonly cached?: ReadonlyMap<number, Uint8Array> | undefined;
}): Effect.Effect<EnvironmentKeys, CliError> {
  return Effect.gen(function* () {
    // 現エポックはチェーン導出値(§6.2 — 環境未作成はここで止まる)
    const currentEpoch = (yield* requireChainEnvironment(input.verified, input.environmentId))
      .currentEpoch;
    if (input.cached?.has(currentEpoch) === true) {
      return { currentEpoch, deksByEpoch: input.cached };
    }
    const wire =
      input.prefetched ??
      (yield* input.client.deks
        .listMine({
          params: { projectId: input.verified.projectId, environmentId: input.environmentId },
        })
        .pipe(
          Effect.mapError(toCliError),
          Effect.map((response) => response.deks),
        ));
    const deksByEpoch = yield* verifyAndUnwrapDeks({
      verified: input.verified,
      environmentId: input.environmentId,
      recipient: input.recipient,
      deks: wire,
    });
    return { currentEpoch, deksByEpoch };
  });
}
