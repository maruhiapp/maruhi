// 配布されたラップ済み DEK の検証と復号(CRYPTO_SPEC §5.1 / §12-7)。
//
// 検証の座標は申告値を信用せず自前で組み立てる: projectId = 検証済み genesis
// ハッシュ、environmentId = リクエストに使った ID、recipient = 自分の
// user_id + 自分の enc 公開鍵。署名者の鍵は「検証済みチェーン履歴で
// signerUserId に束縛された sig 鍵のうち FP が一致するもの」(削除済み
// メンバーの当時の鍵も可 — チェーンは append-only)。
// wrap の epoch は申告値だが、登録署名(§5.1)と HPKE info(§5)の両方に
// 束縛されるため、別エポックへの移植は検証・復号失敗に落ちる。

import type { RecipientDek } from "@maruhi/api-schema";
import type { EncryptionKeyPair } from "@maruhi/crypto";
import {
  decodeHex,
  importSigningPublicKey,
  SUITE_ID,
  unwrapDek,
  verifyDekWrapSignature,
} from "@maruhi/crypto";
import { Effect } from "effect";

import { cliError, type CliError } from "./errors.ts";
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

async function verifyAndUnwrapOne(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly recipient: DekRecipient;
  readonly wrap: RecipientDek;
}): Promise<Uint8Array | { readonly failure: string }> {
  const { verified, environmentId, recipient, wrap } = input;
  const signerKeyBytes = signerKeyFor(verified, wrap);
  if (signerKeyBytes === null) {
    return {
      failure: `署名者がチェーン履歴に存在しません(signer=${wrap.signerUserId}, fp=${wrap.signerKeyFingerprintHex})`,
    };
  }
  const signerKey = await importSigningPublicKey(signerKeyBytes);
  if (!signerKey.ok) {
    return { failure: "署名者の公開鍵を読み込めません" };
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
      failure: `DEK ラップの登録署名が検証できません(epoch=${wrap.epoch}, signer=${wrap.signerUserId})`,
    };
  }
  const enc = decodeHex(wrap.encHex);
  const ciphertext = decodeHex(wrap.ciphertextHex);
  if (enc === null || ciphertext === null) {
    return { failure: `DEK ラップの形式が不正です(epoch=${wrap.epoch})` };
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
      failure: `DEK を復号できません(epoch=${wrap.epoch}, signer=${wrap.signerUserId})。ラップが自分の鍵宛でないか、破損しています`,
    };
  }
  return dek.value;
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
export function verifyAndUnwrapDeks(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly recipient: DekRecipient;
  readonly deks: readonly RecipientDek[];
}): Effect.Effect<ReadonlyMap<number, Uint8Array>, CliError> {
  const chainEpoch = input.verified.state.environmentEpochs.get(input.environmentId) ?? 1;
  return Effect.gen(function* () {
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
            `チェーン上の現エポック(${chainEpoch})を超えるエポック ${wrap.epoch} の DEK ラップが配布されました(サーバー応答とチェーンの矛盾)`,
          ),
        );
      }
      if (byEpoch.has(wrap.epoch)) {
        return yield* Effect.fail(
          cliError(`同一エポックの DEK ラップが重複しています(epoch=${wrap.epoch})`),
        );
      }
      const result = yield* Effect.promise(() =>
        verifyAndUnwrapOne({
          verified: input.verified,
          environmentId: input.environmentId,
          recipient: input.recipient,
          wrap,
        }),
      );
      if (!(result instanceof Uint8Array)) {
        return yield* Effect.fail(cliError(result.failure));
      }
      byEpoch.set(wrap.epoch, result);
    }
    return byEpoch;
  });
}
