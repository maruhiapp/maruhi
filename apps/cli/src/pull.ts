// 一括 pull と復号(AUTH_SPEC §12-7 + CRYPTO_SPEC §5.1)。
//
// 復号文脈(AAD)は暗号文に併置された申告 `aad` を信用せず、値を帰属させる
// 座標 — 検証済み genesis ハッシュの projectId・URL に使った environmentId・
// 応答メタデータ(PulledVariableSchema)の variableId — で組み立てる。
// epoch / version は申告値を使うが、この座標に束縛されるため、サーバーが
// 別変数の暗号文を差し替えれば復号失敗に落ちる(session-07 §5)。
//
// 平文はメモリ上の Uint8Array のみ。ディスクへ書く経路はこのモジュールに
// 存在しない(ディスクレス不変条件)。

import type { EnvironmentId } from "@maruhi/core";
import { decodeHex, decryptVariable } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { type DekRecipient, requireChainEnvironment, verifyAndUnwrapDeks } from "./deks.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import type { VerifiedProject } from "./sync.ts";

/** One decrypted variable (plaintext bytes live in memory only). */
export interface DecryptedVariable {
  readonly variableId: string;
  readonly name: string;
  readonly version: number;
  readonly epoch: number;
  readonly value: Uint8Array;
}

/**
 * Pulls one environment and decrypts every variable's latest version after
 * the §5.1 wrap verification. DEKs are indexed by epoch because latest
 * versions may span epochs until re-encryption completes (§12-7).
 */
export function pullVariables(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
}): Effect.Effect<readonly DecryptedVariable[], CliError> {
  return Effect.gen(function* () {
    const response = yield* input.client.variables
      .pull({ params: { projectId: input.verified.projectId, environmentId: input.environmentId } })
      .pipe(Effect.mapError(toCliError));

    const deksByEpoch = yield* verifyAndUnwrapDeks({
      verified: input.verified,
      environmentId: input.environmentId,
      recipient: input.recipient,
      deks: response.deks,
    });

    const results: DecryptedVariable[] = [];
    const seenNames = new Set<string>();
    // 環境の存在はチェーン導出(§6.2 — verifyAndUnwrapDeks が検査済みだが、
    // 現エポックの参照もチェーン導出値から取る)
    const chainEpoch = (yield* requireChainEnvironment(input.verified, input.environmentId))
      .currentEpoch;
    for (const variable of response.variables) {
      // 変数名の一意性はサーバーが強制する(§12-1)が、`maruhi run` の環境変数
      // 注入が黙って片方を潰さないようクライアントでも検査する(サーバー不信)
      if (seenNames.has(variable.name)) {
        return yield* Effect.fail(
          cliError(`変数名が重複しています(サーバー応答の不整合): ${displayText(variable.name)}`),
        );
      }
      seenNames.add(variable.name);

      const declaredEpoch = variable.value.aad.epoch;
      const declaredVersion = variable.value.aad.version;
      // ファントムエポック対策の第二層(deks.ts のラップ側検査と対): 申告
      // epoch はチェーン導出の現エポック以下でなければならない
      if (declaredEpoch > chainEpoch) {
        return yield* Effect.fail(
          cliError(
            `変数 ${displayText(variable.name)} の申告エポック ${declaredEpoch} がチェーン上の現エポック(${chainEpoch})を超えています。直後にローテーションが行われた可能性があります — 再実行して解消しない場合、サーバー応答とチェーンが矛盾しています`,
          ),
        );
      }
      const dek = deksByEpoch.get(declaredEpoch);
      if (dek === undefined) {
        return yield* Effect.fail(
          cliError(
            `変数 ${displayText(variable.name)} のエポック ${declaredEpoch} の DEK が配布されていません(自分宛ラップの欠落)`,
          ),
        );
      }
      const nonce = decodeHex(variable.value.nonceHex);
      const ciphertext = decodeHex(variable.value.ciphertextHex);
      if (nonce === null || ciphertext === null) {
        return yield* Effect.fail(
          cliError(`変数 ${displayText(variable.name)} の暗号文形式が不正です`),
        );
      }
      const plaintext = yield* Effect.promise(() =>
        decryptVariable({
          dek,
          // 申告 AAD をそのまま使わない: 座標(project / environment / variable)は
          // 自前の検証済み値。epoch / version のみ申告値(この座標に束縛される)
          context: {
            projectId: input.verified.projectId,
            environmentId: input.environmentId,
            epoch: declaredEpoch,
            variableId: variable.variableId,
            version: declaredVersion,
          },
          nonce,
          ciphertext,
        }),
      );
      if (!plaintext.ok) {
        return yield* Effect.fail(
          cliError(
            `変数 ${displayText(variable.name)} を復号できません(文脈不一致または暗号文破損 — サーバーによる差し替えの可能性)`,
          ),
        );
      }
      results.push({
        variableId: variable.variableId,
        name: variable.name,
        version: declaredVersion,
        epoch: declaredEpoch,
        value: plaintext.value,
      });
    }
    return results;
  });
}
