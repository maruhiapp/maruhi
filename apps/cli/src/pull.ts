// 一括 pull と復号(AUTH_SPEC §12-7 + CRYPTO_SPEC §4.1 / §5.1 / §5.2)。
//
// 検証順(§6.3): (1) 全値の値署名を復号より前に検証する(values.ts — future
// head の有界再同期を含む)、(2) 自分宛ラップの §5.1 登録署名 + §5.2 DEK
// コミットメント照合(deks.ts)、(3) AES-GCM 復号。復号文脈(AAD)は申告
// `aad` を信用せず、検証済み座標(genesis ハッシュ・要求環境・応答メタの
// variableId)で組み立てる(session-07 §5 / session-14 裁定 G)。
//
// 平文はメモリ上の Uint8Array のみ。ディスクへ書く経路はこのモジュールに
// 存在しない(ディスクレス不変条件)。

import type { EnvironmentId } from "@maruhi/core";
import { decodeHex, decryptVariable } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { type DekRecipient, environmentKeysFor } from "./deks.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import type { FloorHandle } from "./floor-check.ts";
import type { VerifiedProject } from "./sync.ts";
import { pullVerifiedEnvironment } from "./values.ts";

/** One decrypted variable (plaintext bytes live in memory only). */
export interface DecryptedVariable {
  /** 検証済みメタステートメント由来の名前(§4.2 — 裸の name を信用しない)。 */
  readonly variableId: string;
  readonly name: string;
  readonly version: number;
  readonly epoch: number;
  readonly value: Uint8Array;
}

/** 復号済み変数と、検証中に収集した SHOULD 警告(非 NFC 名の配布等)。 */
export interface PulledVariables {
  readonly variables: readonly DecryptedVariable[];
  readonly warnings: readonly string[];
}

/**
 * Pulls one environment, verifies every value's write signature and every
 * metadata statement (§4.1 / §4.2 — before any decryption; names come only
 * from verified statements), verifies and unwraps the caller's DEKs (§5.1
 * registration signature + §5.2 commitment matching stay mandatory), then
 * decrypts every latest version. DEKs are indexed by epoch because latest
 * versions may span epochs until a rotation's re-encryption completes
 * (§12-7).
 */
export function pullVariables(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
  /** future head(§6.3-2b)時の有界再同期。 */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** ローカル床(§6.3 — 検査と検証成功後の原子コミット)。 */
  readonly floor: FloorHandle;
}): Effect.Effect<PulledVariables, CliError> {
  return Effect.gen(function* () {
    // (1) 値署名の検証(復号より前)。future head なら有界再同期で前進した
    // ビューが返る — 以降の検証(ラップ・エポック)も同じビューで行う
    const pulled = yield* pullVerifiedEnvironment(input);
    const verified = pulled.verified;

    // (2) ラップの §5.1 / §5.2 検証と unwrap(コミットメント照合まで成功する
    // まで DEK は使用しない)。現エポック(チェーン導出 — §6.2)と DEK 集合は
    // 同じ検証済みビューから一括導出する(deks.ts の environmentKeysFor)
    const keys = yield* environmentKeysFor({
      client: input.client,
      verified,
      environmentId: input.environmentId,
      recipient: input.recipient,
      prefetched: pulled.deks,
    });
    const deksByEpoch = keys.deksByEpoch;

    const results: DecryptedVariable[] = [];
    const chainEpoch = keys.currentEpoch;
    for (const variable of pulled.variables) {
      // 同名 active の重複はステートメント検証(values.ts)が解決拒否済み
      // (§4.2 — `maruhi run` の環境変数注入が黙って片方を潰す経路はない)

      // 値署名の検証(§6.3-4)が「宣言ヘッド時点の現エポック = 値の epoch」を
      // 保証済みで、エポックの単調性からこの値は現エポック以下。ここの検査は
      // 導出不整合(実装バグ)への防衛線として残す
      if (variable.epoch > chainEpoch) {
        return yield* Effect.fail(
          cliError(
            `変数 ${displayText(variable.name)} の申告エポック ${variable.epoch} がチェーン上の現エポック(${chainEpoch})を超えています(検証済みビューとの不整合)`,
          ),
        );
      }
      const dek = deksByEpoch.get(variable.epoch);
      if (dek === undefined) {
        return yield* Effect.fail(
          cliError(
            `変数 ${displayText(variable.name)} のエポック ${variable.epoch} の DEK が配布されていません(自分宛ラップの欠落)`,
          ),
        );
      }
      const nonce = decodeHex(variable.nonceHex);
      const ciphertext = decodeHex(variable.ciphertextHex);
      if (nonce === null || ciphertext === null) {
        return yield* Effect.fail(
          cliError(`変数 ${displayText(variable.name)} の暗号文形式が不正です`),
        );
      }
      const plaintext = yield* Effect.tryPromise({
        try: () =>
          decryptVariable({
            dek,
            // 座標(project / environment / variable)は自前の検証済み値。
            // epoch / version は値署名で検証済みの申告値(この座標に束縛される)
            context: {
              projectId: verified.projectId,
              environmentId: input.environmentId,
              epoch: variable.epoch,
              variableId: variable.variableId,
              version: variable.version,
            },
            nonce,
            ciphertext,
          }),
        catch: () =>
          cliError(`変数 ${displayText(variable.name)} の復号処理が失敗しました(暗号処理エラー)`),
      });
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
        version: variable.version,
        epoch: variable.epoch,
        value: plaintext.value,
      });
    }
    return { variables: results, warnings: pulled.warnings };
  });
}
