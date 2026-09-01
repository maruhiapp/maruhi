// 一括 pull と復号(AUTH_SPEC §12-7 + CRYPTO_SPEC §4.1 / §5.1 / §5.2)。
//
// 検証順(§6.3): (1) 全値の値署名を復号より前に検証する(values.ts — future
// head の有界再同期を含む)、(2) 自分宛ラップの §5.1 登録署名 + §5.2 DEK
// コミットメント照合(deks.ts)、(3) AES-GCM 復号。復号文脈(AAD)は申告
// `aad` を信用せず、検証済み座標(genesis ハッシュ・要求環境・応答メタの
// variableId)で組み立てる(session-07 §5 / session-14 裁定 G)。
//
// 平文はメモリ上の Uint8Array のみ。ディスクへ書く経路はこのモジュールに
// 存在しない(ディスクレス不変条件)。復号の産物は `Redacted` で包み、
// ログ・エラー・テンプレート展開へ素で流れないようにする(剥がすのは
// 注入直前 = run.ts、表示ゲートの後ろ = display.ts、暗号境界 = push.ts のみ)。

import type { EnvironmentId } from "@maruhi/core";
import type { MetaVarType } from "@maruhi/crypto";
import { decodeHex, decryptVariable } from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

import type { MaruhiClient } from "./api.ts";
import { type DekRecipient, environmentKeysFor } from "./deks.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import type { FloorHandle, VerifiedVariableStatement } from "./floor-check.ts";
import type { VerifiedProject } from "./sync.ts";
import { pullVerifiedEnvironment, type VerifiedPulledValue } from "./values.ts";

/** One decrypted variable (plaintext bytes live in memory only). */
export interface DecryptedVariable {
  /** 検証済みメタステートメント由来の名前(§4.2 — 裸の name を信用しない)。 */
  readonly variableId: string;
  readonly name: string;
  readonly version: number;
  readonly epoch: number;
  /**
   * 宣言型(§4.2 レイアウト v2 のスキーマ欄。v1 / 未指定 = "")。注入直前の
   * advisory 型検証(run.ts — §14.3-7: 検証は警告のみで実行は続行)にだけ使う。
   */
  readonly varType: MetaVarType;
  /** 平文バイト列(メモリ上のみ。剥がす箇所は run / show / 再暗号化に限る)。 */
  readonly value: Redacted.Redacted<Uint8Array>;
}

/**
 * One declared variable (a schema-only declaration with no value —
 * CRYPTO_SPEC §4.2 layout v2). `maruhi run` / `ci run` の presence 検査
 * (required 硬 — §14.2-8)の材料。description は運ばない(fail-fast の
 * エラー文面に description を含めない — session-46 §8 第 3 周)。
 */
export interface DeclaredVariable {
  readonly variableId: string;
  readonly name: string;
  readonly required: boolean;
  readonly varType: MetaVarType;
}

/** 復号済み変数・declared 宣言と、検証中に収集した SHOULD 警告(非 NFC 名の配布等)。 */
export interface PulledVariables {
  readonly variables: readonly DecryptedVariable[];
  /** 検証済み declared(値なし — 注入対象外。presence 検査は呼び出し側)。 */
  readonly declared: readonly DeclaredVariable[];
  readonly warnings: readonly string[];
}

/**
 * 検証済み declared ステートメント → presence 検査の材料。declared はレイアウト
 * v2 限定(§4.2 — v1 declared は検証段で拒否済み)なので schema は必ず載るが、
 * 型の上の null は fail-closed に required = true 扱いにする(required の欠落を
 * 「注入せず素通り」に落とさない)。
 */
export function toDeclaredVariables(
  statements: readonly VerifiedVariableStatement[],
): readonly DeclaredVariable[] {
  return statements.map((statement) => ({
    variableId: statement.variableId,
    name: statement.name,
    required: statement.schema?.required ?? true,
    varType: statement.schema?.varType ?? "",
  }));
}

/**
 * 「自分宛に当該エポックのラップが無い」理由文。**復号の失敗理由を作る側**に置き、
 * 呼び出し側(env-rotate の警告)と共有する: env rotate はこの文面で「良性の欠落」を
 * 見分け、`dedupeWarnings`(完全一致の集合)で重複を潰すため、2 箇所に書くと
 * 片方を直した瞬間に同じ変数の警告が 2 行出るようになる。
 */
export function missingWrapReason(variable: {
  readonly name: string;
  readonly epoch: number;
}): string {
  return `No DEK for epoch ${variable.epoch} of variable ${displayText(variable.name)} was distributed (your wrap is missing)`;
}

/**
 * Decrypts one already-verified value (§6.3 を通過した values.ts の産物)。
 * 復号文脈(AAD)の座標は申告 `aad` ではなく検証済みの値(genesis ハッシュ・
 * 要求環境・応答外側の variableId)から組む。epoch / version は値署名で検証
 * 済みの申告値(この座標に束縛される)。
 *
 * 共有点である理由: `maruhi run` の pull と `maruhi env rotate` の再暗号化は
 * 同じ規律で復号しなければならない(復号経路が 2 つに割れると、片方だけが
 * 座標の自前構築・エポック上限検査を失う静かな退行になる)。
 */
export function decryptVerifiedValue(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly variable: VerifiedPulledValue;
  readonly deksByEpoch: ReadonlyMap<number, Redacted.Redacted<Uint8Array>>;
  /** チェーン導出の現エポック(申告エポックの上限 — 導出不整合への防衛線)。 */
  readonly chainEpoch: number;
}): Effect.Effect<Redacted.Redacted<Uint8Array>, CliError> {
  return Effect.gen(function* () {
    const variable = input.variable;
    // 値署名の検証(§6.3-4)が「宣言ヘッド時点の現エポック = 値の epoch」を
    // 保証済みで、エポックの単調性からこの値は現エポック以下。ここの検査は
    // 導出不整合(実装バグ)への防衛線として残す
    if (variable.epoch > input.chainEpoch) {
      return yield* Effect.fail(
        cliError(
          `Variable ${displayText(variable.name)} declares epoch ${variable.epoch}, beyond the chain's current epoch (${input.chainEpoch}) (inconsistent with the verified view)`,
        ),
      );
    }
    const dek = input.deksByEpoch.get(variable.epoch);
    if (dek === undefined) {
      return yield* Effect.fail(cliError(missingWrapReason(variable)));
    }
    const nonce = decodeHex(variable.nonceHex);
    const ciphertext = decodeHex(variable.ciphertextHex);
    if (nonce === null || ciphertext === null) {
      return yield* Effect.fail(
        cliError(`Variable ${displayText(variable.name)} has a malformed ciphertext`),
      );
    }
    const plaintext = yield* Effect.tryPromise({
      try: () =>
        decryptVariable({
          // 剥がす理由: 復号の鍵入力(暗号境界)
          dek: Redacted.value(dek),
          context: {
            projectId: input.verified.projectId,
            environmentId: input.environmentId,
            epoch: variable.epoch,
            variableId: variable.variableId,
            version: variable.version,
          },
          nonce,
          ciphertext,
        }),
      catch: () =>
        cliError(`Decryption of variable ${displayText(variable.name)} failed (crypto error)`),
    });
    if (!plaintext.ok) {
      return yield* Effect.fail(
        cliError(
          `Cannot decrypt variable ${displayText(variable.name)} (context mismatch or corrupted ciphertext — possibly replaced by the server)`,
        ),
      );
    }
    // 復号の産物はここで包む。以降、平文は Redacted としてしか流れない
    return Redacted.make(plaintext.value, { label: "variable-value" });
  });
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

    // §7 の全エポック配布との差分検査(未完了バックフィルの本人側検出 — B2 裁定):
    // 全メンバーは 1〜現エポックの全 DEK を自分宛に持つはずで、欠けは常に
    // member add のバックフィル中断・修復未了の兆候(誤検知なし)。現在値の
    // 復号に必要なエポックの欠けは decryptVerifiedValue が硬い失敗として止める
    // ので、ここは履歴エポックの静かな欠け(現在値だけでは永遠に顕在化しない)を
    // SHOULD 警告として拾う
    const missingEpochs: number[] = [];
    for (let epoch = 1; epoch <= keys.currentEpoch; epoch += 1) {
      if (!deksByEpoch.has(epoch)) {
        missingEpochs.push(epoch);
      }
    }
    const warnings =
      missingEpochs.length === 0
        ? pulled.warnings
        : [
            ...pulled.warnings,
            `Warning: no DEK wraps for you exist at epochs ${missingEpochs.join(", ")} (inconsistent with the CRYPTO_SPEC §7 all-epoch distribution). A member-add backfill may have been interrupted — historical versions in those epochs cannot be decrypted. Ask an administrator who holds wraps for all epochs to re-run maruhi member add (or re-register through the repair path)`,
          ];

    const results: DecryptedVariable[] = [];
    for (const variable of pulled.variables) {
      // 同名 active の重複はステートメント検証(values.ts)が解決拒否済み
      // (§4.2 — `maruhi run` の環境変数注入が黙って片方を潰す経路はない)
      const plaintext = yield* decryptVerifiedValue({
        verified,
        environmentId: input.environmentId,
        variable,
        deksByEpoch,
        chainEpoch: keys.currentEpoch,
      });
      results.push({
        variableId: variable.variableId,
        name: variable.name,
        version: variable.version,
        epoch: variable.epoch,
        varType: variable.schema?.varType ?? "",
        value: plaintext,
      });
    }
    return { variables: results, declared: toDeclaredVariables(pulled.declared), warnings };
  });
}
