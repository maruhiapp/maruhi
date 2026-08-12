// エポックローテーション(CRYPTO_SPEC §7 / §5.2 / §6.2、AUTH_SPEC §12-4 / §12-5)。
//
// ローテーションは構造的に 2 段である: (i) `rotate_epoch` エントリ(新エポックの
// DEK コミットメント込み)+ 新エポックのラップ完全集合の**複合受理**(原子的 —
// §12-4)、(ii) 現在値の再暗号化 = 実行者が writer として署名する通常 push の列
// (§7 / §4.1。値の量に依存する巨大リクエストを避けるため複合に含めない)。
// (i) と (ii) の間で中断すると「エポックは進んだが再暗号化が残っている」状態が
// 残る — これは §12-7 が明示する正当な過渡状態であり、本コマンドの再実行は
// **エポックを進めずにその再暗号化を再開する**(冪等な再開)。
//
// 検出は配布データからのみ行う(ローカルの進捗ファイルを持たない = ディスクレス
// 不変条件と両立し、別デバイス・別メンバーからの再開もそのまま成立する):
// 検証済み pull の「最新値の epoch < チェーン導出の現エポック」が未完了の証拠。
//
// 平文はメモリ上の Uint8Array のみ。ログ・エラーに出るのは検証済みステートメント
// 由来の変数名(displayText 済み)・件数・エポック番号だけである。

import {
  ChainHeadConflictError,
  EnvironmentNotFoundError,
  EpochConflictError,
  VersionConflictError,
  type WrappedDek,
} from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import type { ChainEntry, ChainMember, SigningKeyPair } from "@maruhi/crypto";
import { computeDekCommitment, generateDek, signChainEntry, SUITE_ID } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { buildWrapSetForMembers, ensureNoServerGrant, sameMemberSet } from "./dek-wrap.ts";
import { type DekRecipient, environmentKeysFor, requireChainEnvironment } from "./deks.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import type { FloorHandle } from "./floor-check.ts";
import { CliIo } from "./io.ts";
import { decryptVerifiedValue } from "./pull.ts";
import { encryptAndSignPayload } from "./push.ts";
import { retryOnConflict } from "./retry.ts";
import { resyncExtended, type VerifiedProject } from "./sync.ts";
import { pullVerifiedEnvironment, type VerifiedPulledValue } from "./values.ts";

const MAX_ATTEMPTS = 5;
/** 再暗号化の巡回上限(1 巡 = 全対象への push + 競合分の再取得・再検証)。 */
const MAX_REENCRYPT_PASSES = 3;
/** チェーンの自由文字列フィールドの合意規則上限(CRYPTO_SPEC §6.1)。 */
const MAX_REASON_BYTES = 1024;

/** ローテーション 1 回分の結果(表示・終了コードの材料)。 */
export interface RotationSummary {
  /** rotated = 新エポックを開始した / resumed = 未完了の再暗号化を再開した。 */
  readonly mode: "rotated" | "resumed";
  readonly previousEpoch: number;
  readonly epoch: number;
  /** 新エポックの DEK をラップした現メンバー数(resumed では現メンバー数)。 */
  readonly memberCount: number;
  /** 再暗号化して push した変数数。 */
  readonly reencrypted: number;
  /** 並行 push により既に現エポックで書かれていた変数数(再暗号化不要)。 */
  readonly alreadyCurrent: number;
  /** 競合が解けず未完了のまま残った変数数(> 0 なら部分完了)。 */
  readonly remaining: number;
  readonly warnings: readonly string[];
}

interface RotateInput {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
  /** チェーンに記録される理由(§6.2 の payload フィールド)。 */
  readonly reason: string;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  /** 再同期(チェーン全再検証)。CAS 競合・受理後の確認に使う。 */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** ローカル床(§6.3 — 内部 pull の検査・コミットと、再暗号化 push の床前進)。 */
  readonly floor: FloorHandle;
}

/** 再暗号化 1 変数分の材料(検証済み最新値 + その平文)。 */
interface ReencryptTarget {
  readonly value: VerifiedPulledValue;
  /** メモリ上のみ。ディスク・ログ・エラーメッセージへ出す経路を持たない。 */
  readonly plaintext: Uint8Array;
}

interface ReencryptOutcome {
  readonly reencrypted: number;
  readonly alreadyCurrent: number;
  readonly remaining: number;
  readonly warnings: readonly string[];
}

/**
 * 理由文字列の正規化と早期検証。チェーンの自由文字列上限(§6.1)を超える
 * エントリは**無効**(合意規則)なので、サーバーの拒否を待たず手前で落とす。
 */
function normalizeReason(reason: string): Effect.Effect<string, CliError> {
  const trimmed = reason.trim();
  if (trimmed.length === 0) {
    return Effect.fail(
      cliError(
        "--reason にローテーションの理由を指定してください(チェーンの rotate_epoch エントリに記録され、後から書き換えられません)",
      ),
    );
  }
  const bytes = new TextEncoder().encode(trimmed).length;
  if (bytes > MAX_REASON_BYTES) {
    return Effect.fail(
      cliError(
        `--reason が長すぎます(${bytes} バイト)。チェーンエントリの自由文字列上限は UTF-8 で ${MAX_REASON_BYTES} バイトです(CRYPTO_SPEC §6.1)`,
      ),
    );
  }
  return Effect.succeed(trimmed);
}

/**
 * ローテーション可能性の早期検査: grant_server 未対応・環境のチェーン存在・
 * 自分が現メンバーであること・role が member 以上であること(§6.2)。
 * pull(値の取得 = var.read の記録)より前に落とす。
 */
function ensureRotatable(
  verified: VerifiedProject,
  environmentId: string,
  signerUserId: string,
): Effect.Effect<ChainMember, CliError> {
  return Effect.gen(function* () {
    // §7: grant_server が有効なら新エポック DEK をサーバー鍵へも再ラップしなければ
    // リース経路が停止する。メンバー宛だけの完全集合で黙って進めない
    yield* ensureNoServerGrant(verified, "ローテーション");
    yield* requireChainEnvironment(verified, environmentId);
    const member = verified.state.members.get(signerUserId);
    if (member === undefined) {
      return yield* Effect.fail(
        cliError(
          "このプロジェクトのチェーン導出メンバーではありません(エポックをローテーションできません)",
        ),
      );
    }
    if (member.role === "reader") {
      return yield* Effect.fail(
        cliError(
          "reader はエポックをローテーションできません(rotate_epoch と値の push は member 以上 — CRYPTO_SPEC §6.2)",
        ),
      );
    }
    return member;
  });
}

/** rotate_epoch エントリを現ヘッドの直後(seq = head + 1)に署名する。 */
function signRotateEntry(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly newEpoch: number;
  readonly reason: string;
  readonly dekCommitmentHex: string;
  readonly member: ChainMember;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<ChainEntry & { readonly op: "rotate_epoch" }, CliError> {
  return Effect.gen(function* () {
    const signed = yield* Effect.tryPromise({
      try: () =>
        signChainEntry({
          entry: {
            suite: SUITE_ID,
            seq: input.verified.state.headSeq + 1,
            prevHashHex: input.verified.state.headHashHex,
            op: "rotate_epoch",
            actor: {
              userId: input.member.userId,
              keyFingerprintHex: input.member.keyFingerprintHex,
            },
            payload: {
              environmentId: input.environmentId,
              newEpoch: input.newEpoch,
              reason: input.reason,
              dekCommitmentHex: input.dekCommitmentHex,
            },
            timestampMs: Date.now(),
          },
          signingKey: input.signingKeyPair.privateKey,
        }),
      catch: () => cliError("rotate_epoch エントリの署名に失敗しました"),
    });
    if (!signed.ok) {
      return yield* Effect.fail(cliError("rotate_epoch エントリの署名に失敗しました"));
    }
    // op の絞り込み(signChainEntry は入力の op を保存する)
    if (signed.value.op !== "rotate_epoch") {
      return yield* Effect.fail(cliError("rotate_epoch エントリの署名に失敗しました"));
    }
    return signed.value;
  });
}

/** CAS リトライの状態: 検証ビュー・自分のメンバー行・新エポックのラップ集合。 */
interface RotateState {
  readonly verified: VerifiedProject;
  readonly member: ChainMember;
  readonly deks: readonly WrappedDek[];
}

/** 複合受理の結果(受理時点の状態を持ち帰り、受理後の再同期の基準にする)。 */
interface AcceptedRotation {
  readonly state: RotateState;
}

/**
 * 削除済み(tombstone)環境への rotate は 404(§12-4)。チェーンは環境の存在を
 * 主張しているのにサーバーが 404 を返す形なので、§7 の規律どおり「黙って
 * スキップせず中断して警告する」— 汎用の「環境が見つかりません」に潰さない。
 */
function mapRotateFailure(environmentId: string): (error: unknown) => unknown {
  return (error) =>
    error instanceof EnvironmentNotFoundError
      ? cliError(
          `環境 ${environmentId} へのローテーションが 404 で拒否されました。検証済みの削除ステートメントを確認できない限り、悪意あるサーバーによる選択的なローテーション阻止の可能性があります — 黙ってスキップせず中断します(CRYPTO_SPEC §7)`,
        )
      : // ChainHeadConflict 等の分類対象はそのまま通す(retryOnConflict の classify)
        error;
}

/**
 * `rotate_epoch` 複合の送信(§12-4)。親ヘッド CAS 失敗は再同期 → エントリ
 * 再署名でリトライし(ラップ集合はメンバー集合が変わった場合のみ作り直す)、
 * 受理後は再同期して「チェーン導出の現エポックが新エポックであること」と
 * 「そのエポックのコミットメントが自分の生成した DEK のものであること」
 * (§5.2 — 照合まで DEK を使わない規律の自己生成 DEK への適用)を確認する。
 */
function appendRotation(
  input: RotateInput & {
    readonly baseline: VerifiedProject;
    readonly member: ChainMember;
    readonly reason: string;
    readonly newEpoch: number;
    readonly dek: Uint8Array;
    readonly dekCommitmentHex: string;
  },
): Effect.Effect<{ readonly view: VerifiedProject; readonly memberCount: number }, CliError> {
  return Effect.gen(function* () {
    const buildWraps = (verified: VerifiedProject) =>
      buildWrapSetForMembers({
        verified,
        environmentId: input.environmentId,
        epoch: input.newEpoch,
        dek: input.dek,
        signerUserId: input.signerUserId,
        signingKeyPair: input.signingKeyPair,
      });

    const accepted = yield* retryOnConflict<RotateState, AcceptedRotation, "head-conflict">(
      { verified: input.baseline, member: input.member, deks: yield* buildWraps(input.baseline) },
      {
        maxAttempts: MAX_ATTEMPTS,
        attempt: (state) =>
          Effect.gen(function* () {
            const entry = yield* signRotateEntry({
              verified: state.verified,
              environmentId: input.environmentId,
              newEpoch: input.newEpoch,
              reason: input.reason,
              dekCommitmentHex: input.dekCommitmentHex,
              member: state.member,
              signingKeyPair: input.signingKeyPair,
            });
            yield* input.client.environments
              .rotate({
                params: {
                  projectId: state.verified.projectId,
                  environmentId: input.environmentId,
                },
                payload: {
                  parentHeadHashHex: state.verified.state.headHashHex,
                  entry,
                  deks: state.deks,
                },
              })
              .pipe(Effect.mapError(mapRotateFailure(input.environmentId)));
            return { state };
          }),
        classify: (error) => (error instanceof ChainHeadConflictError ? "head-conflict" : null),
        recover: (state) =>
          Effect.gen(function* () {
            const resynced = yield* resyncExtended(input.resync, state.verified);
            const member = yield* ensureRotatable(
              resynced,
              input.environmentId,
              input.signerUserId,
            );
            const environment = yield* requireChainEnvironment(resynced, input.environmentId);
            if (environment.currentEpoch + 1 !== input.newEpoch) {
              // 他メンバーが並行してローテーションした。生成済みの新 DEK・
              // コミットメント・ラップ集合は当該エポック専用(§5 の info /
              // §5.2 の原像に epoch が入る)なので流用せず中断する。再実行は
              // 未完了の再暗号化があればエポックを進めずに再開する
              return yield* Effect.fail(
                cliError(
                  `他のメンバーによる並行ローテーションを検出しました(環境 ${input.environmentId} の現エポックは ${environment.currentEpoch})。生成した新 DEK は使用せず中断します — 再実行してください`,
                ),
              );
            }
            const deks = sameMemberSet(state.verified, resynced)
              ? state.deks
              : yield* buildWraps(resynced);
            return { verified: resynced, member, deks };
          }),
        exhaustedMessage: `ローテーションのチェーンヘッド競合が解消しません(${MAX_ATTEMPTS} 回試行)。時間をおいて再実行してください`,
      },
    );

    // 受理後の確認はサーバー申告(応答の currentEpoch)ではなくチェーン再検証で行う
    const view = yield* resyncExtended(input.resync, accepted.state.verified);
    const environment = yield* requireChainEnvironment(view, input.environmentId);
    if (environment.currentEpoch !== input.newEpoch) {
      return yield* Effect.fail(
        cliError(
          `ローテーション(epoch=${input.newEpoch})は受理されましたが、再同期したチェーンの現エポックは ${environment.currentEpoch} です(受理直後の並行ローテーションの可能性)。再実行すると未完了の再暗号化から再開します`,
        ),
      );
    }
    if (environment.dekCommitments.get(input.newEpoch) !== input.dekCommitmentHex) {
      // §5.2: コミットメント照合に成功するまで DEK をいかなる暗号操作にも使わない。
      // 自分で生成した DEK にも同じ規律を適用する(受理されたエントリが自分の
      // ものであることの確認 = 再暗号化を他人の DEK 前提で始めない)
      return yield* Effect.fail(
        cliError(
          `受理された epoch=${input.newEpoch} のコミットメントが、生成した DEK のものと一致しません(CRYPTO_SPEC §5.2)。この DEK は使用せず中断します — 再実行してください`,
        ),
      );
    }
    return { view, memberCount: accepted.state.deks.length };
  });
}

/** 検証済み最新値の復号(再暗号化の材料づくり)。復号規律は pull と共有する。 */
function decryptTargets(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly values: readonly VerifiedPulledValue[];
  readonly deksByEpoch: ReadonlyMap<number, Uint8Array>;
  readonly chainEpoch: number;
}): Effect.Effect<readonly ReencryptTarget[], CliError> {
  return Effect.gen(function* () {
    const targets: ReencryptTarget[] = [];
    for (const value of input.values) {
      const plaintext = yield* decryptVerifiedValue({
        verified: input.verified,
        environmentId: input.environmentId,
        variable: value,
        deksByEpoch: input.deksByEpoch,
        chainEpoch: input.chainEpoch,
      });
      targets.push({ value, plaintext });
    }
    return targets;
  });
}

/**
 * 再暗号化 1 変数分の push(§7 / §4.1 — 再暗号化は「実行者が writer として
 * 署名する通常 push」であり、専用のワイヤも認可も持たない)。
 */
function pushReencrypted(input: {
  readonly client: MaruhiClient;
  readonly environmentId: EnvironmentId;
  readonly view: VerifiedProject;
  readonly floor: FloorHandle;
  readonly target: ReencryptTarget;
  readonly epoch: number;
  readonly dek: Uint8Array;
  readonly writerUserId: string;
  readonly signingKey: CryptoKey;
}): Effect.Effect<"pushed" | "conflict", CliError> {
  return Effect.gen(function* () {
    const latest = input.target.value;
    const version = latest.version + 1;
    // prev は検証済み最新値の**自計算**ハッシュ(サーバー申告のハッシュへ
    // 連鎖署名しない — §12-5 の証拠連鎖の汚染回避)
    const signed = yield* encryptAndSignPayload({
      verified: input.view,
      environmentId: input.environmentId,
      variableId: latest.variableId,
      epoch: input.epoch,
      version,
      prevValueSigHashHex: latest.signedBytesHashHex,
      dek: input.dek,
      value: input.target.plaintext,
      writerUserId: input.writerUserId,
      signingKey: input.signingKey,
    });
    const outcome = yield* input.client.variables
      .push({
        params: {
          projectId: input.view.projectId,
          environmentId: input.environmentId,
          variableId: latest.variableId,
        },
        payload: { value: signed.payload },
      })
      .pipe(
        Effect.map(() => "pushed" as const),
        Effect.catch((error): Effect.Effect<"pushed" | "conflict", CliError> => {
          if (error instanceof VersionConflictError) {
            // 並行 push の勝者がいる。409 の申告値では決めず、呼び出し側が
            // 再取得・再検証して実態(勝者が既に現エポックか)を確かめる
            return Effect.succeed("conflict");
          }
          if (error instanceof EpochConflictError) {
            return Effect.fail(
              cliError(
                `再暗号化の途中で環境 ${input.environmentId} のエポックが進みました(他メンバーによる並行ローテーション)。再実行すると新しいエポックの再暗号化から再開します`,
              ),
            );
          }
          return Effect.fail(toCliError(error));
        }),
      );
    if (outcome === "conflict") {
      return "conflict";
    }
    // 受理された自分の書き込みを床へ昇格する(§6.3)。メタは変更していないので
    // 床のメタ記録は検証済み latest のまま。規則 (c) の基準は動かさない
    yield* input.floor
      .commitPush(
        latest.variableId,
        {
          status: "active",
          version,
          epoch: input.epoch,
          valueSigHashHex: signed.signedBytesHashHex,
          metaVersion: latest.metaVersion,
          metaSigHashHex: latest.metaSignedBytesHashHex,
        },
        { seq: input.view.state.headSeq, hashHex: input.view.state.headHashHex },
      )
      .pipe(Effect.mapError((error) => cliError(`再暗号化は受理されましたが、${error.message}`)));
    return "pushed";
  });
}

interface ReplanResult {
  readonly view: VerifiedProject;
  readonly targets: readonly ReencryptTarget[];
  readonly alreadyCurrent: number;
  readonly warnings: readonly string[];
}

/**
 * VersionConflict を起こした変数の再計画(§12-5 の再試行手順): 再取得 →
 * §6.3 全検証 → 勝者の実態で分岐する。勝者の epoch が既に新エポックなら
 * 再暗号化は不要(push は現エポックでしか受理されない — §12-5)であり、
 * それ未満なら勝者を新しい基準にして再暗号化し直す。
 */
function replanConflicted(input: {
  readonly client: MaruhiClient;
  readonly environmentId: EnvironmentId;
  readonly view: VerifiedProject;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
  readonly epoch: number;
  readonly deksByEpoch: ReadonlyMap<number, Uint8Array>;
  readonly conflicted: readonly string[];
}): Effect.Effect<ReplanResult, CliError> {
  return Effect.gen(function* () {
    const pulled = yield* pullVerifiedEnvironment({
      client: input.client,
      verified: input.view,
      environmentId: input.environmentId,
      resync: input.resync,
      floor: input.floor,
    });
    const view = pulled.verified;
    const environment = yield* requireChainEnvironment(view, input.environmentId);
    if (environment.currentEpoch !== input.epoch) {
      return yield* Effect.fail(
        cliError(
          `再暗号化の途中で環境 ${input.environmentId} のエポックが ${input.epoch} → ${environment.currentEpoch} へ進みました(他メンバーによる並行ローテーション)。再実行すると新しいエポックの再暗号化から再開します`,
        ),
      );
    }
    const warnings = [...pulled.warnings];
    const targets: ReencryptTarget[] = [];
    let alreadyCurrent = 0;
    for (const variableId of input.conflicted) {
      const latest = pulled.variables.find((value) => value.variableId === variableId);
      if (latest === undefined) {
        warnings.push(
          `変数 ${displayText(variableId)} は再取得時のアクティブ集合に存在しません(他メンバーによる並行削除)。再暗号化の対象から外します`,
        );
        continue;
      }
      if (latest.epoch >= input.epoch) {
        alreadyCurrent += 1;
        continue;
      }
      const plaintext = yield* decryptVerifiedValue({
        verified: view,
        environmentId: input.environmentId,
        variable: latest,
        deksByEpoch: input.deksByEpoch,
        chainEpoch: environment.currentEpoch,
      });
      targets.push({ value: latest, plaintext });
    }
    return { view, targets, alreadyCurrent, warnings };
  });
}

/**
 * 現在値の再暗号化(§7): 対象を新エポック DEK で暗号化して通常 push し、
 * VersionConflict は再取得・再検証で実態を確かめてから次巡へ回す(上限
 * {@link MAX_REENCRYPT_PASSES} 巡)。解けなかった分は remaining として
 * 呼び出し側が部分完了の警告に使う — 黙って完了扱いにしない。
 */
function reencryptCurrentValues(input: {
  readonly client: MaruhiClient;
  readonly environmentId: EnvironmentId;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
  readonly writerUserId: string;
  readonly signingKey: CryptoKey;
  readonly view: VerifiedProject;
  readonly epoch: number;
  readonly dek: Uint8Array;
  readonly deksByEpoch: ReadonlyMap<number, Uint8Array>;
  readonly targets: readonly ReencryptTarget[];
}): Effect.Effect<ReencryptOutcome, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const total = input.targets.length;
    const warnings: string[] = [];
    let view = input.view;
    let pending = input.targets;
    let reencrypted = 0;
    let alreadyCurrent = 0;

    for (let pass = 1; pass <= MAX_REENCRYPT_PASSES; pass += 1) {
      const conflicted: string[] = [];
      for (const target of pending) {
        const result = yield* pushReencrypted({
          client: input.client,
          environmentId: input.environmentId,
          view,
          floor: input.floor,
          target,
          epoch: input.epoch,
          dek: input.dek,
          writerUserId: input.writerUserId,
          signingKey: input.signingKey,
        });
        if (result === "conflict") {
          conflicted.push(target.value.variableId);
          continue;
        }
        reencrypted += 1;
        yield* io.log(
          `  再暗号化 (${reencrypted}/${total}): ${displayText(target.value.name)}(version=${target.value.version + 1})`,
        );
      }
      if (conflicted.length === 0) {
        return { reencrypted, alreadyCurrent, remaining: 0, warnings };
      }
      if (pass === MAX_REENCRYPT_PASSES) {
        return { reencrypted, alreadyCurrent, remaining: conflicted.length, warnings };
      }
      const replanned = yield* replanConflicted({
        client: input.client,
        environmentId: input.environmentId,
        view,
        resync: input.resync,
        floor: input.floor,
        epoch: input.epoch,
        deksByEpoch: input.deksByEpoch,
        conflicted,
      });
      view = replanned.view;
      pending = replanned.targets;
      alreadyCurrent += replanned.alreadyCurrent;
      warnings.push(...replanned.warnings);
      if (pending.length === 0) {
        return { reencrypted, alreadyCurrent, remaining: 0, warnings };
      }
    }
    return { reencrypted, alreadyCurrent, remaining: pending.length, warnings };
  });
}

/**
 * `maruhi env rotate`: rotates one environment's epoch — the §12-4 composite
 * (`rotate_epoch` entry with the new epoch's §5.2 DEK commitment plus the
 * complete new-epoch wrap set) followed by re-encrypting every active
 * variable's current value under the new DEK as ordinary pushes (§7 / §4.1).
 *
 * Re-running after an interruption resumes instead of rotating again: when a
 * verified pull shows latest values below the chain-derived current epoch,
 * the epoch is left alone and only the outstanding re-encryption is finished
 * (§12-7 の正当な過渡状態からの冪等な再開)。
 */
export function envRotateOp(input: RotateInput): Effect.Effect<RotationSummary, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const reason = yield* normalizeReason(input.reason);
    yield* ensureRotatable(input.verified, input.environmentId, input.signerUserId);

    // (1) 検証済み pull(§6.3 / §12-7): 全アクティブ変数の最新値 + 自分宛の
    // 全エポックのラップ。ローテーション後・再暗号化完了前は最新値のエポックが
    // 変数ごとに異なりうる(§12-7)— それが中断復旧の検出材料でもある
    const pulled = yield* pullVerifiedEnvironment({
      client: input.client,
      verified: input.verified,
      environmentId: input.environmentId,
      resync: input.resync,
      floor: input.floor,
    });
    const keys = yield* environmentKeysFor({
      client: input.client,
      verified: pulled.verified,
      environmentId: input.environmentId,
      recipient: input.recipient,
      prefetched: pulled.deks,
    });
    const warnings = [...pulled.warnings];
    const currentEpoch = keys.currentEpoch;
    const stale = pulled.variables.filter((value) => value.epoch < currentEpoch);

    if (stale.length > 0) {
      // --- 中断復旧: エポックは進んだが再暗号化が残っている ---
      const dek = keys.deksByEpoch.get(currentEpoch);
      if (dek === undefined) {
        return yield* Effect.fail(
          cliError(
            `現エポック ${currentEpoch} の DEK が自分宛に登録されていません(ローテーション実行者による再ラップ待ちの可能性)。再暗号化を再開できません`,
          ),
        );
      }
      yield* io.logError(
        `注意: 環境 ${input.environmentId} は epoch ${currentEpoch} へのローテーション後、${stale.length} 変数の再暗号化が未完了です。新しいエポックへは進めず、この再暗号化を再開します(--reason はチェーンに記録されません。新しいローテーションは完了後に再実行してください)`,
      );
      const targets = yield* decryptTargets({
        verified: pulled.verified,
        environmentId: input.environmentId,
        values: stale,
        deksByEpoch: keys.deksByEpoch,
        chainEpoch: currentEpoch,
      });
      const outcome = yield* reencryptCurrentValues({
        client: input.client,
        environmentId: input.environmentId,
        resync: input.resync,
        floor: input.floor,
        writerUserId: input.signerUserId,
        signingKey: input.signingKeyPair.privateKey,
        view: pulled.verified,
        epoch: currentEpoch,
        dek,
        deksByEpoch: keys.deksByEpoch,
        targets,
      });
      return {
        mode: "resumed",
        previousEpoch: currentEpoch,
        epoch: currentEpoch,
        memberCount: pulled.verified.state.members.size,
        reencrypted: outcome.reencrypted,
        alreadyCurrent: outcome.alreadyCurrent,
        remaining: outcome.remaining,
        warnings: [...warnings, ...outcome.warnings],
      };
    }

    // --- 通常のローテーション ---
    const newEpoch = currentEpoch + 1;
    const member = yield* ensureRotatable(pulled.verified, input.environmentId, input.signerUserId);
    // 再暗号化に要する平文は**エポックを進める前に**手元へ揃える: 復号できない
    // 値があるなら、エポックだけが進んで再暗号化が永久に完了しない状態を作らない
    const targets = yield* decryptTargets({
      verified: pulled.verified,
      environmentId: input.environmentId,
      values: pulled.variables,
      deksByEpoch: keys.deksByEpoch,
      chainEpoch: currentEpoch,
    });
    const dek = generateDek();
    const commitment = yield* Effect.tryPromise({
      try: () =>
        computeDekCommitment({
          context: {
            suite: SUITE_ID,
            projectId: pulled.verified.projectId,
            environmentId: input.environmentId,
            epoch: newEpoch,
          },
          dek,
        }),
      catch: () => cliError("DEK コミットメントの計算に失敗しました"),
    });
    if (!commitment.ok) {
      return yield* Effect.fail(cliError("DEK コミットメントの計算に失敗しました"));
    }
    yield* io.log(
      `環境 ${input.environmentId} をローテーションします(epoch ${currentEpoch} → ${newEpoch}、対象 ${targets.length} 変数)`,
    );
    const rotated = yield* appendRotation({
      ...input,
      baseline: pulled.verified,
      member,
      reason,
      newEpoch,
      dek,
      dekCommitmentHex: commitment.value,
    });
    yield* io.log(
      `rotate_epoch を受理しました(epoch=${newEpoch}、新 DEK を現メンバー ${rotated.memberCount} 名へラップ済み)`,
    );
    // 新エポックの DEK は生成元(自分)が保持している。チェーン導出コミットメントとの
    // 照合は appendRotation が済ませている(§5.2)
    const deksByEpoch = new Map<number, Uint8Array>(keys.deksByEpoch);
    deksByEpoch.set(newEpoch, dek);
    const outcome = yield* reencryptCurrentValues({
      client: input.client,
      environmentId: input.environmentId,
      resync: input.resync,
      floor: input.floor,
      writerUserId: input.signerUserId,
      signingKey: input.signingKeyPair.privateKey,
      view: rotated.view,
      epoch: newEpoch,
      dek,
      deksByEpoch,
      targets,
    });
    return {
      mode: "rotated",
      previousEpoch: currentEpoch,
      epoch: newEpoch,
      memberCount: rotated.memberCount,
      reencrypted: outcome.reencrypted,
      alreadyCurrent: outcome.alreadyCurrent,
      remaining: outcome.remaining,
      warnings: [...warnings, ...outcome.warnings],
    };
  });
}
