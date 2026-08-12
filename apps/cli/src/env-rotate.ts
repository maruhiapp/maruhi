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
import { encryptAndSignPayload, winnerRegression } from "./push.ts";
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
  /** 再暗号化を中断させた原因(null = 最後まで走った)。呼び出し側が警告に使う。 */
  readonly failure: string | null;
  readonly warnings: readonly string[];
}

interface RotateInput {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
  /** チェーンに記録される理由(§6.2 の payload フィールド)。 */
  readonly reason: string;
  /**
   * 未完了の再暗号化があっても再開で済ませず、必ず新しいエポックを作る
   * (`--new-epoch`)。「この実行の後に必ず新エポックが存在する」ことを要求
   * する呼び出し(退職者の削除に伴う全環境ローテーション — §7)のための保証。
   */
  readonly forceNewEpoch: boolean;
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
  /**
   * 再暗号化を中断させた原因(null = 最後まで走った)。エポックが進んだ後の
   * 失敗を例外として投げ捨てると、「エポックだけ進んで再暗号化が残っている」
   * 事実が呼び出し側の部分完了警告を素通りしてしまうため、結果として返す。
   */
  readonly failure: string | null;
}

/** 409 を返された 1 変数(勝者の検証に要する既知 latest と申告 version を保つ)。 */
interface ConflictedTarget {
  readonly variableId: string;
  /** 競合時に自分が prev の基準にしていた検証済み値。 */
  readonly known: VerifiedPulledValue;
  /** 409 が申告した最新 version(勝者の整合検査の入力 — 採否の根拠にはしない)。 */
  readonly currentVersion: number;
}

/**
 * 理由文字列の早期検証(長さのみ)。チェーンの自由文字列上限(§6.1)を超える
 * エントリは**無効**(合意規則)なので、サーバーの拒否を待たず手前で落とす。
 *
 * 「未指定」の判定はここでは行わない: 再開(新エントリを作らない)経路では
 * reason は記録されず必須でもないため、必須検査は実際にエントリを署名する
 * 直前(requireReason)に置く。壊れた状態からの復旧を、書き込まれない
 * フィールドの欠落で拒否しない。
 */
function checkReasonLength(reason: string): Effect.Effect<string, CliError> {
  const trimmed = reason.trim();
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

/** 新エポックを作る経路でのみ理由を必須にする(rotate_epoch payload の一部)。 */
function requireReason(reason: string): Effect.Effect<string, CliError> {
  if (reason.length === 0) {
    return Effect.fail(
      cliError(
        "--reason にローテーションの理由を指定してください(チェーンの rotate_epoch エントリに記録され、後から書き換えられません)",
      ),
    );
  }
  return Effect.succeed(reason);
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

/** 1 変数の再暗号化 push の結果(競合は 409 の申告 version を持ち帰る)。 */
type PushAttempt =
  | { readonly kind: "pushed" }
  | { readonly kind: "conflict"; readonly currentVersion: number };

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
}): Effect.Effect<PushAttempt, CliError> {
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
        Effect.map(() => ({ kind: "pushed" }) as const),
        Effect.catch((error): Effect.Effect<PushAttempt, CliError> => {
          if (error instanceof VersionConflictError) {
            // 並行 push の勝者がいる。409 の申告値では決めず、呼び出し側が
            // 再取得・再検証して実態(勝者が既に現エポックか)を確かめる
            return Effect.succeed({ kind: "conflict", currentVersion: error.currentVersion });
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
    if (outcome.kind === "conflict") {
      return outcome;
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
    return { kind: "pushed" };
  });
}

/** 再取得・再検証の結果(完了検証と 409 競合の再計画を兼ねる)。 */
interface RescanResult {
  readonly view: VerifiedProject;
  /** 目標エポック未満のまま残っている active 値(= 次巡の再暗号化対象)。 */
  readonly targets: readonly ReencryptTarget[];
  /** 競合していたが既に現エポックで書かれていた変数数(再暗号化不要)。 */
  readonly alreadyCurrent: number;
  readonly warnings: readonly string[];
  /**
   * 暗号学的証拠(巻き戻し・equivocation・分岐した prev 連鎖)。非 null は
   * 即時中断であり、「再実行で解消する」種類の失敗と混ぜてはならない。
   */
  readonly evidence: string | null;
}

/**
 * 環境の再取得・再検証(§6.3)。2 つの役割を 1 経路で担う:
 *
 * 1. **完了検証**: 目標エポック未満の active 値が残っていないことを確かめる。
 *    初回 pull から複合受理までの窓で他メンバーが作成した変数は最初の対象集合に
 *    入っておらず(受理後の作成は現エポックでしか受理されない — §12-5)、この
 *    再走査で初めて可視になる。これを省くと「エポックだけ進み、旧 DEK のままの
 *    値が残っているのに完了と報告する」形になる
 * 2. **409 競合の再計画**(§12-5 の再試行手順): 勝者を §6.3 で検証し、
 *    **勝者の整合検査(push.ts と共有の winnerRegression)**を採否の判断より
 *    前に適用する。再暗号化は勝者の signed bytes ハッシュへ prev を付け替えて
 *    署名するため、検査なしでは分岐した履歴へ自分の署名で連鎖してしまう
 *    (§12-5 の証拠連鎖の汚染)。ローカル床は巻き戻し・同一 version の相違を
 *    捕まえるが SHOULD であり(初回同期・破損時は不在)、隣接 prev の不一致は
 *    床に材料自体がない
 */
function rescanEnvironment(input: {
  readonly client: MaruhiClient;
  readonly environmentId: EnvironmentId;
  readonly view: VerifiedProject;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
  readonly epoch: number;
  readonly deksByEpoch: ReadonlyMap<number, Uint8Array>;
  readonly conflicted: readonly ConflictedTarget[];
}): Effect.Effect<RescanResult, CliError> {
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
          `再暗号化の途中で環境 ${input.environmentId} のエポックが ${input.epoch} → ${environment.currentEpoch} へ進みました(他メンバーによる並行ローテーション)`,
        ),
      );
    }
    const warnings = [...pulled.warnings];
    const rejected = (evidence: string): RescanResult => ({
      view,
      targets: [],
      alreadyCurrent: 0,
      warnings,
      evidence,
    });
    let alreadyCurrent = 0;
    for (const conflict of input.conflicted) {
      const latest = pulled.variables.find((value) => value.variableId === conflict.variableId);
      if (latest === undefined) {
        warnings.push(
          `変数 ${displayText(conflict.variableId)} は再取得時のアクティブ集合に存在しません(他メンバーによる並行削除)。再暗号化の対象から外します`,
        );
        continue;
      }
      // 整合検査は「採用するか」に関わらず先に行う: 巻き戻し・equivocation・
      // 分岐した prev 連鎖は、それ自体が中断すべき証拠である
      const regression = winnerRegression(
        conflict.variableId,
        conflict.known,
        latest,
        conflict.currentVersion,
      );
      if (regression !== null) {
        return rejected(regression);
      }
      if (latest.epoch >= input.epoch) {
        alreadyCurrent += 1;
      }
    }
    // 完了検証 + 次巡の対象: 目標エポック未満の active 値すべて(競合分に
    // 限らない — 窓の間に作られた変数もここに現れる)
    const targets = yield* decryptTargets({
      verified: view,
      environmentId: input.environmentId,
      values: pulled.variables.filter((value) => value.epoch < input.epoch),
      deksByEpoch: input.deksByEpoch,
      chainEpoch: environment.currentEpoch,
    });
    return { view, targets, alreadyCurrent, warnings, evidence: null };
  });
}

/**
 * 現在値の再暗号化(§7): 対象を目標エポックの DEK で暗号化して通常 push し、
 * **毎巡の末尾で環境を再走査して完了を検証する**(上限
 * {@link MAX_REENCRYPT_PASSES} 巡)。再走査は競合の実態確認(勝者が既に現
 * エポックなら再暗号化不要)と、初回 pull 以降に作られた変数の発見を兼ねる。
 * 「対象を全部 push し終えた」ことは完了の証拠にならない — 完了の証拠は
 * 「再取得・再検証したビューに目標エポック未満の active 値がない」ことである。
 *
 * 失敗は投げずに {@link ReencryptOutcome.failure} として返す: この関数が
 * 走る時点でエポックは既に進んでおり、途中の失敗(ネットワーク・並行
 * ローテーション・床書き込み)を例外として投げると「エポックだけ進んで
 * 再暗号化が残っている」事実が部分完了の報告経路を素通りしてしまう。
 * ただし**暗号学的証拠(RescanResult.evidence)は例外**で、これは即時中断
 * (エラー channel)とする — 「再実行すれば直る」種類の失敗ではないため、
 * 部分完了 + 再開案内に混ぜてはならない(push 経路の扱いと揃える)。
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
    const warnings: string[] = [];
    let view = input.view;
    let pending = input.targets;
    let reencrypted = 0;
    let alreadyCurrent = 0;

    const outcome = (remaining: number, failure: string | null): ReencryptOutcome => ({
      reencrypted,
      alreadyCurrent,
      remaining,
      warnings,
      failure,
    });

    for (let pass = 1; pass <= MAX_REENCRYPT_PASSES; pass += 1) {
      const conflicted: ConflictedTarget[] = [];
      // 進行表示の分母は「この巡で判明している総数」(再走査で対象が増えうる)
      const total = reencrypted + pending.length;
      let processed = 0;
      for (const target of pending) {
        const attempt = yield* pushReencrypted({
          client: input.client,
          environmentId: input.environmentId,
          view,
          floor: input.floor,
          target,
          epoch: input.epoch,
          dek: input.dek,
          writerUserId: input.writerUserId,
          signingKey: input.signingKey,
        }).pipe(
          Effect.map((value) => ({ kind: "ok", value }) as const),
          Effect.catch((error) => Effect.succeed({ kind: "failed", error } as const)),
        );
        processed += 1;
        if (attempt.kind === "failed") {
          // 未処理分(この変数を含む残り)+ 競合分が未完了として残る
          return outcome(pending.length - processed + 1 + conflicted.length, attempt.error.message);
        }
        if (attempt.value.kind === "conflict") {
          conflicted.push({
            variableId: target.value.variableId,
            known: target.value,
            currentVersion: attempt.value.currentVersion,
          });
          continue;
        }
        reencrypted += 1;
        yield* io.log(
          `  再暗号化 (${reencrypted}/${total}): ${displayText(target.value.name)}(version=${target.value.version + 1})`,
        );
      }
      // 完了検証(競合の有無に関わらず必ず行う)
      const rescan = yield* rescanEnvironment({
        client: input.client,
        environmentId: input.environmentId,
        view,
        resync: input.resync,
        floor: input.floor,
        epoch: input.epoch,
        deksByEpoch: input.deksByEpoch,
        conflicted,
      }).pipe(
        Effect.map((value) => ({ kind: "ok", value }) as const),
        Effect.catch((error) => Effect.succeed({ kind: "failed", error } as const)),
      );
      if (rescan.kind === "failed") {
        // 完了を**検証できなかった**(残数は下限しか分からない)
        return outcome(conflicted.length, rescan.error.message);
      }
      warnings.push(...rescan.value.warnings);
      if (rescan.value.evidence !== null) {
        // 暗号学的証拠は即時中断(再実行では解消しない)。エポックが進んでいる
        // 文脈も一緒に伝える — 証拠だけ出して運用状態を伝え損ねない
        return yield* Effect.fail(
          cliError(
            `${rescan.value.evidence}\n環境 ${input.environmentId} は epoch ${input.epoch} へ進んでおり、再暗号化は ${reencrypted} 変数で中断しました。これは再実行では解消しない証拠です — サーバーの応答を調査してください`,
          ),
        );
      }
      view = rescan.value.view;
      pending = rescan.value.targets;
      alreadyCurrent += rescan.value.alreadyCurrent;
      if (pending.length === 0) {
        // 再取得・再検証したビューに目標エポック未満の active 値がない = 完了
        return outcome(0, null);
      }
    }
    return outcome(pending.length, null);
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
    const reason = yield* checkReasonLength(input.reason);
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

    if (stale.length > 0 && !input.forceNewEpoch) {
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
        `注意: 環境 ${input.environmentId} は epoch ${currentEpoch} へのローテーション後、${stale.length} 変数の再暗号化が未完了です。新しいエポックへは進めず、この再暗号化を再開します(この経路はチェーンエントリを作らないため --reason は記録されません)。中断状態に関わらず新しいエポックを必ず作るには --new-epoch を付けてください`,
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
        failure: outcome.failure,
        warnings: [...warnings, ...outcome.warnings],
      };
    }

    // --- 通常のローテーション ---
    // 理由が必須になるのはここから(チェーンエントリを実際に署名する経路)
    const entryReason = yield* requireReason(reason);
    const newEpoch = currentEpoch + 1;
    const member = yield* ensureRotatable(pulled.verified, input.environmentId, input.signerUserId);
    // 再暗号化に要する平文は**エポックを進める前に**手元へ揃える: 復号できない
    // 値があるなら、エポックだけが進んで再暗号化が永久に完了しない状態を作らない。
    // 未完了の再暗号化(旧エポックの値)がある状態で --new-epoch が指定された
    // 場合も、対象は「全アクティブ変数」なので中間エポックを経由せず一気に
    // 新エポックへ揃う(全エポックの DEK は自分宛ラップから復号済み)
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
      reason: entryReason,
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
      failure: outcome.failure,
      warnings: [...warnings, ...outcome.warnings],
    };
  });
}
