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
  VariableNotFoundError,
  VersionConflictError,
  type WrappedDek,
} from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import type { ChainEntry, ChainMember, SigningKeyPair } from "@maruhi/crypto";
import { computeDekCommitment, generateDek, signChainEntry, SUITE_ID } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { buildWrapSetForMembers, requireWritingMember, sameMemberSet } from "./dek-wrap.ts";
import { type DekRecipient, environmentKeysFor, requireChainEnvironment } from "./deks.ts";
import { displayText, logWarnings } from "./display.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { isServerRejection, toCliError } from "./failure.ts";
import type { FloorHandle } from "./floor-check.ts";
import { CliIo } from "./io.ts";
import { decryptVerifiedValue, missingWrapReason } from "./pull.ts";
import { encryptAndSignPayload, winnerInconsistency } from "./push.ts";
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
  /**
   * rotated = 新エポックを開始した / resumed = 未完了の再暗号化を再開した /
   * up-to-date = 未完了がなく、新しいエポックも要求されなかった(確認のみ)。
   */
  readonly mode: "rotated" | "resumed" | "up-to-date";
  readonly previousEpoch: number;
  readonly epoch: number;
  /** 再暗号化して push した変数数。 */
  readonly reencrypted: number;
  /** 並行 push により既に現エポックで書かれていた変数数(再暗号化不要)。 */
  readonly alreadyCurrent: number;
  /** 競合が解けず未完了のまま残った変数数(> 0 なら部分完了)。 */
  readonly remaining: number;
  /**
   * `remaining` が再走査を通った実測か(false = 中断により上限しか分からない)。
   * 表示で「未確認を含む」と断らねばならないのはこちらだけである。
   */
  readonly remainingExact: boolean;
  /** 再暗号化を中断させた原因(null = 最後まで走った)。呼び出し側が警告に使う。 */
  readonly failure: string | null;
  readonly warnings: readonly string[];
}

interface RotateInput {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
  /**
   * チェーンに記録される理由(§6.2 の payload フィールド)。`undefined` は
   * **`--reason` 自体が未指定**であることを表す(空文字列との区別が要る —
   * checkReasonLength)。
   */
  readonly reason: string | undefined;
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
  /**
   * `remaining` が再走査を通った**実測**か(false = 再走査に到達できず、
   * 「今巡で完了しなかった数」という上限しか分かっていない)。
   */
  readonly remainingExact: boolean;
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
 * 理由文字列の早期検証。返り値の `null` は「`--reason` そのものが未指定」で、
 * 空文字列は返さない — **指定されたが空**(`--reason "$UNSET_VAR"` など)は
 * ここで落とす。両者を `""` に潰すと、ローテーションを要求した実行が
 * 「理由なしの確認だけ」の経路へ滑り込み、何も要求を送らないまま成功終了する
 * (退職者削除のスクリプトが、進んでいないエポックを進んだと受け取る)。
 *
 * 長さ上限はチェーンの自由文字列上限(§6.1)。超えるエントリは**無効**
 * (合意規則)なので、サーバーの拒否を待たず手前で落とす。
 *
 * 「必須」判定はここでは行わない: 再開(新エントリを作らない)経路では reason は
 * 記録されず必須でもないため、必須検査は実際にエントリを署名する直前
 * (requireReason)に置く。壊れた状態からの復旧を、書き込まれないフィールドの
 * 欠落で拒否しない。
 */
function checkReasonLength(reason: string | undefined): Effect.Effect<string | null, CliError> {
  if (reason === undefined) {
    return Effect.succeed(null);
  }
  // 書き方の誤りは usage エラー(2)。値そのものが空の形は共通の引数検査が
  // 先に落とすので、ここへ来るのは空白だけ / 長すぎるの 2 つ
  const trimmed = reason.trim();
  if (trimmed.length === 0) {
    return Effect.fail(
      usageError(
        "--reason が空です。ローテーションの理由を指定してください(値が空になる変数展開の可能性があります)。理由を書かずに未完了の再暗号化だけを再開する場合は --reason を付けずに実行してください",
      ),
    );
  }
  const bytes = new TextEncoder().encode(trimmed).length;
  if (bytes > MAX_REASON_BYTES) {
    return Effect.fail(
      usageError(
        `--reason が長すぎます(${bytes} バイト)。チェーンエントリの自由文字列上限は UTF-8 で ${MAX_REASON_BYTES} バイトです(CRYPTO_SPEC §6.1)`,
      ),
    );
  }
  return Effect.succeed(trimmed);
}

/**
 * 警告の重複排除。初回 pull と毎巡の再走査は同じ pull 全体の SHOULD 警告
 * (非 NFC 名など)を返すため、そのまま並べると同じ行が 4 回出て、実行固有の
 * 警告(並行削除・床の欠落)が埋もれる。
 */
function dedupeWarnings(warnings: readonly string[]): readonly string[] {
  return [...new Set(warnings)];
}

/** 新エポックを作る経路でのみ理由を必須にする(rotate_epoch payload の一部)。 */
function requireReason(reason: string | null): Effect.Effect<string, CliError> {
  if (reason === null) {
    return Effect.fail(
      usageError(
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
    // grant ガード + メンバー性 + role(member 以上)は env create と共有
    // (§7: grant_server が有効なら新エポック DEK をサーバー鍵へも再ラップしなければ
    // リース経路が停止する。メンバー宛だけの完全集合で黙って進めない)
    const member = yield* requireWritingMember({
      verified,
      environmentId,
      signerUserId,
      operation: "ローテーション",
      forbidden:
        "reader はエポックをローテーションできません(rotate_epoch と値の push は member 以上 — CRYPTO_SPEC §6.2)",
    });
    yield* requireChainEnvironment(verified, environmentId);
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

/**
 * 複合の送信が CAS 以外の理由で失敗したときの報告文。**「届かなかった」とは
 * 限らない**(応答の消失・502 / 504)ので、チェーンを見て実際に受理されたかを
 * 確かめてから言う。素の転送エラーだけを出すと、「エポックだけ進んで再暗号化は
 * 0 件」という最も危険な状態を「何も起きなかった」と読ませてしまう。
 */
function describeSendFailure(input: {
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly baseline: VerifiedProject;
  readonly environmentId: string;
  readonly newEpoch: number;
  /** 自分が生成した DEK のコミットメント(受理されたのが**自分の**分かの判定)。 */
  readonly dekCommitmentHex: string;
  readonly cause: string;
}): Effect.Effect<CliError, never> {
  return Effect.gen(function* () {
    const probe = yield* asOutcome(
      Effect.gen(function* () {
        const view = yield* resyncExtended(input.resync, input.baseline);
        return yield* requireChainEnvironment(view, input.environmentId);
      }),
    );
    if (probe.kind === "failed") {
      return cliError(
        `${input.cause}。この失敗は「リクエストが届かなかった」ことを意味しません(応答の消失もありえます)。受理されたかどうかをチェーンで確認しようとしましたが、それも失敗しました(${probe.error.message})— **環境 ${input.environmentId} のエポックが既に ${input.newEpoch} へ進んでいる可能性があります**。通信を復旧したうえで maruhi env rotate ${input.environmentId} を再実行してください(進んでいれば再暗号化から再開し、進んでいなければローテーションからやり直します)`,
      );
    }
    // 判定は**コミットメントの一致**で行い、現エポックの値では見ない。
    // dekCommitments は全エポック分を持つので、受理後にさらに他メンバーが
    // ローテーションして現エポックが目標を追い越していても、自分の分が載って
    // いれば受理済みと分かる — 現エポックの一致を条件にすると、その場合に
    // 「受理されていません」と報告してしまう(エポックは進み、再暗号化は 0 件)
    if (probe.value.dekCommitments.get(input.newEpoch) === input.dekCommitmentHex) {
      return cliError(
        `${input.cause}。ただしチェーンを確認したところ、**このローテーション自体は受理されています**(環境 ${input.environmentId} の epoch ${input.newEpoch} は自分が生成した DEK のものです)。現在値の再暗号化は 1 件も実行されていないため、旧エポックの DEK 保持者は現在値を読めるままです — maruhi env rotate ${input.environmentId} を再実行すると、エポックを進めずに再暗号化から再開します`,
      );
    }
    if (probe.value.currentEpoch >= input.newEpoch) {
      return cliError(
        `${input.cause}。チェーン上の epoch ${input.newEpoch} は**他メンバーのローテーション**であり、この実行の分は受理されていません(生成した DEK は使用しません)— maruhi env rotate ${input.environmentId} を再実行してください(未完了の再暗号化があれば、エポックを進めずに再開します)`,
      );
    }
    return cliError(
      `${input.cause}。チェーンを確認したところ受理されていません(環境 ${input.environmentId} は epoch ${probe.value.currentEpoch} のまま)。そのまま再実行できます`,
    );
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
): Effect.Effect<
  {
    readonly view: VerifiedProject;
    readonly memberCount: number;
    /**
     * **受理に使った**自分のメンバー行。CAS リトライで再同期した場合、呼び出し
     * 側が最初に持っていた行とは鍵フィンガープリントが違いうる — 以後の書き込みの
     * 帰属(台帳の writer)はこちらを使う。
     */
    readonly member: ChainMember;
  },
  CliError
> {
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

    // 送信が「届いたかどうか不明」か(= 受理確認のプローブが要るか)。**送信を
    // 試みたときだけ**立てる: 署名の失敗など送信前の失敗にプローブを走らせると、
    // ローカルな失敗に「届いているかもしれません」と付けてチェーンを取り直す。
    // 送信した場合は「サーバー自身のエラー本文で拒否された」ときだけ確定側へ倒す
    // (CAS 競合も確定側 — 受理されていないことが分かっているので、その後の
    // recover の中断(並行ローテーション検出)にもプローブは要らない)
    let ambiguousSend = false;
    const attempted = yield* asOutcome(
      retryOnConflict<RotateState, AcceptedRotation, "head-conflict">(
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
                .pipe(
                  Effect.mapError((error) => {
                    ambiguousSend = !isServerRejection(error);
                    return mapRotateFailure(input.environmentId)(error);
                  }),
                );
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
      ),
    );
    if (attempted.kind === "failed") {
      // 確定した拒否(サーバー自身のエラー本文)や、recover が下した中断
      // (並行ローテーション検出 — 既に再同期してチェーンを見ている)は、
      // 受理の有無が分かっているので追加のプローブも案内も要らない。
      // 「そのまま再実行できます」を §7 の中断メッセージへ足さないための分岐でもある
      if (!ambiguousSend) {
        return yield* Effect.fail(attempted.error);
      }
      // 送信の失敗を「何も起きなかった」と読ませない(describeSendFailure)
      return yield* Effect.fail(
        yield* describeSendFailure({
          resync: input.resync,
          baseline: input.baseline,
          environmentId: input.environmentId,
          newEpoch: input.newEpoch,
          dekCommitmentHex: input.dekCommitmentHex,
          cause: attempted.error.message,
        }),
      );
    }
    const accepted = attempted.value;

    // 受理後の確認はサーバー申告(応答の currentEpoch)ではなくチェーン再検証で
    // 行う。ここから先の失敗は**エポックが既に進んだ後**の失敗なので、原因だけ
    // 出して「エポックが動いた・再暗号化は未実行」という運用状態を伝え損ねない
    // (再同期のネットワーク障害が素の転送エラーとして出る形を塞ぐ)
    const confirmed = yield* Effect.gen(function* () {
      const view = yield* resyncExtended(input.resync, accepted.state.verified);
      const environment = yield* requireChainEnvironment(view, input.environmentId);
      if (environment.currentEpoch !== input.newEpoch) {
        return yield* Effect.fail(
          cliError(
            `再同期したチェーンの現エポックが ${environment.currentEpoch} です(受理直後の並行ローテーションの可能性)`,
          ),
        );
      }
      if (environment.dekCommitments.get(input.newEpoch) !== input.dekCommitmentHex) {
        // §5.2: コミットメント照合に成功するまで DEK をいかなる暗号操作にも使わない。
        // 自分で生成した DEK にも同じ規律を適用する(受理されたエントリが自分の
        // ものであることの確認 = 再暗号化を他人の DEK 前提で始めない)
        return yield* Effect.fail(
          cliError(
            `受理された epoch=${input.newEpoch} のコミットメントが、生成した DEK のものと一致しません(CRYPTO_SPEC §5.2)。この DEK は使用しません`,
          ),
        );
      }
      return view;
    }).pipe(
      Effect.mapError((error) =>
        cliError(
          `ローテーション(epoch=${input.newEpoch})は受理されましたが、受理後の確認に失敗しました: ${error.message}。環境 ${input.environmentId} のエポックは進んでおり、現在値の再暗号化は 1 件も実行されていません — 原因を解消して再実行すると、エポックを進めずに再暗号化から再開します`,
        ),
      ),
    );
    return {
      view: confirmed,
      memberCount: accepted.state.deks.length,
      member: accepted.state.member,
    };
  });
}

/**
 * 再暗号化材料の準備(復号 + 開けなかった値の警告)。
 *
 * 「開けない」= **自分宛に当該エポックのラップが無い**場合だけである
 * (それ以外の復号失敗は decryptTargets が即時中断する)。これは別メンバーなら
 * 開ける良性の欠落なので、1 件のために全体を止めない — 失効操作で守れる範囲まで
 * 自ら捨てることになるためで、開けなかった分は部分完了として報告する。
 *
 * この状況が起こりうるのは §12-7 の過渡状態(旧エポックの値が残っている)だけで、
 * 通常のローテーション経路(旧エポックの値が無い = 全値が現エポック)では
 * 現エポックの DEK を必ず持っているため発生しない。
 */
function decryptForRotation(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly values: readonly VerifiedPulledValue[];
  readonly deksByEpoch: ReadonlyMap<number, Uint8Array>;
  readonly chainEpoch: number;
  readonly warnings: string[];
}): Effect.Effect<readonly ReencryptTarget[], CliError> {
  return Effect.gen(function* () {
    const decrypted = yield* decryptTargets(input);
    for (const reason of decrypted.undecryptable) {
      input.warnings.push(undecryptableWarning(reason));
    }
    return decrypted.targets;
  });
}

/**
 * 1 つも再暗号化できないならエポックを進めない。進めても全ての現在値が旧エポックの
 * DEK のまま取り残されるだけで、**失効にならない**(自分宛ラップが 1 つも無い
 * メンバー / 全ラップを落とす応答で、エポックだけが空回りする)。--new-epoch も
 * 助けにならない — 開ける値が無い以上、再暗号化する材料が無い。
 */
function ensureRotationIsUseful(targets: number, variables: number): Effect.Effect<void, CliError> {
  if (targets > 0 || variables === 0) {
    return Effect.void;
  }
  return Effect.fail(
    cliError(
      `${nothingDecryptable(variables)}。この状態でエポックを進めても現在値は旧エポックの DEK のまま取り残され、失効になりません — 当該エポックのラップを持つメンバーが実行してください`,
    ),
  );
}

/**
 * 「1 つも開けない」ことの文面。**1 箇所に固定する**(通常経路の中断と再開経路の
 * 早期切り上げが同じ事実を言うため — 割れると dedupeWarnings が同じ状況について
 * 似て非なる 2 行を通す)。
 */
function nothingDecryptable(variables: number): string {
  return `再暗号化できる値が 1 つもありません(${variables} 変数すべてについて自分宛のラップが不足しています)`;
}

/** タグ付き失敗からメッセージだけを取り出す(null 伝播)。 */
function failureMessage(
  failure: { readonly variableId: string; readonly message: string } | null,
): string | null {
  return failure === null ? null : failure.message;
}

/**
 * 巡末の実態で裏を取った push 失敗だけを原因候補にする。並行削除(404)のように
 * **その変数自体が解決している**失敗を原因として掲げると、実際に未完了で残って
 * いる別の変数(競合など)の本当の原因を隠してしまう。
 */
function pendingFailure(
  failure: { readonly variableId: string; readonly message: string } | null,
  staleIds: ReadonlySet<string>,
): string | null {
  if (failure === null) {
    return null;
  }
  return staleIds.has(failure.variableId) ? failure.message : null;
}

/**
 * 未完了の原因の優先順: push の失敗 > 開けない値 > 競合(既定文言 = null)。
 * 開けない値を競合に潰すと、存在しない並行 writer を追わせることになる —
 * 実際に要るのは「当該エポックのラップを持つ別メンバーによる再実行」である。
 */
function blockingCause(
  pushFailure: string | null,
  undecryptable: readonly string[],
): string | null {
  return pushFailure ?? undecryptable[0] ?? null;
}

/**
 * 未完了で終わった実行の締め。原因(blockingFailure)がある場合はそれが報告され
 * るので何もせず、無い場合だけ「起きたがもう原因ではない失敗」を警告に残す。
 */
function noteStaleFailures(
  warnings: string[],
  blockingFailure: string | null,
  seenFailure: string | null,
): void {
  if (blockingFailure !== null) {
    return;
  }
  // 最終巡に失敗がない = 残っているのは競合分。過去の失敗は原因ではない
  noteResolvedFailure(
    warnings,
    seenFailure,
    "その後の巡で解消しています(未完了として残っているのは競合分です)",
  );
}

/**
 * 未完了が残っているのに押せる対象が 1 つも無い状態か(= 復号できない値だけが
 * 残っている)。残りの巡を回しても pull を繰り返すだけで前進しない。
 * 最終巡の targets は「復号しない」ので常に空 — 判定するのは復号を試みた巡だけ。
 */
function stalledOnUndecryptable(pending: readonly ReencryptTarget[], pass: number): boolean {
  return pending.length === 0 && pass < MAX_REENCRYPT_PASSES;
}

/**
 * 復号できなかった値の警告文。**1 箇所に固定する**: 同じ変数が経路ごとに
 * 少しずつ違う文面で警告されると、dedupeWarnings(集合)は別物として通してしまい、
 * 重複排除のために入れた仕組みがそのまま重複を出すことになる。
 */
function undecryptableWarning(reason: string): string {
  return `再暗号化できない値が残っています(${reason})。この変数は旧エポックの DEK のままです — 当該エポックのラップを持つメンバーによる再実行が必要です`;
}

/** 復号の結果。開けなかった値は「再暗号化できない値」として数と理由を持ち帰る。 */
interface DecryptOutcome {
  readonly targets: readonly ReencryptTarget[];
  /**
   * **自分宛に当該エポックのラップが無い**ために開けなかった値の理由。
   * これは良性の欠落(別メンバーなら開ける)なので、1 件で全体を落とさない —
   * ローテーションは失効操作であり、開けない値が 1 つあるからといって開ける
   * 99 件を旧 DEK のまま残すのは、守れる範囲を自ら捨てることになる。
   *
   * **ラップを持っているのに開けない場合はここに入らない**(暗号文の差し替え・
   * 検証済みビューとの不整合の可能性であり、pull / run と同じく即時中断する)。
   */
  readonly undecryptable: readonly string[];
}

/** 検証済み最新値の復号(再暗号化の材料づくり)。復号規律は pull と共有する。 */
function decryptTargets(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly values: readonly VerifiedPulledValue[];
  readonly deksByEpoch: ReadonlyMap<number, Uint8Array>;
  readonly chainEpoch: number;
}): Effect.Effect<DecryptOutcome, CliError> {
  return Effect.gen(function* () {
    const targets: ReencryptTarget[] = [];
    const undecryptable: string[] = [];
    for (const value of input.values) {
      // 良性の欠落(自分宛ラップが無い)だけを「開けない値」として飛ばす。
      // ラップを持っているのに復号が失敗するのは、AEAD 認証の失敗(暗号文の
      // 差し替え)か検証済みビューとの不整合であり、pull / run と同じく
      // 即時中断する — これを「別メンバーの再実行待ち」に潰すと、差し替えの
      // 兆候を良性の運用待ちとして報告し、--new-epoch で踏み越えるよう案内する
      // ことになる
      //
      // 「良性」と見なすのは**チェーン導出の現エポック以下**の欠落だけである:
      // 現エポックを超える申告エポックの値は、手元に当該エポックのラップが無いのが
      // 当然(deks.ts が上限超過のラップを拒否する)なので、この検査を素通りさせると
      // 検証済みビューとの不整合が「別メンバー待ち」に化ける。上限超過は
      // decryptVerifiedValue が pull / run と同じ文言で即時中断する
      // (§6.3-4 の epoch-not-current-at-head が本線で、これは導出不整合への防衛線)
      if (value.epoch <= input.chainEpoch && !input.deksByEpoch.has(value.epoch)) {
        undecryptable.push(missingWrapReason(value));
        continue;
      }
      const plaintext = yield* decryptVerifiedValue({
        verified: input.verified,
        environmentId: input.environmentId,
        variable: value,
        deksByEpoch: input.deksByEpoch,
        chainEpoch: input.chainEpoch,
      });
      targets.push({ value, plaintext });
    }
    return { targets, undecryptable };
  });
}

/** 1 変数の再暗号化 push の結果(競合は 409 の申告 version を持ち帰る)。 */
type PushAttempt =
  /**
   * 受理済み。床の更新に失敗した場合のみ警告を伴う(受理自体は取り消せない)。
   * `written` は**受理された自分の書き込み**であり、以後の再走査における
   * 整合検査の基準になる(床は SHOULD で、書き込み失敗もありうるため、
   * 自分の書き込みの巻き戻しを床だけに頼らない)。
   */
  | {
      readonly kind: "pushed";
      readonly floorWarning: string | null;
      readonly written: VerifiedPulledValue;
    }
  | { readonly kind: "conflict"; readonly currentVersion: number }
  /** 並行削除(404)。削除済み変数に再暗号化すべき現在値は存在しない。 */
  | { readonly kind: "deleted" }
  /**
   * サーバーがエポック競合を申告した(409 EpochConflict)。原因の断定はここで
   * せず、再走査(チェーン再検証)に委ねる — 「他メンバーが並行ローテーション
   * した」のか「サーバーの申告がチェーンと矛盾している」のかは、チェーン導出の
   * 現エポックを見るまで区別できない(push.ts の epoch-conflict と同じ規律)。
   */
  | { readonly kind: "epoch-stale" };

/**
 * 再暗号化 1 変数分の push(§7 / §4.1 — 再暗号化は「実行者が writer として
 * 署名する通常 push」であり、専用のワイヤも認可も持たない)。
 */
function pushReencrypted(input: {
  readonly context: ReencryptContext;
  readonly view: VerifiedProject;
  readonly target: ReencryptTarget;
}): Effect.Effect<PushAttempt, CliError> {
  return Effect.gen(function* () {
    const { environmentId, epoch, dek, writerUserId, signingKey, floor, client } = input.context;
    const latest = input.target.value;
    const version = latest.version + 1;
    // prev は検証済み最新値の**自計算**ハッシュ(サーバー申告のハッシュへ
    // 連鎖署名しない — §12-5 の証拠連鎖の汚染回避)
    const signed = yield* encryptAndSignPayload({
      verified: input.view,
      environmentId: environmentId,
      variableId: latest.variableId,
      epoch: epoch,
      version,
      prevValueSigHashHex: latest.signedBytesHashHex,
      dek: dek,
      value: input.target.plaintext,
      writerUserId: writerUserId,
      signingKey: signingKey,
    });
    const outcome = yield* client.variables
      .push({
        params: {
          projectId: input.view.projectId,
          environmentId: environmentId,
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
          if (error instanceof VariableNotFoundError) {
            // 並行削除。削除は tombstone + 全バージョン削除(§12-5)であり、
            // 再暗号化すべき現在値は存在しない — 再走査側の同じレースの扱い
            // (警告して対象から外す)と揃え、残りの変数の処理を止めない
            return Effect.succeed({ kind: "deleted" });
          }
          if (error instanceof EpochConflictError) {
            // 申告を真実源にしない: チェーン再検証は再走査が行う
            return Effect.succeed({ kind: "epoch-stale" });
          }
          return Effect.fail(toCliError(error));
        }),
      );
    if (outcome.kind !== "pushed") {
      return outcome;
    }
    // 受理された自分の書き込みを床へ昇格する(§6.3)。メタは変更していないので
    // 床のメタ記録は検証済み latest のまま。規則 (c) の基準は動かさない。
    //
    // 床の書き込み失敗で「受理済みの再暗号化」を未完了扱いにしない: 受理は
    // 取り消せず、この変数は既に新エポックにある。失う(SHOULD の)検出材料を
    // 警告として伝え、残りの変数の処理は止めない
    const floorWarning = yield* floor
      .commitPush(
        latest.variableId,
        {
          status: "active",
          version,
          epoch: epoch,
          valueSigHashHex: signed.signedBytesHashHex,
          metaVersion: latest.metaVersion,
          metaSigHashHex: latest.metaSignedBytesHashHex,
        },
        { seq: input.view.state.headSeq, hashHex: input.view.state.headHashHex },
      )
      .pipe(
        Effect.as(null),
        Effect.catch((error) =>
          Effect.succeed(
            `変数 ${displayText(latest.name)} の再暗号化は受理されましたが、${error.message}(この変数の巻き戻し検出の材料が一部欠けます)`,
          ),
        ),
      );
    // 受理された自分の書き込み(署名対象そのものから組む — サーバー echo でない)
    const written: VerifiedPulledValue = {
      ...latest,
      version,
      epoch,
      nonceHex: signed.payload.nonceHex,
      ciphertextHex: signed.payload.ciphertextHex,
      prevValueSigHashHex: latest.signedBytesHashHex,
      signedBytesHashHex: signed.signedBytesHashHex,
      valueChainHeadSeq: input.view.state.headSeq,
      valueChainHeadHashHex: input.view.state.headHashHex,
      valueSignatureHex: signed.payload.signatureHex,
      writerUserId,
      writerKeyFingerprintHex: input.context.writerKeyFingerprintHex,
    };
    return { kind: "pushed", floorWarning, written };
  });
}

/**
 * 既知値と再取得値の突き合わせ。この実行で §6.3 検証を通した値(次巡の prev
 * アンカーの基準)に対して、巻き戻し・equivocation・分岐した prev 連鎖・409
 * 申告との食い違いを検査し(push 経路と同一の winnerInconsistency)、未完了の
 * まま消えた変数を並行削除として警告する。
 *
 * 整合検査は「その値を採用するか」に関わらず先に行う: 証拠はそれ自体が中断
 * すべき事実であり、「再暗号化不要」の近道に隠れてはならない。
 */
function reconcileKnown(input: {
  readonly known: ReadonlyMap<string, ConflictedTarget>;
  /**
   * 今巡で再暗号化を完了できなかった変数(409・一時失敗・404・エポック競合)。
   * 消失の警告と「他メンバーが既に現エポックで書いていた」の計上は、409 に
   * 限らずこの集合を基準にする — でないと 502 で落ちた変数が再暗号化・
   * 再暗号化不要・未完了のどれにも数えられず、合計が合わなくなる。
   */
  readonly unfinishedIds: ReadonlySet<string>;
  readonly latest: readonly VerifiedPulledValue[];
  readonly epoch: number;
  readonly collectWarning: (warning: string) => void;
}): { readonly evidence: string | null; readonly alreadyCurrent: number } {
  const latestById = new Map(input.latest.map((value) => [value.variableId, value]));
  let alreadyCurrent = 0;
  for (const [variableId, previous] of input.known) {
    const latest = latestById.get(variableId);
    if (latest === undefined) {
      if (input.unfinishedIds.has(variableId)) {
        // 未完了のまま消えた = 並行削除。黙って対象から外さない
        input.collectWarning(
          `変数 ${displayText(previous.known.name)} は再取得時のアクティブ集合に存在しません(他メンバーによる並行削除)。再暗号化の対象から外します`,
        );
      }
      continue;
    }
    const inconsistency = winnerInconsistency(
      variableId,
      previous.known,
      latest,
      previous.currentVersion,
    );
    if (inconsistency !== null) {
      return { evidence: inconsistency, alreadyCurrent: 0 };
    }
    if (input.unfinishedIds.has(variableId) && latest.epoch >= input.epoch) {
      alreadyCurrent += 1;
    }
  }
  return { evidence: null, alreadyCurrent };
}

/** 再取得・再検証の結果(完了検証と 409 競合の再計画を兼ねる)。 */
interface RescanResult {
  readonly view: VerifiedProject;
  /**
   * 目標エポック未満のまま残っている active 値。**完了判定と残数はこちらが正**
   * (targets は最終巡で空になるため)。
   */
  readonly stale: readonly VerifiedPulledValue[];
  /**
   * stale を復号した再暗号化材料(= 次巡の対象)。**最終巡では空**: 次巡が
   * 無いのに復号すると、押すことのない平文を変数の数だけメモリへ作ることになる。
   */
  readonly targets: readonly ReencryptTarget[];
  /**
   * 開けなかった値の理由。最終巡(復号しない)でも自分宛ラップの有無だけは
   * 判定するので、「開けない値だけが残った」ことは常に原因として報告できる。
   */
  readonly undecryptable: readonly string[];
  /** 競合していたが既に現エポックで書かれていた変数数(再暗号化不要)。 */
  readonly alreadyCurrent: number;
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
  readonly context: ReencryptContext;
  readonly view: VerifiedProject;
  /**
   * この実行で一度でも §6.3 検証を通した値(variableId → 既知値 + 409 申告
   * version)。**409 を返した変数に限らない**: 一時的な失敗で再走査から拾い
   * 直した変数も次巡の prev アンカーになるため、同じ整合検査を通す。
   */
  readonly known: ReadonlyMap<string, ConflictedTarget>;
  /**
   * 今巡で再暗号化を**完了できなかった**変数(409・一時失敗・404・エポック競合)。
   * これらがアクティブ集合から消えていれば並行削除として警告する — 完了扱いに
   * するのは「消えたことを見た」場合だけであり、黙って落とさない。
   */
  readonly unfinishedIds: ReadonlySet<string>;
  /**
   * 警告の受け皿。失敗しても収集済みの警告(非 NFC 名・並行削除)を失わないよう、
   * 戻り値ではなくここへ流す(エラー channel は警告を運べない)。
   */
  readonly collectWarning: (warning: string) => void;
  /**
   * チェーンの強制再同期。サーバーがエポック競合を申告した巡では、pull の
   * future head 条件に依存せず**必ず**チェーンを取り直して現エポックを
   * 導出し直す(取り直さないと、他メンバーの並行ローテーションを
   * 「サーバーの矛盾」と誤認する — push.ts の epoch-conflict と同じ規律)。
   */
  readonly forceResync: boolean;
  /**
   * 残った対象を復号するか。次巡がある場合だけ true — 最終巡は残数を数えるだけ
   * なので、押すことのない平文を作らない(復号は「使う直前」に限る)。
   */
  readonly decryptRemaining: boolean;
}): Effect.Effect<RescanResult, CliError> {
  return Effect.gen(function* () {
    const { client, environmentId, resync, floor, epoch, deksByEpoch } = input.context;
    const base = input.forceResync ? yield* resyncExtended(resync, input.view) : input.view;
    const pulled = yield* pullVerifiedEnvironment({
      client,
      verified: base,
      environmentId,
      resync,
      floor,
    });
    const view = pulled.verified;
    // 警告は**どの判定より前に**流す: 並行ローテーションで中断する巡でも、
    // この pull が集めた SHOULD 警告は失われてはならない(sink の規律)
    for (const warning of pulled.warnings) {
      input.collectWarning(warning);
    }
    const environment = yield* requireChainEnvironment(view, environmentId);
    if (environment.currentEpoch !== epoch) {
      return yield* Effect.fail(
        cliError(
          `再暗号化の途中で環境 ${environmentId} のエポックが ${epoch} → ${environment.currentEpoch} へ進みました(他メンバーによる並行ローテーション)`,
        ),
      );
    }
    const reconciled = reconcileKnown({
      known: input.known,
      unfinishedIds: input.unfinishedIds,
      latest: pulled.variables,
      epoch,
      collectWarning: input.collectWarning,
    });
    if (reconciled.evidence !== null) {
      return {
        view,
        stale: [],
        targets: [],
        undecryptable: [],
        alreadyCurrent: 0,
        evidence: reconciled.evidence,
      };
    }
    // 完了検証 + 次巡の対象: 目標エポック未満の active 値すべて(競合分に
    // 限らない — 窓の間に作られた変数もここに現れる)
    const stale = pulled.variables.filter((value) => value.epoch < epoch);
    if (!input.decryptRemaining) {
      // 復号はしないが「開けるのか」は判定する: 自分宛ラップの有無は Map の
      // 参照だけで分かり、平文を作らずに済む。これを飛ばすと、最終巡で初めて
      // 判明する「開けない値だけが残った」状態の原因が既定文言(競合)に化ける
      const missing = stale.filter((value) => !deksByEpoch.has(value.epoch)).map(missingWrapReason);
      // 復号を試みる巡と同じく、変数ごとの警告も出す(原因としての報告だけだと、
      // push の失敗が優先された巡でどの変数が取り残されたのか伝わらない)
      for (const reason of missing) {
        input.collectWarning(undecryptableWarning(reason));
      }
      return {
        view,
        stale,
        targets: [],
        undecryptable: missing,
        alreadyCurrent: reconciled.alreadyCurrent,
        evidence: null,
      };
    }
    // 自分宛ラップの欠落(良性)では再走査自体を失敗させない: 完了判定は復号前の
    // stale が決めており、ここで落とすと**押せた分まで**「完了を検証できません
    // でした」に化ける。一方、ラップを持っているのに開けない場合(差し替え・
    // ビュー不整合)は**証拠**として扱う — 初回 pull では即時中断する条件なので、
    // 巡の途中で現れたときだけ「再実行で直る部分完了」へ格下げしてはならない
    const attempted = yield* asOutcome(
      decryptTargets({
        verified: view,
        environmentId,
        values: stale,
        deksByEpoch,
        chainEpoch: environment.currentEpoch,
      }),
    );
    if (attempted.kind === "failed") {
      return {
        view,
        stale,
        targets: [],
        undecryptable: [],
        alreadyCurrent: 0,
        evidence: attempted.error.message,
      };
    }
    const decrypted = attempted.value;
    for (const reason of decrypted.undecryptable) {
      input.collectWarning(undecryptableWarning(reason));
    }
    return {
      view,
      stale,
      targets: decrypted.targets,
      undecryptable: decrypted.undecryptable,
      alreadyCurrent: reconciled.alreadyCurrent,
      evidence: null,
    };
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
/**
 * 再暗号化の 3 関数(1 変数の push・1 巡の push・巡末の再走査)が共有する文脈。
 * 巡ごとに変わるのは view と対象だけなので、変わらないものを 1 つにまとめる
 * (同形の長い引数列が call site ごとに重複するのを避ける)。
 */
interface ReencryptContext {
  readonly client: MaruhiClient;
  readonly environmentId: EnvironmentId;
  readonly floor: FloorHandle;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** 再暗号化の目標エポック(ローテーション後の新エポック / 再開時の現エポック)。 */
  readonly epoch: number;
  readonly dek: Uint8Array;
  readonly deksByEpoch: ReadonlyMap<number, Uint8Array>;
  readonly writerUserId: string;
  /** 自分の鍵 FP(受理済みの自分の書き込みを台帳へ記録するときの帰属)。 */
  readonly writerKeyFingerprintHex: string;
  readonly signingKey: CryptoKey;
}

/**
 * 失敗を投げずに値として持ち帰る。エポックが進んだ後の失敗は「部分完了」の
 * 報告経路へ乗せる必要があり、例外として抜けると運用状態を伝え損ねる。
 */
function asOutcome<A, R>(
  effect: Effect.Effect<A, CliError, R>,
): Effect.Effect<
  | { readonly kind: "ok"; readonly value: A }
  | { readonly kind: "failed"; readonly error: CliError },
  never,
  R
> {
  return effect.pipe(
    Effect.map((value) => ({ kind: "ok", value }) as const),
    Effect.catch((error) => Effect.succeed({ kind: "failed", error } as const)),
  );
}

/** RotateInput + エポック固有の材料から再暗号化の文脈を組む。 */
function reencryptContext(
  input: RotateInput,
  member: ChainMember,
  epochMaterial: {
    readonly epoch: number;
    readonly dek: Uint8Array;
    readonly deksByEpoch: ReadonlyMap<number, Uint8Array>;
  },
): ReencryptContext {
  return {
    client: input.client,
    environmentId: input.environmentId,
    floor: input.floor,
    resync: input.resync,
    writerUserId: input.signerUserId,
    writerKeyFingerprintHex: member.keyFingerprintHex,
    signingKey: input.signingKeyPair.privateKey,
    ...epochMaterial,
  };
}

/** 1 巡分の push の結果。 */
interface PushPassResult {
  readonly reencrypted: number;
  readonly conflicted: readonly ConflictedTarget[];
  /**
   * サーバーがエポック競合を申告した変数(チェーンとの突き合わせは再走査が行う)。
   * **数ではなく id で持つ**: 「申告がチェーンと矛盾している」と断じてよいのは、
   * 申告された当の変数が再走査でも残っている場合だけである(他の変数が別の理由で
   * 残っているだけなら、その実行は普通の部分完了として案内すべき)。
   */
  readonly epochStaleIds: ReadonlySet<string>;
  /** 再暗号化を完了できなかった変数(409・一時失敗・エポック競合)。 */
  readonly unfinishedIds: ReadonlySet<string>;
  /** 受理された自分の書き込み(台帳の新しい基準)。 */
  readonly written: readonly VerifiedPulledValue[];
  /**
   * 個別に失敗した最初の原因(巡自体は止めない。数は unfinishedIds が持つ)。
   * **どの変数の失敗か**も持つ: 巡末の再走査でその変数が解決していた場合
   * (並行削除の 404 など)、未完了の原因として掲げると別の変数の本当の原因を
   * 隠してしまうため、呼び出し側が実態と突き合わせて捨てられるようにする。
   */
  readonly firstFailure: { readonly variableId: string; readonly message: string } | null;
  readonly warnings: readonly string[];
}

/**
 * 1 巡分の再暗号化 push。競合(409)は次の再走査へ回し、並行削除(404)は
 * 警告して飛ばす。
 *
 * **個別の失敗で巡を中断しない**: 1 変数の一時的な失敗(502 等)で残りを
 * 見捨てると、100 変数のうち 3 番目で落ちた場合に 97 変数が旧エポックの DEK で
 * 読めるまま残る。さらに恒久的に失敗する 1 変数があると、順序が安定なため
 * 以後の変数が**どの再実行でも**到達不能になる。失敗は数と原因として集計し、
 * 実際の残りは巡末の再走査(検証済みの実態)が決める。
 */
function runPushPass(input: {
  readonly context: ReencryptContext;
  readonly view: VerifiedProject;
  readonly pending: readonly ReencryptTarget[];
  /** 進行表示の通し番号の起点(これまでに再暗号化した数)。 */
  readonly doneBefore: number;
}): Effect.Effect<PushPassResult, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const conflicted: ConflictedTarget[] = [];
    const written: VerifiedPulledValue[] = [];
    const unfinishedIds = new Set<string>();
    const warnings: string[] = [];
    // 進行表示の分母は「この巡で判明している総数」(再走査で対象が増えうる)
    const total = input.doneBefore + input.pending.length;
    let reencrypted = 0;
    const epochStaleIds = new Set<string>();
    let firstFailure: { readonly variableId: string; readonly message: string } | null = null;
    for (const target of input.pending) {
      const attempt = yield* asOutcome(
        pushReencrypted({ context: input.context, view: input.view, target }),
      );
      if (attempt.kind === "failed") {
        // 巡は止めない(残りの変数を旧エポックに取り残さない)。
        // **どの変数がどう失敗したかは全件残す**: 原因として掲げられるのは 1 件
        // だけなので、警告に出さないと恒久的に失敗する変数(値が大きすぎる等)の
        // 理由がどの実行でも表に出ず、旧エポックのまま取り残され続ける
        const message = `変数 ${displayText(target.value.name)} の再暗号化に失敗しました: ${attempt.error.message}`;
        warnings.push(message);
        firstFailure ??= { variableId: target.value.variableId, message };
        unfinishedIds.add(target.value.variableId);
        continue;
      }
      if (attempt.value.kind === "conflict") {
        conflicted.push({
          variableId: target.value.variableId,
          known: target.value,
          currentVersion: attempt.value.currentVersion,
        });
        unfinishedIds.add(target.value.variableId);
        continue;
      }
      if (attempt.value.kind === "deleted") {
        warnings.push(
          `変数 ${displayText(target.value.name)} の再暗号化が 404 で拒否されました(他メンバーによる並行削除の可能性)。再取得でアクティブ集合から消えていれば対象から外し、まだ配布されていれば未完了として数えます`,
        );
        firstFailure ??= {
          variableId: target.value.variableId,
          message: `変数 ${displayText(target.value.name)} の再暗号化が 404 で拒否されました(並行削除の可能性)`,
        };
        unfinishedIds.add(target.value.variableId);
        continue;
      }
      if (attempt.value.kind === "epoch-stale") {
        // 再走査がチェーン導出のエポックで実態を判定する。この変数は旧エポックの
        // ままなので、エポックが動いていなければ次巡の対象として再び現れる
        epochStaleIds.add(target.value.variableId);
        unfinishedIds.add(target.value.variableId);
        continue;
      }
      if (attempt.value.floorWarning !== null) {
        warnings.push(attempt.value.floorWarning);
      }
      // 受理済みの自分の書き込みを台帳の基準へ昇格する: 以後の再走査が
      // 押し戻し(自分の書き込みの巻き戻し)を検出できるようにする
      written.push(attempt.value.written);
      reencrypted += 1;
      yield* io.log(
        `  再暗号化 (${input.doneBefore + reencrypted}/${total}): ${displayText(target.value.name)}(version=${target.value.version + 1})`,
      );
    }
    return {
      reencrypted,
      conflicted,
      epochStaleIds,
      unfinishedIds,
      written,
      firstFailure,
      warnings,
    };
  });
}

/**
 * §6.3 検証を通した値を既知値の台帳へ記録する。入口は 2 つあるが記録は同一:
 *
 * - **今巡の対象**: 次巡の prev アンカーになりうるため、409 を返したものに
 *   限らず整合検査(§12-5)の基準として保持する
 * - **受理された自分の書き込み**: 床(SHOULD)の更新に失敗しても、次の再走査は
 *   「自分が書いた version」を基準に比較できる — 受理済みの書き込みを押し戻す
 *   応答を、床の有無に関わらず巻き戻しとして検出する
 *
 * どちらも「自分が正しいと確認した値とその version」であり、記録の形が割れると
 * 片方だけ §12-5 の検査が弱まるため 1 つにしてある(409 の申告 version を運ぶ
 * recordConflicts だけは別物)。
 */
function recordKnown(
  known: Map<string, ConflictedTarget>,
  values: readonly VerifiedPulledValue[],
): void {
  for (const value of values) {
    known.set(value.variableId, {
      variableId: value.variableId,
      known: value,
      currentVersion: value.version,
    });
  }
}

/**
 * 409 の申告 version で台帳を上書きする。競合の「集合」は別途保持しない —
 * 消失の警告も alreadyCurrent の計上も未完了集合(409 に限らない)が基準であり、
 * 409 だけの集合を持ち回ると「まだ何かの判断に使われている」と読めてしまう。
 */
function recordConflicts(
  known: Map<string, ConflictedTarget>,
  conflicted: readonly ConflictedTarget[],
): void {
  for (const conflict of conflicted) {
    known.set(conflict.variableId, conflict);
  }
}

/** 巡末の判定(完了検証の結果をどう扱うか)。 */
type PassVerdict =
  /** 続行可能(remaining が 0 なら完了)。 */
  | {
      readonly kind: "settled";
      readonly view: VerifiedProject;
      /** 目標エポック未満のまま残っている変数数(完了判定と残数の正)。 */
      readonly remaining: number;
      /** 次巡の対象(最終巡は空 — remaining が 0 でなくても復号しない)。 */
      readonly targets: readonly ReencryptTarget[];
      /** 開けなかった値の理由(未完了の原因として報告する)。 */
      readonly undecryptable: readonly string[];
      /** まだ目標エポック未満のまま残っている変数 id(原因の取捨に使う)。 */
      readonly staleIds: ReadonlySet<string>;
      readonly alreadyCurrent: number;
    }
  /**
   * 完了を検証できなかった。`remaining` は「今巡で完了しなかった数」であって
   * 実測ではない — 上限でも下限でもない(競合分が他メンバーの手で解決していれば
   * 過大、実行中に作られた変数は数に入らないため過小になりうる)。表示側は
   * これを「未確認を含む」と断って出す(remainingExact = false)。
   */
  | { readonly kind: "unverified"; readonly remaining: number; readonly failure: string }
  /** 再実行では解消しない中断(暗号学的証拠・サーバーとチェーンの矛盾)。 */
  | { readonly kind: "abort"; readonly message: string };

/**
 * 1 巡の末尾の完了検証と判定。再走査(競合・失敗の有無に関わらず必ず行う)の
 * 結果から、続行・完了・未検証・即時中断のいずれかを決める。判定の優先順は
 * 「証拠 > 矛盾 > 続行」— 証拠は再実行で解消しないため他の理由に潰されない。
 */
function settlePass(input: {
  readonly context: ReencryptContext;
  readonly view: VerifiedProject;
  readonly known: ReadonlyMap<string, ConflictedTarget>;
  readonly pass: PushPassResult;
  readonly reencrypted: number;
  /** 次巡があるか(= 残った対象を復号する意味があるか)。 */
  readonly hasNextPass: boolean;
}): Effect.Effect<
  { readonly verdict: PassVerdict; readonly warnings: readonly string[] },
  never,
  never
> {
  return Effect.gen(function* () {
    const { environmentId, epoch } = input.context;
    // 収集済みの警告は再走査が失敗しても失わない(エラー channel は運べない)
    const warnings: string[] = [];
    const rescan = yield* asOutcome(
      rescanEnvironment({
        context: input.context,
        view: input.view,
        known: input.known,
        unfinishedIds: input.pass.unfinishedIds,
        collectWarning: (warning) => warnings.push(warning),
        // エポック競合の申告があった巡は、チェーンを取り直してから判定する
        forceResync: input.pass.epochStaleIds.size > 0,
        decryptRemaining: input.hasNextPass,
      }),
    );
    if (rescan.kind === "failed") {
      // **再走査の失敗を優先する**: 床の巻き戻し・チェーン分岐の証拠や並行
      // ローテーションの検出はここに現れるため、変数 1 件の一時的な失敗で
      // 覆い隠してはならない(押し出すと「再実行で直る」案内に化ける)
      const pushFailure =
        input.pass.firstFailure === null
          ? ""
          : `(併せて再暗号化中の失敗もありました: ${input.pass.firstFailure.message})`;
      return {
        warnings,
        verdict: {
          kind: "unverified",
          remaining: input.pass.unfinishedIds.size,
          failure: `${rescan.error.message}${pushFailure}`,
        },
      } as const;
    }
    const context = `環境 ${environmentId} は epoch ${epoch} へ進んでおり、再暗号化は ${input.reencrypted} 変数で中断しました`;
    if (rescan.value.evidence !== null) {
      // 暗号学的証拠は最優先の即時中断(再実行では解消しない)。エポックが
      // 進んでいる文脈も一緒に伝える — 証拠だけ出して運用状態を伝え損ねない
      return {
        warnings,
        verdict: {
          kind: "abort",
          message: `${rescan.value.evidence}\n${context}。これは再実行では解消しない証拠です — サーバーの応答を調査してください`,
        },
      } as const;
    }
    if (input.pass.epochStaleIds.size > 0) {
      // 強制再同期したチェーンでもエポックが変わっていない(進んでいれば
      // rescanEnvironment が失敗している)。サーバーの EpochConflict 申告は
      // チェーンと矛盾しており、その変数を押し直しても解けない(push.ts と同じ判定)。
      //
      // ただし中断してよいのは**申告された当の変数がまだ残っている**場合だけ:
      // 他メンバーが同じエポックで書き切るなどしてその変数が解消していれば、
      // 残りは別の理由(一時的な失敗・競合)であり、再実行で片付く。「再実行では
      // 解消しません」と断じると、再開の案内も残数の報告も届かなくなる。
      // 再暗号化の完否を決めるのは検証済みの実態であって、サーバーの自己申告ではない
      // 判定は stale(常に埋まる)で行う — targets は最終巡で空になる
      const unresolved = rescan.value.stale.filter((value) =>
        input.pass.epochStaleIds.has(value.variableId),
      );
      if (unresolved.length > 0) {
        return {
          warnings,
          verdict: {
            kind: "abort",
            message: `サーバーがエポック競合を申告しましたが、チェーン上の現エポックは ${epoch} のままです(サーバー応答とチェーンの矛盾)。${context} — 再実行では解消しません`,
          },
        } as const;
      }
      warnings.push(
        `サーバーが再暗号化の push に対してエポック競合を申告しましたが、チェーン上の現エポックは ${epoch} のままでした(サーバー応答とチェーンの矛盾)。申告された変数は再走査の未完了集合に残っていない(現エポックで書かれたか、削除された)ので処理を続けますが、この応答の矛盾自体は調査対象です`,
      );
    }
    return {
      warnings,
      verdict: {
        kind: "settled",
        view: rescan.value.view,
        remaining: rescan.value.stale.length,
        targets: rescan.value.targets,
        undecryptable: rescan.value.undecryptable,
        staleIds: new Set(rescan.value.stale.map((value) => value.variableId)),
        alreadyCurrent: rescan.value.alreadyCurrent,
      },
    } as const;
  });
}

/**
 * 「起きたが、もう原因ではない失敗」の記録。原因として掲げると調査を誤誘導する
 * が、黙って落とすと 502 が起きた事実自体が消える — 解決の仕方を添えて警告に残す。
 */
function noteResolvedFailure(warnings: string[], failure: string | null, resolution: string): void {
  if (failure !== null) {
    warnings.push(`再暗号化の途中で失敗がありましたが、${resolution}: ${failure}`);
  }
}

function reencryptCurrentValues(input: {
  readonly context: ReencryptContext;
  readonly view: VerifiedProject;
  readonly targets: readonly ReencryptTarget[];
  /**
   * 警告の受け皿(呼び出し側と共有する配列)。中断は例外として抜けるため、
   * 戻り値で返すと**失敗時にだけ**警告が消える — 中断こそ、床の更新失敗や
   * 並行削除の通知が最も効く場面なので、書き込み先を共有して失わない。
   */
  readonly sink: string[];
}): Effect.Effect<ReencryptOutcome, CliError, CliIo> {
  return Effect.gen(function* () {
    const warnings = input.sink;
    let view = input.view;
    let pending = input.targets;
    let reencrypted = 0;
    let alreadyCurrent = 0;
    /**
     * **直近の巡**で実際に起きた失敗(= いま未完了を塞いでいる原因)。巡を跨いで
     * 持ち越さない: 1 巡目の一時失敗が 2 巡目で解消したなら、それはもう原因では
     * ない。持ち越すと、解消済みの失敗を掲げたまま本当の原因(解けない 409 なら
     * 「並行 push との競合」)を隠し、調査を検証失敗・床違反の方向へ誤誘導する。
     */
    let blockingFailure: string | null = null;
    /** この実行で一度でも起きた失敗(完了できた場合の「起きたが解決した」報告用)。 */
    let seenFailure: string | null = null;
    /**
     * 目標エポック未満のまま残っている変数数。**毎巡の再走査が確定させる**ので、
     * ここは初期値を持たない(0 のまま読まれる経路は無い — 読むのは巡を 1 度
     * 以上回した後だけ)。対象数で初期化すると、報告され得ない数を「残数の
     * 既定値」に見せてしまう
     */
    let staleCount = 0;
    /** この実行で §6.3 検証を通した値(次巡の prev アンカーの整合検査の基準)。 */
    const known = new Map<string, ConflictedTarget>();

    const outcome = (
      remaining: number,
      failure: string | null,
      remainingExact: boolean,
    ): ReencryptOutcome => ({
      reencrypted,
      alreadyCurrent,
      remaining,
      remainingExact,
      failure,
    });

    for (let pass = 1; pass <= MAX_REENCRYPT_PASSES; pass += 1) {
      recordKnown(
        known,
        pending.map((target) => target.value),
      );
      const attempted = yield* runPushPass({
        context: input.context,
        view,
        pending,
        doneBefore: reencrypted,
      });
      reencrypted += attempted.reencrypted;
      warnings.push(...attempted.warnings);
      recordKnown(known, attempted.written);
      recordConflicts(known, attempted.conflicted);
      const settled = yield* settlePass({
        context: input.context,
        view,
        known,
        pass: attempted,
        reencrypted,
        hasNextPass: pass < MAX_REENCRYPT_PASSES,
      });
      warnings.push(...settled.warnings);
      if (settled.verdict.kind === "unverified") {
        // 再走査に到達できていない = 残数は実測ではない(PassVerdict の定義)
        return outcome(settled.verdict.remaining, settled.verdict.failure, false);
      }
      if (settled.verdict.kind === "abort") {
        return yield* Effect.fail(cliError(settled.verdict.message));
      }
      view = settled.verdict.view;
      pending = settled.verdict.targets;
      alreadyCurrent += settled.verdict.alreadyCurrent;
      staleCount = settled.verdict.remaining;
      if (staleCount === 0) {
        // 再取得・再検証したビューに目標エポック未満の active 値がない = 完了。
        // 途中の一時的な失敗は「起きたが結果として解決した」事実として警告に残す
        // (完了を検証できている以上、部分完了として非ゼロ終了させない)
        noteResolvedFailure(
          warnings,
          failureMessage(attempted.firstFailure) ?? seenFailure,
          "再走査で完了を確認しました",
        );
        return outcome(0, null, true);
      }
      blockingFailure = blockingCause(
        pendingFailure(attempted.firstFailure, settled.verdict.staleIds),
        settled.verdict.undecryptable,
      );
      seenFailure ??= failureMessage(attempted.firstFailure);
      if (stalledOnUndecryptable(pending, pass)) {
        // 未完了は残っているのに押せる対象が 1 つも無い = 復号できない値だけが
        // 残っている。残りの巡を回しても pull を繰り返すだけで前進しない
        break;
      }
    }
    noteStaleFailures(warnings, blockingFailure, seenFailure);
    // 巡を使い切った(中断ではない): 残数は最終巡の再走査を通った**実測**である
    return outcome(staleCount, blockingFailure, true);
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
  // 収集した警告は**失敗経路でも**必ず吐く: 成功時は呼び出し側が
  // summary.warnings を表示するが、中断すると表示経路に到達しない。床の更新
  // 失敗・並行削除・床なしの但し書きは、まさに中断時に効く情報である
  //
  // 受け皿は **Effect の中**で作る: 外で作ると 2 回目の実行が 1 回目の警告を
  // 抱えたまま始まり(retry / repeat / 同じ Effect の再実行)、前回の床警告や
  // 削除通知が今回の結果として報告される
  return Effect.suspend(() => {
    const warnings: string[] = [];
    return rotateWithWarnings(input, warnings).pipe(
      Effect.catch((error) =>
        Effect.gen(function* () {
          yield* logWarnings(dedupeWarnings(warnings));
          return yield* Effect.fail(error);
        }),
      ),
    );
  });
}

/**
 * 中断復旧: エポックは進んだが再暗号化が残っている状態(§12-7 の正当な過渡
 * 状態)を、**エポックを進めずに**続きから片付ける。新しいチェーンエントリは
 * 作らないので、この経路では `--reason` は記録されず必須でもない。
 */
function resumeReencryption(input: {
  readonly input: RotateInput;
  readonly pulled: { readonly verified: VerifiedProject };
  readonly keys: { readonly deksByEpoch: ReadonlyMap<number, Uint8Array> };
  readonly currentEpoch: number;
  readonly stale: readonly VerifiedPulledValue[];
  /** 指定された理由(null = `--reason` 未指定)。警告の文面にだけ効く。 */
  readonly reason: string | null;
  /**
   * 現在値のうち 1 つでも自分で開けるか。再開できないときに `--new-epoch` を
   * 勧めてよいか(= 進めた先に再暗号化する材料があるか)の判定に使う。
   */
  readonly anyDecryptable: boolean;
  readonly warnings: string[];
}): Effect.Effect<RotationSummary, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const { currentEpoch, stale, warnings } = input;
    const environmentId = input.input.environmentId;
    // 前進した検証ビューでガードを再適用する(初回検査から pull までの間に
    // grant_server の有効化・role 変更・削除が起きていれば、古い検証状態の
    // まま再開経路だけが素通りしてしまう — Cursor Security Reviewer 指摘)
    const member = yield* ensureRotatable(
      input.pulled.verified,
      environmentId,
      input.input.signerUserId,
    );
    const dek = input.keys.deksByEpoch.get(currentEpoch);
    if (dek === undefined) {
      // 逃げ道は**満たせるときだけ**案内する: --new-epoch は自分で新 DEK を作る
      // ので現エポックの DEK 自体は要らないが、再暗号化する材料(開ける現在値)が
      // 1 つも無ければ ensureRotationIsUseful で弾かれる。無条件に勧めると、
      // 2 つの矛盾するエラーの間で利用者を往復させることになる
      return yield* Effect.fail(
        cliError(
          input.anyDecryptable
            ? `現エポック ${currentEpoch} の DEK が自分宛に登録されていません(ローテーション実行者による再ラップ待ちの可能性)。未完了の再暗号化を再開できません — 再ラップを待つか、失効を優先する場合は --new-epoch を付けて実行してください(自分で開ける値だけが新エポックへ移り、開けない値は未完了として報告されます)`
            : `現エポック ${currentEpoch} の DEK が自分宛に登録されていません(ローテーション実行者による再ラップ待ちの可能性)。開ける現在値が 1 つも無いため、--new-epoch でエポックを進めても再暗号化できるものがありません — 自分宛の再ラップを待つか、当該エポックのラップを持つメンバーが実行してください`,
        ),
      );
    }
    // 文面は「要求があったか」で変える: 理由なしの実行(部分完了の案内が
    // 勧める形)は何も要求していないので、切り替えたと言うと嘘になる
    const switched =
      input.reason === null
        ? "この再暗号化を再開します(新しいエポックは作りません)"
        : "**要求されたローテーションは実行せず**、この再暗号化の再開に切り替えます(新しいエポックは作られず、この経路はチェーンエントリを作らないため --reason も記録されません)";
    yield* io.logError(
      `警告: 環境 ${environmentId} は epoch ${currentEpoch} へのローテーション後、${stale.length} 変数の再暗号化が未完了です。${switched}。退職者の削除など「新しいエポックが必ず必要」な場合は --new-epoch を付けて実行してください — 未完了状態を装う応答でローテーションを抑止される経路への対策でもあります`,
    );
    // 開けない値があっても再開自体は止めない: **エポックは既に進んでいる**ので、
    // 「エポックだけ進んで再暗号化が完了しない状態を作らない」という通常経路の
    // 理由はここでは成立しない — その状態はもう出来ており、開ける分を押さない
    // 選択はそれを維持するだけである(100 件中 1 件が開けないとき、残り 99 件を
    // 旧 DEK のまま置き去りにしない)。= 「必ず進める」側と同じ方針なので
    // decryptForRotation と方針を共有する(2 箇所に割れると、分類の変更が
    // 再開経路にだけ入り損ねる)
    const targets = yield* decryptForRotation({
      verified: input.pulled.verified,
      environmentId,
      values: stale,
      deksByEpoch: input.keys.deksByEpoch,
      chainEpoch: currentEpoch,
      warnings,
    });
    // 押せる対象が 1 つも無いなら巡へ入らない。入っても空の push 巡と環境の
    // 全再取得・全再検証を 1 往復して、既に分かっている原因へ戻るだけである
    // (通常経路の ensureRotationIsUseful に相当する早期の切り上げ)
    const outcome =
      targets.length === 0
        ? {
            reencrypted: 0,
            alreadyCurrent: 0,
            remaining: stale.length,
            remainingExact: true,
            failure: nothingDecryptable(stale.length),
          }
        : yield* reencryptCurrentValues({
            context: reencryptContext(input.input, member, {
              epoch: currentEpoch,
              dek,
              deksByEpoch: input.keys.deksByEpoch,
            }),
            view: input.pulled.verified,
            targets,
            sink: warnings,
          });
    return {
      mode: "resumed",
      previousEpoch: currentEpoch,
      epoch: currentEpoch,
      reencrypted: outcome.reencrypted,
      alreadyCurrent: outcome.alreadyCurrent,
      remaining: outcome.remaining,
      remainingExact: outcome.remainingExact,
      failure: outcome.failure,
      warnings: dedupeWarnings(warnings),
    };
  });
}

function rotateWithWarnings(
  input: RotateInput,
  warnings: string[],
): Effect.Effect<RotationSummary, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const reason = yield* checkReasonLength(input.reason);
    yield* ensureRotatable(input.verified, input.environmentId, input.signerUserId);
    // --new-epoch は再開経路を通らない = 必ずエントリを署名する。理由の必須検査を
    // 署名直前まで遅らせる理由(再開では reason が記録されない)がここには無いので、
    // pull より前に落とす — 満たしようのない引数検査のために全変数の暗号文を
    // 取りに行き、変数ごとの var.read を監査ログへ残さない(ensureRotatable と同じ規律)
    if (input.forceNewEpoch) {
      yield* requireReason(reason);
    }
    // 対象集合の出所はサーバーの pull 応答しかない(変数一覧はチェーンに載らない
    // — §6.2)。欠落の検出はローカル床の variable-omitted 規則(§6.3 (a))が担う
    // ため、床がない実行(初回同期・破損後)では「一貫して落とされた変数」を
    // 検出できない。ローテーションは失効操作でありこの残余は重いので、
    // 完了報告の前に明示する(§14.3-3 の支配的残余の、この経路での現れ方)
    const floorless = input.floor.current() === null;

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
    // 警告は後続の失敗(DEK 検証など)より**前**に sink へ入れる: 失敗経路の
    // flush に含まれなければ、失敗時にだけ消えるという round 8 と同じ穴になる
    warnings.push(...pulled.warnings);
    if (floorless) {
      warnings.push(
        `この環境のローカル床がまだないため、サーバーが応答から落とし続けた変数(存在するのに一覧に現れない変数)は再暗号化の対象に入らず、欠落も検出できません(CRYPTO_SPEC §6.3 の欠落検出は床を前提とします)。失効目的のローテーションでは、床のある環境で再実行して ${displayText(input.environmentId)} の変数一覧が一致することを確認してください`,
      );
    }
    const keys = yield* environmentKeysFor({
      client: input.client,
      verified: pulled.verified,
      environmentId: input.environmentId,
      recipient: input.recipient,
      prefetched: pulled.deks,
    });
    const currentEpoch = keys.currentEpoch;
    const stale = pulled.variables.filter((value) => value.epoch < currentEpoch);

    // --- 中断復旧: エポックは進んだが再暗号化が残っている ---
    if (stale.length > 0 && !input.forceNewEpoch) {
      return yield* resumeReencryption({
        input,
        pulled,
        keys,
        currentEpoch,
        stale,
        reason,
        anyDecryptable: pulled.variables.some((value) => keys.deksByEpoch.has(value.epoch)),
        warnings,
      });
    }

    // 未完了がなく --reason も指定されていない = 「確認だけ」の実行(部分完了の
    // 案内が勧める再実行の形)。ここで --reason を要求すると、案内どおりに
    // 再実行した利用者が理由を求められ、指定すると**二度目のローテーション**に
    // なってしまう。何もせず完了状態を報告する。
    // `--reason ""` はこの経路に入らない(checkReasonLength が手前で落とす)
    if (reason === null && !input.forceNewEpoch) {
      return {
        mode: "up-to-date",
        previousEpoch: currentEpoch,
        epoch: currentEpoch,
        reencrypted: 0,
        alreadyCurrent: 0,
        remaining: 0,
        remainingExact: true,
        failure: null,
        warnings: dedupeWarnings(warnings),
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
    const targets = yield* decryptForRotation({
      verified: pulled.verified,
      environmentId: input.environmentId,
      values: pulled.variables,
      deksByEpoch: keys.deksByEpoch,
      chainEpoch: currentEpoch,
      warnings,
    });
    yield* ensureRotationIsUseful(targets.length, pulled.variables.length);
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
      // 帰属は受理時点のメンバー行(CAS リトライで再署名していれば更新済み)
      context: reencryptContext(input, rotated.member, { epoch: newEpoch, dek, deksByEpoch }),
      view: rotated.view,
      targets,
      sink: warnings,
    });
    return {
      mode: "rotated",
      previousEpoch: currentEpoch,
      epoch: newEpoch,
      reencrypted: outcome.reencrypted,
      alreadyCurrent: outcome.alreadyCurrent,
      remaining: outcome.remaining,
      remainingExact: outcome.remainingExact,
      failure: outcome.failure,
      warnings: dedupeWarnings(warnings),
    };
  });
}
