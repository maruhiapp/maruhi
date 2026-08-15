// 全環境ローテーション義務(CRYPTO_SPEC §7)の走査の共有実装。
//
// revoke_server(server-revoke)と remove_member / member 未満への降格
// (member remove / change-role)は、いずれも「チェーン上の基準 seq より後に
// 現エポックが始まっていない環境は強制ローテーション、それ以外は検証パス
// (未完了の再暗号化の再開 or 完了確認)」という同じ中断復旧構造を持つ。
// 進捗ファイルは持たず、チェーン導出状態だけから対象を決める(別デバイス・
// 別メンバーからの再開もそのまま成立する — server-revoke の規律の共有化)。
//
// 削除済み環境の除外は**検証済みの削除ステートメント**のみを根拠とする
// (サーバーの 404 申告だけで黙ってスキップしない — §7)。

import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { RotationSummary } from "./env-rotate.ts";
import type { CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import type { VerifiedProject } from "./sync.ts";
import { verifiedDeletedEnvironments } from "./values.ts";

/** ローテーション注入のモード: force = 新エポック必須 / verify = 再開・確認のみ。 */
export type SweepRotateMode = "force" | "verify";

/** 1 環境のローテーションの注入(cli.ts が envRotateOp を床付きで包んで渡す)。 */
export type SweepRotate<R> = (
  environmentId: string,
  mode: SweepRotateMode,
) => Effect.Effect<RotationSummary, CliError, R>;

/** 全環境走査の結果(revoke / remove / 降格で共通の報告材料)。 */
export interface SweepOutcome {
  /** ローテーション(強制 or 再開)を実行した環境(環境 ID → 結果)。 */
  readonly rotated: readonly {
    readonly environmentId: string;
    readonly summary: RotationSummary;
    /** 新エポックを要求した実行か(true = 強制 / false = 検証パスの再開)。 */
    readonly forcedNewEpoch: boolean;
  }[];
  /** ローテーションに失敗した環境(§7 — 黙ってスキップしない)。 */
  readonly failed: readonly { readonly environmentId: string; readonly message: string }[];
  /** 基準より後のエポックで、未完了の再暗号化がないことを**確認済み**の環境。 */
  readonly alreadyRotated: readonly string[];
}

/**
 * 「基準 seq の後にまだローテーションされていない環境」の導出(中断復旧の基準)。
 * 基準 seq より現エポックの開始 seq が前 = その環境の現 DEK は基準イベント
 * (失効・削除・降格)の前に配られたまま。チェーンだけから決まるので進捗
 * ファイルは不要。開始 seq が導出できない環境は fail-closed で対象に含める
 * (環境が黙って対象から外れる形にしない)。
 */
function pendingEnvironmentsAfter(
  verified: VerifiedProject,
  baselineSeq: number,
): readonly string[] {
  const pending: string[] = [];
  for (const [environmentId, environment] of verified.state.environments) {
    const startSeq = environment.epochStartSeqs.get(environment.currentEpoch);
    if (startSeq === undefined || startSeq < baselineSeq) {
      pending.push(environmentId);
    }
  }
  return pending.toSorted();
}

/**
 * 検証済みの削除環境集合(除外の唯一の根拠 — §7)。環境一覧を取得し、署名済み
 * 削除ステートメントの検証に通ったものだけを返す。検証できない環境は走査対象に
 * 残り、rotate の失敗として表面化する。
 */
export function verifiedDeletedEnvironmentSet(
  client: MaruhiClient,
  verified: VerifiedProject,
): Effect.Effect<ReadonlySet<string>, CliError> {
  return Effect.gen(function* () {
    const listed = yield* client.environments
      .list({ params: { projectId: verified.projectId } })
      .pipe(Effect.mapError(toCliError));
    return yield* verifiedDeletedEnvironments(verified, listed.environments);
  });
}

/** 1 環境のローテーションの結果化(失敗は投げずに集める — §7 の全環境走査用)。 */
function rotateOutcome<R>(
  rotate: SweepRotate<R>,
  environmentId: string,
  mode: SweepRotateMode,
): Effect.Effect<
  | { readonly kind: "ok"; readonly summary: RotationSummary }
  | { readonly kind: "failed"; readonly message: string },
  never,
  R
> {
  return rotate(environmentId, mode).pipe(
    Effect.map((summary) => ({ kind: "ok", summary }) as const),
    Effect.catch((error) => Effect.succeed({ kind: "failed", message: error.message } as const)),
  );
}

/**
 * §7 の全環境走査: pending は強制ローテーション、それ以外は検証パス
 * (未完了の再暗号化の再開 or 完了確認)。1 環境の失敗で残りを止めない
 * (失敗は集めて報告し、再実行で続きから再開する)。
 */
export function sweepRotations<R>(input: {
  readonly rotate: SweepRotate<R>;
  readonly verified: VerifiedProject;
  /** ローテーション義務を発生させたチェーンイベントの seq(revoke / remove / 降格)。 */
  readonly baselineSeq: number;
  readonly deletedVerified: ReadonlySet<string>;
}): Effect.Effect<SweepOutcome, never, R> {
  return Effect.gen(function* () {
    const pendingSet = new Set(pendingEnvironmentsAfter(input.verified, input.baselineSeq));
    const candidates = [...input.verified.state.environments.keys()]
      .filter((environmentId) => !input.deletedVerified.has(environmentId))
      .toSorted();
    const rotated: {
      readonly environmentId: string;
      readonly summary: RotationSummary;
      readonly forcedNewEpoch: boolean;
    }[] = [];
    const failed: { readonly environmentId: string; readonly message: string }[] = [];
    const alreadyRotated: string[] = [];
    for (const environmentId of candidates.filter((id) => pendingSet.has(id))) {
      const result = yield* rotateOutcome(input.rotate, environmentId, "force");
      if (result.kind === "ok") {
        rotated.push({ environmentId, summary: result.summary, forcedNewEpoch: true });
      } else {
        failed.push({ environmentId, message: result.message });
      }
    }
    // エポックは基準より後に始まっているが、その回の**再暗号化が完了したか**は
    // チェーンからは分からない(§12-7 の過渡状態)。検証パスで確かめる
    for (const environmentId of candidates.filter((id) => !pendingSet.has(id))) {
      const result = yield* rotateOutcome(input.rotate, environmentId, "verify");
      if (result.kind !== "ok") {
        failed.push({ environmentId, message: result.message });
      } else if (
        result.summary.mode === "up-to-date" &&
        result.summary.remaining === 0 &&
        result.summary.failure === null
      ) {
        alreadyRotated.push(environmentId);
      } else {
        // 再開した(または部分完了が残った)— 表示・終了コードは呼び出し側の
        // reportRotation が RotationSummary から導く
        rotated.push({ environmentId, summary: result.summary, forcedNewEpoch: false });
      }
    }
    return { rotated, failed, alreadyRotated: alreadyRotated.toSorted() };
  });
}
