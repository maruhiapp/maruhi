// CAS 競合リトライの共有コンビネータ(AUTH_SPEC §12-4 / §12-5 の再試行手順)。
//
// 「試行 → 競合分類 → 回復(再同期ビューで再署名の材料づくり)→ 再試行、
// 最終試行でも回復を走らせて定的エラーを表面化する」の骨格を push.ts /
// env-create.ts で共有する。ドメイン固有の回復(winner 採用・再解決・
// ラップ再構築)は呼び出し側の recover に残る。

import { Effect } from "effect";

import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";

export interface ConflictRetryOptions<S, A, C> {
  readonly maxAttempts: number;
  /** 1 試行(現在の状態からの署名・送信まで)。受理値で成功するか、生エラーで失敗する。 */
  readonly attempt: (state: S) => Effect.Effect<A, unknown>;
  /** 失敗の分類: リトライ可能な競合なら分類値、定的エラーなら null(CliError へ写して伝播)。 */
  readonly classify: (error: unknown) => C | null;
  /** 競合からの回復。失敗(定的エラー)はそのまま伝播する。 */
  readonly recover: (state: S, conflict: C) => Effect.Effect<S, CliError>;
  /** 全試行が競合で尽きたときのメッセージ。 */
  readonly exhaustedMessage: string;
}

/**
 * Retries a CAS-style operation: run `attempt`, classify failures into
 * retryable conflicts, `recover` a fresh state (re-sync, re-resolve,
 * re-sign material) and try again, up to `maxAttempts`.
 *
 * 最終試行の競合でも recover を実行する: 再同期・再解決で判明する定的エラー
 * (equivocation の証拠・サーバー応答とチェーンの矛盾・並行作成の duplicate 等)は
 * 汎用の exhausted メッセージより情報量が高い。定的エラーはそのまま伝播し、
 * 再試行可能な状態が返った場合のみ次周回で使う(最終周回では未使用)。
 */
export function retryOnConflict<S, A, C>(
  initial: S,
  options: ConflictRetryOptions<S, A, C>,
): Effect.Effect<A, CliError> {
  return Effect.gen(function* () {
    let state = initial;
    for (let attempt = 1; attempt <= options.maxAttempts; attempt += 1) {
      const outcome = yield* options.attempt(state).pipe(
        Effect.map((value) => ({ kind: "accepted", value }) as const),
        Effect.catch(
          (
            error,
          ): Effect.Effect<
            | { readonly kind: "accepted"; readonly value: A }
            | { readonly kind: "conflict"; readonly conflict: C },
            CliError
          > => {
            const conflict = options.classify(error);
            return conflict === null
              ? Effect.fail(toCliError(error))
              : Effect.succeed({ kind: "conflict", conflict } as const);
          },
        ),
      );
      if (outcome.kind === "accepted") {
        return outcome.value;
      }
      state = yield* options.recover(state, outcome.conflict);
    }
    return yield* Effect.fail(cliError(options.exhaustedMessage));
  });
}
