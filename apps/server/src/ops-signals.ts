// 運用カウンタの書き込み点 — docs/notes/hosted-ops.md §2-A。
//
// - GitHub token 請求: `GitHubApi.exchangeCode` の呼び出し点を装飾する(web OAuth
//   callback と CLI ハンドオフの両経路が同じ実装を通るため、ハンドラを触らない)。
//   成否を問わず 1 計上(GitHub は請求を数える — 2,000 回/時の secondary)
// - ログインフロー行の作成上限到達: createOrMatch が capacity を返した点
//
// 計数は観測であり受理面の挙動(拒否・遅延)を変えない。増分の失敗は握り潰さず
// 静的 1 行を残して続行する(ログイン経路の可用性に優先しない)。

import { Effect } from "effect";

import type { GitHubApiShape } from "./auth.package/index.ts";
import type { OpsCounterMetric, OpsRepoShape } from "./db.package/index.ts";
import { OpsRepo } from "./db.package/index.ts";

/** カウンタ +1(best-effort — 失敗は静的ログのみ)。 */
export function noteOpsCounter(metric: OpsCounterMetric): Effect.Effect<void, never, OpsRepo> {
  return Effect.flatMap(OpsRepo, (ops) => ops.incrementCounter(metric, Date.now())).pipe(
    Effect.catchCause(() =>
      Effect.sync(() => {
        // 静的メッセージのみ(metric 名は固定語彙)
        console.warn(
          `ops counter increment failed (${metric}); the signal undercounts this window`,
        );
      }),
    ),
  );
}

/** exchangeCode の呼び出しを計数する装飾(index.ts の buildServices で 1 か所)。 */
export function countingGitHubApi(api: GitHubApiShape, ops: OpsRepoShape): GitHubApiShape {
  return {
    ...api,
    exchangeCode: (code, redirectUri) =>
      ops.incrementCounter("github_token_requests", Date.now()).pipe(
        Effect.catchCause(() =>
          Effect.sync(() => {
            console.warn(
              "ops counter increment failed (github_token_requests); the signal undercounts this window",
            );
          }),
        ),
        Effect.andThen(api.exchangeCode(code, redirectUri)),
      ),
  };
}
