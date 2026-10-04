// Write points for the operations counters — docs/notes/hosted-ops.md
// §2-A.
//
// - GitHub token requests: decorate the call site of
//   `GitHubApi.exchangeCode` (the web OAuth callback and the CLI
//   handoff both pass through the same implementation, so no handler
//   is touched). +1 regardless of success (GitHub counts requests —
//   the 2,000/hour secondary limit)
// - Login-flow row creation cap reached: the point where createOrMatch
//   returns capacity
//
// Counting is observation and does not change the acceptance
// surface's behavior (refusals, delays). An increment failure is not
// swallowed — a static 1-line log is left and processing continues
// (does not take precedence over login-path availability).

import { Effect } from "effect";

import type { GitHubApiShape } from "../auth.package/index.ts";
import type { OpsCounterMetric, OpsRepoShape } from "../db.package/index.ts";
import { OpsRepo } from "../db.package/index.ts";

/** Counter +1 (best-effort — a failure leaves only a static log). */
export function noteOpsCounter(metric: OpsCounterMetric): Effect.Effect<void, never, OpsRepo> {
  return Effect.flatMap(OpsRepo, (ops) => ops.incrementCounter(metric, Date.now())).pipe(
    Effect.catchCause(() =>
      Effect.sync(() => {
        // Static message only (metric names are fixed vocabulary)
        console.warn(
          `ops counter increment failed (${metric}); the signal undercounts this window`,
        );
      }),
    ),
  );
}

/** Decoration counting exchangeCode calls (one place in index.ts's buildServices). */
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
