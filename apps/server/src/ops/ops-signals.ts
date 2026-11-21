import { Clock, Effect } from "effect";

import type { GitHubApiShape } from "../auth.package/index.ts";
import type { OpsCounterMetric, OpsRepoShape } from "../db.package/index.ts";
import { OpsRepo } from "../db.package/index.ts";

export function noteOpsCounter(metric: OpsCounterMetric): Effect.Effect<void, never, OpsRepo> {
  return Effect.flatMap(OpsRepo, (ops) =>
    Effect.flatMap(Clock.currentTimeMillis, (nowMs) => ops.incrementCounter(metric, nowMs)),
  ).pipe(
    Effect.catchCause(() =>
      Effect.logWarning(
        `ops counter increment failed (${metric}); the signal undercounts this window`,
      ),
    ),
  );
}

export function countingGitHubApi(api: GitHubApiShape, ops: OpsRepoShape): GitHubApiShape {
  return {
    ...api,
    exchangeCode: (code, redirectUri) =>
      Clock.currentTimeMillis.pipe(
        Effect.flatMap((nowMs) => ops.incrementCounter("github_token_requests", nowMs)),
        Effect.catchCause(() =>
          Effect.logWarning(
            "ops counter increment failed (github_token_requests); the signal undercounts this window",
          ),
        ),
        Effect.andThen(api.exchangeCode(code, redirectUri)),
      ),
  };
}
