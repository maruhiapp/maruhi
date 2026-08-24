// worker 内共有の小物: Env サービスと DO RPC 呼び出しヘルパ。

import { Context, Effect } from "effect";

import type { Env, ProjectChainDO } from "./chain-do.ts";

export class WorkerEnv extends Context.Service<WorkerEnv, Env>()("WorkerEnv") {}

/** プロジェクト DO のスタブを解決する(DO 名 = プロジェクト ID)。 */
export const projectStub = (env: Env, projectId: string): DurableObjectStub<ProjectChainDO> =>
  env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));

// workers-types の RPC スタブ型は union 戻り値をメンバーごとの Promise 交差型に
// 分配してしまうため、DO メソッドの宣言どおりの Promise<Outcome> へ戻す
export const rpcCall = <T>(call: () => PromiseLike<unknown>): Effect.Effect<T> =>
  Effect.promise(() => call() as Promise<T>);

/**
 * 発信元 IP 単位の best-effort レート制限(Workers Rate Limiting binding —
 * deepsec M3/B11/M5)。true = 許可。
 *
 * fail-open の線引き(すべて可用性側に倒す):
 * - binding 不在(ratelimits 未設定の旧 wrangler.jsonc のまま self-host)は従来挙動
 * - CF-Connecting-IP 不在は帰属不能として通す。本番の Cloudflare 経路では常に
 *   エッジが**上書き付与**するヘッダーで、クライアントに偽装余地はない。不在に
 *   なるのは直接到達(wrangler dev・テスト)だけ
 * - limiter 自体の障害は通す(認証系・リース経路をリミッタ障害で全停止させない)
 */
export function ipRateLimitAllowed(
  limiter: RateLimit | undefined,
  request: { readonly source: unknown },
): Effect.Effect<boolean> {
  return Effect.promise(async () => {
    if (limiter === undefined) {
      return true;
    }
    const source = request.source;
    const ip = source instanceof Request ? source.headers.get("cf-connecting-ip") : null;
    if (ip === null || ip === "") {
      return true;
    }
    try {
      const outcome = await limiter.limit({ key: ip });
      return outcome.success;
    } catch {
      return true;
    }
  });
}
