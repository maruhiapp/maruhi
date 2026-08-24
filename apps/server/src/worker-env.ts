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
 * ratelimits binding の固定窓の周期(秒)。binding からは period を読めないため、
 * wrangler.jsonc の `ratelimits[].simple.period` と**手動で一致**させること
 * (429 応答の retryAfterSeconds に使う — レビューループ 2)。
 */
export const IP_RATE_LIMIT_PERIOD_SECONDS = 60;

/**
 * レート制限キーの正規化(レビューループ 5): IPv6 は /64 プレフィックスへ丸める。
 * 標準割当の /64 内で下位 64 bit をローテーションすると、素のアドレスキーでは
 * 毎リクエストが新規キーになり窓が一切効かない(Cloudflare WAF のレート制限が
 * 既定で /64 集約するのと同じ理由)。IPv4 はそのまま。パースできない値は素の
 * 文字列キーへフォールバックする(アドレス単位の制限は維持される)。
 */
export function rateLimitKeyOf(ip: string): string {
  if (!ip.includes(":")) {
    return ip;
  }
  return ipv6Prefix64(ip) ?? ip;
}

/** 圧縮形("::")・IPv4 埋め込み末尾を展開し、正規化した /64 プレフィックスを返す。 */
function ipv6Prefix64(ip: string): string | null {
  const zoneless = ip.split("%")[0] ?? ip;
  const halves = zoneless.split("::");
  if (halves.length > 2) {
    return null;
  }
  const head = parseIpv6Groups(halves[0] ?? "");
  const tail = halves.length === 2 ? parseIpv6Groups(halves[1] ?? "") : [];
  if (head === null || tail === null) {
    return null;
  }
  const missing = 8 - head.length - tail.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) {
    return null;
  }
  const full = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill("0"), ...tail];
  if (full.length !== 8) {
    return null;
  }
  const prefix = full.slice(0, 4).map((group) => Number.parseInt(group, 16).toString(16));
  return `${prefix.join(":")}::/64`;
}

/** ":" 区切りグループ列 → 16 進グループ配列(IPv4 埋め込みは 2 グループ)。 */
function parseIpv6Groups(raw: string): string[] | null {
  if (raw === "") {
    return [];
  }
  const groups: string[] = [];
  for (const piece of raw.split(":")) {
    if (piece.includes(".")) {
      const octets = piece.split(".").map(Number);
      if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) {
        return null;
      }
      groups.push(
        ((((octets[0] ?? 0) << 8) | (octets[1] ?? 0)) >>> 0).toString(16),
        ((((octets[2] ?? 0) << 8) | (octets[3] ?? 0)) >>> 0).toString(16),
      );
    } else if (/^[0-9a-fA-F]{1,4}$/.test(piece)) {
      groups.push(piece.toLowerCase());
    } else {
      return null;
    }
  }
  return groups;
}

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
      const outcome = await limiter.limit({ key: rateLimitKeyOf(ip) });
      return outcome.success;
    } catch (error) {
      // fail-open の**明示的な**回復(可用性側の設計判断 — 上の doc)。ただし
      // 無言では飲まない(CLAUDE.md): binding の設定ミス等で limiter が恒久に
      // 落ちていると、制限が全て無効のまま誰も気づけない。Workers のログ
      // (wrangler tail / Workers Logs — 運用者のみが読む。外部送信ではない)へ
      // 静的メッセージだけ残す(リクエスト内容・IP は書かない)
      console.warn(
        "rate limiter binding failed; allowing the request (fail-open)",
        error instanceof Error ? error.message : String(error),
      );
      return true;
    }
  });
}
