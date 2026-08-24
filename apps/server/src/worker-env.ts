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
 * (429 応答の retryAfterSeconds / Retry-After ヘッダーに使う — レビューループ 2)。
 * 片方だけ変えると案内する待ち時間が実際の窓とずれる(制限自体は正しく効く —
 * 安全側でなく利便側の劣化)。型・テストでの強制は不可(wrangler 設定は
 * 実行時に読めず、workerd テストからファイルも読めない)ため、両側のコメントで
 * ペアを明示する(wrangler.jsonc 側にも同じ注記がある)。
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
  const groups = ipv6Groups(ip);
  if (groups === null) {
    return ip;
  }
  // IPv4-mapped(::ffff:a.b.c.d)は埋め込み IPv4 をキーにする(レビューループ 6):
  // /64 集約へ入れると、v4-mapped で到達する全 IPv4 クライアントが単一バケット
  // "0:0:0:0::/64" に畳まれ、1 発信元が全 IPv4 ユーザーの窓を食い潰せてしまう
  const upperZero = groups.slice(0, 5).every((group) => Number.parseInt(group, 16) === 0);
  if (upperZero && Number.parseInt(groups[5] ?? "", 16) === 0xff_ff) {
    const hi = Number.parseInt(groups[6] ?? "0", 16);
    const lo = Number.parseInt(groups[7] ?? "0", 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  const prefix = groups.slice(0, 4).map((group) => Number.parseInt(group, 16).toString(16));
  return `${prefix.join(":")}::/64`;
}

/** "::" で分けた前後半のグループ列(不正・"::" が 2 つ以上は null)。 */
function splitIpv6Halves(
  ip: string,
): { readonly head: string[]; readonly tail: string[]; readonly compressed: boolean } | null {
  const halves = (ip.split("%")[0] ?? ip).split("::");
  if (halves.length > 2) {
    return null;
  }
  const compressed = halves.length === 2;
  const tailRaw = halves[1] ?? "";
  // IPv4 埋め込みはアドレス**末尾**にしか置けない(RFC 4291 §2.2 (3))。
  // 末尾を含む側の半分だけに許可を渡し、その中でも最後のピースに限る
  // (deepsec R9): "1.2.3.4::" や "::ffff:1.2.3.4:0" のような形を弾く
  const ipv4InTail = compressed && tailRaw !== "";
  const head = parseIpv6Groups(halves[0] ?? "", !compressed);
  const tail = parseIpv6Groups(tailRaw, ipv4InTail);
  if (head === null || tail === null) {
    return null;
  }
  return { head, tail, compressed };
}

/** 圧縮形("::")・IPv4 埋め込み末尾を展開した正規化 8 グループ(不正は null)。 */
function ipv6Groups(ip: string): string[] | null {
  const split = splitIpv6Halves(ip);
  if (split === null) {
    return null;
  }
  const zeros = 8 - split.head.length - split.tail.length;
  if (!split.compressed) {
    // 非圧縮形は前半だけが全 8 グループを持つ("::" が無いので後半は空)
    return zeros === 0 ? split.head : null;
  }
  return zeros >= 1 ? [...split.head, ...Array<string>(zeros).fill("0"), ...split.tail] : null;
}

/**
 * ":" 区切りグループ列 → 16 進グループ配列(空文字列は空配列。不正は null)。
 * `ipv4Tail` はこの半分の**最後のピース**に IPv4 埋め込みを許すかどうか。
 */
function parseIpv6Groups(raw: string, ipv4Tail: boolean): string[] | null {
  const groups: string[] = [];
  const pieces = raw === "" ? [] : raw.split(":");
  for (const [index, piece] of pieces.entries()) {
    const parsed = groupsOfPiece(piece, ipv4Tail && index === pieces.length - 1);
    if (parsed === null) {
      return null;
    }
    groups.push(...parsed);
  }
  return groups;
}

/**
 * 10 進 octet の厳密形(deepsec R9): 0-255 で、先頭ゼロ・空・16 進・指数表記・
 * 空白を許さない。`Number()` の強制変換は "" → 0、"0x10" → 16、"1e2" → 100 を
 * 通してしまい、後段の範囲検査では捕まらない(変換が先に成功しているため)。
 */
const DECIMAL_OCTET = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

/** 1 ピース → 16 進グループ(IPv4 埋め込みは 2 グループ。不正は null)。 */
function groupsOfPiece(piece: string, ipv4Allowed: boolean): readonly string[] | null {
  if (!piece.includes(".")) {
    return /^[0-9a-fA-F]{1,4}$/.test(piece) ? [piece.toLowerCase()] : null;
  }
  if (!ipv4Allowed) {
    return null;
  }
  const octets = piece.split(".");
  if (octets.length !== 4 || !octets.every((octet) => DECIMAL_OCTET.test(octet))) {
    return null;
  }
  const [a = 0, b = 0, c = 0, d = 0] = octets.map(Number);
  return [((a << 8) | b).toString(16), ((c << 8) | d).toString(16)];
}

// binding 不在の警告は isolate ごとに 1 回だけ出す(毎リクエストだとログが溢れる)
let warnedMissingRateLimitBinding = false;

/**
 * 発信元 IP 単位の best-effort レート制限(Workers Rate Limiting binding —
 * deepsec M3/B11/M5)。true = 許可。
 *
 * fail-open の線引き(すべて可用性側に倒す):
 * - binding 不在(ratelimits 未設定の旧 wrangler.jsonc のまま self-host)は
 *   従来挙動(isolate ごと 1 回の warn で観測可能にする)
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
      // fail-open だが無言にしない(pullfrog 指摘): コードだけ更新して旧
      // wrangler.jsonc のまま再デプロイした self-host は、レート制限が恒久に
      // 無効なまま何の signal も出ない — catch 側より現実的に当たる経路
      if (!warnedMissingRateLimitBinding) {
        warnedMissingRateLimitBinding = true;
        console.warn(
          "rate limiter binding is not configured; requests are not rate limited (redeploy with the ratelimits section of wrangler.jsonc to enable)",
        );
      }
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
      // error.message は管理下にない文字列(将来 limiter 実装が key を載せうる —
      // pullfrog 指摘)。「IP は書かない」の約束に合わせ、種別名だけ残す
      console.warn(
        "rate limiter binding failed; allowing the request (fail-open)",
        error instanceof Error ? error.name : "unknown",
      );
      return true;
    }
  });
}
