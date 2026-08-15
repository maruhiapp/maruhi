// OIDC discovery + JWKS の取得と TTL キャッシュ(AUTH_SPEC §14-1)。
//
// 取得先は**対応 issuer 一覧(静的設定)に含まれる issuer だけ**である。
// この順序は DoS 上重要で、リースエンドポイントは未認証(§14-1)であるため、
// 任意の issuer 文字列で外部 fetch を誘発できると増幅攻撃になる。issuer の
// 許可リスト照合は fetch より前に行う(verifier.ts の判定順)。
//
// **stale-while-revalidate**(2026-08-15): 再取得に失敗しても、猶予窓
// (STALE_GRACE_MS)内に取得できていた JWKS があればそれで検証を続ける。
// これは fail-closed(§14-1)と矛盾しない — 署名検証は必ず実施し、鍵が
// 1 つも無い場合にだけ拒否する。この設計にする理由は 2 つ:
//   1. issuer / ネットワークの一過性障害が、全プロジェクトの全 CI ジョブの
//      停止に直結するのを避ける(TTL 15 分に対し障害は数分〜数時間ありうる)
//   2. **未知 kid による強制リフレッシュを攻撃者が誘発できる**(kid は署名
//      検証の前に読まれる)。失敗した取得がキャッシュを破棄する設計だと、
//      未認証の攻撃者が存在しない kid を投げるだけで TTL 内の正常な鍵を
//      落とし、以後の正当なトークンを 503 に落とせてしまう。最後に成功した
//      JWKS を保持し、失敗が既存キャッシュを**決して**壊さない構造にする
//      (Cursor Bugbot の指摘と同じ経路 — PR #65)
// 猶予窓は「issuer が鍵を失効させてから、それを受理しなくなるまでの上限」でも
// あるため、可用性と失効追随のトレードオフとして明示的な定数に置く。
//
// 鍵が 1 つも無いときだけ拒否し、応答は 401 ではなく 503
// `oidc-jwks-unavailable` にする(errors/lease.ts の理由コード参照 — 一過性の
// 障害を「資格情報が不正」と伝えない)。
//
// キャッシュは isolate 内メモリ。DO ストレージにも D1 にも置かない:
// JWKS は公開情報であり、永続化しても得られるのは cold start 時の 1 往復の
// 節約だけで、保存物の管理コストに見合わない。

import { Effect } from "effect";

import { algorithmForJwk, importJwk, type Jwk } from "./jwk.ts";

/** discovery ドキュメントの TTL(jwks_uri は実質不変のため長く取る)。 */
const DISCOVERY_TTL_MS = 24 * 60 * 60 * 1000;
/** JWKS の TTL。 */
const JWKS_TTL_MS = 15 * 60 * 1000;
/**
 * 未知 kid による強制リフレッシュのクールダウン。鍵ローテーション直後の
 * 「TTL 内だが古い JWKS」を 1 往復で追随させつつ、存在しない kid を並べる
 * リクエストで issuer を叩き続けないようにする。
 */
const FORCED_REFRESH_COOLDOWN_MS = 60 * 1000;

/**
 * 再取得に失敗したときに、最後に成功した JWKS を使い続けてよい上限。
 * 可用性(issuer 障害中も CI を止めない)と失効追随(issuer が鍵を失効させて
 * から受理しなくなるまでの遅れ)のトレードオフであり、6 時間は現実的な障害
 * (数分〜数時間)を覆いつつ、失効の遅れを 1 日未満に抑える値として置く。
 */
const STALE_GRACE_MS = 6 * 60 * 60 * 1000;

/** 取得したドキュメントのサイズ上限(肥大応答によるメモリ消費の遮断)。 */
const MAX_DOCUMENT_BYTES = 256 * 1024;

/**
 * 1 回の取得のタイムアウト。未認証経路(リース)から誘発される外部 fetch で
 * あり、応答しない issuer にリクエストを張り付かせない(jose の
 * `timeoutDuration` 既定と同値)。
 */
const FETCH_TIMEOUT_MS = 5_000;

/** 解決済みの検証鍵(JWK と、その JWK から導いたアルゴリズム束縛)。 */
export interface ResolvedVerificationKey {
  readonly key: CryptoKey;
  readonly binding: NonNullable<ReturnType<typeof algorithmForJwk>>;
}

export interface JwksCacheShape {
  /**
   * issuer の JWKS から `kid` に対応する検証鍵を解決する。未知 kid は
   * クールダウン内で 1 度だけ強制リフレッシュしてから判定する(鍵ローテーション
   * 追随)。見つからなければ null(= 401 unknown-key)、取得自体に失敗したら
   * "jwks-unavailable"(= 503。理由は読まれず 503 へ写るだけなので、
   * server-key.ts の ResealFailure と同じ文字列リテラルの形にしている)。
   */
  readonly resolveKey: (
    issuer: string,
    kid: string | null,
  ) => Effect.Effect<ResolvedVerificationKey | null, "jwks-unavailable">;
}

interface CachedJwks {
  readonly keys: readonly Jwk[];
  readonly fetchedAtMs: number;
  readonly forcedRefreshAtMs: number;
}

interface CachedDiscovery {
  readonly jwksUri: string;
  readonly fetchedAtMs: number;
}

async function fetchJson(url: string): Promise<unknown> {
  const response = await fetch(url, {
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error("jwks fetch: non-ok response");
  }
  const text = await response.text();
  if (text.length > MAX_DOCUMENT_BYTES) {
    throw new Error("jwks fetch: document too large");
  }
  return JSON.parse(text) as unknown;
}

/**
 * discovery ドキュメントから `jwks_uri` を取り出す。**issuer の自己申告を
 * 検査する**: `issuer` フィールドが要求した issuer と一致し、`jwks_uri` が
 * その issuer と同一オリジンの https であること。issuer 自体は静的許可リスト
 * 由来で信頼できるが、そこから返る URL は取得先を任意に付け替えられる位置に
 * あるため、鍵の出所を issuer のオリジンに固定する。
 */
function jwksUriOf(document: unknown, issuer: string): string | null {
  if (typeof document !== "object" || document === null) {
    return null;
  }
  const record = document as Record<string, unknown>;
  if (record["issuer"] !== issuer) {
    return null;
  }
  const jwksUri = record["jwks_uri"];
  if (typeof jwksUri !== "string") {
    return null;
  }
  try {
    const parsed = new URL(jwksUri);
    return parsed.protocol === "https:" && parsed.origin === new URL(issuer).origin
      ? jwksUri
      : null;
  } catch {
    return null;
  }
}

function keysOf(document: unknown): readonly Jwk[] | null {
  if (typeof document !== "object" || document === null) {
    return null;
  }
  const keys = (document as Record<string, unknown>)["keys"];
  return Array.isArray(keys) ? (keys as readonly Jwk[]) : null;
}

/** `kid` に一致する使用可能な鍵を選ぶ(kid なしは鍵が 1 本のときだけ許す)。 */
function selectJwk(keys: readonly Jwk[], kid: string | null): Jwk | null {
  const usable = keys.filter((jwk) => algorithmForJwk(jwk) !== null);
  if (kid !== null) {
    return usable.find((jwk) => jwk.kid === kid) ?? null;
  }
  // kid のないトークンは、候補が一意に定まるときだけ受ける。複数鍵を総当たり
  // すると「どの鍵でも通る」検証になり、ローテーション中の鍵の同定が緩む
  return usable.length === 1 ? (usable[0] ?? null) : null;
}

/**
 * JWKS キャッシュ(isolate 単位)。worker 起動時に 1 回だけ構築する
 * (buildServices — index.ts)。並行リクエストは取得中の Promise を共有し、
 * cold start の突入で同じ issuer を同時に叩かない。
 */
export function makeJwksCache(now: () => number = Date.now): JwksCacheShape {
  // **最後に成功した値**と**取得中の Promise**を分けて持つ。失敗した取得が
  // 既存の good 値を壊さないための構造(冒頭コメントの 2 番目の理由)
  const lastGoodDiscovery = new Map<string, CachedDiscovery>();
  const lastGoodJwks = new Map<string, CachedJwks>();
  const inFlight = new Map<string, Promise<CachedJwks>>();
  const discoveryInFlight = new Map<string, Promise<CachedDiscovery>>();

  const loadDiscovery = async (issuer: string): Promise<CachedDiscovery> => {
    const document = await fetchJson(
      `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`,
    );
    const jwksUri = jwksUriOf(document, issuer);
    if (jwksUri === null) {
      throw new Error("jwks: discovery document rejected");
    }
    return { jwksUri, fetchedAtMs: now() };
  };

  /**
   * discovery は `jwks_uri` の解決にしか使わず、その値は実質不変。取得に
   * 失敗しても最後に成功した値があればそれを使い続ける(鮮度の上限は JWKS 側の
   * 猶予窓が握るため、ここに独立の窓は置かない)。
   */
  const discoveryFor = async (issuer: string): Promise<CachedDiscovery> => {
    const cached = lastGoodDiscovery.get(issuer);
    if (cached !== undefined && now() - cached.fetchedAtMs < DISCOVERY_TTL_MS) {
      return cached;
    }
    const pending =
      discoveryInFlight.get(issuer) ??
      loadDiscovery(issuer)
        .then((loaded) => {
          lastGoodDiscovery.set(issuer, loaded);
          return loaded;
        })
        .finally(() => discoveryInFlight.delete(issuer));
    discoveryInFlight.set(issuer, pending);
    try {
      return await pending;
    } catch (error) {
      if (cached !== undefined) {
        return cached;
      }
      throw error;
    }
  };

  const loadJwks = async (issuer: string, forcedRefreshAtMs: number): Promise<CachedJwks> => {
    const { jwksUri } = await discoveryFor(issuer);
    const keys = keysOf(await fetchJson(jwksUri));
    if (keys === null) {
      throw new Error("jwks: document has no keys array");
    }
    return { keys, fetchedAtMs: now(), forcedRefreshAtMs };
  };

  /**
   * キャッシュ済み JWKS をそのまま使えるか。TTL 内であっても、未知 kid の
   * ときはクールダウン付きで 1 度だけ取り直す(鍵ローテーション直後の追随 —
   * §14-1 の JWKS キャッシュ戦略)。
   */
  const isUsable = (cached: CachedJwks, kid: string | null): boolean => {
    if (now() - cached.fetchedAtMs >= JWKS_TTL_MS) {
      return false;
    }
    if (selectJwk(cached.keys, kid) !== null) {
      return true;
    }
    return now() - cached.forcedRefreshAtMs < FORCED_REFRESH_COOLDOWN_MS;
  };

  /** 取得中の Promise を共有する(cold start の突入で同じ issuer を同時に叩かない)。 */
  const refresh = (issuer: string, forcedRefreshAtMs: number): Promise<CachedJwks> => {
    const existing = inFlight.get(issuer);
    if (existing !== undefined) {
      return existing;
    }
    const pending = loadJwks(issuer, forcedRefreshAtMs)
      // good 値の更新は**成功時だけ**。失敗は既存の good 値に触れない
      .then((loaded) => {
        lastGoodJwks.set(issuer, loaded);
        return loaded;
      })
      .finally(() => inFlight.delete(issuer));
    inFlight.set(issuer, pending);
    return pending;
  };

  /**
   * 再取得の起点にする forcedRefreshAtMs。TTL 内なのに取り直す = 未知 kid に
   * よる強制リフレッシュなので、その時刻をクールダウンの起点として記録する
   * (TTL 切れの通常更新では据え置く)。
   */
  const forcedRefreshStamp = (cached: CachedJwks | undefined): number => {
    if (cached === undefined) {
      return 0;
    }
    return now() - cached.fetchedAtMs < JWKS_TTL_MS ? now() : cached.forcedRefreshAtMs;
  };

  /** 猶予窓内の good 値か(stale-while-revalidate の受理条件)。 */
  const isWithinGrace = (cached: CachedJwks | undefined): cached is CachedJwks =>
    cached !== undefined && now() - cached.fetchedAtMs < STALE_GRACE_MS;

  const jwksFor = async (issuer: string, kid: string | null): Promise<CachedJwks> => {
    const cached = lastGoodJwks.get(issuer);
    if (cached !== undefined && isUsable(cached, kid)) {
      return cached;
    }
    const forcedRefreshAtMs = forcedRefreshStamp(cached);
    try {
      return await refresh(issuer, forcedRefreshAtMs);
    } catch (error) {
      // stale-while-revalidate: 猶予窓内の good 値があればそれで検証を続ける。
      // 署名検証自体は必ず行われる(鍵が 1 つも無いときだけ拒否する)
      if (!isWithinGrace(cached)) {
        throw error;
      }
      // **失敗した強制リフレッシュもクールダウンの起点にする**(Cursor Bugbot の
      // 指摘への追加対応 — PR #65)。ここを据え置くと、未知 kid を連打する
      // 未認証の呼び出し元が 1 リクエストにつき 1 回 issuer を叩かせられる
      const held = { ...cached, forcedRefreshAtMs };
      lastGoodJwks.set(issuer, held);
      return held;
    }
  };

  return {
    resolveKey: (issuer, kid) =>
      Effect.tryPromise({
        try: async () => {
          const document = await jwksFor(issuer, kid);
          const jwk = selectJwk(document.keys, kid);
          if (jwk === null) {
            return null;
          }
          const binding = algorithmForJwk(jwk);
          if (binding === null) {
            return null;
          }
          const key = await importJwk(jwk, binding);
          return key === null ? null : { key, binding };
        },
        catch: () => "jwks-unavailable" as const,
      }),
  };
}
