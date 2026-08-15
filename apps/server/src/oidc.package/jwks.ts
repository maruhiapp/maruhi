// OIDC discovery + JWKS の取得と TTL キャッシュ(AUTH_SPEC §14-1)。
//
// 取得先は**対応 issuer 一覧(静的設定)に含まれる issuer だけ**である。
// この順序は DoS 上重要で、リースエンドポイントは未認証(§14-1)であるため、
// 任意の issuer 文字列で外部 fetch を誘発できると増幅攻撃になる。issuer の
// 許可リスト照合は fetch より前に行う(verifier.ts の判定順)。
//
// 取得失敗は fail-closed(§14-1)。ただし応答は 401 ではなく 503
// `oidc-jwks-unavailable` にする(errors/lease.ts の理由コード参照 — 一過性の
// 障害を「資格情報が不正」と伝えない)。
//
// キャッシュは isolate 内メモリ。DO ストレージにも D1 にも置かない:
// JWKS は公開情報であり、永続化しても得られるのは cold start 時の 1 往復の
// 節約だけで、失効した鍵を掴み続ける危険と保存物の管理コストに見合わない。

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

/** 取得したドキュメントのサイズ上限(肥大応答によるメモリ消費の遮断)。 */
const MAX_DOCUMENT_BYTES = 256 * 1024;

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
  const response = await fetch(url, { headers: { accept: "application/json" } });
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
  const discovery = new Map<string, Promise<CachedDiscovery>>();
  const jwks = new Map<string, Promise<CachedJwks>>();

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

  const discoveryFor = async (issuer: string): Promise<CachedDiscovery> => {
    const cached = discovery.get(issuer);
    if (cached !== undefined) {
      const settled = await cached.catch(() => null);
      if (settled !== null && now() - settled.fetchedAtMs < DISCOVERY_TTL_MS) {
        return settled;
      }
    }
    const pending = loadDiscovery(issuer);
    discovery.set(issuer, pending);
    // 失敗した Promise を残すと以後の再取得まで同じ失敗を返し続けるため捨てる
    // (後続の取得がすでにエントリを差し替えていたら消さない)
    pending.catch(() => {
      if (discovery.get(issuer) === pending) {
        discovery.delete(issuer);
      }
    });
    return pending;
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

  const jwksFor = async (issuer: string, kid: string | null): Promise<CachedJwks> => {
    const cached = await (jwks.get(issuer)?.catch(() => null) ?? Promise.resolve(null));
    if (cached !== null && isUsable(cached, kid)) {
      return cached;
    }
    // TTL 内なのに取り直す = 未知 kid による強制リフレッシュ。その時刻を
    // 記録してクールダウンの起点にする(TTL 切れの通常更新では据え置く)
    const forced = cached !== null && now() - cached.fetchedAtMs < JWKS_TTL_MS;
    const forcedRefreshAtMs = forced ? now() : (cached?.forcedRefreshAtMs ?? 0);
    // 強制リフレッシュの失敗では TTL 内の旧ドキュメントへ巻き戻す(クール
    // ダウンだけ進める): kid は署名検証前の攻撃者制御値であり、偽 kid の
    // 失敗取得で有効なキャッシュを失うと既知鍵の検証まで 503 に落ちる
    const entry: Promise<CachedJwks> = loadJwks(issuer, forcedRefreshAtMs).catch((error) => {
      if (forced && cached !== null) {
        return { ...cached, forcedRefreshAtMs };
      }
      throw error;
    });
    jwks.set(issuer, entry);
    // 失敗した Promise を残すと以後の再取得まで同じ失敗を返し続けるため捨てる
    // (後続の取得がすでにエントリを差し替えていたら消さない)
    entry.catch(() => {
      if (jwks.get(issuer) === entry) {
        jwks.delete(issuer);
      }
    });
    return entry;
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
