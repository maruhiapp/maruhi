// OIDC discovery + JWKS fetch with a TTL cache (AUTH_SPEC §14-1).
//
// The fetch target is **only issuers listed in the supported-issuer list
// (static configuration)**. This ordering matters for DoS: the lease endpoint
// is unauthenticated (§14-1), so letting an arbitrary issuer string trigger an
// outbound fetch would be an amplification attack. The issuer allowlist check
// runs before any fetch (the check order in verifier.ts).
//
// **stale-while-revalidate**: even when a refresh fails, if a JWKS was fetched
// within the grace window (STALE_GRACE_MS) verification continues with it.
// This does not contradict fail-closed (§14-1) — signature verification is
// always performed, and rejection happens only when no key is available at
// all. Two reasons for this design:
//   1. A transient issuer / network failure must not directly stop every CI
//      job of every project (against a 15-minute TTL, outages can run from
//      minutes to hours)
//   2. **An attacker can trigger a forced refresh via an unknown kid** (the kid
//      is read before signature verification). If a failed fetch discarded the
//      cache, an unauthenticated attacker could just throw a nonexistent kid to
//      drop the good keys inside their TTL and force 503s on subsequent
//      legitimate tokens. Keep the last successful JWKS and build so that a
//      failure **never** corrupts the existing cache
// The grace window is also "the upper bound between an issuer revoking a key
// and us stopping accepting it", so it is an explicit constant trading off
// availability against revocation lag.
//
// Reject only when no key is available at all, and answer 503
// `oidc-jwks-unavailable` rather than 401 (see the reason code in
// errors/lease.ts — a transient failure must not be reported as "bad
// credentials").
//
// The cache is in-isolate memory. It lives in neither DO storage nor D1: a
// JWKS is public information, and persisting it only saves one round trip on
// cold start — not worth the management cost of stored data.

import { Effect } from "effect";

import { algorithmForJwk, importJwk, type Jwk } from "./jwk.ts";

/** TTL of a discovery document (jwks_uri is effectively immutable, so it is long). */
const DISCOVERY_TTL_MS = 24 * 60 * 60 * 1000;
/** TTL of a JWKS. */
const JWKS_TTL_MS = 15 * 60 * 1000;
/**
 * Cooldown for a forced refresh triggered by an unknown kid. Lets the "within
 * TTL but stale JWKS" right after a key rotation catch up in one round trip,
 * while requests listing nonexistent kids cannot keep hammering the issuer.
 */
const FORCED_REFRESH_COOLDOWN_MS = 60 * 1000;

/**
 * Interval after a **failed** refresh before the next refresh is attempted.
 * While an issuer is down, `fetchedAtMs` stays past the TTL, so without this,
 * for the rest of the grace window (just under 6 hours at most) "one
 * unauthenticated request = one outbound fetch to the issuer (5-second timeout
 * each)" would persist. `inFlight` folds only **concurrent** requests;
 * sequential requests are not folded. Amplification bites exactly when the
 * issuer is already weakened — the shape we least want.
 */
const FAILED_REFRESH_COOLDOWN_MS = 60 * 1000;

/**
 * The upper bound for how long the last successful JWKS may keep being used
 * after a refresh failure. It trades off availability (do not stop CI during
 * an issuer outage) against revocation lag (the delay between an issuer
 * revoking a key and us stopping accepting it); 6 hours covers realistic
 * outages (minutes to hours) while keeping revocation lag under a day.
 */
const STALE_GRACE_MS = 6 * 60 * 60 * 1000;

/**
 * Size limit of a fetched document (in **bytes**). Cut off by measured bytes —
 * the result length of `Response.text()` is in UTF-16 code units, not bytes,
 * and by that point the whole body is already in memory. Only by aborting on
 * threshold overflow while reading the stream does this become "cutting off
 * memory consumption by an oversized response".
 */
const MAX_DOCUMENT_BYTES = 256 * 1024;

/**
 * Timeout of one fetch. This is an outbound fetch triggered from the
 * unauthenticated path (leases); do not let a request hang on an issuer that
 * never responds (same value as jose's `timeoutDuration` default).
 */
const FETCH_TIMEOUT_MS = 5_000;

/** A resolved verification key (a JWK and the algorithm binding derived from it). */
export interface ResolvedVerificationKey {
  readonly key: CryptoKey;
  readonly binding: NonNullable<ReturnType<typeof algorithmForJwk>>;
}

export interface JwksCacheShape {
  /**
   * Resolve the verification key for `kid` from the issuer's JWKS. An unknown
   * kid triggers one forced refresh within the cooldown before the verdict
   * (key-rotation follow-up). Returns null if not found (= 401 unknown-key),
   * or "jwks-unavailable" when no usable key can be obtained at all (= 503;
   * the reason is never read, only mapped to a 503, so it takes the same
   * string-literal shape as ResealFailure in server-key.ts).
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

/** Read up to the byte limit; abort on overflow (overflow throws). */
async function readWithinLimit(body: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    total += value.length;
    if (total > MAX_DOCUMENT_BYTES) {
      await reader.cancel();
      throw new Error("jwks fetch: document too large");
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.length;
  }
  return merged;
}

async function fetchJson(url: string): Promise<unknown> {
  const response = await fetch(url, {
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    // **Never follow redirects**: the check pinning `jwks_uri` to the issuer's
    // origin (jwksUriOf) is an explicit security control, and following a 302
    // to another origin would defeat the pinning. A 3xx is rejected via
    // ok=false
    redirect: "manual",
  });
  if (!response.ok || response.body === null) {
    throw new Error("jwks fetch: non-ok response");
  }
  const bytes = await readWithinLimit(response.body);
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
}

/**
 * Extract `jwks_uri` from a discovery document. **Verify the issuer's
 * self-declaration**: the `issuer` field must equal the requested issuer, and
 * `jwks_uri` must be https on the same origin as that issuer. The issuer
 * itself is trustworthy because it comes from the static allowlist, but a URL
 * returned by it sits in a position where the fetch target could be swapped
 * arbitrarily, so pin the keys' provenance to the issuer's origin.
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

/** Pick the usable key matching `kid` (a missing kid is allowed only when there is exactly one key). */
function selectJwk(keys: readonly Jwk[], kid: string | null): Jwk | null {
  const usable = keys.filter((jwk) => algorithmForJwk(jwk) !== null);
  if (kid !== null) {
    return usable.find((jwk) => jwk.kid === kid) ?? null;
  }
  // A token without a kid is accepted only when the candidate is uniquely
  // determined. Trying every key would make verification "any key passes" and
  // loosen key identification during rotation
  return usable.length === 1 ? (usable[0] ?? null) : null;
}

/**
 * The JWKS cache (per isolate). Built once at worker startup (buildServices —
 * index.ts). Concurrent requests share the in-flight Promise, so a cold-start
 * rush does not hit the same issuer simultaneously.
 */
export function makeJwksCache(now: () => number = Date.now): JwksCacheShape {
  // Keep **the last successful value** and **the in-flight Promise** in
  // separate maps. The structure that keeps a failed fetch from corrupting the
  // existing good value (the second reason in the header comment)
  const lastGoodDiscovery = new Map<string, CachedDiscovery>();
  const lastGoodJwks = new Map<string, CachedJwks>();
  // The time of the most recent failed refresh (thins out retries while the
  // issuer is down). Cleared on success
  const lastFailureAtMs = new Map<string, number>();
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
   * discovery is used only to resolve `jwks_uri`, and that value is
   * effectively immutable. If a fetch fails but a last-successful value
   * exists, keep using it (the freshness bound is held by the JWKS-side grace
   * window, so no separate window lives here).
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
   * Whether the cached JWKS can be used as-is. Even inside the TTL, an unknown
   * kid triggers exactly one re-fetch under a cooldown (following a key
   * rotation right after it happens — the §14-1 JWKS cache strategy).
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

  /** Share the in-flight Promise (a cold-start rush must not hit the same issuer simultaneously). */
  const refresh = (issuer: string, forcedRefreshAtMs: number): Promise<CachedJwks> => {
    const existing = inFlight.get(issuer);
    if (existing !== undefined) {
      return existing;
    }
    const pending = loadJwks(issuer, forcedRefreshAtMs)
      // The good value updates **only on success**; a failure never touches it
      .then((loaded) => {
        lastGoodJwks.set(issuer, loaded);
        return loaded;
      })
      .finally(() => inFlight.delete(issuer));
    inFlight.set(issuer, pending);
    return pending;
  };

  /**
   * The forcedRefreshAtMs to seed a refresh with. A re-fetch inside the TTL
   * means a forced refresh triggered by an unknown kid, so record that time as
   * the cooldown's origin (a normal TTL-expired refresh leaves it unchanged).
   */
  const forcedRefreshStamp = (cached: CachedJwks | undefined): number => {
    if (cached === undefined) {
      return 0;
    }
    return now() - cached.fetchedAtMs < JWKS_TTL_MS ? now() : cached.forcedRefreshAtMs;
  };

  /** Whether a good value is inside the grace window (the stale-while-revalidate acceptance condition). */
  const isWithinGrace = (cached: CachedJwks | undefined): cached is CachedJwks =>
    cached !== undefined && now() - cached.fetchedAtMs < STALE_GRACE_MS;

  const jwksFor = async (issuer: string, kid: string | null): Promise<CachedJwks> => {
    const cached = lastGoodJwks.get(issuer);
    if (cached !== undefined && isUsable(cached, kid)) {
      return cached;
    }
    // If the latest refresh failed, do not re-hit the issuer until the
    // cooldown ends. In the "TTL expired + issuer down" state `isUsable`
    // returns false at its first branch (the TTL) and never reaches the
    // forced-refresh cooldown, so the failure side needs its own interval
    const failedAt = lastFailureAtMs.get(issuer);
    if (failedAt !== undefined && now() - failedAt < FAILED_REFRESH_COOLDOWN_MS) {
      if (isWithinGrace(cached)) {
        return cached;
      }
      throw new Error("jwks: refresh is cooling down after a failure");
    }
    const forcedRefreshAtMs = forcedRefreshStamp(cached);
    try {
      const loaded = await refresh(issuer, forcedRefreshAtMs);
      lastFailureAtMs.delete(issuer);
      return loaded;
    } catch (error) {
      lastFailureAtMs.set(issuer, now());
      // stale-while-revalidate: if a good value is inside the grace window,
      // keep verifying with it. Signature verification itself always runs
      // (rejection only happens when no key is available at all)
      if (!isWithinGrace(cached)) {
        throw error;
      }
      // **A failed forced refresh also becomes a cooldown origin**. An
      // invariant independent of the failure cooldown above, so that hammering
      // unknown kids inside the TTL does not become one fetch per request
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
