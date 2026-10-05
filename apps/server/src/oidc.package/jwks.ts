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

import { Clock, Data, Deferred, Effect, Layer, Schema, Stream, SynchronizedRef } from "effect";
import { FetchHttpClient, HttpClient, HttpClientRequest, HttpClientResponse } from "effect/http";

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
 * Size limit of a fetched document (in **bytes**). Cut off by measured bytes
 * while reading the stream — `schemaBodyJson` buffers the whole body, so only
 * by stopping the stream at the threshold does this stay "cutting off memory
 * consumption by an oversized response".
 */
const MAX_DOCUMENT_BYTES = 256 * 1024;

/**
 * Timeout of one fetch. This is an outbound fetch triggered from the
 * unauthenticated path (leases); do not let a request hang on an issuer that
 * never responds (same value as jose's `timeoutDuration` default).
 */
const FETCH_TIMEOUT_MS = 5_000;

/**
 * Any failure that leaves no usable verification key (transport, non-OK
 * status, decode, oversize body, timeout, post-failure cooldown). Callers
 * map it to 503 `oidc-jwks-unavailable` — the same "transient, not 401"
 * shape the old `"jwks-unavailable"` literal carried; `reason` is
 * diagnostic only.
 */
class JwksUnavailableError extends Data.TaggedError("JwksUnavailable")<{
  readonly reason: "fetch" | "status" | "decode" | "too-large" | "timeout" | "cooldown";
}> {}

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
   * or fails with `JwksUnavailableError` when no usable key can be obtained at
   * all (= 503; the reason is never read, only mapped to a 503, so it takes
   * the same single-shape role as ResealFailure in server-key.ts).
   */
  readonly resolveKey: (
    issuer: string,
    kid: string | null,
  ) => Effect.Effect<ResolvedVerificationKey | null, JwksUnavailableError>;
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

/**
 * The whole cache state lives in one `SynchronizedRef` — the last successful
 * values, the failure timestamps, and the in-flight `Deferred`s that fold
 * concurrent same-issuer requests into one fetch (single-flight). Keeping
 * the last-good values and the in-flight markers in separate fields is what
 * keeps a failed fetch from corrupting an existing good value (the second
 * reason in the header comment).
 */
interface CacheState {
  readonly lastGoodDiscovery: Readonly<Record<string, CachedDiscovery>>;
  readonly lastGoodJwks: Readonly<Record<string, CachedJwks>>;
  readonly lastFailureAtMs: Readonly<Record<string, number>>;
  readonly jwksInFlight: Readonly<
    Record<string, Deferred.Deferred<CachedJwks, JwksUnavailableError>>
  >;
  readonly discoveryInFlight: Readonly<
    Record<string, Deferred.Deferred<CachedDiscovery, JwksUnavailableError>>
  >;
}

const emptyCacheState: CacheState = {
  lastGoodDiscovery: {},
  lastGoodJwks: {},
  lastFailureAtMs: {},
  jwksInFlight: {},
  discoveryInFlight: {},
};

/** Drop one key from an immutable record copy. */
function dropKey<T>(record: Readonly<Record<string, T>>, key: string): Readonly<Record<string, T>> {
  const next = { ...record };
  delete next[key];
  return next;
}

/** The discovery document's fields the pin checks read (issuer + jwks_uri). */
const DiscoveryDocument = Schema.Struct({
  issuer: Schema.String,
  jwks_uri: Schema.String,
});

/**
 * The JWKS document. Entries stay `unknown` and are narrowed to objects by
 * `isJwk` — a non-object entry is unusable and gets skipped by selection
 * rather than rejecting the whole set (issuers may publish keys we cannot
 * use).
 */
const JwksDocument = Schema.Struct({
  keys: Schema.Array(Schema.Unknown),
});

/** A decoded JWKS entry is usable only when it is a JSON object. */
const isJwk = (value: unknown): value is Jwk => typeof value === "object" && value !== null;

/**
 * The `HttpClient` layer the package's fetches run on when no layer is
 * passed. `redirect: "manual"` is kept via `FetchHttpClient.RequestInit`:
 * **never follow redirects** — the check pinning `jwks_uri` to the issuer's
 * origin (jwksUriOf) is an explicit security control, and following a 302
 * to another origin would defeat the pinning. A 3xx is rejected by the
 * status check in fetchJson.
 */
const defaultHttpClientLayer = FetchHttpClient.layer.pipe(
  Layer.provide(Layer.succeed(FetchHttpClient.RequestInit, { redirect: "manual" })),
);

/**
 * GET `url` and decode the JSON body with `schema` via
 * `HttpClientResponse.schemaBodyJson` (typed decoding — no `as` casts).
 * The byte cap reads the body as a stream and stops at MAX_DOCUMENT_BYTES
 * before wrapping it back into a `Response` — the same early-abort bound
 * the pre-Effect reader loop gave. The FETCH_TIMEOUT_MS timeout covers the
 * request **and** the body read, matching the old `AbortSignal.timeout`.
 */
const fetchJson = <S extends Schema.Constraint>(
  url: string,
  schema: S,
): Effect.Effect<S["Type"], JwksUnavailableError, HttpClient.HttpClient | S["DecodingServices"]> =>
  Effect.gen(function* () {
    const client = yield* HttpClient.HttpClient;
    // Inside this region every error is foreign — transport, a hung issuer,
    // schema decode — so the pipeline below normalizes them wholesale. Our
    // own verdicts stay in the success channel as strings and become typed
    // errors only outside it (no instanceof discrimination needed).
    const outcome = yield* Effect.gen(function* () {
      const response = yield* client.execute(
        HttpClientRequest.get(url, { headers: { accept: "application/json" } }),
      );
      if (response.status < 200 || response.status >= 300) {
        return "status" as const;
      }
      const chunks: Uint8Array[] = [];
      let total = 0;
      yield* Stream.runForEachWhile(response.stream, (chunk) =>
        Effect.sync(() => {
          chunks.push(chunk);
          total += chunk.length;
          return total <= MAX_DOCUMENT_BYTES;
        }),
      );
      if (total > MAX_DOCUMENT_BYTES) {
        return "too-large" as const;
      }
      const merged = new Uint8Array(total);
      let offset = 0;
      for (const chunk of chunks) {
        merged.set(chunk, offset);
        offset += chunk.length;
      }
      const bounded = HttpClientResponse.fromWeb(
        response.request,
        new Response(merged, { status: response.status, headers: response.headers }),
      );
      return { document: yield* HttpClientResponse.schemaBodyJson(schema)(bounded) } as const;
    }).pipe(
      Effect.timeout(FETCH_TIMEOUT_MS),
      Effect.catchTags({
        TimeoutError: () => Effect.fail(new JwksUnavailableError({ reason: "timeout" })),
        SchemaError: () => Effect.fail(new JwksUnavailableError({ reason: "decode" })),
      }),
      Effect.mapError(() => new JwksUnavailableError({ reason: "fetch" })),
    );
    if (typeof outcome === "string") {
      return yield* Effect.fail(new JwksUnavailableError({ reason: outcome }));
    }
    return outcome.document;
  });

/**
 * Extract `jwks_uri` from a decoded discovery document. **Verify the
 * issuer's self-declaration**: the `issuer` field must equal the requested
 * issuer, and `jwks_uri` must be https on the same origin as that issuer.
 * The issuer itself is trustworthy because it comes from the static
 * allowlist, but a URL returned by it sits in a position where the fetch
 * target could be swapped arbitrarily, so pin the keys' provenance to the
 * issuer's origin.
 */
function jwksUriOf(document: typeof DiscoveryDocument.Type, issuer: string): string | null {
  if (document.issuer !== issuer) {
    return null;
  }
  try {
    const parsed = new URL(document.jwks_uri);
    return parsed.protocol === "https:" && parsed.origin === new URL(issuer).origin
      ? document.jwks_uri
      : null;
  } catch {
    return null;
  }
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

const loadDiscovery = (
  issuer: string,
): Effect.Effect<CachedDiscovery, JwksUnavailableError, HttpClient.HttpClient> =>
  Effect.gen(function* () {
    const document = yield* fetchJson(
      `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`,
      DiscoveryDocument,
    );
    const jwksUri = jwksUriOf(document, issuer);
    if (jwksUri === null) {
      return yield* Effect.fail(new JwksUnavailableError({ reason: "decode" }));
    }
    return { jwksUri, fetchedAtMs: yield* Clock.currentTimeMillis };
  });

/**
 * Whether the cached JWKS can be used as-is. Even inside the TTL, an unknown
 * kid triggers exactly one re-fetch under a cooldown (following a key
 * rotation right after it happens — the §14-1 JWKS cache strategy).
 */
const isUsable = (cached: CachedJwks, kid: string | null, nowMs: number): boolean => {
  if (nowMs - cached.fetchedAtMs >= JWKS_TTL_MS) {
    return false;
  }
  if (selectJwk(cached.keys, kid) !== null) {
    return true;
  }
  return nowMs - cached.forcedRefreshAtMs < FORCED_REFRESH_COOLDOWN_MS;
};

/**
 * The forcedRefreshAtMs to seed a refresh with. A re-fetch inside the TTL
 * means a forced refresh triggered by an unknown kid, so record that time as
 * the cooldown's origin (a normal TTL-expired refresh leaves it unchanged).
 */
const forcedRefreshStamp = (cached: CachedJwks | undefined, nowMs: number): number => {
  if (cached === undefined) {
    return 0;
  }
  return nowMs - cached.fetchedAtMs < JWKS_TTL_MS ? nowMs : cached.forcedRefreshAtMs;
};

/** Whether a good value is inside the grace window (the stale-while-revalidate acceptance condition). */
const isWithinGrace = (cached: CachedJwks | undefined, nowMs: number): cached is CachedJwks =>
  cached !== undefined && nowMs - cached.fetchedAtMs < STALE_GRACE_MS;

/**
 * One keyed in-flight record's slice of `CacheState`: which record the
 * single-flight `Deferred`s live in, and where a successful load lands.
 * Discovery and JWKS share the same register-or-join machinery through
 * these accessors (`Deferred` is invariant in its value type, so the slot
 * picks the concrete record rather than the record being generic).
 */
interface InFlightSlot<A> {
  readonly inFlightOf: (
    state: CacheState,
  ) => Readonly<Record<string, Deferred.Deferred<A, JwksUnavailableError>>>;
  readonly setInFlight: (
    state: CacheState,
    inFlight: Readonly<Record<string, Deferred.Deferred<A, JwksUnavailableError>>>,
  ) => CacheState;
  readonly setLoaded: (state: CacheState, issuer: string, loaded: A) => CacheState;
}

const discoverySlot: InFlightSlot<CachedDiscovery> = {
  inFlightOf: (state) => state.discoveryInFlight,
  setInFlight: (state, inFlight) => ({ ...state, discoveryInFlight: inFlight }),
  setLoaded: (state, issuer, loaded) => ({
    ...state,
    lastGoodDiscovery: { ...state.lastGoodDiscovery, [issuer]: loaded },
    discoveryInFlight: dropKey(state.discoveryInFlight, issuer),
  }),
};

const jwksSlot: InFlightSlot<CachedJwks> = {
  inFlightOf: (state) => state.jwksInFlight,
  setInFlight: (state, inFlight) => ({ ...state, jwksInFlight: inFlight }),
  setLoaded: (state, issuer, loaded) => ({
    ...state,
    lastGoodJwks: { ...state.lastGoodJwks, [issuer]: loaded },
    jwksInFlight: dropKey(state.jwksInFlight, issuer),
  }),
};

/**
 * The JWKS cache (per isolate). Built once at worker startup (buildServices —
 * index.ts). The `SynchronizedRef`/`Deferred`s are `makeUnsafe` so the
 * constructor stays synchronous; concurrent requests share the in-flight
 * `Deferred`, so a cold-start rush does not hit the same issuer
 * simultaneously.
 */
export function makeJwksCache(
  httpClientLayer: Layer.Layer<HttpClient.HttpClient> = defaultHttpClientLayer,
): JwksCacheShape {
  const state = SynchronizedRef.makeUnsafe(emptyCacheState);

  /**
   * Single-flight over `state`: join the in-flight `Deferred` for `issuer`,
   * or — as the first arrival — run `load` on a detached fiber exactly
   * once. Detached like the old shared Promise: the load must not die with
   * the requester that happened to start it — every joiner awaits the same
   * Deferred, and the finalization inside always completes it. The whole
   * register-and-fork step is uninterruptible so no joiner can strand a
   * Deferred that never completes.
   */
  const singleFlight = <A>(
    issuer: string,
    slot: InFlightSlot<A>,
    load: Effect.Effect<A, JwksUnavailableError, HttpClient.HttpClient>,
  ): Effect.Effect<Deferred.Deferred<A, JwksUnavailableError>, never, HttpClient.HttpClient> =>
    Effect.uninterruptible(
      Effect.gen(function* () {
        const [created, winner] = yield* SynchronizedRef.modify(
          state,
          (
            current,
          ): readonly [
            readonly [Deferred.Deferred<A, JwksUnavailableError>, boolean],
            CacheState,
          ] => {
            const existing = slot.inFlightOf(current)[issuer];
            if (existing !== undefined) {
              return [[existing, false], current];
            }
            const made = Deferred.makeUnsafe<A, JwksUnavailableError>();
            return [
              [made, true],
              slot.setInFlight(current, { ...slot.inFlightOf(current), [issuer]: made }),
            ];
          },
        );
        if (winner) {
          yield* Effect.forkDetach(
            Effect.matchEffect(load, {
              onSuccess: (loaded) =>
                Effect.andThen(
                  SynchronizedRef.update(state, (current) =>
                    slot.setLoaded(current, issuer, loaded),
                  ),
                  Deferred.succeed(created, loaded),
                ),
              onFailure: (error) =>
                Effect.andThen(
                  SynchronizedRef.update(state, (current) =>
                    slot.setInFlight(current, dropKey(slot.inFlightOf(current), issuer)),
                  ),
                  Deferred.fail(created, error),
                ),
            }),
          );
        }
        return created;
      }),
    );

  /**
   * discovery is used only to resolve `jwks_uri`, and that value is
   * effectively immutable. If a fetch fails but a last-successful value
   * exists, keep using it (the freshness bound is held by the JWKS-side grace
   * window, so no separate window lives here).
   */
  const discoveryFor = (
    issuer: string,
  ): Effect.Effect<CachedDiscovery, JwksUnavailableError, HttpClient.HttpClient> =>
    Effect.gen(function* () {
      const nowMs = yield* Clock.currentTimeMillis;
      const snapshot = yield* SynchronizedRef.get(state);
      const cached = snapshot.lastGoodDiscovery[issuer];
      if (cached !== undefined && nowMs - cached.fetchedAtMs < DISCOVERY_TTL_MS) {
        return cached;
      }
      const deferred = yield* singleFlight(issuer, discoverySlot, loadDiscovery(issuer));
      return yield* Effect.matchEffect(Deferred.await(deferred), {
        onSuccess: Effect.succeed,
        onFailure: (error) => (cached !== undefined ? Effect.succeed(cached) : Effect.fail(error)),
      });
    });

  const loadJwks = (
    issuer: string,
    forcedRefreshAtMs: number,
  ): Effect.Effect<CachedJwks, JwksUnavailableError, HttpClient.HttpClient> =>
    Effect.gen(function* () {
      const { jwksUri } = yield* discoveryFor(issuer);
      const document = yield* fetchJson(jwksUri, JwksDocument);
      const keys = document.keys.filter(isJwk);
      return { keys, fetchedAtMs: yield* Clock.currentTimeMillis, forcedRefreshAtMs };
    });

  const jwksFor = (
    issuer: string,
    kid: string | null,
  ): Effect.Effect<CachedJwks, JwksUnavailableError, HttpClient.HttpClient> =>
    Effect.gen(function* () {
      const nowMs = yield* Clock.currentTimeMillis;
      const snapshot = yield* SynchronizedRef.get(state);
      const cached = snapshot.lastGoodJwks[issuer];
      if (cached !== undefined && isUsable(cached, kid, nowMs)) {
        return cached;
      }
      // If the latest refresh failed, do not re-hit the issuer until the
      // cooldown ends. In the "TTL expired + issuer down" state `isUsable`
      // returns false at its first branch (the TTL) and never reaches the
      // forced-refresh cooldown, so the failure side needs its own interval
      const failedAt = snapshot.lastFailureAtMs[issuer];
      if (failedAt !== undefined && nowMs - failedAt < FAILED_REFRESH_COOLDOWN_MS) {
        if (isWithinGrace(cached, nowMs)) {
          return cached;
        }
        return yield* Effect.fail(new JwksUnavailableError({ reason: "cooldown" }));
      }
      const forcedRefreshAtMs = forcedRefreshStamp(cached, nowMs);

      const deferred = yield* singleFlight(issuer, jwksSlot, loadJwks(issuer, forcedRefreshAtMs));
      return yield* Effect.matchEffect(Deferred.await(deferred), {
        onSuccess: (loaded) =>
          Effect.as(
            SynchronizedRef.update(state, (current) => ({
              ...current,
              lastFailureAtMs: dropKey(current.lastFailureAtMs, issuer),
            })),
            loaded,
          ),
        onFailure: (error) =>
          Effect.gen(function* () {
            const failureAtMs = yield* Clock.currentTimeMillis;
            yield* SynchronizedRef.update(state, (current) => ({
              ...current,
              lastFailureAtMs: { ...current.lastFailureAtMs, [issuer]: failureAtMs },
            }));
            // stale-while-revalidate: if a good value is inside the grace
            // window, keep verifying with it. Signature verification itself
            // always runs (rejection only happens when no key is available at
            // all)
            if (!isWithinGrace(cached, failureAtMs)) {
              return yield* Effect.fail(error);
            }
            // **A failed forced refresh also becomes a cooldown origin**. An
            // invariant independent of the failure cooldown above, so that
            // hammering unknown kids inside the TTL does not become one fetch
            // per request
            const held = { ...cached, forcedRefreshAtMs };
            yield* SynchronizedRef.update(state, (current) => ({
              ...current,
              lastGoodJwks: { ...current.lastGoodJwks, [issuer]: held },
            }));
            return held;
          }),
      });
    });

  return {
    resolveKey: (issuer, kid) =>
      Effect.gen(function* () {
        const document = yield* jwksFor(issuer, kid);
        const jwk = selectJwk(document.keys, kid);
        if (jwk === null) {
          return null;
        }
        const binding = algorithmForJwk(jwk);
        if (binding === null) {
          return null;
        }
        const key = yield* Effect.promise(() => importJwk(jwk, binding));
        return key === null ? null : { key, binding };
      }).pipe(Effect.provide(httpClientLayer)),
  };
}
