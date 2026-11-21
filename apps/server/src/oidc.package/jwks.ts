import { egressHttpClientLayer } from "@maruhi/core";
import {
  Clock,
  Data,
  Deferred,
  Effect,
  Exit,
  Option,
  Schema,
  Stream,
  SynchronizedRef,
} from "effect";
import { HttpClient, HttpClientRequest, HttpClientResponse } from "effect/http";
import { Jwk } from "effect/jose";

type JwkRecord = Readonly<Record<string, unknown>>;

const declaresAlg = (jwk: JwkRecord, allowed: "RS256" | "ES256"): boolean =>
  jwk["alg"] === undefined || jwk["alg"] === allowed;

function algorithmForJwk(jwk: JwkRecord): "RS256" | "ES256" | null {
  if (jwk["use"] !== undefined && jwk["use"] !== "sig") {
    return null;
  }
  if (jwk["kty"] === "RSA") {
    return declaresAlg(jwk, "RS256") ? "RS256" : null;
  }
  if (jwk["kty"] === "EC" && jwk["crv"] === "P-256") {
    return declaresAlg(jwk, "ES256") ? "ES256" : null;
  }
  return null;
}

const DISCOVERY_TTL_MS = 24 * 60 * 60 * 1000;
const JWKS_TTL_MS = 15 * 60 * 1000;
const FORCED_REFRESH_COOLDOWN_MS = 60 * 1000;

const FAILED_REFRESH_COOLDOWN_MS = 60 * 1000;

const STALE_GRACE_MS = 6 * 60 * 60 * 1000;

const MAX_DOCUMENT_BYTES = 256 * 1024;

const FETCH_TIMEOUT_MS = 5_000;

class JwksUnavailableError extends Data.TaggedError("JwksUnavailable")<{
  readonly reason: "fetch" | "status" | "decode" | "too-large" | "timeout" | "cooldown";
}> {}

export interface ResolvedVerificationKey {
  readonly key: Jwk.PublicKey;
}

export interface JwksCacheShape {
  readonly resolveKey: (
    issuer: string,
    kid: string | null,
  ) => Effect.Effect<ResolvedVerificationKey | null, JwksUnavailableError>;
}

interface CachedJwks {
  readonly keys: readonly JwkRecord[];
  readonly fetchedAtMs: number;
  readonly forcedRefreshAtMs: number;
}

interface CachedDiscovery {
  readonly jwksUri: string;
  readonly fetchedAtMs: number;
}

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

function dropKey<T>(record: Readonly<Record<string, T>>, key: string): Readonly<Record<string, T>> {
  const next = { ...record };
  delete next[key];
  return next;
}

const DiscoveryDocument = Schema.Struct({
  issuer: Schema.String,
  jwks_uri: Schema.String,
});

const JwksDocument = Schema.Struct({
  keys: Schema.Array(Schema.Record(Schema.String, Schema.Unknown)),
});

const defaultHttpClientLayer = egressHttpClientLayer({ redirect: "manual" });

const utf8FatalDecoder = new TextDecoder("utf-8", { fatal: true });

const fetchJson = Effect.fn("jwks.fetchJson")(function* <S extends Schema.Constraint>(
  url: string,
  schema: S,
): Effect.fn.Return<
  S["Type"],
  JwksUnavailableError,
  HttpClient.HttpClient | S["DecodingServices"]
> {
  const client = yield* HttpClient.HttpClient;
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
    yield* Effect.try({
      try: () => utf8FatalDecoder.decode(merged),
      catch: () => new JwksUnavailableError({ reason: "decode" }),
    });
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
      HttpClientError: () => Effect.fail(new JwksUnavailableError({ reason: "fetch" })),
    }),
  );
  if (typeof outcome === "string") {
    return yield* Effect.fail(new JwksUnavailableError({ reason: outcome }));
  }
  return outcome.document;
});

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

function selectJwk(keys: readonly JwkRecord[], kid: string | null): JwkRecord | null {
  const usable = keys.filter((jwk) => algorithmForJwk(jwk) !== null);
  if (kid !== null) {
    return usable.find((jwk) => jwk["kid"] === kid) ?? null;
  }
  return usable.length === 1 ? (usable[0] ?? null) : null;
}

const loadDiscovery = Effect.fn("jwks.loadDiscovery")(function* (
  issuer: string,
): Effect.fn.Return<CachedDiscovery, JwksUnavailableError, HttpClient.HttpClient> {
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

const isUsable = (cached: CachedJwks, kid: string | null, nowMs: number): boolean => {
  if (nowMs - cached.fetchedAtMs >= JWKS_TTL_MS) {
    return false;
  }
  if (selectJwk(cached.keys, kid) !== null) {
    return true;
  }
  return nowMs - cached.forcedRefreshAtMs < FORCED_REFRESH_COOLDOWN_MS;
};

const forcedRefreshStamp = (cached: CachedJwks | undefined, nowMs: number): number => {
  if (cached === undefined) {
    return 0;
  }
  return nowMs - cached.fetchedAtMs < JWKS_TTL_MS ? nowMs : cached.forcedRefreshAtMs;
};

const isWithinGrace = (cached: CachedJwks | undefined, nowMs: number): cached is CachedJwks =>
  cached !== undefined && nowMs - cached.fetchedAtMs < STALE_GRACE_MS;

interface InFlightSlot<A> {
  readonly inFlightOf: (
    state: CacheState,
  ) => Readonly<Record<string, Deferred.Deferred<A, JwksUnavailableError>>>;
  readonly setInFlight: (
    state: CacheState,
    inFlight: Readonly<Record<string, Deferred.Deferred<A, JwksUnavailableError>>>,
  ) => CacheState;
}

const discoverySlot: InFlightSlot<CachedDiscovery> = {
  inFlightOf: (state) => state.discoveryInFlight,
  setInFlight: (state, inFlight) => ({ ...state, discoveryInFlight: inFlight }),
};

const jwksSlot: InFlightSlot<CachedJwks> = {
  inFlightOf: (state) => state.jwksInFlight,
  setInFlight: (state, inFlight) => ({ ...state, jwksInFlight: inFlight }),
};

export function makeJwksCache(): JwksCacheShape {
  const state = SynchronizedRef.makeUnsafe(emptyCacheState);

  const singleFlight = <A>(
    issuer: string,
    slot: InFlightSlot<A>,
    load: Effect.Effect<A, JwksUnavailableError, HttpClient.HttpClient>,
    settle: (
      current: CacheState,
      exit: Exit.Exit<A, JwksUnavailableError>,
      nowMs: number,
    ) => CacheState,
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
            Effect.uninterruptible(
              Effect.gen(function* () {
                const exit = yield* Effect.exit(
                  load.pipe(
                    Effect.catchDefect(() =>
                      Effect.fail(new JwksUnavailableError({ reason: "fetch" })),
                    ),
                  ),
                );
                const settledAtMs = yield* Clock.currentTimeMillis;
                yield* SynchronizedRef.update(state, (current) =>
                  settle(current, exit, settledAtMs),
                );
                yield* Deferred.done(created, exit);
              }),
            ),
          );
        }
        return created;
      }),
    );

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
      const deferred = yield* singleFlight(
        issuer,
        discoverySlot,
        loadDiscovery(issuer),
        (current, exit) =>
          Exit.isSuccess(exit)
            ? {
                ...current,
                lastGoodDiscovery: { ...current.lastGoodDiscovery, [issuer]: exit.value },
                discoveryInFlight: dropKey(current.discoveryInFlight, issuer),
              }
            : { ...current, discoveryInFlight: dropKey(current.discoveryInFlight, issuer) },
      );
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
      return {
        keys: document.keys,
        fetchedAtMs: yield* Clock.currentTimeMillis,
        forcedRefreshAtMs,
      };
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
      const failedAt = snapshot.lastFailureAtMs[issuer];
      if (failedAt !== undefined && nowMs - failedAt < FAILED_REFRESH_COOLDOWN_MS) {
        if (isWithinGrace(cached, nowMs)) {
          return cached;
        }
        return yield* Effect.fail(new JwksUnavailableError({ reason: "cooldown" }));
      }
      const forcedRefreshAtMs = forcedRefreshStamp(cached, nowMs);

      const deferred = yield* singleFlight(
        issuer,
        jwksSlot,
        loadJwks(issuer, forcedRefreshAtMs),
        (current, exit, settledAtMs) => {
          const dropped = { ...current, jwksInFlight: dropKey(current.jwksInFlight, issuer) };
          if (Exit.isSuccess(exit)) {
            return {
              ...dropped,
              lastGoodJwks: { ...current.lastGoodJwks, [issuer]: exit.value },
              lastFailureAtMs: dropKey(current.lastFailureAtMs, issuer),
            };
          }
          const after = current.lastGoodJwks[issuer];
          return {
            ...dropped,
            lastFailureAtMs: { ...current.lastFailureAtMs, [issuer]: settledAtMs },
            ...(isWithinGrace(after, settledAtMs)
              ? {
                  lastGoodJwks: {
                    ...current.lastGoodJwks,
                    [issuer]: { ...after, forcedRefreshAtMs },
                  },
                }
              : {}),
          };
        },
      );
      return yield* Effect.matchEffect(Deferred.await(deferred), {
        onSuccess: Effect.succeed,
        onFailure: (error) =>
          Effect.gen(function* () {
            const settledAtMs = yield* Clock.currentTimeMillis;
            const after = (yield* SynchronizedRef.get(state)).lastGoodJwks[issuer];
            if (!isWithinGrace(after, settledAtMs)) {
              return yield* Effect.fail(error);
            }
            return after;
          }),
      });
    });

  return {
    resolveKey: Effect.fn("jwks.resolveKey")(function* (issuer, kid) {
      const document = yield* jwksFor(issuer, kid);
      const jwk = selectJwk(document.keys, kid);
      if (jwk === null) {
        return null;
      }
      const algorithm = algorithmForJwk(jwk);
      if (algorithm === null) {
        return null;
      }
      const publicJwk = Schema.decodeUnknownOption(Jwk.PublicJwk)(jwk);
      if (Option.isNone(publicJwk)) {
        return null;
      }
      const key = yield* Effect.option(Jwk.importPublic(publicJwk.value, algorithm));
      return Option.isNone(key) ? null : { key: key.value };
    }, Effect.provide(defaultHttpClientLayer)),
  };
}
