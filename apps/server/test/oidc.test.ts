// Unit tests for OIDC verification and the JWKS cache (AUTH_SPEC
// §14-1).
//
// Where the lease integration tests (lease.test.ts) pin the
// real-path judgment order, this file pins "situations that are
// hard to create on the real path":
//   - fail-closed when the JWKS cannot be fetched = signature
//     verification cannot run, and that the response is not 401
//     but 503 `oidc-jwks-unavailable`
//   - reuse within the TTL / a forced refresh on an unknown kid /
//     the cooldown (following key rotation)
//   - the self-declaration checks of the discovery document
//     (issuer match, same-origin jwks_uri)
//
// fetch is swapped out inside the test and its call count is
// tallied (no traffic to the real network).

import { Effect } from "effect";
import { afterEach, describe, expect, it } from "vitest";

import { makeJwksCache, makeOidcVerifier } from "../src/oidc.package/index.ts";
import { makeOidcToken } from "./support/lease.ts";
import { OIDC_DISCOVERY, OIDC_ISSUER, OIDC_JWKS, OIDC_KID } from "./support/oidc-issuer.ts";

const realFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = realFetch;
});

interface FetchLog {
  readonly urls: string[];
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/**
 * A fetch stub returning discovery / JWKS. Swap `jwks` to simulate
 * key rotation; set `failJwks` to simulate an issuer-side outage.
 */
function stubFetch(
  options: {
    readonly jwks?: () => unknown;
    readonly failJwks?: () => boolean;
    readonly discovery?: unknown;
  } = {},
): FetchLog {
  const log: FetchLog = { urls: [] };
  globalThis.fetch = ((input: RequestInfo | URL) => {
    const url = String(input);
    log.urls.push(url);
    if (url.endsWith("/.well-known/openid-configuration")) {
      return Promise.resolve(json(options.discovery ?? OIDC_DISCOVERY));
    }
    if (url.endsWith("/.well-known/jwks")) {
      return options.failJwks?.() === true
        ? Promise.resolve(new Response("boom", { status: 503 }))
        : Promise.resolve(json(options.jwks?.() ?? OIDC_JWKS));
    }
    return Promise.resolve(new Response("unexpected", { status: 500 }));
  }) as typeof fetch;
  return log;
}

/** Fold the outcome into a tagged value (Effect v4 beta has no Effect.either). */
const run = <A, E>(effect: Effect.Effect<A, E>) =>
  Effect.runPromise(
    Effect.match(effect, {
      onSuccess: (value: A) => ({ ok: true as const, value }),
      onFailure: (error: E) => ({ ok: false as const, error }),
    }),
  );

describe("JWKS cache (§14-1)", () => {
  it("caches the discovery document and the JWKS across calls", async () => {
    const log = stubFetch();
    const cache = makeJwksCache();
    for (let index = 0; index < 3; index += 1) {
      const resolved = await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, OIDC_KID));
      expect(resolved).not.toBeNull();
    }
    // 3 resolutions make just 1 discovery + 1 JWKS round trips
    // (reused within the TTL)
    expect(log.urls.length).toBe(2);
  });

  it("force-refreshes once for an unknown kid, then respects the cooldown", async () => {
    let rotated = false;
    const log = stubFetch({
      jwks: () => (rotated ? { keys: [{ ...OIDC_JWKS.keys[0], kid: "rotated-in" }] } : OIDC_JWKS),
    });
    let currentMs = 1_000_000;
    const cache = makeJwksCache(() => currentMs);

    // Warm up with a known kid (discovery + JWKS)
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, OIDC_KID))).not.toBeNull();
    const afterWarmup = log.urls.length;

    // The issuer rotated its keys. An unknown kid is re-fetched
    // exactly once
    rotated = true;
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, "rotated-in"))).not.toBeNull();
    expect(log.urls.length).toBe(afterWarmup + 1);

    // An unknown kid within the cooldown is not re-fetched (a
    // nonexistent kid must not hammer the issuer)
    const afterRefresh = log.urls.length;
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, "never-existed"))).toBeNull();
    expect(log.urls.length).toBe(afterRefresh);

    // Past the cooldown it is re-fetched once more
    currentMs += 61_000;
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, "still-missing"))).toBeNull();
    expect(log.urls.length).toBe(afterRefresh + 1);
  });

  it("rejects a discovery document whose issuer does not match the requested issuer", async () => {
    stubFetch({ discovery: { ...OIDC_DISCOVERY, issuer: "https://evil.example" } });
    const result = await run(makeJwksCache().resolveKey(OIDC_ISSUER, OIDC_KID));
    expect(result.ok).toBe(false);
  });

  it("rejects a jwks_uri on another origin (key provenance is pinned to the issuer)", async () => {
    stubFetch({
      discovery: { ...OIDC_DISCOVERY, jwks_uri: "https://cdn.evil.example/.well-known/jwks" },
    });
    const result = await run(makeJwksCache().resolveKey(OIDC_ISSUER, OIDC_KID));
    expect(result.ok).toBe(false);
  });

  it("keeps a TTL-valid document — and advances the cooldown — when a forced refresh fails", async () => {
    let failing = false;
    const log = stubFetch({ failJwks: () => failing });
    const cache = makeJwksCache();

    // Warm up with a known kid (discovery + JWKS)
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, OIDC_KID))).not.toBeNull();

    // Even if an unknown kid (which an attacker can choose freely)
    // triggers a forced refresh while the issuer is down, the old
    // in-TTL document is not lost: the unknown kid is 401 (null),
    // while a known kid never drops to 503 and still verifies
    failing = true;
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, "never-existed"))).toBeNull();
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, OIDC_KID))).not.toBeNull();
    // A failed forced refresh also starts the cooldown (the issuer
    // is not hammered)
    const afterFailure = log.urls.length;
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, "still-missing"))).toBeNull();
    expect(log.urls.length).toBe(afterFailure);
  });

  it("does not cache a failed fetch permanently (retries once the cooldown lapses)", async () => {
    let failing = true;
    const log = stubFetch({ failJwks: () => failing });
    let currentMs = 1_000_000;
    const cache = makeJwksCache(() => currentMs);
    expect((await run(cache.resolveKey(OIDC_ISSUER, OIDC_KID))).ok).toBe(false);

    // Even with no good value, nothing is re-fetched during the
    // failure cooldown (cold + issuer outage must not become "1
    // request = 1 fetch"). Failures are immediate during this window
    failing = false;
    expect((await run(cache.resolveKey(OIDC_ISSUER, OIDC_KID))).ok).toBe(false);
    expect(log.urls.filter((url) => url.endsWith("/jwks")).length).toBe(1);

    // After the cooldown it re-fetches, proving the failure did not stick
    currentMs += 61_000;
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, OIDC_KID))).not.toBeNull();
    expect(log.urls.filter((url) => url.endsWith("/jwks")).length).toBe(2);
  });

  it("serves the last good JWKS while a refresh keeps failing (stale-while-revalidate)", async () => {
    let failing = false;
    stubFetch({ failJwks: () => failing });
    let currentMs = 1_000_000;
    const cache = makeJwksCache(() => currentMs);
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, OIDC_KID))).not.toBeNull();

    // Past the TTL (15 minutes) with the issuer still down
    failing = true;
    currentMs += 20 * 60 * 1000;
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, OIDC_KID))).not.toBeNull();

    // Past the grace window (6 hours) it is no longer accepted
    currentMs += 6 * 60 * 60 * 1000;
    expect((await run(cache.resolveKey(OIDC_ISSUER, OIDC_KID))).ok).toBe(false);
  });

  it("does not re-fetch on every request while the issuer stays down (cuts off amplification)", async () => {
    // On TTL expiry + issuer outage, `isUsable` returns false at the
    // TTL branch, so the forced-refresh cooldown is never reached.
    // Without an independent interval on the failure side, "1
    // unauthenticated request = 1 outbound fetch" would persist for
    // the remainder of the grace window (just under 6 hours)
    let failing = false;
    const log = stubFetch({ failJwks: () => failing });
    let currentMs = 1_000_000;
    const cache = makeJwksCache(() => currentMs);
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, OIDC_KID))).not.toBeNull();

    // Past the TTL (15 minutes), the issuer goes down
    failing = true;
    currentMs += 20 * 60 * 1000;
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, OIDC_KID))).not.toBeNull();
    const afterFirstFailure = log.urls.length;

    // Subsequent requests during the outage are served stale; the
    // issuer is not re-hit
    for (let attempt = 0; attempt < 5; attempt += 1) {
      expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, OIDC_KID))).not.toBeNull();
    }
    expect(log.urls.length).toBe(afterFirstFailure);

    // After the cooldown (60 seconds) it retries once and picks up
    // the recovery
    currentMs += 61_000;
    failing = false;
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, OIDC_KID))).not.toBeNull();
    expect(log.urls.length).toBe(afterFirstFailure + 1);
  });

  it("aborts a hanging JWKS fetch instead of holding the request open", async () => {
    // An external fetch inducible via an unauthenticated path, so an
    // unresponsive issuer must not hold the request open
    // (AbortSignal.timeout)
    globalThis.fetch = ((_input: RequestInfo | URL, init?: RequestInit) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          reject(new Error("aborted"));
        });
      })) as typeof fetch;
    const result = await run(makeJwksCache().resolveKey(OIDC_ISSUER, OIDC_KID));
    expect(result.ok).toBe(false);
  }, 20_000);
});

const nowMs = (): number => Date.now();

describe("OIDC verifier(§14-1)", () => {
  it("fails closed with 503 oidc-jwks-unavailable when the JWKS cannot be fetched", async () => {
    stubFetch({ failJwks: () => true });
    const verifier = makeOidcVerifier(makeJwksCache());
    const result = await run(verifier.verify(await makeOidcToken(), nowMs()));
    expect(result.ok).toBe(false);
    // A transient outage must not be reported as "bad credentials
    // (401)" — a CI job would treat it as a non-retryable failure
    // (errors/lease.ts)
    expect(result.ok === false && result.error).toMatchObject({
      _tag: "LeaseUnavailable",
      reason: "oidc-jwks-unavailable",
    });
  });

  it("checks the issuer allowlist before any outbound fetch (cuts off amplification from the unauthenticated surface)", async () => {
    const log = stubFetch();
    const verifier = makeOidcVerifier(makeJwksCache());
    const result = await run(
      verifier.verify(await makeOidcToken({ issuer: "https://evil.example" }), nowMs()),
    );
    expect(result.ok === false && result.error).toMatchObject({ reason: "unsupported-issuer" });
    // With an issuer outside the allowlist it never goes out even once
    expect(log.urls.length).toBe(0);
  });

  it("accepts an array `aud` (RFC 7519) and normalizes it", async () => {
    stubFetch();
    const verifier = makeOidcVerifier(makeJwksCache());
    const token = await makeOidcToken({ audience: ["https://a.example", "https://b.example"] });
    const result = await run(verifier.verify(token, nowMs()));
    expect(result.ok).toBe(true);
    expect(result.ok === true && result.value.audiences).toEqual([
      "https://a.example",
      "https://b.example",
    ]);
  });

  it("accepts a token at the edge of the ±60s skew and rejects it just outside", async () => {
    stubFetch();
    const verifier = makeOidcVerifier(makeJwksCache());
    const expSeconds = Math.floor(Date.now() / 1000) - 30;
    const token = await makeOidcToken({ expSeconds });
    // exp 30 seconds ago = within skew, so still valid
    expect((await run(verifier.verify(token, Date.now()))).ok).toBe(true);
    // Verifying the same token at a time beyond the skew is expired
    const later = await run(verifier.verify(token, Date.now() + 90_000));
    expect(later.ok === false && later.error).toMatchObject({ reason: "token-expired" });
  });

  it("rejects a token whose payload is not a JSON object", async () => {
    stubFetch();
    const verifier = makeOidcVerifier(makeJwksCache());
    // The header.payload.signature shape holds but the payload is a JSON array
    const segment = btoa("[1,2,3]").replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    const header = btoa(JSON.stringify({ alg: "ES256", kid: OIDC_KID }))
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replaceAll("=", "");
    const result = await run(verifier.verify(`${header}.${segment}.AAAA`, nowMs()));
    expect(result.ok === false && result.error).toMatchObject({ reason: "malformed-token" });
  });

  it("rejects a JWS that declares a crit extension (RFC 7515 §4.1.11)", async () => {
    // crit declares "extensions that must not be accepted unless
    // understood"; this implementation supports no extensions, so
    // every crit value is rejected. The missing check became CVEs in
    // Authlib / PyJWT / fast-jwt in 2025–2026
    stubFetch();
    const verifier = makeOidcVerifier(makeJwksCache());
    const token = await makeOidcToken({ crit: ["exp"] });
    const result = await run(verifier.verify(token, nowMs()));
    expect(result.ok === false && result.error).toMatchObject({ reason: "unsupported-crit" });
  });

  it("rejects a non-string sub / missing sub as a claim problem, not a signature problem", async () => {
    stubFetch();
    const verifier = makeOidcVerifier(makeJwksCache());
    const result = await run(
      verifier.verify(await makeOidcToken({ claims: { sub: 42 } }), nowMs()),
    );
    expect(result.ok === false && result.error).toMatchObject({ reason: "missing-claim" });
  });
});
