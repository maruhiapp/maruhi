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
// Outbound HTTP is stubbed through `FetchHttpClient.Fetch` (a
// `Context.Reference` holding the fetch function the client reads from
// the requesting fiber — a test provides it at the run site and the
// detached load fiber inherits it), whose called URLs are tallied. Time
// is driven by `TestClock` (no traffic to the real network).

import { Effect, ManagedRuntime } from "effect";
import { FetchHttpClient } from "effect/http";
import { TestClock } from "effect/testing";
import { describe, expect, it } from "vitest";

import { makeJwksCache, makeOidcVerifier } from "../src/oidc.package/index.ts";
import { makeOidcToken } from "./support/lease.ts";
import { OIDC_DISCOVERY, OIDC_ISSUER, OIDC_JWKS, OIDC_KID } from "./support/oidc-issuer.ts";

interface StubbedFetch {
  readonly fetch: typeof globalThis.fetch;
  readonly urls: string[];
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/**
 * A `fetch` stub serving discovery / JWKS. Swap `jwks` to simulate key
 * rotation; `failJwks` for an issuer-side outage; `hang` for an issuer
 * that never answers (the fetch timeout then has to win —
 * `TestClock.adjust` fires it); `dieJwks` for a defect inside the load
 * (a response whose body cannot be read); `gateJwks` to hold the JWKS
 * response open until the gate resolves.
 */
type StubOptions = {
  readonly jwks?: () => unknown;
  readonly failJwks?: () => boolean;
  readonly dieJwks?: () => boolean;
  readonly discovery?: unknown;
  readonly hang?: boolean;
  readonly gateJwks?: Promise<void>;
};

const jwksResponse = (options: StubOptions): Response => {
  const response =
    options.failJwks?.() === true
      ? new Response("boom", { status: 503 })
      : json(options.jwks?.() ?? OIDC_JWKS);
  if (options.dieJwks?.() === true) {
    // A defect, not a typed failure: reading the body throws inside the
    // load, the way an unrecoverable internal error would
    Object.defineProperty(response, "body", {
      get() {
        throw new Error("client blew up");
      },
    });
  }
  return response;
};

function stubFetch(options: StubOptions = {}): StubbedFetch {
  const urls: string[] = [];
  const fetch: typeof globalThis.fetch = (input) => {
    const href = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    urls.push(href);
    if (options.hang === true) {
      return new Promise<Response>(() => {});
    }
    if (href.endsWith("/.well-known/openid-configuration")) {
      return Promise.resolve(json(options.discovery ?? OIDC_DISCOVERY));
    }
    if (href.endsWith("/.well-known/jwks")) {
      const gate = options.gateJwks;
      return gate === undefined
        ? Promise.resolve(jwksResponse(options))
        : gate.then(() => jwksResponse(options));
    }
    return Promise.resolve(new Response("unexpected", { status: 500 }));
  };
  return { fetch, urls };
}

/**
 * A runtime whose Clock reference is a fresh `TestClock`, started well
 * past the forced-refresh sentinel: a fresh cache records
 * `forcedRefreshAtMs = 0` for "never force-refreshed", so at t < 60s
 * (where TestClock begins) it would read as "just refreshed". Real
 * clocks sit near 1.7e12 ms; put the test clock at the old harness's
 * 1_000_000 ms start too.
 */
type TestRuntime = ManagedRuntime.ManagedRuntime<TestClock.TestClock, never>;
const makeTestRuntime = async (): Promise<TestRuntime> => {
  const rt = ManagedRuntime.make(TestClock.layer());
  await rt.runPromise(TestClock.adjust(1_000_000));
  return rt;
};

const advance = (rt: TestRuntime, ms: number) => rt.runPromise(TestClock.adjust(ms));

/** Fold the outcome into a tagged value, run under `rt` with `fetch` installed. */
const run = <A, E>(rt: TestRuntime, fetch: typeof globalThis.fetch, effect: Effect.Effect<A, E>) =>
  rt.runPromise(
    Effect.match(effect.pipe(Effect.provideService(FetchHttpClient.Fetch, fetch)), {
      onSuccess: (value: A) => ({ ok: true as const, value }),
      onFailure: (error: E) => ({ ok: false as const, error }),
    }),
  );

/** Resolve under `rt` with `fetch`, expecting a key or null (the non-failure verdicts). */
const resolve = (
  cache: ReturnType<typeof makeJwksCache>,
  rt: TestRuntime,
  fetch: typeof globalThis.fetch,
  kid: string,
) =>
  rt.runPromise(
    Effect.provideService(cache.resolveKey(OIDC_ISSUER, kid), FetchHttpClient.Fetch, fetch),
  );

describe("JWKS cache (§14-1)", () => {
  it("caches the discovery document and the JWKS across calls", async () => {
    const stub = stubFetch();
    const rt = await makeTestRuntime();
    const cache = makeJwksCache();
    for (let index = 0; index < 3; index += 1) {
      const resolved = await resolve(cache, rt, stub.fetch, OIDC_KID);
      expect(resolved).not.toBeNull();
    }
    // 3 resolutions make just 1 discovery + 1 JWKS round trips
    // (reused within the TTL)
    expect(stub.urls.length).toBe(2);
  });

  it("folds concurrent resolveKey calls into one discovery and one JWKS fetch", async () => {
    // Hold the winner's JWKS fetch at the gate until every caller has
    // joined — a caller that arrives after settle would be served by the
    // TTL cache instead of the in-flight Deferred, and this test would
    // prove nothing about concurrency
    let releaseGate = (): void => {};
    const gate = new Promise<void>((resolveGate) => {
      releaseGate = resolveGate;
    });
    const stub = stubFetch({ gateJwks: gate });
    const rt = await makeTestRuntime();
    const cache = makeJwksCache();
    const pending = Array.from({ length: 5 }, () => resolve(cache, rt, stub.fetch, OIDC_KID));
    for (let tick = 0; tick < 50 && stub.urls.length < 2; tick += 1) {
      await rt.runPromise(Effect.yieldNow);
    }
    releaseGate();
    const results = await Promise.all(pending);
    for (const result of results) {
      expect(result).not.toBeNull();
    }
    // 5 concurrent resolutions made just 1 discovery + 1 JWKS round trip
    expect(stub.urls.length).toBe(2);
  });

  it("force-refreshes once for an unknown kid, then respects the cooldown", async () => {
    let rotated = false;
    const stub = stubFetch({
      jwks: () => (rotated ? { keys: [{ ...OIDC_JWKS.keys[0], kid: "rotated-in" }] } : OIDC_JWKS),
    });
    const rt = await makeTestRuntime();
    const cache = makeJwksCache();

    // Warm up with a known kid (discovery + JWKS)
    expect(await resolve(cache, rt, stub.fetch, OIDC_KID)).not.toBeNull();
    const afterWarmup = stub.urls.length;

    // The issuer rotated its keys. An unknown kid is re-fetched
    // exactly once
    rotated = true;
    expect(await resolve(cache, rt, stub.fetch, "rotated-in")).not.toBeNull();
    expect(stub.urls.length).toBe(afterWarmup + 1);

    // An unknown kid within the cooldown is not re-fetched (a
    // nonexistent kid must not hammer the issuer)
    const afterRefresh = stub.urls.length;
    expect(await resolve(cache, rt, stub.fetch, "never-existed")).toBeNull();
    expect(stub.urls.length).toBe(afterRefresh);

    // Past the cooldown it is re-fetched once more
    await advance(rt, 61_000);
    expect(await resolve(cache, rt, stub.fetch, "still-missing")).toBeNull();
    expect(stub.urls.length).toBe(afterRefresh + 1);
  });

  it("rejects a discovery document whose issuer does not match the requested issuer", async () => {
    const stub = stubFetch({
      discovery: { ...OIDC_DISCOVERY, issuer: "https://evil.example" },
    });
    const rt = await makeTestRuntime();
    const result = await run(rt, stub.fetch, makeJwksCache().resolveKey(OIDC_ISSUER, OIDC_KID));
    expect(result.ok).toBe(false);
  });

  it("rejects a jwks_uri on another origin (key provenance is pinned to the issuer)", async () => {
    const stub = stubFetch({
      discovery: { ...OIDC_DISCOVERY, jwks_uri: "https://cdn.evil.example/.well-known/jwks" },
    });
    const rt = await makeTestRuntime();
    const result = await run(rt, stub.fetch, makeJwksCache().resolveKey(OIDC_ISSUER, OIDC_KID));
    expect(result.ok).toBe(false);
  });

  it("rejects a JWKS document whose keys hold a non-object entry", async () => {
    const stub = stubFetch({ jwks: () => ({ keys: [null, OIDC_JWKS.keys[0]] }) });
    const rt = await makeTestRuntime();
    const result = await run(rt, stub.fetch, makeJwksCache().resolveKey(OIDC_ISSUER, OIDC_KID));
    expect(result.ok).toBe(false);
  });

  it("keeps a TTL-valid document — and advances the cooldown — when a forced refresh fails", async () => {
    let failing = false;
    const stub = stubFetch({ failJwks: () => failing });
    const rt = await makeTestRuntime();
    const cache = makeJwksCache();

    // Warm up with a known kid (discovery + JWKS)
    expect(await resolve(cache, rt, stub.fetch, OIDC_KID)).not.toBeNull();

    // Even if an unknown kid (which an attacker can choose freely)
    // triggers a forced refresh while the issuer is down, the old
    // in-TTL document is not lost: the unknown kid is 401 (null),
    // while a known kid never drops to 503 and still verifies
    failing = true;
    expect(await resolve(cache, rt, stub.fetch, "never-existed")).toBeNull();
    expect(await resolve(cache, rt, stub.fetch, OIDC_KID)).not.toBeNull();
    // A failed forced refresh also starts the cooldown (the issuer
    // is not hammered)
    const afterFailure = stub.urls.length;
    expect(await resolve(cache, rt, stub.fetch, "still-missing")).toBeNull();
    expect(stub.urls.length).toBe(afterFailure);
  });

  it("does not cache a failed fetch permanently (retries once the cooldown lapses)", async () => {
    let failing = true;
    const stub = stubFetch({ failJwks: () => failing });
    const rt = await makeTestRuntime();
    const cache = makeJwksCache();
    expect((await run(rt, stub.fetch, cache.resolveKey(OIDC_ISSUER, OIDC_KID))).ok).toBe(false);

    // Even with no good value, nothing is re-fetched during the
    // failure cooldown (cold + issuer outage must not become "1
    // request = 1 fetch"). Failures are immediate during this window
    failing = false;
    expect((await run(rt, stub.fetch, cache.resolveKey(OIDC_ISSUER, OIDC_KID))).ok).toBe(false);
    expect(stub.urls.filter((url) => url.endsWith("/jwks")).length).toBe(1);

    // After the cooldown it re-fetches, proving the failure did not stick
    await advance(rt, 61_000);
    expect(await resolve(cache, rt, stub.fetch, OIDC_KID)).not.toBeNull();
    expect(stub.urls.filter((url) => url.endsWith("/jwks")).length).toBe(2);
  });

  it("serves the last good JWKS while a refresh keeps failing (stale-while-revalidate)", async () => {
    let failing = false;
    const stub = stubFetch({ failJwks: () => failing });
    const rt = await makeTestRuntime();
    const cache = makeJwksCache();
    expect(await resolve(cache, rt, stub.fetch, OIDC_KID)).not.toBeNull();

    // Past the TTL (15 minutes) with the issuer still down
    failing = true;
    await advance(rt, 20 * 60 * 1000);
    expect(await resolve(cache, rt, stub.fetch, OIDC_KID)).not.toBeNull();

    // Past the grace window (6 hours) it is no longer accepted
    await advance(rt, 6 * 60 * 60 * 1000);
    expect((await run(rt, stub.fetch, cache.resolveKey(OIDC_ISSUER, OIDC_KID))).ok).toBe(false);
  });

  it("does not re-fetch on every request while the issuer stays down (cuts off amplification)", async () => {
    // On TTL expiry + issuer outage, `isUsable` returns false at the
    // TTL branch, so the forced-refresh cooldown is never reached.
    // Without an independent interval on the failure side, "1
    // unauthenticated request = 1 outbound fetch" would persist for
    // the remainder of the grace window (just under 6 hours)
    let failing = false;
    const stub = stubFetch({ failJwks: () => failing });
    const rt = await makeTestRuntime();
    const cache = makeJwksCache();
    expect(await resolve(cache, rt, stub.fetch, OIDC_KID)).not.toBeNull();

    // Past the TTL (15 minutes), the issuer goes down
    failing = true;
    await advance(rt, 20 * 60 * 1000);
    expect(await resolve(cache, rt, stub.fetch, OIDC_KID)).not.toBeNull();
    const afterFirstFailure = stub.urls.length;

    // Subsequent requests during the outage are served stale; the
    // issuer is not re-hit
    for (let attempt = 0; attempt < 5; attempt += 1) {
      expect(await resolve(cache, rt, stub.fetch, OIDC_KID)).not.toBeNull();
    }
    expect(stub.urls.length).toBe(afterFirstFailure);

    // After the cooldown (60 seconds) it retries once and picks up
    // the recovery
    await advance(rt, 61_000);
    failing = false;
    expect(await resolve(cache, rt, stub.fetch, OIDC_KID)).not.toBeNull();
    expect(stub.urls.length).toBe(afterFirstFailure + 1);
  });

  it("settles the shared load when the fetch dies with a defect, then retries after the cooldown", async () => {
    // A defect inside the single-flight load must still complete the
    // Deferred and drop the in-flight entry (the old Promise always
    // rejected and cleaned up in `.finally`) — a dead in-flight entry
    // would hang every later caller on that issuer
    let dying = true;
    const stub = stubFetch({ dieJwks: () => dying });
    const rt = await makeTestRuntime();
    const cache = makeJwksCache();
    expect((await run(rt, stub.fetch, cache.resolveKey(OIDC_ISSUER, OIDC_KID))).ok).toBe(false);

    dying = false;
    await advance(rt, 61_000);
    expect(await resolve(cache, rt, stub.fetch, OIDC_KID)).not.toBeNull();
  });

  it("aborts a hanging JWKS fetch instead of holding the request open", async () => {
    // An external fetch inducible via an unauthenticated path, so an
    // unresponsive issuer must not hold the request open
    // (FETCH_TIMEOUT_MS via Effect.timeout)
    const stub = stubFetch({ hang: true });
    const rt = await makeTestRuntime();
    const pending = run(rt, stub.fetch, makeJwksCache().resolveKey(OIDC_ISSUER, OIDC_KID));
    // No ordering assumption about which tick the detached fetch fiber
    // registers its timeout sleep on: yield the runtime's scheduler and
    // advance in slices until the verdict settles. 20 s of virtual time
    // covers FETCH_TIMEOUT_MS several times over; a fetch that never
    // settles fails the assertion below instead of hanging the suite
    for (let tick = 0; tick < 20; tick += 1) {
      await rt.runPromise(Effect.yieldNow);
      await advance(rt, 1_000);
      if ((await Promise.race([pending, Promise.resolve("pending")])) !== "pending") break;
    }
    const result = await Promise.race([pending, Promise.resolve("pending" as const)]);
    if (result === "pending") {
      throw new Error("resolveKey did not settle within 20 s of virtual time");
    }
    expect(result.ok).toBe(false);
  });
});

const nowMs = (): number => Date.now();

describe("OIDC verifier(§14-1)", () => {
  it("fails closed with 503 oidc-jwks-unavailable when the JWKS cannot be fetched", async () => {
    const stub = stubFetch({ failJwks: () => true });
    const rt = await makeTestRuntime();
    const verifier = makeOidcVerifier();
    const result = await run(rt, stub.fetch, verifier.verify(await makeOidcToken(), nowMs()));
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
    const stub = stubFetch();
    const rt = await makeTestRuntime();
    const verifier = makeOidcVerifier();
    const result = await run(
      rt,
      stub.fetch,
      verifier.verify(await makeOidcToken({ issuer: "https://evil.example" }), nowMs()),
    );
    expect(result.ok === false && result.error).toMatchObject({ reason: "unsupported-issuer" });
    // With an issuer outside the allowlist it never goes out even once
    expect(stub.urls.length).toBe(0);
  });

  it("accepts an array `aud` (RFC 7519) and normalizes it", async () => {
    const stub = stubFetch();
    const rt = await makeTestRuntime();
    const verifier = makeOidcVerifier();
    const token = await makeOidcToken({ audience: ["https://a.example", "https://b.example"] });
    const result = await run(rt, stub.fetch, verifier.verify(token, nowMs()));
    expect(result.ok).toBe(true);
    expect(result.ok === true && result.value.audiences).toEqual([
      "https://a.example",
      "https://b.example",
    ]);
  });

  it("accepts a token at the edge of the ±60s skew and rejects it just outside", async () => {
    const stub = stubFetch();
    const rt = await makeTestRuntime();
    const verifier = makeOidcVerifier();
    const expSeconds = Math.floor(Date.now() / 1000) - 30;
    const token = await makeOidcToken({ expSeconds });
    // exp 30 seconds ago = within skew, so still valid
    expect((await run(rt, stub.fetch, verifier.verify(token, Date.now()))).ok).toBe(true);
    // Verifying the same token at a time beyond the skew is expired
    const later = await run(rt, stub.fetch, verifier.verify(token, Date.now() + 90_000));
    expect(later.ok === false && later.error).toMatchObject({ reason: "token-expired" });
  });

  it("rejects a token whose payload is not a JSON object", async () => {
    const stub = stubFetch();
    const rt = await makeTestRuntime();
    const verifier = makeOidcVerifier();
    // The header.payload.signature shape holds but the payload is a JSON array
    const segment = btoa("[1,2,3]").replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    const header = btoa(JSON.stringify({ alg: "ES256", kid: OIDC_KID }))
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replaceAll("=", "");
    const result = await run(rt, stub.fetch, verifier.verify(`${header}.${segment}.AAAA`, nowMs()));
    expect(result.ok === false && result.error).toMatchObject({ reason: "malformed-token" });
  });

  it("rejects a JWS that declares a crit extension (RFC 7515 §4.1.11)", async () => {
    // crit declares "extensions that must not be accepted unless
    // understood"; this implementation supports no extensions, so
    // every crit value is rejected. The missing check became CVEs in
    // Authlib / PyJWT / fast-jwt in 2025–2026
    const stub = stubFetch();
    const rt = await makeTestRuntime();
    const verifier = makeOidcVerifier();
    const token = await makeOidcToken({ crit: ["exp"] });
    const result = await run(rt, stub.fetch, verifier.verify(token, nowMs()));
    expect(result.ok === false && result.error).toMatchObject({ reason: "unsupported-crit" });
  });

  it("rejects a non-string sub / missing sub as a claim problem, not a signature problem", async () => {
    const stub = stubFetch();
    const rt = await makeTestRuntime();
    const verifier = makeOidcVerifier();
    const result = await run(
      rt,
      stub.fetch,
      verifier.verify(await makeOidcToken({ claims: { sub: 42 } }), nowMs()),
    );
    expect(result.ok === false && result.error).toMatchObject({ reason: "missing-claim" });
  });
});
