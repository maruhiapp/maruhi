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
//   - the JOSE attack classes of §14-1's verification stage, pinned
//     at the verifier level (an unsigned `alg=none` token, HS256
//     algorithm confusion, embedded `jwk` header parameters,
//     base64url canonicality), so the verification semantics stay
//     fixed on maruhi's side across effect/jose version bumps
//   - the cryptographic stage against the worked examples of
//     RFC 7515 Appendix A (A.2 RS256 / A.3 ES256)
//
// Outbound HTTP is stubbed through `FetchHttpClient.Fetch` (a
// `Context.Reference` holding the fetch function the client reads from
// the requesting fiber — a test provides it at the run site and the
// detached load fiber inherits it), whose called URLs are tallied. Time
// is driven by `TestClock` (no traffic to the real network).

import { cryptoServicesLayer } from "@maruhi/core";
import { Effect, ManagedRuntime, Result } from "effect";
import { Digest, Signature } from "effect/crypto";
import { Base64Url } from "effect/encoding";
import { FetchHttpClient } from "effect/http";
import { Jws } from "effect/jose";
import { TestClock } from "effect/testing";
import { describe, expect, it } from "vite-plus/test";

import { makeJwksCache, makeOidcVerifier } from "../src/oidc.package/index.ts";
import { LEASE_AUDIENCE, LEASE_SUBJECT, makeOidcToken } from "./support/lease.ts";
import {
  OIDC_DISCOVERY,
  OIDC_ISSUER,
  OIDC_JWKS,
  OIDC_KID,
  OIDC_PRIVATE_JWK,
} from "./support/oidc-issuer.ts";

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
const run = <A, E>(
  rt: TestRuntime,
  fetch: typeof globalThis.fetch,
  effect: Effect.Effect<A, E, Digest.Digest | Signature.Signature>,
) =>
  rt.runPromise(
    Effect.match(
      effect.pipe(
        Effect.provideService(FetchHttpClient.Fetch, fetch),
        // The verifier's crypto services (the signing-input hash's
        // Digest, effect/jose's Signature) come from the same composed
        // layer production wires
        Effect.provide(cryptoServicesLayer),
      ),
      {
        onSuccess: (value: A) => ({ ok: true as const, value }),
        onFailure: (error: E) => ({ ok: false as const, error }),
      },
    ),
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

/** base64url-encodes raw bytes (unpadded, the compact-JWS segment shape). */
const b64urlBytes = (bytes: Uint8Array): string =>
  btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");

const encodeJsonSegment = (value: unknown): string =>
  b64urlBytes(new TextEncoder().encode(JSON.stringify(value)));

/** Lenient base64url decode (atob) — used only to construct malleated spellings. */
function decodeSegmentBytes(segment: string): Uint8Array {
  const padded = segment
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(segment.length + ((4 - (segment.length % 4)) % 4), "=");
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

/**
 * A byte-identical re-spelling of a segment: a different final
 * character that decodes to the same bytes (the unused bits of the
 * final base64url group differ). Returns null when the segment's
 * length leaves no unused bits. The same construction as
 * lease-scenario.ts's `malleateSignatureSegment`, generalized to any
 * segment.
 */
function malleateSegment(segment: string): string | null {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const target = decodeSegmentBytes(segment);
  const lastIndex = segment.length - 1;
  for (const candidate of alphabet) {
    if (candidate === segment[lastIndex]) {
      continue;
    }
    const mutated = segment.slice(0, lastIndex) + candidate;
    const decoded = decodeSegmentBytes(mutated);
    if (decoded.length === target.length && decoded.every((b, i) => b === target[i])) {
      return mutated;
    }
  }
  return null;
}

/** Claims satisfying §14-1's presence / time checks right now (for hand-built tokens). */
const testClaims = (): Record<string, unknown> => {
  const nowSeconds = Math.floor(Date.now() / 1000);
  return {
    iss: OIDC_ISSUER,
    sub: LEASE_SUBJECT,
    aud: LEASE_AUDIENCE,
    exp: nowSeconds + 300,
    iat: nowSeconds - 5,
  };
};

/**
 * ES256-signs a compact JWS with an arbitrary header and key
 * (makeOidcToken's header and key are fixed to the test issuer's).
 */
async function signEs256Token(
  header: Record<string, unknown>,
  claims: Record<string, unknown>,
  privateJwk: JsonWebKey,
): Promise<string> {
  const signingInput = `${encodeJsonSegment(header)}.${encodeJsonSegment(claims)}`;
  const key = await crypto.subtle.importKey(
    "jwk",
    privateJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      new TextEncoder().encode(signingInput),
    ),
  );
  return `${signingInput}.${b64urlBytes(signature)}`;
}

const issuerPrivateJwk = OIDC_PRIVATE_JWK as unknown as JsonWebKey;

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

describe("OIDC verifier: JOSE attack classes (§14-1)", () => {
  it("rejects a genuinely unsigned alg=none token (empty signature segment)", async () => {
    // §14-1 (2): `none` is refused. lease.test.ts pins the header
    // variant on the HTTP path (alg "none" with a signature still
    // attached); this pins the canonical attack shape — no signature
    // at all — at the verifier level. The refusal happens at the alg
    // allowlist, before any JWKS fetch
    const stub = stubFetch();
    const rt = await makeTestRuntime();
    const verifier = makeOidcVerifier();
    const token = `${encodeJsonSegment({ alg: "none", typ: "JWT", kid: OIDC_KID })}.${encodeJsonSegment(testClaims())}.`;
    const result = await run(rt, stub.fetch, verifier.verify(token, nowMs()));
    expect(result.ok === false && result.error).toMatchObject({ reason: "unsupported-alg" });
    expect(stub.urls.length).toBe(0);
  });

  it("rejects an HS256 token HMAC-signed with the public key material (algorithm confusion)", async () => {
    // The classic confusion: the token claims HS256 and is MACed
    // with the verification key's public material as the HMAC secret,
    // so an implementation that branches on the header's alg and
    // treats the public key as a MAC secret accepts it. Two walls
    // refuse it here — the alg allowlist (§14-1 (2): symmetric algs
    // are refused), and behind it the JWK-side algorithm derivation,
    // which has no symmetric branch at all. The refusal precedes any
    // JWKS fetch
    const stub = stubFetch();
    const rt = await makeTestRuntime();
    const verifier = makeOidcVerifier();
    const signingInput = `${encodeJsonSegment({ alg: "HS256", typ: "JWT", kid: OIDC_KID })}.${encodeJsonSegment(testClaims())}`;
    // The public key material exactly as the JWKS publishes it
    const secret = new TextEncoder().encode(JSON.stringify(OIDC_JWKS.keys[0]));
    const macKey = await crypto.subtle.importKey(
      "raw",
      secret,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const mac = new Uint8Array(
      await crypto.subtle.sign("HMAC", macKey, new TextEncoder().encode(signingInput)),
    );
    const result = await run(
      rt,
      stub.fetch,
      verifier.verify(`${signingInput}.${b64urlBytes(mac)}`, nowMs()),
    );
    expect(result.ok === false && result.error).toMatchObject({ reason: "unsupported-alg" });
    expect(stub.urls.length).toBe(0);
  });

  it("never verifies against an embedded jwk header parameter (the attacker's own key)", async () => {
    // RFC 7515 §4.1.3's `jwk` header parameter carries a key chosen
    // by the token's author. Accepting it makes verification
    // self-asserted (the node-jose CVE-2018-0114 class, still
    // recurring — Authlib CVE-2026-27962). maruhi's verifier reads
    // only alg / crit / kid from the header; the key always comes
    // from the JWKS, selected by kid. A token signed by the embedded
    // key therefore fails against the issuer's key — and the verdict
    // is signature-invalid, proving the flow reached verification
    // with the JWKS key rather than refusing the shape outright
    const stub = stubFetch();
    const rt = await makeTestRuntime();
    const verifier = makeOidcVerifier();
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ]);
    const attackerPublic = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const attackerPrivate = await crypto.subtle.exportKey("jwk", pair.privateKey);
    const token = await signEs256Token(
      { alg: "ES256", typ: "JWT", kid: OIDC_KID, jwk: attackerPublic },
      testClaims(),
      attackerPrivate,
    );
    const result = await run(rt, stub.fetch, verifier.verify(token, nowMs()));
    expect(result.ok === false && result.error).toMatchObject({ reason: "signature-invalid" });
  });

  it("ignores an embedded jwk header parameter on an otherwise valid token", async () => {
    // The counterpart pin: the parameter is inert, not refused — a
    // token signed by the issuer's key verifies even when it carries
    // a (decoy) embedded key, because nothing ever reads it
    const stub = stubFetch();
    const rt = await makeTestRuntime();
    const verifier = makeOidcVerifier();
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ]);
    const decoyPublic = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const token = await signEs256Token(
      { alg: "ES256", typ: "JWT", kid: OIDC_KID, jwk: decoyPublic },
      testClaims(),
      issuerPrivateJwk,
    );
    const result = await run(rt, stub.fetch, verifier.verify(token, nowMs()));
    expect(result.ok).toBe(true);
  });

  it("accepts a byte-identical re-spelling of the signature segment, with the same signing-input hash", async () => {
    // Deliberate (§14-1's first-come binding): a re-spelling of the
    // signature segment's final character that decodes to the same
    // bytes must still verify — the binding key is the signing
    // input's hash, invariant under the re-spelling, so the token
    // binds identically (lease-binding.test.ts pins the same fact on
    // the lease path). The verifier's canonical re-encode of the
    // signature segment before effect/jose's verify is what admits
    // the re-spelling; this pins that adaptation at the verifier
    // level
    const stub = stubFetch();
    const rt = await makeTestRuntime();
    const verifier = makeOidcVerifier();
    const token = await makeOidcToken();
    const [header, payload, signature] = token.split(".");
    if (header === undefined || payload === undefined || signature === undefined) {
      throw new Error("makeOidcToken did not produce a compact JWS");
    }
    const malleated = malleateSegment(signature);
    if (malleated === null) {
      throw new Error("the ES256 signature segment is not malleable");
    }
    const original = await run(rt, stub.fetch, verifier.verify(token, nowMs()));
    const respelled = await run(
      rt,
      stub.fetch,
      verifier.verify(`${header}.${payload}.${malleated}`, nowMs()),
    );
    expect(original.ok).toBe(true);
    expect(respelled.ok).toBe(true);
    expect(original.ok === true && original.value.signingInputHashHex).toBe(
      respelled.ok === true && respelled.value.signingInputHashHex,
    );
  });

  it("rejects a byte-identical re-spelling of the header segment", async () => {
    // Only the signature segment gets the canonical re-encode: the
    // header segment's spelling is part of the signed content, so a
    // re-spelling (same decoded header, different string) is a
    // different signing input and the signature no longer matches.
    // The `cty` member sizes the header JSON (56 bytes) so its final
    // base64url group has unused bits to re-spell
    const stub = stubFetch();
    const rt = await makeTestRuntime();
    const verifier = makeOidcVerifier();
    const token = await signEs256Token(
      { alg: "ES256", typ: "JWT", kid: OIDC_KID, cty: "x" },
      testClaims(),
      issuerPrivateJwk,
    );
    const [header, payload, signature] = token.split(".");
    if (header === undefined || payload === undefined || signature === undefined) {
      throw new Error("signEs256Token did not produce a compact JWS");
    }
    const malleated = malleateSegment(header);
    if (malleated === null) {
      throw new Error("the header segment is not malleable");
    }
    // Control: the token as signed verifies — the refusal below is
    // the re-spelling, not the `cty` member
    expect((await run(rt, stub.fetch, verifier.verify(token, nowMs()))).ok).toBe(true);
    const result = await run(
      rt,
      stub.fetch,
      verifier.verify(`${malleated}.${payload}.${signature}`, nowMs()),
    );
    expect(result.ok === false && result.error).toMatchObject({ reason: "signature-invalid" });
  });

  it("rejects a byte-identical re-spelling of the payload segment", async () => {
    // Same pin as the header's, for the payload segment: the signed
    // content is the received spelling, never a decode → re-encode
    // product
    const stub = stubFetch();
    const rt = await makeTestRuntime();
    const verifier = makeOidcVerifier();
    // A segment is re-spellable only when its byte length leaves
    // unused bits in the final base64url group (length % 3 !== 0);
    // padding the subject by 0–2 characters covers every residue
    let original: string | null = null;
    let respelled: string | null = null;
    for (const pad of ["", "x", "xx"]) {
      const token = await makeOidcToken({ subject: `${LEASE_SUBJECT}${pad}` });
      const [header, payload, signature] = token.split(".");
      if (header === undefined || payload === undefined || signature === undefined) {
        throw new Error("makeOidcToken did not produce a compact JWS");
      }
      const malleated = malleateSegment(payload);
      if (malleated !== null) {
        original = token;
        respelled = `${header}.${malleated}.${signature}`;
        break;
      }
    }
    if (original === null || respelled === null) {
      throw new Error("no re-spellable payload among the padded subjects");
    }
    // Control: the token as signed verifies
    expect((await run(rt, stub.fetch, verifier.verify(original, nowMs()))).ok).toBe(true);
    const result = await run(rt, stub.fetch, verifier.verify(respelled, nowMs()));
    expect(result.ok === false && result.error).toMatchObject({ reason: "signature-invalid" });
  });

  it("rejects a segment carrying = padding as malformed (the strict segment shape)", async () => {
    // Compact JWS segments are unpadded base64url (RFC 7515
    // Appendix C). The upstream decoder is lenient about `=` padding
    // and the length check only refuses % 4 == 1, so the verifier
    // holds every segment to the strict alphabet first (verifier.ts's
    // decodeBase64Url) — a padded segment is malformed, not "the same
    // bytes spelled with padding". The payload is sized (subject
    // padding) so its segment length is % 4 == 3: the padded form is
    // then % 4 == 0 and decodes leniently, which isolates the strict
    // alphabet as the only gate that can refuse it
    const stub = stubFetch();
    const rt = await makeTestRuntime();
    const verifier = makeOidcVerifier();
    let padded: string | null = null;
    for (const pad of ["", "x", "xx"]) {
      const token = await makeOidcToken({ subject: `${LEASE_SUBJECT}${pad}` });
      const [header, payload, signature] = token.split(".");
      if (header === undefined || payload === undefined || signature === undefined) {
        throw new Error("makeOidcToken did not produce a compact JWS");
      }
      if (payload.length % 4 === 3) {
        padded = `${header}.${payload}=.${signature}`;
        break;
      }
    }
    if (padded === null) {
      throw new Error("no payload segment with length % 4 == 3 among the padded subjects");
    }
    const result = await run(rt, stub.fetch, verifier.verify(padded, nowMs()));
    expect(result.ok === false && result.error).toMatchObject({ reason: "malformed-token" });
  });
});

describe("OIDC verification: RFC 7515 Appendix A vectors", () => {
  // The worked examples of RFC 7515 Appendix A.2 (RS256) and A.3
  // (ES256), transcribed from the RFC (the signature values were
  // cross-checked against the octet sequences printed there during
  // development). The RFC payload (iss "joe", exp 1300819380, no
  // `iat`) predates maruhi's claim policy (§14-1 (3) requires `iat`),
  // so the vectors are pinned at the composition the verifier itself
  // uses for the cryptographic stage — the real JWKS cache (discovery
  // pinning, key selection, the JWK-side algorithm derivation, the
  // effect/jose import) feeding effect/jose's verify over the
  // verifier's canonically re-encoded token — not at verify()'s
  // claim stages, which the RFC payload cannot satisfy.
  const RFC_PAYLOAD_SEGMENT =
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

  const RFC_A2_JWK = {
    kty: "RSA",
    n: "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
    e: "AQAB",
  } as const;
  const RFC_A2_TOKEN = `eyJhbGciOiJSUzI1NiJ9.${RFC_PAYLOAD_SEGMENT}.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw`;

  const RFC_A3_JWK = {
    kty: "EC",
    crv: "P-256",
    x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
  } as const;
  const RFC_A3_TOKEN = `eyJhbGciOiJFUzI1NiJ9.${RFC_PAYLOAD_SEGMENT}.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q`;

  /** One payload character changed — the tamper control proving the positive verifies are not vacuous. */
  const tamperPayloadSegment = (token: string): string => {
    const [header, payload, signature] = token.split(".");
    if (header === undefined || payload === undefined || signature === undefined) {
      throw new Error("not a compact JWS");
    }
    const at = 10;
    const flipped = payload[at] === "A" ? "B" : "A";
    return `${header}.${payload.slice(0, at)}${flipped}${payload.slice(at + 1)}.${signature}`;
  };

  const verifyVector = async (jwk: unknown, token: string, alg: "RS256" | "ES256") => {
    const stub = stubFetch({ jwks: () => ({ keys: [jwk] }) });
    const rt = await makeTestRuntime();
    const cache = makeJwksCache();
    // The RFC headers carry no `kid`: resolution selects the one
    // usable key, and the algorithm is derived from the JWK side
    const resolved = await rt.runPromise(
      Effect.provideService(cache.resolveKey(OIDC_ISSUER, null), FetchHttpClient.Fetch, stub.fetch),
    );
    expect(resolved).not.toBeNull();
    expect(resolved?.key.algorithm).toBe(alg);
    if (resolved === null) {
      throw new Error("the RFC key did not resolve");
    }
    // The verifier's one adaptation (verifier.ts): the signature
    // segment is re-encoded canonically from its decoded bytes
    // before effect/jose sees the token (a no-op for the RFC's
    // already-canonical segments)
    const idx = token.lastIndexOf(".");
    const signature = Base64Url.decode(token.slice(idx + 1));
    if (!Result.isSuccess(signature)) {
      throw new Error("the RFC signature segment does not decode");
    }
    const canonicalToken = `${token.slice(0, idx)}.${Base64Url.encode(signature.success)}`;
    return run(rt, stub.fetch, Jws.verify(canonicalToken, resolved.key));
  };

  it("verifies the RFC 7515 Appendix A.2 example (RS256)", async () => {
    const result = await verifyVector(RFC_A2_JWK, RFC_A2_TOKEN, "RS256");
    if (result.ok !== true) {
      throw new Error("the RFC A.2 vector did not verify");
    }
    expect(result.value.protectedHeader.alg).toBe("RS256");
    const payload = JSON.parse(new TextDecoder().decode(result.value.payload)) as Record<
      string,
      unknown
    >;
    expect(payload).toMatchObject({
      iss: "joe",
      exp: 1300819380,
      "http://example.com/is_root": true,
    });
    // Tamper control: one changed payload character breaks it
    const tampered = await verifyVector(RFC_A2_JWK, tamperPayloadSegment(RFC_A2_TOKEN), "RS256");
    expect(tampered.ok).toBe(false);
  });

  it("verifies the RFC 7515 Appendix A.3 example (ES256)", async () => {
    const result = await verifyVector(RFC_A3_JWK, RFC_A3_TOKEN, "ES256");
    if (result.ok !== true) {
      throw new Error("the RFC A.3 vector did not verify");
    }
    expect(result.value.protectedHeader.alg).toBe("ES256");
    const payload = JSON.parse(new TextDecoder().decode(result.value.payload)) as Record<
      string,
      unknown
    >;
    expect(payload).toMatchObject({
      iss: "joe",
      exp: 1300819380,
      "http://example.com/is_root": true,
    });
    // Tamper control: one changed payload character breaks it
    const tampered = await verifyVector(RFC_A3_JWK, tamperPayloadSegment(RFC_A3_TOKEN), "ES256");
    expect(tampered.ok).toBe(false);
  });
});
