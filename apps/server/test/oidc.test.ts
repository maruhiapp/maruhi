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

type TestRuntime = ManagedRuntime.ManagedRuntime<TestClock.TestClock, never>;
const makeTestRuntime = async (): Promise<TestRuntime> => {
  const rt = ManagedRuntime.make(TestClock.layer());
  await rt.runPromise(TestClock.adjust(1_000_000));
  return rt;
};

const advance = (rt: TestRuntime, ms: number) => rt.runPromise(TestClock.adjust(ms));

const run = <A, E>(
  rt: TestRuntime,
  fetch: typeof globalThis.fetch,
  effect: Effect.Effect<A, E, Digest.Digest | Signature.Signature>,
) =>
  rt.runPromise(
    Effect.match(
      effect.pipe(
        Effect.provideService(FetchHttpClient.Fetch, fetch),
        Effect.provide(cryptoServicesLayer),
      ),
      {
        onSuccess: (value: A) => ({ ok: true as const, value }),
        onFailure: (error: E) => ({ ok: false as const, error }),
      },
    ),
  );

const resolve = (
  cache: ReturnType<typeof makeJwksCache>,
  rt: TestRuntime,
  fetch: typeof globalThis.fetch,
  kid: string,
) =>
  rt.runPromise(
    Effect.provideService(cache.resolveKey(OIDC_ISSUER, kid), FetchHttpClient.Fetch, fetch),
  );

const b64urlBytes = (bytes: Uint8Array): string =>
  btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");

const encodeJsonSegment = (value: unknown): string =>
  b64urlBytes(new TextEncoder().encode(JSON.stringify(value)));

function decodeSegmentBytes(segment: string): Uint8Array {
  const padded = segment
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(segment.length + ((4 - (segment.length % 4)) % 4), "=");
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

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
    expect(stub.urls.length).toBe(2);
  });

  it("folds concurrent resolveKey calls into one discovery and one JWKS fetch", async () => {
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
    expect(stub.urls.length).toBe(2);
  });

  it("force-refreshes once for an unknown kid, then respects the cooldown", async () => {
    let rotated = false;
    const stub = stubFetch({
      jwks: () => (rotated ? { keys: [{ ...OIDC_JWKS.keys[0], kid: "rotated-in" }] } : OIDC_JWKS),
    });
    const rt = await makeTestRuntime();
    const cache = makeJwksCache();

    expect(await resolve(cache, rt, stub.fetch, OIDC_KID)).not.toBeNull();
    const afterWarmup = stub.urls.length;

    rotated = true;
    expect(await resolve(cache, rt, stub.fetch, "rotated-in")).not.toBeNull();
    expect(stub.urls.length).toBe(afterWarmup + 1);

    const afterRefresh = stub.urls.length;
    expect(await resolve(cache, rt, stub.fetch, "never-existed")).toBeNull();
    expect(stub.urls.length).toBe(afterRefresh);

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

    expect(await resolve(cache, rt, stub.fetch, OIDC_KID)).not.toBeNull();

    failing = true;
    expect(await resolve(cache, rt, stub.fetch, "never-existed")).toBeNull();
    expect(await resolve(cache, rt, stub.fetch, OIDC_KID)).not.toBeNull();
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

    failing = false;
    expect((await run(rt, stub.fetch, cache.resolveKey(OIDC_ISSUER, OIDC_KID))).ok).toBe(false);
    expect(stub.urls.filter((url) => url.endsWith("/jwks")).length).toBe(1);

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

    failing = true;
    await advance(rt, 20 * 60 * 1000);
    expect(await resolve(cache, rt, stub.fetch, OIDC_KID)).not.toBeNull();

    await advance(rt, 6 * 60 * 60 * 1000);
    expect((await run(rt, stub.fetch, cache.resolveKey(OIDC_ISSUER, OIDC_KID))).ok).toBe(false);
  });

  it("does not re-fetch on every request while the issuer stays down (cuts off amplification)", async () => {
    let failing = false;
    const stub = stubFetch({ failJwks: () => failing });
    const rt = await makeTestRuntime();
    const cache = makeJwksCache();
    expect(await resolve(cache, rt, stub.fetch, OIDC_KID)).not.toBeNull();

    failing = true;
    await advance(rt, 20 * 60 * 1000);
    expect(await resolve(cache, rt, stub.fetch, OIDC_KID)).not.toBeNull();
    const afterFirstFailure = stub.urls.length;

    for (let attempt = 0; attempt < 5; attempt += 1) {
      expect(await resolve(cache, rt, stub.fetch, OIDC_KID)).not.toBeNull();
    }
    expect(stub.urls.length).toBe(afterFirstFailure);

    await advance(rt, 61_000);
    failing = false;
    expect(await resolve(cache, rt, stub.fetch, OIDC_KID)).not.toBeNull();
    expect(stub.urls.length).toBe(afterFirstFailure + 1);
  });

  it("settles the shared load when the fetch dies with a defect, then retries after the cooldown", async () => {
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
    const stub = stubFetch({ hang: true });
    const rt = await makeTestRuntime();
    const pending = run(rt, stub.fetch, makeJwksCache().resolveKey(OIDC_ISSUER, OIDC_KID));
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
    expect((await run(rt, stub.fetch, verifier.verify(token, Date.now()))).ok).toBe(true);
    const later = await run(rt, stub.fetch, verifier.verify(token, Date.now() + 90_000));
    expect(later.ok === false && later.error).toMatchObject({ reason: "token-expired" });
  });

  it("rejects a token whose payload is not a JSON object", async () => {
    const stub = stubFetch();
    const rt = await makeTestRuntime();
    const verifier = makeOidcVerifier();
    const segment = btoa("[1,2,3]").replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    const header = btoa(JSON.stringify({ alg: "ES256", kid: OIDC_KID }))
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replaceAll("=", "");
    const result = await run(rt, stub.fetch, verifier.verify(`${header}.${segment}.AAAA`, nowMs()));
    expect(result.ok === false && result.error).toMatchObject({ reason: "malformed-token" });
  });

  it("rejects a JWS that declares a crit extension (RFC 7515 §4.1.11)", async () => {
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
    const stub = stubFetch();
    const rt = await makeTestRuntime();
    const verifier = makeOidcVerifier();
    const token = `${encodeJsonSegment({ alg: "none", typ: "JWT", kid: OIDC_KID })}.${encodeJsonSegment(testClaims())}.`;
    const result = await run(rt, stub.fetch, verifier.verify(token, nowMs()));
    expect(result.ok === false && result.error).toMatchObject({ reason: "unsupported-alg" });
    expect(stub.urls.length).toBe(0);
  });

  it("rejects an HS256 token HMAC-signed with the public key material (algorithm confusion)", async () => {
    const stub = stubFetch();
    const rt = await makeTestRuntime();
    const verifier = makeOidcVerifier();
    const signingInput = `${encodeJsonSegment({ alg: "HS256", typ: "JWT", kid: OIDC_KID })}.${encodeJsonSegment(testClaims())}`;
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
    expect((await run(rt, stub.fetch, verifier.verify(token, nowMs()))).ok).toBe(true);
    const result = await run(
      rt,
      stub.fetch,
      verifier.verify(`${malleated}.${payload}.${signature}`, nowMs()),
    );
    expect(result.ok === false && result.error).toMatchObject({ reason: "signature-invalid" });
  });

  it("rejects a byte-identical re-spelling of the payload segment", async () => {
    const stub = stubFetch();
    const rt = await makeTestRuntime();
    const verifier = makeOidcVerifier();
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
    expect((await run(rt, stub.fetch, verifier.verify(original, nowMs()))).ok).toBe(true);
    const result = await run(rt, stub.fetch, verifier.verify(respelled, nowMs()));
    expect(result.ok === false && result.error).toMatchObject({ reason: "signature-invalid" });
  });

  it("rejects a segment carrying = padding as malformed (the strict segment shape)", async () => {
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
    const resolved = await rt.runPromise(
      Effect.provideService(cache.resolveKey(OIDC_ISSUER, null), FetchHttpClient.Fetch, stub.fetch),
    );
    expect(resolved).not.toBeNull();
    expect(resolved?.key.algorithm).toBe(alg);
    if (resolved === null) {
      throw new Error("the RFC key did not resolve");
    }
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
    const tampered = await verifyVector(RFC_A3_JWK, tamperPayloadSegment(RFC_A3_TOKEN), "ES256");
    expect(tampered.ok).toBe(false);
  });
});
