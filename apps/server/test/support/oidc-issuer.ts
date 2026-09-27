// Fake materials for the test OIDC issuer (AUTH_SPEC §14-1).
//
// A shared module read from **both** vitest.config.ts's outboundService (the
// Node side) and the workerd-side test code. The former serves discovery /
// JWKS; the latter signs tokens with the same key — since both sides must
// reference the same key material, the key lives here as a fixed value.
//
// **The key is a disposable dummy generated for these tests only** and is
// not used in any real environment (no real secrets in the repository —
// CLAUDE.md). It never reaches a real network: unexpected destinations are
// dropped with a 500 by outboundService.

/** The issuer v1 supports (matches SUPPORTED_ISSUERS in
 * src/oidc.package/verifier.ts). */
export const OIDC_ISSUER = "https://token.actions.githubusercontent.com";

export const OIDC_KID = "test-key-1";

/** The public key JWKS serves (ES256 / P-256). */
const OIDC_PUBLIC_JWK = {
  kty: "EC",
  crv: "P-256",
  x: "iNfHA_z5to4xNsQixaDJraQDztajJHGeMpfnURO-Neg",
  y: "30E8jN4fba7AKUMLv5XuXorD3QHqAJI-l8_BnMKy0aY",
  use: "sig",
  alg: "ES256",
  kid: OIDC_KID,
} as const;

/** The private side of the same key (used only so tests can sign tokens). */
export const OIDC_PRIVATE_JWK = {
  ...OIDC_PUBLIC_JWK,
  d: "mIuIyT-VxYQPpQMi0zwtrO_1sSATkC633euZ0SrkGBU",
  key_ops: ["sign"],
} as const;

/** The discovery document (§14-1: the issuer's self-declaration and
 * jwks_uri on the same origin). */
export const OIDC_DISCOVERY = {
  issuer: OIDC_ISSUER,
  jwks_uri: `${OIDC_ISSUER}/.well-known/jwks`,
} as const;

export const OIDC_JWKS = { keys: [OIDC_PUBLIC_JWK] } as const;

function body(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/**
 * A router called from outboundService (returns null when not addressed to
 * the issuer — the caller forwards to other fakes). Returns **only happy
 * responses**: the fetch-failure side (fail-closed and 503
 * `oidc-jwks-unavailable`) is checked by unit tests that swap out fetch
 * (test/oidc.test.ts) — outboundService runs on the Node side, so its state
 * cannot be flipped from workerd-side tests.
 */
export function fakeOidcIssuer(url: URL): Response | null {
  if (url.origin !== new URL(OIDC_ISSUER).origin) {
    return null;
  }
  if (url.pathname === "/.well-known/openid-configuration") {
    return body(OIDC_DISCOVERY);
  }
  if (url.pathname === "/.well-known/jwks") {
    return body(OIDC_JWKS);
  }
  return new Response(`unexpected issuer path in tests: ${url.pathname}`, { status: 500 });
}
