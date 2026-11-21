export const OIDC_ISSUER = "https://token.actions.githubusercontent.com";

export const OIDC_KID = "test-key-1";

const OIDC_PUBLIC_JWK = {
  kty: "EC",
  crv: "P-256",
  x: "iNfHA_z5to4xNsQixaDJraQDztajJHGeMpfnURO-Neg",
  y: "30E8jN4fba7AKUMLv5XuXorD3QHqAJI-l8_BnMKy0aY",
  use: "sig",
  alg: "ES256",
  kid: OIDC_KID,
} as const;

export const OIDC_PRIVATE_JWK = {
  ...OIDC_PUBLIC_JWK,
  d: "mIuIyT-VxYQPpQMi0zwtrO_1sSATkC633euZ0SrkGBU",
  key_ops: ["sign"],
} as const;

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
