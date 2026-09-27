// The public surface of oidc.package (the ImportLint boundary).
//
// Only AUTH_SPEC §14-1's authentication stage (OIDC token
// verification) is confined here. The internals — base64url decoding,
// the JWK → WebCrypto mapping, the JWKS cache — stay inside the
// boundary; from the outside it looks like a single operation,
// "token → verified claims".
//
// Authorization (the comparison against lease_policy) is not placed
// here: separating authentication from authorization at the
// implementation-unit level is what structurally guarantees §14-3's
// "authentication failure alone is 401 / authorization failure is
// uniformly 404".

export { makeJwksCache } from "./jwks.ts";
export {
  makeOidcVerifier,
  OIDC_CLOCK_SKEW_MS,
  OidcVerifier,
  type VerifiedOidcToken,
} from "./verifier.ts";
