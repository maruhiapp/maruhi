// Evaluation of lease_policy (AUTH_SPEC §14-1's authorization stage).
//
// **The chain is the source of truth for authorization** (CRYPTO_SPEC
// §9.1): which workloads may receive a lease is the lease_policy of
// grant_server payloads, not a server-mutable setting. What lives here
// is only "the evaluation semantics over the structure (the agreed
// rules)"; the chain format is untouched (the §6.2
// structure/semantics split — extending evaluation happens via an
// AUTH_SPEC §14 revision and needs no grandfathering).
//
// The check is an **existential quantification** (§14-1): one matching
// element suffices to authorize. Shaping it as "pick the matching
// element" would make the selection nondeterministic when several
// elements match, and which element matched affects neither the
// authorization result nor the lease wrap (claims_digest is computed
// from the token's issuer / sub / aud and does not depend on
// identifying the element).

import type { LeasePolicyIssuer, ServerGrant } from "@maruhi/crypto";

import type { VerifiedOidcToken } from "./oidc.package/index.ts";

/**
 * The part of the token the policy evaluation reads. It is the common
 * subset of VerifiedOidcToken (worker side) and the RPC's
 * LeaseTokenFacts (DO side); the type pins that evaluation does not
 * depend on the time fields (time checks already completed in the
 * authentication stage — §14-1).
 */
type PolicyEvaluationToken = Pick<VerifiedOidcToken, "issuer" | "audiences" | "claims">;

/**
 * Evaluation of one claim constraint (v1 = exact match only —
 * §14-1).
 *
 * **A non-string claim value never matches**: coercing numbers,
 * booleans, or arrays to strings would conflate distinct things like
 * `1` and `"1"`, `["a"]` and `"a"`, producing surprises that widen
 * authorization. Only claims enumerated in the constraint are
 * evaluated; claims outside the enumeration take no part (§14-1).
 */
function claimMatches(
  claims: Readonly<Record<string, unknown>>,
  constraint: { readonly claimName: string; readonly claimValue: string },
): boolean {
  const value = claims[constraint.claimName];
  return typeof value === "string" && value === constraint.claimValue;
}

/**
 * Evaluation of one lease_policy element: issuer_url matches the
 * token's issuer, audience is contained in the token's `aud`, and
 * **every** claim_constraint matches exactly. An element whose
 * claim_constraints is empty fails closed and does not match. Since
 * issuer is shared across all of GitHub Actions and audience is
 * caller-chosen, treating empty as unconditional allow would
 * authorize third-party workloads.
 *
 * The `aud` check is containment (contains, not equality) because RFC
 * 7519 allows `aud` to be an array. A single-string `aud` is already
 * normalized to a one-element array by the verifier, in which case
 * this check degenerates to an exact match.
 */
function elementMatches(element: LeasePolicyIssuer, token: PolicyEvaluationToken): boolean {
  return (
    element.claimConstraints.length > 0 &&
    element.issuerUrl === token.issuer &&
    token.audiences.includes(element.audience) &&
    element.claimConstraints.every((constraint) => claimMatches(token.claims, constraint))
  );
}

/**
 * The authorization decision by existential quantification (§14-1).
 * An empty lease_policy means "no lease path", so it is always false
 * (such a grant permits only registering wraps addressed to the
 * server key — CRYPTO_SPEC §6.2).
 */
export function leasePolicyAuthorizes(grant: ServerGrant, token: PolicyEvaluationToken): boolean {
  return grant.leasePolicy.some((element) => elementMatches(element, token));
}

/** Whether the disclosure scope (scope_environments) contains the target environment (§14-1). */
export function grantCoversEnvironment(grant: ServerGrant, environmentId: string): boolean {
  return grant.scopeEnvironmentIds.includes(environmentId);
}
