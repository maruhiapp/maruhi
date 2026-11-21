import type { EnvironmentId } from "@maruhi/core";
import type { LeasePolicyIssuer, ServerGrant } from "@maruhi/crypto";

import type { VerifiedOidcToken } from "./oidc.package/index.ts";

type PolicyEvaluationToken = Pick<VerifiedOidcToken, "issuer" | "audiences" | "claims">;

function claimMatches(
  claims: Readonly<Record<string, unknown>>,
  constraint: { readonly claimName: string; readonly claimValue: string },
): boolean {
  const value = claims[constraint.claimName];
  return typeof value === "string" && value === constraint.claimValue;
}

function elementMatches(element: LeasePolicyIssuer, token: PolicyEvaluationToken): boolean {
  return (
    element.claimConstraints.length > 0 &&
    element.issuerUrl === token.issuer &&
    token.audiences.includes(element.audience) &&
    element.claimConstraints.every((constraint) => claimMatches(token.claims, constraint))
  );
}

export function leasePolicyAuthorizes(grant: ServerGrant, token: PolicyEvaluationToken): boolean {
  return grant.leasePolicy.some((element) => elementMatches(element, token));
}

export function grantCoversEnvironment(grant: ServerGrant, environmentId: EnvironmentId): boolean {
  return grant.scopeEnvironmentIds.includes(environmentId);
}
