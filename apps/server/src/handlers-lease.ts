// Handlers for workload leases (AUTH_SPEC §14 = CRYPTO_SPEC §9.1).
//
// **Only this handler does not reference RequestAuth**: the credential
// is the OIDC token bundled in the request, and AuthMiddleware is not
// declared (api-schema's lease-api.ts).
//
// The worker carries only the authentication stage (§14-1); everything
// from authorization onward (grant / lease_policy / scope / rate
// limiting / unwrap / re-wrap / audit) is confined to one RPC on the
// project DO (top of programs-lease.ts — audit atomicity). This split
// structurally guarantees §14-3's "authentication failure alone is
// 401 / authorization failure is uniformly 404".

import {
  LeaseRateLimitedError,
  LeaseUnauthorizedError,
  LeaseUnavailableError,
  maruhiApi,
  ProjectNotFoundError,
} from "@maruhi/api-schema";
import { computeLeaseClaimsDigest } from "@maruhi/crypto";
import { Effect } from "effect";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import { toWireVariable } from "./data-http.ts";
import { OidcVerifier, type VerifiedOidcToken } from "./oidc.package/index.ts";
import { LEASE_BINDING_RETENTION_MARGIN_MS } from "./policy.ts";
import type { LeaseOutcome, LeaseTokenFacts } from "./programs-lease.ts";
import {
  IP_RATE_LIMIT_PERIOD_SECONDS,
  ipRateLimitAllowed,
  projectStub,
  rpcCall,
  WorkerEnv,
} from "./worker-env.ts";

/**
 * claims_digest (CRYPTO_SPEC §9.1) is computed from the **verified**
 * token's issuer / sub / aud. For a token whose `aud` is an array, the
 * audience placed on the digest is not uniquely determined, so **only
 * single-audience tokens are accepted on the lease path**: if the
 * implementation chose which of several audiences to take, server and
 * workload could disagree and issue an undecryptable lease (it would
 * break §9.1's premise that "both sides can independently compute the
 * same value"). GitHub Actions OIDC tokens are single-audience, so
 * this is no constraint on the v1 supported issuers.
 */
function claimsDigestFor(token: VerifiedOidcToken): Effect.Effect<string, LeaseUnauthorizedError> {
  const audience = token.audiences.length === 1 ? token.audiences[0] : undefined;
  if (audience === undefined) {
    // `aud` does exist (there are just several), so it is not
    // missing-claim — use distinct vocabulary so an operator chasing
    // the reason code does not go looking for a "claim that exists"
    return Effect.fail(new LeaseUnauthorizedError({ reason: "ambiguous-audience" }));
  }
  return Effect.flatMap(
    Effect.promise(() =>
      computeLeaseClaimsDigest({
        issuerUrl: token.issuer,
        subject: token.subject,
        audience,
      }),
    ),
    (digest) =>
      // Unreachable because the verifier has already dropped empty
      // fields (stringClaim / audiencesOf), but do not swallow crypto's
      // Result
      digest.ok
        ? Effect.succeed(digest.value)
        : Effect.fail(new LeaseUnauthorizedError({ reason: "missing-claim" })),
  );
}

/**
 * The DO's LeaseOutcome → api-schema typed errors (the response side
 * of §14-3's check order). `not-found` folds unknown project, no
 * grant, policy mismatch, out of scope, and missing environment into
 * one — do not create a response the caller can distinguish (§14-1's
 * existence hiding).
 */
function unwrapLeaseOutcome(outcome: LeaseOutcome, projectId: string) {
  if (outcome.kind === "ok") {
    return Effect.succeed(outcome.value);
  }
  const { rejection } = outcome;
  switch (rejection.kind) {
    case "rate-limited": {
      return Effect.fail(
        new LeaseRateLimitedError({
          retryAfterSeconds: rejection.retryAfterSeconds,
          scope: "project-window",
        }),
      );
    }
    case "unavailable": {
      return Effect.fail(new LeaseUnavailableError({ reason: rejection.reason }));
    }
    // A first-come-binding violation (§14-1) is not folded into 404:
    // it is a failure attributable to the presented credentials, and
    // half of its visibility is being diagnosable when it happens on
    // the legitimate job side (= the token was stolen and used first).
    // Reachable only after authorization passes, so compatible with
    // existence hiding
    case "replayed": {
      return Effect.fail(new LeaseUnauthorizedError({ reason: "token-replayed" }));
    }
    case "not-found": {
      return Effect.fail(new ProjectNotFoundError({ projectId }));
    }
  }
}

export const leaseLive = HttpApiBuilder.group(maruhiApi, "lease", (handlers) =>
  handlers.handle("issue", ({ params, payload, request }) =>
    Effect.gen(function* () {
      // 0. Request-level rate limiting on the source IP. Since a DO is
      // implicitly created by naming it, anyone holding a valid OIDC
      // token could mass-produce DOs under different project IDs (the
      // constructor creates tables) — bound the creation rate before
      // projectStub. This serves a different role than the per-project
      // window inside the DO (post-authorization — placed after the
      // 404s for §11-2's existence hiding), and this check is
      // independent of project state (IP only), so it does not break
      // existence hiding
      const env = yield* WorkerEnv;
      const allowed = yield* ipRateLimitAllowed(env.LEASE_RATE_LIMIT, request);
      if (!allowed) {
        return yield* Effect.fail(
          new LeaseRateLimitedError({
            retryAfterSeconds: IP_RATE_LIMIT_PERIOD_SECONDS,
            scope: "source-address",
          }),
        );
      }
      // 1. The authentication stage (§14-1): verify the OIDC token.
      //    No chain-derived state is consulted
      const verifier = yield* OidcVerifier;
      const token = yield* verifier.verify(payload.oidcToken, Date.now());
      const claimsDigestHex = yield* claimsDigestFor(token);
      // The first-come-binding key (§14-1) is already computed by the
      // verifier from the signed bytes (signing input) — not a hash of
      // the raw token (see the doc of VerifiedOidcToken's
      // signingInputHashHex). Only this hash, the verified claims, and
      // the lifetime reach the DO — never the token itself. The
      // lifetime is at least "the last time a time check could accept
      // this token" (policy.ts's slack derives from clock skew — a
      // binding retention shorter than the acceptance window becomes a
      // replay window of exactly that difference)
      const facts: LeaseTokenFacts = {
        issuer: token.issuer,
        subject: token.subject,
        audiences: token.audiences,
        claims: token.claims,
        claimsDigestHex,
        bindingKeyHex: token.signingInputHashHex,
        bindingExpiresAtMs: token.expiresAtSec * 1000 + LEASE_BINDING_RETENTION_MARGIN_MS,
      };
      // 2. Everything from authorization onward is a single DO RPC
      //    (audit is written under the same permit, in the same sync
      //    block)
      const outcome = yield* rpcCall<LeaseOutcome>(() =>
        projectStub(env, params.projectId).issueLease(
          params.environmentId,
          payload.ephemeralPubHex,
          facts,
        ),
      );
      const leased = yield* unwrapLeaseOutcome(outcome, params.projectId);
      // The value wire form is identical to the bulk pull (§12-7) —
      // they share the verification-material bundling discipline, so
      // the workload's client-side verification stays as §6.3
      return {
        projectId: params.projectId,
        environmentId: leased.environmentId,
        currentEpoch: leased.currentEpoch,
        chain: leased.chain,
        headSeq: leased.headSeq,
        headHashHex: leased.headHashHex,
        statement: leased.statement,
        variables: leased.variables.map((row) =>
          toWireVariable(params.projectId, params.environmentId, row),
        ),
        deletedVariables: leased.deletedVariables,
        leases: leased.leases,
        // The latest manifest (§14-2 — material for the workload's
        // verification duty §9.1 (5))
        ...(leased.manifest === undefined ? {} : { manifest: leased.manifest }),
        // The value snapshot at checkpoint time (§14-2 — same material
        // as §12-7. Material for the workload's checkpoint consistency
        // and rule 2 — CRYPTO_SPEC §6.3)
        ...(leased.checkpointSnapshot === undefined
          ? {}
          : { checkpointSnapshot: leased.checkpointSnapshot }),
      };
    }),
  ),
);
