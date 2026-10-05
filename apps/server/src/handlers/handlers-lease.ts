// Handlers for workload leases (AUTH_SPEC §14 = CRYPTO_SPEC §9.1) and the
// sealed-proposal mint that shares their credential (AUTH_SPEC §14-5 =
// CRYPTO_SPEC §5.3).
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
  RotationProposalRejectedError,
} from "@maruhi/api-schema";
import { cryptoEffect } from "@maruhi/core";
import { computeLeaseClaimsDigest } from "@maruhi/crypto";
import { Clock, Effect } from "effect";
import { HttpApiBuilder } from "effect/http-api";

import { toWireVariable } from "../data/data-http.ts";
import { OidcVerifier, type VerifiedOidcToken } from "../oidc.package/index.ts";
import { LEASE_BINDING_RETENTION_MARGIN_MS } from "../policy.ts";
import type { LeaseOutcome, LeaseRejection, LeaseTokenFacts } from "../programs/programs-lease.ts";
import type {
  PreflightOutcome,
  ProposalOutcome,
  ProposalRejection,
} from "../programs/programs-proposal.ts";
import {
  IP_RATE_LIMIT_PERIOD_SECONDS,
  ipRateLimitAllowed,
  projectStub,
  rpcCall,
  WorkerEnv,
} from "../worker-env.ts";

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
  // Unreachable because the verifier has already dropped empty
  // fields (stringClaim / audiencesOf), but a wrapped crypto error is
  // still mapped rather than swallowed
  return cryptoEffect(() =>
    computeLeaseClaimsDigest({
      issuerUrl: token.issuer,
      subject: token.subject,
      audience,
    }),
  ).pipe(Effect.mapError(() => new LeaseUnauthorizedError({ reason: "missing-claim" })));
}

/**
 * The DO's LeaseOutcome → api-schema typed errors (the response side
 * of §14-3's check order). `not-found` folds unknown project, no
 * grant, policy mismatch, out of scope, and missing environment into
 * one — do not create a response the caller can distinguish (§14-1's
 * existence hiding).
 */
function leaseRejectionError(rejection: LeaseRejection, projectId: string) {
  switch (rejection.kind) {
    case "rate-limited": {
      return new LeaseRateLimitedError({
        retryAfterSeconds: rejection.retryAfterSeconds,
        scope: "project-window",
      });
    }
    case "unavailable": {
      return new LeaseUnavailableError({ reason: rejection.reason });
    }
    // A first-come-binding violation (§14-1) is not folded into 404:
    // it is a failure attributable to the presented credentials, and
    // half of its visibility is being diagnosable when it happens on
    // the legitimate job side (= the token was stolen and used first).
    // Reachable only after authorization passes, so compatible with
    // existence hiding
    case "replayed": {
      return new LeaseUnauthorizedError({ reason: "token-replayed" });
    }
    case "not-found": {
      return new ProjectNotFoundError({ projectId });
    }
  }
}

function unwrapLeaseOutcome(outcome: LeaseOutcome, projectId: string) {
  return outcome.kind === "ok"
    ? Effect.succeed(outcome.value)
    : Effect.fail(leaseRejectionError(outcome.rejection, projectId));
}

/**
 * The authentication stage shared by the lease and the sealed-proposal
 * mint (§14-1 / §14-5): the source-IP limit, OIDC verification, and the
 * facts of the verified token. No chain-derived state is consulted —
 * everything from authorization onward is one DO RPC.
 */
const authenticateWorkload = (
  payload: { readonly oidcToken: string; readonly ephemeralPubHex: string },
  request: { readonly source: unknown },
) =>
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
    const token = yield* verifier.verify(payload.oidcToken, yield* Clock.currentTimeMillis);
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
    return { env, facts };
  });

/** The mint's rejections → api-schema errors: the lease vocabulary as-is, plus the §14-5 acceptance reasons (422). */
function proposalRejectionError(rejection: ProposalRejection, projectId: string) {
  return rejection.kind === "proposal-rejected"
    ? new RotationProposalRejectedError({ reason: rejection.reason })
    : leaseRejectionError(rejection, projectId);
}

function unwrapProposalOutcome(outcome: ProposalOutcome, projectId: string) {
  return outcome.kind === "ok"
    ? Effect.succeed(outcome.value)
    : Effect.fail(proposalRejectionError(outcome.rejection, projectId));
}

/** The coordinates of a workload call: the project and the environment. */
interface WorkloadParams {
  readonly projectId: string;
  readonly environmentId: string;
}

/**
 * Authenticates the workload (step 1), then runs one DO RPC under its
 * credential — everything from authorization onward is that single RPC
 * (the audit is written under the same permit, in the same sync block).
 */
function workloadRpc<T>(
  params: WorkloadParams,
  payload: Parameters<typeof authenticateWorkload>[0],
  request: Parameters<typeof authenticateWorkload>[1],
  call: (stub: ReturnType<typeof projectStub>, facts: LeaseTokenFacts) => Promise<T>,
) {
  return Effect.gen(function* () {
    const { env, facts } = yield* authenticateWorkload(payload, request);
    // An RPC failure has no typed answer here: a defect (500), as before
    return yield* rpcCall<T>(() => call(projectStub(env, params.projectId), facts)).pipe(
      Effect.orDie,
    );
  });
}

export const leaseLive = HttpApiBuilder.group(maruhiApi, "lease", (handlers) =>
  handlers
    .handle("issue", ({ params, payload, request }) =>
      Effect.gen(function* () {
        const outcome = yield* workloadRpc<LeaseOutcome>(params, payload, request, (stub, facts) =>
          stub.issueLease(params.environmentId, payload.ephemeralPubHex, facts),
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
    )
    // The mint's pre-flight (§14-5 — O-4): the same credential and
    // authorization, no wraps, nothing stored — a job learns before the
    // issuer is touched that its proposal would be refused or would stack
    .handle("preflight", ({ params, payload, request }) =>
      Effect.gen(function* () {
        const outcome = yield* workloadRpc<PreflightOutcome>(
          params,
          payload,
          request,
          (stub, facts) =>
            stub.preflightRotation(
              params.environmentId,
              payload.ephemeralPubHex,
              facts,
              payload.variables,
              payload.recipients,
            ),
        );
        if (outcome.kind === "rejected") {
          return yield* Effect.fail(proposalRejectionError(outcome.rejection, params.projectId));
        }
        return { ok: true as const };
      }),
    )
    // The sealed-proposal mint (§14-5 = CRYPTO_SPEC §5.3): the same
    // credential and the same DO-side authorization as the lease; the
    // server stores ciphertexts it cannot open and touches no key
    .handle("propose", ({ params, payload, request }) =>
      Effect.gen(function* () {
        const outcome = yield* workloadRpc<ProposalOutcome>(
          params,
          payload,
          request,
          (stub, facts) =>
            stub.proposeRotation(
              params.environmentId,
              payload.ephemeralPubHex,
              facts,
              payload.proposal,
            ),
        );
        return yield* unwrapProposalOutcome(outcome, params.projectId);
      }),
    ),
);
