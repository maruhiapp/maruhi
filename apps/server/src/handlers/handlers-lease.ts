import {
  LeaseRateLimitedError,
  LeaseResponseSchema,
  LeaseUnauthorizedError,
  LeaseUnavailableError,
  maruhiApi,
  ProjectNotFoundError,
  RotationProposalRejectedError,
} from "@maruhi/api-schema";
import type { EnvironmentId, ProjectId } from "@maruhi/core";
import { cryptoEffect } from "@maruhi/core";
import { type ChainEntry, computeLeaseClaimsDigest } from "@maruhi/crypto";
import { Clock, Effect, Schema } from "effect";
import { HttpServerResponse } from "effect/http";
import { HttpApiBuilder } from "effect/http-api";

import { toWireVariable } from "../data.package/index.ts";
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
import { jsonStream } from "./json-stream.ts";

function claimsDigestFor(token: VerifiedOidcToken): Effect.Effect<string, LeaseUnauthorizedError> {
  const audience = token.audiences.length === 1 ? token.audiences[0] : undefined;
  if (audience === undefined) {
    return Effect.fail(new LeaseUnauthorizedError({ reason: "ambiguous-audience" }));
  }
  return cryptoEffect(() =>
    computeLeaseClaimsDigest({
      issuerUrl: token.issuer,
      subject: token.subject,
      audience,
    }),
  ).pipe(Effect.mapError(() => new LeaseUnauthorizedError({ reason: "missing-claim" })));
}

function leaseRejectionError(rejection: LeaseRejection, projectId: ProjectId) {
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
    case "replayed": {
      return new LeaseUnauthorizedError({ reason: "token-replayed" });
    }
    case "not-found": {
      return new ProjectNotFoundError({ projectId });
    }
  }
}

function unwrapLeaseOutcome(outcome: LeaseOutcome, projectId: ProjectId) {
  return outcome.kind === "ok"
    ? Effect.succeed(outcome)
    : Effect.fail(leaseRejectionError(outcome.rejection, projectId));
}

const authenticateWorkload = Effect.fn("handlers-lease.authenticateWorkload")(function* (
  payload: { readonly oidcToken: string; readonly ephemeralPubHex: string },
  request: { readonly source: unknown },
) {
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
  const verifier = yield* OidcVerifier;
  const token = yield* verifier.verify(payload.oidcToken, yield* Clock.currentTimeMillis);
  const claimsDigestHex = yield* claimsDigestFor(token);
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

function proposalRejectionError(rejection: ProposalRejection, projectId: ProjectId) {
  return rejection.kind === "proposal-rejected"
    ? new RotationProposalRejectedError({ reason: rejection.reason })
    : leaseRejectionError(rejection, projectId);
}

function unwrapProposalOutcome(outcome: ProposalOutcome, projectId: ProjectId) {
  return outcome.kind === "ok"
    ? Effect.succeed(outcome.value)
    : Effect.fail(proposalRejectionError(outcome.rejection, projectId));
}

interface WorkloadParams {
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
}

const workloadRpc = Effect.fn("handlers-lease.workloadRpc")(function* <T>(
  params: WorkloadParams,
  payload: Parameters<typeof authenticateWorkload>[0],
  request: Parameters<typeof authenticateWorkload>[1],
  call: (stub: ReturnType<typeof projectStub>, facts: LeaseTokenFacts) => Promise<T>,
) {
  const { env, facts } = yield* authenticateWorkload(payload, request);
  return yield* rpcCall<T>(() => call(projectStub(env, params.projectId), facts)).pipe(
    Effect.orDie,
  );
});

export const leaseLive = HttpApiBuilder.group(maruhiApi, "lease", (handlers) =>
  handlers
    .handle(
      "issue",
      Effect.fn("handlers-lease.issue")(function* ({ params, payload, request }) {
        const outcome = yield* workloadRpc<LeaseOutcome>(params, payload, request, (stub, facts) =>
          stub.issueLease(params.environmentId, payload.ephemeralPubHex, facts),
        );
        const { value: leased, chainToken } = yield* unwrapLeaseOutcome(outcome, params.projectId);
        const env = yield* WorkerEnv;
        const chain = yield* rpcCall<readonly ChainEntry[]>(() =>
          projectStub(env, params.projectId).leaseChain(chainToken),
        ).pipe(Effect.orDie);
        const response: typeof LeaseResponseSchema.Type = {
          projectId: params.projectId,
          environmentId: leased.environmentId,
          currentEpoch: leased.currentEpoch,
          chain,
          headSeq: leased.headSeq,
          headHashHex: leased.headHashHex,
          statement: leased.statement,
          variables: leased.variables.map((row) =>
            toWireVariable(params.projectId, params.environmentId, row),
          ),
          deletedVariables: leased.deletedVariables,
          ...(leased.declaredVariables === undefined
            ? {}
            : { declaredVariables: leased.declaredVariables }),
          leases: leased.leases,
          manifest: leased.manifest,
          ...(leased.checkpointSnapshot === undefined
            ? {}
            : { checkpointSnapshot: leased.checkpointSnapshot }),
        };
        const encoded = yield* Schema.encodeEffect(LeaseResponseSchema)(response).pipe(
          Effect.orDie,
        );
        return HttpServerResponse.raw(jsonStream(encoded), { contentType: "application/json" });
      }),
    )
    .handle(
      "preflight",
      Effect.fn("handlers-lease.preflight")(function* ({ params, payload, request }) {
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
    .handle(
      "propose",
      Effect.fn("handlers-lease.propose")(function* ({ params, payload, request }) {
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
