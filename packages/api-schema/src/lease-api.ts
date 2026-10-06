// HttpApi definition of the workload-lease API (AUTH_SPEC §14 =
// CRYPTO_SPEC §9.1).
//
// **This group alone declares no AuthMiddleware**: the credential is the
// OIDC token bundled in the request itself; maruhi sessions and API
// tokens are not used (§14-1 — outside §12-3's authorization table). It
// is also the API-surface statement that this path exists for workloads
// with no long-lived credential.
//
// The API-boundary invariant (CRYPTO_SPEC §10) is unchanged on the lease
// path too: responses carry only ciphertexts and wraps — plaintext
// values, DEKs, and private keys never appear. Lease wraps travel as
// LeasedDek (a separate type with no registration signature —
// data.ts).

import { EnvironmentIdSchema, ProjectIdSchema, VariableIdSchema } from "@maruhi/core";
import { Schema } from "effect";
import { HttpApiEndpoint, HttpApiGroup } from "effect/http-api";

import { ChainEntrySchema } from "./chain.ts";
import { PulledVariableSchema } from "./data-api.ts";
import {
  BoundedUserId,
  CheckpointValueSnapshotSchema,
  DistributedEnvironmentMetaStatementSchema,
  DistributedVariableMetaStatementSchema,
  LeasedDekSchema,
  RequiredDistributedEnvironmentManifestSchema,
} from "./data.ts";
import {
  LeaseRateLimitedError,
  LeaseUnauthorizedError,
  LeaseUnavailableError,
  ProjectNotFoundError,
  RotationProposalRejectedError,
} from "./errors/index.ts";
import { EncPubHex, PositiveInt, Sha256Hex } from "./hex.ts";
import { RotationProposalInputSchema, RotationProposalReceiptSchema } from "./rotation-api.ts";
import { strictPayload } from "./strict.ts";

/**
 * Acceptance policy (§14-3): oidcToken is at most 16 KiB. Unlike a
 * value it has no dedicated verification layer, so the Schema enforces
 * it (same discipline as the 256-char cap on display names — §12-8). A
 * JWT is a compact serialization made only of base64url + `.`, and the
 * character set is narrowed here too (obvious foreign matter is dropped
 * before parsing).
 */
const OidcTokenSchema = Schema.String.check(
  Schema.isMaxLength(16 * 1024),
  Schema.isPattern(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, {
    description: "compact JWS (three base64url segments)",
  }),
);

/**
 * Lease request (AUTH_SPEC §14-2): the workload's OIDC token and the ephemeral
 * X25519 public key it generated in memory for this job. The matching private
 * key never leaves the workload and dies with the job, so the response is
 * worthless to anyone else (CRYPTO_SPEC §9.1).
 */
export const LeaseRequestSchema = Schema.Struct({
  oidcToken: OidcTokenSchema,
  ephemeralPubHex: EncPubHex,
});

/**
 * Lease response (AUTH_SPEC §14-2). Shaped like the bulk pull (§12-7) — the
 * same verification material travels with every value and statement — plus
 * two differences that follow from the recipient not being a chain member:
 *
 * - **the chain travels with it**: the chain API returns 404 to non-members
 *   (§11-2), so this response is the workload's only distribution channel for
 *   the material its §6.3 verification needs
 * - **`leases` instead of `deks`**: server-generated, response-scoped wraps
 *   sealed to the ephemeral key (CRYPTO_SPEC §9.1), never the stored
 *   `RecipientDek` wraps a chain member registered
 *
 * The workload must run the §9.1 verification duties (chain verification with
 * a pre-pinned genesis, repository anchor, commitment matching, value and
 * statement signatures) before using anything here.
 */
export const LeaseResponseSchema = Schema.Struct({
  projectId: ProjectIdSchema,
  environmentId: EnvironmentIdSchema,
  currentEpoch: PositiveInt,
  // The whole chain (the §14-2 bundle). The workload pre-pins the
  // genesis and runs the §6.3 verification itself — it must not trust a
  // server-declared head
  chain: Schema.Array(ChainEntrySchema),
  headSeq: PositiveInt,
  headHashHex: Sha256Hex,
  statement: DistributedEnvironmentMetaStatementSchema,
  variables: Schema.Array(PulledVariableSchema),
  deletedVariables: Schema.Array(DistributedVariableMetaStatementSchema),
  /**
   * The latest statements of declared variables (the §12-7
   * distribution rule applied to lease responses too — statements only,
   * no values. Material for the workload's manifest-digest
   * recomputation [§9.1 (5)]. Absent in environments with no declared
   * variables).
   */
  declaredVariables: Schema.optionalKey(Schema.Array(DistributedVariableMetaStatementSchema)),
  leases: Schema.Array(LeasedDekSchema),
  /**
   * The latest environment manifest + issuer info (§14-2). Material for
   * the workload's verification duty §9.1 (5) (digest recomputation,
   * epoch consistency). Required — a created environment always has a
   * stored manifest (§12-4); a missing one is refused, same as pull
   * (CRYPTO_SPEC §6.3).
   */
  manifest: RequiredDistributedEnvironmentManifestSchema,
  /**
   * Enumeration of the checkpoint-time value snapshot (§14-2 — same
   * material as §12-7). The workload's checkpoint-consistency
   * verification (CRYPTO_SPEC §6.3 rule 2) refuses a response that
   * lacks the enumeration while a baseline `checkpoint` for that
   * environment exists on the bundled chain. Absent in environments
   * with no baseline (then it is a warning — §6.3 SHOULD).
   */
  checkpointSnapshot: Schema.optionalKey(CheckpointValueSnapshotSchema),
});

/**
 * Workload lease (AUTH_SPEC §14 = CRYPTO_SPEC §9.1): a CI job with no
 * long-lived credential presents an OIDC token and an ephemeral public key,
 * and receives the environment's chain, ciphertexts, statements and the epoch
 * DEKs re-sealed to that ephemeral key. The server opens only its own
 * server-addressed wraps — it never decrypts a value (§9.1).
 *
 * Decision order (§14-3): OIDC verification (401) → lease_policy match
 * + disclosure scope (any mismatch is uniformly 404) → first-come
 * binding (same token + a different key is 401 `token-replayed` —
 * §14-1) → environment existence (404) → rate limit (429) → server
 * wraps exist (503). The rate limit sits behind authorization for
 * §11-2 existence concealment (errors/lease.ts). `token-replayed` is
 * the only 401 reachable after authorization passes, and is compatible
 * with existence concealment (LeaseUnauthorizedReasonSchema in
 * errors/lease.ts).
 */
/**
 * The sealed-proposal mint (AUTH_SPEC §14-5 = CRYPTO_SPEC §5.3): the
 * same credential as the lease (the OIDC token and the ephemeral key the
 * job leased with — one token, one key) plus the proposal. Authentication
 * and authorization are the lease's; the server never touches the server
 * key on this path (nothing is unwrapped), so a copy of the token in
 * other hands is refused by the first-come binding before anything is
 * stored.
 */
export const RotationProposalRequestSchema = Schema.Struct({
  ...LeaseRequestSchema.fields,
  proposal: RotationProposalInputSchema,
});

/**
 * The mint's pre-flight (AUTH_SPEC §14-5 — ruling O-4): the same credential
 * and authorization as the mint, no wraps; every §14-5 check that needs no
 * sealed value runs (the variables exist and are active at the named base
 * versions, no proposal already targets one of them, the pending cap, the
 * mirror mark), so a CI job learns **before the issuer is touched** that
 * its proposal would be refused or would stack on one a member has not
 * acted on. Nothing is stored; the token's first-come binding is taken.
 */
export const RotationPreflightRequestSchema = Schema.Struct({
  ...LeaseRequestSchema.fields,
  variables: Schema.Array(
    Schema.Struct({ variableId: VariableIdSchema, baseVersion: PositiveInt }),
  ).check(Schema.isMinLength(1), Schema.isMaxLength(8)),
  /**
   * The recipient set the job will seal to (public chain facts — user id
   * and device enc public key), checked against W(E) before the issuer is
   * touched (ruling O revision, round 4); the mint repeats the check on
   * the wraps. W(E) is bounded by the chain's capacity, not by a member
   * cap; the bound is the §12-8 DEK-wrap row cap, set above that for the
   * same reason (the mint's wraps carry the same set).
   */
  recipients: Schema.optionalKey(
    Schema.Array(Schema.Struct({ userId: BoundedUserId, encPubHex: EncPubHex })).check(
      Schema.isMaxLength(10_000),
    ),
  ),
});

/** The pre-flight passed (the proposal would be accepted as far as its content is not involved). */
export const RotationPreflightResultSchema = Schema.Struct({ ok: Schema.Literal(true) });

export const leaseGroup = HttpApiGroup.make("lease")
  .add(
    HttpApiEndpoint.post(
      "propose",
      "/projects/:projectId/environments/:environmentId/rotation-proposals",
      {
        params: { projectId: ProjectIdSchema, environmentId: EnvironmentIdSchema },
        payload: strictPayload(RotationProposalRequestSchema),
        success: RotationProposalReceiptSchema,
        error: [
          LeaseUnauthorizedError,
          // The same uniform 404 as the lease (§14-1 existence concealment)
          ProjectNotFoundError,
          LeaseRateLimitedError,
          LeaseUnavailableError,
          // Judged after authorization (§14-5 — the reason leaks nothing new)
          RotationProposalRejectedError,
        ],
      },
    ),
  )
  .add(
    HttpApiEndpoint.post(
      "preflight",
      "/projects/:projectId/environments/:environmentId/rotation-proposals/preflight",
      {
        params: { projectId: ProjectIdSchema, environmentId: EnvironmentIdSchema },
        payload: strictPayload(RotationPreflightRequestSchema),
        success: RotationPreflightResultSchema,
        error: [
          LeaseUnauthorizedError,
          ProjectNotFoundError,
          LeaseRateLimitedError,
          LeaseUnavailableError,
          RotationProposalRejectedError,
        ],
      },
    ),
  )
  .add(
    HttpApiEndpoint.post("issue", "/projects/:projectId/environments/:environmentId/lease", {
      params: { projectId: ProjectIdSchema, environmentId: EnvironmentIdSchema },
      // strict acceptance (§12-10 (1)). The shared LeaseRequestSchema
      // itself is not wrapped (so it does not propagate into other
      // endpoints' responses). strict covers only this payload's decode /
      // encode; it does not reach the success / error encodings.
      payload: strictPayload(LeaseRequestSchema),
      success: LeaseResponseSchema,
      error: [
        LeaseUnauthorizedError,
        // Unknown project / no grant / policy mismatch / out of scope /
        // missing environment all fold into **this one kind** (§14-1
        // existence concealment). EnvironmentNotFound is not declared
        // separately: a form that reveals an environment's absence only to
        // callers who passed authorization is worthless on the lease path
        // (the workload holds the environment ID as configuration, so an
        // absent one is a configuration mistake and a 404 suffices),
        // while two 404s side by side in the contract would give the
        // implementation a choice of which to return
        ProjectNotFoundError,
        LeaseRateLimitedError,
        LeaseUnavailableError,
      ],
    }),
  );
