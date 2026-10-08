// HttpApi definition of the membership log (CRYPTO_SPEC §6.4). The
// shared source for the server implementation (apps/server) and the
// future derived CLI client.
//
// API-boundary invariant (§10): no type in this file represents a
// plaintext secret, a DEK, or a master private key. Chain entries are
// signed public data.

import { OrgIdSchema, ProjectIdSchema } from "@maruhi/core";
import { Schema } from "effect";
import { HttpApi, HttpApiEndpoint, HttpApiGroup, HttpApiSchema } from "effect/http-api";

import { auditGroup } from "./audit-api.ts";
import { authGroup } from "./auth-api.ts";
import { authCliGroup } from "./auth-cli-api.ts";
import { AuthMiddleware } from "./auth-middleware.ts";
import { ChainEntrySchema, RoleSchema } from "./chain.ts";
import { deksGroup, environmentsGroup, schemaPolicyGroup, variablesGroup } from "./data-api.ts";
import { devicesGroup } from "./devices-api.ts";
import {
  AttestationRateLimitedError,
  AttestationRegressionError,
  AttestationRejectedError,
  AuditHeadNotReadyError,
  ChainCapacityExceededError,
  ChainEntryInvalidError,
  ChainEntryTooLargeError,
  ChainHeadConflictError,
  CheckpointStateMismatchError,
  CompositeRequiredError,
  DataLimitExceededError,
  DeviceLimitError,
  ForbiddenError,
  ProjectAlreadyInitializedError,
  ProjectLimitError,
  ProjectNotFoundError,
  ProposalLimitError,
} from "./errors/index.ts";
import { exportGroup } from "./export-api.ts";
import { HeadAttestationSignatureHex, KeyFingerprintHex, PositiveInt, Sha256Hex } from "./hex.ts";
import { invitesGroup } from "./invites-api.ts";
import { keyWrapsGroup } from "./key-wraps-api.ts";
import { leaseGroup } from "./lease-api.ts";
import { mirrorGroup } from "./mirror-api.ts";
import { rotationGroup } from "./rotation-api.ts";
import { assertSessionCapabilityClassified } from "./session-capability.ts";
import { assertSecurityCriticalPayloadsStrict, strictPayload } from "./strict.ts";

/** Chain head after a successful initialization or append. */
export const ChainHeadSchema = Schema.Struct({
  projectId: ProjectIdSchema,
  headSeq: PositiveInt,
  headHashHex: Sha256Hex,
});

/**
 * Submission request of a head attestation (CRYPTO_SPEC §6.6 /
 * AUTH_SPEC §16-1). The attester is the calling principal (§12-5's
 * "calling principal = signer" rule — the wire has no attester field).
 */
export const HeadAttestationSubmissionSchema = Schema.Struct({
  suite: Schema.Literal("maruhi/v1"),
  chainHeadHashHex: Sha256Hex,
  chainHeadSeq: PositiveInt,
  signatureHex: HeadAttestationSignatureHex,
});

/**
 * The distributed form of a head attestation (AUTH_SPEC §16-1 — the
 * `attestations` of the chain-fetch response). attesterUserId +
 * attesterKeyFingerprintHex have the same shape as §12-2's verification
 * material (the recipient matches them against the chain history to run
 * CRYPTO_SPEC §6.6's client verification). The server's acceptance time
 * is not distributed (it confines the action information an attestation
 * carries to "the reached point of chain sync" — §16-1).
 */
export const DistributedHeadAttestationSchema = Schema.Struct({
  suite: Schema.Literal("maruhi/v1"),
  attesterUserId: Schema.String,
  attesterKeyFingerprintHex: KeyFingerprintHex,
  chainHeadHashHex: Sha256Hex,
  chainHeadSeq: PositiveInt,
  signatureHex: HeadAttestationSignatureHex,
});

/**
 * Full chain as stored by the project DO (entries in seq order).
 *
 * `attestations` = the current members' latest head-attestation set
 * (AUTH_SPEC §16-1). Omitted distribution is CRYPTO_SPEC §6.3's
 * normative non-guarantee (G8), so an empty set is not refused.
 */
export const ChainSnapshotSchema = Schema.Struct({
  projectId: ProjectIdSchema,
  entries: Schema.Array(ChainEntrySchema),
  headSeq: PositiveInt,
  headHashHex: Sha256Hex,
  attestations: Schema.Array(DistributedHeadAttestationSchema),
});

/**
 * One row of the list (AUTH_SPEC §11-5). `role` is the **chain-derived
 * role at acceptance time** that each project DO returns at read time —
 * not the D1 projection (candidate index) value (the projection holds
 * no role). It is a server-declared display value; verified state is
 * the domain of `maruhi project verify` / chain fetch + client
 * verification.
 */
export const ProjectMembershipSchema = Schema.Struct({
  projectId: ProjectIdSchema,
  role: RoleSchema,
});

/**
 * The `GET /projects` response (AUTH_SPEC §11-5). `nextAfter` is a
 * cursor carried only when the D1 candidate page is full (server-fixed
 * 100 rows) (the exclusive lower bound in project_id ascending order).
 * Org membership, creation time, and head info are deliberately absent
 * (the minimal form that does not disclose other orgs' membership info
 * to cross-org members — session-42 ruling BK).
 */
export const ProjectListSchema = Schema.Struct({
  projects: Schema.Array(ProjectMembershipSchema),
  nextAfter: Schema.optionalKey(ProjectIdSchema),
});

/**
 * Membership-log endpoints (CRYPTO_SPEC §6.4). Every endpoint requires
 * authentication (AUTH_SPEC §11-1; AuthMiddleware supplies the 401 /
 * CSRF 403).
 *
 * - `init`: submit a genesis entry; the server verifies it and derives the
 *   project id as the genesis entry hash. `orgId` is the destination
 *   org (§11-3; creation permission = org member or higher). Responses
 *   to non-members / out-of-scope are uniformly 404 (§11-2). When the
 *   org's active-project count has reached the cap (AUTH_SPEC §11-3 —
 *   drafted value 100), a **fresh** genesis is 429 `ProjectLimit` (the
 *   repair path = re-init of an already-initialized project passes
 *   regardless of the cap).
 * - `get`: fetch the stored chain for client-side verification (§6.3).
 * - `append`: append one entry; `parentHeadHashHex` is the compare-and-swap
 *   parent (§6.4). Distinct from §6.3's "signed declared head" (head
 *   gossip). Requires an exact match between the authenticated
 *   principal and entry.actor (§11-1).
 *   `create_environment` / `rotate_epoch` are accepted only via the
 *   composite endpoints (create / rotate on the environments group —
 *   AUTH_SPEC §12-4) and are refused here with CompositeRequired
 *   (AUTH_SPEC §6).
 *   A standalone (periodic) `checkpoint` is accepted by this endpoint
 *   (AUTH_SPEC §16-2): authorization is empty audit_head_hash = write ×
 *   member or higher, non-empty = effective permission admin (403 when
 *   short). A match failure against the acceptance-time stored state is
 *   422 `CheckpointStateMismatch`.
 */
export const membershipGroup = HttpApiGroup.make("membership")
  .add(
    HttpApiEndpoint.post("init", "/projects", {
      // strict acceptance (§12-10 (1) — the chain-append surface carrying a genesis)
      payload: strictPayload(Schema.Struct({ orgId: OrgIdSchema, entry: ChainEntrySchema })),
      success: ChainHeadSchema,
      error: [
        ProjectAlreadyInitializedError,
        ChainEntryInvalidError,
        ChainEntryTooLargeError,
        ForbiddenError,
        // The org's active-project cap (AUTH_SPEC §11-3). Fresh
        // geneses only. Judged after the org permission check (403) =
        // principals outside the org are not told whether the cap is
        // reached
        ProjectLimitError,
      ],
    }).middleware(AuthMiddleware),
  )
  .add(
    // Project list (AUTH_SPEC §11-5). Returns only projects where the
    // caller is a chain-derived member. Having no target designator
    // (path, query), a 404-family error structurally cannot exist
    // (trivially compatible with §11-2 existence concealment). Token
    // principals get only the intersection with their scopes (out of
    // scope = does not appear); session principals are allowed via §5's
    // allowlist (SESSION_ALLOWED_ENDPOINTS).
    HttpApiEndpoint.get("list", "/projects", {
      query: { after: Schema.optionalKey(ProjectIdSchema) },
      success: ProjectListSchema,
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("get", "/projects/:projectId/chain", {
      params: { projectId: ProjectIdSchema },
      success: ChainSnapshotSchema,
      error: [ProjectNotFoundError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("append", "/projects/:projectId/chain/entries", {
      params: { projectId: ProjectIdSchema },
      payload: strictPayload(
        Schema.Struct({
          // The CAS parent head. Malformed values are dropped by the schema boundary's 400 (a deliberate acceptance change)
          parentHeadHashHex: Sha256Hex,
          entry: ChainEntrySchema,
        }),
      ),
      success: ChainHeadSchema,
      error: [
        ProjectNotFoundError,
        ChainHeadConflictError,
        ChainEntryInvalidError,
        ChainEntryTooLargeError,
        ChainCapacityExceededError,
        CheckpointStateMismatchError,
        // The stage before acceptance-checking a non-empty
        // audit_head_hash: bounded extension of the audit-head derived
        // column is unfinished (AUDIT_SPEC §5.1). retryable 503 —
        // audit-head-unknown / stale are never judged on a stale column
        // (fail-closed)
        AuditHeadNotReadyError,
        CompositeRequiredError,
        // ProposalLimit is propose's acceptance policy (AUTH_SPEC §12-8 —
        // 32 pending, expires_at_ms capped at 30 days; not a consensus rule)
        ProposalLimitError,
        // DeviceLimit is add_device's acceptance policy
        // (AUTH_SPEC §12-8 — 16 active devices / member / project; not a consensus rule)
        DeviceLimitError,
        ForbiddenError,
        // DO total-storage guard (AUTH_SPEC §12-8): on a DO at or above
        // the refusal threshold, the access-widening add_member /
        // grant_server are refused with 422 `project-storage-bytes`.
        // remove_member / revoke_server / change_role / checkpoint are
        // still accepted under refusal (the same section's explicit
        // enumeration)
        DataLimitExceededError,
      ],
    }).middleware(AuthMiddleware),
  )
  .add(
    // Submission of a head attestation (CRYPTO_SPEC §6.6 / AUTH_SPEC
    // §16-1). Authorization is token scope read × chain role reader or
    // higher (an attestation accompanies a read sync; only one's own
    // signed one-line attestation can be written — §16-1). Acceptance
    // verification (signature, head existence, seq monotonic advance) is
    // §6.4. Regression = 409 (returns the stored seq — never silently
    // succeeds); resubmission of the same seq = idempotent 204.
    HttpApiEndpoint.put("attest", "/projects/:projectId/head-attestation", {
      params: { projectId: ProjectIdSchema },
      // strict acceptance (§12-10 (1) — a mutation carrying a signed structure)
      payload: strictPayload(HeadAttestationSubmissionSchema),
      success: HttpApiSchema.NoContent,
      error: [
        ProjectNotFoundError,
        AttestationRegressionError,
        AttestationRejectedError,
        AttestationRateLimitedError,
      ],
    }).middleware(AuthMiddleware),
  );

/** The maruhi HTTP API. */
export const maruhiApi = HttpApi.make("maruhi")
  .add(membershipGroup)
  .add(authGroup)
  // CLI login (AUTH_SPEC §4) — entirely unauthenticated (the
  // credential = the flow credential; classified in
  // session-capability.ts's UNAUTHENTICATED_ENDPOINTS)
  .add(authCliGroup)
  .add(environmentsGroup)
  .add(variablesGroup)
  .add(deksGroup)
  // schemaPolicy configuration (AUTH_SPEC §12-11 — GET is read ×
  // reader, PUT is admin × admin; session principals are refused on
  // both = outside §5's allowlist)
  .add(schemaPolicyGroup)
  .add(invitesGroup)
  // The reserve-key wrap ledger (AUTH_SPEC §13-6 through §13-10 — KL3); only status is session-allowed
  .add(keyWrapsGroup)
  // The device registry and device-add requests (AUTH_SPEC §13-11 — DK K3; advisory; only reads are session-allowed)
  .add(devicesGroup)
  .add(rotationGroup)
  .add(auditGroup)
  // Project export (AUTH_SPEC §11-6 — PF3; owner × admin scope, never session-allowed)
  .add(exportGroup)
  // Mirrors (AUTH_SPEC §11-7 — PF2; the mark, the promotion and the replication pages; never session-allowed)
  .add(mirrorGroup)
  // The only unauthenticated group (credential = the OIDC token itself — AUTH_SPEC §14-1)
  .add(leaseGroup);

// Load-time sweep (AUTH_SPEC §12-10 (1)): checks at import time that
// the payload of every registered security-critical endpoint refuses
// unknown fields even in an options-less decode. The schema AST's
// parseOptions are no longer read by the parser since rc.113. Success
// and error encodings are not made strict (TaggedError's stack metadata
// turns into HTTP 500 under strict encode).
assertSecurityCriticalPayloadsStrict(maruhiApi);

// Load-time sweep (AUTH_SPEC §5 — W2b): checks at import time that the
// session-capability restriction declaration (session-capability.ts)
// agrees with the registered endpoint set — the allowlist actually
// exists + AuthMiddleware is held, and the unauthenticated surface is
// explicitly classified. The effectiveness of unlisted = refused
// (fail-closed) is guaranteed by server-side matrix tests.
assertSessionCapabilityClassified(maruhiApi);
