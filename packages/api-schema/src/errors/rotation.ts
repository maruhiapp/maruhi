// Typed errors of the rotation-required-flag API (AUDIT_SPEC §4.1 / §7)
// and of sealed value proposals (CRYPTO_SPEC §5.3 / AUTH_SPEC §14-5).

import { EnvironmentIdSchema, VariableIdSchema } from "@maruhi/core";
import { Schema } from "effect";

/**
 * 404: no currently-effective rotation flag exists for this
 * (environment, variable) pair, so there is nothing to dismiss. Dismissals
 * must target live flags (AUDIT_SPEC §3.3 — a cancellation event without a
 * live target would silently record nothing meaningful).
 */
export class RotationFlagNotFoundError extends Schema.TaggedError<RotationFlagNotFoundError>()(
  "RotationFlagNotFound",
  { environmentId: EnvironmentIdSchema, variableId: VariableIdSchema },
  { httpApiStatus: 404 },
) {}

/**
 * Why a sealed value proposal is refused (AUTH_SPEC §14-5 — judged after
 * authorization, so a reason leaks nothing an authorized workload or a
 * member would not learn from a successful call):
 *
 * - `duplicate-id` — a proposal with this id is already stored
 * - `duplicate-variable` — the same variable is listed twice
 * - `variable-inactive` — a variable is unknown, declared, or deleted
 *   (a proposal replaces an existing value)
 * - `base-version-stale` — the variable moved since the lease (another
 *   push landed); the job re-leases and re-mints
 * - `recipients-mismatch` — the wraps are not exactly the recipient set
 *   W(E) (CRYPTO_SPEC §5.3): someone missing, someone extra, or a
 *   duplicate device
 * - `pending-limit` — the project already holds 32 pending proposals
 * - `version-missing` — on acceptance, a named version does not exist or
 *   is not newer than the proposal's base version (the member pushes
 *   first, then resolves)
 */
export const RotationProposalRejectReasonSchema = Schema.Literals([
  "duplicate-id",
  "duplicate-variable",
  "variable-inactive",
  "base-version-stale",
  "recipients-mismatch",
  "pending-limit",
  "version-missing",
  // The proposal's sealed values would carry the project past the §12-8 ciphertext cap
  "storage-limit",
  // The pre-flight (AUTH_SPEC §14-5 — O-4): a pending proposal already
  // targets the variable; the job stops before the issuer is touched
  "variable-pending",
  // The project is a read-only mirror (AUTH_SPEC §11-7): the workload's
  // credential is not a member's, so the refusal rides this vocabulary
  // rather than Forbidden; the job mints against the source deployment
  "mirror-read-only",
]);

/** 422: a sealed value proposal (or its resolution) fails an acceptance check (AUTH_SPEC §14-5). */
export class RotationProposalRejectedError extends Schema.TaggedError<RotationProposalRejectedError>()(
  "RotationProposalRejected",
  { reason: RotationProposalRejectReasonSchema },
  { httpApiStatus: 422 },
) {}

/**
 * 404: no pending proposal with this id (unknown, already resolved, or
 * expired — the three fold into one so a resolution cannot probe which).
 */
export class RotationProposalNotFoundError extends Schema.TaggedError<RotationProposalNotFoundError>()(
  "RotationProposalNotFound",
  { proposalId: Schema.String },
  { httpApiStatus: 404 },
) {}
