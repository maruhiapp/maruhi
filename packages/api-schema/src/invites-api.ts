// HttpApi definition of the invite API (AUTH_SPEC §15 — 2026-09-13 IV revision).
//
// - Issue / list / revoke live under the project (authorization = token
//   scope admin × chain role admin or higher; always 404 to non-members
//   — §11-2)
// - Issue: the client assigns the invite id and passes the **issuance
//   signature** (CRYPTO_SPEC §6.5) over the link public key, the
//   verified head, and the role as the issuance statement. The server
//   runs format checks and UNIQUE violations (409) only — it does not
//   verify the issuance signature (its verifiers are the inviter and
//   the acceptor). The response carries only the expiry; **the server
//   never returns an invitation secret** (the old token is retired)
// - Accept lives off the project path (§15-2): holding the link key
//   (= being able to make the link signature) is the capability on the
//   target invite, and only the public key reaches the server from the
//   link's fragment. An unknown link_pub is 404 (InviteNotFound —
//   carries no project coordinates), unusable is 410 (InviteGone),
//   signature is 422
// - Every endpoint requires authentication (AuthMiddleware supplies the
//   401 / CSRF 403. The list GET writes no audit = holds no state, so it
//   is outside §11-4's added-CSRF scope)

import {
  type EnvironmentId,
  EnvironmentIdSchema,
  ProjectIdSchema,
  UserIdSchema,
} from "@maruhi/core";
import { Schema } from "effect";
import { HttpApiEndpoint, HttpApiGroup, HttpApiSchema } from "effect/http-api";

import { AuthMiddleware } from "./auth-middleware.ts";
import { ScopeKindSchema } from "./chain.ts";
import {
  ForbiddenError,
  InviteConflictError,
  InviteGoneError,
  InviteNotFoundError,
  InvitePendingLimitError,
  InviteRateLimitedError,
  InviteSignatureInvalidError,
  ProjectNotFoundError,
} from "./errors/index.ts";
import {
  EncPubHex,
  InviteAcceptSignatureHex,
  InviteIssueSignatureHex,
  InviteLinkSignatureHex,
  PositiveInt,
  PublicKeyHex,
  Sha256Hex,
} from "./hex.ts";
import { strictPayload } from "./strict.ts";

/** Roles grantable via an invite (owner is never granted via the invite path — AUTH_SPEC §15-1). */
export const InviteRoleSchema = Schema.Literals(["reader", "member", "admin"]);

/** Cap on the scope environment list (CRYPTO_SPEC §6.1 / §6.2 — same 256 as grant_server's scope). */
const MAX_INVITE_SCOPE_ENVIRONMENTS = 256;

/**
 * An invite's to-be-granted scope (AUTH_SPEC §15-2 — 2026-09-14 ES).
 * Format checks only: a closed kind set, an empty array under `all`,
 * at most 256 elements, no duplicates, each id in §12-1 form.
 * **No existence check** (verifyChain checks it as a consensus rule
 * when the add_member is accepted). The issue body, list rows, and
 * accept response carry the same two fields.
 */
const inviteScopeFields = {
  scopeKind: ScopeKindSchema,
  scopeEnvironmentIds: Schema.Array(EnvironmentIdSchema),
};

/** Applies the scope structural rules (same as §6.2 — all ⇒ empty, cap, no duplicates) to the whole Struct. */
function withInviteScopeShape<
  S extends Schema.Struct<typeof inviteScopeFields & Schema.Struct.Fields>,
>(schema: S): S {
  return schema.check(
    Schema.makeFilter((o: { scopeKind: string; scopeEnvironmentIds: readonly EnvironmentId[] }) => {
      if (o.scopeKind === "all" && o.scopeEnvironmentIds.length > 0) {
        return { path: ["scopeEnvironmentIds"], issue: "must be empty when scopeKind is all" };
      }
      if (o.scopeEnvironmentIds.length > MAX_INVITE_SCOPE_ENVIRONMENTS) {
        return { path: ["scopeEnvironmentIds"], issue: "at most 256 environments" };
      }
      if (new Set(o.scopeEnvironmentIds).size !== o.scopeEnvironmentIds.length) {
        return { path: ["scopeEnvironmentIds"], issue: "duplicate environment id" };
      }
      return undefined;
    }),
  ) as S;
}

/** The stored invite status (expired is derived from expiresAtMs — §15-1). */
export const InviteStatusSchema = Schema.Literals(["pending", "accepted", "completed", "revoked"]);

/** Invite id (a client-assigned ULID — Crockford Base32, 26 chars; covered by the issuance signature). */
export const InviteIdSchema = Schema.String.check(
  Schema.isPattern(/^[0-9A-HJKMNP-TV-Z]{26}$/, { description: "invite id (ULID)" }),
);

/**
 * The issuance statement (CRYPTO_SPEC §6.5): the link public key, the
 * inviter's verified head at issuance time, and the issuance signature.
 * The server only stores and distributes it — it does not verify. The
 * inviter client re-verifies it under its own sig public key before
 * `add_member` (does not rely on the issuance pin).
 */
export const InviteIssuanceSchema = Schema.Struct({
  linkPubHex: PublicKeyHex,
  headHashHex: Sha256Hex,
  headSeq: PositiveInt,
  issueSignatureHex: InviteIssueSignatureHex,
});

/** The acceptance block (status accepted or later — §15-1). */
export const InviteAcceptanceSchema = Schema.Struct({
  inviteeUserId: UserIdSchema,
  inviteeEncPubHex: EncPubHex,
  inviteeSigPubHex: PublicKeyHex,
  /** The CRYPTO_SPEC §6.5 acceptance signature (the acceptor's chain sig key). The inviter client verifies it independently */
  signatureHex: InviteAcceptSignatureHex,
  /** The CRYPTO_SPEC §6.5 link signature (the link key). A co-signature over the same byte string */
  linkSignatureHex: InviteLinkSignatureHex,
  acceptedAtMs: Schema.Number,
});

/**
 * One row of the list. The issuance statement and the acceptance block
 * are needed for the inviter client's re-verification (CRYPTO_SPEC §6.5
 * — the material to reconstruct signed_bytes) and for the FP word
 * display.
 */
export const InvitationSummarySchema = Schema.Struct({
  id: Schema.String,
  projectId: ProjectIdSchema,
  role: InviteRoleSchema,
  ...inviteScopeFields,
  status: InviteStatusSchema,
  inviterUserId: UserIdSchema,
  issuance: InviteIssuanceSchema,
  createdAtMs: Schema.Number,
  expiresAtMs: Schema.Number,
  acceptance: Schema.NullOr(InviteAcceptanceSchema),
});

/** GET /projects/:projectId/invites: the project's invitations (AUTH_SPEC §15-2). */
export const InvitationListSchema = Schema.Struct({
  invitations: Schema.Array(InvitationSummarySchema),
});

/** The issue request (§15-2): a client-assigned id + the issuance statement (includes role and scope). */
export const InviteIssuePayloadSchema = withInviteScopeShape(
  Schema.Struct({
    id: InviteIdSchema,
    role: InviteRoleSchema,
    ...inviteScopeFields,
    linkPubHex: PublicKeyHex,
    headHashHex: Sha256Hex,
    headSeq: PositiveInt,
    issueSignatureHex: InviteIssueSignatureHex,
  }),
);

/** The issue response. Expiry only (there is no token-equivalent secret — §15-1). */
export const InviteIssueResultSchema = Schema.Struct({
  expiresAtMs: Schema.Number,
});

/**
 * The accept response. Minimal form (§15-1: it must not create a
 * surface where server-declared display information is trusted — the
 * inviter info and the anchor ride in the link's fragment).
 */
export const InviteAcceptResultSchema = Schema.Struct({
  id: Schema.String,
  projectId: ProjectIdSchema,
  role: InviteRoleSchema,
  ...inviteScopeFields,
});

/**
 * Invitation endpoints (AUTH_SPEC §15-2).
 *
 * - `issue`: create one invitation from a client-generated id and issuance
 *   statement; nothing secret is returned. Only an owner may issue an
 *   invite with role = admin (same level as the CRYPTO_SPEC §6.2
 *   add_member permission table).
 * - `accept`: single-use CAS (pending → accepted). The server
 *   reconstructs signed_bytes from the stored row + the calling
 *   principal and verifies the link signature and the acceptance
 *   signature (CRYPTO_SPEC §6.5). Keys get a format check only (the
 *   source of truth for member-key uniqueness is add_member's chain
 *   consensus rule).
 * - `list` / `revoke`: the management surface. revoke works on pending |
 *   accepted (410 for completed / revoked).
 */
export const invitesGroup = HttpApiGroup.make("invites")
  .add(
    HttpApiEndpoint.post("issue", "/projects/:projectId/invites", {
      params: { projectId: ProjectIdSchema },
      // strict acceptance (§12-10 (1) — invite creation / acceptance is §15-2's key-declaration class)
      payload: strictPayload(InviteIssuePayloadSchema),
      success: InviteIssueResultSchema,
      error: [
        ProjectNotFoundError,
        ForbiddenError,
        InviteConflictError,
        InvitePendingLimitError,
        InviteRateLimitedError,
      ],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("accept", "/invites/accept", {
      payload: strictPayload(
        Schema.Struct({
          linkPubHex: PublicKeyHex,
          encPubHex: EncPubHex,
          sigPubHex: PublicKeyHex,
          acceptSignatureHex: InviteAcceptSignatureHex,
          linkSignatureHex: InviteLinkSignatureHex,
        }),
      ),
      success: InviteAcceptResultSchema,
      error: [InviteNotFoundError, InviteGoneError, InviteSignatureInvalidError, ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("list", "/projects/:projectId/invites", {
      params: { projectId: ProjectIdSchema },
      success: InvitationListSchema,
      error: [ProjectNotFoundError, ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.delete("revoke", "/projects/:projectId/invites/:id", {
      params: { projectId: ProjectIdSchema, id: Schema.String },
      success: HttpApiSchema.NoContent,
      error: [ProjectNotFoundError, ForbiddenError, InviteNotFoundError, InviteGoneError],
    }).middleware(AuthMiddleware),
  );
