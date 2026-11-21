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
} from "./errors.package/index.ts";
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

export const InviteRoleSchema = Schema.Literals(["reader", "member", "admin"]);

const MAX_INVITE_SCOPE_ENVIRONMENTS = 256;

const inviteScopeFields = {
  scopeKind: ScopeKindSchema,
  scopeEnvironmentIds: Schema.Array(EnvironmentIdSchema),
};

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

export const InviteStatusSchema = Schema.Literals(["pending", "accepted", "completed", "revoked"]);

export const InviteIdSchema = Schema.String.check(
  Schema.isPattern(/^[0-9A-HJKMNP-TV-Z]{26}$/, { description: "invite id (ULID)" }),
);

export const InviteIssuanceSchema = Schema.Struct({
  linkPubHex: PublicKeyHex,
  headHashHex: Sha256Hex,
  headSeq: PositiveInt,
  issueSignatureHex: InviteIssueSignatureHex,
});

export const InviteAcceptanceSchema = Schema.Struct({
  inviteeUserId: UserIdSchema,
  inviteeEncPubHex: EncPubHex,
  inviteeSigPubHex: PublicKeyHex,
  signatureHex: InviteAcceptSignatureHex,
  linkSignatureHex: InviteLinkSignatureHex,
  acceptedAtMs: Schema.Number,
});

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

export const InvitationListSchema = Schema.Struct({
  invitations: Schema.Array(InvitationSummarySchema),
});

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

export const InviteIssueResultSchema = Schema.Struct({
  expiresAtMs: Schema.Number,
});

export const InviteAcceptResultSchema = Schema.Struct({
  id: Schema.String,
  projectId: ProjectIdSchema,
  role: InviteRoleSchema,
  ...inviteScopeFields,
});

export const invitesGroup = HttpApiGroup.make("invites")
  .add(
    HttpApiEndpoint.post("issue", "/projects/:projectId/invites", {
      params: { projectId: ProjectIdSchema },
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
