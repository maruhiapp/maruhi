import { ProjectIdSchema } from "@maruhi/core";
import { Schema } from "effect";
import { HttpApiEndpoint, HttpApiGroup } from "effect/http-api";

import { AuthMiddleware } from "./auth-middleware.ts";
import { BoundedUserId } from "./data.ts";
import {
  ExportChangedError,
  ExportRateLimitedError,
  ForbiddenError,
  ProjectNotFoundError,
} from "./errors.package/index.ts";
import { PositiveInt, Sha256Hex } from "./hex.ts";

export const ExportCursorSchema = Schema.String.check(
  Schema.isMinLength(1),
  Schema.isMaxLength(4096),
  Schema.isPattern(/^[A-Za-z0-9_-]+$/, { description: "base64url" }),
);

export const ExportHeadSchema = Schema.Struct({
  chainHeadSeq: PositiveInt,
  chainHeadHashHex: Sha256Hex,
  auditMaxSeq: Schema.Number,
  mutationSeq: Schema.Number,
  mirrorOf: Schema.optionalKey(Schema.String),
});

export const ExportPageSchema = Schema.Struct({
  lines: Schema.Array(Schema.String),
  next: Schema.optionalKey(ExportCursorSchema),
  head: ExportHeadSchema,
});

export type ExportPage = typeof ExportPageSchema.Type;

export const ExportIdentitySchema = Schema.Struct({
  userId: BoundedUserId,
  provider: Schema.Literals(["github"]),
  providerUserId: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(256)),
  providerLogin: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(256))),
});

export type ExportIdentity = typeof ExportIdentitySchema.Type;

export const ExportIdentitiesSchema = Schema.Struct({
  exportedBy: BoundedUserId,
  chainHeadSeq: PositiveInt,
  chainHeadHashHex: Sha256Hex,
  identities: Schema.Array(ExportIdentitySchema),
  unlinked: Schema.Array(BoundedUserId),
});

export type ExportIdentities = typeof ExportIdentitiesSchema.Type;

export const exportGroup = HttpApiGroup.make("export")
  .add(
    HttpApiEndpoint.get("page", "/projects/:projectId/export", {
      params: { projectId: ProjectIdSchema },
      query: { cursor: Schema.optionalKey(ExportCursorSchema) },
      success: ExportPageSchema,
      error: [ProjectNotFoundError, ForbiddenError, ExportChangedError, ExportRateLimitedError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("identities", "/projects/:projectId/export/identities", {
      params: { projectId: ProjectIdSchema },
      success: ExportIdentitiesSchema,
      error: [ProjectNotFoundError, ForbiddenError],
    }).middleware(AuthMiddleware),
  );
