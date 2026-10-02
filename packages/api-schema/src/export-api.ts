// HttpApi definition of the project export API (AUTH_SPEC §11-6 — PF3,
// docs/notes/pf3-design.md).
//
// An export is the project's Durable Object content in the evacuation
// format of docs/notes/hosted-ops.md §2-D (gzip NDJSON: header / table /
// row / trailer lines) delivered page by page over the authenticated API:
// each page carries the lines of one slice and an opaque cursor; the
// client concatenates the lines, gzips them, and holds a file the
// destination's restore path accepts unchanged. Nothing is decrypted,
// re-encrypted, or signed: the file is exactly what the server stores
// (ciphertext, the signed chain, wraps, statements, the audit log).
//
// Authorization: chain role owner × token scope admin (the export carries
// every member's wraps and the class-2 audit rows — the strongest read a
// project has). Session principals are not allowed (no screen). Readers,
// members and admins get 403; non-members the uniform 404 (§11-2).
//
// The identities companion lists the current members' provider identities
// so the destination can pre-bind them to the chain's user ids (ruling G).

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
} from "./errors/index.ts";
import { PositiveInt, Sha256Hex } from "./hex.ts";

/** The opaque page cursor (base64url — the server's encoding; the client never interprets it). */
export const ExportCursorSchema = Schema.String.check(
  Schema.isMinLength(1),
  Schema.isMaxLength(4096),
  Schema.isPattern(/^[A-Za-z0-9_-]+$/, { description: "base64url" }),
);

/** The watermarks of the project state an export is taken from (the cursor binds them; the trailer repeats them). */
export const ExportHeadSchema = Schema.Struct({
  chainHeadSeq: PositiveInt,
  chainHeadHashHex: Sha256Hex,
  auditMaxSeq: Schema.Number,
  /** The project DO's mutation counter at the export (a mirror records it with the replica — the sync's no-change check). */
  mutationSeq: Schema.optionalKey(Schema.Number),
});

/**
 * One page of an export: the NDJSON lines of this slice (the first page
 * begins with the header line, the last page ends with the trailer
 * line), the cursor of the next page (absent on the last), and the
 * watermarks.
 */
export const ExportPageSchema = Schema.Struct({
  lines: Schema.Array(Schema.String),
  next: Schema.optionalKey(ExportCursorSchema),
  head: ExportHeadSchema,
});

export type ExportPage = typeof ExportPageSchema.Type;

/** One current member's provider identity, keyed by the chain's user id (AUTH_SPEC §2 — the login lookup key). */
export const ExportIdentitySchema = Schema.Struct({
  userId: BoundedUserId,
  provider: Schema.Literals(["github"]),
  providerUserId: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(256)),
  providerLogin: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(256))),
});

export type ExportIdentity = typeof ExportIdentitySchema.Type;

/**
 * The identities companion of an export: the exporting owner (whose
 * personal org the destination attaches the project to) and the current
 * members' identities. A member whose identity is not linked on this
 * deployment is listed in `unlinked` (the destination cannot pre-bind
 * them; they stay a chain member nobody can log in as until the
 * follow-up of ruling G-2).
 */
export const ExportIdentitiesSchema = Schema.Struct({
  exportedBy: BoundedUserId,
  /** The chain head the members were read at: the companion belongs to the file whose trailer names this head (ruling H revision). */
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
