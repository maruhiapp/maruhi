// HttpApi definition of the mirror API (AUTH_SPEC §11-7 — PF2,
// docs/notes/pf2-design.md).
//
// A mirror is a project on a second deployment that holds a verified
// replica of a source project for reads (pulls, workload leases) when the
// source cannot answer. The project is **marked** (the DO holds the mark —
// ruling A), a marked project refuses every write with 403 `Forbidden`
// reason `mirror-read-only` (ruling B), and the replica arrives as the
// export's pages uploaded by a member (ruling D): the same bytes the
// owner can take out with `GET /projects/:id/export`, staged in the DO
// and committed when the page carrying the trailer arrives — only if the
// replica's chain extends the chain the mirror holds. Unmarking promotes
// the mirror to a primary (ruling C).
//
// Authorization: the mark and the promotion are chain role owner × token
// scope admin; the pages are admin or above × admin; the status is
// reader or above × read. Session principals are refused on all of them
// (outside §5's allowlist); non-members get the uniform 404 (§11-2).

import { ProjectIdSchema } from "@maruhi/core";
import { Schema } from "effect";
import { HttpApiEndpoint, HttpApiGroup } from "effect/http-api";

import { AuthMiddleware } from "./auth-middleware.ts";
import {
  DataLimitExceededError,
  ForbiddenError,
  MirrorStateError,
  MirrorSyncRejectedError,
  ProjectNotFoundError,
} from "./errors/index.ts";
import { ExportHeadSchema } from "./export-api.ts";
import { PositiveInt, Sha256Hex } from "./hex.ts";
import { strictPayload } from "./strict.ts";

/**
 * One page carries at most the export's row bound plus one table line per
 * snapshot table and the header / trailer (the export emits at most
 * 2,000 rows a page — AUTH_SPEC §11-6; the server also bounds the bytes).
 */
const MAX_MIRROR_PAGE_LINES = 2_064;

/** The source deployment's origin (scheme + host [+ port]; no path, no trailing slash). */
export const MirrorSourceOriginSchema = Schema.String.check(
  Schema.isMaxLength(256),
  Schema.isPattern(/^https?:\/\/[A-Za-z0-9.-]+(?::[0-9]{1,5})?$/, {
    description: "an http(s) origin",
  }),
);

/** The replica position a committed replication (or the mark's bootstrap) brought. */
export const MirrorSyncRecordSchema = Schema.Struct({
  atMs: Schema.Number,
  chainHeadSeq: PositiveInt,
  chainHeadHashHex: Sha256Hex,
  auditMaxSeq: Schema.Number,
});

export type MirrorSyncRecord = typeof MirrorSyncRecordSchema.Type;

/**
 * The mark and the replication state as every member may read it: whether
 * the project is a mirror, of which source, the last committed
 * replication, the sequence a replication in progress expects next, and
 * the mirror's current head (the same watermarks the export reports).
 */
export const MirrorStatusSchema = Schema.Struct({
  mirror: Schema.Boolean,
  sourceOrigin: Schema.optionalKey(MirrorSourceOriginSchema),
  markedAtMs: Schema.optionalKey(Schema.Number),
  lastSync: Schema.optionalKey(MirrorSyncRecordSchema),
  nextSequence: Schema.optionalKey(Schema.Number),
  head: ExportHeadSchema,
});

export type MirrorStatus = typeof MirrorStatusSchema.Type;

export const MirrorMarkSchema = Schema.Struct({ sourceOrigin: MirrorSourceOriginSchema });

/** One replication page: the export's lines in order and the page's sequence (0 starts a replica over). */
export const MirrorPageSchema = Schema.Struct({
  sequence: Schema.Number.check(
    Schema.isInt(),
    Schema.isGreaterThanOrEqualTo(0),
    Schema.isLessThanOrEqualTo(1_000_000),
  ),
  lines: Schema.Array(Schema.String).check(
    Schema.isMinLength(1),
    Schema.isMaxLength(MAX_MIRROR_PAGE_LINES),
  ),
});

export type MirrorPage = typeof MirrorPageSchema.Type;

/** The page was staged (`nextSequence` follows) or, when it carried the trailer, committed (`nextSequence` is 0 again). */
export const MirrorPageOutcomeSchema = Schema.Struct({
  nextSequence: Schema.Number,
  committed: Schema.optionalKey(MirrorSyncRecordSchema),
});

export type MirrorPageOutcome = typeof MirrorPageOutcomeSchema.Type;

export const mirrorGroup = HttpApiGroup.make("mirror")
  .add(
    HttpApiEndpoint.get("status", "/projects/:projectId/mirror", {
      params: { projectId: ProjectIdSchema },
      success: MirrorStatusSchema,
      error: [ProjectNotFoundError, ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.put("mark", "/projects/:projectId/mirror", {
      params: { projectId: ProjectIdSchema },
      payload: MirrorMarkSchema,
      success: MirrorStatusSchema,
      error: [ProjectNotFoundError, ForbiddenError, MirrorStateError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.delete("unmark", "/projects/:projectId/mirror", {
      params: { projectId: ProjectIdSchema },
      success: MirrorStatusSchema,
      error: [ProjectNotFoundError, ForbiddenError, MirrorStateError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.put("pages", "/projects/:projectId/mirror/pages", {
      params: { projectId: ProjectIdSchema },
      payload: strictPayload(MirrorPageSchema),
      success: MirrorPageOutcomeSchema,
      error: [
        ProjectNotFoundError,
        ForbiddenError,
        MirrorStateError,
        MirrorSyncRejectedError,
        // The staging in progress is growth under the §12-8 storage guard
        DataLimitExceededError,
      ],
    }).middleware(AuthMiddleware),
  );
