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
} from "./errors.package/index.ts";
import { PositiveInt, Sha256Hex } from "./hex.ts";
import { strictPayload } from "./strict.ts";

const MAX_MIRROR_PAGE_LINES = 2_064;

export const MirrorSourceOriginSchema = Schema.String.check(
  Schema.isMaxLength(256),
  Schema.isPattern(/^https?:\/\/[A-Za-z0-9.-]+(?::[0-9]{1,5})?$/, {
    description: "an http(s) origin",
  }),
);

export const MirrorSyncRecordSchema = Schema.Struct({
  atMs: Schema.Number,
  chainHeadSeq: PositiveInt,
  chainHeadHashHex: Sha256Hex,
  auditMaxSeq: Schema.Number,
  attestationMark: Schema.Number,
  mutationSeq: Schema.Number,
  ownAuditRows: Schema.optionalKey(Schema.Number),
});

export const MirrorHeadSchema = Schema.Struct({
  chainHeadSeq: PositiveInt,
  chainHeadHashHex: Sha256Hex,
  auditMaxSeq: Schema.optionalKey(Schema.Number),
  attestationMark: Schema.optionalKey(Schema.Number),
  mutationSeq: Schema.optionalKey(Schema.Number),
});

export type MirrorSyncRecord = typeof MirrorSyncRecordSchema.Type;

export const MirrorStatusSchema = Schema.Struct({
  mirror: Schema.Boolean,
  sourceOrigin: Schema.optionalKey(MirrorSourceOriginSchema),
  markedAtMs: Schema.optionalKey(Schema.Number),
  lastSync: Schema.optionalKey(MirrorSyncRecordSchema),
  nextSequence: Schema.optionalKey(Schema.Number),
  head: MirrorHeadSchema,
});

export type MirrorStatus = typeof MirrorStatusSchema.Type;

export const MirrorMarkSchema = Schema.Struct({ sourceOrigin: MirrorSourceOriginSchema });

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
  sourceMutationSeq: Schema.Number.check(
    Schema.isInt(),
    Schema.isGreaterThanOrEqualTo(0),
    Schema.isLessThanOrEqualTo(Number.MAX_SAFE_INTEGER),
  ),
});

export type MirrorPage = typeof MirrorPageSchema.Type;

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
        DataLimitExceededError,
      ],
    }).middleware(AuthMiddleware),
  );
