// Typed errors of the project export API (AUTH_SPEC §11-6 — PF3).

import { Schema } from "effect";

/**
 * 409: the project changed between two pages of one export (a chain
 * append, a data write, or a head attestation moved the watermarks the
 * cursor carries — docs/notes/pf3-design.md ruling C). The export is not
 * resumable: the client starts over from the first page.
 */
export class ExportChangedError extends Schema.TaggedError<ExportChangedError>()(
  "ExportChanged",
  { reason: Schema.Literals(["project-changed"]) },
  { httpApiStatus: 409 },
) {}

/**
 * 429: the project's export window is exhausted (first pages per hour —
 * AUTH_SPEC §11-6). Judged after authorization, like the lease windows.
 */
export class ExportRateLimitedError extends Schema.TaggedError<ExportRateLimitedError>()(
  "ExportRateLimited",
  { retryAfterSeconds: Schema.Number },
  { httpApiStatus: 429 },
) {}
