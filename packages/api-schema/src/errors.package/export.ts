import { Schema } from "effect";

export class ExportChangedError extends Schema.TaggedError<ExportChangedError>()(
  "ExportChanged",
  { reason: Schema.Literals(["project-changed"]) },
  { httpApiStatus: 409 },
) {}

export class ExportRateLimitedError extends Schema.TaggedError<ExportRateLimitedError>()(
  "ExportRateLimited",
  { retryAfterSeconds: Schema.Number },
  { httpApiStatus: 429 },
) {}
