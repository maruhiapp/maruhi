// 要ローテーションフラグ API の型付きエラー(AUDIT_SPEC §4.1 / §7 — Wave 2 B2)。

import { Schema } from "effect";

/**
 * 404: no currently-effective rotation flag exists for this
 * (environment, variable) pair, so there is nothing to dismiss. Dismissals
 * must target live flags (AUDIT_SPEC §3.3 — a cancellation event without a
 * live target would silently record nothing meaningful).
 */
export class RotationFlagNotFoundError extends Schema.TaggedError<RotationFlagNotFoundError>()(
  "RotationFlagNotFound",
  { environmentId: Schema.String, variableId: Schema.String },
  { httpApiStatus: 404 },
) {}
