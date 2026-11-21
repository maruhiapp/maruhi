import { Schema } from "effect";

import { EncPubHex } from "../hex.ts";

export const DekWrapRejectReasonSchema = Schema.Literals([
  "recipient-not-member",
  "recipient-not-granted",
  "recipient-key-mismatch",
  "recipient-missing",
  "duplicate-recipient",
  "epoch-out-of-range",
  "scope-out-of-range",
  "signature-invalid",
]);

export class DekWrapRejectedError extends Schema.TaggedError<DekWrapRejectedError>()(
  "DekWrapRejected",
  { reason: DekWrapRejectReasonSchema },
  { httpApiStatus: 422 },
) {}

export class DekWrapExistsError extends Schema.TaggedError<DekWrapExistsError>()(
  "DekWrapExists",
  {
    epoch: Schema.Number,
    recipientUserId: Schema.String,
    storedRecipientEncPubHex: EncPubHex,
  },
  { httpApiStatus: 409 },
) {}

export class DekWrapNotFoundError extends Schema.TaggedError<DekWrapNotFoundError>()(
  "DekWrapNotFound",
  { epoch: Schema.Number, recipientUserId: Schema.String },
  { httpApiStatus: 404 },
) {}
