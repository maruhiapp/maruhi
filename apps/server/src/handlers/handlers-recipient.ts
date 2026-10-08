// The recipient position of a wrap, decoded at the wire boundary
// (AUTH_SPEC §12-6 / CRYPTO_SPEC §9): a member's user id for class member,
// the server key fingerprint for class server. Shared by the wrap-deletion
// endpoints (deks, environments).

import {
  decodeKeyFingerprintHex,
  decodeUserId,
  type KeyFingerprintHex,
  type UserId,
} from "@maruhi/core";

/**
 * A `server`-class ref whose recipient is not fingerprint-shaped can never
 * name a stored server wrap — brand it as a user-id value so the lookup
 * misses (404) instead of throwing on the mint.
 */
const mintServerRecipient = (value: string): UserId | KeyFingerprintHex => {
  try {
    return decodeKeyFingerprintHex(value);
  } catch {
    return decodeUserId(value);
  }
};

/** The wrap's recipient as a branded id (a wire-boundary mint). */
export const recipientOf = (d: {
  readonly recipientClass: "member" | "server";
  readonly recipientUserId: string;
}): UserId | KeyFingerprintHex =>
  d.recipientClass === "server"
    ? mintServerRecipient(d.recipientUserId)
    : decodeUserId(d.recipientUserId);
