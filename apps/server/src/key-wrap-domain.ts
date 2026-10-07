// Domain types of the master-key wrap ledger (AUTH_SPEC §13-6–13-10 —
// KL3).
// The public shapes handed outside db.package (Drizzle types never
// leave — ADR-0006).
// In every type, wraps and segments are opaque ciphertext as seen by
// the server (hex strings); KEK material and plaintext segments never
// appear.

import type { UserId } from "@maruhi/core";

/** The guardian group's threshold mode (CRYPTO_SPEC §8.3). */
export type GuardianMode = "any" | "all";

/** The wrap of B (the master-key blob) (AES-256-GCM; §13-9 MasterKeyWrap). */
export interface MasterKeyWrapBlob {
  readonly suite: string;
  readonly nonceHex: string;
  readonly ciphertextHex: string;
}

/** A class-S (passkey-prf) ledger row. `params` is the JSON string of public parameters. */
export interface PasskeyWrapRecord {
  readonly wrapId: string;
  readonly params: string;
  readonly wrap: MasterKeyWrapBlob;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
}

/** A class-G segment row (an HPKE Seal to the guardian's enc public key). */
export interface GuardianShareRecord {
  readonly shareIndex: number;
  readonly guardianUserId: UserId;
  readonly guardianEncPubHex: string;
  readonly guardianKeyFingerprintHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

/** A class-G group row (segments included). */
export interface GuardianGroupRecord {
  readonly groupId: string;
  readonly userId: UserId;
  readonly mode: GuardianMode;
  readonly wrap: MasterKeyWrapBlob;
  readonly createdAtMs: number;
  readonly shares: readonly GuardianShareRecord[];
}

/** The guardian's own segment as the guardian sees it (with ward info). **One row per device** (2026-09-19 DK). */
export interface WardShareRecord {
  readonly wardUserId: UserId;
  /** A display snapshot of linked_identities.provider_login (not an identifier) */
  readonly wardLogin: string | null;
  readonly groupId: string;
  readonly mode: GuardianMode;
  readonly shareIndex: number;
  /** The sealed-to device key (the guardian's device — identifies the row) */
  readonly guardianKeyFingerprintHex: string;
  readonly guardianEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly createdAtMs: number;
}

/** A class-H handoff request (does not hold E.pub — request_id is a derivative of it). */
export interface HandoffRequestRecord {
  readonly requestId: string;
  readonly userId: UserId;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
  readonly collectedAtMs: number | null;
}

/** A class-H approval (response scope — disappears with the request). */
export interface HandoffApprovalRecord {
  readonly source: string;
  readonly shareIndex: number;
  readonly approverUserId: string;
  readonly approverKeyFingerprintHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly createdAtMs: number;
}

/** The §13-8 fixed-window kinds. */
export type KeyWrapWindowKind = "blob-fetch" | "handoff-request" | "approval" | "device-request";

/** The result of a fixed-window consumption. */
export type KeyWrapWindowDecision =
  | { readonly allowed: true }
  | { readonly allowed: false; readonly retryAfterSeconds: number };
