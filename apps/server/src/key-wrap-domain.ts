import type { KeyFingerprintHex, UserId } from "@maruhi/core";

export type GuardianMode = "any" | "all";

export interface MasterKeyWrapBlob {
  readonly suite: string;
  readonly nonceHex: string;
  readonly ciphertextHex: string;
}

export interface PasskeyWrapRecord {
  readonly wrapId: string;
  readonly params: string;
  readonly wrap: MasterKeyWrapBlob;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
}

export interface GuardianShareRecord {
  readonly shareIndex: number;
  readonly guardianUserId: UserId;
  readonly guardianEncPubHex: string;
  readonly guardianKeyFingerprintHex: KeyFingerprintHex;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

export interface GuardianGroupRecord {
  readonly groupId: string;
  readonly userId: UserId;
  readonly mode: GuardianMode;
  readonly wrap: MasterKeyWrapBlob;
  readonly createdAtMs: number;
  readonly shares: readonly GuardianShareRecord[];
}

export interface WardShareRecord {
  readonly wardUserId: UserId;
  readonly wardLogin: string | null;
  readonly groupId: string;
  readonly mode: GuardianMode;
  readonly shareIndex: number;
  readonly guardianKeyFingerprintHex: KeyFingerprintHex;
  readonly guardianEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly createdAtMs: number;
}

export interface HandoffRequestRecord {
  readonly requestId: string;
  readonly userId: UserId;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
  readonly collectedAtMs: number | null;
}

export interface HandoffApprovalRecord {
  readonly source: string;
  readonly shareIndex: number;
  readonly approverUserId: UserId;
  readonly approverKeyFingerprintHex: KeyFingerprintHex;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly createdAtMs: number;
}

export type KeyWrapWindowKind = "blob-fetch" | "handoff-request" | "approval" | "device-request";

export type KeyWrapWindowDecision =
  | { readonly allowed: true }
  | { readonly allowed: false; readonly retryAfterSeconds: number };
