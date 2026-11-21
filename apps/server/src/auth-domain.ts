import type {
  AuthMethod,
  OrgId,
  OrgRole,
  ProviderUserId,
  SignupDenialReason,
  TokenScope,
  UserId,
} from "@maruhi/core";

export interface VerifiedIdentity {
  readonly provider: "github";
  readonly providerUserId: ProviderUserId;
  readonly providerLogin: string | null;
  readonly verifiedEmail: string | null;
}

export interface ResolvedUser {
  readonly userId: UserId;
  readonly created: boolean;
}

export type { SignupDenialReason } from "@maruhi/core";

export type SignupGateResult = ResolvedUser | { readonly denied: SignupDenialReason };

export interface UserOrg {
  readonly orgId: OrgId;
  readonly slug: string;
  readonly name: string;
  readonly role: OrgRole;
}

export interface SessionRecord {
  readonly userId: UserId;
  readonly authMethod: AuthMethod;
  readonly expiresAtMs: number;
}

export interface ApiTokenRecord {
  readonly id: string;
  readonly userId: UserId;
  readonly tokenHash: string;
  readonly scopes: readonly TokenScope[];
  readonly expiresAtMs: number;
  readonly lastUsedAtMs: number | null;
}

export interface ApiTokenSummary {
  readonly id: string;
  readonly name: string;
  readonly tokenPrefix: string;
  readonly scopes: readonly TokenScope[];
  readonly createdAtMs: number;
  readonly lastUsedAtMs: number | null;
  readonly expiresAtMs: number;
}

export interface RecoveryWrapRecord {
  readonly suite: string;
  readonly nonceHex: string;
  readonly ciphertextHex: string;
  readonly updatedAtMs: number;
}

export type RecoveryFetchDecision =
  | { readonly allowed: true }
  | { readonly allowed: false; readonly retryAfterSeconds: number };
