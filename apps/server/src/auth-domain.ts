// Server-internal domain types for authentication (AUTH_SPEC §2-§6).
//
// Shared by db.package (repositories) and auth.package (service
// implementations). Drizzle types do not appear here (ADR-0006: confined
// within the service boundary).

import type {
  AuthMethod,
  OrgId,
  OrgRole,
  ProviderUserId,
  SignupDenialReason,
  TokenScope,
  UserId,
} from "@maruhi/core";

/**
 * Provider-verified identity (the output of the AUTH_SPEC §3 / §4
 * authentication dance). email is only one verified on the provider side
 * (§3 — unverified email is not stored).
 */
export interface VerifiedIdentity {
  readonly provider: "github";
  readonly providerUserId: ProviderUserId;
  readonly providerLogin: string | null;
  readonly verifiedEmail: string | null;
}

/** Result of getOrCreateUser (AUTH_SPEC §1-5: the single idempotent entry). */
export interface ResolvedUser {
  readonly userId: UserId;
  readonly created: boolean;
}

/**
 * Reason for signup denial (AUTH_SPEC §3 signup control) — core's
 * SIGNUP_DENIAL_REASONS, the `auth.signup_denied` audit payload's reason
 * (AUDIT_SPEC §3.1).
 */
export type { SignupDenialReason } from "@maruhi/core";

/**
 * Result of get-or-create through the signupPolicy gate (AUTH_SPEC §3).
 * Resolving an existing user always succeeds; a denial is returned only on
 * the "absent → create" branch (blocks only new creation). On denial no
 * users / linked_identities / org / membership rows are created
 * (fail-closed).
 */
export type SignupGateResult = ResolvedUser | { readonly denied: SignupDenialReason };

/** The org an authenticated user belongs to (AUTH_SPEC §9-1). */
export interface UserOrg {
  readonly orgId: OrgId;
  readonly slug: string;
  readonly name: string;
  readonly role: OrgRole;
}

/** Domain representation of a session row (no raw value exists; id is a hash). */
export interface SessionRecord {
  readonly userId: UserId;
  readonly authMethod: AuthMethod;
  readonly expiresAtMs: number;
}

/** Domain representation of an API token row (no raw value exists). */
export interface ApiTokenRecord {
  readonly id: string;
  readonly userId: UserId;
  readonly tokenHash: string;
  readonly scopes: readonly TokenScope[];
  readonly expiresAtMs: number;
  readonly lastUsedAtMs: number | null;
}

/**
 * One row of the token list (AUTH_SPEC §6 — W3a). Kept separate from the
 * verification ApiTokenRecord: this one is the distribution surface and does
 * not even carry the token_hash **structure** (the type closes the path that
 * would copy it into a response by mistake).
 */
export interface ApiTokenSummary {
  readonly id: string;
  readonly name: string;
  readonly tokenPrefix: string;
  readonly scopes: readonly TokenScope[];
  readonly createdAtMs: number;
  readonly lastUsedAtMs: number | null;
  readonly expiresAtMs: number;
}

/**
 * Domain representation of a recovery blob row (AUTH_SPEC §13 — the wrapped
 * master secret key of CRYPTO_SPEC §8). Opaque ciphertext from the server's
 * point of view; the recovery code itself appears in no layer.
 */
export interface RecoveryWrapRecord {
  readonly suite: string;
  readonly nonceHex: string;
  readonly ciphertextHex: string;
  readonly updatedAtMs: number;
}

/** Result of the rate-limit check for blob fetch (AUTH_SPEC §13-3 fixed window). */
export type RecoveryFetchDecision =
  | { readonly allowed: true }
  | { readonly allowed: false; readonly retryAfterSeconds: number };
