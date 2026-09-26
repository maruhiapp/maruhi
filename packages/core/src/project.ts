// The domain type of project identifiers.
//
// CRYPTO_SPEC §6.4: project ID = the entry hash of the genesis entry
// (64 lowercase hex chars). Binds the chain and the ID
// cryptographically.

import { Schema } from "effect";

const PROJECT_ID_PATTERN = /^[0-9a-f]{64}$/;

/** Schema for a project id: the lowercase-hex SHA-256 hash of the genesis entry. */
export const ProjectIdSchema = Schema.String.check(
  Schema.isPattern(PROJECT_ID_PATTERN, {
    description: "project id (lowercase hex SHA-256 of the genesis entry)",
  }),
);

/** Project id: lowercase-hex SHA-256 (64 chars) of the project's genesis entry. */
export type ProjectId = typeof ProjectIdSchema.Type;

/** Runtime guard matching {@link ProjectIdSchema}. */
export function isProjectId(value: string): value is ProjectId {
  return PROJECT_ID_PATTERN.test(value);
}

// ---------------------------------------------------------------------------
// Stable identifiers of the data plane (AUTH_SPEC §12-1)
//
// environment_id / variable_id are client-assigned (the values entering
// AAD / HPKE info must be fixed before encryption / wrapping —
// CRYPTO_SPEC §3-§5). The form is an API acceptance policy, not a
// chain-validity consensus rule (CRYPTO_SPEC §6.1).
// ---------------------------------------------------------------------------

const RESOURCE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

/** Schema for a client-issued environment id (AUTH_SPEC §12-1). */
export const EnvironmentIdSchema = Schema.String.check(
  Schema.isPattern(RESOURCE_ID_PATTERN, {
    description: "environment id (1-64 chars of [A-Za-z0-9_-], starting alphanumeric)",
  }),
);

/** Environment id: a stable client-issued identifier (rename-safe, used in AADs). */
export type EnvironmentId = typeof EnvironmentIdSchema.Type;

/** Schema for a client-issued variable id (AUTH_SPEC §12-1). */
export const VariableIdSchema = Schema.String.check(
  Schema.isPattern(RESOURCE_ID_PATTERN, {
    description: "variable id (1-64 chars of [A-Za-z0-9_-], starting alphanumeric)",
  }),
);

/** Variable id: a stable client-issued identifier (rename-safe, used in AADs). */
export type VariableId = typeof VariableIdSchema.Type;

/** Runtime guard matching {@link EnvironmentIdSchema}. */
export function isEnvironmentId(value: string): value is EnvironmentId {
  return RESOURCE_ID_PATTERN.test(value);
}

/** Runtime guard matching {@link VariableIdSchema}. */
export function isVariableId(value: string): value is VariableId {
  return RESOURCE_ID_PATTERN.test(value);
}
