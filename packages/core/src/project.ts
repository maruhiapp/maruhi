// The domain types of project identifiers.
//
// CRYPTO_SPEC §6.4: project ID = the entry hash of the genesis entry
// (64 lowercase hex chars). Binds the chain and the ID
// cryptographically.
//
// The three ids are branded (crypto's nominal brands — the same pattern as
// `UserId` / `KeyFingerprintHex` in identity.ts): each carries an invariant
// a plain string cannot. `EnvironmentId` and `VariableId` share one wire
// format, so the brand is what keeps one out of the other's positions in
// AADs, HPKE info and chain payloads; `ProjectId` keeps a chain head hash,
// an org id or any other 64-hex string out of project-id positions.
//
// The brands are minted only at trust boundaries: decoding at the wire
// (these schemas, also behind CLI arguments; `decode*` for hand-written
// parsers and generated ids), DB row mapping inside the server's repository
// service (the Drizzle column types) and the data store's branded column
// reads. `.oxlintrc.json` enforces this: the schemas and `decode*` mints
// below may be imported only by the listed mint sites.

import type { EnvironmentId, ProjectId, VariableId } from "@maruhi/crypto";
import { Schema } from "effect";

export type { EnvironmentId, ProjectId, VariableId } from "@maruhi/crypto";

const PROJECT_ID_PATTERN = /^[0-9a-f]{64}$/;

/** Runtime guard matching {@link ProjectIdSchema}; narrowing mints the brand. */
export function isProjectId(value: string): value is ProjectId {
  return PROJECT_ID_PATTERN.test(value);
}

/** Schema for a project id: the lowercase-hex SHA-256 hash of the genesis entry. Decoding mints a {@link ProjectId}. */
export const ProjectIdSchema = Schema.String.pipe(
  Schema.refine(isProjectId, {
    expected: "project id (lowercase hex SHA-256 of the genesis entry)",
  }),
);

/**
 * Mints a {@link ProjectId} where no Schema field does the decoding — only at
 * a trust boundary: project creation (the genesis hash), a hand-written
 * parser of a wire or stored record, or a branded column read. Throws on a
 * malformed value.
 */
export const decodeProjectId: (value: string) => ProjectId = Schema.decodeSync(ProjectIdSchema);

// ---------------------------------------------------------------------------
// Stable identifiers of the data plane (AUTH_SPEC §12-1)
//
// environment_id / variable_id are client-assigned (the values entering
// AAD / HPKE info must be fixed before encryption / wrapping —
// CRYPTO_SPEC §3-§5). The form is an API acceptance policy, not a
// chain-validity consensus rule (CRYPTO_SPEC §6.1).
// ---------------------------------------------------------------------------

const RESOURCE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

/** Runtime guard matching {@link EnvironmentIdSchema}; narrowing mints the brand. */
export function isEnvironmentId(value: string): value is EnvironmentId {
  return RESOURCE_ID_PATTERN.test(value);
}

/** Schema for a client-issued environment id (AUTH_SPEC §12-1). Decoding mints an {@link EnvironmentId}. */
export const EnvironmentIdSchema = Schema.String.pipe(
  Schema.refine(isEnvironmentId, {
    expected: "environment id (1-64 chars of [A-Za-z0-9_-], starting alphanumeric)",
  }),
);

/**
 * Mints an {@link EnvironmentId} where no Schema field does the decoding —
 * only at a trust boundary: a validated command argument or a branded column
 * read. Throws on a malformed value.
 */
export const decodeEnvironmentId: (value: string) => EnvironmentId =
  Schema.decodeSync(EnvironmentIdSchema);

/** Runtime guard matching {@link VariableIdSchema}; narrowing mints the brand. */
export function isVariableId(value: string): value is VariableId {
  return RESOURCE_ID_PATTERN.test(value);
}

/** Schema for a client-issued variable id (AUTH_SPEC §12-1). Decoding mints a {@link VariableId}. */
export const VariableIdSchema = Schema.String.pipe(
  Schema.refine(isVariableId, {
    expected: "variable id (1-64 chars of [A-Za-z0-9_-], starting alphanumeric)",
  }),
);

/**
 * Mints a {@link VariableId} where no Schema field does the decoding — only
 * at a trust boundary: a validated command argument or a branded column
 * read. Throws on a malformed value.
 */
export const decodeVariableId: (value: string) => VariableId = Schema.decodeSync(VariableIdSchema);
