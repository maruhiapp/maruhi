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
//
// Every exported `is*` guard is a non-narrowing predicate. The only
// brand-returning predicates are module-private and feed a `Schema.refine`
// mint: the `narrows*` below, `narrowsKeyFingerprintHex` and `isUserId` in
// identity.ts (which accepts every string, because `UserId` records
// provenance, not a format).
//
// `isProjectId` / `isEnvironmentId` / `isVariableId` (and
// `isKeyFingerprintHex` in identity.ts) do not narrow because every one of
// these formats collides with another domain's: env and var ids share one
// regex, a 64-hex project id has the shape of every SHA-256 hex (chain head
// hashes, proposal ids), and a 32-hex fingerprint matches proposal / audit
// row ids. A `value is` guard would let any file mint one brand from another
// domain's same-shaped string — the very confusion the brands exist to
// prevent. Minting is consolidated in the schemas and `decode*` below
// (`.oxlintrc.json`-restricted); a boolean check mints nothing, so it needs
// no restriction.

import type { EnvironmentId, ProjectId, VariableId } from "@maruhi/crypto";
import { Schema } from "effect";

export type { EnvironmentId, ProjectId, VariableId } from "@maruhi/crypto";

const PROJECT_ID_PATTERN = /^[0-9a-f]{64}$/;

/**
 * Format check matching {@link ProjectIdSchema}. Non-narrowing on purpose
 * (see the header): minting is the schema's and `decodeProjectId`'s job.
 */
export function isProjectId(value: string): boolean {
  return PROJECT_ID_PATTERN.test(value);
}

const narrowsProjectId = (value: string): value is ProjectId => PROJECT_ID_PATTERN.test(value);

/**
 * The schemas' `expected` annotations, exported for the CLI's diagnostic
 * formatter (SAFE_EXPECTATIONS echoes them next to a refused flag — the
 * annotation carries no input, so the echo is safe by construction).
 */
export const PROJECT_ID_EXPECTED = "project id (lowercase hex SHA-256 of the genesis entry)";
export const ENVIRONMENT_ID_EXPECTED =
  "environment id (1-64 chars of [A-Za-z0-9_-], starting alphanumeric)";
export const VARIABLE_ID_EXPECTED =
  "variable id (1-64 chars of [A-Za-z0-9_-], starting alphanumeric)";

/** Schema for a project id: the lowercase-hex SHA-256 hash of the genesis entry. Decoding mints a {@link ProjectId}. */
export const ProjectIdSchema = Schema.String.pipe(
  Schema.refine(narrowsProjectId, {
    expected: PROJECT_ID_EXPECTED,
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

/**
 * Format check matching {@link EnvironmentIdSchema}. Non-narrowing on
 * purpose (see the header): minting is the schema's and `decodeEnvironmentId`'s
 * job.
 */
export function isEnvironmentId(value: string): boolean {
  return RESOURCE_ID_PATTERN.test(value);
}

const narrowsEnvironmentId = (value: string): value is EnvironmentId =>
  RESOURCE_ID_PATTERN.test(value);

/** Schema for a client-issued environment id (AUTH_SPEC §12-1). Decoding mints an {@link EnvironmentId}. */
export const EnvironmentIdSchema = Schema.String.pipe(
  Schema.refine(narrowsEnvironmentId, {
    expected: ENVIRONMENT_ID_EXPECTED,
  }),
);

/**
 * The same mint as {@link EnvironmentIdSchema} with a caller-supplied
 * failure message (config leaves that must not echo the typed value).
 */
export const environmentIdSchemaWithMessage = (message: string) =>
  Schema.String.annotate({ message }).pipe(Schema.refine(narrowsEnvironmentId, { message }));

/**
 * Mints an {@link EnvironmentId} where no Schema field does the decoding —
 * only at a trust boundary: a validated command argument or a branded column
 * read. Throws on a malformed value.
 */
export const decodeEnvironmentId: (value: string) => EnvironmentId =
  Schema.decodeSync(EnvironmentIdSchema);

/**
 * Format check matching {@link VariableIdSchema}. Non-narrowing on purpose
 * (see the header): minting is the schema's and `decodeVariableId`'s job.
 */
export function isVariableId(value: string): boolean {
  return RESOURCE_ID_PATTERN.test(value);
}

const narrowsVariableId = (value: string): value is VariableId => RESOURCE_ID_PATTERN.test(value);

/** Schema for a client-issued variable id (AUTH_SPEC §12-1). Decoding mints a {@link VariableId}. */
export const VariableIdSchema = Schema.String.pipe(
  Schema.refine(narrowsVariableId, {
    expected: VARIABLE_ID_EXPECTED,
  }),
);

/**
 * Mints a {@link VariableId} where no Schema field does the decoding — only
 * at a trust boundary: a validated command argument or a branded column
 * read. Throws on a malformed value.
 */
export const decodeVariableId: (value: string) => VariableId = Schema.decodeSync(VariableIdSchema);
