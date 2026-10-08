// HttpApi definition of the audit-event read API (AUDIT_SPEC §6 / §7 — Phase 2 C1).
//
// - project DO events (§3.3-3.5 + the §3.4 mirror): seq cursor paging
//   (newest first, limit ≤ 200) + filters (event type / actor_user_id /
//   target_user_id / variable_id / environment_id — §7 vocabulary only).
//   Visibility classes (§6) are enforced at the authorization stage; class 2
//   rows and filters behave "as if they do not exist" for below-admin
//   callers (not returning count fields is for the same reason)
// - invite.* (stored in D1 — §3.2): reads scoped to project_id. The
//   permission axis is chain role admin or higher on that project
//   (org admin does not grant read access — §7)
// - user-scoped events (§3.1): the user themselves only (§6). The token
//   requirement is the same level as the key-material class (AUTH_SPEC
//   §13-2) — do not let scope-limited tokens read account-wide history
// - Responses carry rows **as recorded** (including the name snapshots in
//   the payload — §1-3). Every field is a server assertion; the client
//   resolves display names against verified statements (including
//   tombstones). chain.* mirror rows can be verified by the client against
//   the verified chain (the §1-5 / §6 mitigation — payload snapshots also
//   derive from signed entries, so they are verifiable)
// - No append API is exposed (the §7 principle — only server-side processing generates events)

import {
  EnvironmentIdSchema,
  OrgIdSchema,
  ProjectIdSchema,
  UserIdSchema,
  VariableIdSchema,
} from "@maruhi/core";
import { Schema } from "effect";
import { HttpApiEndpoint, HttpApiGroup } from "effect/http-api";

import { AuthMiddleware } from "./auth-middleware.ts";
import {
  AuditHeadNotReadyError,
  DataLimitExceededError,
  ForbiddenError,
  ProjectNotFoundError,
} from "./errors/index.ts";
import { hexPattern, hexString, KeyFingerprintHex, PositiveInt } from "./hex.ts";

/** Max page size (AUDIT_SPEC §7: limit ≤ 200; excess is a Schema 400). */
export const MAX_AUDIT_EVENTS_PAGE_LIMIT = 200;

/** Default page size when limit is omitted (applied server-side). */
export const DEFAULT_AUDIT_EVENTS_PAGE_LIMIT = 50;

/** Byte length of a row identifier (row_id) (§5.1). */
const ROW_ID_BYTES = 16;

/**
 * Format of row identifiers and cursors (16-byte lowercase hex — §5.1
 * row_id). Exported so the CLI's pre-request check shares the same format
 * as the Schema (avoids duplicating the format).
 */
export const AUDIT_ROW_ID_PATTERN = hexPattern(ROW_ID_BYTES);

const RowIdHex = hexString(ROW_ID_BYTES);

/** The recorded actor of an audit event (AUDIT_SPEC §2). */
export const AuditActorSchema = Schema.Struct({
  type: Schema.Literals(["user", "server", "system"]),
  userId: Schema.optionalKey(UserIdSchema),
  keyFingerprintHex: Schema.optionalKey(KeyFingerprintHex),
  apiTokenId: Schema.optionalKey(Schema.String),
});

/**
 * One recorded audit event (AUDIT_SPEC §5.1 columns). Shared by every audit
 * read endpoint (project DO events, invite.* rows, user-scoped rows) so the
 * consumers — `maruhi audit` and the Phase 2 web audit UI — handle a single
 * wire shape; fields a given store never records are simply absent.
 *
 * Identifier fields (environmentId etc.) are plain strings: the write-time
 * Schema already enforced the format, and re-asserting the format on the
 * read side would 500 on encode failure when serving historical rows
 * (rows accepted before an acceptance-policy revision) — breaking faithful
 * audit replay.
 */
export const AuditEventSchema = Schema.Struct({
  /**
   * Wire row identifier = 16 random bytes (AUDIT_SPEC §5.1 row_id). Also
   * used as the paging cursor (before). Independent of the assigned seq
   * and carries no ordinal distance (§7 — non-leakage of counts).
   */
  id: RowIdHex,
  /**
   * Stored sequence number (§5.1 — gapless). **Only present on project DO
   * responses with admin visibility (chain role admin × token scope
   * admin)** — the material for §6's "a gap = a trace of deletion"
   * detection. Always absent on the D1 paths (invites / self) — do not
   * leak deployment-wide autoincrement ordinals (§7).
   */
  seq: Schema.optionalKey(PositiveInt),
  serverTs: Schema.Number,
  clientTs: Schema.optionalKey(Schema.Number),
  event: Schema.String,
  actor: AuditActorSchema,
  targetUserId: Schema.optionalKey(UserIdSchema),
  targetKeyFingerprintHex: Schema.optionalKey(KeyFingerprintHex),
  environmentId: Schema.optionalKey(EnvironmentIdSchema),
  variableId: Schema.optionalKey(VariableIdSchema),
  epoch: Schema.optionalKey(PositiveInt),
  version: Schema.optionalKey(PositiveInt),
  chainSeq: Schema.optionalKey(PositiveInt),
  orgId: Schema.optionalKey(OrgIdSchema),
  projectId: Schema.optionalKey(ProjectIdSchema),
  /** Supplementary JSON as recorded (a server assertion — see the verification discipline in the header comment). */
  payload: Schema.optionalKey(Schema.JsonObject),
});

/** Success response of an audit read (shared by all endpoints). Never returns count fields. */
export const AuditEventsPageSchema = Schema.Struct({
  events: Schema.Array(AuditEventSchema),
});

/**
 * Response of GET /projects/:projectId/audit-head (AUTH_SPEC §16-2).
 * Carries only the cumulative hash (AUDIT_SPEC §5.1); the audit seq and
 * row count are not included (§7 non-leakage of counts). A project with
 * zero audit rows returns the empty string.
 */
export const AuditHeadSchema = Schema.Struct({
  auditHeadHashHex: Schema.String.check(
    Schema.isPattern(/^(?:[0-9a-f]{64})?$/, {
      description: "empty string or 64 lowercase hex digits",
    }),
  ),
});

// The query-string limit. Defined on NumberFromString to satisfy
// QueryConstraint (encode to string)
const PageLimitFromString = Schema.NumberFromString.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(1),
  Schema.isLessThanOrEqualTo(MAX_AUDIT_EVENTS_PAGE_LIMIT),
);

// Acceptance limits for filter values. user_id uses the free-string limit
// of the chain consensus rules (CRYPTO_SPEC §6.1's 1024 bytes); event
// names and variable/environment IDs are comfortably short under the
// §12-1 / §3 vocabulary
const EventNameFilter = Schema.String.check(Schema.isMaxLength(64));
const UserIdFilter = Schema.String.check(Schema.isMaxLength(1024));
const IdFilter = Schema.String.check(Schema.isMaxLength(64));

/**
 * Cursor-paging query (shared by all endpoints). `before` is the `id`
 * (opaque row_id) of the last row of the previous page; rows older than
 * it are returned. An id that is invisible or unknown to the viewer
 * behaves as an "empty page" (no existence oracle — §7).
 */
const pageQuery = {
  before: Schema.optionalKey(RowIdHex),
  limit: Schema.optionalKey(PageLimitFromString),
};

export const auditGroup = HttpApiGroup.make("audit")
  .add(
    HttpApiEndpoint.get("events", "/projects/:projectId/audit/events", {
      params: { projectId: ProjectIdSchema },
      query: {
        ...pageQuery,
        event: Schema.optionalKey(EventNameFilter),
        // Prefix match on the event namespace (AUDIT_SPEC §7).
        // Needed so `maruhi audit verify` can pull **every row** in the
        // `chain.` namespace: fetching known mirror names one by one by
        // exact match would never fetch a forged row claiming a `chain.*`
        // name outside the known set, and verification would end OK. The
        // server implements this with a substr comparison, not LIKE (no
        // wildcard semantics)
        eventPrefix: Schema.optionalKey(EventNameFilter),
        // Return only rows that carry a chain_seq (AUDIT_SPEC §7).
        // On an honest server only chain.* mirrors set chain_seq, but a
        // tampered audit log could claim the same coordinates under a
        // different event name — a presence filter so verify also catches
        // forged provenance claims outside the namespace.
        // No extra boolean conversion on the query string: when present,
        // only the literal "true" is accepted
        chainSeqPresent: Schema.optionalKey(Schema.Literal("true")),
        // Below admin, only self may be specified (specifying another
        // user is 403 — per §6, "cross-searching rows whose actor is
        // someone else is class 2". A static, data-independent rule, so
        // existence information does not leak)
        actorUserId: Schema.optionalKey(UserIdFilter),
        targetUserId: Schema.optionalKey(UserIdFilter),
        variableId: Schema.optionalKey(IdFilter),
        environmentId: Schema.optionalKey(IdFilter),
      },
      success: AuditEventsPageSchema,
      error: [ProjectNotFoundError, ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    // Reading invite.* (the §7 exception provision): stored in D1, but
    // the permission axis is the project's chain role admin or higher ×
    // token scope admin (same as §6 class 2)
    HttpApiEndpoint.get("invites", "/projects/:projectId/audit/invites", {
      params: { projectId: ProjectIdSchema },
      query: pageQuery,
      success: AuditEventsPageSchema,
      error: [ProjectNotFoundError, ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    // Self-reading of user-scoped events (§3.1) (§6). Session principals
    // or `*` × admin-scope tokens only (same level as AUTH_SPEC §13-2 —
    // do not let easily-exposed scope-limited tokens read account-wide
    // history that includes sensitive events)
    HttpApiEndpoint.get("self", "/auth/audit/events", {
      query: pageQuery,
      success: AuditEventsPageSchema,
      error: [ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    // Fetch the audit head (AUTH_SPEC §16-2 — the assertion source for
    // the checkpoint's audit_head_hash notarization). Authorization is
    // effective-permission admin (token scope admin × chain role admin or
    // higher — the §9-2 min): opening it at member level would make
    // polling for cumulative-hash changes a timing side channel that
    // leaks class-2 (AUDIT_SPEC §6) activity windows. The response is
    // only auditHeadHashHex (audit seq and row count are not included —
    // §7 non-leakage of counts). Zero audit rows returns the empty string
    HttpApiEndpoint.get("auditHead", "/projects/:projectId/audit-head", {
      params: { projectId: ProjectIdSchema },
      success: AuditHeadSchema,
      // AuditHeadNotReady (503): lazy materialization's expansion hit the
      // per-call limit (AUDIT_SPEC §5.1 bounded expansion). Retryable —
      // progress is already saved and retries make progress. Returned
      // only after the authorization decision (404 / 403), so it is
      // compatible with §11-2 existence concealment
      // DataLimitExceeded (422 project-storage-bytes — AUTH_SPEC §12-8):
      // returned on a DO above the refusal threshold only when the derived
      // column has not reached MAX(seq) and materialization (writes
      // proportional to the audit row count) is required. When the column
      // is current, a read alone passes
      error: [ProjectNotFoundError, ForbiddenError, AuditHeadNotReadyError, DataLimitExceededError],
    }).middleware(AuthMiddleware),
  );
