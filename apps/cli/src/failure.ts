// Maps API / crypto typed errors to user-facing CliErrors.
//
// Discipline: messages consist only of identifiers (IDs, reason codes,
// limit values, HTTP status) and never carry plaintext values, key
// material, or raw token values (CLAUDE.md). Direct `_tag` access is
// banned by oxlint, so discrimination is by instanceof
// (Schema.TaggedError supports instanceof).

import {
  AuditHeadNotReadyError,
  AuthFlowError,
  AuthRateLimitedError,
  ChainCapacityExceededError,
  ChainEntryInvalidError,
  ChainEntryTooLargeError,
  ChainHeadConflictError,
  CheckpointStateMismatchError,
  CompositeRequiredError,
  DataLimitExceededError,
  DekWrapExistsError,
  DekWrapNotFoundError,
  DekWrapRejectedError,
  DeviceLimitError,
  EnvironmentConflictError,
  EnvironmentNotFoundError,
  EpochConflictError,
  ExportChangedError,
  ExportRateLimitedError,
  ForbiddenError,
  LeaseRateLimitedError,
  LeaseUnauthorizedError,
  LeaseUnavailableError,
  ManifestRejectedError,
  ManifestVersionConflictError,
  MirrorStateError,
  MirrorSyncRejectedError,
  PayloadMismatchError,
  ProjectAlreadyInitializedError,
  ProjectLimitError,
  ProjectNotFoundError,
  ProposalLimitError,
  RotationProposalNotFoundError,
  RotationProposalRejectedError,
  SetupIncompleteError,
  TokenLimitError,
  UnauthorizedError,
  ValueTooLargeError,
  VariableConflictError,
  VariableNotFoundError,
  VersionConflictError,
} from "@maruhi/api-schema";
import { ChainInvalidError } from "@maruhi/core";
import { Schema } from "effect";
import { HttpClientError } from "effect/http";

import { displayText } from "./display.ts";
import { CliError, cliError } from "./errors.ts";

type Renderer = (error: unknown) => string | null;

/** The conversion to display ProposalLimit's TTL (milliseconds) in days. */
const MS_PER_DAY = 24 * 60 * 60 * 1000;

function when<T>(guard: (error: unknown) => error is T, render: (error: T) => string): Renderer {
  return (error) => (guard(error) ? render(error) : null);
}

function isInstanceOf<T>(ctor: new (...args: never[]) => T) {
  return (error: unknown): error is T => error instanceof ctor;
}

/**
 * Schema mismatch (`Schema.SchemaError`).
 *
 * A typed client's failure is, per `HttpApiClient`'s declaration, one of
 * three kinds — "the endpoint's declared error | `HttpClientError` |
 * `Schema.SchemaError`" — and the mapping above handles the first two.
 * **This is the remaining kind**.
 *
 * **The direction cannot be told from the type**: upstream sends not only
 * response decodes but also request encodes (`encodePayload` /
 * `encodeParams` / `encodeHeaders` / `encodeQuery`) into **the same error
 * channel**, so `Schema.isSchemaError` catches both. Therefore the
 * wording **does not assert a server-side fault**, and the guidance lists
 * both directions (request side = check the values you provided /
 * response side = version consistency. Listing only "version
 * consistency" would steer to the server, contradicting the first half
 * that avoided asserting it) — in fact an over-long `--token-name` value
 * used to arrive here as an encode failure (today the argument layer
 * drops it before any communication; cli.ts's requireTokenName).
 * Checking request-side values at the argument layer is the plug — not
 * this mapping.
 *
 * Why `message` may pass through (measured — 8 shapes confirmed on
 * rc.109): upstream's formatting shows **only the expected type and
 * location**, **never the mismatching value itself** (`Expected number at
 * ["variables"][0]["version"]`). A response body can carry variable names
 * and ciphertexts, so if this ever became value-containing formatting,
 * diagnostics would become a leak path — that property is pinned by
 * units.test.ts's **negative check** (it fails if upstream changes it).
 *
 * Newlines are folded into one line before neutralizing (`displayText`
 * also replaces newlines with the replacement character — unfolded it
 * would render `Expected number\uFFFD at …`, unreadable).
 */
function renderSchemaFailure(error: Schema.SchemaError): string {
  const detail = displayText(error.message.replace(/\s+/g, " ").trim());
  return `Some data does not match the schema (${detail}). Check the values you provided, and that the CLI and server versions match`;
}

/**
 * Reason-specific guidance for 503 `LeaseUnavailable` (AUTH_SPEC
 * §14-3). All three reasons mean "not a credential problem — the lease
 * cannot be issued right now", and the next step differs — not mixed
 * with 401, the fix target is named per reason (re-run / administrator /
 * deploy config).
 */
function renderLeaseUnavailable(error: LeaseUnavailableError): string {
  if (error.reason === "oidc-jwks-unavailable") {
    return "The server could not fetch the OIDC issuer's signing keys (oidc-jwks-unavailable). This is a transient issuer or network condition, not a problem with your credentials — retry the job later";
  }
  if (error.reason === "server-key-unconfigured") {
    return "This deployment has no server key configured (server-key-unconfigured), so leases cannot be issued. The server administrator should complete the setup in docs/SELF_HOSTING.md";
  }
  return "The lease is authorized, but the epoch DEKs have not been re-wrapped to the server key yet (server-wraps-missing). An administrator should complete the pending rotation or grant backfill (`maruhi env rotate` / `maruhi server grant`), then retry";
}

/**
 * Whether the failure is the server not answering at all — no response
 * (DNS, connection, TLS, a cut-off transfer) or a gateway's own status in
 * front of it (502 / 503 / 504, Cloudflare's 52x) — as opposed to an
 * answer of the server (any typed error, or a 4xx / other 5xx the schema
 * could not interpret). The read-only fallback to a configured mirror
 * (PF2 — AUTH_SPEC §11-7) fires on this and on nothing else.
 */
/**
 * Whether nothing answered at all (a transport failure or the request
 * bound — never an HTTP status, not even a 500): the question of a
 * promotion's probe ("is the source gone?"), narrower than
 * {@link isUnreachable} ("should a read-only fallback be tried?").
 */
export function isNoAnswer(error: unknown): boolean {
  return error instanceof HttpClientError.HttpClientError && error.response === undefined;
}

function isUnreachable(error: HttpClientError.HttpClientError): boolean {
  const status = error.response?.status;
  // A 500 is the server failing to answer the read (a crashed handler), not
  // an answer about the read (a 403, a 404): a read-only fallback is as
  // right for it as for a gateway's 502 (PF2 ruling E revision)
  return (
    status === undefined ||
    status === 500 ||
    status === 502 ||
    status === 503 ||
    status === 504 ||
    (status >= 520 && status <= 530)
  );
}

function renderHttpFailure(error: HttpClientError.HttpClientError): string {
  const status = error.response?.status;
  if (status === 413) {
    // A raw 413 outside the schema (the HTTP raw-body cap — the handed-down branch of session-07 §5)
    return "The server rejected the request for its size (HTTP 413). The value is too large";
  }
  if (status !== undefined) {
    return `Cannot interpret the server response (HTTP ${status}). Check the server URL, and that the CLI and server versions match`;
  }
  // The request bound of api.ts names itself (a server that accepted the
  // connection and never answered is told apart from one nothing reached)
  if (
    error.reason instanceof HttpClientError.TransportError &&
    error.reason.description !== undefined
  ) {
    return `The server did not answer (${error.reason.description}; check your network and the server URL)`;
  }
  return "Failed to connect to the server (check your network and the server URL)";
}

// A CliError is returned as-is at toCliError's entry (so the usage flag is not dropped)
const renderers: readonly Renderer[] = [
  when(
    isInstanceOf(UnauthorizedError),
    // Expiry folds into the same 401 as revocation (AUTH_SPEC §6 — W3a:
    // the distinction is not put on the wire), so the guidance names both
    // possibilities
    () =>
      "Authentication failed (the token may be expired or revoked). Log in again with `maruhi login`",
  ),
  when(isInstanceOf(ForbiddenError), (e) =>
    e.reason === "insufficient-scope"
      ? "Insufficient permission (insufficient-scope): the target environment is outside your environment scope on this project's chain. Your local chain view may be stale (the scope may have just been narrowed) — re-run to resync, or ask a project admin to widen your scope (`maruhi member list` shows scopes)"
      : `Insufficient permission (${e.reason})`,
  ),
  // The error Schema's ID / field columns are unconstrained Schema.String
  // on the wire (the server can fill them freely) — unlike reason / op /
  // resource (Literals), they need neutralizing
  when(
    isInstanceOf(ProjectNotFoundError),
    (e) =>
      `Project not found: ${displayText(e.projectId)} (its existence is hidden from non-members; check the ID and your access)`,
  ),
  when(
    isInstanceOf(EnvironmentNotFoundError),
    (e) => `Environment not found: ${displayText(e.environmentId)}`,
  ),
  when(
    isInstanceOf(VariableNotFoundError),
    (e) => `Variable not found: ${displayText(e.variableId)}`,
  ),
  when(
    isInstanceOf(ProjectAlreadyInitializedError),
    (e) => `The project is already initialized: ${displayText(e.projectId)}`,
  ),
  when(
    isInstanceOf(ChainHeadConflictError),
    (e) => `The chain head conflicted (current head seq=${e.currentHeadSeq}). Re-sync and retry`,
  ),
  // Manifest-related (§12-5). Paths where a command has its own mapping
  // (env rotate / push's 409 re-resolution) never arrive here — this is
  // the catch-all for the rest
  when(
    isInstanceOf(ManifestRejectedError),
    (e) =>
      `The environment manifest was rejected by server-side validation (reason=${e.reason} — AUTH_SPEC §12-5)`,
  ),
  when(
    isInstanceOf(ManifestVersionConflictError),
    (e) =>
      `The manifestVersion conflicted (current manifestVersion=${e.currentManifestVersion}). A concurrent meta operation advanced the environment's manifest — re-run to rebuild it from the refreshed state`,
  ),
  when(
    isInstanceOf(ChainEntryInvalidError),
    (e) =>
      `The chain entry was rejected by server-side validation (seq=${e.seq}, reason=${e.reason})`,
  ),
  when(
    isInstanceOf(ChainEntryTooLargeError),
    (e) => `The chain entry is too large (limit ${e.limitBytes} bytes)`,
  ),
  when(
    isInstanceOf(ChainCapacityExceededError),
    (e) =>
      `The chain capacity limit is reached (max ${e.maxEntries} entries / ${e.maxTotalBytes} bytes)`,
  ),
  when(
    isInstanceOf(CompositeRequiredError),
    (e) =>
      `This operation (${e.op}) is only accepted through the compound endpoint (AUTH_SPEC §12-4)`,
  ),
  // The acceptance policy for device count (AUTH_SPEC §12-3 — not a consensus rule. DK K3)
  when(
    isInstanceOf(DeviceLimitError),
    (e) =>
      `This project already has the maximum number of active devices for that member (${e.limit}). Revoke a device first (\`maruhi device revoke\`), then re-run`,
  ),
  // The acceptance policy for propose (AUTH_SPEC §12-8 — not a consensus rule. K5)
  when(isInstanceOf(ProposalLimitError), (e) =>
    e.reason === "pending-proposals"
      ? `This project already has the maximum number of pending proposals (${e.limit}). Withdraw or complete an existing proposal first (expired proposals do not count)`
      : `The proposal's expiry is too far in the future (server limit: ${Math.round(e.limit / MS_PER_DAY)} days from now)`,
  ),
  // The catch-all for the remaining paths that do not go through the
  // dedicated bounded retries (checkpoint.ts / audit-reconcile.ts).
  // Retryable, so a re-run is suggested
  when(
    isInstanceOf(AuditHeadNotReadyError),
    () =>
      "The server is still materializing the audit-head hash column (this happens once on a project with a large existing audit log). Progress is saved server-side — re-run the command to continue",
  ),
  when(
    isInstanceOf(ChainInvalidError),
    (e) =>
      `Chain verification failed (seq=${e.seq}, reason=${e.reason}). The server may be distributing an invalid chain`,
  ),
  when(
    isInstanceOf(EnvironmentConflictError),
    (e) => `Environment conflict: ${displayText(e.environmentId)} (${e.reason})`,
  ),
  when(
    isInstanceOf(VariableConflictError),
    (e) => `Variable conflict: ${displayText(e.variableId)} (${e.reason})`,
  ),
  when(
    isInstanceOf(VersionConflictError),
    (e) =>
      `Version conflict (current version=${e.currentVersion}). Giving up after the retry limit`,
  ),
  when(
    isInstanceOf(EpochConflictError),
    (e) => `Epoch conflict (current epoch=${e.currentEpoch}). Giving up after the retry limit`,
  ),
  when(
    isInstanceOf(PayloadMismatchError),
    (e) => `The declared AAD does not match the storage coordinates (${displayText(e.field)})`,
  ),
  when(
    isInstanceOf(ValueTooLargeError),
    (e) => `The value is too large (ciphertext limit ${e.limitBytes} bytes)`,
  ),
  // The DO total-storage guard (AUTH_SPEC §12-8) is told apart by
  // resource: unlike the other count caps it is a measured-amount
  // threshold, not "the amount this request adds", so the guidance names
  // the next step (free space by deleting — deletes and reads still pass
  // under the rejection)
  when(isInstanceOf(DataLimitExceededError), (e) =>
    e.resource === "project-storage-bytes"
      ? `The project's stored data has reached the server's storage guard (${e.limit} bytes — AUTH_SPEC §12-8). Writes that add content are rejected until space is freed; reading values, deleting environments / variables / DEK wraps, removing members and rotating still work. Delete what you no longer need, then retry`
      : `Exceeds a server acceptance limit (${e.resource} limit ${e.limit})`,
  ),
  when(
    isInstanceOf(DekWrapRejectedError),
    (e) => `The DEK-wrap registration was rejected (${e.reason})`,
  ),
  // recipientUserId is a free-form string in the server response — neutralize before emitting to the terminal
  when(
    isInstanceOf(DekWrapExistsError),
    (e) =>
      `A DEK wrap already exists (epoch=${e.epoch}, recipient=${displayText(e.recipientUserId)}). Overwriting is forbidden`,
  ),
  when(
    isInstanceOf(DekWrapNotFoundError),
    (e) => `DEK wrap not found (epoch=${e.epoch}, recipient=${displayText(e.recipientUserId)})`,
  ),
  // Lease-related (AUTH_SPEC §14-3). reason is a Literal (the server
  // cannot fill it freely), so it is shown as-is. Token values and
  // external identifiers are not carried
  when(
    isInstanceOf(LeaseUnauthorizedError),
    (e) =>
      `The OIDC token was rejected by the lease endpoint (${e.reason}). Check the token's issuer, audience, and validity window (AUTH_SPEC §14-1)`,
  ),
  when(isInstanceOf(LeaseRateLimitedError), (e) =>
    e.scope === "source-address"
      ? `Too many lease requests from this source address (HTTP 429). Retry after ${e.retryAfterSeconds} seconds — if legitimate CI traffic shares this egress IP, the server operator can raise the per-IP limit (docs/SELF_HOSTING.md)`
      : `The project's lease rate limit is exhausted (HTTP 429). Retry after ${e.retryAfterSeconds} seconds — re-run the job later; retrying immediately only consumes the window`,
  ),
  when(isInstanceOf(LeaseUnavailableError), renderLeaseUnavailable),
  // Sealed value proposals (AUTH_SPEC §14-5). reason is a Literal (shown as-is)
  when(
    isInstanceOf(ExportChangedError),
    () =>
      "The project changed while it was being exported (a push, a chain append, or an attestation landed between two pages) and the export was restarted too many times. Wait for the writes to settle and re-run `maruhi project export`",
  ),
  when(
    isInstanceOf(ExportRateLimitedError),
    (e) =>
      `Too many exports of this project in the last hour (HTTP 429). Retry after ${e.retryAfterSeconds} seconds`,
  ),
  when(
    isInstanceOf(RotationProposalRejectedError),
    (e) => `The server refused the sealed proposal (${e.reason} — AUTH_SPEC §14-5)`,
  ),
  when(
    isInstanceOf(RotationProposalNotFoundError),
    (e) =>
      `No pending sealed proposal has the id ${displayText(e.proposalId)} (it was resolved, expired, or never existed; \`maruhi rotation proposals\` lists the pending ones)`,
  ),
  when(isInstanceOf(AuthFlowError), (e) => `The authentication flow failed (${e.reason})`),
  when(
    isInstanceOf(AuthRateLimitedError),
    (e) =>
      `Too many login attempts from this address (HTTP 429). Retry after ${e.retryAfterSeconds} seconds`,
  ),
  when(
    isInstanceOf(SetupIncompleteError),
    (e) =>
      `The server's self-hosting setup is incomplete (${e.reason}). The server administrator should register a GitHub OAuth App following docs/SELF_HOSTING.md`,
  ),
  when(
    isInstanceOf(TokenLimitError),
    (e) => `The API-token issuance limit is reached (${e.limit} tokens)`,
  ),
  // The project-count / org acceptance cap (AUTH_SPEC §11-3). Only new
  // inits are subject (a repair re-init of an existing project passes
  // regardless of the cap)
  when(
    isInstanceOf(ProjectLimitError),
    (e) =>
      `This organization already holds the maximum number of projects (${e.limit} — AUTH_SPEC §11-3). New projects are rejected until the limit is raised by the server operator; existing projects are unaffected`,
  ),
  // Mirrors (AUTH_SPEC §11-7 — PF2)
  when(isInstanceOf(MirrorSyncRejectedError), renderMirrorSyncRejected),
  when(isInstanceOf(MirrorStateError), renderMirrorState),
  when(isInstanceOf(HttpClientError.HttpClientError), renderHttpFailure),
  // The third kind of typed-client failure (with the two above, the declaration is exhausted)
  when(Schema.isSchemaError, renderSchemaFailure),
];

/** Why a replication page was refused (AUTH_SPEC §11-7 — `maruhi mirror sync`). */
function renderMirrorSyncRejected(error: MirrorSyncRejectedError): string {
  switch (error.reason) {
    case "chain-not-extension":
      return "The mirror refused the replica: its chain does not extend the chain the mirror holds (chain-not-extension). The mirror holds a newer or a different project — check `maruhi mirror status`; a stale former primary is never replicated over a promoted mirror";
    case "chain-invalid":
      return "The mirror refused the replica: its chain does not verify (chain-invalid). The export is not the server's own content — do not use that file, and run `maruhi project verify` against the server";
    case "audit-regression":
      return "The mirror refused the replica: its audit log is behind the one the mirror last replicated (audit-regression). The export came from an older state than the last sync — re-run against the current server";
    case "audit-not-extension":
      return "The mirror refused the replica: its audit log is not the one the mirror last replicated (audit-not-extension — the cumulative hash at the replicated position differs). The server's log was rewritten or restored from another copy; investigate before relying on either side";
    case "sequence-mismatch":
      return "The mirror refused a page as out of sequence (sequence-mismatch) — another sync is running against the same mirror, or a page was lost. Re-run `maruhi mirror sync`";
    case "schema-mismatch":
      return "The mirror refused the replica: its schema version is not the mirror's (schema-mismatch). Upgrade the deployment that is behind, then re-run";
    case "page-too-large":
      return "The mirror refused a page as too large (page-too-large). The CLI and the mirror disagree on the page bounds — check that their versions match";
    default:
      return `The mirror refused the replica (${error.reason}). The export is not a snapshot the mirror can accept — check that the CLI, the server and the mirror versions match`;
  }
}

function renderMirrorState(error: MirrorStateError): string {
  return error.reason === "already-mirror"
    ? "This project is already marked as a mirror (already-mirror). Promote it first with `maruhi mirror promote` to mark it again"
    : "This project is not marked as a mirror on that server (not-mirror). An owner marks it with `maruhi mirror mark --server <mirror url> --source <server url>`";
}

/**
 * Whether the server **rejected with its own error body** (= it is
 * certain the request arrived, was processed, and was refused). Only a
 * server that processed the request can return one of these bodies, so
 * whether it was accepted is settled.
 *
 * Failures not listed here (transport errors, lost responses,
 * uninterpretable 5xx) are **unknown whether accepted** — to default to
 * "unknown", the test is an allow-list (an unknown error never silently
 * falls into the "settled" side).
 */
export function isServerRejection(error: unknown): boolean {
  return [
    AuditHeadNotReadyError,
    ChainCapacityExceededError,
    ChainHeadConflictError,
    ChainEntryInvalidError,
    ChainEntryTooLargeError,
    CheckpointStateMismatchError,
    CompositeRequiredError,
    DataLimitExceededError,
    DekWrapExistsError,
    DekWrapNotFoundError,
    DekWrapRejectedError,
    DeviceLimitError,
    EnvironmentConflictError,
    EnvironmentNotFoundError,
    EpochConflictError,
    ForbiddenError,
    ManifestRejectedError,
    ManifestVersionConflictError,
    MirrorStateError,
    MirrorSyncRejectedError,
    PayloadMismatchError,
    ProjectLimitError,
    ProjectNotFoundError,
    RotationProposalNotFoundError,
    RotationProposalRejectedError,
    UnauthorizedError,
    ValueTooLargeError,
    VariableConflictError,
    VariableNotFoundError,
    VersionConflictError,
  ].some((ctor) => error instanceof ctor);
}

/**
 * Names the *type* of an internal failure (defect) without echoing its message.
 *
 * A defect's `message` can arrive carrying wording that embeds the typed
 * value (`Invalid value: <plaintext>`), so neutralizing control
 * characters alone cannot uphold the discipline (never show typed values
 * in diagnostics). Yet silently swallowing is also banned (CLAUDE.md), so
 * only the type name — **vocabulary derived from code** — is kept as a
 * clue: it cannot be built from argv, and `bun build --compile` does not
 * minify, so it survives in the distributed binary.
 */
export function internalErrorKind(failure: unknown): string {
  return displayText(failure instanceof Error ? failure.constructor.name : typeof failure);
}

/**
 * Collapses any failure into a user-facing {@link CliError}. Failures that no
 * renderer claims are reported by **type name only** — never by their message
 * (see the comment at the fallback).
 */
export function toCliError(error: unknown): CliError {
  // Already a CliError: return it as-is without dropping the usage flag (exit code 2)
  if (error instanceof CliError) {
    return error;
  }
  // The server did not answer (transport, or a gateway in front of it):
  // the one failure a configured mirror may take over (context.ts)
  if (error instanceof HttpClientError.HttpClientError && isUnreachable(error)) {
    return new CliError({ message: renderHttpFailure(error), unreachable: true });
  }
  for (const render of renderers) {
    const message = render(error);
    if (message !== null) {
      return cliError(message);
    }
  }
  // Only **the unknown beyond the exhausted declaration** arrives here
  // (the three kinds of typed-client failure are mapped above). An unknown
  // message is not passed through — wording may arrive containing
  // fragments of a response body or a typed value, so control-char
  // neutralizing alone cannot uphold the discipline. Not swallowed
  // silently either — the type name (code-derived vocabulary) is kept as
  // a clue
  return cliError(`Unexpected error (${internalErrorKind(error)})`);
}
