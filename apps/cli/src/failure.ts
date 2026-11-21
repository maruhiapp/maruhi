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
  MetaStatementRejectedError,
  MetaVersionConflictError,
  MirrorStateError,
  MirrorSyncRejectedError,
  NameNotNfcError,
  PayloadMismatchError,
  ProjectAlreadyInitializedError,
  ProjectLimitError,
  ProjectNotFoundError,
  ProposalLimitError,
  RotationProposalNotFoundError,
  RotationProposalRejectedError,
  SchemaPolicyRejectedError,
  SetupIncompleteError,
  TokenLimitError,
  UnauthorizedError,
  ValueTooLargeError,
  VariableConflictError,
  VariableNotFoundError,
  VersionConflictError,
} from "@maruhi/api-schema";
import { ChainInvalidError } from "@maruhi/core";
import { Schema, SchemaIssue } from "effect";
import { HttpClientError } from "effect/http";
import { HttpApiError } from "effect/http-api";

import { displayText } from "./display.ts";
import { CliError, cliError } from "./errors.ts";

type Renderer = (error: unknown) => string | null;

const MS_PER_DAY = 24 * 60 * 60 * 1000;

function when<T>(guard: (error: unknown) => error is T, render: (error: T) => string): Renderer {
  return (error) => (guard(error) ? render(error) : null);
}

function isInstanceOf<T>(ctor: new (...args: never[]) => T) {
  return (error: unknown): error is T => error instanceof ctor;
}

function renderSchemaFailure(error: Schema.SchemaError): string {
  const detail = displayText(error.message.replace(/\s+/g, " ").trim());
  return `Some data does not match the schema (${detail}). Check the values you provided, and that the CLI and server versions match`;
}

const isMissingManifestIssue = (issue: SchemaIssue.Issue): boolean => {
  if (issue instanceof SchemaIssue.Pointer) {
    return (
      issue.path.length === 1 &&
      issue.path[0] === "manifest" &&
      issue.issue instanceof SchemaIssue.MissingKey
    );
  }
  if (issue instanceof SchemaIssue.Filter || issue instanceof SchemaIssue.Encoding) {
    return isMissingManifestIssue(issue.issue);
  }
  if (issue instanceof SchemaIssue.Composite || issue instanceof SchemaIssue.AnyOf) {
    return issue.issues.some(isMissingManifestIssue);
  }
  return false;
};

const MANIFEST_SUPPRESSION_MESSAGE =
  "The server did not distribute an environment manifest. A missing manifest is treated as manifest suppression (statement omission cannot be ruled out — CRYPTO_SPEC §6.3) and the response is rejected";

function renderLeaseUnavailable(error: LeaseUnavailableError): string {
  if (error.reason === "oidc-jwks-unavailable") {
    return "The server could not fetch the OIDC issuer's signing keys (oidc-jwks-unavailable). This is a transient issuer or network condition, not a problem with your credentials — retry the job later";
  }
  if (error.reason === "server-key-unconfigured") {
    return "This deployment has no server key configured (server-key-unconfigured), so leases cannot be issued. The server administrator should complete the setup in docs/SELF_HOSTING.md";
  }
  return "The lease is authorized, but the epoch DEKs have not been re-wrapped to the server key yet (server-wraps-missing). An administrator should complete the pending rotation or grant backfill (`maruhi env rotate` / `maruhi server grant`), then retry";
}

function renderSetupIncomplete(error: SetupIncompleteError): string {
  if (error.reason === "rate-limit-unconfigured") {
    return "The server's self-hosting setup is incomplete (rate-limit-unconfigured): its deployment lacks the per-source-IP rate-limit binding this request needs. The server administrator should redeploy with the `bindings.rateLimit` entries of apps/server/cloudflare.config.ts (docs/SELF_HOSTING.md)";
  }
  return "The server's self-hosting setup is incomplete (github-oauth-unconfigured). The server administrator should register a GitHub OAuth App following docs/SELF_HOSTING.md";
}

function renderDataLimit(error: DataLimitExceededError): string {
  if (error.resource === "project-storage-bytes") {
    return `The project's stored data has reached the server's storage guard (${error.limit} bytes — AUTH_SPEC §12-8). Writes that add content are rejected until space is freed; reading values, deleting environments / variables / DEK wraps, removing members and a rotation's key change still work (re-encrypted values cannot be pushed). Delete what you no longer need and retry; if the audit log fills the project, deleting frees little — move the values to a new project before the platform's 10 GB limit stops reads too`;
  }
  if (error.resource === "environment-ciphertext-bytes") {
    return `The environment's current values would exceed the server's per-environment limit (${error.limit} bytes of ciphertext in total — AUTH_SPEC §12-8: a pull returns them all in one response). Delete values this environment no longer needs, or move some to another environment, then retry`;
  }
  return `Exceeds a server acceptance limit (${error.resource} limit ${error.limit})`;
}

export function isNoAnswer(error: unknown): boolean {
  return error instanceof HttpClientError.HttpClientError && error.response === undefined;
}

function isUnreachable(error: HttpClientError.HttpClientError): boolean {
  const status = error.response?.status;
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
    return "The server rejected the request for its size (HTTP 413). The value is too large";
  }
  if (status !== undefined) {
    return `Cannot interpret the server response (HTTP ${status}). Check the server URL, and that the CLI and server versions match`;
  }
  if (
    error.reason instanceof HttpClientError.TransportError &&
    error.reason.description !== undefined
  ) {
    return `The server did not answer (${error.reason.description}; check your network and the server URL)`;
  }
  return "Failed to connect to the server (check your network and the server URL)";
}

const renderers: readonly Renderer[] = [
  when(
    isInstanceOf(HttpApiError.BadRequestProblem),
    () =>
      "Some data does not match the schema (the server could not decode the request). Check the values you provided, and that the CLI and server versions match",
  ),
  when(
    isInstanceOf(HttpApiError.InternalServerErrorProblem),
    () => "The server failed to produce a response. Try again, and check for a server update",
  ),
  when(
    isInstanceOf(UnauthorizedError),
    () =>
      "Authentication failed (the token may be expired or revoked). Log in again with `maruhi login`",
  ),
  when(isInstanceOf(ForbiddenError), (e) =>
    e.reason === "insufficient-scope"
      ? "Insufficient permission (insufficient-scope): the target environment is outside your environment scope on this project's chain. Your local chain view may be stale (the scope may have just been narrowed) — re-run to resync, or ask a project admin to widen your scope (`maruhi member list` shows scopes)"
      : `Insufficient permission (${e.reason})`,
  ),
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
    isInstanceOf(MetaVersionConflictError),
    (e) =>
      `The metaVersion conflicted (current metaVersion=${e.currentMetaVersion}). A concurrent meta operation changed the statement first — re-run to sign over the refreshed state`,
  ),
  when(
    isInstanceOf(MetaStatementRejectedError),
    (e) =>
      `The meta statement was rejected by server-side validation (reason=${e.reason} — CRYPTO_SPEC §4.2 / AUTH_SPEC §12-5)`,
  ),
  when(
    isInstanceOf(NameNotNfcError),
    () =>
      "The server refused the display name as not NFC-normalized (AUTH_SPEC §12-1). This CLI normalizes names before signing — update the maruhi CLI if this persists",
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
  when(
    isInstanceOf(DeviceLimitError),
    (e) =>
      `This project already has the maximum number of active devices for that member (${e.limit}). Revoke a device first (\`maruhi device revoke\`), then re-run`,
  ),
  when(isInstanceOf(ProposalLimitError), (e) =>
    e.reason === "pending-proposals"
      ? `This project already has the maximum number of pending proposals (${e.limit}). Withdraw or complete an existing proposal first (expired proposals do not count)`
      : `The proposal's expiry is too far in the future (server limit: ${Math.round(e.limit / MS_PER_DAY)} days from now)`,
  ),
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
    isInstanceOf(SchemaPolicyRejectedError),
    (e) =>
      `This project's schema policy is locked: creating a variable requires a declared type (${e.reason}). Declare it first with \`maruhi schema set NAME --type <string|number|boolean|url>\`, then push its value`,
  ),
  when(
    isInstanceOf(PayloadMismatchError),
    (e) => `The declared AAD does not match the storage coordinates (${displayText(e.field)})`,
  ),
  when(
    isInstanceOf(ValueTooLargeError),
    (e) => `The value is too large (ciphertext limit ${e.limitBytes} bytes)`,
  ),
  when(isInstanceOf(DataLimitExceededError), renderDataLimit),
  when(
    isInstanceOf(DekWrapRejectedError),
    (e) => `The DEK-wrap registration was rejected (${e.reason})`,
  ),
  when(
    isInstanceOf(DekWrapExistsError),
    (e) =>
      `A DEK wrap already exists (epoch=${e.epoch}, recipient=${displayText(e.recipientUserId)}). Overwriting is forbidden`,
  ),
  when(
    isInstanceOf(DekWrapNotFoundError),
    (e) => `DEK wrap not found (epoch=${e.epoch}, recipient=${displayText(e.recipientUserId)})`,
  ),
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
  when(isInstanceOf(SetupIncompleteError), renderSetupIncomplete),
  when(
    isInstanceOf(TokenLimitError),
    (e) => `The API-token issuance limit is reached (${e.limit} tokens)`,
  ),
  when(
    isInstanceOf(ProjectLimitError),
    (e) =>
      `This organization already holds the maximum number of projects (${e.limit} — AUTH_SPEC §11-3). New projects are rejected until the limit is raised by the server operator; existing projects are unaffected`,
  ),
  when(isInstanceOf(MirrorSyncRejectedError), renderMirrorSyncRejected),
  when(isInstanceOf(MirrorStateError), renderMirrorState),
  when(isInstanceOf(HttpClientError.HttpClientError), renderHttpFailure),
  when(
    (error): error is Schema.SchemaError =>
      Schema.isSchemaError(error) && isMissingManifestIssue(error.issue),
    () => MANIFEST_SUPPRESSION_MESSAGE,
  ),
  when(Schema.isSchemaError, renderSchemaFailure),
];

function renderMirrorSyncRejected(error: MirrorSyncRejectedError): string {
  switch (error.reason) {
    case "chain-not-extension":
      return "The mirror refused the replica: its chain does not extend the chain the mirror holds (chain-not-extension). The mirror holds a newer or a different project — check `maruhi mirror status`; a stale former primary is never replicated over a promoted mirror";
    case "chain-invalid":
      return "The mirror refused the replica: its chain does not verify (chain-invalid). The export is not the server's own content — do not use that file, and run `maruhi project verify` against the server";
    case "audit-regression":
      return "The mirror refused the replica: its audit log is behind the one the mirror last replicated (audit-regression). The export came from an older state than the last sync — re-run against the current server";
    case "audit-not-extension":
      return "The mirror refused the replica: its audit log is not the one the mirror last replicated (audit-not-extension — a row at or below the replicated position is missing or differs). A mirror that itself syncs cannot be a source (its own rows are renumbered at every commit): re-point this mirror at the primary; if the server is the primary, its log was rewritten or restored from another copy — investigate before relying on either side";
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
    MetaStatementRejectedError,
    MetaVersionConflictError,
    MirrorStateError,
    MirrorSyncRejectedError,
    NameNotNfcError,
    PayloadMismatchError,
    ProjectLimitError,
    ProjectNotFoundError,
    RotationProposalNotFoundError,
    RotationProposalRejectedError,
    SchemaPolicyRejectedError,
    UnauthorizedError,
    ValueTooLargeError,
    VariableConflictError,
    VariableNotFoundError,
    VersionConflictError,
  ].some((ctor) => error instanceof ctor);
}

export function internalErrorKind(failure: unknown): string {
  return displayText(failure instanceof Error ? failure.constructor.name : typeof failure);
}

export function toCliError(error: unknown): CliError {
  if (error instanceof CliError) {
    return error;
  }
  if (error instanceof HttpClientError.HttpClientError && isUnreachable(error)) {
    return new CliError({ message: renderHttpFailure(error), unreachable: true });
  }
  for (const render of renderers) {
    const message = render(error);
    if (message !== null) {
      return cliError(message);
    }
  }
  return cliError(`Unexpected error (${internalErrorKind(error)})`);
}
