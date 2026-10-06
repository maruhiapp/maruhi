// Issuing periodic checkpoints (the issuance SHOULD of CRYPTO_SPEC §6.3 /
// AUTH_SPEC §16-2).
//
// - Refresh the view right before issuing → build the manifest reference
//   and values_digest from the verified view (a verified pull) (never sign
//   server-declared values as-is — §16-2). Coverage is every environment in
//   the verified view (SHOULD; environments with a verified deletion
//   statement are not included) — trigger (i) [after rotate + re-encryption
//   completes] is a single tuple for that environment (the ruling is
//   docs/notes/session-35.md)
// - Only effective-admin authority (min(token scope, chain role) — §9-2)
//   notarizes the audit head. The scope comes from /auth/me's tokenScopes
//   and the role is **decided up front** from the verified view (no fallback
//   after hitting a 403 — §16-2). The attestation is fetched after the CAS
//   parent (the chain head) is settled (§6.3 — makes audit-head-stale
//   practically unreachable for an honest client)
// - Retries on 422 (CheckpointStateMismatch) are bounded: refetch the view,
//   re-verify, re-sign (including refetching the attestation when
//   notarizing). When the budget is spent, issuance is attempted exactly
//   once with the subset of environments whose acceptance-time match held
//   (the tuples unchanged across the last two builds — a partial baseline is
//   stronger than none — §6.3)
// - Post-acceptance reconciliation (§12-10 (3)): success is reported only
//   after a chain sync confirms own entry landed (a 2xx is only a
//   transport-layer fact). No intent (3-F) is accumulated — a checkpoint
//   does not advance local state, so there is no path by which an
//   unconfirmed landing could taint later decisions (the ruling is
//   docs/notes/session-35.md)

import {
  AuditHeadNotReadyError,
  ChainHeadConflictError,
  CheckpointStateMismatchError,
} from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import { cryptoEffect, cryptoPromise, scopePermissionFor } from "@maruhi/core";
import type {
  ChainEntry,
  CheckpointEnvironmentEntry,
  EnvValuesDigestEntry,
  SigningKeyPair,
} from "@maruhi/crypto";
import {
  computeChainEntryHash,
  computeEnvValuesDigest,
  scopeIncludesEnvironment,
  SUITE_ID,
} from "@maruhi/crypto";
import { Effect, Schedule } from "effect";

import type { MaruhiClient } from "./api.ts";
import { signEntryAtHead } from "./chain-append.ts";
import type { VerifiedProject } from "./chain-sync.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { isServerRejection, toCliError } from "./failure.ts";
import type { FloorHandle } from "./floor-check.ts";
import { CliIo, type CliIoShape } from "./io.ts";
import { verifiedDeletedEnvironmentSet } from "./rotation-sweep.ts";
import { requireEnvironmentInScope } from "./scope.ts";
import { pullVerifiedEnvironment } from "./values.ts";

/** The cap on 422 retries (when spent, a subset issuance is attempted exactly once). */
const MAX_STATE_MISMATCH_ATTEMPTS = 3;
/** The cap on re-signing retries for a CAS conflict (409) (same level as the existing chain-CAS convention). */
const MAX_HEAD_CONFLICT_ATTEMPTS = 5;
/**
 * The retry cap for AuditHeadNotReady (503 — the bounded extension of the
 * audit-head derived column is incomplete; AUDIT_SPEC §5.1 / AUTH_SPEC
 * §16-2). A single failure response still advances the server side by its
 * full cap (10k rows), so budget x server cap = 100k rows of extension per
 * run is guaranteed. Exhaustion is an error, but progress is saved so a
 * re-run continues from where it left off (guided by the message —
 * session-38 ruling AG).
 */
const MAX_AUDIT_HEAD_NOT_READY_ATTEMPTS = 10;

/**
 * The backoff between AuditHeadNotReady retries (§16-2). The bounded
 * extension on the server side advances on every call, so a retry is
 * productive — the exponential wait only keeps the loop from pounding the
 * endpoint and stays within a few seconds across the whole budget.
 */
const AUDIT_HEAD_NOT_READY_BASE_DELAY = "5 millis";

/** The guidance shown on AuditHeadNotReady exhaustion (shared by the fetch and send paths). */
const AUDIT_HEAD_NOT_READY_EXHAUSTED = `The server is still materializing the audit-head hash column after ${MAX_AUDIT_HEAD_NOT_READY_ATTEMPTS} attempts (this happens once, on the first audit-head access of a project with a very large existing audit log). Progress is saved server-side and every attempt advances it — re-run the command to continue where it left off`;

/** The baseline age for issuance trigger (iii) (7 days — the drafted value of CRYPTO_SPEC §6.3). */
const CHECKPOINT_PROPOSAL_AGE_MS = 7 * 24 * 60 * 60 * 1000;

/** The issuance result (the material for display and the exit code). */
interface CheckpointSummary {
  /** The notarized environment IDs (ascending byte order = payload order). */
  readonly environmentIds: readonly string[];
  /** The environments left out of the all-environments coverage (SHOULD), with the reason (non-empty only for a subset issuance). */
  readonly skippedEnvironmentIds: readonly string[];
  /** Whether the audit head was notarized (effective admin only — §16-2). */
  readonly attestedAuditHead: boolean;
  readonly headSeq: number;
  readonly warnings: readonly string[];
}

interface CheckpointInput {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /**
   * The coverage target. "all" = every environment in the verified view
   * (except environments with a verified deletion statement — §6.3). An
   * explicit list is for trigger (i) (the environment whose rotate just
   * completed).
   */
  readonly environmentIds: "all" | readonly EnvironmentId[];
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  /** The per-environment floor handle (for the verified pull's checks and commit). */
  readonly floorFor: (environmentId: EnvironmentId) => Effect.Effect<FloorHandle, CliError>;
}

/** Ascending UTF-8 byte order comparison (the payload generation order SHOULD — CRYPTO_SPEC §6.2). */
function compareUtf8Bytes(a: string, b: string): number {
  const encoder = new TextEncoder();
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  const length = Math.min(left.length, right.length);
  for (let i = 0; i < length; i += 1) {
    const diff = (left[i] ?? 0) - (right[i] ?? 0);
    if (diff !== 0) {
      return diff;
    }
  }
  return left.length - right.length;
}

/** One environment's built tuple (a comparable shape — the material for the subset-fallback decision). */
interface BuiltTuple {
  readonly environmentId: string;
  readonly epoch: number;
  readonly manifestVersion: number;
  readonly manifestSigHashHex: string;
  readonly valuesDigestHex: string;
}

interface BuiltView {
  readonly view: VerifiedProject;
  readonly tuples: readonly BuiltTuple[];
  readonly warnings: readonly string[];
}

function sameTuple(a: BuiltTuple, b: BuiltTuple | undefined): boolean {
  return (
    b !== undefined &&
    a.epoch === b.epoch &&
    a.manifestVersion === b.manifestVersion &&
    a.manifestSigHashHex === b.manifestSigHashHex &&
    a.valuesDigestHex === b.valuesDigestHex
  );
}

/**
 * The up-front decision of effective-admin authority (min(token scope,
 * chain role) — §9-2). The role comes from the verified view and the scope
 * from /auth/me's tokenScopes (absent = a session principal = the user's
 * full power); no 403 is hit (§16-2).
 */
const determineAuditAttestation = Effect.fn("checkpoint.determineAuditAttestation")(
  function* (input: {
    readonly client: MaruhiClient;
    readonly verified: VerifiedProject;
    readonly signerUserId: string;
  }): Effect.fn.Return<boolean, CliError> {
    const member = input.verified.state.members.get(input.signerUserId);
    if (member === undefined || (member.role !== "admin" && member.role !== "owner")) {
      return false;
    }
    const me = yield* input.client.auth.me({}).pipe(Effect.mapError(toCliError));
    if (me.tokenScopes === undefined) {
      return true;
    }
    const granted = scopePermissionFor(me.tokenScopes, input.verified.projectId);
    return granted === "admin";
  },
);

/**
 * Resolving the coverage targets ("all" = chain-derived environments -
 * verified deletions - **outside one's own scope**). An out-of-scope
 * environment cannot be value-pulled and cannot be notarized (CRYPTO_SPEC
 * §6.2 `checkpoint` requires every tuple's environment in actor scope; §6.3
 * cross-environment (i) — 2026-09-15 ES K4). Exclusions are returned via
 * `outOfScope` so the caller puts them on a SHOULD warning (the reason for
 * missing the all-environments SHOULD must not be silenced). An explicit
 * list (trigger (i)) is a typed error when out of scope.
 */
const resolveTargets = Effect.fn("checkpoint.resolveTargets")(function* (
  input: CheckpointInput,
): Effect.fn.Return<
  { readonly targets: readonly EnvironmentId[]; readonly outOfScope: readonly string[] },
  CliError
> {
  if (input.environmentIds !== "all") {
    for (const environmentId of input.environmentIds) {
      yield* requireEnvironmentInScope({
        verified: input.verified,
        userId: input.signerUserId,
        environmentId,
        operation: "checkpoint",
      });
    }
    return { targets: input.environmentIds, outOfScope: [] };
  }
  const all = [...input.verified.state.environments.keys()];
  if (all.length === 0) {
    return { targets: [], outOfScope: [] };
  }
  const self = input.verified.state.members.get(input.signerUserId);
  if (self === undefined) {
    return yield* Effect.fail(cliError("You are not a chain-derived member of this project"));
  }
  const deleted = yield* verifiedDeletedEnvironmentSet(input.client, input.verified);
  const active = all.filter((environmentId) => !deleted.has(environmentId));
  return {
    targets: active
      .filter((environmentId) => scopeIncludesEnvironment(self.scope, environmentId))
      .toSorted(compareUtf8Bytes) as readonly EnvironmentId[],
    outOfScope: active
      .filter((environmentId) => !scopeIncludesEnvironment(self.scope, environmentId))
      .toSorted(compareUtf8Bytes),
  };
});

/**
 * Building the verified view: verified-pull each target environment in
 * order and assemble the tuples. The view may advance via a pull's bounded
 * resync — the last pull's view becomes the signing basis (the CAS parent)
 * and each tuple's epoch copies that view's chain-derived value (the
 * consensus rule's exact match at entry time). A change between pull and
 * signing is detected by the acceptance stage (409 / 422) and absorbed by
 * bounded retries.
 */
const buildTuples = Effect.fn("checkpoint.buildTuples")(function* (
  input: CheckpointInput,
  targets: readonly EnvironmentId[],
): Effect.fn.Return<BuiltView, CliError> {
  let view = yield* input.resync;
  const warnings: string[] = [];
  const pulls = new Map<
    string,
    {
      readonly manifestVersion: number;
      readonly manifestSigHashHex: string;
      readonly values: readonly EnvValuesDigestEntry[];
    }
  >();
  for (const environmentId of targets) {
    const floor = yield* input.floorFor(environmentId);
    const pulled = yield* pullVerifiedEnvironment({
      client: input.client,
      verified: view,
      environmentId,
      resync: input.resync,
      floor,
    }).pipe(
      Effect.mapError((error) =>
        cliError(
          `Cannot build the checkpoint for environment ${displayText(environmentId)}: ${error.message}`,
        ),
      ),
    );
    view = pulled.verified;
    warnings.push(...pulled.warnings);
    pulls.set(environmentId, {
      manifestVersion: pulled.manifest.manifestVersion,
      manifestSigHashHex: pulled.manifest.signedBytesHashHex,
      values: pulled.variables.map((value) => ({
        variableId: value.variableId,
        version: value.version,
        valueSigHashHex: value.signedBytesHashHex,
      })),
    });
  }
  const tuples: BuiltTuple[] = [];
  for (const environmentId of targets) {
    const pulled = pulls.get(environmentId);
    const environment = view.state.environments.get(environmentId);
    if (pulled === undefined || environment === undefined) {
      return yield* Effect.fail(
        cliError(
          `Environment ${displayText(environmentId)} disappeared from the verified chain while building the checkpoint — re-run`,
        ),
      );
    }
    const digest = yield* cryptoEffect(() => computeEnvValuesDigest(SUITE_ID, pulled.values)).pipe(
      Effect.mapError(() => cliError("Failed to compute the checkpoint values digest")),
    );
    tuples.push({
      environmentId,
      epoch: environment.currentEpoch,
      manifestVersion: pulled.manifestVersion,
      manifestSigHashHex: pulled.manifestSigHashHex,
      valuesDigestHex: digest,
    });
  }
  return { view, tuples, warnings };
});

/**
 * Fetching the audit-head attestation (called only for effective admin —
 * §16-2). AuditHeadNotReady (503 — the lazy materialization's bounded
 * extension is incomplete) is absorbed by a dedicated bounded retry: the
 * server-side progress is saved per call and always advances, so a
 * bounded retry converges (exponential backoff — see the constant). On
 * exhaustion the message guides the cause and the fix by re-running
 * (never silently drop to a generic error). `maruhi audit reconcile`
 * shares this too.
 */
export const fetchAuditHead = Effect.fn("checkpoint.fetchAuditHead")(function* (
  client: MaruhiClient,
  projectId: string,
): Effect.fn.Return<string, CliError, CliIo> {
  const io = yield* CliIo;
  // 503 failures absorbed so far (the count behind the message's
  // attempt numbering). The cap lives in `while`, not the schedule:
  // stopping the schedule by `times` would still run the `while`
  // predicate on the final step — emitting a spurious retry line
  let notReady = 0;
  return yield* client.audit.auditHead({ params: { projectId } }).pipe(
    Effect.map((response) => response.auditHeadHashHex),
    Effect.catchTag("AuditHeadNotReady", Effect.fail, (error) =>
      Effect.fail(
        cliError(`Cannot fetch the audit head attestation (${toCliError(error).message})`),
      ),
    ),
    Effect.retry({
      while: (error) => {
        if (
          !(error instanceof AuditHeadNotReadyError) ||
          notReady >= MAX_AUDIT_HEAD_NOT_READY_ATTEMPTS - 1
        ) {
          return false;
        }
        notReady += 1;
        return Effect.as(
          io.log(
            `The server is materializing the audit-head hash column — retrying (attempt ${notReady + 1} of ${MAX_AUDIT_HEAD_NOT_READY_ATTEMPTS})`,
          ),
          true,
        );
      },
      schedule: Schedule.exponential(AUDIT_HEAD_NOT_READY_BASE_DELAY),
    }),
    Effect.catchTag(
      "AuditHeadNotReady",
      () => Effect.fail(cliError(AUDIT_HEAD_NOT_READY_EXHAUSTED)),
      Effect.fail,
    ),
  );
});

/** One attempt of sign → append → post-acceptance reconciliation (§12-10 (3)). */
const sendCheckpoint = Effect.fn("checkpoint.sendCheckpoint")(function* (input: {
  readonly client: MaruhiClient;
  readonly view: VerifiedProject;
  readonly tuples: readonly BuiltTuple[];
  readonly auditHeadHashHex: string;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
}): Effect.fn.Return<
  { readonly headSeq: number },
  ChainHeadConflictError | CheckpointStateMismatchError | AuditHeadNotReadyError | CliError
> {
  const environments: CheckpointEnvironmentEntry[] = input.tuples.map((tuple) => ({
    environmentId: tuple.environmentId,
    epoch: tuple.epoch,
    manifestVersion: tuple.manifestVersion,
    manifestSigHashHex: tuple.manifestSigHashHex,
    valuesDigestHex: tuple.valuesDigestHex,
  }));
  const entry = yield* signEntryAtHead({
    verified: input.view,
    signerUserId: input.signerUserId,
    operation: {
      op: "checkpoint",
      payload: { environments, auditHeadHashHex: input.auditHeadHashHex },
    },
    signingKeyPair: input.signingKeyPair,
    failureText: "Failed to sign the checkpoint entry",
  });
  yield* appendCheckpoint(input.client, input.view, entry);
  // Post-acceptance reconciliation (§12-10 (3)): confirming own entry on
  // the verified chain. A 2xx is only a transport-layer fact — success is
  // reported only after this confirmation passes
  yield* confirmAccepted(entry, input.resync);
  return { headSeq: entry.seq };
});

/**
 * Sending the append. 409 (CAS) and 422 (CheckpointStateMismatch) are
 * returned as their types for the caller's retry. A transport-layer
 * failure (a lost response) fails with "may or may not have landed"
 * explicit — a checkpoint does not advance local state and re-running is
 * safe either way (if it landed, it simply becomes the baseline on a newer
 * head), so a landing probe like rotate's is unnecessary (the ruling is
 * docs/notes/session-35.md).
 */
function appendCheckpoint(
  client: MaruhiClient,
  view: VerifiedProject,
  entry: ChainEntry,
): Effect.Effect<
  void,
  ChainHeadConflictError | CheckpointStateMismatchError | AuditHeadNotReadyError | CliError
> {
  return client.membership
    .append({
      params: { projectId: view.projectId },
      payload: { parentHeadHashHex: view.state.headHashHex, entry },
    })
    .pipe(
      Effect.asVoid,
      Effect.catchTag(
        ["ChainHeadConflict", "CheckpointStateMismatch", "AuditHeadNotReady"],
        Effect.fail,
        (error) =>
          Effect.fail(
            isServerRejection(error)
              ? toCliError(error)
              : cliError(
                  `Sending the checkpoint failed (${toCliError(error).message}). The entry may or may not have landed — re-running \`maruhi project checkpoint\` is safe either way (a landed checkpoint simply becomes the baseline; a re-run notarizes the current view)`,
                ),
          ),
      ),
    );
}

/**
 * Post-acceptance reconciliation (§12-10 (3)): own entry's hash must sit
 * on the re-synced verified chain at that seq. If absent, acceptance is
 * unconfirmed (success is not reported even on a 2xx).
 */
const confirmAccepted = Effect.fn("checkpoint.confirmAccepted")(function* (
  entry: ChainEntry,
  resync: Effect.Effect<VerifiedProject, CliError>,
): Effect.fn.Return<void, CliError> {
  const expectedHash = yield* cryptoPromise("computeChainEntryHash", () =>
    computeChainEntryHash(entry),
  ).pipe(Effect.mapError(() => cliError("Failed to compute the checkpoint entry hash")));
  const view = yield* resync.pipe(
    Effect.mapError((error) =>
      cliError(
        `The checkpoint was submitted, but the post-acceptance chain sync failed (${error.message}). Re-run to confirm it landed`,
      ),
    ),
  );
  if (view.history.entryHashAt(entry.seq) !== expectedHash) {
    return yield* Effect.fail(
      cliError(
        "The server returned success, but the re-synced chain does not contain this checkpoint entry — do not trust this submission; re-run (the effect of a mutation is confirmed only through verifiable distribution — AUTH_SPEC §12-10)",
      ),
    );
  }
});

/**
 * Zero coverage targets is a failure (when only out-of-scope ones remain,
 * say so); the out-of-scope exclusion is a SHOULD warning (the reason for
 * missing the all-environments SHOULD must not be silenced — design record
 * K4-M).
 */
function scopeCoverageNotes(
  targets: readonly EnvironmentId[],
  outOfScope: readonly string[],
): Effect.Effect<string[], CliError> {
  const listed = outOfScope.map(displayText).join(", ");
  if (targets.length === 0) {
    return Effect.fail(
      cliError(
        outOfScope.length === 0
          ? "This project has no active environments to checkpoint"
          : `This project has no active environments in your scope to checkpoint (outside your scope: ${listed})`,
      ),
    );
  }
  if (outOfScope.length === 0) {
    return Effect.succeed([]);
  }
  return Effect.succeed([
    `${outOfScope.length === 1 ? "environment" : "environments"} ${listed} outside your scope cannot be covered (a checkpoint notarizes only environments in the issuer's scope — CRYPTO_SPEC §6.2); a member whose scope includes them should checkpoint separately`,
  ]);
}

/**
 * The shared implementation of `maruhi project checkpoint` (trigger (ii))
 * and the periodic issuance after a rotate completes (trigger (i)).
 * Includes the retries and subset fallback of the CRYPTO_SPEC §6.3
 * issuance SHOULD.
 */
export const issueCheckpoint = Effect.fn("checkpoint.issueCheckpoint")(function* (
  input: CheckpointInput,
): Effect.fn.Return<CheckpointSummary, CliError, CliIo> {
  const io = yield* CliIo;
  const { targets, outOfScope } = yield* resolveTargets(input);
  const warnings: string[] = yield* scopeCoverageNotes(targets, outOfScope);
  const attest = yield* determineAuditAttestation(input);
  const counters: RetryCounters = { mismatch: 0, headConflict: 0, notReady: 0 };
  let previous: BuiltView | null = null;
  let subset: readonly EnvironmentId[] | null = null;
  for (;;) {
    // The retried unit of §12-10 (3): rebuild the view, refetch the
    // attestation (fetched after the CAS parent — the chain head the
    // signing is based on — is settled, §6.3; a retry refetches it too,
    // §16-2), and send. An AuditHeadNotReady (503) from the accepting
    // side is retried by Effect.retry on this whole unit — a fresh view
    // + attestation is exactly what converges it (the failure response
    // still advanced the server's bounded extension — progress saved,
    // AUDIT_SPEC §5.1). `while` carries the cumulative cap for the same
    // reason as fetchAuditHead (the outer for(;;) interleaves other
    // retriable kinds, so a per-call `times` could not bound it)
    const attemptBody: Effect.Effect<
      {
        readonly built: BuiltView;
        readonly baseline: BuiltView | null;
        readonly outcome:
          | { readonly kind: "accepted"; readonly accepted: { readonly headSeq: number } }
          | { readonly kind: "head-conflict" }
          | { readonly kind: "state-mismatch"; readonly reason: string };
      },
      AuditHeadNotReadyError | CliError,
      CliIo
    > = Effect.gen(function* () {
      // The type annotation cuts the generator's self-referential inference (built → subset → built)
      const built: BuiltView = yield* buildTuples(input, subset ?? targets);
      warnings.push(...built.warnings);
      // The subset-fallback baseline = the previous build (null while a
      // subset issuance is in flight — no fallback inside a subset)
      const baseline = subset === null ? previous : null;
      previous = built;
      const auditHeadHashHex = attest
        ? yield* fetchAuditHead(input.client, input.verified.projectId)
        : "";
      const outcome = yield* sendCheckpoint({
        client: input.client,
        view: built.view,
        tuples: built.tuples,
        auditHeadHashHex,
        signerUserId: input.signerUserId,
        signingKeyPair: input.signingKeyPair,
        resync: input.resync,
      }).pipe(
        Effect.map((accepted) => ({ kind: "accepted" as const, accepted })),
        // The 503 re-fails before classification — it is retried by the
        // Effect.retry on the unit, not absorbed as an outcome
        Effect.catchTags(
          {
            ChainHeadConflict: () => Effect.succeed({ kind: "head-conflict" as const }),
            CheckpointStateMismatch: (error) =>
              Effect.succeed({ kind: "state-mismatch" as const, reason: error.reason }),
          },
          // The 503 (AuditHeadNotReady) and the rest re-fail here — the
          // unit's Effect.retry handles the 503, toCliError is the CLI's
          // final shape elsewhere
          Effect.fail,
        ),
      );
      return { built, baseline, outcome };
    });
    const attempt = yield* attemptBody.pipe(
      Effect.retry({
        while: (error) => {
          if (
            !(error instanceof AuditHeadNotReadyError) ||
            counters.notReady >= MAX_AUDIT_HEAD_NOT_READY_ATTEMPTS - 1
          ) {
            return false;
          }
          counters.notReady += 1;
          return Effect.as(
            io.log(
              `The server is materializing the audit-head hash column — refetching the attestation and retrying (attempt ${counters.notReady + 1} of ${MAX_AUDIT_HEAD_NOT_READY_ATTEMPTS})`,
            ),
            true,
          );
        },
        schedule: Schedule.exponential(AUDIT_HEAD_NOT_READY_BASE_DELAY),
      }),
      Effect.catchTag(
        "AuditHeadNotReady",
        () => Effect.fail(cliError(AUDIT_HEAD_NOT_READY_EXHAUSTED)),
        Effect.fail,
      ),
    );
    if (attempt.outcome.kind === "accepted") {
      return summarizeAccepted({
        targets,
        subset,
        attest,
        headSeq: attempt.outcome.accepted.headSeq,
        warnings,
      });
    }
    // Absorbing a retriable failure: null = retry as-is, array = fall back to the subset
    const nextSubset = yield* absorbSendFailure({
      failure: attempt.outcome,
      counters,
      built: attempt.built,
      baseline: attempt.baseline,
      warnings,
      io,
    });
    if (nextSubset !== null) {
      subset = nextSubset;
    }
  }
});

/** issueCheckpoint's retry counters (an independent budget per failure kind). */
interface RetryCounters {
  mismatch: number;
  headConflict: number;
  notReady: number;
}

/**
 * Absorbing a send failure (the three retriable kinds). Return null =
 * refetch the view and retry as-is, array = fall back to the subset
 * (§6.3). Budget exhaustion becomes a definitive failure with per-kind
 * guidance.
 *
 * - head-conflict (409): re-sign and retry (the existing convention's cap)
 * - state-mismatch (422): retry with a refetched view; past the cap, issue
 *   exactly once with the subset of tuples unchanged across the last two
 *   builds (the §6.3 fallback path)
 *
 * (audit-head-not-ready (503) no longer reaches here — the retried unit's
 * Effect.retry absorbs it by refetching the view and the attestation;
 * even on a failure response the server's extension has advanced, so
 * retrying converges — progress saved, AUDIT_SPEC §5.1. Exhaustion is
 * not silenced either: the message guides the cause and the fix by
 * re-running — session-38 ruling AG)
 */
const absorbSendFailure = Effect.fn("checkpoint.absorbSendFailure")(function* (input: {
  readonly failure:
    | { readonly kind: "head-conflict" }
    | { readonly kind: "state-mismatch"; readonly reason: string };
  readonly counters: RetryCounters;
  readonly built: BuiltView;
  readonly baseline: BuiltView | null;
  readonly warnings: string[];
  readonly io: CliIoShape;
}): Effect.fn.Return<readonly EnvironmentId[] | null, CliError> {
  const { failure, counters, io } = input;
  if (failure.kind === "head-conflict") {
    counters.headConflict += 1;
    yield* ensureHeadConflictBudget(counters.headConflict);
    yield* io.log("The chain head advanced while the checkpoint was in flight — re-signing");
    return null;
  }
  counters.mismatch += 1;
  if (counters.mismatch < MAX_STATE_MISMATCH_ATTEMPTS) {
    yield* io.log(
      `The server-side state advanced past this checkpoint's view (${failure.reason}) — re-pulling and retrying (attempt ${counters.mismatch + 1} of ${MAX_STATE_MISMATCH_ATTEMPTS})`,
    );
    return null;
  }
  const stableIds = yield* stableSubsetOrFail({
    built: input.built,
    baseline: input.baseline,
    reason: failure.reason,
  });
  input.warnings.push(
    `Bounded retries were exhausted by concurrent writes; issuing a partial checkpoint covering the ${stableIds.length} stable environment(s) (a partial baseline is strictly stronger than none — CRYPTO_SPEC §6.3). Re-run \`maruhi project checkpoint\` later to cover the rest`,
  );
  yield* io.log(
    `Retrying with the stable subset of ${stableIds.length} environment(s) (bounded retries exhausted)`,
  );
  return stableIds;
});

/** The post-acceptance summary (for a subset issuance, skipped makes the miss of the all-environments SHOULD explicit). */
function summarizeAccepted(input: {
  readonly targets: readonly EnvironmentId[];
  readonly subset: readonly EnvironmentId[] | null;
  readonly attest: boolean;
  readonly headSeq: number;
  readonly warnings: readonly string[];
}): CheckpointSummary {
  const covered = (input.subset ?? input.targets).map(String);
  return {
    environmentIds: covered,
    skippedEnvironmentIds: input.targets.map(String).filter((id) => !covered.includes(id)),
    attestedAuditHead: input.attest,
    headSeq: input.headSeq,
    warnings: [...new Set(input.warnings)],
  };
}

/** The remaining-budget check for CAS-conflict (409) re-signing retries (spent = definitive failure). */
function ensureHeadConflictBudget(attempts: number): Effect.Effect<void, CliError> {
  return attempts >= MAX_HEAD_CONFLICT_ATTEMPTS
    ? Effect.fail(
        cliError(
          `The checkpoint's chain-head conflict did not resolve (${MAX_HEAD_CONFLICT_ATTEMPTS} attempts). Wait a moment and re-run \`maruhi project checkpoint\``,
        ),
      )
    : Effect.void;
}

/**
 * The subset fallback (§6.3): returns the environment IDs of the tuples
 * unchanged across the last two builds (baseline / built). When the
 * fallback is impossible (already re-failed on a subset = no baseline, or
 * no stable environment at all) it is a definitive failure.
 */
function stableSubsetOrFail(input: {
  readonly built: BuiltView;
  readonly baseline: BuiltView | null;
  readonly reason: string;
}): Effect.Effect<readonly EnvironmentId[], CliError> {
  if (input.baseline === null) {
    return Effect.fail(
      cliError(
        `The checkpoint could not be issued: concurrent writes kept invalidating the acceptance-time match (${input.reason}) even for the stable subset. Wait for the writes to settle and re-run \`maruhi project checkpoint\``,
      ),
    );
  }
  const baseline = input.baseline;
  const stableIds = input.built.tuples
    .filter((tuple) =>
      sameTuple(
        tuple,
        baseline.tuples.find((candidate) => candidate.environmentId === tuple.environmentId),
      ),
    )
    .map((tuple) => tuple.environmentId as EnvironmentId);
  if (stableIds.length === 0) {
    return Effect.fail(
      cliError(
        `The checkpoint could not be issued: concurrent writes kept invalidating the acceptance-time match (${input.reason}) for every environment. Wait for the writes to settle and re-run \`maruhi project checkpoint\``,
      ),
    );
  }
  return Effect.succeed(stableIds);
}

// ---------------------------------------------------------------------------
// Issuance trigger (iii): the proposal on push / pull success (CRYPTO_SPEC
// §6.3 — detecting a baseline older than 7 days or never issued). The
// baseline differs by effective authority: admin = "the latest notarized
// (non-empty audit_head_hash) checkpoint", others = "the latest
// checkpoint" — without the split a member's issuance would squash an
// admin's trigger and the notarized prefix would never advance.
//
// **How to read "never issued" (DP5 ruling C)**: "never issued" means the
// baseline is still genesis, so the elapsed days are counted **from
// genesis's time**. A boundary checkpoint (bundled into a compound —
// boundary-checkpoint.ts) is not notarized, so without this reading an
// effective-admin user would get the proposal on every push / pull
// **starting the day the project was created** (a proposal while there is
// no audit log to notarize yet = training to ignore it). The 7-day
// threshold is the same, and "the issued baseline is old" and "no baseline
// for 7 days" are treated at the same milestone.
// ---------------------------------------------------------------------------

/** The proposal text of trigger (iii) (the `Note:` prefix is added by notice.ts). */
const PLAIN_BASELINE_PROPOSAL =
  "this project's checkpoint baseline is more than 7 days behind (or was never issued). Run `maruhi project checkpoint` to refresh the rollback-detection baseline (CRYPTO_SPEC §6.3)";
const ATTESTED_BASELINE_PROPOSAL =
  "this project's latest notarized checkpoint is more than 7 days behind (or was never issued). Run `maruhi project checkpoint` to advance the notarized audit prefix (AUDIT_SPEC §6)";

/**
 * Whether the baseline checkpoint (genesis if none) is more than 7 days
 * old. With no baseline, count from genesis's time (entries[0]) (DP5
 * ruling C). A verified view with no entry at all cannot exist (genesis is
 * mandatory), but the type allows undefined — fall to the proposing side
 * (fail-open, a single Note line).
 */
function baselineIsStale(
  entry: ChainEntry | null,
  verified: VerifiedProject,
  nowMs: number,
): boolean {
  const baselineMs = entry === null ? verified.entries[0]?.timestampMs : entry.timestampMs;
  return baselineMs === undefined || nowMs - baselineMs > CHECKPOINT_PROPOSAL_AGE_MS;
}

/** The latest checkpoint entry on the chain (with a switch restricting to notarized ones). */
function latestCheckpointEntry(
  verified: VerifiedProject,
  attestedOnly: boolean,
): ChainEntry | null {
  for (let index = verified.entries.length - 1; index >= 0; index -= 1) {
    const entry = verified.entries[index];
    if (entry === undefined || entry.op !== "checkpoint") {
      continue;
    }
    if (!attestedOnly || entry.payload.auditHeadHashHex !== "") {
      return entry;
    }
  }
  return null;
}

/**
 * The issuance proposal on push / pull success (trigger (iii)). /auth/me
 * is fetched only when a proposal is about to be made (deciding the
 * effective authority needs the scope, but the proposal's frequency must
 * not add scope-fetching round trips — a role below admin settles on the
 * un-notarized baseline). The return value is the proposal line to display
 * (null = no proposal). timestampMs is the client-declared time, used only
 * for the proposal's threshold decision (not for verification).
 */
export const checkpointProposal = Effect.fn("checkpoint.checkpointProposal")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly nowMs: number;
}): Effect.fn.Return<string | null, never> {
  const member = input.verified.state.members.get(input.signerUserId);
  if (member === undefined || member.role === "reader") {
    // Issuance is member or above (§6.2). No proposal for a reader
    return null;
  }
  const plainBasis = latestCheckpointEntry(input.verified, false);
  const stale = (entry: ChainEntry | null): boolean =>
    baselineIsStale(entry, input.verified, input.nowMs);
  const adminRole = member.role === "admin" || member.role === "owner";
  if (!adminRole) {
    return stale(plainBasis) ? PLAIN_BASELINE_PROPOSAL : null;
  }
  const attestedBasis = latestCheckpointEntry(input.verified, true);
  if (!stale(attestedBasis)) {
    return null;
  }
  // The notarized baseline is stale: check the effective authority (the
  // scope half) before deciding the proposal's wording. /auth/me is
  // fetched only when the proposal is about to hold
  const effectiveAdmin = yield* determineAuditAttestation(input).pipe(
    Effect.orElseSucceed(() => false),
  );
  if (effectiveAdmin) {
    return ATTESTED_BASELINE_PROPOSAL;
  }
  return stale(plainBasis) ? PLAIN_BASELINE_PROPOSAL : null;
});

/**
 * The anchor-refresh proposal (session-25 §8 / the second half of
 * CRYPTO_SPEC §6.3 (b) SHOULD). On rotate success it is unconditional (the
 * anchor's epoch floor goes stale — the core detection material of the
 * anchor); on push success it is bundled into **the same single line** as
 * the trigger (iii) proposal (the ruling is docs/notes/session-35.md —
 * since local code cannot know whether an anchor is in use, an
 * unconditional output on every push would train users to ignore the
 * proposal. DP5 ruling C folded it from 2 lines to 1).
 */
export const ANCHOR_REFRESH_PROPOSAL =
  "If this project commits a repository anchor for CI (CRYPTO_SPEC §6.3), refresh it afterwards: `maruhi project anchor > <anchor-file>` and commit the update";

/** The anchor proposal on rotate success (the epoch advanced = the anchor is certainly stale). */
export const ANCHOR_STALE_AFTER_ROTATION =
  "the epoch advanced, so a committed repository anchor (if any) is now stale. Refresh it: `maruhi project anchor > <anchor-file>` and commit the update (CRYPTO_SPEC §6.3)";
