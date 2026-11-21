import {
  AuditHeadNotReadyError,
  ChainHeadConflictError,
  CheckpointStateMismatchError,
} from "@maruhi/api-schema";
import {
  type EnvironmentId,
  type ProjectId,
  type UserId,
  cryptoEffect,
  cryptoPromise,
  scopePermissionFor,
} from "@maruhi/core";
import type {
  ChainEntry,
  CheckpointEnvironmentEntry,
  EnvValuesDigestEntry,
  MemberScope,
  SigningKeyPair,
} from "@maruhi/crypto";
import {
  computeChainEntryHash,
  computeEnvValuesDigest,
  scopeIncludesEnvironment,
  SUITE_ID,
} from "@maruhi/crypto";
import { Clock, Effect, Schedule } from "effect";

import type { MaruhiClient } from "../api.ts";
import { signEntryAtHead } from "../chain-append.ts";
import type { VerifiedProject } from "../chain-sync.ts";
import { chainDeletedEnvironments, chainEnvironmentIds } from "../deks.ts";
import { displayText } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import { isServerRejection, toCliError } from "../failure.ts";
import type { FloorHandle } from "../floor-check.ts";
import { CliIo, type CliIoShape } from "../io.ts";
import { requireEnvironmentInScope } from "../scope.ts";
import { pullVerifiedEnvironment } from "../values.ts";

const MAX_STATE_MISMATCH_ATTEMPTS = 3;
const MAX_HEAD_CONFLICT_ATTEMPTS = 5;
const MAX_AUDIT_HEAD_NOT_READY_ATTEMPTS = 10;

const AUDIT_HEAD_NOT_READY_BASE_DELAY = "5 millis";

const AUDIT_HEAD_NOT_READY_EXHAUSTED = `The server is still materializing the audit-head hash column after ${MAX_AUDIT_HEAD_NOT_READY_ATTEMPTS} attempts (this happens once, on the first audit-head access of a project with a very large existing audit log). Progress is saved server-side and every attempt advances it — re-run the command to continue where it left off`;

const CHECKPOINT_PROPOSAL_AGE_MS = 7 * 24 * 60 * 60 * 1000;

interface CheckpointSummary {
  readonly environmentIds: readonly EnvironmentId[];
  readonly unchangedEnvironmentIds: readonly EnvironmentId[];
  readonly skippedEnvironmentIds: readonly string[];
  readonly outOfScopeEnvironmentIds: readonly string[];
  readonly attestedAuditHead: boolean;
  readonly headSeq: number | null;
  readonly warnings: readonly string[];
}

interface CheckpointInput {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly environmentIds: "all" | readonly EnvironmentId[];
  readonly signerUserId: UserId;
  readonly signingKeyPair: SigningKeyPair;
  readonly floorFor: (environmentId: EnvironmentId) => Effect.Effect<FloorHandle, CliError>;
}

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

interface BuiltTuple {
  readonly environmentId: EnvironmentId;
  readonly epoch: number;
  readonly manifestVersion: number;
  readonly manifestSigHashHex: string;
  readonly valuesDigestHex: string;
}

interface BuiltView {
  readonly view: VerifiedProject;
  readonly tuples: readonly BuiltTuple[];
  readonly unchanged: readonly EnvironmentId[];
  readonly warnings: readonly string[];
}

type TupleCoordinates = Omit<BuiltTuple, "environmentId">;

function sameTuple(a: TupleCoordinates, b: TupleCoordinates | undefined): boolean {
  return (
    b !== undefined &&
    a.epoch === b.epoch &&
    a.manifestVersion === b.manifestVersion &&
    a.manifestSigHashHex === b.manifestSigHashHex &&
    a.valuesDigestHex === b.valuesDigestHex
  );
}

const determineAuditAttestation = Effect.fn("checkpoint.determineAuditAttestation")(
  function* (input: {
    readonly client: MaruhiClient;
    readonly verified: VerifiedProject;
    readonly signerUserId: UserId;
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
  if (chainEnvironmentIds(input.verified).length === 0) {
    return { targets: [], outOfScope: [] };
  }
  const self = input.verified.state.members.get(input.signerUserId);
  if (self === undefined) {
    return yield* Effect.fail(cliError("You are not a chain-derived member of this project"));
  }
  return splitByScope(input.verified, self.scope);
});

function splitByScope(
  verified: VerifiedProject,
  scope: MemberScope,
): { readonly targets: readonly EnvironmentId[]; readonly outOfScope: readonly string[] } {
  const deleted = chainDeletedEnvironments(verified);
  const active = chainEnvironmentIds(verified).filter((id) => !deleted.has(id));
  return {
    targets: active
      .filter((environmentId) => scopeIncludesEnvironment(scope, environmentId))
      .toSorted(compareUtf8Bytes) as readonly EnvironmentId[],
    outOfScope: active
      .filter((environmentId) => !scopeIncludesEnvironment(scope, environmentId))
      .toSorted(compareUtf8Bytes),
  };
}

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
  const unchanged = tuples.filter((tuple) =>
    sameTuple(tuple, view.state.checkpoints.get(tuple.environmentId)),
  );
  return {
    view,
    tuples: tuples.filter((tuple) => !unchanged.includes(tuple)),
    unchanged: unchanged.map((tuple) => tuple.environmentId),
    warnings,
  };
});

const retryWhileAuditHeadNotReady = Effect.fn("checkpoint.retryWhileAuditHeadNotReady")(function* <
  A,
  R,
>(
  effect: Effect.Effect<A, AuditHeadNotReadyError | CliError, R>,
  counts: { notReady: number },
  retrying: string,
): Effect.fn.Return<A, CliError, R | CliIo> {
  const io = yield* CliIo;
  return yield* effect.pipe(
    Effect.retry({
      while: (error) => {
        if (
          !(error instanceof AuditHeadNotReadyError) ||
          counts.notReady >= MAX_AUDIT_HEAD_NOT_READY_ATTEMPTS - 1
        ) {
          return false;
        }
        counts.notReady += 1;
        return Effect.as(
          io.log(
            `The server is materializing the audit-head hash column — ${retrying} (attempt ${counts.notReady + 1} of ${MAX_AUDIT_HEAD_NOT_READY_ATTEMPTS})`,
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

export const fetchAuditHead = Effect.fn("checkpoint.fetchAuditHead")(function* (
  client: MaruhiClient,
  projectId: ProjectId,
): Effect.fn.Return<string, CliError, CliIo> {
  return yield* retryWhileAuditHeadNotReady(
    client.audit.auditHead({ params: { projectId } }).pipe(
      Effect.map((response) => response.auditHeadHashHex),
      Effect.catchTag("AuditHeadNotReady", Effect.fail, (error) =>
        Effect.fail(
          cliError(`Cannot fetch the audit head attestation (${toCliError(error).message})`),
        ),
      ),
    ),
    { notReady: 0 },
    "retrying",
  );
});

const sendCheckpoint = Effect.fn("checkpoint.sendCheckpoint")(function* (input: {
  readonly client: MaruhiClient;
  readonly view: VerifiedProject;
  readonly tuples: readonly BuiltTuple[];
  readonly auditHeadHashHex: string;
  readonly signerUserId: UserId;
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
  });
  yield* appendCheckpoint(input.client, input.view, entry);
  yield* confirmAccepted(entry, input.resync);
  return { headSeq: entry.seq };
});

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

export const issueCheckpoint = Effect.fn("checkpoint.issueCheckpoint")(function* (
  input: CheckpointInput,
): Effect.fn.Return<CheckpointSummary, CliError, CliIo> {
  const io = yield* CliIo;
  const { targets, outOfScope } = yield* resolveTargets(input);
  const warnings: string[] = yield* scopeCoverageNotes(targets, outOfScope);
  const attest = yield* determineAuditAttestation(input);
  const nowMs = yield* Clock.currentTimeMillis;
  const issuesTupleLess = (view: VerifiedProject): boolean =>
    attest ||
    (input.environmentIds === "all" &&
      outOfScope.length === 0 &&
      baselineIsStale(latestCheckpointEntry(view, false), view, nowMs));
  const counters: RetryCounters = { mismatch: 0, headConflict: 0, notReady: 0 };
  let previous: BuiltView | null = null;
  let subset: readonly EnvironmentId[] | null = null;
  let unchangedBeforeSubset: readonly EnvironmentId[] = [];
  for (;;) {
    const attemptBody: Effect.Effect<
      {
        readonly built: BuiltView;
        readonly baseline: BuiltView | null;
        readonly outcome:
          | { readonly kind: "accepted"; readonly accepted: { readonly headSeq: number } }
          | { readonly kind: "current" }
          | { readonly kind: "head-conflict" }
          | { readonly kind: "state-mismatch"; readonly reason: string };
      },
      AuditHeadNotReadyError | CliError,
      CliIo
    > = Effect.gen(function* () {
      const built: BuiltView = yield* buildTuples(input, subset ?? targets);
      warnings.push(...built.warnings);
      const baseline = subset === null ? previous : null;
      previous = built;
      if (built.tuples.length === 0 && !issuesTupleLess(built.view)) {
        return { built, baseline, outcome: { kind: "current" as const } };
      }
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
        Effect.catchTags(
          {
            ChainHeadConflict: () => Effect.succeed({ kind: "head-conflict" as const }),
            CheckpointStateMismatch: (error) =>
              Effect.succeed({ kind: "state-mismatch" as const, reason: error.reason }),
          },
          Effect.fail,
        ),
      );
      return { built, baseline, outcome };
    });
    const attempt = yield* retryWhileAuditHeadNotReady(
      attemptBody,
      counters,
      "refetching the attestation and retrying",
    );
    if (attempt.outcome.kind === "accepted" || attempt.outcome.kind === "current") {
      return summarize({
        targets,
        outOfScope,
        built: attempt.built,
        unchangedBeforeSubset,
        attest,
        headSeq: attempt.outcome.kind === "accepted" ? attempt.outcome.accepted.headSeq : null,
        warnings,
      });
    }
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
      unchangedBeforeSubset = attempt.built.unchanged;
    }
  }
});

interface RetryCounters {
  mismatch: number;
  headConflict: number;
  notReady: number;
}

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

function summarize(input: {
  readonly targets: readonly EnvironmentId[];
  readonly outOfScope: readonly string[];
  readonly built: BuiltView;
  readonly unchangedBeforeSubset: readonly EnvironmentId[];
  readonly attest: boolean;
  readonly headSeq: number | null;
  readonly warnings: readonly string[];
}): CheckpointSummary {
  const covered = input.built.tuples.map((tuple) => tuple.environmentId);
  const unchanged = [...new Set([...input.unchangedBeforeSubset, ...input.built.unchanged])];
  return {
    environmentIds: covered,
    unchangedEnvironmentIds: unchanged,
    skippedEnvironmentIds: input.targets.filter(
      (id) => !covered.includes(id) && !unchanged.includes(id),
    ),
    outOfScopeEnvironmentIds: input.outOfScope,
    attestedAuditHead: input.headSeq !== null && input.attest,
    headSeq: input.headSeq,
    warnings: [...new Set(input.warnings)],
  };
}

function ensureHeadConflictBudget(attempts: number): Effect.Effect<void, CliError> {
  return attempts >= MAX_HEAD_CONFLICT_ATTEMPTS
    ? Effect.fail(
        cliError(
          `The checkpoint's chain-head conflict did not resolve (${MAX_HEAD_CONFLICT_ATTEMPTS} attempts). Wait a moment and re-run \`maruhi project checkpoint\``,
        ),
      )
    : Effect.void;
}

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
    .map((tuple) => tuple.environmentId);
  if (stableIds.length === 0) {
    return Effect.fail(
      cliError(
        `The checkpoint could not be issued: concurrent writes kept invalidating the acceptance-time match (${input.reason}) for every environment. Wait for the writes to settle and re-run \`maruhi project checkpoint\``,
      ),
    );
  }
  return Effect.succeed(stableIds);
}

const PLAIN_BASELINE_PROPOSAL =
  "this project's checkpoint baseline is more than 7 days behind (or was never issued). Run `maruhi project checkpoint` to refresh the rollback-detection baseline (CRYPTO_SPEC §6.3)";
const ATTESTED_BASELINE_PROPOSAL =
  "this project's latest notarized checkpoint is more than 7 days behind (or was never issued). Run `maruhi project checkpoint` to advance the notarized audit prefix (AUDIT_SPEC §6)";

function baselineIsStale(
  entry: ChainEntry | null,
  verified: VerifiedProject,
  nowMs: number,
): boolean {
  const baselineMs = entry === null ? verified.entries[0]?.timestampMs : entry.timestampMs;
  return baselineMs === undefined || nowMs - baselineMs > CHECKPOINT_PROPOSAL_AGE_MS;
}

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

export const checkpointProposal = Effect.fn("checkpoint.checkpointProposal")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly signerUserId: UserId;
  readonly nowMs: number;
  readonly afterWrite: boolean;
}): Effect.fn.Return<string | null, never> {
  const member = input.verified.state.members.get(input.signerUserId);
  if (member === undefined || member.role === "reader") {
    return null;
  }
  const plainBasis = latestCheckpointEntry(input.verified, false);
  const stale = (entry: ChainEntry | null): boolean =>
    baselineIsStale(entry, input.verified, input.nowMs);
  const plainProposal = (): string | null =>
    stale(plainBasis) &&
    (input.afterWrite || splitByScope(input.verified, member.scope).outOfScope.length === 0)
      ? PLAIN_BASELINE_PROPOSAL
      : null;
  const adminRole = member.role === "admin" || member.role === "owner";
  if (!adminRole) {
    return plainProposal();
  }
  const attestedBasis = latestCheckpointEntry(input.verified, true);
  if (!stale(attestedBasis)) {
    return null;
  }
  const effectiveAdmin = yield* determineAuditAttestation(input).pipe(
    Effect.orElseSucceed(() => false),
  );
  if (effectiveAdmin) {
    return ATTESTED_BASELINE_PROPOSAL;
  }
  return plainProposal();
});

export const ANCHOR_REFRESH_PROPOSAL =
  "If this project commits a repository anchor for CI (CRYPTO_SPEC §6.3), refresh it afterwards: `maruhi project anchor > <anchor-file>` and commit the update";

export const ANCHOR_STALE_AFTER_ROTATION =
  "the epoch advanced, so a committed repository anchor (if any) is now stale. Refresh it: `maruhi project anchor > <anchor-file>` and commit the update (CRYPTO_SPEC §6.3)";
