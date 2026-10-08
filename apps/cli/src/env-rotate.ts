// Epoch rotation (CRYPTO_SPEC §7 / §5.2 / §6.2, AUTH_SPEC §12-4 / §12-5).
//
// A rotation is structurally two stages: (i) the `rotate_epoch` entry (with
// the new epoch's DEK commitments) + the **composite acceptance** of the
// new epoch's complete wrap set (atomic — §12-4), (ii) the re-encryption
// of the current values = a series of ordinary pushes signed by the
// performer as writer (§7 / §4.1. Not bundled into the composite to avoid
// a giant request whose size depends on the amount of values).
// Interrupting between (i) and (ii) leaves the state "the epoch advanced
// but re-encryption remains" — a legitimate transitional state §12-7
// makes explicit, and re-running this command **resumes that re-encryption
// without advancing the epoch** (an idempotent resume).
//
// Detection happens only from the distributed data (no local progress file
// = compatible with the diskless invariant, and resumption from another
// device or member works as-is): "the latest value's epoch < the
// chain-derived current epoch" on a verified pull is the evidence of
// incompleteness.
//
// Plaintext exists only as in-memory Uint8Arrays. Logs and errors carry
// only variable names (already displayText'd) from verified statements,
// counts, and epoch numbers.

import { cryptoEffect, type EnvironmentId, type ProjectId } from "@maruhi/core";
import { computeDekCommitment, generateDek, SUITE_ID } from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

import type { VerifiedProject } from "./chain-sync.ts";
import { issueCheckpoint } from "./checkpoint.ts";
import { environmentKeysFor } from "./deks.ts";
import { ownDeviceBySigningKey } from "./device-key.ts";
import { countNoun, displayText, logWarnings } from "./display.ts";
import {
  nothingDecryptable,
  decryptForRotation,
  ensureRotationIsUseful,
} from "./env-rotate-decrypt.ts";
import { reencryptContext, reencryptCurrentValues } from "./env-rotate-pass.ts";
import { appendRotation, type RotateValuesConflictError } from "./env-rotate-send.ts";
import { ensureRotatable, type RotateInput, dedupeWarnings } from "./env-rotate-shared.ts";
import { CliError, cliError, usageError } from "./errors.ts";
import { CliIo } from "./io.ts";
import type { ManifestDigestEntry } from "./manifest.ts";
import { logWarning } from "./notice.ts";
import type { VerifiedPulledValue } from "./values-verify.ts";
import { pullVerifiedEnvironment, type VerifiedEnvironmentPull } from "./values.ts";

/** The consensus-rule bound of the chain's free-text field (CRYPTO_SPEC §6.1). */
const MAX_REASON_BYTES = 1024;

/** The result of one rotation (the material of the display and the exit code). */
export interface RotationSummary {
  /**
   * rotated = started a new epoch / resumed = resumed an unfinished
   * re-encryption / up-to-date = no incompleteness and no new epoch
   * requested (a check only).
   */
  readonly mode: "rotated" | "resumed" | "up-to-date";
  readonly previousEpoch: number;
  readonly epoch: number;
  /** The number of variables re-encrypted and pushed. */
  readonly reencrypted: number;
  /** The number of variables a concurrent push already wrote at the current epoch (no re-encryption needed). */
  readonly alreadyCurrent: number;
  /** The number of variables left incomplete, conflict unresolved (> 0 = a partial completion). */
  readonly remaining: number;
  /**
   * Whether `remaining` is measured through the end-of-run rescan (false =
   * only the upper bound is known because an interruption happened). Only
   * this shape must be labeled "includes unverified" on display.
   */
  readonly remainingExact: boolean;
  /** The cause that interrupted the re-encryption (null = ran to the end). Used by the caller for warnings. */
  readonly failure: string | null;
  /**
   * The **accepted** re-encryption writes of this run (name and new
   * version. Aggregated across passes and resumes). Material for advancing
   * the sync receipt: since re-encryption does not change the plaintext, a
   * version listed here carries the same plaintext as the previous
   * version. `alreadyCurrent` (concurrent pushes — the plaintext may
   * differ) and the unfinished part are not listed. An accepted write
   * cannot be taken back, so it is listed even on a run that never reached
   * the rescan (`remainingExact = false`) — a regression of one's own
   * write (rollback) is interrupted by the rescan as evidence, so it never
   * appears on a path that returns a summary.
   */
  readonly written: readonly ReencryptedVariable[];
  readonly warnings: readonly string[];
}

/** One accepted re-encryption (the name from a verified statement and the new version). */
export interface ReencryptedVariable {
  readonly name: string;
  readonly version: number;
}

/**
 * Early validation of the reason string. A `null` return means
 * "`--reason` itself was not given"; an empty string is never returned —
 * **given but empty** (`--reason "$UNSET_VAR"` etc.) is dropped here.
 * Collapsing both to `""` would let a run that requested a rotation slip
 * into the "a check without a reason" path and exit successfully having
 * sent no request (a departing-member removal script would read an
 * unadvanced epoch as advanced). The length cap is the chain's free-text
 * bound (§6.1). An entry over it is **invalid** (a consensus rule), so it
 * is dropped here without waiting for the server's refusal.
 *
 * The "required" judgment does not happen here: on the resume path (which
 * creates no new entry) the reason is neither recorded nor required, so
 * the required check sits right before the entry is actually signed
 * (requireReason). Never refuse a recovery from a broken state on the
 * absence of a field that would not be written.
 */
function checkReasonLength(reason: string | undefined): Effect.Effect<string | null, CliError> {
  if (reason === undefined) {
    return Effect.succeed(null);
  }
  // A malformed spelling is a usage error (2). The common argument checks
  // already drop a value that is empty itself, so the only shapes that
  // reach here are whitespace-only / too long
  const trimmed = reason.trim();
  if (trimmed.length === 0) {
    return Effect.fail(
      usageError(
        "--reason is empty. Specify the rotation reason (an unset shell variable may have expanded to an empty value). To only resume incomplete re-encryption without recording a reason, run without --reason",
      ),
    );
  }
  const bytes = new TextEncoder().encode(trimmed).length;
  if (bytes > MAX_REASON_BYTES) {
    return Effect.fail(
      usageError(
        `--reason is too long (${bytes} bytes). Free-form strings in chain entries are limited to ${MAX_REASON_BYTES} UTF-8 bytes (CRYPTO_SPEC §6.1)`,
      ),
    );
  }
  return Effect.succeed(trimmed);
}

/** Makes the reason required only on the path that creates a new epoch (part of the rotate_epoch payload). */
function requireReason(reason: string | null): Effect.Effect<string, CliError> {
  if (reason === null) {
    return Effect.fail(
      usageError(
        "Specify the rotation reason with --reason (it is recorded on the chain's rotate_epoch entry and cannot be rewritten later)",
      ),
    );
  }
  return Effect.succeed(reason);
}

/**
 * `maruhi env rotate`: rotates one environment's epoch — the §12-4 composite
 * (`rotate_epoch` entry with the new epoch's §5.2 DEK commitment plus the
 * complete new-epoch wrap set) followed by re-encrypting every active
 * variable's current value under the new DEK as ordinary pushes (§7 / §4.1).
 *
 * Re-running after an interruption resumes instead of rotating again: when a
 * verified pull shows latest values below the chain-derived current epoch,
 * the epoch is left alone and only the outstanding re-encryption is finished
 * (an idempotent resume from §12-7's legitimate transitional state).
 */
export function envRotateOp(input: RotateInput): Effect.Effect<RotationSummary, CliError, CliIo> {
  return rotateAttempt(input, 1);
}

/**
 * The bound of the bounded retry against the values_digest cross-check's
 * 422 (§12-4 — a concurrent push after the declared head settled). The
 * retry redoes from a verified pull (identical to the reads re-encryption
 * needs — doubles as preventing omissions).
 */
const MAX_VALUES_CONFLICT_ATTEMPTS = 3;

function rotateAttempt(
  input: RotateInput,
  attempt: number,
): Effect.Effect<RotationSummary, CliError, CliIo> {
  // The collected warnings are always flushed **even on a failure path**:
  // on success the caller displays summary.warnings, but an abort never
  // reaches that display path. A floor-update failure, a concurrent
  // deletion, and the no-floor caveat are precisely the information that
  // matters on an abort
  //
  // The receptacle is created **inside the Effect**: built outside, a
  // second run would start carrying the first run's warnings (retry /
  // repeat / a re-run of the same Effect), and the previous floor warning
  // or deletion notice would be reported as this run's result
  return Effect.suspend(() => {
    const warnings: string[] = [];
    return rotateWithWarnings(input, warnings).pipe(
      Effect.tapError(() => logWarnings(dedupeWarnings(warnings))),
      Effect.catchTag("RotateValuesConflictError", (error) =>
        Effect.gen(function* () {
          if (attempt < MAX_VALUES_CONFLICT_ATTEMPTS) {
            // A concurrent push advanced the current values (§12-4).
            // This attempt's composite was not accepted (the epoch did not
            // advance), so the generated new DEK and wrap set may be
            // discarded. Redo from a verified pull and rebuild the
            // values_digest material from the current stored state
            const io = yield* CliIo;
            yield* io.log(
              `A concurrent push advanced environment ${input.environmentId}'s values — re-pulling and retrying the rotation (attempt ${attempt + 1} of ${MAX_VALUES_CONFLICT_ATTEMPTS})`,
            );
            return yield* rotateAttempt(input, attempt + 1);
          }
          // On exhaustion it surfaces as a plain CliError with the same
          // message (the tag is only for this catch)
          return yield* Effect.fail(cliError(error.message));
        }),
      ),
    );
  });
}

/**
 * Interruption recovery: cleaning up from the state "the epoch advanced
 * but re-encryption remains" (§12-7's legitimate transitional state)
 * **without advancing the epoch**. Since no new chain entry is created,
 * `--reason` is neither recorded nor required on this path.
 */
const resumeReencryption = Effect.fn("env-rotate.resumeReencryption")(function* (input: {
  readonly input: RotateInput;
  readonly pulled: { readonly verified: VerifiedProject };
  readonly keys: { readonly deksByEpoch: ReadonlyMap<number, Redacted.Redacted<Uint8Array>> };
  readonly currentEpoch: number;
  readonly stale: readonly VerifiedPulledValue[];
  /** The given reason (null = `--reason` not given). Affects only the warning's wording. */
  readonly reason: string | null;
  /**
   * Whether I can open at least one of the current values. Used to
   * judge whether `--new-epoch` may be suggested when a resume is
   * impossible (= whether re-encryption material exists past the
   * advance).
   */
  readonly anyDecryptable: boolean;
  readonly warnings: string[];
}): Effect.fn.Return<RotationSummary, CliError, CliIo> {
  const { currentEpoch, stale, warnings } = input;
  const environmentId = input.input.environmentId;
  // Re-applying the guard on the advanced verified view (if a role
  // change / deletion happened between the first check and the pull,
  // only the resume path would slip through with a stale verification
  // state. The resume path only pushes and builds no wrap set, so a
  // grant's enablement creates no duty here)
  const member = yield* ensureRotatable(
    input.pulled.verified,
    environmentId,
    input.input.signerUserId,
    input.input.signingKeyPair,
  );
  const dek = input.keys.deksByEpoch.get(currentEpoch);
  if (dek === undefined) {
    // The escape is suggested **only when it can be fulfilled**:
    // --new-epoch creates the new DEK itself so it doesn't need the
    // current epoch's DEK, but with no re-encryption material (an
    // openable current value) it gets rejected by
    // ensureRotationIsUseful. Suggesting it unconditionally would send
    // the user bouncing between two contradictory errors
    return yield* Effect.fail(
      cliError(
        input.anyDecryptable
          ? `The DEK for current epoch ${currentEpoch} is not registered for you (possibly awaiting a re-wrap by the rotation's executor). Cannot resume the incomplete re-encryption — wait for the re-wrap, or if revocation takes priority, run with --new-epoch (only values you can open move to the new epoch; the rest are reported as incomplete)`
          : `The DEK for current epoch ${currentEpoch} is not registered for you (possibly awaiting a re-wrap by the rotation's executor). You cannot open any current value, so advancing the epoch with --new-epoch would re-encrypt nothing — wait for a re-wrap addressed to you, or have a member holding wraps for that epoch run this`,
      ),
    );
  }
  // The wording differs by "was a request made": a reason-less run (the
  // shape the partial-completion guidance suggests) requested nothing,
  // so saying it switched would be a lie
  const switched =
    input.reason === null
      ? "Resuming this re-encryption (no new epoch will be created)"
      : "**The requested rotation will not be performed**; switching to resuming this re-encryption (no new epoch is created, and since this path appends no chain entry, --reason is not recorded either)";
  yield* logWarning(
    `after the rotation to epoch ${currentEpoch}, environment ${environmentId} still has ${countNoun(stale.length, "variable")} with incomplete re-encryption. ${switched}. If a new epoch is strictly required (e.g. after removing a departed member), run with --new-epoch — this also counters responses that fake an incomplete state to suppress rotations`,
  );
  // Unopenable values do not stop the resume itself: **the epoch has
  // already advanced**, so the normal path's reason "never create the
  // state where only the epoch advanced and re-encryption never
  // completes" does not hold here — that state already exists, and
  // choosing not to push the openable share only maintains it (with 1
  // of 100 unopenable, never strand the other 99 on the old DEK). = the
  // same policy as the "always advance" side, so the policy is shared
  // with decryptForRotation (splitting into two places would let a
  // classification change miss only the resume path)
  const targets = yield* decryptForRotation({
    verified: input.pulled.verified,
    environmentId,
    values: stale,
    deksByEpoch: input.keys.deksByEpoch,
    chainEpoch: currentEpoch,
    warnings,
  });
  // If nothing can be pushed, never enter the passes. Entering would
  // only run an empty push pass and a full re-fetch / re-verify of the
  // environment, returning to an already-known cause (the early cut-off
  // equivalent of the normal path's ensureRotationIsUseful)
  const outcome =
    targets.length === 0
      ? {
          reencrypted: 0,
          alreadyCurrent: 0,
          remaining: stale.length,
          remainingExact: true,
          failure: nothingDecryptable(stale.length),
          written: [],
        }
      : yield* reencryptCurrentValues({
          context: reencryptContext(
            input.input,
            yield* ownDeviceBySigningKey(input.pulled.verified, member, input.input.signingKeyPair),
            {
              epoch: currentEpoch,
              dek,
              deksByEpoch: input.keys.deksByEpoch,
            },
          ),
          view: input.pulled.verified,
          targets,
          sink: warnings,
        });
  // Issuance trigger (i) (CRYPTO_SPEC §6.3): a **completion** via the
  // resume path is the same milestone — the first run never reached
  // issuance because of a crash, and only here does the interrupted
  // re-encryption complete and "the post-completion data state" come
  // into being. Issued on the same condition as the normal path (full
  // completion only)
  if (outcome.remaining === 0 && outcome.failure === null) {
    yield* issuePostRotationCheckpoint(input.input, input.pulled.verified, warnings);
  }
  return {
    mode: "resumed",
    previousEpoch: currentEpoch,
    epoch: currentEpoch,
    reencrypted: outcome.reencrypted,
    alreadyCurrent: outcome.alreadyCurrent,
    remaining: outcome.remaining,
    remainingExact: outcome.remainingExact,
    failure: outcome.failure,
    written: outcome.written,
    warnings: dedupeWarnings(warnings),
  };
});

/**
 * The pre-rotate situation warnings (no floor). Placed right after the pull
 * warnings = before any subsequent failure (DEK verification etc.).
 */
function rotateSituationWarnings(input: RotateInput, floorless: boolean): readonly string[] {
  const warnings: string[] = [];
  if (floorless) {
    warnings.push(
      `This environment has no local floor yet, so variables the server keeps omitting from responses (ones that exist but never appear in listings) are not covered by re-encryption, and the omission cannot be detected (omission detection in CRYPTO_SPEC §6.3 presumes a floor). For revocation-purpose rotations, re-run from a machine that has a floor and confirm the variable listing for ${displayText(input.environmentId)} matches`,
    );
  }
  return warnings;
}

/**
 * Path selection: send the composite (rotate), a composite-less resume
 * (resume), or a check only (up-to-date). --new-epoch always sends the
 * composite.
 */
function rotatePathOf(input: {
  readonly staleCount: number;
  readonly reason: string | null;
  readonly forceNewEpoch: boolean;
}): "resume" | "up-to-date" | "rotate" {
  if (input.forceNewEpoch) {
    return "rotate";
  }
  if (input.staleCount > 0) {
    return "resume";
  }
  return input.reason === null ? "up-to-date" : "rotate";
}

/**
 * The bundled manifest's material is assembled from the verified pull
 * (the same posture as §16-2's "from your own verified view" — never sign
 * server-claimed values as-is).
 */
function manifestBaseOf(pulled: VerifiedEnvironmentPull): {
  readonly previous: {
    readonly manifestVersion: number;
    readonly signedBytesHashHex: string;
  };
  readonly entries: readonly ManifestDigestEntry[];
  readonly envMeta: { readonly metaVersion: number; readonly sigHashHex: string };
} {
  return {
    previous: {
      manifestVersion: pulled.manifest.manifestVersion,
      signedBytesHashHex: pulled.manifest.signedBytesHashHex,
    },
    entries: [
      ...pulled.variables.map((value) => ({
        variableId: value.variableId,
        status: "active" as const,
        metaVersion: value.metaVersion,
        metaSigHashHex: value.metaSignedBytesHashHex,
      })),
      // declared (valueless declarations — §4.2) are also manifest-digest
      // targets (§4.3 — every statement's latest form. Dropping them gives
      // a digest mismatch → 422)
      ...pulled.declared.map((statement) => ({
        variableId: statement.variableId,
        status: "declared" as const,
        metaVersion: statement.metaVersion,
        metaSigHashHex: statement.metaSigHashHex,
      })),
      ...pulled.tombstones.map((tombstone) => ({
        variableId: tombstone.variableId,
        status: "deleted" as const,
        metaVersion: tombstone.metaVersion,
        metaSigHashHex: tombstone.metaSigHashHex,
      })),
    ],
    envMeta: {
      metaVersion: pulled.environment.metaVersion,
      sigHashHex: pulled.environment.metaSigHashHex,
    },
  };
}

const rotateWithWarnings = Effect.fn("env-rotate.rotateWithWarnings")(function* (
  input: RotateInput,
  warnings: string[],
): Effect.fn.Return<RotationSummary, CliError | RotateValuesConflictError, CliIo> {
  const io = yield* CliIo;
  const reason = yield* checkReasonLength(input.reason);
  yield* ensureRotatable(
    input.verified,
    input.environmentId,
    input.signerUserId,
    input.signingKeyPair,
  );
  // --new-epoch never goes through the resume path = it always signs an
  // entry. The reason the required check is deferred to just before
  // signing (on resume the reason is not recorded) does not exist here,
  // so it is dropped before the pull — never fetch every variable's
  // ciphertext for an unsatisfiable argument check and leave a
  // per-variable var.read on the audit log (same discipline as
  // ensureRotatable)
  if (input.forceNewEpoch) {
    yield* requireReason(reason);
  }
  // The target set's only source is the server's pull response (the
  // variable list is not on the chain — §6.2). Since detecting an
  // omission is the local floor's variable-omitted rule's job (§6.3
  // (a)), a run without a floor (first sync, after corruption) cannot
  // detect "a variable consistently withheld". A rotation is a
  // revocation operation and this leftover is heavy, so it is made
  // explicit before reporting completion (how §14.3-3's dominant
  // leftover appears on this path)
  const floorless = input.floor.current() === null;

  // (1) The verified pull (§6.3 / §12-7): every active variable's
  // latest value + the wraps of every epoch addressed to me. Between
  // the rotation and the re-encryption's completion, the latest
  // values' epochs can differ per variable (§12-7) — which is also the
  // detection material of interruption recovery
  const pulled = yield* pullVerifiedEnvironment({
    client: input.client,
    verified: input.verified,
    environmentId: input.environmentId,
    resync: input.resync,
    floor: input.floor,
  });
  // Warnings enter the sink **before** any subsequent failure (DEK
  // verification etc.): if the failure path's flush didn't include them,
  // they'd vanish exactly on failure — the same hole as round 8
  warnings.push(...pulled.warnings, ...rotateSituationWarnings(input, floorless));
  const keys = yield* environmentKeysFor({
    client: input.client,
    verified: pulled.verified,
    environmentId: input.environmentId,
    recipient: input.recipient,
    prefetched: pulled.deks,
  });
  const currentEpoch = keys.currentEpoch;
  const stale = pulled.variables.filter((value) => value.epoch < currentEpoch);
  const path = rotatePathOf({
    staleCount: stale.length,
    reason,
    forceNewEpoch: input.forceNewEpoch,
  });

  // --- Interruption recovery: the epoch advanced but re-encryption remains ---
  if (path === "resume") {
    return yield* resumeReencryption({
      input,
      pulled,
      keys,
      currentEpoch,
      stale,
      reason,
      anyDecryptable: pulled.variables.some((value) => keys.deksByEpoch.has(value.epoch)),
      warnings,
    });
  }

  // No incompleteness and no --reason given = a "check only" run (the
  // re-run shape the partial-completion guidance suggests). Requiring
  // --reason here would ask the user who re-ran as guided for a reason,
  // and giving one would become **a second rotation**. Nothing is done;
  // the completion state is reported. `--reason ""` never reaches this
  // path (checkReasonLength drops it earlier)
  if (path === "up-to-date") {
    return {
      mode: "up-to-date",
      previousEpoch: currentEpoch,
      epoch: currentEpoch,
      reencrypted: 0,
      alreadyCurrent: 0,
      remaining: 0,
      remainingExact: true,
      failure: null,
      written: [],
      warnings: dedupeWarnings(warnings),
    };
  }

  // --- The normal rotation ---
  // The reason becomes required from here (the path that actually signs a chain entry)
  const entryReason = yield* requireReason(reason);
  const newEpoch = currentEpoch + 1;
  const member = yield* ensureRotatable(
    pulled.verified,
    input.environmentId,
    input.signerUserId,
    input.signingKeyPair,
  );
  // The plaintext re-encryption needs is gathered **before advancing
  // the epoch**: with an undecryptable value present, never create the
  // state where only the epoch advanced and re-encryption can never
  // complete. When --new-epoch is given while an unfinished
  // re-encryption (old-epoch values) exists, the targets are "all
  // active variables" anyway, so they converge to the new epoch in one
  // go without transiting an intermediate epoch (every epoch's DEK is
  // already decrypted from the wraps addressed to me)
  const targets = yield* decryptForRotation({
    verified: pulled.verified,
    environmentId: input.environmentId,
    values: pulled.variables,
    deksByEpoch: keys.deksByEpoch,
    chainEpoch: currentEpoch,
    warnings,
  });
  yield* ensureRotationIsUseful(targets.length, pulled.variables.length);
  // Wrapped right after generation (from here on the DEK only flows as a Redacted)
  const dek = Redacted.make(generateDek(), { label: "dek" });
  const dekCommitmentHex = yield* computeRotationCommitmentHex({
    projectId: pulled.verified.projectId,
    environmentId: input.environmentId,
    newEpoch,
    dek,
  });
  yield* io.log(
    `Rotating environment ${input.environmentId} (epoch ${currentEpoch} → ${newEpoch}, ${countNoun(targets.length, "variable")} targeted)`,
  );
  const rotated = yield* appendRotation({
    ...input,
    baseline: pulled.verified,
    member,
    reason: entryReason,
    newEpoch,
    dek,
    dekCommitmentHex,
    manifestBase: manifestBaseOf(pulled),
    checkpointValues: pulled.variables.map((value) => ({
      variableId: value.variableId,
      version: value.version,
      valueSigHashHex: value.signedBytesHashHex,
    })),
  });
  yield* io.log(
    `rotate_epoch accepted (epoch=${newEpoch}, new DEK wrapped for ${countNoun(rotated.memberCount, "current member")})`,
  );
  if (rotated.floorWarning !== null) {
    warnings.push(rotated.floorWarning);
  }
  // The new epoch's DEK is held by its generator (me). The match
  // against the chain-derived commitment was already done by
  // appendRotation (§5.2)
  const deksByEpoch = new Map<number, Redacted.Redacted<Uint8Array>>(keys.deksByEpoch);
  deksByEpoch.set(newEpoch, dek);
  const outcome = yield* reencryptCurrentValues({
    // The attribution is the member row at acceptance time (already updated if re-signed under CAS retry)
    context: reencryptContext(
      input,
      yield* ownDeviceBySigningKey(pulled.verified, rotated.member, input.signingKeyPair),
      {
        epoch: newEpoch,
        dek,
        deksByEpoch,
      },
    ),
    view: rotated.view,
    targets,
    sink: warnings,
  });
  if (outcome.remaining === 0 && outcome.failure === null) {
    yield* issuePostRotationCheckpoint(input, rotated.view, warnings);
  }
  return {
    mode: "rotated",
    previousEpoch: currentEpoch,
    epoch: newEpoch,
    reencrypted: outcome.reencrypted,
    alreadyCurrent: outcome.alreadyCurrent,
    remaining: outcome.remaining,
    remainingExact: outcome.remainingExact,
    failure: outcome.failure,
    written: outcome.written,
    warnings: dedupeWarnings(warnings),
  };
});

/** Computing the new-epoch DEK's commitment (CRYPTO_SPEC §5.2). Failures are CliError. */
function computeRotationCommitmentHex(input: {
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly newEpoch: number;
  readonly dek: Redacted.Redacted<Uint8Array>;
}): Effect.Effect<string, CliError> {
  return cryptoEffect(() =>
    computeDekCommitment({
      context: {
        suite: SUITE_ID,
        projectId: input.projectId,
        environmentId: input.environmentId,
        epoch: input.newEpoch,
      },
      // Why it is unwrapped: it is the commitment computation's input (the encryption boundary). The product is a hash
      dek: Redacted.value(input.dek),
    }),
  ).pipe(Effect.mapError(() => cliError("Failed to compute the DEK commitment")));
}

/**
 * Issuance trigger (i) (CRYPTO_SPEC §6.3 — SHOULD): issue the
 * environment's periodic checkpoint **after the completion** of the
 * rotate and its accompanying re-encryption (the boundary share is
 * already bundled in the composite. Since issuance is post-completion, it
 * never self-conflicts with the acceptance-time match check). The cover
 * is the one tuple of this environment (charging a rotate an
 * all-environment cover would force value fetches of environments it
 * never read — the same reasoning as §12-4's audit discipline. The ruling
 * is docs/notes/session-35.md). Not called on a partial completion or a
 * failure (there is no "post-completion data state" to notarize). A
 * completion via the resume path (resumeReencryption) issues at the same
 * milestone — the first run never reached issuance because of a crash.
 * Being a SHOULD, an issuance failure never overturns the rotate's
 * success and is disclosed as a warning.
 */
const issuePostRotationCheckpoint = Effect.fn("env-rotate.issuePostRotationCheckpoint")(function* (
  input: RotateInput,
  view: VerifiedProject,
  warnings: string[],
): Effect.fn.Return<void, never, CliIo> {
  const io = yield* CliIo;
  yield* issueCheckpoint({
    client: input.client,
    verified: view,
    resync: input.resync,
    environmentIds: [input.environmentId],
    signerUserId: input.signerUserId,
    signingKeyPair: input.signingKeyPair,
    floorFor: () => Effect.succeed(input.floor),
  }).pipe(
    Effect.tap((issued) =>
      Effect.gen(function* () {
        warnings.push(...issued.warnings);
        yield* io.log(
          `Issued the post-rotation periodic checkpoint for environment ${input.environmentId}${issued.attestedAuditHead ? " (audit head attested)" : ""} — CRYPTO_SPEC §6.3 (i)`,
        );
      }),
    ),
    Effect.catch((error) =>
      Effect.sync(() => {
        warnings.push(
          `The post-rotation periodic checkpoint could not be issued (${error.message}). The boundary checkpoint from the rotation still holds; run \`maruhi project checkpoint\` to notarize the re-encrypted state (CRYPTO_SPEC §6.3 (i))`,
        );
      }),
    ),
  );
});
