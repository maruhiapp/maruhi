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

import {
  AuditHeadNotReadyError,
  ChainHeadConflictError,
  CheckpointStateMismatchError,
  EnvironmentNotFoundError,
  EpochConflictError,
  ManifestVersionConflictError,
  VariableNotFoundError,
  VersionConflictError,
  type WrappedDek,
} from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import type {
  ChainDevice,
  ChainEntry,
  ChainMember,
  EnvValuesDigestEntry,
  SigningKeyPair,
} from "@maruhi/crypto";
import { computeDekCommitment, generateDek, SUITE_ID } from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

import type { MaruhiClient } from "./api.ts";
import { signBoundaryCheckpoint } from "./boundary-checkpoint.ts";
import { signEntryAtHead } from "./chain-append.ts";
import { issueCheckpoint } from "./checkpoint.ts";
import { buildWrapCompleteSet, requireWritingMember, sameWrapRecipientSet } from "./dek-wrap.ts";
import { type DekRecipient, environmentKeysFor, requireChainEnvironment } from "./deks.ts";
import { ownDeviceBySigningKey } from "./device-key.ts";
import { countNoun, displayText, logWarnings } from "./display.ts";
import { CliError, cliError, usageError } from "./errors.ts";
import { isServerRejection, toCliError } from "./failure.ts";
import type { FloorHandle } from "./floor-check.ts";
import type { ManifestFloor } from "./floor.ts";
import { CliIo } from "./io.ts";
import { type ManifestDigestEntry, signNextManifest } from "./manifest.ts";
import { logWarning } from "./notice.ts";
import { decryptVerifiedValue, missingWrapReason } from "./pull.ts";
import { encryptAndSignPayload, winnerInconsistency } from "./push.ts";
import { retryOnConflict } from "./retry.ts";
import { resyncExtended, type VerifiedProject } from "./sync.ts";
import {
  pullVerifiedEnvironment,
  type VerifiedEnvironmentPull,
  type VerifiedPulledValue,
} from "./values.ts";

const MAX_ATTEMPTS = 5;
/** The re-encryption pass limit (one pass = a push to every target + re-fetch / re-verify of the conflicts). */
const MAX_REENCRYPT_PASSES = 3;
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

interface RotateInput {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
  /**
   * The reason recorded on the chain (the §6.2 payload field).
   * `undefined` means **`--reason` itself was not given** (distinct from
   * the empty string — checkReasonLength).
   */
  readonly reason: string | undefined;
  /**
   * Even with an unfinished re-encryption, never resume it — always create
   * a new epoch (`--new-epoch`). A guarantee for a caller that requires
   * "a new epoch definitely exists after this run" (the all-environment
   * rotation on a departing member's removal — §7).
   */
  readonly forceNewEpoch: boolean;
  /**
   * Allowing a manifest **omission** (`--init-manifest` — the migration
   * path). An explicit operation limited to initializing manifest_version 1
   * on environments created before manifests existed. Verification when
   * distributed is not relaxed (manifest.ts's convention).
   */
  readonly initManifest: boolean;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  /** Resync (full chain re-verification). Used for CAS conflicts and post-acceptance confirmation. */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** The local floor (§6.3 — the check / commit of internal pulls and the floor advance of re-encryption pushes). */
  readonly floor: FloorHandle;
}

/** The material of one variable's re-encryption (the verified latest value + its plaintext). */
interface ReencryptTarget {
  readonly value: VerifiedPulledValue;
  /**
   * Memory only. No path puts it on disk, in logs, or in error messages.
   * Since it holds the value itself (not just a DEK) for re-encryption, it
   * is wrapped in `Redacted` — unwrapping happens only inside
   * encryptAndSignPayload (the encryption boundary).
   */
  readonly plaintext: Redacted.Redacted<Uint8Array>;
}

interface ReencryptOutcome {
  readonly reencrypted: number;
  readonly alreadyCurrent: number;
  readonly remaining: number;
  /**
   * Whether `remaining` is a **measurement** through the rescan (false =
   * the rescan was never reached and only the upper bound "the number not
   * completed this pass" is known).
   */
  readonly remainingExact: boolean;
  /**
   * The cause that interrupted the re-encryption (null = ran to the end).
   * Throwing a post-advance failure away as an exception would let the
   * fact "only the epoch advanced and re-encryption remains" slip past the
   * caller's partial-completion warning, so it is returned as a result.
   */
  readonly failure: string | null;
  /** My accepted writes (aggregated across all passes — material for RotationSummary.written). */
  readonly written: readonly ReencryptedVariable[];
}

/** One variable that got a 409 (keeps the known latest needed for verifying the winner and the claimed version). */
interface ConflictedTarget {
  readonly variableId: string;
  /** The verified value I used as the prev's basis at the conflict. */
  readonly known: VerifiedPulledValue;
  /** The latest version the 409 claimed (the input of the winner-consistency check — never the basis of adopt/reject). */
  readonly currentVersion: number;
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

/**
 * Warning dedup. The first pull and each pass's rescan return the same
 * pull-wide SHOULD warnings (non-NFC names etc.), so naively listing them
 * prints the same line 4 times and buries the run-specific warnings
 * (concurrent deletions, a missing floor).
 */
function dedupeWarnings(warnings: readonly string[]): readonly string[] {
  return [...new Set(warnings)];
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
 * Early check of rotatability: the environment exists on the chain, I am a
 * current member, and my role is member or above (§6.2). Drops before the
 * pull (fetching values = recording var.read). With grant_server enabled,
 * the complete wrap set includes a server-key wrap (buildWrapCompleteSet —
 * §12-4 / §7's re-wrap duty).
 */
function ensureRotatable(
  verified: VerifiedProject,
  environmentId: string,
  signerUserId: string,
  signingKeyPair: SigningKeyPair,
): Effect.Effect<ChainMember, CliError> {
  return Effect.gen(function* () {
    // Membership + the device's effective role (member or above) / scope are shared with env create
    const { member } = yield* requireWritingMember({
      verified,
      environmentId,
      signerUserId,
      signingKeyPair,
      operation: "rotate the epoch",
      forbidden:
        "A reader cannot rotate the epoch (rotate_epoch and value pushes require the member role or above — CRYPTO_SPEC §6.2)",
    });
    yield* requireChainEnvironment(verified, environmentId);
    return member;
  });
}

/** Signs a rotate_epoch entry right after the current head (seq = head + 1). */
function signRotateEntry(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly newEpoch: number;
  readonly reason: string;
  readonly dekCommitmentHex: string;
  readonly member: ChainMember;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<ChainEntry & { readonly op: "rotate_epoch" }, CliError> {
  return Effect.gen(function* () {
    // Resolving the signing device and signing share one place (chain-append.ts — DK K13-12)
    const signed = yield* signEntryAtHead({
      verified: input.verified,
      signerUserId: input.member.userId,
      operation: {
        op: "rotate_epoch",
        payload: {
          environmentId: input.environmentId,
          newEpoch: input.newEpoch,
          reason: input.reason,
          dekCommitmentHex: input.dekCommitmentHex,
        },
      },
      signingKeyPair: input.signingKeyPair,
      failureText: "Failed to sign the rotate_epoch entry",
    });
    // Narrowing the op (signChainEntry persists the input's op)
    if (signed.op !== "rotate_epoch") {
      return yield* Effect.fail(cliError("Failed to sign the rotate_epoch entry"));
    }
    return signed;
  });
}

/**
 * The discriminable outcomes of a send. Acceptance is confirmed by my own
 * DEK commitment matching on the chain (§12-10 (3) — a composite's effect
 * confirmation is a chain sync), and the accepted family becomes material
 * for advancing the floor (my issued manifest) **even on a path where the
 * command exits with an error**.
 */
type RotateSendOutcome =
  /** Refused with the server's own error body (no effect has occurred — settled). */
  | { readonly kind: "rejected" }
  /**
   * Confirmed it was not accepted (settled). The chain having advanced
   * past the declared head = this attempt's CAS can no longer hold (the
   * prev is signed).
   */
  | { readonly kind: "not-accepted" }
  /** Acceptance confirmed, and the current epoch = the target epoch (the normal path). */
  | { readonly kind: "accepted-and-current"; readonly view: VerifiedProject }
  /** Acceptance confirmed, but another rotation overtook the current epoch. */
  | { readonly kind: "accepted-but-superseded"; readonly view: VerifiedProject }
  /**
   * The chain is still at the declared head = the sent composite **could
   * still land** (the response vanished but the request may be in
   * transit). Never settle to not-accepted — the intent (3-F) is left
   * unresolved and the reconciliation after the chain moves settles it.
   */
  | { readonly kind: "send-pending" }
  /** Could not confirm acceptance (probe failure) — never advance the floor. */
  | { readonly kind: "acceptance-unknown" };

/**
 * The probe for when the composite send failed for a non-CAS reason.
 * **"It didn't arrive" is not guaranteed** (a vanished response, 502 /
 * 504), so check the chain for whether it was actually accepted before
 * saying anything. Emitting only the raw transport error would present
 * the most dangerous state — "only the epoch advanced, zero
 * re-encryptions" — as "nothing happened".
 */
function probeAmbiguousSend(input: {
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly baseline: VerifiedProject;
  readonly environmentId: string;
  readonly newEpoch: number;
  /** The commitment of the DEK I generated (judges whether **mine** was the accepted share). */
  readonly dekCommitmentHex: string;
  /** The declared head of the attempt whose response vanished (= the composite's CAS parent). Material for judging landing-possibility. */
  readonly declaredHead: { readonly seq: number; readonly hashHex: string };
  readonly cause: string;
}): Effect.Effect<{ readonly outcome: RotateSendOutcome; readonly error: CliError }, never> {
  return Effect.gen(function* () {
    const probe = yield* asOutcome(
      Effect.gen(function* () {
        const view = yield* resyncExtended(input.resync, input.baseline);
        const environment = yield* requireChainEnvironment(view, input.environmentId);
        return { view, environment };
      }),
    );
    if (probe.kind === "failed") {
      return {
        outcome: { kind: "acceptance-unknown" } as const,
        error: cliError(
          `${input.cause}. This failure does not mean the request never arrived (the response may have been lost). Tried to confirm on the chain whether it was accepted, but that also failed (${probe.error.message}) — environment ${input.environmentId} may already have advanced to epoch ${input.newEpoch}. Restore connectivity and re-run \`maruhi env rotate ${input.environmentId}\` (if the epoch advanced, the run resumes re-encryption; if not, it restarts the rotation)`,
        ),
      };
    }
    // The judgment is a **commitment match** — never read off the current
    // epoch's value. dekCommitments holds every epoch, so even when another
    // member rotated further after acceptance and the current epoch has
    // overtaken the target, seeing my share there settles it as accepted —
    // conditioning on the current epoch matching would report "not
    // accepted" in that case (the epoch advanced, zero re-encryptions)
    if (probe.value.environment.dekCommitments.get(input.newEpoch) === input.dekCommitmentHex) {
      const superseded = probe.value.environment.currentEpoch > input.newEpoch;
      return {
        outcome: superseded
          ? ({ kind: "accepted-but-superseded", view: probe.value.view } as const)
          : ({ kind: "accepted-and-current", view: probe.value.view } as const),
        error: cliError(
          `${input.cause}. However, the chain shows this rotation itself was accepted (epoch ${input.newEpoch} of environment ${input.environmentId} carries the DEK generated by this run). No current values have been re-encrypted yet, so holders of older-epoch DEKs can still read them — re-run \`maruhi env rotate ${input.environmentId}\` to resume re-encryption without advancing the epoch`,
        ),
      };
    }
    if (probe.value.environment.currentEpoch >= input.newEpoch) {
      return {
        outcome: { kind: "not-accepted" } as const,
        error: cliError(
          `${input.cause}. Epoch ${input.newEpoch} on the chain is another member's rotation; this run's entry was not accepted (the generated DEK will not be used) — re-run \`maruhi env rotate ${input.environmentId}\` (if re-encryption is incomplete, it resumes without advancing the epoch)`,
        ),
      };
    }
    // The current epoch below the target: settleability splits on the
    // declared-head position. If the chain has advanced past the declared
    // head, this attempt's CAS can no longer hold (settled refusal). If it
    // is still at the declared head (the slot is open), an in-transit
    // request could still land — never settle to not-accepted (the intent
    // stays unresolved and the reconciliation after the chain moves
    // settles it)
    if (probe.value.view.state.headSeq > input.declaredHead.seq) {
      return {
        outcome: { kind: "not-accepted" } as const,
        error: cliError(
          `${input.cause}. The chain shows it was not accepted (the chain advanced past this attempt's declared parent head, so it can no longer land; environment ${input.environmentId} is still at epoch ${probe.value.environment.currentEpoch}). It is safe to simply re-run`,
        ),
      };
    }
    return {
      outcome: { kind: "send-pending" } as const,
      error: cliError(
        `${input.cause}. The chain does not show it as accepted yet (environment ${input.environmentId} is still at epoch ${probe.value.environment.currentEpoch}, and the request may still be in flight). It is safe to simply re-run — the re-run resumes re-encryption if it landed, or restarts the rotation if not`,
      ),
    };
  });
}

/** The CAS-retry state: the verification view, my member row, and the new epoch's wrap set. */
interface RotateState {
  readonly verified: VerifiedProject;
  readonly member: ChainMember;
  readonly deks: readonly WrappedDek[];
}

/** The composite-acceptance result (carries back the state at acceptance as the baseline of the post-acceptance resync). */
interface AcceptedRotation {
  readonly state: RotateState;
  /** The floor record of the accepted bundled manifest (self-computed — material for §6.3's rules (a)(b)(c)). */
  readonly manifest: ManifestFloor;
  /** The id of the intent (3-F) appended before the send. The effect confirmation's result closes it. */
  readonly intentId: string;
  /** This attempt's declared head (= the composite's CAS parent. Material for the probe's landing-possibility judgment). */
  readonly declaredHead: { readonly seq: number; readonly hashHex: string };
}

/**
 * The 422 marker of the boundary checkpoint's values_digest cross-check
 * (§12-4): the shape where a concurrent push advanced the current values
 * after the declared head settled — a re-sign does not resolve it
 * (re-fetching the value set is required). CliError is subclassed so
 * envRotateOp's bounded retry (redoing from a verified pull — §12-4's
 * specification) can catch it by type (toCliError passes CliError
 * through, so the type survives even across retryOnConflict's
 * unclassified path).
 */
class RotateValuesConflictError extends CliError {}

/**
 * A rotate into a deleted (tombstone) environment is a 404 (§12-4). The
 * shape is "the chain asserts the environment exists but the server
 * returned 404", so per §7's discipline "never skip silently — interrupt
 * and warn" — never collapse it into the generic "environment not found".
 */
function mapRotateFailure(environmentId: string): (error: unknown) => unknown {
  return (error) => {
    if (error instanceof EnvironmentNotFoundError) {
      return cliError(
        `Rotation for environment ${environmentId} was rejected with 404. Unless a verified deletion statement can be confirmed, a malicious server may be selectively blocking rotation — aborting instead of silently skipping (CRYPTO_SPEC §7)`,
      );
    }
    if (error instanceof ManifestVersionConflictError) {
      // A CAS conflict on the bundled manifest (§12-5 (6)) = another meta
      // operation (a variable create / rename / delete / an environment
      // rename) was interposed between issuance and acceptance. Since the
      // meta set may have changed, re-signing within this run cannot
      // resolve it — a re-run re-fetches the meta state (unlike a chain
      // CAS 409, the material must be re-fetched)
      return cliError(
        `A concurrent meta operation advanced environment ${environmentId}'s manifest (the server reports manifestVersion ${error.currentManifestVersion}). Re-run \`maruhi env rotate\` to rebuild the manifest from the refreshed state`,
      );
    }
    if (error instanceof CheckpointStateMismatchError) {
      // The 422 of the boundary checkpoint's values_digest cross-check
      // (§12-4). envRotateOp picks it up via a bounded retry from a
      // verified pull (on exhaustion this wording surfaces as-is)
      return new RotateValuesConflictError({
        message: `A concurrent push advanced environment ${environmentId}'s values while the rotation was in flight (the server reports ${error.reason}). Re-run \`maruhi env rotate\` to rebuild the checkpoint from the refreshed state`,
      });
    }
    // Classification targets like ChainHeadConflict pass through as-is (retryOnConflict's classify)
    return error;
  };
}

/**
 * Sending the `rotate_epoch` composite (§12-4). A parent-head CAS failure
 * retries via resync → re-sign the entry (the wrap set is rebuilt only
 * when the member set changed), and after acceptance it resyncs and
 * confirms "the chain-derived current epoch is the new epoch" and "that
 * epoch's commitment is the DEK I generated" (§5.2 — applying to a
 * self-generated DEK the discipline of never using a DEK before the
 * match).
 */
function appendRotation(
  input: RotateInput & {
    readonly baseline: VerifiedProject;
    readonly member: ChainMember;
    readonly reason: string;
    readonly newEpoch: number;
    readonly dek: Redacted.Redacted<Uint8Array>;
    readonly dekCommitmentHex: string;
    /**
     * The bundled-manifest (§12-4) material: the previous manifest from a
     * verified pull (null = the migration path's v1 initialization), the
     * current meta set (tombstones included), and the latest shape of the
     * environment meta. The meta set is unchanged by a rotate (§4.3 — only
     * the epoch advance is reflected).
     */
    readonly manifestBase: {
      readonly previous: {
        readonly manifestVersion: number;
        readonly signedBytesHashHex: string;
      } | null;
      readonly entries: readonly ManifestDigestEntry[];
      readonly envMeta: { readonly metaVersion: number; readonly sigHashHex: string };
    };
    /**
     * The boundary-checkpoint (§12-4) values_digest material: the
     * value-level latest form of the verified pull (active variables only.
     * Not-yet-re-encrypted = a legitimate state of §12-7 — an old epoch's
     * current value). It is the very values actually read for
     * re-encryption, so no additional reads happen.
     */
    readonly checkpointValues: readonly EnvValuesDigestEntry[];
  },
): Effect.Effect<
  {
    readonly view: VerifiedProject;
    readonly memberCount: number;
    /**
     * My member row **used for acceptance**. On a resync under CAS retry,
     * it may have a different key fingerprint than the row the caller
     * first held — the attribution of subsequent writes (the ledger's
     * writer) uses this one.
     */
    readonly member: ChainMember;
    /** The manifest-floor-commit failure warning (null = success). The caller accumulates it into the sink. */
    readonly floorWarning: string | null;
  },
  CliError
> {
  return Effect.gen(function* () {
    const buildWraps = (verified: VerifiedProject) =>
      buildWrapCompleteSet({
        verified,
        environmentId: input.environmentId,
        epoch: input.newEpoch,
        dek: input.dek,
        signerUserId: input.signerUserId,
        signingKeyPair: input.signingKeyPair,
      });

    // Whether the send was "arrival unknown" (= whether an
    // acceptance-confirmation probe is needed). **Set only when a send was
    // attempted**: probing on a pre-send failure like a signing failure
    // would attach "it may have arrived" to a local failure and re-fetch
    // the chain. When it did send, only "refused with the server's own
    // error body" goes to the settled side (a CAS conflict is also settled
    // — we know it was not accepted, so the recover's interruption
    // (concurrent-rotation detection) after it needs no probe either)
    let ambiguousSend = false;
    // The latest send attempt's intent and manifest (self-computed). When
    // the probe confirms the acceptance of an attempt whose response
    // vanished, they become the floor-advance material and the resolution
    // target
    let lastSent: AcceptedRotation | null = null;
    const attempted = yield* asOutcome(
      retryOnConflict<RotateState, AcceptedRotation, "head-conflict">(
        { verified: input.baseline, member: input.member, deks: yield* buildWraps(input.baseline) },
        {
          maxAttempts: MAX_ATTEMPTS,
          attempt: (state) =>
            Effect.gen(function* () {
              const entry = yield* signRotateEntry({
                verified: state.verified,
                environmentId: input.environmentId,
                newEpoch: input.newEpoch,
                reason: input.reason,
                dekCommitmentHex: input.dekCommitmentHex,
                member: state.member,
                signingKeyPair: input.signingKeyPair,
              });
              // The manifest with the new epoch baked in (§12-4 / §4.3 —
              // re-issued reflecting the epoch advance even though the meta
              // set is unchanged). The declared head is the current head
              // before the append. Under CAS retry both the entry and the
              // manifest are re-signed
              const manifest = yield* signNextManifest({
                verified: state.verified,
                environmentId: input.environmentId,
                epoch: input.newEpoch,
                previous: input.manifestBase.previous,
                entries: input.manifestBase.entries,
                envMeta: input.manifestBase.envMeta,
                issuerUserId: input.signerUserId,
                signingKey: input.signingKeyPair.privateKey,
                chainHead: {
                  seq: state.verified.state.headSeq,
                  hashHex: state.verified.state.headHashHex,
                },
              });
              // journal-before-send (3-F): the intent is appended before
              // sending a security-critical mutation (never send when
              // persisting failed — fail-closed). What a crash / vanished
              // response loses is not "the belief it succeeded" but "the
              // record of the confirmation duty", which the next run's
              // reconciliation (a chain sync) resolves
              const intentId = yield* input.floor.appendIntent({
                op: "rotate_epoch",
                environmentId: input.environmentId,
                epoch: input.newEpoch,
                dekCommitmentHex: input.dekCommitmentHex,
                variableId: null,
                manifestVersion: manifest.manifestVersion,
                manifestSigHashHex: manifest.manifestSigHashHex,
                declaredHead: {
                  seq: state.verified.state.headSeq,
                  hashHex: state.verified.state.headHashHex,
                },
              });
              // The boundary checkpoint (H+2 — §12-4): the one tuple of
              // this environment (new_epoch, the bundled manifest's
              // version and hash, and the values_digest of the
              // actually-read current values). Under CAS retry it is
              // re-signed together with the entry and the manifest
              const checkpoint = yield* signBoundaryCheckpoint({
                compositeEntry: entry,
                environmentId: input.environmentId,
                epoch: input.newEpoch,
                manifestVersion: manifest.manifestVersion,
                manifestSigHashHex: manifest.manifestSigHashHex,
                values: input.checkpointValues,
                verified: state.verified,
                member: state.member,
                deviceFingerprintHex: entry.actor.keyFingerprintHex,
                signingKey: input.signingKeyPair.privateKey,
              });
              const sent: AcceptedRotation = {
                state,
                manifest: {
                  manifestVersion: manifest.manifestVersion,
                  epoch: manifest.epoch,
                  manifestSigHashHex: manifest.manifestSigHashHex,
                },
                intentId,
                declaredHead: {
                  seq: state.verified.state.headSeq,
                  hashHex: state.verified.state.headHashHex,
                },
              };
              lastSent = sent;
              yield* input.client.environments
                .rotate({
                  params: {
                    projectId: state.verified.projectId,
                    environmentId: input.environmentId,
                  },
                  payload: {
                    parentHeadHashHex: state.verified.state.headHashHex,
                    entry,
                    deks: state.deks,
                    manifest: manifest.manifest,
                    checkpoint,
                  },
                })
                .pipe(
                  Effect.tapError((error) =>
                    // A refusal with the server's own error body (a CAS
                    // 409 included) = no effect has occurred (settled) —
                    // close the intent. A resolution-append failure may be
                    // swallowed: the direction where the intent stays open
                    // is the safe side
                    isServerRejection(error)
                      ? Effect.ignore(input.floor.resolveIntent(intentId, "rejected"))
                      : Effect.void,
                  ),
                  Effect.mapError((error) => {
                    ambiguousSend = !isServerRejection(error);
                    return mapRotateFailure(input.environmentId)(error);
                  }),
                );
              return sent;
            }),
          // AuditHeadNotReady (503) advances with the same recovery as a
          // CAS conflict (resync + re-sign + re-send) — the reason and the
          // defensive classification's intent are the same as
          // env-create.ts's
          classify: (error) =>
            error instanceof ChainHeadConflictError || error instanceof AuditHeadNotReadyError
              ? "head-conflict"
              : null,
          recover: (state) =>
            Effect.gen(function* () {
              const resynced = yield* resyncExtended(input.resync, state.verified);
              const member = yield* ensureRotatable(
                resynced,
                input.environmentId,
                input.signerUserId,
                input.signingKeyPair,
              );
              const environment = yield* requireChainEnvironment(resynced, input.environmentId);
              if (environment.currentEpoch + 1 !== input.newEpoch) {
                // Another member rotated concurrently. The generated new
                // DEK, commitment, and wrap set are dedicated to that epoch
                // (§5's info / §5.2's preimage carry the epoch), so abort
                // without reusing them. A re-run resumes without advancing
                // the epoch if an unfinished re-encryption exists
                return yield* Effect.fail(
                  cliError(
                    `Detected a concurrent rotation by another member (environment ${input.environmentId} is now at epoch ${environment.currentEpoch}). The newly generated DEK will not be used; aborting — please re-run`,
                  ),
                );
              }
              const deks = sameWrapRecipientSet(state.verified, resynced, input.environmentId)
                ? state.deks
                : yield* buildWraps(resynced);
              return { verified: resynced, member, deks };
            }),
          // AuditHeadNotReady also cycles under the same classification,
          // so the wording stays faithful to both causes (prevents a wrong
          // guidance if it ever becomes reachable)
          exhaustedMessage: `The rotation kept being rejected with retryable conflicts (a chain-head conflict, or audit-head materialization in progress) after ${MAX_ATTEMPTS} attempts. Wait a moment and re-run — server-side progress is preserved`,
        },
      ),
    );
    if (attempted.kind === "failed") {
      // A settled refusal (the server's own error body) or an abort
      // decided by recover (concurrent-rotation detection — the chain was
      // already resynced and observed) know whether acceptance happened,
      // so they need no extra probe or guidance. It is also the branch
      // that keeps "you can re-run as-is" off the §7 interruption message
      if (!ambiguousSend || lastSent === null) {
        return yield* Effect.fail(attempted.error);
      }
      // Never let a send failure read as "nothing happened": probe the
      // chain, drop to a discriminable outcome, and always return a
      // failure
      return yield* settleAmbiguousRotation(input, lastSent, attempted.error.message);
    }
    // The post-acceptance confirmation uses chain re-verification, not
    // the server's claim (the response's currentEpoch) (§12-10 (3) — a
    // composite's effect confirmation is a chain sync)
    return yield* confirmAcceptedRotation(input, attempted.value);
  });
}

/** The shared input of a discriminable outcome (used by appendRotation's confirmation and the probe path). */
interface RotationConfirmInput {
  readonly floor: FloorHandle;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly baseline: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly newEpoch: number;
  readonly dekCommitmentHex: string;
}

/**
 * The floor promotion of an acceptance-confirmed manifest (the
 * "acceptance confirmed" recording trigger of §6.3. Runs unconditionally
 * the moment the on-chain own-commitment match is confirmed, even on a
 * path where the command exits with an error). A floor write failure
 * never turns an already-accepted rotation into a failure (the floor is a
 * SHOULD — disclosed as a warning).
 */
function promoteAcceptedManifest(
  floor: FloorHandle,
  accepted: AcceptedRotation,
  view: VerifiedProject,
): Effect.Effect<string | null, never> {
  return floor
    .commitManifest(accepted.manifest, {
      seq: view.state.headSeq,
      hashHex: view.state.headHashHex,
    })
    .pipe(
      Effect.as<string | null>(null),
      Effect.catch((error) =>
        Effect.succeed<string | null>(
          `The accepted rotation could not be recorded in the local floor (${error.message}). Manifest rollback detection for this rotation starts from the next successful pull`,
        ),
      ),
    );
}

/**
 * Resolving an intent (3-F). A resolution-append failure may be
 * swallowed: the direction where the intent stays open is the safe side
 * (the next run's reconciliation just redoes the same judgment).
 */
function resolveRotationIntent(
  floor: FloorHandle,
  accepted: AcceptedRotation,
  outcome: "accepted" | "accepted-superseded" | "not-accepted",
): Effect.Effect<void> {
  return Effect.ignore(floor.resolveIntent(accepted.intentId, outcome));
}

/**
 * Settling a send whose response vanished: probe the chain and drop to a
 * discriminable outcome. The accepted family advances the floor and
 * closes the intent even when the command exits with an error.
 * acceptance-unknown neither advances the floor nor resolves the intent
 * (never write an unconfirmed acceptance into the floor — the next run's
 * reconciliation [a chain sync] resolves it).
 */
function settleAmbiguousRotation(
  input: RotationConfirmInput,
  sent: AcceptedRotation,
  cause: string,
): Effect.Effect<never, CliError> {
  return Effect.gen(function* () {
    const probed = yield* probeAmbiguousSend({
      resync: input.resync,
      baseline: input.baseline,
      environmentId: input.environmentId,
      newEpoch: input.newEpoch,
      dekCommitmentHex: input.dekCommitmentHex,
      declaredHead: sent.declaredHead,
      cause,
    });
    const outcome = probed.outcome;
    if (outcome.kind === "accepted-and-current" || outcome.kind === "accepted-but-superseded") {
      // Acceptance confirmed on the chain = the floor advances even when
      // the command exits with an error (closes the window that would roll
      // it back to the pre-acceptance manifest / epoch baseline)
      const floorWarning = yield* promoteAcceptedManifest(input.floor, sent, outcome.view);
      yield* resolveRotationIntent(
        input.floor,
        sent,
        outcome.kind === "accepted-and-current" ? "accepted" : "accepted-superseded",
      );
      return yield* Effect.fail(
        floorWarning === null ? probed.error : cliError(`${probed.error.message}. ${floorWarning}`),
      );
    }
    if (outcome.kind === "not-accepted") {
      yield* resolveRotationIntent(input.floor, sent, "not-accepted");
    }
    // send-pending / acceptance-unknown are never settled: the intent
    // (3-F) stays unresolved and the next run's reconciliation (a chain
    // sync) settles accepted / rejected
    return yield* Effect.fail(probed.error);
  });
}

/**
 * The post-acceptance confirmation of a composite that got a 200 (§12-10
 * (3) — a chain sync). Any failure from here on is a failure **after the
 * epoch already advanced**, so it surfaces only the cause without losing
 * the operational state "the epoch moved, re-encryption is not done".
 */
function confirmAcceptedRotation(
  input: RotationConfirmInput,
  accepted: AcceptedRotation,
): Effect.Effect<
  {
    readonly view: VerifiedProject;
    readonly memberCount: number;
    readonly member: ChainMember;
    readonly floorWarning: string | null;
  },
  CliError
> {
  return Effect.gen(function* () {
    const postCheckError = (message: string): CliError =>
      cliError(
        `The rotation (epoch=${input.newEpoch}) was accepted, but the post-acceptance check failed: ${message}. Environment ${input.environmentId}'s epoch has advanced and no current values have been re-encrypted — resolve the cause and re-run to resume re-encryption without advancing the epoch`,
      );
    const resynced = yield* asOutcome(
      Effect.gen(function* () {
        const view = yield* resyncExtended(input.resync, accepted.state.verified);
        const environment = yield* requireChainEnvironment(view, input.environmentId);
        return { view, environment };
      }),
    );
    if (resynced.kind === "failed") {
      // Equivalent to acceptance-unknown (a 2xx is only a transport-layer
      // fact — §12-10 (3)). Since the effect could not be confirmed on the
      // distribution, the floor is not advanced and the intent stays
      // unresolved (the next run's reconciliation resolves it)
      return yield* Effect.fail(postCheckError(resynced.error.message));
    }
    const { view, environment } = resynced.value;
    if (environment.dekCommitments.get(input.newEpoch) !== input.dekCommitmentHex) {
      // §5.2: never use a DEK in any cryptographic operation until the
      // commitment match succeeds. The same discipline applies to a
      // self-generated DEK (confirming the accepted entry is mine = never
      // start re-encryption on someone else's DEK). A 2xx without my
      // commitment on the chain = not accepted (settled)
      yield* resolveRotationIntent(input.floor, accepted, "not-accepted");
      return yield* Effect.fail(
        postCheckError(
          `The accepted epoch=${input.newEpoch} commitment does not match the generated DEK's (CRYPTO_SPEC §5.2). This DEK will not be used`,
        ),
      );
    }
    if (environment.currentEpoch !== input.newEpoch) {
      // accepted-but-superseded: my rotate was accepted (commitment
      // match), but an immediately-following different rotate overtook
      // the current epoch. Keep the self-issued manifest as a minimum
      // floor (pinned test: "200 + another rotate right after")
      const floorWarning = yield* promoteAcceptedManifest(input.floor, accepted, view);
      yield* resolveRotationIntent(input.floor, accepted, "accepted-superseded");
      return yield* Effect.fail(
        postCheckError(
          `The resynced chain is now at epoch ${environment.currentEpoch} (possibly a concurrent rotation right after acceptance). This rotation itself was accepted and its manifest was recorded in the local floor${floorWarning === null ? "" : ` (with a caveat: ${floorWarning})`}`,
        ),
      );
    }
    // accepted-and-current: floor promotion → intent resolution → success
    // (§12-10 (3) — recording into the floor and reporting success only
    // after the effect confirmation passes)
    const floorWarning = yield* promoteAcceptedManifest(input.floor, accepted, view);
    yield* resolveRotationIntent(input.floor, accepted, "accepted");
    return {
      view,
      memberCount: accepted.state.deks.length,
      member: accepted.state.member,
      floorWarning,
    };
  });
}

/**
 * Preparing the re-encryption material (decryption + warning for the values that could not be opened).
 *
 * "Cannot open" = **only when no wrap of that epoch is addressed to me**
 * (any other decryption failure makes decryptTargets abort immediately).
 * Since this is a benign absence another member can open, the whole run is
 * never stopped for one — a revocation operation would otherwise give up
 * the range it could protect; the unopened share is reported as a partial
 * completion.
 *
 * This situation can only arise in §12-7's transitional state (an
 * old-epoch value remains). On the normal rotation path (no old-epoch
 * values = every value at the current epoch) it never happens, since the
 * current epoch's DEK is always held.
 */
function decryptForRotation(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly values: readonly VerifiedPulledValue[];
  readonly deksByEpoch: ReadonlyMap<number, Redacted.Redacted<Uint8Array>>;
  readonly chainEpoch: number;
  readonly warnings: string[];
}): Effect.Effect<readonly ReencryptTarget[], CliError> {
  return Effect.gen(function* () {
    const decrypted = yield* decryptTargets(input);
    for (const reason of decrypted.undecryptable) {
      input.warnings.push(undecryptableWarning(reason));
    }
    return decrypted.targets;
  });
}

/**
 * If nothing can be re-encrypted, never advance the epoch. Advancing
 * would only strand every current value on the old epoch's DEK — **not a
 * revocation** (a member with no wraps addressed to them / a response that
 * dropped every wrap, spinning only the epoch). --new-epoch doesn't help
 * either — with no value that can be opened, there is no material to
 * re-encrypt.
 */
function ensureRotationIsUseful(targets: number, variables: number): Effect.Effect<void, CliError> {
  if (targets > 0 || variables === 0) {
    return Effect.void;
  }
  return Effect.fail(
    cliError(
      `${nothingDecryptable(variables)}. Advancing the epoch in this state would leave current values stranded under old-epoch DEKs, so nothing is actually revoked — a member holding wraps for those epochs must run this instead`,
    ),
  );
}

/**
 * The wording of "nothing can be opened". **Pinned to one place** (the
 * normal path's abort and the resume path's early cut-off state the same
 * fact — split, and dedupeWarnings would pass two lookalike lines about
 * the same situation).
 */
function nothingDecryptable(variables: number): string {
  return `No values can be re-encrypted (wraps addressed to you are missing for all ${countNoun(variables, "variable")})`;
}

/** Extracts just the message from a tagged failure (null-propagating). */
function failureMessage(
  failure: { readonly variableId: string; readonly message: string } | null,
): string | null {
  return failure === null ? null : failure.message;
}

/**
 * Only a push failure corroborated by the end-of-pass reality becomes a
 * cause candidate. Listing a failure whose **variable resolved itself**
 * (like a concurrent deletion's 404) as the cause hides the real cause of
 * another variable that is actually still unfinished (a conflict, etc.).
 */
function pendingFailure(
  failure: { readonly variableId: string; readonly message: string } | null,
  staleIds: ReadonlySet<string>,
): string | null {
  if (failure === null) {
    return null;
  }
  return staleIds.has(failure.variableId) ? failure.message : null;
}

/**
 * The priority of an incompleteness cause: a push failure > unopenable
 * values > a conflict (the default wording = null). Folding an unopenable
 * value into "conflict" would send the user chasing a nonexistent
 * concurrent writer — what is actually needed is "a re-run by another
 * member who holds that epoch's wrap".
 */
function blockingCause(
  pushFailure: string | null,
  undecryptable: readonly string[],
): string | null {
  return pushFailure ?? undecryptable[0] ?? null;
}

/**
 * Closing a run that ended incomplete. When there is a cause
 * (blockingFailure) it is reported and nothing happens here; only without
 * one, the "failure that happened but is no longer the cause" is left as
 * a warning.
 */
function noteStaleFailures(
  warnings: string[],
  blockingFailure: string | null,
  seenFailure: string | null,
): void {
  if (blockingFailure !== null) {
    return;
  }
  // No failure on the last pass = what remains is the conflicts. Past failures are not the cause
  noteResolvedFailure(
    warnings,
    seenFailure,
    "they resolved in later passes (what remains incomplete is the conflicted portion)",
  );
}

/**
 * Whether the state is "unfinished work remains yet nothing can be
 * pushed" (= only undecryptable values are left). Cycling the remaining
 * passes would just repeat pulls without progress. The final pass's
 * targets is always empty since it "does not decrypt" — the judgment
 * looks only at passes that attempted decryption.
 */
function stalledOnUndecryptable(pending: readonly ReencryptTarget[], pass: number): boolean {
  return pending.length === 0 && pass < MAX_REENCRYPT_PASSES;
}

/**
 * The warning text of undecryptable values. **Pinned to one place**: when
 * the same variable is warned with slightly different wording per path,
 * dedupeWarnings (a set) would pass them as distinct — the mechanism put
 * in for dedup would itself emit the duplicates.
 */
function undecryptableWarning(reason: string): string {
  return `Some values cannot be re-encrypted (${reason}). These variables remain under old-epoch DEKs — a member holding wraps for those epochs must re-run this`;
}

/** The decryption result. Unopened values come back as "undecryptable values" with a count and a reason. */
interface DecryptOutcome {
  readonly targets: readonly ReencryptTarget[];
  /**
   * The reason of a value that could not be opened because **no wrap of
   * that epoch is addressed to me**. This is a benign absence (another
   * member can open it), so one item never drops the whole run — a
   * rotation is a revocation operation, and leaving 99 openable values on
   * the old DEK because 1 cannot be opened gives up the range that could
   * be protected. **A value that cannot be opened despite holding the
   * wrap never enters here** (a possible ciphertext substitution or
   * inconsistency with the verified view — an immediate abort, same as
   * pull / run).
   */
  readonly undecryptable: readonly string[];
}

/** Decrypting the verified latest values (the re-encryption material). The decryption discipline is shared with pull. */
function decryptTargets(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly values: readonly VerifiedPulledValue[];
  readonly deksByEpoch: ReadonlyMap<number, Redacted.Redacted<Uint8Array>>;
  readonly chainEpoch: number;
}): Effect.Effect<DecryptOutcome, CliError> {
  return Effect.gen(function* () {
    const targets: ReencryptTarget[] = [];
    const undecryptable: string[] = [];
    for (const value of input.values) {
      // Only a benign absence (no wrap addressed to me) is skipped as an
      // "unopenable value". A decryption failure despite holding the wrap
      // is an AEAD authentication failure (a ciphertext substitution) or
      // an inconsistency with the verified view, and aborts immediately
      // like pull / run — collapsing it into "waiting on another member's
      // re-run" would report a substitution's sign as a benign operational
      // wait and guide toward stepping over it with --new-epoch
      //
      // "Benign" is judged only for an absence **at or below the
      // chain-derived current epoch**: for a value with a claimed epoch
      // beyond the current epoch, not holding that epoch's wrap is the
      // expected state (deks.ts refuses an over-the-cap wrap), so letting
      // it slip through this check would disguise an inconsistency with
      // the verified view as "waiting on another member". An over-the-cap
      // epoch makes decryptVerifiedValue abort immediately with the same
      // wording as pull / run (§6.3-4's epoch-not-current-at-head is the
      // main line; this is a defense line against a derivation
      // inconsistency)
      if (value.epoch <= input.chainEpoch && !input.deksByEpoch.has(value.epoch)) {
        undecryptable.push(missingWrapReason(value));
        continue;
      }
      const plaintext = yield* decryptVerifiedValue({
        verified: input.verified,
        environmentId: input.environmentId,
        variable: value,
        deksByEpoch: input.deksByEpoch,
        chainEpoch: input.chainEpoch,
      });
      targets.push({ value, plaintext });
    }
    return { targets, undecryptable };
  });
}

/** The result of one variable's re-encryption push (a conflict carries back the 409's claimed version). */
type PushAttempt =
  /**
   * Accepted. Accompanied by a warning only when the floor update failed
   * (the acceptance itself cannot be taken back). `written` is **my
   * accepted write** and becomes the consistency-check baseline of later
   * rescans (the floor is a SHOULD and its write can fail, so a rollback
   * use of one's own writes never relies on the floor alone).
   */
  | {
      readonly kind: "pushed";
      readonly floorWarning: string | null;
      readonly written: VerifiedPulledValue;
    }
  | { readonly kind: "conflict"; readonly currentVersion: number }
  /** A concurrent deletion (404). A deleted variable has no current value to re-encrypt. */
  | { readonly kind: "deleted" }
  /**
   * The server claimed an epoch conflict (409 EpochConflict). The cause
   * is not decided here — left to the rescan (a chain re-verification):
   * whether "another member rotated concurrently" or "the server's claim
   * contradicts the chain" is indistinguishable until the chain-derived
   * current epoch is observed (same discipline as push.ts's
   * epoch-conflict).
   */
  | { readonly kind: "epoch-stale" };

/**
 * The push of one variable's re-encryption (§7 / §4.1 — a re-encryption
 * is "an ordinary push signed by the performer as writer" and carries no
 * dedicated wire or authorization).
 */
function pushReencrypted(input: {
  readonly context: ReencryptContext;
  readonly view: VerifiedProject;
  readonly target: ReencryptTarget;
}): Effect.Effect<PushAttempt, CliError> {
  return Effect.gen(function* () {
    const { environmentId, epoch, dek, writerUserId, signingKey, floor, client } = input.context;
    const latest = input.target.value;
    const version = latest.version + 1;
    // The prev is the **self-computed** hash of the verified latest value
    // (never chain-sign onto the server-claimed hash — avoiding the
    // evidence-chain contamination of §12-5)
    const signed = yield* encryptAndSignPayload({
      verified: input.view,
      environmentId: environmentId,
      variableId: latest.variableId,
      epoch: epoch,
      version,
      prevValueSigHashHex: latest.signedBytesHashHex,
      dek: dek,
      value: input.target.plaintext,
      writerUserId: writerUserId,
      signingKey: signingKey,
    });
    const outcome = yield* client.variables
      .push({
        params: {
          projectId: input.view.projectId,
          environmentId: environmentId,
          variableId: latest.variableId,
        },
        // reencryption = the re-encryption marker (AUTH_SPEC §12-5 —
        // SHOULD): this push is a new-epoch re-encryption of the same
        // plaintext and must never count as clearing the needs-rotation
        // flag (an upstream credential update — AUDIT_SPEC §4.1-5)
        payload: { value: signed.payload, reencryption: true },
      })
      .pipe(
        Effect.map(() => ({ kind: "pushed" }) as const),
        Effect.catch((error): Effect.Effect<PushAttempt, CliError> => {
          if (error instanceof VersionConflictError) {
            // There is a concurrent push's winner. Never decide on the
            // 409's claimed value — the caller re-fetches and re-verifies
            // the reality (whether the winner is already at the current
            // epoch)
            return Effect.succeed({ kind: "conflict", currentVersion: error.currentVersion });
          }
          if (error instanceof VariableNotFoundError) {
            // A concurrent deletion. A deletion is a tombstone + the
            // deletion of all versions (§12-5), so there is no current
            // value to re-encrypt — aligned with the rescan side's
            // handling of the same race (warn and drop from the targets);
            // the remaining variables' processing is not stopped
            return Effect.succeed({ kind: "deleted" });
          }
          if (error instanceof EpochConflictError) {
            // Never make the claim the source of truth: the chain re-verification happens in the rescan
            return Effect.succeed({ kind: "epoch-stale" });
          }
          return Effect.fail(toCliError(error));
        }),
      );
    if (outcome.kind !== "pushed") {
      return outcome;
    }
    // Promoting my accepted write into the floor (§6.3). Since the meta
    // did not change, the floor's meta record stays the verified latest.
    // Rule (c)'s baseline does not move. Never let a floor write failure
    // turn an "accepted re-encryption" into unfinished: the acceptance
    // cannot be taken back and this variable already lives at the new
    // epoch. The lost (SHOULD) detection material is conveyed as a
    // warning, and the remaining variables' processing is not stopped
    const floorWarning = yield* floor
      .commitPush(
        latest.variableId,
        {
          status: "active",
          version,
          epoch: epoch,
          valueSigHashHex: signed.signedBytesHashHex,
          metaVersion: latest.metaVersion,
          metaSigHashHex: latest.metaSignedBytesHashHex,
        },
        { seq: input.view.state.headSeq, hashHex: input.view.state.headHashHex },
      )
      .pipe(
        Effect.as(null),
        Effect.catch((error) =>
          Effect.succeed(
            `Re-encryption of variable ${displayText(latest.name)} was accepted, but ${error.message} (some rollback-detection material for this variable is missing)`,
          ),
        ),
      );
    // My accepted write (assembled from the signed subject itself — not a server echo)
    const written: VerifiedPulledValue = {
      ...latest,
      version,
      epoch,
      nonceHex: signed.payload.nonceHex,
      ciphertextHex: signed.payload.ciphertextHex,
      prevValueSigHashHex: latest.signedBytesHashHex,
      signedBytesHashHex: signed.signedBytesHashHex,
      valueChainHeadSeq: input.view.state.headSeq,
      valueChainHeadHashHex: input.view.state.headHashHex,
      valueSignatureHex: signed.payload.signatureHex,
      writerUserId,
      writerKeyFingerprintHex: input.context.writerKeyFingerprintHex,
    };
    return { kind: "pushed", floorWarning, written };
  });
}

/**
 * Matching known values against re-fetched ones. Against the values that
 * passed §6.3 verification in this run (the basis of the next pass's prev
 * anchors), it checks for rollbacks, equivocations, forked prev chains,
 * and disagreements with the 409 claims (the same winnerInconsistency as
 * the push path), and warns of variables that vanished while still
 * unfinished as concurrent deletions.
 *
 * The consistency check runs before the "adopt it or not" question
 * regardless: evidence is itself a fact worth aborting on and must not
 * hide behind the "no re-encryption needed" shortcut.
 */
function reconcileKnown(input: {
  readonly known: ReadonlyMap<string, ConflictedTarget>;
  /**
   * The variables that could not finish re-encrypting this pass (409,
   * transient failure, 404, epoch conflict). The vanishing warning and the
   * "another member already wrote it at the current epoch" accounting are
   * based on this set, not just 409s — otherwise a variable that fell to a
   * 502 would be counted in none of re-encrypted / already-current /
   * unfinished, and the totals would not add up.
   */
  readonly unfinishedIds: ReadonlySet<string>;
  readonly latest: readonly VerifiedPulledValue[];
  readonly epoch: number;
  readonly collectWarning: (warning: string) => void;
}): { readonly evidence: string | null; readonly alreadyCurrent: number } {
  const latestById = new Map(input.latest.map((value) => [value.variableId, value]));
  let alreadyCurrent = 0;
  for (const [variableId, previous] of input.known) {
    const latest = latestById.get(variableId);
    if (latest === undefined) {
      if (input.unfinishedIds.has(variableId)) {
        // Vanished while unfinished = a concurrent deletion. Never silently dropped from the targets
        input.collectWarning(
          `Variable ${displayText(previous.known.name)} is no longer in the re-fetched active set (concurrently deleted by another member). Removing it from the re-encryption targets`,
        );
      }
      continue;
    }
    const inconsistency = winnerInconsistency(
      variableId,
      previous.known,
      latest,
      previous.currentVersion,
    );
    if (inconsistency !== null) {
      return { evidence: inconsistency, alreadyCurrent: 0 };
    }
    if (input.unfinishedIds.has(variableId) && latest.epoch >= input.epoch) {
      alreadyCurrent += 1;
    }
  }
  return { evidence: null, alreadyCurrent };
}

/** The result of re-fetch + re-verify (doubles as the completion check and the re-plan of 409 conflicts). */
interface RescanResult {
  readonly view: VerifiedProject;
  /**
   * The active values still below the target epoch. **This side is
   * correct for the completion judgment and the remaining count**
   * (targets becomes empty on the final pass).
   */
  readonly stale: readonly VerifiedPulledValue[];
  /**
   * The re-encryption material from decrypting stale (= the next pass's
   * targets). **Empty on the final pass**: decrypting when no next pass
   * exists would build one unusable plaintext per variable in memory.
   */
  readonly targets: readonly ReencryptTarget[];
  /**
   * The reasons of the values that could not be opened. Even on the
   * final pass (no decryption) the presence of a wrap addressed to me is
   * still judged, so "only unopenable values remain" can always be
   * reported as a cause.
   */
  readonly undecryptable: readonly string[];
  /** The number of variables that had conflicts but were already written at the current epoch (no re-encryption needed). */
  readonly alreadyCurrent: number;
  /**
   * Cryptographic evidence (a rollback, equivocation, forked prev chain).
   * Non-null is an immediate abort — never mix it with the "a re-run
   * resolves it" kind of failure.
   */
  readonly evidence: string | null;
}

/**
 * Re-fetch + re-verify of the environment (§6.3). Two roles, one path:
 * 1. **The completion check**: confirm no active value below the target
 *    epoch remains. A variable another member created in the window
 *    between the first pull and the composite's acceptance was never in
 *    the initial target set (a post-acceptance create is only accepted at
 *    the current epoch — §12-5) and becomes visible for the first time in
 *    this rescan. Skipping it produces the shape "the epoch advanced and
 *    values still on the old DEK remain, yet completion was reported"
 * 2. **Re-planning 409 conflicts** (§12-5's retry procedure): verify the
 *    winner under §6.3, and apply **the winner's consistency check
 *    (winnerRegression, shared with push.ts) before the adopt/reject
 *    decision**. Re-encryption re-anchors the prev onto the winner's
 *    signed-bytes hash and signs, so without the check one's own
 *    signature would chain onto a forked history (§12-5's evidence-chain
 *    contamination). The local floor catches rollbacks and same-version
 *    differences but is a SHOULD (absent on first sync / after
 *    corruption), and for an adjacent-prev mismatch the floor has no
 *    material at all
 */
function rescanEnvironment(input: {
  readonly context: ReencryptContext;
  readonly view: VerifiedProject;
  /**
   * The values that passed §6.3 verification at least once in this run
   * (variableId → known value + 409-claimed version). **Not limited to
   * variables that got a 409**: a variable recovered by the rescan after a
   * transient failure also becomes the next pass's prev anchor, so it
   * passes the same consistency check.
   */
  readonly known: ReadonlyMap<string, ConflictedTarget>;
  /**
   * The variables that could **not finish** re-encrypting this pass (409,
   * transient failure, 404, epoch conflict). If these vanished from the
   * active set they are warned as concurrent deletions — "finished" is
   * only for the ones *seen* to vanish; never dropped silently.
   */
  readonly unfinishedIds: ReadonlySet<string>;
  /**
   * The warnings' receptacle. To keep already-collected warnings (non-NFC
   * names, concurrent deletions) even on failure, they flow in here
   * instead of the return value (the error channel cannot carry
   * warnings).
   */
  readonly collectWarning: (warning: string) => void;
  /**
   * A forced resync of the chain. On a pass where the server claimed an
   * epoch conflict, **always** re-fetch the chain and re-derive the
   * current epoch without depending on pull's future-head condition
   * (without the re-fetch, another member's concurrent rotation would be
   * mistaken for "a server contradiction" — same discipline as push.ts's
   * epoch-conflict).
   */
  readonly forceResync: boolean;
  /**
   * Whether to decrypt the remaining targets. true only when a next pass
   * exists — the final pass only counts what remains, so no unusable
   * plaintext is built (decryption only right before use).
   */
  readonly decryptRemaining: boolean;
}): Effect.Effect<RescanResult, CliError> {
  return Effect.gen(function* () {
    const { client, environmentId, resync, floor, epoch, deksByEpoch } = input.context;
    const base = input.forceResync ? yield* resyncExtended(resync, input.view) : input.view;
    const pulled = yield* pullVerifiedEnvironment({
      client,
      verified: base,
      environmentId,
      resync,
      floor,
    });
    const view = pulled.verified;
    // Warnings flow **before any judgment**: even on a pass aborted by a
    // concurrent rotation, the SHOULD warnings this pull collected must
    // not be lost (the sink's discipline)
    for (const warning of pulled.warnings) {
      input.collectWarning(warning);
    }
    const environment = yield* requireChainEnvironment(view, environmentId);
    if (environment.currentEpoch !== epoch) {
      return yield* Effect.fail(
        cliError(
          `Environment ${environmentId}'s epoch advanced from ${epoch} to ${environment.currentEpoch} during re-encryption (a concurrent rotation by another member)`,
        ),
      );
    }
    const reconciled = reconcileKnown({
      known: input.known,
      unfinishedIds: input.unfinishedIds,
      latest: pulled.variables,
      epoch,
      collectWarning: input.collectWarning,
    });
    if (reconciled.evidence !== null) {
      return {
        view,
        stale: [],
        targets: [],
        undecryptable: [],
        alreadyCurrent: 0,
        evidence: reconciled.evidence,
      };
    }
    // The completion check + the next pass's targets: every active value
    // below the target epoch (not limited to the conflicts — a variable
    // created in the window also appears here)
    const stale = pulled.variables.filter((value) => value.epoch < epoch);
    if (!input.decryptRemaining) {
      // No decryption, but "can it be opened" is still judged: the
      // presence of a wrap addressed to me is known from a Map lookup and
      // builds no plaintext. Skipping it would disguise as the default
      // wording (conflict) the cause of a state that only surfaces on the
      // final pass — "only unopenable values remain"
      const missing = stale.filter((value) => !deksByEpoch.has(value.epoch)).map(missingWrapReason);
      // Like the passes that attempt decryption, per-variable warnings
      // are emitted too (with only the as-cause report, which variables
      // were stranded is invisible on a pass where a push failure took
      // priority)
      for (const reason of missing) {
        input.collectWarning(undecryptableWarning(reason));
      }
      return {
        view,
        stale,
        targets: [],
        undecryptable: missing,
        alreadyCurrent: reconciled.alreadyCurrent,
        evidence: null,
      };
    }
    // A missing wrap addressed to me (benign) never fails the rescan
    // itself: the completion judgment was made by the pre-decryption
    // stale, and dropping here would turn **even the pushable share** into
    // "completion could not be verified". On the other hand, a value that
    // cannot be opened despite holding the wrap (substitution / view
    // inconsistency) is treated as **evidence** — it was an
    // immediate-abort condition on the first pull, so it must not be
    // downgraded to "a re-run-fixable partial completion" just because it
    // surfaced mid-pass
    const attempted = yield* asOutcome(
      decryptTargets({
        verified: view,
        environmentId,
        values: stale,
        deksByEpoch,
        chainEpoch: environment.currentEpoch,
      }),
    );
    if (attempted.kind === "failed") {
      return {
        view,
        stale,
        targets: [],
        undecryptable: [],
        alreadyCurrent: 0,
        evidence: attempted.error.message,
      };
    }
    const decrypted = attempted.value;
    for (const reason of decrypted.undecryptable) {
      input.collectWarning(undecryptableWarning(reason));
    }
    return {
      view,
      stale,
      targets: decrypted.targets,
      undecryptable: decrypted.undecryptable,
      alreadyCurrent: reconciled.alreadyCurrent,
      evidence: null,
    };
  });
}

/**
 * Re-encrypting the current values (§7): encrypt each target with the
 * target epoch's DEK and push it as an ordinary push, and **at the end of
 * every pass, rescan the environment and verify the completion** (up to
 * {@link MAX_REENCRYPT_PASSES} passes). The rescan doubles as confirming
 * the conflicts' reality (a winner already at the current epoch needs no
 * re-encryption) and discovering variables created after the first pull.
 * "Finished pushing every target" is not evidence of completion —
 * completion's evidence is "the re-fetched, re-verified view carries no
 * active value below the target epoch".
 *
 * Failures are never thrown — they come back as {@link
 * ReencryptOutcome.failure}: by the time this function runs the epoch has
 * already advanced, and throwing a mid-run failure (network, a concurrent
 * rotation, a floor write) as an exception would let the fact "only the
 * epoch advanced and re-encryption remains" slip past the
 * partial-completion reporting path. The exception is **cryptographic
 * evidence (RescanResult.evidence)** alone, which is an immediate abort
 * (the error channel) — it is not the "a re-run fixes it" kind of
 * failure, so it must not blend into partial-completion + resume guidance
 * (aligned with the push path's handling).
 */
/**
 * The context the 3 re-encryption functions share (one variable's push,
 * one pass's push, the end-of-pass rescan). Only the view and the targets
 * change per pass, so the invariants are bundled into one (avoids the
 * same long argument list being duplicated per call site).
 */
interface ReencryptContext {
  readonly client: MaruhiClient;
  readonly environmentId: EnvironmentId;
  readonly floor: FloorHandle;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** The re-encryption's target epoch (the post-rotation new epoch / the current epoch on a resume). */
  readonly epoch: number;
  readonly dek: Redacted.Redacted<Uint8Array>;
  readonly deksByEpoch: ReadonlyMap<number, Redacted.Redacted<Uint8Array>>;
  readonly writerUserId: string;
  /** My key FP (the attribution when recording my accepted writes into the ledger). */
  readonly writerKeyFingerprintHex: string;
  readonly signingKey: CryptoKey;
}

/**
 * Failures are carried back as a value, never thrown. A post-advance
 * failure must ride the "partial completion" reporting path — escaping as
 * an exception would lose the operational state.
 */
function asOutcome<A, R>(
  effect: Effect.Effect<A, CliError, R>,
): Effect.Effect<
  | { readonly kind: "ok"; readonly value: A }
  | { readonly kind: "failed"; readonly error: CliError },
  never,
  R
> {
  return effect.pipe(
    Effect.map((value) => ({ kind: "ok", value }) as const),
    Effect.catch((error) => Effect.succeed({ kind: "failed", error } as const)),
  );
}

/** Builds the re-encryption context from a RotateInput + epoch-specific material. */
function reencryptContext(
  input: RotateInput,
  /** The writer's signing device (the device holding this machine's key — device-key.ts). */
  writerDevice: ChainDevice,
  epochMaterial: {
    readonly epoch: number;
    readonly dek: Redacted.Redacted<Uint8Array>;
    readonly deksByEpoch: ReadonlyMap<number, Redacted.Redacted<Uint8Array>>;
  },
): ReencryptContext {
  return {
    client: input.client,
    environmentId: input.environmentId,
    floor: input.floor,
    resync: input.resync,
    writerUserId: input.signerUserId,
    writerKeyFingerprintHex: writerDevice.keyFingerprintHex,
    signingKey: input.signingKeyPair.privateKey,
    ...epochMaterial,
  };
}

/** The result of one pass's pushes. */
interface PushPassResult {
  readonly reencrypted: number;
  readonly conflicted: readonly ConflictedTarget[];
  /**
   * The variables the server claimed an epoch conflict on (the rescan
   * does the matching against the chain). **Held as ids, not a count**:
   * "the claim contradicts the chain" may be asserted only when the very
   * claimed variable still remains on the rescan (if other variables
   * remain for other reasons, the run should be guided as an ordinary
   * partial completion).
   */
  readonly epochStaleIds: ReadonlySet<string>;
  /** The variables that could not finish re-encrypting (409, transient failure, epoch conflict). */
  readonly unfinishedIds: ReadonlySet<string>;
  /** My accepted writes (the ledger's new baseline). */
  readonly written: readonly VerifiedPulledValue[];
  /**
   * The first cause that failed individually (the pass itself doesn't
   * stop. The count lives in unfinishedIds). **Which variable failed** is
   * also kept: when the end-of-pass rescan finds that variable resolved
   * (like a concurrent deletion's 404), listing it as the incompleteness
   * cause would hide another variable's real cause, so the caller can
   * drop it by matching against reality.
   */
  readonly firstFailure: { readonly variableId: string; readonly message: string } | null;
  readonly warnings: readonly string[];
}

/**
 * One pass of re-encryption pushes. Conflicts (409) go to the next
 * rescan; concurrent deletions (404) are warned and skipped.
 *
 * **An individual failure never aborts the pass**: abandoning the rest on
 * one variable's transient failure (a 502, etc.) would leave 97 of 100
 * variables readable under the old epoch's DEK when it falls on the 3rd.
 * And with one permanently-failing variable, the stable ordering would
 * make every later variable unreachable **on every re-run**. Failures are
 * aggregated as a count and a cause; the actual remainder is decided by
 * the end-of-pass rescan (the verified reality).
 */
function runPushPass(input: {
  readonly context: ReencryptContext;
  readonly view: VerifiedProject;
  readonly pending: readonly ReencryptTarget[];
  /** The starting number of the progress display's running count (the number re-encrypted so far). */
  readonly doneBefore: number;
}): Effect.Effect<PushPassResult, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const conflicted: ConflictedTarget[] = [];
    const written: VerifiedPulledValue[] = [];
    const unfinishedIds = new Set<string>();
    const warnings: string[] = [];
    // The progress display's denominator is "the total known on this pass" (a rescan can grow the targets)
    const total = input.doneBefore + input.pending.length;
    let reencrypted = 0;
    const epochStaleIds = new Set<string>();
    let firstFailure: { readonly variableId: string; readonly message: string } | null = null;
    for (const target of input.pending) {
      const attempt = yield* asOutcome(
        pushReencrypted({ context: input.context, view: input.view, target }),
      );
      if (attempt.kind === "failed") {
        // The pass does not stop (never strand the remaining variables on
        // the old epoch). **Every variable's failure mode is kept**: only
        // one can be listed as the cause, so without a warning, a
        // permanently-failing variable (a too-large value, etc.) would
        // never surface its reason on any run and stay stranded on the old
        // epoch forever
        const message = `Failed to re-encrypt variable ${displayText(target.value.name)}: ${attempt.error.message}`;
        warnings.push(message);
        firstFailure ??= { variableId: target.value.variableId, message };
        unfinishedIds.add(target.value.variableId);
        continue;
      }
      if (attempt.value.kind === "conflict") {
        conflicted.push({
          variableId: target.value.variableId,
          known: target.value,
          currentVersion: attempt.value.currentVersion,
        });
        unfinishedIds.add(target.value.variableId);
        continue;
      }
      if (attempt.value.kind === "deleted") {
        warnings.push(
          `Re-encryption of variable ${displayText(target.value.name)} was rejected with 404 (possibly deleted concurrently by another member). If it is gone from the re-fetched active set it is dropped from the targets; if it is still being served it is counted as incomplete`,
        );
        firstFailure ??= {
          variableId: target.value.variableId,
          message: `Re-encryption of variable ${displayText(target.value.name)} was rejected with 404 (possible concurrent deletion)`,
        };
        unfinishedIds.add(target.value.variableId);
        continue;
      }
      if (attempt.value.kind === "epoch-stale") {
        // The rescan judges reality by the chain-derived epoch. This
        // variable stays at the old epoch, so if the epoch did not move it
        // appears again as the next pass's target
        epochStaleIds.add(target.value.variableId);
        unfinishedIds.add(target.value.variableId);
        continue;
      }
      if (attempt.value.floorWarning !== null) {
        warnings.push(attempt.value.floorWarning);
      }
      // Promoting my accepted write into the ledger's baseline: lets later
      // rescans detect a rollback of my own writes (regression)
      written.push(attempt.value.written);
      reencrypted += 1;
      yield* io.log(
        `  Re-encrypted (${input.doneBefore + reencrypted}/${total}): ${displayText(target.value.name)} (version=${target.value.version + 1})`,
      );
    }
    return {
      reencrypted,
      conflicted,
      epochStaleIds,
      unfinishedIds,
      written,
      firstFailure,
      warnings,
    };
  });
}

/**
 * Recording into the known-values ledger a value that passed §6.3
 * verification. There are two entries but one record shape:
 * - **this pass's targets**: kept as the consistency-check baseline
 *   (§12-5) because they can become the next pass's prev anchor — not
 *   limited to the ones that got a 409
 * - **my accepted writes**: even when the floor (SHOULD) update fails, the
 *   next rescan can compare against "the version I wrote" — detecting a
 *   response that rolls back an accepted write as a rollback regardless
 *   of the floor's presence
 * Both are "a value and its version that I verified as correct"; a split
 * record shape would weaken one side's §12-5 check, so they are unified
 * (only recordConflicts, which carries the 409's claimed version, is
 * different).
 */
function recordKnown(
  known: Map<string, ConflictedTarget>,
  values: readonly VerifiedPulledValue[],
): void {
  for (const value of values) {
    known.set(value.variableId, {
      variableId: value.variableId,
      known: value,
      currentVersion: value.version,
    });
  }
}

/**
 * Overwriting the ledger at the 409's claimed version. No separate
 * conflict "set" is kept — the vanishing warning and the alreadyCurrent
 * accounting are based on the unfinished set (not limited to 409s), and
 * carrying a 409-only set around reads as "still used by some judgment".
 */
function recordConflicts(
  known: Map<string, ConflictedTarget>,
  conflicted: readonly ConflictedTarget[],
): void {
  for (const conflict of conflicted) {
    known.set(conflict.variableId, conflict);
  }
}

/** The end-of-pass judgment (what to do with the completion check's result). */
type PassVerdict =
  /** Can continue (0 remaining = done). */
  | {
      readonly kind: "settled";
      readonly view: VerifiedProject;
      /** The number of variables still below the target epoch (the correct source of the completion judgment and the remaining count). */
      readonly remaining: number;
      /** The next pass's targets (empty on the final pass — no decryption even when remaining > 0). */
      readonly targets: readonly ReencryptTarget[];
      /** The reasons of the unopened values (reported as the incompleteness cause). */
      readonly undecryptable: readonly string[];
      /** The ids of variables still below the target epoch (used to pick the cause). */
      readonly staleIds: ReadonlySet<string>;
      readonly alreadyCurrent: number;
    }
  /**
   * Completion could not be verified. `remaining` is "the number not
   * completed this pass", not a measurement — neither an upper nor a
   * lower bound (over-counted when another member's hand resolved the
   * conflicts, under-counted since a variable created mid-run isn't in
   * the count). The display side labels it "includes unverified"
   * (remainingExact = false).
   */
  | { readonly kind: "unverified"; readonly remaining: number; readonly failure: string }
  /** An abort no re-run resolves (cryptographic evidence, a server–chain contradiction). */
  | { readonly kind: "abort"; readonly message: string };

/**
 * The end-of-pass completion check and judgment. From the rescan's result
 * (always done regardless of conflicts / failures), one of continue /
 * done / unverified / abort is decided. The judgment priority is
 * "evidence > contradiction > continue" — evidence is resolved by no
 * re-run, so it is never folded into another reason.
 */
function settlePass(input: {
  readonly context: ReencryptContext;
  readonly view: VerifiedProject;
  readonly known: ReadonlyMap<string, ConflictedTarget>;
  readonly pass: PushPassResult;
  readonly reencrypted: number;
  /** Whether a next pass exists (= whether decrypting the remaining targets has a point). */
  readonly hasNextPass: boolean;
}): Effect.Effect<
  { readonly verdict: PassVerdict; readonly warnings: readonly string[] },
  never,
  never
> {
  return Effect.gen(function* () {
    const { environmentId, epoch } = input.context;
    // The collected warnings are not lost even when the rescan fails (the error channel cannot carry them)
    const warnings: string[] = [];
    const rescan = yield* asOutcome(
      rescanEnvironment({
        context: input.context,
        view: input.view,
        known: input.known,
        unfinishedIds: input.pass.unfinishedIds,
        collectWarning: (warning) => warnings.push(warning),
        // A pass where an epoch conflict was claimed re-fetches the chain before judging
        forceResync: input.pass.epochStaleIds.size > 0,
        decryptRemaining: input.hasNextPass,
      }),
    );
    const context = `Environment ${environmentId} has advanced to epoch ${epoch}, and re-encryption stopped after ${countNoun(input.reencrypted, "variable")}`;
    if (rescan.kind === "failed") {
      if (rescan.error.evidence === true) {
        // The rescan's pull was refused with evidence (a floor violation,
        // checkpoint-integrity rule 2). An immediate abort, same as the
        // decryption stage's evidence (rescan.value.evidence) — never
        // downgraded to "a re-run-fixable partial completion"
        return {
          warnings,
          verdict: {
            kind: "abort",
            message: `${rescan.error.message}\n${context}. This is evidence that re-running will not resolve — investigate the server's responses`,
          },
        } as const;
      }
      // **The rescan's failure takes priority**: a concurrent rotation's
      // detection and transient failures surface here, so they must not be
      // covered up by a single variable's transient failure (that would
      // disguise it as "a re-run fixes it" guidance)
      const pushFailure =
        input.pass.firstFailure === null
          ? ""
          : ` (there were also failures during re-encryption: ${input.pass.firstFailure.message})`;
      return {
        warnings,
        verdict: {
          kind: "unverified",
          remaining: input.pass.unfinishedIds.size,
          failure: `${rescan.error.message}${pushFailure}`,
        },
      } as const;
    }
    if (rescan.value.evidence !== null) {
      // Cryptographic evidence is the top-priority immediate abort (no
      // re-run resolves it). The epoch-advanced context is conveyed
      // together — emitting only the evidence would lose the operational
      // state
      return {
        warnings,
        verdict: {
          kind: "abort",
          message: `${rescan.value.evidence}\n${context}. This is evidence that re-running will not resolve — investigate the server's responses`,
        },
      } as const;
    }
    if (input.pass.epochStaleIds.size > 0) {
      // Even on the force-resynced chain the epoch did not move (if it
      // had, rescanEnvironment would have failed). The server's
      // EpochConflict claim contradicts the chain, and re-pushing that
      // variable cannot resolve it (same judgment as push.ts). But an
      // abort is allowed **only when the very claimed variable still
      // remains**: if it resolved — say another member finished writing it
      // at the same epoch — the rest remains for other reasons (a
      // transient failure, a conflict) and a re-run cleans up. Declaring
      // "a re-run won't resolve this" would keep both the resume guidance
      // and the remaining-count report from arriving. Whether
      // re-encryption is complete is decided by the verified reality, not
      // the server's self-claim. The judgment uses stale (always
      // populated) — targets is empty on the final pass
      const unresolved = rescan.value.stale.filter((value) =>
        input.pass.epochStaleIds.has(value.variableId),
      );
      if (unresolved.length > 0) {
        return {
          warnings,
          verdict: {
            kind: "abort",
            message: `The server reported an epoch conflict, but the chain is still at epoch ${epoch} (the server's response contradicts the chain). ${context} — re-running will not resolve this`,
          },
        } as const;
      }
      warnings.push(
        `The server reported an epoch conflict for a re-encryption push, but the chain was still at epoch ${epoch} (the server's response contradicts the chain). The reported variable is not in the rescanned incomplete set (it was rewritten at the current epoch, or deleted), so processing continues — but the contradictory response itself warrants investigation`,
      );
    }
    return {
      warnings,
      verdict: {
        kind: "settled",
        view: rescan.value.view,
        remaining: rescan.value.stale.length,
        targets: rescan.value.targets,
        undecryptable: rescan.value.undecryptable,
        staleIds: new Set(rescan.value.stale.map((value) => value.variableId)),
        alreadyCurrent: rescan.value.alreadyCurrent,
      },
    } as const;
  });
}

/**
 * The record of "a failure that happened but is no longer the cause".
 * Listing it as the cause misleads the investigation, but silently
 * dropping it erases the very fact that a 502 happened — it stays as a
 * warning with how it resolved.
 */
function noteResolvedFailure(warnings: string[], failure: string | null, resolution: string): void {
  if (failure !== null) {
    warnings.push(`There were failures during re-encryption, but ${resolution}: ${failure}`);
  }
}

function reencryptCurrentValues(input: {
  readonly context: ReencryptContext;
  readonly view: VerifiedProject;
  readonly targets: readonly ReencryptTarget[];
  /**
   * The warnings' receptacle (an array shared with the caller). Since an
   * abort escapes as an exception, returning them would lose the warnings
   * **only on failure** — an abort is exactly where a floor-update failure
   * or a concurrent-deletion notice matters most, so the destination is
   * shared and never lost.
   */
  readonly sink: string[];
}): Effect.Effect<ReencryptOutcome, CliError, CliIo> {
  return Effect.gen(function* () {
    const warnings = input.sink;
    let view = input.view;
    let pending = input.targets;
    let reencrypted = 0;
    let alreadyCurrent = 0;
    /**
     * The failures that actually happened **on the latest pass** (= what
     * is blocking the completion now). Never carried across passes: if a
     * pass-1 transient failure resolved on pass 2, it is no longer the
     * cause. Carrying it would display a resolved failure while hiding
     * the real cause (an unresolvable 409 = "a conflict with a concurrent
     * push"), misdirecting the investigation toward verification failures
     * and floor violations.
     */
    let blockingFailure: string | null = null;
    /** Every failure that happened this run (for the "happened but resolved" report when it completes). */
    let seenFailure: string | null = null;
    /**
     * The number of variables still below the target epoch. **Fixed by
     * each pass's rescan**, so no initial value is held here (no path
     * reads it as 0 — it is read only after at least one pass ran).
     * Initializing it with the target count would dress an unreportable
     * number as "the default remaining count".
     */
    let staleCount = 0;
    /** The values that passed §6.3 verification this run (the baseline of the next pass's prev-anchor consistency check). */
    const known = new Map<string, ConflictedTarget>();
    /** My accepted writes (aggregated across passes — the receipt-advance material). */
    const written: ReencryptedVariable[] = [];

    const outcome = (
      remaining: number,
      failure: string | null,
      remainingExact: boolean,
    ): ReencryptOutcome => ({
      reencrypted,
      alreadyCurrent,
      remaining,
      remainingExact,
      failure,
      written,
    });

    for (let pass = 1; pass <= MAX_REENCRYPT_PASSES; pass += 1) {
      recordKnown(
        known,
        pending.map((target) => target.value),
      );
      const attempted = yield* runPushPass({
        context: input.context,
        view,
        pending,
        doneBefore: reencrypted,
      });
      reencrypted += attempted.reencrypted;
      warnings.push(...attempted.warnings);
      written.push(
        ...attempted.written.map((value) => ({ name: value.name, version: value.version })),
      );
      recordKnown(known, attempted.written);
      recordConflicts(known, attempted.conflicted);
      const settled = yield* settlePass({
        context: input.context,
        view,
        known,
        pass: attempted,
        reencrypted,
        hasNextPass: pass < MAX_REENCRYPT_PASSES,
      });
      warnings.push(...settled.warnings);
      if (settled.verdict.kind === "unverified") {
        // Never reached the rescan = the remaining count is not a measurement (PassVerdict's definition)
        return outcome(settled.verdict.remaining, settled.verdict.failure, false);
      }
      if (settled.verdict.kind === "abort") {
        return yield* Effect.fail(cliError(settled.verdict.message));
      }
      view = settled.verdict.view;
      pending = settled.verdict.targets;
      alreadyCurrent += settled.verdict.alreadyCurrent;
      staleCount = settled.verdict.remaining;
      if (staleCount === 0) {
        // The re-fetched, re-verified view carries no active value below
        // the target epoch = complete. A transient mid-run failure stays
        // as a warning, a "happened but resolved in the end" fact (since
        // the completion was verified, it is not reported as a partial
        // completion with a non-zero exit)
        noteResolvedFailure(
          warnings,
          failureMessage(attempted.firstFailure) ?? seenFailure,
          "the rescan confirmed completion",
        );
        return outcome(0, null, true);
      }
      blockingFailure = blockingCause(
        pendingFailure(attempted.firstFailure, settled.verdict.staleIds),
        settled.verdict.undecryptable,
      );
      seenFailure ??= failureMessage(attempted.firstFailure);
      if (stalledOnUndecryptable(pending, pass)) {
        // Unfinished work remains yet nothing can be pushed = only
        // undecryptable values are left. Cycling the remaining passes
        // would just repeat pulls without progress
        break;
      }
    }
    noteStaleFailures(warnings, blockingFailure, seenFailure);
    // The passes ran out (not an abort): the remaining count is a **measurement** through the final pass's rescan
    return outcome(staleCount, blockingFailure, true);
  });
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
      Effect.catch((error) =>
        Effect.gen(function* () {
          yield* logWarnings(dedupeWarnings(warnings));
          if (
            error instanceof RotateValuesConflictError &&
            attempt < MAX_VALUES_CONFLICT_ATTEMPTS
          ) {
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
          return yield* Effect.fail(error);
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
function resumeReencryption(input: {
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
}): Effect.Effect<RotationSummary, CliError, CliIo> {
  return Effect.gen(function* () {
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
              yield* ownDeviceBySigningKey(
                input.pulled.verified,
                member,
                input.input.signingKeyPair,
              ),
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
}

/**
 * The warning wording of a run where `--init-manifest` turned out
 * unnecessary. **Chosen after rotatePathOf's result is settled**: a run
 * whose path is resume / up-to-date sends no rotate composite = issues no
 * next manifestVersion, so the wording "this rotation re-issues the next
 * version" would be a lie (making the flag-passing user believe in a
 * re-issuance that never happened).
 */
function initManifestWarning(
  environmentId: string,
  manifestVersion: number,
  path: "resume" | "up-to-date" | "rotate",
): string {
  const base = `--init-manifest was passed, but environment ${displayText(environmentId)} already has a verified manifest (manifestVersion ${manifestVersion}). The flag is not needed`;
  switch (path) {
    case "rotate":
      return `${base} — this rotation re-issues the next manifestVersion as usual`;
    case "resume":
      return `${base} — this run only resumes the incomplete re-encryption and issues no new manifest`;
    case "up-to-date":
      return `${base} — this run issues nothing (it only confirms the environment is up to date)`;
  }
}

/**
 * Of the pre-rotate situation warnings (manifest migration + no floor),
 * the ones that don't depend on the path. Placed right after the pull
 * warnings = before any subsequent failure (DEK verification etc.). Only
 * the `--init-manifest` unneeded-flag wording waits for the path to
 * settle (initManifestWarning).
 */
function rotateSituationWarnings(
  input: RotateInput,
  pulled: VerifiedEnvironmentPull,
  floorless: boolean,
): readonly string[] {
  const warnings: string[] = [];
  if (pulled.manifest === null) {
    warnings.push(
      `Environment ${displayText(input.environmentId)} has no manifest yet (created before manifests were introduced). This rotation initializes manifestVersion 1 — after it succeeds, every distribution of this environment is manifest-verified and a missing manifest is rejected (CRYPTO_SPEC §6.3)`,
    );
  }
  if (floorless) {
    warnings.push(
      `This environment has no local floor yet, so variables the server keeps omitting from responses (ones that exist but never appear in listings) are not covered by re-encryption, and the omission cannot be detected (omission detection in CRYPTO_SPEC §6.3 presumes a floor). For revocation-purpose rotations, re-run from a machine that has a floor and confirm the variable listing for ${displayText(input.environmentId)} matches`,
    );
  }
  return warnings;
}

/**
 * Path selection: send the composite (rotate), a composite-less resume
 * (resume), or a check only (up-to-date). --new-epoch and "an actually
 * needed --init-manifest" always send the composite — issuing
 * manifestVersion 1 happens only bundled with a meta operation (§12-5),
 * so an early return would look like success while leaving it
 * uninitialized.
 */
function rotatePathOf(input: {
  readonly staleCount: number;
  readonly reason: string | null;
  readonly forceNewEpoch: boolean;
  readonly mustInitialize: boolean;
}): "resume" | "up-to-date" | "rotate" {
  if (input.forceNewEpoch || input.mustInitialize) {
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
  } | null;
  readonly entries: readonly ManifestDigestEntry[];
  readonly envMeta: { readonly metaVersion: number; readonly sigHashHex: string };
} {
  return {
    previous:
      pulled.manifest === null
        ? null
        : {
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

function rotateWithWarnings(
  input: RotateInput,
  warnings: string[],
): Effect.Effect<RotationSummary, CliError, CliIo> {
  return Effect.gen(function* () {
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
      // Only --init-manifest (the migration path) tolerates a manifest
      // **omission**. Verification when distributed all happens regardless
      // of the flag
      allowMissingManifest: input.initManifest,
    });
    // Warnings enter the sink **before** any subsequent failure (DEK
    // verification etc.): if the failure path's flush didn't include them,
    // they'd vanish exactly on failure — the same hole as round 8
    warnings.push(...pulled.warnings, ...rotateSituationWarnings(input, pulled, floorless));
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
      // A run where the initialization is actually needed (an omission was confirmed) always sends the rotate composite
      mustInitialize: input.initManifest && pulled.manifest === null,
    });
    // The --init-manifest unneeded-flag wording is chosen after the path
    // settles (a resume / up-to-date run sends no composite = never say
    // "it re-issues the next version")
    warnings.push(...initManifestNotices(input, pulled.manifest, path));

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
}

/** The guidance for a run where --init-manifest turned out unnecessary (the wording is chosen after the path settles). */
function initManifestNotices(
  input: RotateInput,
  manifest: { readonly manifestVersion: number } | null,
  path: "resume" | "up-to-date" | "rotate",
): readonly string[] {
  return input.initManifest && manifest !== null
    ? [initManifestWarning(input.environmentId, manifest.manifestVersion, path)]
    : [];
}

/** Computing the new-epoch DEK's commitment (CRYPTO_SPEC §5.2). Failures are CliError. */
function computeRotationCommitmentHex(input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly newEpoch: number;
  readonly dek: Redacted.Redacted<Uint8Array>;
}): Effect.Effect<string, CliError> {
  return Effect.tryPromise({
    try: () =>
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
    catch: () => cliError("Failed to compute the DEK commitment"),
  }).pipe(
    Effect.flatMap((commitment) =>
      commitment.ok
        ? Effect.succeed(commitment.value)
        : Effect.fail(cliError("Failed to compute the DEK commitment")),
    ),
  );
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
function issuePostRotationCheckpoint(
  input: RotateInput,
  view: VerifiedProject,
  warnings: string[],
): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
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
}
