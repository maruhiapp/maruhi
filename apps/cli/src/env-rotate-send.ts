// Stage (i) of `maruhi env rotate` (AUTH_SPEC §12-4): signing and sending
// the `rotate_epoch` composite, probing an ambiguous send result, and
// confirming acceptance on the chain (the stage overview lives in
// env-rotate.ts).

import {
  AuditHeadNotReadyError,
  ChainHeadConflictError,
  type WrappedDek,
} from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import type { ChainEntry, ChainMember, EnvValuesDigestEntry, SigningKeyPair } from "@maruhi/crypto";
import { Data, Effect, Redacted, Runtime } from "effect";

import { signBoundaryCheckpoint } from "./boundary-checkpoint.ts";
import { signEntryAtHead } from "./chain-append.ts";
import { resyncExtended, type VerifiedProject } from "./chain-sync.ts";
import { buildWrapCompleteSet, sameWrapRecipientSet } from "./dek-wrap.ts";
import { requireChainEnvironment } from "./deks.ts";
import { ensureRotatable, type RotateInput, asOutcome } from "./env-rotate-shared.ts";
import { CliError, cliError } from "./errors.ts";
import { isServerRejection } from "./failure.ts";
import type { FloorHandle } from "./floor-check.ts";
import type { ManifestFloor } from "./floor.ts";
import { type ManifestDigestEntry, signNextManifest } from "./manifest.ts";
import { retryOnConflict } from "./retry.ts";

const MAX_ATTEMPTS = 5;

/** Signs a rotate_epoch entry right after the current head (seq = head + 1). */
const signRotateEntry = Effect.fn("env-rotate-send.signRotateEntry")(function* (input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly newEpoch: number;
  readonly reason: string;
  readonly dekCommitmentHex: string;
  readonly member: ChainMember;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.fn.Return<ChainEntry & { readonly op: "rotate_epoch" }, CliError> {
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
const probeAmbiguousSend = Effect.fn("env-rotate-send.probeAmbiguousSend")(function* (input: {
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly baseline: VerifiedProject;
  readonly environmentId: string;
  readonly newEpoch: number;
  /** The commitment of the DEK I generated (judges whether **mine** was the accepted share). */
  readonly dekCommitmentHex: string;
  /** The declared head of the attempt whose response vanished (= the composite's CAS parent). Material for judging landing-possibility. */
  readonly declaredHead: { readonly seq: number; readonly hashHex: string };
  readonly cause: string;
}): Effect.fn.Return<{ readonly outcome: RotateSendOutcome; readonly error: CliError }, never> {
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
 * (re-fetching the value set is required). A tag of its own so
 * envRotateOp's bounded retry (redoing from a verified pull — §12-4's
 * specification) catches it by tag: it survives retryOnConflict
 * via the `passthrough` option (the unclassified path's toCliError
 * mapping would erase the distinction), and it becomes a plain
 * {@link CliError} with the same message when env-rotate.ts gives up.
 */
export class RotateValuesConflictError extends Data.TaggedError("RotateValuesConflictError")<{
  readonly message: string;
}> {
  /** The same exit code CliError gives it (a failure, not a usage error). */
  override get [Runtime.errorExitCode](): number {
    return 1;
  }
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
export const appendRotation = Effect.fn("env-rotate-send.appendRotation")(function* (
  input: RotateInput & {
    readonly baseline: VerifiedProject;
    readonly member: ChainMember;
    readonly reason: string;
    readonly newEpoch: number;
    readonly dek: Redacted.Redacted<Uint8Array>;
    readonly dekCommitmentHex: string;
    /**
     * The bundled-manifest (§12-4) material: the previous manifest from a
     * verified pull, the current meta set (tombstones included), and the
     * latest shape of the environment meta. The meta set is unchanged by a
     * rotate (§4.3 — only the epoch advance is reflected).
     */
    readonly manifestBase: {
      readonly previous: {
        readonly manifestVersion: number;
        readonly signedBytesHashHex: string;
      };
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
): Effect.fn.Return<
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
  CliError | RotateValuesConflictError
> {
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
    retryOnConflict(
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
                Effect.tapError((error) => {
                  ambiguousSend = !isServerRejection(error);
                  // A refusal with the server's own error body (a CAS
                  // 409 included) = no effect has occurred (settled) —
                  // close the intent. A resolution-append failure may be
                  // swallowed: the direction where the intent stays open
                  // is the safe side
                  return isServerRejection(error)
                    ? Effect.ignore(input.floor.resolveIntent(intentId, "rejected"))
                    : Effect.void;
                }),
                Effect.catchTags(
                  {
                    // A rotate into a deleted (tombstone) environment is a
                    // 404 (§12-4). The shape is "the chain asserts the
                    // environment exists but the server returned 404", so
                    // per §7's discipline "never skip silently — interrupt
                    // and warn" — never collapse it into the generic
                    // "environment not found"
                    EnvironmentNotFound: () =>
                      Effect.fail(
                        cliError(
                          `Rotation for environment ${input.environmentId} was rejected with 404. Unless a verified deletion statement can be confirmed, a malicious server may be selectively blocking rotation — aborting instead of silently skipping (CRYPTO_SPEC §7)`,
                        ),
                      ),
                    // A CAS conflict on the bundled manifest (§12-5 (6))
                    // = another meta operation (a variable create /
                    // rename / delete / an environment rename) was
                    // interposed between issuance and acceptance. Since
                    // the meta set may have changed, re-signing within
                    // this run cannot resolve it — a re-run re-fetches
                    // the meta state (unlike a chain CAS 409, the
                    // material must be re-fetched)
                    ManifestVersionConflict: (error) =>
                      Effect.fail(
                        cliError(
                          `A concurrent meta operation advanced environment ${input.environmentId}'s manifest (the server reports manifestVersion ${error.currentManifestVersion}). Re-run \`maruhi env rotate\` to rebuild the manifest from the refreshed state`,
                        ),
                      ),
                    // The 422 of the boundary checkpoint's values_digest
                    // cross-check (§12-4). envRotateOp picks it up via a
                    // bounded retry from a verified pull (on exhaustion
                    // this wording surfaces as-is)
                    CheckpointStateMismatch: (error) =>
                      Effect.fail(
                        new RotateValuesConflictError({
                          message: `A concurrent push advanced environment ${input.environmentId}'s values while the rotation was in flight (the server reports ${error.reason}). Re-run \`maruhi env rotate\` to rebuild the checkpoint from the refreshed state`,
                        }),
                      ),
                  },
                  // Classification targets like ChainHeadConflict pass
                  // through as-is (retryOnConflict's classify)
                  Effect.fail,
                ),
              );
            return sent;
          }),
        // RotateValuesConflictError bypasses classification: it is the
        // outer bounded retry's signal (env-rotate.ts catches it by
        // tag), and the unclassified path's toCliError mapping would
        // erase the distinction
        passthrough: "RotateValuesConflictError",
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
const settleAmbiguousRotation = Effect.fn("env-rotate-send.settleAmbiguousRotation")(function* (
  input: RotationConfirmInput,
  sent: AcceptedRotation,
  cause: string,
): Effect.fn.Return<never, CliError> {
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

/**
 * The post-acceptance confirmation of a composite that got a 200 (§12-10
 * (3) — a chain sync). Any failure from here on is a failure **after the
 * epoch already advanced**, so it surfaces only the cause without losing
 * the operational state "the epoch moved, re-encryption is not done".
 */
const confirmAcceptedRotation = Effect.fn("env-rotate-send.confirmAcceptedRotation")(function* (
  input: RotationConfirmInput,
  accepted: AcceptedRotation,
): Effect.fn.Return<
  {
    readonly view: VerifiedProject;
    readonly memberCount: number;
    readonly member: ChainMember;
    readonly floorWarning: string | null;
  },
  CliError
> {
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
