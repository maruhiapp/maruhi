// The client side of head gossip (CRYPTO_SPEC §6.3 head gossip / §6.6,
// AUTH_SPEC §16-1).
//
// Reconciliation (reconcileDistributedAttestations): verifies the other
// members' attestations bundled with the chain-fetch response per §6.6,
// then reconciles them against the local view.
//   (a) attested seq ≤ own head with a hash mismatch = **hard evidence**
//       of a fork (equivocation) or a leaked attester key — interrupt use
//       of that sync's artifacts, warn, and save the evidence (the
//       attestation + the local view's chain digest) to append-only,
//       non-confidential local state (the evidencing of §14.2-5 —
//       floor-evidence format)
//   (b) attested seq > own head = possibly just a stale local chain —
//       resolved as an extension by the existing bounded resync
//       (chain-sync.ts's resyncExtended — once) it is fine; if it does not
//       resolve, treat it like (a)
// Attestations that fail verification (signature, out-of-history attester,
// etc.) are **not made reconciliation material** (eliminates
// warning-induction DoS via forged attestations — §6.6). Attestations by
// an attester who is not a current member are excluded the same way
// (§6.6 (1) — the server should delete the row at remove, so the
// distribution itself is a deviation).
//
// Submission (submitHeadAttestationIfAdvanced): after chain sync +
// verification succeed, if the verified head has advanced past the last
// attestation, sign and submit it (SHOULD — a failure is a non-fatal
// warning). Tracking the last attestation is non-confidential local
// state outside the floor's join lattice (floor.ts's loadAttestedHead —
// its loss is absorbed by the server's idempotent 204 on a same-seq
// re-submission).
//
// ci run (the lease path) does not join gossip (§6.6 / §14-2 — the lease
// response bundles no attestations and the workload has no signing key).

import { AttestationRegressionError } from "@maruhi/api-schema";
import { cryptoEffect } from "@maruhi/core";
import { SUITE_ID, signHeadAttestation, verifyDistributedHeadAttestation } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { DistributedAttestationWire, VerifiedProject } from "./chain-sync.ts";
import { resyncExtended } from "./chain-sync.ts";
import type { CliServices } from "./context.ts";
import { type CliError, evidenceError } from "./errors.ts";
import { internalErrorKind } from "./failure.ts";
import { formatAttestationEvidence } from "./floor-evidence.ts";
import { type AttestationEvidenceRecord, FloorStore } from "./floor.ts";
import { logNote, logWarning } from "./notice.ts";

/** The reconciliation outcome of one attestation (internal). */
type MatchOutcome =
  | { readonly kind: "ok" }
  | { readonly kind: "skip" }
  | { readonly kind: "future" }
  | { readonly kind: "mismatch" };

/**
 * §6.6 verification of one attestation + reconciliation against the local
 * view. Verification failures are skip (not reconciliation material); only
 * the two head-binding kinds (§6.3-2) come back as future / mismatch.
 */
function matchAttestation(
  view: VerifiedProject,
  attestation: DistributedAttestationWire,
): Effect.Effect<MatchOutcome> {
  return Effect.gen(function* () {
    // First half of §6.6 (1): the attester (user_id + key FP) must be a
    // current member in the local view. An attestation by a non-current member
    // is not reconciliation material (the server deletes the row at remove —
    // §6.4; even when distributed, a past attestation within the membership
    // interval has no warning value)
    const current = view.history.memberStateAt(attestation.attesterUserId, view.state.headSeq);
    // The attested FP is one of the attester's currently valid devices
    // (2026-09-19 DK — per-device identification)
    if (current === undefined || !current.devices.has(attestation.attesterKeyFingerprintHex)) {
      return { kind: "skip" } satisfies MatchOutcome;
    }
    const outcome = yield* cryptoEffect(() =>
      verifyDistributedHeadAttestation({
        history: view.history,
        context: {
          suite: attestation.suite,
          projectId: view.projectId,
          attesterUserId: attestation.attesterUserId,
          chainHeadHashHex: attestation.chainHeadHashHex,
          chainHeadSeq: attestation.chainHeadSeq,
        },
        attesterKeyFingerprintHex: attestation.attesterKeyFingerprintHex,
        signatureHex: attestation.signatureHex,
      }),
    ).pipe(
      Effect.as({ kind: "ok" } satisfies MatchOutcome),
      // Every other wrapped kind is not reconciliation material — the
      // else branch lands on skip (§6.6: verification failures are
      // skipped, not warned — warning-induction DoS by forged
      // attestations is eliminated that way)
      Effect.catchTags(
        {
          CryptoHeadAttestationInvalid: (error) => {
            if (error.reason === "chain-head-future") {
              return Effect.succeed({ kind: "future" } satisfies MatchOutcome);
            }
            if (error.reason === "chain-head-mismatch") {
              // Signature and key selection are already verified (check order — §6.6),
              // so this mismatch makes the attestation itself evidence (distinct from a
              // discarded skip)
              return Effect.succeed({ kind: "mismatch" } satisfies MatchOutcome);
            }
            return Effect.succeed({ kind: "skip" } satisfies MatchOutcome);
          },
        },
        () => Effect.succeed({ kind: "skip" } satisfies MatchOutcome),
      ),
    );
    return outcome;
  });
}

interface Classified {
  readonly evidence: DistributedAttestationWire[];
  readonly future: DistributedAttestationWire[];
}

function classifyAll(
  view: VerifiedProject,
  attestations: readonly DistributedAttestationWire[],
): Effect.Effect<Classified> {
  return Effect.gen(function* () {
    const evidence: DistributedAttestationWire[] = [];
    const future: DistributedAttestationWire[] = [];
    for (const attestation of attestations) {
      const outcome = yield* matchAttestation(view, attestation);
      if (outcome.kind === "mismatch") {
        evidence.push(attestation);
      } else if (outcome.kind === "future") {
        future.push(attestation);
      }
    }
    return { evidence, future };
  });
}

function evidenceRecordOf(
  view: VerifiedProject,
  attestation: DistributedAttestationWire,
  kind: AttestationEvidenceRecord["kind"],
): AttestationEvidenceRecord {
  return {
    attestation: {
      suite: attestation.suite,
      attesterUserId: attestation.attesterUserId,
      attesterKeyFingerprintHex: attestation.attesterKeyFingerprintHex,
      chainHeadHashHex: attestation.chainHeadHashHex,
      chainHeadSeq: attestation.chainHeadSeq,
      signatureHex: attestation.signatureHex,
    },
    localView: {
      headSeq: view.state.headSeq,
      headHashHex: view.state.headHashHex,
      entryHashAtAttestedSeq: view.history.entryHashAt(attestation.chainHeadSeq) ?? "",
    },
    kind,
    detectedAtMs: Date.now(),
  };
}

/** Save the evidence (append-only) + warn + stop using that sync's artifacts (fail). */
function failWithEvidence(
  projectId: string,
  view: VerifiedProject,
  records: readonly {
    attestation: DistributedAttestationWire;
    kind: AttestationEvidenceRecord["kind"];
  }[],
): Effect.Effect<never, CliError, CliServices> {
  return Effect.gen(function* () {
    const store = yield* FloorStore;
    const evidence = records.map((record) =>
      evidenceRecordOf(view, record.attestation, record.kind),
    );
    let evidencePath = "(could not be written)";
    for (const record of evidence) {
      // A failure to save the evidence itself does not swallow the detection
      // (the warning body carries the evidence — saving is additional
      // preservation; the interruption and warning are unchanged if it fails)
      const written = yield* store
        .appendAttestationEvidence(projectId, record)
        .pipe(Effect.catch(() => Effect.succeed(null)));
      if (written !== null) {
        evidencePath = written;
      }
    }
    // A contradiction between signed data: evidence, which a re-run does
    // not resolve (round 12)
    return yield* Effect.fail(
      evidenceError(formatAttestationEvidence(projectId, evidence, evidencePath)),
    );
  });
}

/**
 * Verify and reconcile the distributed attestation set ((a)/(b) in the module
 * header comment). If any future attestations exist, run one bounded resync
 * (resyncExtended — anything that is not an extension is refused there), then
 * re-reconcile the advanced view's own attestation set plus the unresolved
 * ones. If unresolved: (a). On success, returns the reconciled view (it may
 * have advanced via the resync).
 */
export function reconcileDistributedAttestations(input: {
  readonly projectId: string;
  readonly view: VerifiedProject;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
}): Effect.Effect<VerifiedProject, CliError, CliServices> {
  return Effect.gen(function* () {
    const first = yield* classifyAll(input.view, input.view.attestations);
    if (first.evidence.length > 0) {
      return yield* failWithEvidence(
        input.projectId,
        input.view,
        first.evidence.map((attestation) => ({ attestation, kind: "head-mismatch" as const })),
      );
    }
    if (first.future.length === 0) {
      return input.view;
    }
    // (b): bounded resync (once). The extension check (resyncExtended) drops
    // a substitution to a different chain right there
    const advanced = yield* resyncExtended(input.resync, input.view);
    // Re-reconcile the post-resync view's own attestation set plus the
    // unresolved future ones (the normal shape is that a future entry is
    // replaced in the new set by a newer attestation from the same attester,
    // but if it simply vanished, judge by whether the original attestation
    // resolved).
    // The union dedupes identical attestations (when the attester has not
    // re-attested, the same record appears in the new set) — the same content
    // listed twice in the evidence JSONL / warning would read as "two members
    // contradicting each other".
    // The key is every wire field: with a partial key, a malicious server
    // could mix a one-field-rewritten record into the new set and make a
    // genuine carried-over entry (first.future) get dropped on a key
    // collision (the forged side is silently skipped at signature
    // verification → the carried-over reconciliation misses, reopening the
    // omission bypass that the session-37 ruling AA closed)
    const seen = new Set<string>();
    const union = [...advanced.attestations, ...first.future].filter((attestation) => {
      const key = `${attestation.suite}#${attestation.attesterUserId}#${attestation.attesterKeyFingerprintHex}#${attestation.chainHeadHashHex}#${attestation.chainHeadSeq}#${attestation.signatureHex}`;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
    const second = yield* classifyAll(advanced, union);
    if (second.evidence.length > 0 || second.future.length > 0) {
      return yield* failWithEvidence(input.projectId, advanced, [
        ...second.evidence.map((attestation) => ({
          attestation,
          kind: "head-mismatch" as const,
        })),
        ...second.future.map((attestation) => ({
          attestation,
          kind: "unresolved-after-resync" as const,
        })),
      ]);
    }
    return advanced;
  });
}

/**
 * Submit an attestation for the verified head (§6.3 head gossip —
 * SHOULD). Only when it has advanced past the last attestation is it
 * signed and PUT; on success the tracking is updated. **No failure
 * fails the command** (not ignored either — reduced to a one-line
 * warning — the SHOULD's accompaniment). A 409 (AttestationRegression)
 * is a local-view regression = warned separately as a sign of floor
 * damage or a concurrent CLI.
 */
export function submitHeadAttestationIfAdvanced(input: {
  readonly client: MaruhiClient;
  readonly projectId: string;
  readonly view: VerifiedProject;
  readonly attesterUserId: string;
  readonly signingKey: CryptoKey;
}): Effect.Effect<void, never, CliServices> {
  return Effect.gen(function* () {
    const store = yield* FloorStore;
    const head = { seq: input.view.state.headSeq, hashHex: input.view.state.headHashHex };
    const attested = yield* store
      .loadAttestedHead(input.projectId)
      .pipe(Effect.catch(() => Effect.succeed(null)));
    if (attested !== null && head.seq <= attested.seq && head.hashHex === attested.hashHex) {
      // Suppress only re-attesting the **identical head** that has not
      // advanced (the SHOULD's trigger is "if advanced" — no submission, no
      // rate-window consumption). It is not judged by seq alone because when
      // the floor is missing / corrupt — first run or damaged — and we are
      // shown a different chain at the same seq with a different hash
      // (equivocation), the path by which other members detect the fork via
      // this device's attestation would close too. A seq regression
      // (necessarily a different hash) is submitted too, so the server's 409
      // AttestationRegression surfaces as a warning sign of floor damage or
      // a concurrent CLI
      return;
    }
    const signed = yield* cryptoEffect(() =>
      signHeadAttestation({
        context: {
          suite: SUITE_ID,
          projectId: input.projectId,
          attesterUserId: input.attesterUserId,
          chainHeadHashHex: head.hashHex,
          chainHeadSeq: head.seq,
        },
        signingKey: input.signingKey,
      }),
    ).pipe(Effect.catch(() => Effect.succeed(null)));
    if (signed === null) {
      yield* logNote(
        "could not sign the head attestation for this sync (split-view gossip). This does not affect the current command",
      );
      return;
    }
    // Reading `_tag` directly is banned by oxlint — the discrimination is
    // instanceof (the failure.ts discipline); the diagnostic name is
    // internalErrorKind (the type name only — carries no response fragment)
    const submitted = yield* input.client.membership
      .attest({
        params: { projectId: input.projectId },
        payload: {
          suite: SUITE_ID,
          chainHeadHashHex: head.hashHex,
          chainHeadSeq: head.seq,
          signatureHex: signed,
        },
      })
      .pipe(
        Effect.as("submitted" as const),
        Effect.catch((error) =>
          Effect.succeed(
            error instanceof AttestationRegressionError ? "regression" : internalErrorKind(error),
          ),
        ),
      );
    if (submitted === "submitted") {
      yield* store
        .saveAttestedHead(input.projectId, head)
        .pipe(
          Effect.catch(() =>
            logNote(
              "the head attestation was submitted but its local tracking file could not be written (the next sync may re-submit the same head, which the server treats as an idempotent success)",
            ),
          ),
        );
      return;
    }
    // A submission failure is non-fatal (SHOULD) but not ignored — reduced to a one-line warning
    if (submitted === "regression") {
      yield* logWarning(
        "the server rejected this head attestation as a regression (it stores a later attestation from this account). This can indicate local floor damage or a concurrent CLI on another machine that has seen a later chain — run `maruhi project verify` and compare with other members if you do not recognize this",
      );
      return;
    }
    yield* logNote(
      `could not submit the head attestation for this sync (split-view gossip stays inactive for this account until it succeeds). This does not affect the current command (${submitted})`,
    );
  });
}
