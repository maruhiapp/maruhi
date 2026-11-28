import { cryptoEffect, type ProjectId, type UserId } from "@maruhi/core";
import { SUITE_ID, signHeadAttestation, verifyDistributedHeadAttestation } from "@maruhi/crypto";
import { Clock, Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { DistributedAttestationWire, VerifiedProject } from "./chain-sync.ts";
import { resyncExtended } from "./chain-sync.ts";
import { type CliError, evidenceError } from "./errors.ts";
import { internalErrorKind } from "./failure.ts";
import { formatAttestationEvidence } from "./floor-evidence.ts";
import { type AttestationEvidenceRecord, FloorStore } from "./floor.ts";
import type { CliIo } from "./io.ts";
import { logNote, logWarning } from "./notice.ts";

type MatchOutcome =
  | { readonly kind: "ok" }
  | { readonly kind: "skip" }
  | { readonly kind: "future" }
  | { readonly kind: "mismatch" };

const matchAttestation = Effect.fnUntraced(function* (
  view: VerifiedProject,
  attestation: DistributedAttestationWire,
): Effect.fn.Return<MatchOutcome> {
  const current = view.history.memberStateAt(attestation.attesterUserId, view.state.headSeq);
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
    Effect.catchTags(
      {
        CryptoHeadAttestationInvalid: (error) => {
          if (error.reason === "chain-head-future") {
            return Effect.succeed({ kind: "future" } satisfies MatchOutcome);
          }
          if (error.reason === "chain-head-mismatch") {
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

interface Classified {
  readonly evidence: DistributedAttestationWire[];
  readonly future: DistributedAttestationWire[];
}

const classifyAll = Effect.fn("attestation.classifyAll")(function* (
  view: VerifiedProject,
  attestations: readonly DistributedAttestationWire[],
): Effect.fn.Return<Classified> {
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

function evidenceRecordOf(
  view: VerifiedProject,
  attestation: DistributedAttestationWire,
  kind: AttestationEvidenceRecord["kind"],
  detectedAtMs: number,
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
    detectedAtMs,
  };
}

const failWithEvidence = Effect.fn("attestation.failWithEvidence")(function* (
  projectId: ProjectId,
  view: VerifiedProject,
  records: readonly {
    attestation: DistributedAttestationWire;
    kind: AttestationEvidenceRecord["kind"];
  }[],
): Effect.fn.Return<never, CliError, FloorStore | CliIo> {
  const store = yield* FloorStore;
  const detectedAtMs = yield* Clock.currentTimeMillis;
  const evidence = records.map((record) =>
    evidenceRecordOf(view, record.attestation, record.kind, detectedAtMs),
  );
  let evidencePath = "(could not be written)";
  for (const record of evidence) {
    const written = yield* store
      .appendAttestationEvidence(projectId, record)
      .pipe(Effect.orElseSucceed(() => null));
    if (written !== null) {
      evidencePath = written;
    }
  }
  return yield* Effect.fail(
    evidenceError(formatAttestationEvidence(projectId, evidence, evidencePath)),
  );
});

export const reconcileDistributedAttestations = Effect.fn(
  "attestation.reconcileDistributedAttestations",
)(function* (input: {
  readonly projectId: ProjectId;
  readonly view: VerifiedProject;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
}): Effect.fn.Return<VerifiedProject, CliError, FloorStore | CliIo> {
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
  const advanced = yield* resyncExtended(input.resync, input.view);
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

export const submitHeadAttestationIfAdvanced = Effect.fn(
  "attestation.submitHeadAttestationIfAdvanced",
)(function* (input: {
  readonly client: MaruhiClient;
  readonly projectId: ProjectId;
  readonly view: VerifiedProject;
  readonly attesterUserId: UserId;
  readonly signingKey: CryptoKey;
}): Effect.fn.Return<void, never, FloorStore | CliIo> {
  const store = yield* FloorStore;
  const head = { seq: input.view.state.headSeq, hashHex: input.view.state.headHashHex };
  const attested = yield* store
    .loadAttestedHead(input.projectId)
    .pipe(Effect.orElseSucceed(() => null));
  if (attested !== null && head.seq <= attested.seq && head.hashHex === attested.hashHex) {
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
  ).pipe(Effect.orElseSucceed(() => null));
  if (signed === null) {
    yield* logNote(
      "could not sign the head attestation for this sync (split-view gossip). This does not affect the current command",
    );
    return;
  }
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
      Effect.catchTag(
        "AttestationRegression",
        () => Effect.succeed("regression" as const),
        (error) => Effect.succeed(internalErrorKind(error)),
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
