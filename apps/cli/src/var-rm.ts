// `maruhi var rm <NAME>` — deleting a variable.
//
// The wire, acceptance, and verification already exist
// (DeleteVariableMetaStatement v1 / V3 + the manifest compound —
// AUTH_SPEC §12-5). This module only adds the CLI-side signing,
// sending, and confirmation:
//
//   - Deleting a v1 variable keeps the v1 form (never silently
//     raises the layout). Deleting a v3 variable **keeps the schema
//     fields and layout byte-exactly from the previous statement**
//     (CRYPTO_SPEC §4.2's deletion convention — the server enforces
//     a mismatch as 422 payload-mismatch). name keeps the last
//     active name as-is (deletion never empties the name field)
//   - Deletion is terminal (no return from deleted — §4.2).
//     Deleting an active (valued) variable immediately deletes
//     every version's ciphertext (§12-5). So an interactive
//     explicit confirmation (retyping the variable name) is
//     required, and a non-interactive environment refuses without
//     --force (fail-closed). A declared (valueless) variable is not
//     deleted silently either — it rides the same confirmation
//   - Rides the existing meta-operation discipline: 3-F
//     (journal-before-send — issueManifestWithIntent) + 1-E′
//     (effect confirmation — confirmMetaMutation) + the floor's
//     tombstone advance (commitPush)
//
// Why the command is not placed in the schema group: what
// disappears is not the schema but the variable and the value
// itself (the schema fields are only a part of it).

import { ManifestVersionConflictError, MetaVersionConflictError } from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import { SUITE_ID } from "@maruhi/crypto";
import { Effect, Stdio } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { VerifiedProject } from "./chain-sync.ts";
import { confirmPermanentDeletion } from "./deletion-confirm.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import type { FloorHandle, VerifiedVariableStatement } from "./floor-check.ts";
import { rejectIntentOnServerRejection } from "./floor-check.ts";
import { CliIo } from "./io.ts";
import {
  confirmAcceptedMetaMutation,
  confirmsIssuedStatement,
  issueManifestWithIntent,
} from "./meta-confirm.ts";
import { signStatementAndHash } from "./meta-statement.ts";
import { retryOnConflict } from "./retry.ts";
import {
  signDeleteStatementV3,
  requireVerifiedEnvironment,
  resolveSchemaTarget,
  type SchemaSetState,
} from "./schema.package/index.ts";

const MAX_ATTEMPTS = 5;

interface VarRmInput {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  /** The variable name (NFC normalization is done by this function — §12-1). */
  readonly name: string;
  /** true = skip the confirmation (the only non-interactive path — an explicit risk acceptance). */
  readonly force: boolean;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
  readonly authorUserId: string;
  readonly signingKey: CryptoKey;
}

interface VarRmSummary {
  readonly variableId: string;
  readonly metaVersion: number;
  /** The pre-deletion state (active = the value is also gone / declared = declaration only). */
  readonly previousStatus: "active" | "declared";
  readonly warnings: readonly string[];
}

/** Resolves the target (distinguishing deleted / nonexistent uses the pre-call state). */
const resolveDeletionTarget = Effect.fn("var-rm.resolveDeletionTarget")(function* (
  input: VarRmInput,
  verified: VerifiedProject,
  name: string,
): Effect.fn.Return<SchemaSetState & { readonly target: VerifiedVariableStatement }, CliError> {
  const state = yield* resolveSchemaTarget(input, verified, name);
  const target = state.target;
  if (target !== null) {
    return { ...state, target };
  }
  if (state.tombstones.some((tombstone) => tombstone.name === name)) {
    // Deletion is terminal (§4.2) — rm on an already-deleted
    // name reaches "the desired state" but the call's
    // precondition (this run deletes it) does not hold, so make
    // it an explicit error
    return yield* Effect.fail(
      cliError(
        `Variable ${displayText(name)} is already deleted (deletion is terminal — a deleted variable cannot be restored). Nothing was changed by this run`,
      ),
    );
  }
  return yield* Effect.fail(
    cliError(`Variable ${displayText(name)} does not exist in this environment`),
  );
});

/**
 * The explicit deletion confirmation (fail-closed — deletion-confirm.ts):
 * without --force, an interactive terminal requires **retyping the
 * variable name**; non-interactive refuses without --force.
 */
function ensureDeletionConfirmed(
  input: VarRmInput,
  target: VerifiedVariableStatement,
  name: string,
): Effect.Effect<void, CliError, CliIo | Stdio.Stdio> {
  return confirmPermanentDeletion(input.force, {
    label: displayText(name),
    consequence:
      target.status === "active"
        ? "its value (every stored version) is deleted immediately and cannot be recovered"
        : "the declaration (no value was set) is removed",
    irreversibility: "the variable cannot be restored",
    refusalReason:
      "deletion is terminal and, for a variable with a value, destroys every stored version",
    typedNoun: "variable name",
    mismatchNoun: "name",
    expected: name,
  });
}

interface AcceptedDeletion {
  readonly variableId: string;
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
  readonly previousStatus: "active" | "declared";
  readonly selfManifest: {
    readonly manifestVersion: number;
    readonly epoch: number;
    readonly manifestSigHashHex: string;
  };
  readonly intentId: string;
  readonly state: SchemaSetState;
}

/** A v1 variable's deletion statement (keeps the v1 form — never silently raises the layout). */
const signDeleteStatementV1 = Effect.fn("var-rm.signDeleteStatementV1")(function* (input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly target: VerifiedVariableStatement;
  readonly authorUserId: string;
  readonly signingKey: CryptoKey;
}) {
  // The signed context is built exactly once, and the wire is
  // derived mechanically (same discipline as meta-statement.ts
  // / schema-statement.ts)
  const context = {
    suite: SUITE_ID,
    projectId: input.verified.projectId,
    environmentId: input.environmentId,
    target: { kind: "variable", variableId: input.target.variableId },
    // name keeps the last active name as-is (§4.2 — deletion never empties it)
    name: input.target.name,
    status: "deleted",
    metaVersion: input.target.metaVersion + 1,
    prevMetaSigHashHex: input.target.metaSigHashHex,
    authorUserId: input.authorUserId,
    chainHeadHashHex: input.verified.state.headHashHex,
    chainHeadSeq: input.verified.state.headSeq,
  } as const;
  const signed = yield* signStatementAndHash(context, input.signingKey);
  return {
    statement: {
      suite: context.suite,
      environmentId: context.environmentId,
      variableId: context.target.variableId,
      name: context.name,
      status: context.status,
      metaVersion: context.metaVersion,
      prevMetaSigHashHex: context.prevMetaSigHashHex,
      chainHeadHashHex: context.chainHeadHashHex,
      chainHeadSeq: context.chainHeadSeq,
      signatureHex: signed.signatureHex,
    },
    metaSigHashHex: signed.metaSigHashHex,
  };
});

/**
 * One attempt's concrete failure channel: CliError (own failures and the
 * crypto bridge's wrapped kinds re-mapped at the crypto sites) plus the
 * variables.remove endpoint's declared error union (the raw types —
 * classifyDeletionConflict discriminates them on the retryOnConflict
 * side).
 */
type DeletionAttemptError =
  | CliError
  | Effect.Error<ReturnType<VarRmInput["client"]["variables"]["remove"]>>;

/** One attempt (sign, send). Conflict classification is retryOnConflict's classify's job. */
const attemptDeletion = Effect.fn("var-rm.attemptDeletion")(function* (
  input: VarRmInput,
  state: SchemaSetState & { readonly target: VerifiedVariableStatement },
): Effect.fn.Return<AcceptedDeletion, DeletionAttemptError> {
  const target = state.target;
  const environment = yield* requireVerifiedEnvironment(state, input.environmentId);
  if (target.status !== "active" && target.status !== "declared") {
    return yield* Effect.fail(
      cliError("The resolved deletion target is not a live variable (internal inconsistency)"),
    );
  }
  const previousStatus = target.status;
  // Deleting a v3 variable uses that form (schema fields and layout
  // kept byte-exactly from the previous statement — §12-5's deletion
  // convention); a v1 variable's deletion keeps the v1 form. A verified
  // statement carries schema fields exactly on layout 3
  const signed =
    target.schema !== null
      ? yield* signDeleteStatementV3({
          verified: state.verified,
          environmentId: input.environmentId,
          variableId: target.variableId,
          name: target.name,
          schema: target.schema,
          prev: { metaVersion: target.metaVersion, metaSigHashHex: target.metaSigHashHex },
          authorUserId: input.authorUserId,
          signingKey: input.signingKey,
        })
      : yield* signDeleteStatementV1({
          verified: state.verified,
          environmentId: input.environmentId,
          target,
          authorUserId: input.authorUserId,
          signingKey: input.signingKey,
        });
  // The manifest swaps the target entry for a tombstone (§4.3 —
  // the digest covers every statement including tombstones). The
  // 3-F intent is persisted before sending
  const { manifest, intentId } = yield* issueManifestWithIntent({
    verified: state.verified,
    environmentId: input.environmentId,
    epoch: environment.currentEpoch,
    previous: state.manifestBase.previous,
    entries: [
      ...state.manifestBase.entries.filter((entry) => entry.variableId !== target.variableId),
      {
        variableId: target.variableId,
        status: "deleted" as const,
        metaVersion: target.metaVersion + 1,
        metaSigHashHex: signed.metaSigHashHex,
      },
    ],
    envMeta: state.manifestBase.envMeta,
    issuerUserId: input.authorUserId,
    signingKey: input.signingKey,
    floor: input.floor,
    variableId: target.variableId,
  });
  yield* input.client.variables
    .remove({
      params: {
        projectId: state.verified.projectId,
        environmentId: input.environmentId,
        variableId: target.variableId,
      },
      payload: { statement: signed.statement, manifest: manifest.manifest },
    })
    .pipe(Effect.tapError(rejectIntentOnServerRejection(input.floor, intentId)));
  return {
    variableId: target.variableId,
    metaVersion: target.metaVersion + 1,
    metaSigHashHex: signed.metaSigHashHex,
    previousStatus,
    selfManifest: {
      manifestVersion: manifest.manifestVersion,
      epoch: manifest.epoch,
      manifestSigHashHex: manifest.manifestSigHashHex,
    },
    intentId,
    state,
  };
});

type DeletionConflict = { readonly kind: "re-resolve" };

/** The retryable classification of a CAS conflict (§12-5). Anything else = null (a determinate error). */
function classifyDeletionConflict(error: DeletionAttemptError): DeletionConflict | null {
  if (error instanceof MetaVersionConflictError || error instanceof ManifestVersionConflictError) {
    // A concurrent meta operation re-resolves from the name
    // (§12-5's retry = refetch → verify → re-sign both the
    // statement and the manifest). Losing to a concurrent deletion
    // surfaces from re-resolution as the determinate "already
    // deleted" error
    return { kind: "re-resolve" };
  }
  return null;
}

/**
 * Deletes one variable (declared or active — AUTH_SPEC §12-5): a signed
 * deletion statement (v1 stays v1; a v3 variable's deletion preserves its
 * schema fields and layout byte-exactly) + manifest composite, gated by an
 * explicit confirmation (interactive name re-entry, or --force), and
 * confirmed against the verified distribution (1-E′ — §12-10 (3)) before the
 * local floor advances to the tombstone.
 */
export const varRmOp = Effect.fn("var-rm.varRmOp")(function* (
  input: VarRmInput,
): Effect.fn.Return<VarRmSummary, CliError, CliIo | Stdio.Stdio> {
  // Normalization's agent is the client before signing (§4.2 / §12-1)
  const name = input.name.normalize("NFC");
  const initial = yield* resolveDeletionTarget(input, input.verified, name);
  // The confirmation happens exactly once before signing,
  // sending, and the retry loop. What the confirmation binds is
  // **variableId** (not the name): re-resolution happens by
  // name, so a concurrent deletion + a fresh creation of the
  // same name can put a different variable under that name —
  // that shape is stopped by the recover below as a typed error
  // (never delete an unconfirmed variable)
  yield* ensureDeletionConfirmed(input, initial.target, name);
  const confirmedVariableId = initial.target.variableId;
  const accepted = yield* retryOnConflict(initial, {
    maxAttempts: MAX_ATTEMPTS,
    attempt: (state) => attemptDeletion(input, state),
    classify: classifyDeletionConflict,
    recover: (state) =>
      resolveDeletionTarget(input, state.verified, name).pipe(
        Effect.filterOrFail(
          (next) => next.target.variableId === confirmedVariableId,
          () =>
            cliError(
              `Variable ${displayText(name)} now resolves to a different variable than the one you confirmed (the original was deleted or renamed concurrently, and another variable took the name). Nothing was deleted by this run — re-run \`maruhi var rm\` to confirm against the current state`,
            ),
        ),
      ),
    exhaustedMessage: `The deletion conflict did not resolve (after ${MAX_ATTEMPTS} attempts). Wait a moment and re-run the command`,
  });
  // Effect confirmation (1-E′ — §12-10 (3)): the definition of
  // success is confirmation on the verifiable distribution. A
  // deletion's effect is a tombstone (at or above the issued
  // metaVersion. Same-version requires hash equality — never
  // misread a 2xx lost to a concurrent operation as effective)
  yield* confirmAcceptedMetaMutation(input, accepted, "variable deletion", (metadata, issued) =>
    metadata.tombstones.some(
      (tombstone) =>
        tombstone.variableId === accepted.variableId && confirmsIssuedStatement(tombstone, issued),
    ),
  );
  // The floor's tombstone advance (§6.3 — a later pull can
  // detect the deletion being silently undone.
  // journal-before-release: before the success report). Since
  // the deletion itself is already confirmed, a floor write
  // failure is reported as such
  yield* input.floor
    .commitPush(
      accepted.variableId,
      {
        status: "deleted",
        metaVersion: accepted.metaVersion,
        metaSigHashHex: accepted.metaSigHashHex,
      },
      {
        seq: accepted.state.verified.state.headSeq,
        hashHex: accepted.state.verified.state.headHashHex,
      },
    )
    .pipe(Effect.mapError((error) => cliError(`The deletion was accepted, but ${error.message}`)));
  return {
    variableId: accepted.variableId,
    metaVersion: accepted.metaVersion,
    previousStatus: accepted.previousStatus,
    warnings: accepted.state.warnings,
  };
});
