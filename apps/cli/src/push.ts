// A push with encryption + value signature + meta-statement (AUTH_SPEC §12-5
// = CRYPTO_SPEC §4.1 / §4.2. The PR-3 extension of session-14 ruling G).
//
// - Resolving a name → variableId must **go through verified statements**
//   (§4.2 / §12-7 — closes the known constraint recorded as
//   "unauthenticated" until session-14). Resolution uses a **metadata-only
//   pull** (§12-7 — it carries no values or DEKs, so no var.read is recorded;
//   session-11 ruling 3); only a push to an existing variable runs a
//   value-carrying pull to get the verified latest value and the bundled DEK
//   (no double fetch with listMine). The lookup key is NFC-normalized, then
//   compared byte-exact (§12-1). Duplicate active statements with the same
//   name are refused by the verification side (values-verify.ts)
// - Creation: author-sign a `VariableMetaStatement` (metaVersion 1, active,
//   empty prev) with your own key and bundle it with the version-1 value
//   (§12-5). The name is NFC-normalized before signing (the client is the
//   one performing normalization — §4.2)
// - Normal push: even for an existing variable, the latest value fetched by
//   pull is fully verified under §6.3, and the self-rebuilt signed-bytes
//   hash becomes prev (never chain-sign a server-claimed hash).
//   version = verified latest + 1, declared head = the last verified chain
//   head, the DEK is commitment-verified for the current epoch, the nonce is
//   fresh, and the signature uses your own user id + master sig key
// - 409 VersionConflict: the next version / prev is never decided from the
//   currentVersion number alone. Re-fetch the bulk pull → identify the
//   winner (an existing variable by its stable id; a create's duplicate-name
//   race by re-resolving the current name) → verify the winner's value
//   signature → set prev to the self-computed hash → re-encrypt and re-sign
//   with a fresh nonce. If the pull is older than the 409, refuse as
//   inconsistent; if newer, adopt the real winner. An omission or different
//   signed bytes at the same version (evidence of equivocation) is refused.
//   At most 5 attempts.
//   **The meta side gets the same-shape rollback / fork check** (refusing a
//   regression from the verified latest metaVersion, and different signed
//   bytes at the same metaVersion = equivocation refusal) when the winner is
//   adopted. A 409 MetaVersionConflict (a race with a concurrent rename) is
//   re-resolved from the name (same shape as the value: re-fetch → verify →
//   re-sign; no re-encryption)
// - 409 EpochConflict: resync with the extension check (never take the
//   server's currentEpoch claim as the source of truth) → re-encrypt with
//   the chain-derived epoch and the commitment-verified DEK, re-sign at the
//   new head. prev keeps the verified predecessor hash
// - The value is read from stdin and never lands on argv. The plaintext
//   lives in memory only

import type { EnvironmentId } from "@maruhi/core";
import {
  computeValueSignedBytesHash,
  encodeHex,
  encryptVariable,
  signValue,
  SUITE_ID,
} from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

import type { VerifiedProject } from "./chain-sync.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { rejectIntentOnServerRejection } from "./floor-check.ts";
import type { ManifestFloor, VariableFloor } from "./floor.ts";
import { confirmMetaMutation, issueManifestWithIntent } from "./meta-confirm.ts";
import { signCreateStatement } from "./meta-statement.ts";
import { decryptVerifiedValue } from "./pull.ts";
import { nextVersionOf, prevHashOf } from "./push-resolve.ts";
import {
  classifyPushConflict,
  initialState,
  nextState,
  type PushInput,
  type PushState,
} from "./push-state.ts";
import { retryOnConflict } from "./retry.ts";
import { signContinuationStatementV2 } from "./schema.package/index.ts";
import type { VerifiedPulledValue } from "./values-verify.ts";

const MAX_ATTEMPTS = 5;

/** The stdin value: one trailing newline (LF / CRLF) is dropped (guards against `echo`-sourced contamination). */
export function normalizeStdinValue(bytes: Uint8Array): Uint8Array {
  if (bytes.length > 0 && bytes[bytes.length - 1] === 0x0a) {
    const end = bytes.length > 1 && bytes[bytes.length - 2] === 0x0d ? -2 : -1;
    return bytes.slice(0, end);
  }
  return bytes;
}

/** Result of an accepted push. */
export interface PushedVersion {
  readonly variableId: string;
  readonly version: number;
  readonly epoch: number;
  /** SHOULD warnings collected during verification (a non-NFC name distribution, etc. — displayed by the caller). */
  readonly warnings: readonly string[];
}

/**
 * Encryption (fresh nonce) + the §4.1 value signature. The declared head is
 * the verified view's current head.
 *
 * Rotation re-encryption (env-rotate.ts) goes through the same
 * implementation: re-encryption is "a normal push the performer signs as
 * writer" (§7 / §4.1), and splitting the signed-object assembly across two
 * implementations would let only one of them lose the discipline.
 */
export function encryptAndSignPayload(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly variableId: string;
  readonly epoch: number;
  readonly version: number;
  readonly prevValueSigHashHex: string;
  readonly dek: Redacted.Redacted<Uint8Array>;
  readonly value: Redacted.Redacted<Uint8Array>;
  readonly writerUserId: string;
  readonly signingKey: CryptoKey;
}) {
  const context = {
    projectId: input.verified.projectId,
    environmentId: input.environmentId,
    epoch: input.epoch,
    variableId: input.variableId,
    version: input.version,
  };
  return Effect.gen(function* () {
    const encrypted = yield* Effect.tryPromise({
      // Why it is unwrapped: the input of encryption (plaintext →
      // ciphertext). The product is the ciphertext, so the unwrapped
      // plaintext never leaves this call
      try: () =>
        encryptVariable({
          dek: Redacted.value(input.dek),
          context,
          plaintext: Redacted.value(input.value),
        }),
      catch: () => cliError("Failed to encrypt the value"),
    });
    if (!encrypted.ok) {
      return yield* Effect.fail(cliError("Failed to encrypt the value"));
    }
    const nonceHex = encodeHex(encrypted.value.nonce);
    const ciphertextHex = encodeHex(encrypted.value.ciphertext);
    const signatureContext = {
      suite: SUITE_ID,
      ...context,
      nonceHex,
      ciphertextHex,
      prevValueSigHashHex: input.prevValueSigHashHex,
      writerUserId: input.writerUserId,
      chainHeadHashHex: input.verified.state.headHashHex,
      chainHeadSeq: input.verified.state.headSeq,
    } as const;
    const signature = yield* Effect.tryPromise({
      try: () => signValue({ context: signatureContext, signingKey: input.signingKey }),
      catch: () => cliError("Failed to create the value signature"),
    });
    if (!signature.ok) {
      return yield* Effect.fail(cliError("Failed to create the value signature"));
    }
    // The signed-bytes hash of my own signed object (promoted to the local
    // floor once accepted — a self-computed value, not the server's claim;
    // the same posture as the basis of the next version's prev)
    const signedBytesHash = yield* Effect.tryPromise({
      try: () => computeValueSignedBytesHash(signatureContext),
      catch: () => cliError("Failed to compute the value-signature signed-bytes hash"),
    });
    if (!signedBytesHash.ok) {
      return yield* Effect.fail(
        cliError("Failed to compute the value-signature signed-bytes hash"),
      );
    }
    return {
      payload: {
        suite: SUITE_ID,
        aad: context,
        nonceHex,
        ciphertextHex,
        prevValueSigHashHex: input.prevValueSigHashHex,
        chainHeadHashHex: input.verified.state.headHashHex,
        chainHeadSeq: input.verified.state.headSeq,
        signatureHex: signature.value,
      },
      signedBytesHashHex: signedBytesHash.value,
    } as const;
  });
}

interface AcceptedPush {
  readonly accepted: {
    readonly variableId: string;
    readonly version: number;
    readonly epoch: number;
  };
  /** The floor record of my accepted write (self-computed — not the server echo). */
  readonly floorVariable: VariableFloor;
  /**
   * Meta-operation paths (create / activate) only: the manifest I issued
   * (self-computed). **It is not promoted to the floor directly** — a meta
   * operation's success only holds once it passes the "effect confirmation
   * on a verifiable distributed object" (§12-10 (3)), and advancing the
   * floor's manifest is the job of the confirmation pull's verified
   * observation.
   */
  readonly selfManifest: ManifestFloor | null;
  /** Meta-operation paths only: the id of the intent (3-F) appended before sending. The effect confirmation closes it. */
  readonly intentId: string | null;
  /** The state at acceptance time (the source of the floor commit's head and variable ID). */
  readonly state: PushState;
}

/**
 * A rollback lands only as a normal push to the variable whose history was
 * verified, directly on top of the version the user confirmed (VH): a
 * (re-)resolution to a creation, an activation, another variable, or a newer
 * latest (a concurrent push — including the winner a 409 retry adopts) is
 * refused before anything is signed.
 */
function ensureRestoreTarget(input: PushInput, state: PushState): Effect.Effect<void, CliError> {
  const restore = input.restore;
  if (restore === undefined) {
    return Effect.void;
  }
  const target = state.target;
  if (target.kind !== "push" || target.variableId !== restore.variableId) {
    return Effect.fail(
      cliError(
        `The rollback target ${displayText(input.name)} no longer resolves to the variable whose history was verified (a concurrent delete, rename, or re-creation). Nothing was pushed — re-run the command`,
      ),
    );
  }
  if (
    target.latest.version !== restore.fromVersion ||
    target.latest.signedBytesHashHex !== restore.fromSignedBytesHashHex
  ) {
    return Effect.fail(
      cliError(
        `${displayText(input.name)} changed while the rollback was being prepared (the latest is now version ${target.latest.version}, not the confirmed version ${restore.fromVersion}). Nothing was pushed — check \`maruhi var history\` and re-run the command`,
      ),
    );
  }
  return Effect.void;
}

/**
 * Whether two in-memory plaintexts are byte-identical. Reason for
 * unwrapping: an equality check only — nothing is displayed and the bytes
 * never leave this comparison (shared by the lineage detection below and
 * `var rollback`'s no-op refusal).
 */
export function sameRedactedBytes(
  a: Redacted.Redacted<Uint8Array>,
  b: Redacted.Redacted<Uint8Array>,
): boolean {
  const [left, right] = [a, b].map(Redacted.value);
  return (
    left !== undefined &&
    right !== undefined &&
    left.length === right.length &&
    left.every((byte, index) => byte === right[index])
  );
}

/**
 * The value-lineage declaration of a normal push (AUTH_SPEC §12-5 — SHOULD):
 * a rollback declares the version it restores; otherwise, a value identical
 * to the verified latest declares that version (2026-09-27 VH re-check round
 * — re-pushing the same value, e.g. one first pushed before a mandated
 * rotation, is not a new value and must not look like one to rotation-needed
 * detection). The comparison runs only when this device holds the latest's
 * DEK; without it the push declares nothing (the pre-VH behaviour).
 */
function lineageOf(
  input: PushInput,
  state: PushState,
  latest: VerifiedPulledValue,
): Effect.Effect<number | undefined, CliError> {
  if (input.restore !== undefined) {
    return Effect.succeed(input.restore.sameValueAs);
  }
  if (!state.deks.has(latest.epoch)) {
    return Effect.succeed(undefined);
  }
  return Effect.map(
    decryptVerifiedValue({
      verified: state.verified,
      environmentId: input.environmentId,
      variable: latest,
      deksByEpoch: state.deks,
      chainEpoch: state.epoch,
    }),
    (current) => (sameRedactedBytes(current, input.value) ? latest.version : undefined),
  );
}

/** A normal push's body with the lineage declaration when there is one (AUTH_SPEC §12-5). */
function withLineage<T>(value: T, sameValueAs: number | undefined) {
  return sameValueAs === undefined ? { value } : { value, sameValueAs };
}

/** One attempt (encrypt, sign, send). The conflict classification is retryOnConflict's classify's job. */
function attemptOnce(input: PushInput, state: PushState): Effect.Effect<AcceptedPush, unknown> {
  return Effect.gen(function* () {
    yield* ensureRestoreTarget(input, state);
    const dek = state.deks.get(state.epoch);
    if (dek === undefined) {
      return yield* Effect.fail(
        cliError(
          `No DEK for the current epoch ${state.epoch} is registered for you (possibly awaiting a re-wrap after a rotation)`,
        ),
      );
    }
    const version = nextVersionOf(state.target);
    const signed = yield* encryptAndSignPayload({
      verified: state.verified,
      environmentId: input.environmentId,
      variableId: state.target.variableId,
      epoch: state.epoch,
      version,
      prevValueSigHashHex: prevHashOf(state.target),
      dek,
      value: input.value,
      writerUserId: input.writerUserId,
      signingKey: input.signingKey,
    });
    const valueFloor = {
      status: "active",
      version,
      epoch: state.epoch,
      valueSigHashHex: signed.signedBytesHashHex,
    } as const;
    const params = { projectId: state.verified.projectId, environmentId: input.environmentId };
    if (state.target.kind === "create") {
      // Creation = bundling the version-1 value + the metaVersion-1
      // statement + a manifest reflecting the post-creation set (§12-5).
      // The declared head is the same "last verified chain head" as the
      // value signature, and if a CAS retry advances the verified view all
      // three are rebuilt per attempt (the shared implementations of
      // meta-statement.ts / manifest.ts)
      const target = state.target;
      const issueBase = state.issueBase;
      if (issueBase === null) {
        return yield* Effect.fail(
          cliError(
            `Variable ${target.variableId} resolved as a creation without manifest material (internal inconsistency)`,
          ),
        );
      }
      const created = yield* signCreateStatement({
        verified: state.verified,
        environmentId: input.environmentId,
        target: { kind: "variable", variableId: target.variableId },
        name: input.name,
        authorUserId: input.writerUserId,
        signingKey: input.signingKey,
      });
      // The assigned variableId is randomly generated, so it cannot already
      // exist in the verified set. If it did, fail explicitly as an internal
      // inconsistency instead of swallowing it and dropping it from the
      // digest (which would surface as a server 422 with the cause far away)
      if (issueBase.entries.some((entry) => entry.variableId === target.variableId)) {
        return yield* Effect.fail(
          cliError(
            `Variable ${target.variableId} resolved as a creation but already exists in the verified statement set (internal inconsistency)`,
          ),
        );
      }
      // Manifest issuance + journal-before-send (3-F): append an intent
      // before sending a security-critical mutation (a meta operation —
      // §12-10). If persistence fails, do not send (fail-closed). What a
      // crash or lost response loses is not "the belief that it succeeded"
      // but "the record of the confirmation duty".
      const { manifest, intentId } = yield* issueManifestWithIntent({
        verified: state.verified,
        environmentId: input.environmentId,
        epoch: state.epoch,
        previous: issueBase.previous,
        entries: [
          ...issueBase.entries,
          {
            variableId: target.variableId,
            status: "active" as const,
            metaVersion: 1,
            metaSigHashHex: created.metaSigHashHex,
          },
        ],
        envMeta: issueBase.envMeta,
        issuerUserId: input.writerUserId,
        signingKey: input.signingKey,
        floor: input.floor,
        variableId: target.variableId,
      });
      const accepted = yield* input.client.variables
        .create({
          params,
          payload: {
            statement: created.statement,
            value: signed.payload,
            manifest: manifest.manifest,
          },
        })
        .pipe(
          // Refused in the server's own error body = the effect never
          // happened (decided) — close the intent (the shared callback of
          // floor-check.ts)
          Effect.tapError(rejectIntentOnServerRejection(input.floor, intentId)),
        );
      return {
        accepted,
        floorVariable: { ...valueFloor, metaVersion: 1, metaSigHashHex: created.metaSigHashHex },
        selfManifest: {
          manifestVersion: manifest.manifestVersion,
          epoch: manifest.epoch,
          manifestSigHashHex: manifest.manifestSigHashHex,
        },
        intentId,
        state,
      };
    }
    if (state.target.kind === "activate") {
      // activation (declared → active — §12-5): a composite of value
      // version 1 + a v2 statement with status active (metaVersion + 1) + a
      // manifest. name and the schema column take the declaration-time
      // values over byte-exact (a rename goes through the rename path — the
      // server enforces with 422 payload-mismatch. Schema changes go
      // through `maruhi schema set`)
      const target = state.target;
      const issueBase = state.issueBase;
      if (issueBase === null) {
        return yield* Effect.fail(
          cliError(
            `Variable ${target.variableId} resolved as an activation without manifest material (internal inconsistency)`,
          ),
        );
      }
      const activation = yield* signContinuationStatementV2({
        verified: state.verified,
        environmentId: input.environmentId,
        variableId: target.variableId,
        name: target.prev.name,
        schema: target.prev.schema,
        layoutVersion: target.prev.layoutVersion,
        status: "active",
        prev: {
          metaVersion: target.prev.metaVersion,
          metaSigHashHex: target.prev.metaSigHashHex,
        },
        authorUserId: input.writerUserId,
        signingKey: input.signingKey,
      });
      // The manifest replaces the declared entry with the post-activation shape (§4.3)
      const previousEntry = issueBase.entries.find(
        (entry) => entry.variableId === target.variableId,
      );
      if (previousEntry === undefined || previousEntry.status !== "declared") {
        return yield* Effect.fail(
          cliError(
            `Variable ${target.variableId} resolved as an activation but its declared entry is missing from the verified statement set (internal inconsistency)`,
          ),
        );
      }
      // An activation is also a meta-operation composite (§12-10 (1)) — manifest issuance + a 3-F intent
      const { manifest, intentId } = yield* issueManifestWithIntent({
        verified: state.verified,
        environmentId: input.environmentId,
        epoch: state.epoch,
        previous: issueBase.previous,
        entries: [
          ...issueBase.entries.filter((entry) => entry.variableId !== target.variableId),
          {
            variableId: target.variableId,
            status: "active" as const,
            metaVersion: target.prev.metaVersion + 1,
            metaSigHashHex: activation.metaSigHashHex,
          },
        ],
        envMeta: issueBase.envMeta,
        issuerUserId: input.writerUserId,
        signingKey: input.signingKey,
        floor: input.floor,
        variableId: target.variableId,
      });
      const accepted = yield* input.client.variables
        .activate({
          params: { ...params, variableId: target.variableId },
          payload: {
            value: signed.payload,
            statement: activation.statement,
            manifest: manifest.manifest,
          },
        })
        .pipe(Effect.tapError(rejectIntentOnServerRejection(input.floor, intentId)));
      return {
        accepted,
        floorVariable: {
          ...valueFloor,
          metaVersion: target.prev.metaVersion + 1,
          metaSigHashHex: activation.metaSigHashHex,
        },
        selfManifest: {
          manifestVersion: manifest.manifestVersion,
          epoch: manifest.epoch,
          manifestSigHashHex: manifest.manifestSigHashHex,
        },
        intentId,
        state,
      };
    }
    // A push to an existing variable changes no meta — the floor's meta record stays the verified latest
    const latest = state.target.latest;
    // A value push to an existing variable is out of 1-E′ / 3-F scope
    // (§12-10 (3) — the only distributed object usable for effect
    // confirmation is a value pull, which would bring var.read auditing
    // into the write path). Success is carried by the server's CAS + value
    // signature verification and our own floor's commitPush, as before
    const sameValueAs = yield* lineageOf(input, state, latest);
    const accepted = yield* input.client.variables.push({
      params: { ...params, variableId: state.target.variableId },
      payload: withLineage(signed.payload, sameValueAs),
    });
    return {
      accepted,
      floorVariable: {
        ...valueFloor,
        metaVersion: latest.metaVersion,
        metaSigHashHex: latest.metaSignedBytesHashHex,
      },
      selfManifest: null,
      intentId: null,
      state,
    };
  });
}

/**
 * The effect confirmation of a variable creation / activation (a meta
 * operation) (AUTH_SPEC §12-10 (3) — 1-E′). The shared implementation is
 * meta-confirm.ts — the only path difference is "how the effect looks when
 * the version advanced": creation = the existence of my variableId
 * (randomly assigned — nobody else can generate it), activation = the
 * existence of a statement / tombstone at or above the issued metaVersion
 * (don't misread the shape where a different hash won at the same issued
 * version — a 2xx lost to a concurrent activation — as the effect having
 * landed).
 */
function confirmPushMetaMutation(input: {
  readonly push: PushInput;
  readonly accepted: AcceptedPush;
  readonly selfManifest: ManifestFloor;
}): Effect.Effect<void, CliError> {
  const target = input.accepted.state.target;
  const variableId = target.variableId;
  const issued = input.accepted.floorVariable;
  // A statement at the same version as the issued one must match my hash
  // (same version, different hash = the shape of having lost to a
  // concurrent activation — don't misread it as the effect having landed).
  // A shape advanced past the issued version cannot have its ancestry
  // checked under the latest-only known constraint (the same class of
  // leftover as the create path's "existence of a random ID" — §14.3)
  const statementConfirms = (statement: {
    readonly metaVersion: number;
    readonly metaSigHashHex: string;
  }) =>
    statement.metaVersion > issued.metaVersion ||
    (statement.metaVersion === issued.metaVersion &&
      statement.metaSigHashHex === issued.metaSigHashHex);
  return confirmMetaMutation({
    client: input.push.client,
    verified: input.accepted.state.verified,
    environmentId: input.push.environmentId,
    resync: input.push.resync,
    floor: input.push.floor,
    selfManifest: input.selfManifest,
    intentId: input.accepted.intentId,
    describe: target.kind === "activate" ? "variable activation" : "variable creation",
    effectVisible: (metadata) =>
      target.kind === "create"
        ? metadata.variables.some((statement) => statement.variableId === variableId) ||
          metadata.tombstones.some((tombstone) => tombstone.variableId === variableId)
        : metadata.variables.some(
            (statement) => statement.variableId === variableId && statementConfirms(statement),
          ) ||
          metadata.tombstones.some(
            (tombstone) => tombstone.variableId === variableId && statementConfirms(tombstone),
          ),
  });
}

/**
 * Pushes one variable value: resolve the target by display name through the
 * verified metadata statements of a metadata-only pull (§4.2 / §12-7 — the
 * lookup key is NFC-normalized, matching is byte-exact; only a push to an
 * existing variable fetches values, so a creation is never recorded as a
 * `var.read`), encrypt under the
 * chain-derived current epoch with a commitment-verified DEK, sign as the
 * caller (§4.1: prev = the verified latest value's signed-bytes hash, head =
 * the last verified chain head; creation additionally author-signs a
 * metaVersion-1 statement), and retry through the CAS conflicts (§12-5).
 * The chain — not the server's claim — stays the epoch authority.
 *
 * A variable creation only counts as successful after passing the 1-E′
 * effect confirmation (confirmVariableCreation) (§12-10 (3) — recording to
 * the floor and reporting success to the user happen only after the
 * confirmation passes).
 */
export function pushVariable(input: PushInput): Effect.Effect<PushedVersion, CliError> {
  return Effect.gen(function* () {
    // The client is the one performing normalization, before signing
    // (§4.2 / §12-1): both the lookup key and the name signed on creation
    // are put in NFC normal form
    const normalized: PushInput = { ...input, name: input.name.normalize("NFC") };
    const initial = yield* initialState(normalized);
    const outcome = yield* retryOnConflict(initial, {
      maxAttempts: MAX_ATTEMPTS,
      attempt: (state) => attemptOnce(normalized, state),
      classify: classifyPushConflict,
      recover: (state, conflict) => nextState(normalized, state, conflict),
      exhaustedMessage: `The push conflict did not resolve (after ${MAX_ATTEMPTS} attempts). Wait a moment and re-run the command`,
    });
    const acceptedState = outcome.state;
    if (outcome.selfManifest !== null) {
      // The definition of success for a meta operation (variable creation
      // / activation) = effect confirmation on a verifiable distributed
      // object (1-E′). **Recording to the floor happens only after the
      // confirmation passes** (§12-10 (3)): planting my own write into the
      // floor on 2xx alone would, if the server never actually stored it,
      // leave the floor demanding a variable that is never distributed =
      // every later pull permanently refused as variable-omitted (an
      // unconfirmed belief turning into equivocation evidence). The same
      // discipline as env create writing the v1 floor only after
      // confirmation
      yield* confirmPushMetaMutation({
        push: normalized,
        accepted: outcome,
        selfManifest: outcome.selfManifest,
      });
    }
    // Promote my accepted write into the floor (§6.3 — later pulls can
    // then detect even a rollback of my own write. journal-before-release:
    // before reporting success). A value push to an existing variable is
    // out of 1-E′ scope, so immediately after acceptance = here; a creation
    // comes after the effect confirmation above. The rule (c) baseline does
    // not move. Since the push itself was accepted, a floor write failure
    // is reported as such
    yield* input.floor
      .commitPush(
        // The floor key is the variable ID I signed (the server echo is not trusted)
        acceptedState.target.variableId,
        outcome.floorVariable,
        {
          seq: acceptedState.verified.state.headSeq,
          hashHex: acceptedState.verified.state.headHashHex,
        },
      )
      .pipe(Effect.mapError((error) => cliError(`The push was accepted, but ${error.message}`)));
    // The coordinates reported as success are **the locally signed values**
    // (the same posture as the floor update). The server echo is used only
    // for cross-checking, and a disagreement surfaces as a typed error
    // (promoting the echo into the display would let the user cite
    // server-claimed coordinates as fact)
    const floorVariable = outcome.floorVariable;
    if (floorVariable.status !== "active") {
      // attemptOnce always builds an active floor record — reaching here is an internal inconsistency
      return yield* Effect.fail(
        cliError("The accepted push produced a non-active floor record (internal inconsistency)"),
      );
    }
    const local = {
      variableId: acceptedState.target.variableId,
      version: floorVariable.version,
      epoch: floorVariable.epoch,
    };
    const echo = outcome.accepted;
    if (
      echo.variableId !== local.variableId ||
      echo.version !== local.version ||
      echo.epoch !== local.epoch
    ) {
      return yield* Effect.fail(
        cliError(
          // An existing variable's variableId comes from a
          // server-distributed meta-statement (no character-set check beyond
          // non-empty), so the local side is also neutralized for display
          `The push was accepted and recorded locally as ${displayText(local.variableId)} version=${local.version} epoch=${local.epoch}, but the server's response echoes different coordinates (${displayText(echo.variableId)} version=${echo.version} epoch=${echo.epoch}). The locally signed values are authoritative — verify the server with maruhi pull`,
        ),
      );
    }
    return { ...local, warnings: acceptedState.warnings };
  });
}
