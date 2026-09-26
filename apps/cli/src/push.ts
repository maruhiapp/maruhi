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
//   name are refused by the verification side (values.ts)
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

import {
  ActivationRequiredError,
  EpochConflictError,
  ManifestVersionConflictError,
  MetaVersionConflictError,
  type RecipientDek,
  VariableConflictError,
  VersionConflictError,
} from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import {
  computeValueSignedBytesHash,
  encodeHex,
  encryptVariable,
  signValue,
  SUITE_ID,
} from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

import type { MaruhiClient } from "./api.ts";
import { type DekRecipient, environmentKeysFor } from "./deks.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import {
  type FloorHandle,
  rejectIntentOnServerRejection,
  type VerifiedSchemaFields,
} from "./floor-check.ts";
import type { ManifestFloor, VariableFloor } from "./floor.ts";
import { confirmMetaMutation, issueManifestWithIntent } from "./meta-confirm.ts";
import { generateVariableId, signCreateStatement } from "./meta-statement.ts";
import { retryOnConflict } from "./retry.ts";
import { signContinuationStatementV2 } from "./schema-statement.ts";
import { resyncExtended, type VerifiedProject } from "./sync.ts";
import {
  type ManifestIssueBase,
  manifestIssueBaseOf,
  pullVerifiedEnvironment,
  pullVerifiedEnvironmentMetadata,
  type VerifiedPulledValue,
} from "./values.ts";

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

/** The predecessor-statement material of an activation (declared → active — §12-5). */
interface ActivationPrev {
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
  /** The name at declaration time (an activation never doubles as a rename — the server enforces with 422, §12-5). */
  readonly name: string;
  /** The schema column at declaration time (an activation takes it over byte-exact — the partial-update principle). */
  readonly schema: VerifiedSchemaFields;
}

/**
 * The 3 shapes of a push target (§12-5): creation (a composite of value
 * version 1 + metaVersion 1), activation (the first value push onto a
 * declared variable — a composite of value version 1 + a v2 statement with
 * status active [metaVersion + 1] + a manifest), and a normal push onto an
 * existing active variable (meta untouched).
 */
type PushTarget =
  | { readonly kind: "create"; readonly variableId: string }
  | { readonly kind: "activate"; readonly variableId: string; readonly prev: ActivationPrev }
  | { readonly kind: "push"; readonly variableId: string; readonly latest: VerifiedPulledValue };

function nextVersionOf(target: PushTarget): number {
  // create and activate both write the first value (a declared variable has no value or version — §4.2)
  return target.kind === "push" ? target.latest.version + 1 : 1;
}

function prevHashOf(target: PushTarget): string {
  return target.kind === "push" ? target.latest.signedBytesHashHex : "";
}

interface ResolvedTarget {
  readonly target: PushTarget;
  /** A view that may have advanced during pull verification (the bounded resync of a future head). */
  readonly verified: VerifiedProject;
  readonly warnings: readonly string[];
  /**
   * The bundled DEK of the value-carrying pull made while resolving an
   * existing active variable (null for a create / activate resolution — a
   * declared variable has no value and needs no value-carrying pull). A raw
   * wire shape, on the premise that it is verified and unwrapped under the
   * same view as verified (§12-7 — eliminating the double fetch with
   * listMine: session-11 ruling 3).
   */
  readonly deks: readonly RecipientDek[] | null;
  /** create / activate paths only: the issuing material of the bundled manifest (null on a normal push). */
  readonly issueBase: ManifestIssueBase | null;
}

/**
 * Resolves the push target from a display name. The resolution is a
 * byte-exact comparison against the verified statements of a metadata-only
 * pull (§12-7 — it carries no values or DEKs, so the server records no
 * var.read) (the lookup key is already NFC-normalized by the caller —
 * §12-1; duplicate same-name actives are already refused by the
 * verification side).
 *
 * A value-carrying pull runs only when the target turns out to be an
 * existing variable: the prev chain (§4.1) needs the verified latest
 * value's signed-bytes hash, which cannot be computed without fetching the
 * ciphertext (var.read is correctly recorded for this fetch). A creation
 * reads no value at all (prev is empty, version 1), so no var.read is
 * recorded — the CLI side of "don't record as read what was never read"
 * (session-11 ruling 3).
 */
function resolveTarget(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly name: string;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** The local floor (§6.3 — the verified pulls used for resolution also go through the floor check [plus a floor commit for the value-carrying one]). */
  readonly floor: FloorHandle;
}): Effect.Effect<ResolvedTarget, CliError> {
  return Effect.gen(function* () {
    const metadata = yield* pullVerifiedEnvironmentMetadata(input);
    // A duplicate same-name pair (whether active / declared) is already
    // refused by the verification side, but kept as a defensive line so the
    // push-target identification does not depend on the response ordering
    // (§4.2's resolution refusal)
    const matches = metadata.variables.filter((variable) => variable.name === input.name);
    if (matches.length > 1) {
      return yield* Effect.fail(
        cliError(
          `Multiple live statements with the same name passed verification (server equivocation): ${input.name}. Refusing to resolve the push target`,
        ),
      );
    }
    // The material of the bundled manifest (§12-5) for a meta operation
    // (create / activate) (from the verified metadata pull). A push to an
    // existing active variable issues no manifest (the issuing triggers are
    // limited — §4.3), so its resolution sets issueBase to null
    const issueBase = manifestIssueBaseOf(metadata);
    const existing = matches[0];
    if (existing === undefined) {
      return {
        target: { kind: "create", variableId: generateVariableId() },
        verified: metadata.verified,
        warnings: metadata.warnings,
        deks: null,
        issueBase,
      };
    }
    if (existing.status === "declared") {
      // The first value push onto a declared variable = the activation
      // composite (§12-5). Since no value exists, no value-carrying pull is
      // made (don't pollute var.read — don't let an unread value be recorded
      // as read). The schema column and name take the declaration-time
      // values over byte-exact (a rename goes through the rename path — the
      // server enforces with 422 payload-mismatch)
      if (existing.schema === null) {
        // declared is layout-v2-only (§4.2) — a v1 declared is already refused at the verification stage
        return yield* Effect.fail(
          cliError(
            `Variable ${existing.variableId} is declared but carries no schema fields (internal inconsistency)`,
          ),
        );
      }
      return {
        target: {
          kind: "activate",
          variableId: existing.variableId,
          prev: {
            metaVersion: existing.metaVersion,
            metaSigHashHex: existing.metaSigHashHex,
            name: existing.name,
            schema: existing.schema,
          },
        },
        verified: metadata.verified,
        warnings: metadata.warnings,
        deks: null,
        issueBase,
      };
    }
    const pulled = yield* pullVerifiedEnvironment({ ...input, verified: metadata.verified });
    const latest = pulled.variables.find((variable) => variable.variableId === existing.variableId);
    if (latest === undefined) {
      // A concurrent deletion between resolution and value fetch, or an
      // inconsistency across responses (an omission is per-variable evidence
      // at the floor check too). Refuse explicitly instead of falling back
      // to a creation with a wrong prev
      return yield* Effect.fail(
        cliError(
          `The resolved variable ${existing.variableId} (${input.name}) is missing from the value-carrying pull (a concurrent deletion by another member, or an inconsistent server response). Re-run the command`,
        ),
      );
    }
    if (latest.name !== input.name) {
      // A concurrent rename between resolution and value fetch. Never aim a
      // push at a variable that moved to a name different from the input.
      // latest.name is the verified statement's name (§12-2), so a
      // byte-exact comparison suffices
      return yield* Effect.fail(
        cliError(
          `The resolved variable ${existing.variableId} was renamed from ${displayText(input.name)} to ${displayText(latest.name)} before the value fetch (a concurrent rename by another member). Re-run the command`,
        ),
      );
    }
    return {
      target: { kind: "push", variableId: existing.variableId, latest },
      verified: pulled.verified,
      warnings: [...metadata.warnings, ...pulled.warnings],
      deks: pulled.deks,
      // A push to an existing active variable changes no meta state = issues no manifest (§4.3)
      issueBase: null,
    };
  });
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

type PushConflict =
  | { readonly kind: "version-conflict"; readonly currentVersion: number }
  | { readonly kind: "epoch-conflict" }
  | { readonly kind: "variable-conflict" };

/** The retryable classification of CAS conflicts (§12-5). Anything else is null (a terminal error). */
function classifyPushConflict(error: unknown): PushConflict | null {
  if (error instanceof VersionConflictError) {
    return { kind: "version-conflict", currentVersion: error.currentVersion };
  }
  if (error instanceof EpochConflictError) {
    return { kind: "epoch-conflict" };
  }
  if (
    error instanceof VariableConflictError ||
    error instanceof MetaVersionConflictError ||
    error instanceof ManifestVersionConflictError ||
    error instanceof ActivationRequiredError
  ) {
    // A create's name conflict / metaVersion conflict (concurrent creation,
    // concurrent rename) / manifestVersion conflict (a concurrent meta
    // operation — §12-5 (6)) is re-resolved from the name (§12-5's retry =
    // re-fetch → verify → re-sign both the statement and the manifest. An
    // ID conflict effectively never happens with random IDs).
    // ActivationRequired (a normal push hit a declared variable — §12-5) is
    // not a resync but a switch-to-activation signal: the re-resolution sees
    // the declared variable and switches to the activation composite
    // (design doc §3 row S3)
    return { kind: "variable-conflict" };
  }
  return null;
}

interface PushInput {
  readonly client: MaruhiClient;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
  readonly name: string;
  readonly value: Redacted.Redacted<Uint8Array>;
  readonly verified: VerifiedProject;
  /** The resync (full chain re-verification). The caller runs it through resyncExtended's extension check. */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** The writer of the value signature (my internal user_id) and the master sig key (§4.1). */
  readonly writerUserId: string;
  readonly signingKey: CryptoKey;
  /** The local floor (§6.3 — the check and commit of internal pulls, and the variable-floor advance after acceptance). */
  readonly floor: FloorHandle;
}

interface PushState {
  readonly verified: VerifiedProject;
  readonly epoch: number;
  readonly deks: ReadonlyMap<number, Redacted.Redacted<Uint8Array>>;
  readonly target: PushTarget;
  /** create / activate paths only: the issuing material of the bundled manifest (reresolveTarget re-fetches it). */
  readonly issueBase: ManifestIssueBase | null;
  readonly warnings: readonly string[];
}

function initialState(input: PushInput): Effect.Effect<PushState, CliError> {
  return Effect.gen(function* () {
    const resolved = yield* resolveTarget(input);
    const verified = resolved.verified;
    // The current epoch (the chain-derived value — §6.2; a push against an
    // uncreated environment stops here) and the DEK set are derived together
    // from the same verified view (deks.ts's environmentKeysFor). The DEK is
    // fetched exactly once per path (session-11 ruling 3's double-fetch
    // elimination): for an existing variable the bundled share of the
    // value-carrying pull (prefetched) is verified and unwrapped / for a
    // creation, listMine
    const keys = yield* environmentKeysFor({
      client: input.client,
      verified,
      environmentId: input.environmentId,
      recipient: input.recipient,
      prefetched: resolved.deks,
    });
    return {
      verified,
      epoch: keys.currentEpoch,
      deks: keys.deksByEpoch,
      target: resolved.target,
      issueBase: resolved.issueBase,
      warnings: resolved.warnings,
    };
  });
}

/** One attempt (encrypt, sign, send). The conflict classification is retryOnConflict's classify's job. */
function attemptOnce(input: PushInput, state: PushState): Effect.Effect<AcceptedPush, unknown> {
  return Effect.gen(function* () {
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
    const accepted = yield* input.client.variables.push({
      params: { ...params, variableId: state.target.variableId },
      payload: { value: signed.payload },
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

/** Re-fetches the DEK set only when the epoch changed (or is first seen) (the cached semantics). */
function refreshEpochState(
  input: PushInput,
  state: PushState,
  verified: VerifiedProject,
): Effect.Effect<Pick<PushState, "verified" | "epoch" | "deks">, CliError> {
  return Effect.map(
    environmentKeysFor({
      client: input.client,
      verified,
      environmentId: input.environmentId,
      recipient: input.recipient,
      cached: state.deks,
    }),
    (keys) => ({ verified, epoch: keys.currentEpoch, deks: keys.deksByEpoch }),
  );
}

/**
 * The winner's consistency check against the verified known latest (the
 * value that passed this session's §6.3 verification): regression,
 * equivocation, and chain integrity. On an honest server latest_version is
 * monotonically increasing (no per-version-row deletion; a variable
 * deletion is tombstone + delete-all-rows = 404 from then on), so every
 * regression is evidence of a rollback or equivocation — no false
 * rejection.
 */
function winnerValueRegression(
  variableId: string,
  known: VerifiedPulledValue,
  winner: VerifiedPulledValue,
  currentVersion: number,
): string | null {
  if (currentVersion < known.version || winner.version < known.version) {
    // A regression from this session's verified latest = evidence of a
    // rollback. Adopting it and re-pointing prev would chain my own
    // signature onto a rolled-back branch
    return `The 409 response / re-fetch for variable ${variableId} (version ${Math.min(currentVersion, winner.version)}) is older than the verified latest (version ${known.version}) — evidence of a version rollback`;
  }
  if (winner.version === known.version && winner.signedBytesHashHex !== known.signedBytesHashHex) {
    // Two valid signatures with different content at the same coordinates = cryptographic evidence of equivocation
    return `Variable ${variableId} version ${winner.version} was served with signed bytes different from the verified value (evidence of server equivocation)`;
  }
  // Epoch monotonicity (§4.1) is transitive, so once the winner is newer
  // than the verified latest, epoch non-decrease is required regardless of
  // version-number gaps (review loop 2 [low] — closes an old-epoch
  // injection that bypasses the adjacent check via version-number choice).
  // An honest server is epoch-non-decreasing in acceptance order, so no
  // false rejection
  if (winner.version > known.version && winner.epoch < known.epoch) {
    return `Variable ${variableId} version ${winner.version} has an epoch (${winner.epoch}) that regressed from the verified predecessor version's (${known.epoch}) — an epoch-monotonicity violation (§4.1)`;
  }
  // When the adjacent predecessor is held, §6.3-6's prev-existence match
  // can be checked for free (review loop 1 [medium] — the exception to
  // pull's latest-only constraint)
  if (
    winner.version === known.version + 1 &&
    winner.prevValueSigHashHex !== known.signedBytesHashHex
  ) {
    return `Variable ${variableId} version ${winner.version} has a prev that does not match the verified predecessor version's signed-bytes hash (chaining onto a diverged history — evidence of equivocation)`;
  }
  return null;
}

/**
 * The meta-side same-shape rollback / fork check (§12-5's meta-retry
 * discipline; the PR-3 extension of the value side's
 * winnerValueRegression): refuses a regression from the verified latest
 * metaVersion and different signed bytes at the same metaVersion =
 * equivocation. On an honest server latest_meta_version is also
 * monotonically increasing (no per-statement-row deletion), so no false
 * rejection.
 */
function winnerMetaRegression(
  variableId: string,
  known: VerifiedPulledValue,
  winner: VerifiedPulledValue,
): string | null {
  if (winner.metaVersion < known.metaVersion) {
    return `The re-fetched statement for variable ${variableId} (metaVersion ${winner.metaVersion}) is older than the verified latest (metaVersion ${known.metaVersion}) — evidence of a metadata rollback`;
  }
  if (
    winner.metaVersion === known.metaVersion &&
    winner.metaSignedBytesHashHex !== known.metaSignedBytesHashHex
  ) {
    return `Variable ${variableId} metaVersion ${winner.metaVersion} was served with signed bytes different from the verified statement (evidence of server equivocation)`;
  }
  // When the adjacent predecessor is held, the prev-chain match can be
  // checked for free (the same shape as winnerValueRegression's §6.3-6
  // check — review ② [minor])
  if (
    winner.metaVersion === known.metaVersion + 1 &&
    winner.prevMetaSigHashHex !== known.metaSignedBytesHashHex
  ) {
    return `Variable ${variableId} metaVersion ${winner.metaVersion} has a prev that does not match the verified predecessor metaVersion's signed-bytes hash (chaining onto a diverged history — evidence of equivocation)`;
  }
  return null;
}

function winnerRegression(
  variableId: string,
  known: VerifiedPulledValue,
  winner: VerifiedPulledValue,
  currentVersion: number,
): string | null {
  return (
    winnerValueRegression(variableId, known, winner, currentVersion) ??
    winnerMetaRegression(variableId, known, winner)
  );
}

/**
 * The consistency check of a 409 winner (§12-5). null = adoptable,
 * non-null = the reason to refuse.
 *
 * The checks are 2-layered: (1) consistency across responses (the
 * re-fetched latest being older than a version known to exist = the server
 * contradicting itself), (2) regression from the verified known latest,
 * different signed bytes at the same coordinates, and a mismatched
 * adjacent prev. **Rotation re-encryption (env-rotate.ts) also goes
 * through this check**: re-pointing prev at the winner is the same shape
 * as the push path, and letting just one side chain-sign onto a diverged
 * history would open a hole that relies on the floor (a SHOULD, absent on
 * first sync).
 *
 * `currentVersion` comes from different places per path (push = the 409's
 * claim; rotation = the 409's claim or **a version I got accepted**), so
 * the wording is unified as "the known latest".
 */
export function winnerInconsistency(
  variableId: string,
  known: VerifiedPulledValue | null,
  winner: VerifiedPulledValue,
  currentVersion: number,
): string | null {
  if (winner.version < currentVersion) {
    // Only values older than the latest the 409 claimed are distributed = an inconsistency across responses
    return `The re-fetched pull's latest version (${winner.version}) is older than the known latest version (${currentVersion}) — inconsistent (the server response contradicts itself)`;
  }
  return known === null ? null : winnerRegression(variableId, known, winner, currentVersion);
}

/**
 * The winner re-fetch after a 409 VersionConflict (§12-5's retry
 * procedure): re-fetch the bulk pull, identify the winner by its stable
 * id, verify it, and re-point prev at its signed-bytes hash. The 409
 * response is never asked for the winner's hash.
 */
function adoptConflictWinner(
  input: PushInput,
  state: PushState,
  currentVersion: number,
): Effect.Effect<PushState, CliError> {
  return Effect.gen(function* () {
    const pulled = yield* pullVerifiedEnvironment({
      client: input.client,
      verified: state.verified,
      environmentId: input.environmentId,
      resync: input.resync,
      floor: input.floor,
    });
    const winner = pulled.variables.find(
      (variable) => variable.variableId === state.target.variableId,
    );
    if (winner === undefined) {
      return yield* Effect.fail(
        cliError(
          `The version-conflict winner (variable ${state.target.variableId}) is missing from the re-fetched pull (a concurrent deletion by another member, or an inconsistent server response)`,
        ),
      );
    }
    const inconsistency = winnerInconsistency(
      state.target.variableId,
      state.target.kind === "push" ? state.target.latest : null,
      winner,
      currentVersion,
    );
    if (inconsistency !== null) {
      return yield* Effect.fail(cliError(inconsistency));
    }
    const refreshed = yield* refreshEpochState(input, state, pulled.verified);
    return {
      ...refreshed,
      target: { kind: "push", variableId: state.target.variableId, latest: winner },
      // Adopting the winner = a push to an existing variable (meta state unchanged — no manifest issued)
      issueBase: null,
      warnings: [...state.warnings, ...pulled.warnings],
    };
  });
}

function reresolveTarget(input: PushInput, state: PushState): Effect.Effect<PushState, CliError> {
  return Effect.gen(function* () {
    const resolved = yield* resolveTarget({ ...input, verified: state.verified });
    // The re-resolution's DEK prefers the on-hand set of a known epoch and
    // is re-fetched only when the epoch advanced (refreshEpochState).
    // resolved.deks is for the first resolution only — don't redo the
    // unwrapping on the rare path of a conflict retry
    const refreshed = yield* refreshEpochState(input, state, resolved.verified);
    return {
      ...refreshed,
      target: resolved.target,
      issueBase: resolved.issueBase,
      warnings: [...state.warnings, ...resolved.warnings],
    };
  });
}

/**
 * Recovery from a conflict (the domain-specific part of §12-5's retry
 * procedure). Runs as retryOnConflict's recover — and also after the last
 * attempt (surfacing the terminal errors: equivocation evidence and
 * contradictions between the server response and the chain).
 */
function nextState(
  input: PushInput,
  state: PushState,
  outcome: PushConflict,
): Effect.Effect<PushState, CliError> {
  switch (outcome.kind) {
    case "version-conflict":
      // A VersionConflict on the create path means "a concurrent creation
      // happened"; on the activate path it means "a value version 1 landed
      // first via a concurrent activation" (my send was not stored). Both
      // are re-resolved from the name (a variable the re-resolution sees as
      // active enters the normal push path — the winner is verified via a
      // value-carrying pull)
      if (state.target.kind !== "push") {
        return reresolveTarget(input, state);
      }
      return adoptConflictWinner(input, state, outcome.currentVersion);
    case "epoch-conflict":
      // The epoch's source of truth is the chain (§6.3). Resync with the
      // extension check and use the derived value, and get the
      // commitment-verified DEK of the new epoch. prev stays the verified
      // predecessor hash (the value has not changed — if it had, the next
      // attempt becomes a VersionConflict and enters the procedure above)
      return Effect.gen(function* () {
        const verified = yield* resyncExtended(input.resync, state.verified);
        // The current epoch and DEKs are derived together from the same
        // resync view (no re-fetch when the on-hand verified set already
        // has the current epoch — environmentKeysFor's cached)
        const keys = yield* environmentKeysFor({
          client: input.client,
          verified,
          environmentId: input.environmentId,
          recipient: input.recipient,
          cached: state.deks,
        });
        if (keys.currentEpoch === state.epoch) {
          // If the chain-derived epoch is unchanged after resyncing, the
          // server's EpochConflict claim contradicts the chain (a retry
          // cannot resolve it)
          return yield* Effect.fail(
            cliError(
              `The server reported an epoch conflict, but the chain-derived current epoch is still ${keys.currentEpoch} (the server response contradicts the chain)`,
            ),
          );
        }
        return { ...state, verified, epoch: keys.currentEpoch, deks: keys.deksByEpoch };
      });
    case "variable-conflict":
      return reresolveTarget(input, state);
  }
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
