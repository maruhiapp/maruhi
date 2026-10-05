// Bulk pull and decryption (AUTH_SPEC §12-7 + CRYPTO_SPEC §4.1 / §5.1 /
// §5.2).
//
// Verification order (§6.3): (1) verify every value's value signature
// before decryption (values.ts — including the bounded resync on a
// future head), (2) the §5.1 registration signature + §5.2 DEK
// commitment match of one's own wraps (deks.ts), (3) AES-GCM decryption.
// The decryption context (AAD) never trusts the declared `aad` — it is
// assembled from verified coordinates (the genesis hash, the requested
// environment, the response metadata's variableId) (session-07 §5 /
// session-14 ruling G).
//
// Plaintext lives only in in-memory Uint8Arrays. No path in this module
// writes it to disk (the diskless invariant). The decryption's product
// is wrapped in `Redacted` so it never flows raw into logs, errors, or
// template expansion (unwrapped only just before injection = run.ts,
// behind the display gate = display.ts, or at the crypto boundary =
// push.ts).

import type { EnvironmentId } from "@maruhi/core";
import { cryptoEffect } from "@maruhi/core";
import type { MetaVarType, SigningKeyPair } from "@maruhi/crypto";
import { decodeHex, decryptVariable } from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { VerifiedProject } from "./chain-sync.ts";
import { type DekRecipient, environmentKeysFor, missingEpochsOf } from "./deks.ts";
import {
  describeMissingOwnEpochs,
  fillOwnDeviceGaps,
  type OwnDeviceGapFill,
} from "./device-gaps.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import type { FloorHandle, VerifiedVariableStatement } from "./floor-check.ts";
import { requireEnvironmentInScope } from "./scope.ts";
import type { VerifiedPulledValue } from "./values-verify.ts";
import { pullVerifiedEnvironment } from "./values.ts";

/** One decrypted variable (plaintext bytes live in memory only). */
export interface DecryptedVariable {
  /** The name from the verified meta statement (§4.2 — never trust a bare name). */
  readonly variableId: string;
  readonly name: string;
  readonly version: number;
  readonly epoch: number;
  /**
   * The declared type (the schema column of §4.2 layout v2. v1 /
   * unspecified = ""). Used only by the advisory type check just before
   * injection (run.ts — §14.3-7: the check warns but the run continues).
   */
  readonly varType: MetaVarType;
  /** The required declaration (layout v2's schema column. v1 = false). Used by `maruhi sync`'s completeness check. */
  readonly required: boolean;
  /**
   * The max age the schema declares (layout v3 — PF6 R9; null = none).
   * Input of the point-of-use note of `maruhi run` / `pull` (max-age.ts).
   */
  readonly maxAgeDays: number | null;
  /** The plaintext bytes (memory only. Unwrapped only in run / show / re-encryption). */
  readonly value: Redacted.Redacted<Uint8Array>;
}

/**
 * One declared variable (a schema-only declaration with no value —
 * CRYPTO_SPEC §4.2 layout v2). Material for `maruhi run` / `ci run`'s
 * presence check (required strict — §14.2-8). Carries no description
 * (the fail-fast error wording never includes the description —
 * session-46 §8 turn 3).
 */
export interface DeclaredVariable {
  readonly variableId: string;
  readonly name: string;
  readonly required: boolean;
  readonly varType: MetaVarType;
}

/** The decrypted variables, declared declarations, and the SHOULD warnings collected during verification (non-NFC name distribution etc.). */
export interface PulledVariables {
  /** The view used for verification (it may have advanced via the future head's bounded resync). Later writes inherit it. */
  readonly verified: VerifiedProject;
  readonly variables: readonly DecryptedVariable[];
  /** The verified declared (valueless — outside injection scope. The presence check is the caller's). */
  readonly declared: readonly DeclaredVariable[];
  readonly warnings: readonly string[];
  /** Filling the missing epochs of the same person's other devices (only when `fillOwnDeviceGaps` is passed — DK K11). */
  readonly ownDeviceGapFills: readonly OwnDeviceGapFill[];
}

/**
 * Verified declared statements → the presence check's material. declared
 * is layout v2-only (§4.2 — a v1 declared was already refused at the
 * verification stage) so a schema always rides along, but a null on the
 * type is treated as required = true, fail-closed (never let a missing
 * required collapse into "pass through without injecting").
 */
export function toDeclaredVariables(
  statements: readonly VerifiedVariableStatement[],
): readonly DeclaredVariable[] {
  return statements.map((statement) => ({
    variableId: statement.variableId,
    name: statement.name,
    required: statement.schema?.required ?? true,
    varType: statement.schema?.varType ?? "",
  }));
}

/**
 * The reason sentence for "no wrap for that epoch was addressed to me".
 * Placed on **the side that builds the decryption's failure reason** and
 * shared with the caller (env-rotate's warning): env rotate tells a
 * "benign gap" apart by this wording and dedupes via `dedupeWarnings`
 * (an exact-match set), so writing it in two places would print the same
 * variable's warning twice the moment one side is fixed.
 */
export function missingWrapReason(variable: {
  readonly name: string;
  readonly epoch: number;
}): string {
  return `No DEK for epoch ${variable.epoch} of variable ${displayText(variable.name)} was distributed (your wrap is missing)`;
}

/**
 * Decrypts one already-verified value (values.ts's product, passed
 * through §6.3). The decryption context (AAD) coordinates are assembled
 * from verified values (the genesis hash, the requested environment, the
 * response-outer variableId), not the declared `aad`. epoch / version
 * are the declared values verified by the value signature (bound to
 * these coordinates).
 *
 * Why a shared point: `maruhi run`'s pull and `maruhi env rotate`'s
 * re-encryption must decrypt by the same discipline (a fork into two
 * decryption paths would silently regress — one side would lose the
 * self-built coordinates and the epoch cap check).
 */
export function decryptVerifiedValue(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly variable: VerifiedPulledValue;
  readonly deksByEpoch: ReadonlyMap<number, Redacted.Redacted<Uint8Array>>;
  /** The chain-derived current epoch (the declared epoch's cap — the defense line against a derivation inconsistency). */
  readonly chainEpoch: number;
}): Effect.Effect<Redacted.Redacted<Uint8Array>, CliError> {
  return Effect.gen(function* () {
    const variable = input.variable;
    // The value signature's verification (§6.3-4) already guarantees
    // "the current epoch at declared head = the value's epoch", and by
    // epoch monotonicity this value is at or below the current epoch.
    // The check here is kept as a defense line against a derivation
    // inconsistency (an implementation bug)
    if (variable.epoch > input.chainEpoch) {
      return yield* Effect.fail(
        cliError(
          `Variable ${displayText(variable.name)} declares epoch ${variable.epoch}, beyond the chain's current epoch (${input.chainEpoch}) (inconsistent with the verified view)`,
        ),
      );
    }
    const dek = input.deksByEpoch.get(variable.epoch);
    if (dek === undefined) {
      return yield* Effect.fail(cliError(missingWrapReason(variable)));
    }
    const nonce = decodeHex(variable.nonceHex);
    const ciphertext = decodeHex(variable.ciphertextHex);
    if (nonce === null || ciphertext === null) {
      return yield* Effect.fail(
        cliError(`Variable ${displayText(variable.name)} has a malformed ciphertext`),
      );
    }
    const plaintext = yield* cryptoEffect(() =>
      decryptVariable({
        // Reason for unwrapping: the decryption's key input (the crypto boundary)
        dek: Redacted.value(dek),
        context: {
          projectId: input.verified.projectId,
          environmentId: input.environmentId,
          epoch: variable.epoch,
          variableId: variable.variableId,
          version: variable.version,
        },
        nonce,
        ciphertext,
      }),
    ).pipe(
      Effect.mapError(() =>
        cliError(
          `Cannot decrypt variable ${displayText(variable.name)} (context mismatch or corrupted ciphertext — possibly replaced by the server)`,
        ),
      ),
    );
    // The decryption's product is wrapped here. From here on the plaintext flows only as a Redacted
    return Redacted.make(plaintext, { label: "variable-value" });
  });
}

/** Narrowing the variables to decrypt (omitted `select` = all). Applies only to the verified set. */
function selectedVariables(
  variables: readonly VerifiedPulledValue[],
  select: ((name: string) => boolean) | undefined,
): readonly VerifiedPulledValue[] {
  return select === undefined ? variables : variables.filter((variable) => select(variable.name));
}

/**
 * Pulls one environment, verifies every value's write signature and every
 * metadata statement (§4.1 / §4.2 — before any decryption; names come only
 * from verified statements), verifies and unwraps the caller's DEKs (§5.1
 * registration signature + §5.2 commitment matching stay mandatory), then
 * decrypts every latest version. DEKs are indexed by epoch because latest
 * versions may span epochs until a rotation's re-encryption completes
 * (§12-7).
 */
export function pullVariables(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
  /** The bounded resync on a future head (§6.3-2b). */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** The local floor (§6.3 — the checks and the atomic commit after verification succeeds). */
  readonly floor: FloorHandle;
  /**
   * Narrows the variables to decrypt by name (`maruhi sync`'s integrated
   * token — never materializes the environment's other variables'
   * plaintext in memory). Verification (value signatures, statements,
   * wraps) is still performed across the whole environment. Omitted =
   * decrypt every active variable.
   */
  readonly select?: (name: string) => boolean;
  /**
   * Derives and fills the missing epochs of the same person's other
   * devices from the bundled rows (DK K11-1 / K11-4 — only `maruhi pull`
   * passes this. Signing uses this device's key). Omitted = no fill. DEKs
   * never leave this function (the fill happens here; the result is
   * returned as a fact).
   */
  readonly fillOwnDeviceGaps?: { readonly signingKeyPair: SigningKeyPair };
}): Effect.Effect<PulledVariables, CliError> {
  return Effect.gen(function* () {
    // (0) Target environment ∈ one's own scope (CRYPTO_SPEC §6.3 — never
    // wait for the server's 403. 2026-09-15 ES K4, design record K4-C).
    // This is the only shared path of a values-bearing pull (pull / run /
    // sync / rotate's re-encryption), so a multi-environment command that
    // never passes through the `--env` prologue (context.ts) also stops
    // here. Since a values-bearing pull records a `var.read`, it is
    // dropped before communicating
    yield* requireEnvironmentInScope({
      verified: input.verified,
      userId: input.recipient.userId,
      environmentId: input.environmentId,
      operation: "pull values from",
    });
    // (1) Verifying the value signatures (before decryption). On a
    // future head, a view advanced by the bounded resync comes back — the
    // later checks (wraps, epochs) also run on the same view
    const pulled = yield* pullVerifiedEnvironment(input);
    const verified = pulled.verified;

    // (2) The wraps' §5.1 / §5.2 verification and unwrap (no DEK is used
    // until the commitment match also succeeds). The current epoch
    // (chain-derived — §6.2) and the DEK set are derived in bulk from the
    // same verified view (deks.ts's environmentKeysFor)
    const keys = yield* environmentKeysFor({
      client: input.client,
      verified,
      environmentId: input.environmentId,
      recipient: input.recipient,
      prefetched: pulled.deks,
    });
    const deksByEpoch = keys.deksByEpoch;

    // The difference check against §7's all-epoch distribution (the
    // self-side detection of an unfinished backfill — the B2 ruling):
    // every member should hold every DEK of epochs 1..current addressed
    // to them, so a gap is always a sign of an interrupted member-add
    // backfill or an unfinished repair (no false positives). Since a gap
    // in an epoch the current values need for decryption is already
    // stopped by decryptVerifiedValue as a definitive failure, here we
    // catch a silent gap in historical epochs (never surfaced by the
    // current values alone) as a SHOULD warning
    const missingEpochs = missingEpochsOf(keys);
    const warnings =
      missingEpochs.length === 0
        ? pulled.warnings
        : [
            ...pulled.warnings,
            describeMissingOwnEpochs(verified.projectId, input.environmentId, missingEpochs),
          ];

    const results: DecryptedVariable[] = [];
    for (const variable of selectedVariables(pulled.variables, input.select)) {
      // A duplicate active name was already refused by the statement
      // verification (values-verify.ts) (§4.2 — `maruhi run`'s environment
      // variable injection has no path that silently crushes one side)
      const plaintext = yield* decryptVerifiedValue({
        verified,
        environmentId: input.environmentId,
        variable,
        deksByEpoch,
        chainEpoch: keys.currentEpoch,
      });
      results.push({
        variableId: variable.variableId,
        name: variable.name,
        version: variable.version,
        epoch: variable.epoch,
        varType: variable.schema?.varType ?? "",
        required: variable.schema?.required ?? false,
        maxAgeDays: variable.schema?.maxAgeDays ?? null,
        value: plaintext,
      });
    }
    // Filling the sibling devices' gaps (DK K11): only after decryption
    // is done (a failed pull fills nothing). A failure folds into the
    // result and never changes the pull's outcome
    const ownDeviceGapFills = yield* fillOwnDeviceGaps({
      client: input.client,
      verified,
      environmentId: input.environmentId,
      recipient: input.recipient,
      signer: input.fillOwnDeviceGaps,
      currentEpoch: keys.currentEpoch,
      deksByEpoch,
      rows: pulled.deks,
    });
    return {
      verified,
      variables: results,
      declared: toDeclaredVariables(pulled.declared),
      warnings,
      ownDeviceGapFills,
    };
  });
}
