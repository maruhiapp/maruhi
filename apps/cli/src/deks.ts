// Verifying and decrypting distributed wrapped DEKs (CRYPTO_SPEC §5.1 /
// §5.2 / §12-7).
//
// The verification coordinates are assembled independently without
// trusting declared values: projectId = the verified genesis hash,
// environmentId = the ID used in the request, recipient = my user_id +
// my enc public key. The signer's key is "the sig key bound to
// signerUserId in the verified chain history whose FP matches" (a removed
// member's key of the time also works — the chain is append-only). A
// wrap's epoch is a declared value, but because it is bound into both the
// registration signature (§5.1) and HPKE info (§5), transplanting to
// another epoch fails verification / decryption.
//
// §5.2: an unwrapped DEK is not used in any cryptographic operation
// (decryption, encryption) until it is matched against the chain-derived
// (environment, epoch) commitment. A mismatch is a poisoned wrap (blocks
// a colluding server injecting a false DEK — §14.2-1).

import type { RecipientDek } from "@maruhi/api-schema";
import { cryptoEffect } from "@maruhi/core";
import type { EncryptionKeyPair, EnvironmentChainState } from "@maruhi/crypto";
import {
  decodeHex,
  effectivePermissionOf,
  importSigningPublicKey,
  scopeIncludesEnvironment,
  SUITE_ID,
  unwrapDek,
  verifyDekCommitment,
  verifyDekWrapSignature,
} from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { VerifiedProject } from "./chain-sync.ts";
import { ownDeviceOrFail } from "./device-key.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { describeScope, outOfScopeMessage } from "./scope.ts";

/** The caller as a DEK recipient (own coordinates for §5.1 verification). */
export interface DekRecipient {
  readonly userId: string;
  readonly encPubHex: string;
  readonly encKeyPair: EncryptionKeyPair;
}

function signerKeyFor(verified: VerifiedProject, wrap: RecipientDek): Uint8Array | null {
  const bindings = verified.keyHistory.get(wrap.signerUserId) ?? [];
  const match = bindings.find(
    (binding) => binding.keyFingerprintHex === wrap.signerKeyFingerprintHex,
  );
  return match === undefined ? null : decodeHex(match.sigPubHex);
}

/** Verifies one wrap's registration signature and unwraps it (§5.1), with the §5.2 commitment check before the DEK leaves. */
function verifyAndUnwrapOne(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly recipient: DekRecipient;
  readonly wrap: RecipientDek;
  /** The chain-derived commitment for that (environment, epoch) (§5.2). */
  readonly expectedCommitmentHex: string;
}): Effect.Effect<Uint8Array, CliError> {
  const { verified, environmentId, recipient, wrap } = input;
  return Effect.gen(function* () {
    const signerKeyBytes = signerKeyFor(verified, wrap);
    if (signerKeyBytes === null) {
      return yield* Effect.fail(
        cliError(
          `The signer does not exist in the chain history (signer=${displayText(wrap.signerUserId)}, fp=${wrap.signerKeyFingerprintHex})`,
        ),
      );
    }
    const signerKey = yield* cryptoEffect(() => importSigningPublicKey(signerKeyBytes)).pipe(
      Effect.mapError(() => cliError("Cannot load the signer's public key")),
    );
    yield* cryptoEffect(() =>
      verifyDekWrapSignature({
        context: {
          suite: wrap.suite,
          projectId: verified.projectId,
          environmentId,
          epoch: wrap.epoch,
          recipientUserId: recipient.userId,
          recipientEncPubHex: recipient.encPubHex,
          encHex: wrap.encHex,
          ciphertextHex: wrap.ciphertextHex,
          signerUserId: wrap.signerUserId,
        },
        signatureHex: wrap.signatureHex,
        signerPublicKey: signerKey,
      }),
    ).pipe(
      Effect.mapError(() =>
        cliError(
          `The DEK wrap's registration signature does not verify (epoch=${wrap.epoch}, signer=${displayText(wrap.signerUserId)})`,
        ),
      ),
    );
    const enc = decodeHex(wrap.encHex);
    const ciphertext = decodeHex(wrap.ciphertextHex);
    if (enc === null || ciphertext === null) {
      return yield* Effect.fail(cliError(`The DEK wrap is malformed (epoch=${wrap.epoch})`));
    }
    const dek = yield* cryptoEffect(() =>
      unwrapDek({
        recipientKeyPair: recipient.encKeyPair,
        wrapped: { enc, ciphertext },
        context: {
          projectId: verified.projectId,
          environmentId,
          epoch: wrap.epoch,
          recipientUserId: recipient.userId,
        },
      }),
    ).pipe(
      Effect.mapError(() =>
        cliError(
          `Cannot decrypt the DEK (epoch=${wrap.epoch}, signer=${displayText(wrap.signerUserId)}). The wrap is not addressed to your key, or it is corrupt`,
        ),
      ),
    );
    // §5.2 / §6.3: do not use the DEK until the commitment check succeeds.
    // The coordinates are assembled from our own verified values (the
    // genesis hash, the request's environment ID)
    yield* cryptoEffect(() =>
      verifyDekCommitment({
        context: {
          suite: SUITE_ID,
          projectId: verified.projectId,
          environmentId,
          epoch: wrap.epoch,
        },
        dek,
        expectedCommitmentHex: input.expectedCommitmentHex,
      }),
    ).pipe(
      Effect.mapError(() =>
        cliError(
          `The DEK does not match the commitment on the chain (epoch=${wrap.epoch}, signer=${displayText(wrap.signerUserId)}). This may be a poisoned wrap (a fake DEK) — an administrator must repair it (delete the wrap, then re-register)`,
        ),
      ),
    );
    return dek;
  });
}

/**
 * The environments deleted on the verified chain (`delete_environment` —
 * CRYPTO_SPEC §6.2). The chain is the only authority for deletion: no
 * server listing or statement is consulted, so this needs no request and
 * cannot be withheld.
 */
export function chainDeletedEnvironments(verified: VerifiedProject): ReadonlySet<string> {
  const deleted = new Set<string>();
  for (const [environmentId, environment] of verified.state.environments) {
    if (environment.deletedAtSeq !== null) {
      deleted.add(environmentId);
    }
  }
  return deleted;
}

/** The refusal for operating on an environment the verified chain shows as deleted (§6.3 "Chain-deleted environments"). */
export function deletedEnvironmentMessage(environmentId: string, deletedAtSeq: number): string {
  return `Environment ${displayText(environmentId)} is deleted (delete_environment at chain seq ${deletedAtSeq}). Deletion is terminal: a deleted environment cannot be restored, and its ID can never be reused`;
}

/**
 * Refuses an environment the verified chain shows as deleted, before any
 * request about it (§6.3 "Chain-deleted environments"). An environment the
 * chain does not know is left to each path's own existence check.
 */
export function refuseChainDeletedEnvironment(
  verified: VerifiedProject,
  environmentId: string,
): Effect.Effect<void, CliError> {
  const deletedAtSeq = verified.state.environments.get(environmentId)?.deletedAtSeq ?? null;
  return deletedAtSeq === null
    ? Effect.void
    : Effect.fail(cliError(deletedEnvironmentMessage(environmentId, deletedAtSeq)));
}

/**
 * Chain-derived environment state (§6.2) of a live environment. Distributing
 * a not-yet-created environment contradicts the chain in the server
 * response; a deleted one is never read, written or rotated (§6.3).
 */
export function requireChainEnvironment(
  verified: VerifiedProject,
  environmentId: string,
): Effect.Effect<EnvironmentChainState, CliError> {
  const environment = verified.state.environments.get(environmentId);
  if (environment === undefined) {
    return Effect.fail(
      cliError(
        `Environment ${environmentId} does not exist on the chain (no create_environment observed). It may have just been created — if re-running does not resolve this, the server response contradicts the chain`,
      ),
    );
  }
  if (environment.deletedAtSeq !== null) {
    return Effect.fail(
      cliError(deletedEnvironmentMessage(environmentId, environment.deletedAtSeq)),
    );
  }
  return Effect.succeed(environment);
}

/**
 * Verifies every distributed wrap (§5.1) and unwraps it, indexing DEKs by
 * epoch (§12-7: latest versions may span epochs, so all epochs are needed).
 * Any failure aborts — silently skipping a wrap would hide tampering.
 *
 * Phantom-epoch defense: a wrap's epoch must be at or below the
 * chain-derived current epoch. §12-6's "1 through the current epoch" is
 * server-enforced; under a distrusted server this client check is the
 * main line (accepting a DEK for an epoch with no rotate_epoch on the
 * chain lets a colluding server inject false values via an attacker DEK
 * signed by a regular member).
 */
const verifyAndUnwrapDeks = Effect.fn("deks.verifyAndUnwrapDeks")(function* (input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly recipient: DekRecipient;
  readonly deks: readonly RecipientDek[];
}): Effect.fn.Return<ReadonlyMap<number, Redacted.Redacted<Uint8Array>>, CliError> {
  // An environment's existence itself is chain-derived (§6.2):
  // distribution of an environment absent from the chain is refused
  // wholesale as a phantom environment
  const environment = yield* requireChainEnvironment(input.verified, input.environmentId);
  const chainEpoch = environment.currentEpoch;
  const byEpoch = new Map<number, Redacted.Redacted<Uint8Array>>();
  // Open only the rows addressed to my devices (AUTH_SPEC §12-6's
  // device axis — one response carries all devices of the same person.
  // DK K4-16: read → verify signature → unwrap. Rows for other devices
  // are not poisoned wraps)
  const mine = input.deks.filter((wrap) => wrap.recipientEncPubHex === input.recipient.encPubHex);
  for (const wrap of mine) {
    if (wrap.suite !== SUITE_ID) {
      // Currently unreachable because of the Schema Literal pin, but
      // since the verification coordinates use the declared suite, pin
      // it explicitly on the CLI side too (defense against a future
      // union)
      return yield* Effect.fail(cliError(`The DEK wrap uses an unknown suite (${wrap.suite})`));
    }
    if (wrap.epoch > chainEpoch) {
      return yield* Effect.fail(
        cliError(
          `A DEK wrap for epoch ${wrap.epoch}, beyond the chain's current epoch (${chainEpoch}), was served. A rotation may have just happened — if re-running does not resolve this, the server response contradicts the chain`,
        ),
      );
    }
    if (byEpoch.has(wrap.epoch)) {
      return yield* Effect.fail(
        cliError(`Duplicate DEK wraps for the same epoch (epoch=${wrap.epoch})`),
      );
    }
    // The chain-derived commitment (§5.2). For every epoch in
    // 1 ≤ epoch ≤ current, a create / rotate entry already published
    // the commitment (§6.2 consensus rules)
    const expectedCommitmentHex = environment.dekCommitments.get(wrap.epoch);
    if (expectedCommitmentHex === undefined) {
      return yield* Effect.fail(
        cliError(
          `No commitment for epoch ${wrap.epoch} exists on the chain (a chain-derivation inconsistency)`,
        ),
      );
    }
    const dek = yield* verifyAndUnwrapOne({
      verified: input.verified,
      environmentId: input.environmentId,
      recipient: input.recipient,
      wrap,
      expectedCommitmentHex,
    });
    // The unwrapped DEK is wrapped here (only after the §5.2 commitment
    // check passes — a DEK before the check never leaves the inside of
    // verifyAndUnwrapOne)
    byEpoch.set(wrap.epoch, Redacted.make(dek, { label: "dek" }));
  }
  return byEpoch;
});

/**
 * The set of environment keys derived from a verified view: the pair of
 * the chain-derived current epoch and the my-addressed DEKs verified and
 * unwrapped under the same view.
 */
export interface EnvironmentKeys {
  readonly currentEpoch: number;
  readonly deksByEpoch: ReadonlyMap<number, Redacted.Redacted<Uint8Array>>;
}

/**
 * Among 1 through the current epoch, the epochs with no verified and
 * unwrapped my-addressed DEK (the difference from CRYPTO_SPEC §7's
 * all-epochs distribution). The warning of a pull with values and the
 * reachability check of `device add` (DK K12-2) judge with the same
 * function — the structure removes inputs where an ahead-of-time report
 * and a later warning could disagree.
 */
export function missingEpochsOf(keys: EnvironmentKeys): readonly number[] {
  return Array.from({ length: keys.currentEpoch }, (_, index) => index + 1).filter(
    (epoch) => !keys.deksByEpoch.has(epoch),
  );
}

/**
 * Derives the environment keys — the chain-derived current epoch and the
 * caller's verified, unwrapped DEKs — from one verified view, so that "the
 * epoch and the DEK set come from the same verified view" is enforced by
 * construction instead of by convention.
 *
 * Fetch-path precedence: if cached (the known set already verified in
 * this session) has the current epoch, do not refetch → else if
 * prefetched (the wraps bundled with a pull of values — removes the
 * §12-7 double fetch) exists, verify and unwrap it → else fetch listMine
 * and verify and unwrap. Verification (§5.1 registration signature +
 * §5.2 commitment check) is mandatory on every path.
 *
 * **Receiver-side scope rule (CRYPTO_SPEC §6.3 — 2026-09-15 ES K4,
 * design record K4-F)**: among wraps addressed to me, one whose
 * environment ∉ my scope is not used. Because this is the only
 * acquisition point of my-addressed DEKs, placing the check here makes
 * "not used" hold by structure. The with-values path stops earlier at
 * the pre-flight check (K4-C), so arrival is limited to a race (scope
 * shrank during the sync) or a caller error; abort with a fail-closed
 * typed error (the wrap is neither fetched nor unwrapped, and its
 * content never appears in the message).
 */
export const environmentKeysFor = Effect.fn("deks.environmentKeysFor")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly recipient: DekRecipient;
  /** Wraps bundled with a pull of values (raw wire shape, assumed verified under the same view as verified). */
  readonly prefetched?: readonly RecipientDek[] | null | undefined;
  /** The known set already verified and unwrapped in this session (no refetch when it has the current epoch). */
  readonly cached?: ReadonlyMap<number, Redacted.Redacted<Uint8Array>> | undefined;
}): Effect.fn.Return<EnvironmentKeys, CliError> {
  // The current epoch is a chain-derived value (§6.2 — a not-yet-created environment stops here)
  const currentEpoch = (yield* requireChainEnvironment(input.verified, input.environmentId))
    .currentEpoch;
  const self = input.verified.state.members.get(input.recipient.userId);
  if (self === undefined) {
    return yield* Effect.fail(
      cliError("You are not a chain-derived member of this project (no DEK is addressed to you)"),
    );
  }
  // The unwrapping device = my valid device matching the enc key at
  // hand (DK K4-16). A DEK for an environment outside the effective
  // scope (person ∩ device — K4-17) is not used even when addressed to
  // me
  const device = yield* ownDeviceOrFail(input.verified, self, {
    encPubHex: input.recipient.encPubHex,
  });
  const permission = effectivePermissionOf(self, device);
  if (!scopeIncludesEnvironment(permission.scope, input.environmentId)) {
    return yield* Effect.fail(
      cliError(
        scopeIncludesEnvironment(self.scope, input.environmentId)
          ? outOfScopeMessage({
              member: self,
              device,
              environmentId: input.environmentId,
              operation: "open the DEKs of",
            })
          : `Environment ${displayText(input.environmentId)} is outside your environment scope (your scope: ${describeScope(self.scope)}), so a DEK wrap addressed to you for it is not used (CRYPTO_SPEC §6.3 — such a wrap would mean the server is not enforcing AUTH_SPEC §12-6). Your local chain view may be stale — re-run to resync, or ask an admin to widen your scope`,
      ),
    );
  }
  if (input.cached?.has(currentEpoch) === true) {
    return { currentEpoch, deksByEpoch: input.cached };
  }
  const wire =
    input.prefetched ??
    (yield* input.client.deks
      .listMine({
        params: { projectId: input.verified.projectId, environmentId: input.environmentId },
      })
      .pipe(
        Effect.mapError(toCliError),
        Effect.map((response) => response.deks),
      ));
  const deksByEpoch = yield* verifyAndUnwrapDeks({
    verified: input.verified,
    environmentId: input.environmentId,
    recipient: input.recipient,
    deks: wire,
  });
  return { currentEpoch, deksByEpoch };
});
