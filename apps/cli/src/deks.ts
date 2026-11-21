import type { RecipientDek } from "@maruhi/api-schema";
import { cryptoEffect, type EnvironmentId, type UserId } from "@maruhi/core";
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
import { deletedEnvironmentMessage, describeScope, outOfScopeMessage } from "./scope.ts";

export interface DekRecipient {
  readonly userId: UserId;
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

function verifyAndUnwrapOne(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
  readonly wrap: RecipientDek;
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

export function chainDeletedEnvironments(verified: VerifiedProject): ReadonlySet<EnvironmentId> {
  const deleted = new Set<EnvironmentId>();
  for (const [key, environment] of verified.state.environments) {
    if (environment.deletedAtSeq !== null) {
      deleted.add(key);
    }
  }
  return deleted;
}

export function chainEnvironmentIds(verified: VerifiedProject): readonly EnvironmentId[] {
  return [...verified.state.environments.keys()];
}

export function requireChainEnvironment(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
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

const verifyAndUnwrapDeks = Effect.fn("deks.verifyAndUnwrapDeks")(function* (input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
  readonly deks: readonly RecipientDek[];
}): Effect.fn.Return<ReadonlyMap<number, Redacted.Redacted<Uint8Array>>, CliError> {
  const environment = yield* requireChainEnvironment(input.verified, input.environmentId);
  const chainEpoch = environment.currentEpoch;
  const byEpoch = new Map<number, Redacted.Redacted<Uint8Array>>();
  const mine = input.deks.filter((wrap) => wrap.recipientEncPubHex === input.recipient.encPubHex);
  for (const wrap of mine) {
    if (wrap.suite !== SUITE_ID) {
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
    byEpoch.set(wrap.epoch, Redacted.make(dek, { label: "dek" }));
  }
  return byEpoch;
});

export interface EnvironmentKeys {
  readonly currentEpoch: number;
  readonly deksByEpoch: ReadonlyMap<number, Redacted.Redacted<Uint8Array>>;
}

export function missingEpochsOf(keys: EnvironmentKeys): readonly number[] {
  return Array.from({ length: keys.currentEpoch }, (_, index) => index + 1).filter(
    (epoch) => !keys.deksByEpoch.has(epoch),
  );
}

export const environmentKeysFor = Effect.fn("deks.environmentKeysFor")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
  readonly prefetched?: readonly RecipientDek[] | null | undefined;
  readonly cached?: ReadonlyMap<number, Redacted.Redacted<Uint8Array>> | undefined;
}): Effect.fn.Return<EnvironmentKeys, CliError> {
  const currentEpoch = (yield* requireChainEnvironment(input.verified, input.environmentId))
    .currentEpoch;
  const self = input.verified.state.members.get(input.recipient.userId);
  if (self === undefined) {
    return yield* Effect.fail(
      cliError("You are not a chain-derived member of this project (no DEK is addressed to you)"),
    );
  }
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
