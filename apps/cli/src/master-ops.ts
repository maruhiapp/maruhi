import { cryptoEffect, ulid } from "@maruhi/core";
import {
  decodeHex,
  type EncryptionKey,
  type GuardianWrapContext,
  type HandoffWrapContext,
  type MasterWrapContext,
  openGuardianShare,
  sealHandoffValue,
  type WrappedDek,
  wrapMasterBlob,
} from "@maruhi/crypto";
import { Effect } from "effect";
import { SecureRandom } from "effect/crypto";

import { cliError, type CliError } from "./errors.ts";
import { serializeStoredMasterKey, type StoredMasterKey } from "./keychain.ts";
import type { MasterKeys } from "./session.ts";

export const openOwnGuardianShare = Effect.fn("master-ops.openOwnGuardianShare")(function* (input: {
  readonly masterKeys: MasterKeys;
  readonly wrapped: WrappedDek;
  readonly context: GuardianWrapContext;
}): Effect.fn.Return<Uint8Array, CliError> {
  return yield* cryptoEffect(() =>
    openGuardianShare({
      guardianKeyPair: input.masterKeys.encKeyPair,
      wrapped: input.wrapped,
      context: input.context,
    }),
  ).pipe(
    Effect.mapError(() =>
      cliError(
        "Cannot open your guardian share with the device key on this machine. The ward may have sealed the group to a previous key of yours, or before this device was registered — ask them to re-add you with `maruhi guardian add`",
      ),
    ),
  );
});

export const wrapReserveBlob = Effect.fn("master-ops.wrapReserveBlob")(function* (input: {
  readonly record: StoredMasterKey;
  readonly kek: Uint8Array;
  readonly context: MasterWrapContext;
}): Effect.fn.Return<{ readonly nonce: Uint8Array; readonly ciphertext: Uint8Array }, CliError> {
  const blob = new TextEncoder().encode(serializeStoredMasterKey(input.record));
  return yield* cryptoEffect(() =>
    wrapMasterBlob({ kek: input.kek, masterSecretBlob: blob, context: input.context }),
  ).pipe(Effect.mapError(() => cliError("Failed to wrap the reserve key")));
});

export const sealForRequester = Effect.fn("master-ops.sealForRequester")(function* (input: {
  readonly ephemeralPublicKey: EncryptionKey;
  readonly value: Uint8Array;
  readonly context: HandoffWrapContext;
}): Effect.fn.Return<WrappedDek, CliError> {
  return yield* cryptoEffect(() => sealHandoffValue(input)).pipe(
    Effect.mapError(() => cliError("Failed to seal the approval to the requester's key")),
  );
});

export const newLedgerId = (): Effect.Effect<string, never, SecureRandom.SecureRandom> => ulid();

export function decodeWrapped(input: {
  readonly encHex: string;
  readonly ciphertextHex: string;
}): Effect.Effect<WrappedDek, CliError> {
  const enc = decodeHex(input.encHex);
  const ciphertext = decodeHex(input.ciphertextHex);
  return enc === null || ciphertext === null
    ? Effect.fail(cliError("The server response is malformed (cannot decode hex)"))
    : Effect.succeed({ enc, ciphertext });
}
