// The narrow crypto operations of the ledger (CRYPTO_SPEC §8.3 /
// §8.4 — KL3 / DK).
//
// Only the 3 "compute once with a key" operations gather here:
// opening my segment as a guardian (with my **device key**), wrapping
// the reserve key's blob B (passkey sealing, guardian group — since
// 2026-09-19 DK, B is the reserve key's record), and sealing to the
// requester's ephemeral key (this one needs no key, but the approval
// assembly stays in one place). The old-device approval bundle
// (`kind = "device"`) was removed in DK K4. As the groundwork for
// service-ization under KL4 (the delegation model — the agent
// performs the signing / HPKE open and key material never reaches
// the socket; integration-options.md supplement 19-3 (a)), callers
// never touch `MasterKeys` directly and go through these functions.
//
// Plaintext segments, KEK, and B exist only in each function's
// locals and leave nowhere but the return value (never onto logs or
// errors — CLAUDE.md).

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

import { cliError, type CliError } from "./errors.ts";
import { serializeStoredMasterKey, type StoredMasterKey } from "./keychain.ts";
import type { MasterKeys } from "./session.ts";

/** Opens the segment addressed to me as a guardian (called right before approving; the result is resealed immediately). */
export const openOwnGuardianShare = Effect.fn("master-ops.openOwnGuardianShare")(function* (input: {
  readonly masterKeys: MasterKeys;
  readonly wrapped: WrappedDek;
  readonly context: GuardianWrapContext;
}): Effect.fn.Return<Uint8Array, CliError> {
  // info is assembled by openGuardianShare in the spec's field order (a transplant fails decryption — §8.3)
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

/**
 * Wraps the reserve key's blob B with the KEK (§8.1's master-wrap
 * form). The shared body of passkey registration (kind = passkey-prf
 * — §8.2) and guardian groups (kind = guardian — §8.3). `record` is
 * the reserve key's record (reserve.ts's `ReserveKeys.record`);
 * there is no path that passes a device key's record (the types are
 * the same, but callers only ever bring a reserve key).
 */
export const wrapReserveBlob = Effect.fn("master-ops.wrapReserveBlob")(function* (input: {
  readonly record: StoredMasterKey;
  readonly kek: Uint8Array;
  readonly context: MasterWrapContext;
}): Effect.fn.Return<{ readonly nonce: Uint8Array; readonly ciphertext: Uint8Array }, CliError> {
  // JSON.stringify(record) is not used (the private side would be redacted — the note in keychain.ts)
  const blob = new TextEncoder().encode(serializeStoredMasterKey(input.record));
  return yield* cryptoEffect(() =>
    wrapMasterBlob({ kek: input.kek, masterSecretBlob: blob, context: input.context }),
  ).pipe(Effect.mapError(() => cliError("Failed to wrap the reserve key")));
});

/** Seals a 32-byte value to the requester's ephemeral public key (the E.pub decoded from the code). */
export const sealForRequester = Effect.fn("master-ops.sealForRequester")(function* (input: {
  readonly ephemeralPublicKey: EncryptionKey;
  readonly value: Uint8Array;
  readonly context: HandoffWrapContext;
}): Effect.fn.Return<WrappedDek, CliError> {
  return yield* cryptoEffect(() => sealHandoffValue(input)).pipe(
    Effect.mapError(() => cliError("Failed to seal the approval to the requester's key")),
  );
});

/**
 * The ledger's client-issued id (ULID). wrap_id / group_id are
 * bound by AAD / info, so the client decides them before encryption
 * (AUTH_SPEC §13-9).
 */
export function newLedgerId(): string {
  return ulid();
}

/** hex (32 bytes) → key material. A malformed server response is refused as an implementation bug / tampering. */
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
