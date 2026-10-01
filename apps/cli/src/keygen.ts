// Generating and displaying the device key (CRYPTO_SPEC §3 —
// 2026-09-19 DK: the old "master keypair" is the device key).
//
// - Generation uses only @maruhi/crypto's public API
//   (key-record.ts). Extractable generation → serialize the private
//   key to the OS keychain (never written to a plaintext file)
// - Overwriting an existing key is refused: losing the key loses the
//   ability to decrypt every project (recovery only via the reserve
//   key = `maruhi key recover`)
// - **There is one identity** (design record §9 K4-19): running `key
//   generate` on an account that already has a ledger (a recovery
//   registration) is "a second device", so it is guided to device
//   addition (`maruhi device add`) rather than key generation. If
//   the ledger's state cannot be fetched, refuse fail-closed.
//   Re-creation for someone who lost the key, the code, and every
//   device is `--new-identity` (a specifically-named explicit opt-in)
// - After generation, generate and seal the reserve key (§8 —
//   recovery.ts. In agent environments the sealing is skipped and
//   guidance is shown)
// - Display (key show) shows only the public keys and the
//   fingerprint. The secret key is never displayed

import { Effect, Stdio } from "effect";
import type { HttpClient } from "effect/http";

import type { MaruhiClient } from "./api.ts";
import type { IdentityBacking } from "./config.ts";
import { displayText, formatUtcDate } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { fingerprintWords, formatWordList } from "./fp-words.ts";
import { CliIo } from "./io.ts";
import { offerGithubRegistration } from "./key-publish.ts";
import { generateKeyRecord } from "./key-record.ts";
import { Keychain, serializeStoredMasterKey } from "./keychain.ts";
import { logNote } from "./notice.ts";
import { OwnDeviceStore } from "./own-devices.ts";
import { issueRecoveryAfterKeygen } from "./recovery.ts";
import { recordedReserves } from "./reserve.ts";
import type { ProcessRunner } from "./run.ts";
import {
  type CliSession,
  ensureNoStoredMasterKey,
  cryptoBackendUsable,
  importMasterKeys,
  retryOnSupportedRuntime,
  storeMasterKeyAndReport,
  unsupportedCryptoCause,
  loadMasterKeys,
} from "./session.ts";

/** `maruhi key generate`: create and store this device's key for the session user. */
export function keyGenerateOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  /** The backing source (CRYPTO_SPEC §6.5): when not `none`, the GitHub-registration route is shown right after generation. */
  readonly identityBacking: IdentityBacking;
  /** `--new-identity`: create a new identity even when a ledger exists (K4-19 — a specifically-named explicit opt-in). */
  readonly newIdentity: boolean;
}): Effect.Effect<
  void,
  CliError,
  Keychain | CliIo | ProcessRunner | Stdio.Stdio | HttpClient.HttpClient | OwnDeviceStore
> {
  return Effect.gen(function* () {
    const entryName = yield* ensureNoStoredMasterKey(
      input.session,
      "A device key already exists on this machine. Overwriting it would destroy the ability to decrypt existing projects, so this is refused (check it with `maruhi key show`)",
    );
    // One identity (K4-19): when a ledger exists, this is "a second device" → device addition
    if (!input.newIdentity) {
      const status = yield* input.client.auth
        .recoveryStatus({})
        .pipe(
          Effect.mapError(() =>
            cliError(
              "Cannot check whether your account already has a recovery ledger (the server is unreachable or the token is revoked), so the key was not generated. Re-run when the server is reachable, or pass --new-identity only if you are sure this is your first key",
            ),
          ),
        );
      if (status.registered) {
        return yield* Effect.fail(
          cliError(
            "Your account already has a reserve key in the recovery ledger, so this machine is a second device rather than a new identity. Register it with `maruhi device add` and approve it from a registered device with `maruhi device approve` (no key material moves). If every device and the recovery code / passkeys / guardians are all lost, rebuild with `maruhi key generate --new-identity` (existing project values become undecryptable until you are re-invited)",
          ),
        );
      }
    }

    const record = yield* generateKeyRecord();
    // Re-import the record for self-verification **before** storing
    // (never leave a record that failed verification in the
    // keychain).
    // The failure wording is **specific to this path**: the default
    // wording points at the keychain's record and urges deletion, but
    // here nothing has been stored — that would guide deleting a
    // thing that does not exist. When the cause is the environment
    // (WebCrypto unsupported), it is not a key problem, so that one
    // is distinguished
    const validated = yield* importMasterKeys(record).pipe(
      Effect.catch(() =>
        Effect.flatMap(cryptoBackendUsable(), (usable) =>
          Effect.fail(
            cliError(
              usable
                ? "Could not load the generated key back (nothing was stored in the keychain). Report this as a maruhi bug"
                : // Nothing is stored yet, so "the stored key"
                  // cannot be pointed at. State the safe thing (=
                  // that nothing was written) and share only the
                  // next step
                  `${unsupportedCryptoCause}. Nothing was stored in the keychain. ${retryOnSupportedRuntime}`,
            ),
          ),
        ),
      ),
    );
    // Do not use JSON.stringify(record) — the private side would be
    // stored redacted, leaving a record in the keychain whose key
    // cannot be recovered (the note in keychain.ts).
    // Storing detects overwrite: at this position, between the guard
    // and key generation, a concurrent run may have written first,
    // and a bare set is last-write-wins and silently erases one key.
    // Fail it before the downstream reserve-key sealing
    yield* storeMasterKeyAndReport({
      entryName,
      serialized: serializeStoredMasterKey(record),
      action: "Generated this device's key",
      fingerprintHex: validated.fingerprintHex,
    });
    yield* logNote(
      "this key belongs to this device only. Other machines get their own device key (`maruhi device add`); losing every device is covered by the reserve key created next",
    );
    yield* issueRecoveryAfterKeygen({ session: input.session, client: input.client });
    // The registration route (supplement 21 ruling G ⑥ (b)): ask only after the recovery-code ceremony finishes
    if (input.identityBacking !== "none") {
      yield* offerGithubRegistration({ session: input.session });
    }
  });
}

/** `maruhi key show`: print the public keys and fingerprints (never the private keys). */
export function keyShowOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
}): Effect.Effect<void, CliError, Keychain | CliIo | HttpClient.HttpClient | OwnDeviceStore> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const keys = yield* loadMasterKeys(input.session);
    // userId is a server-derived free-form string. Sanitize like the other output paths
    yield* io.log(`user:                   ${displayText(input.session.userId)}`);
    yield* io.log(`device enc public key:  ${keys.record.encPubHex}`);
    yield* io.log(`device sig public key:  ${keys.record.sigPubHex}`);
    yield* io.log(`device key fingerprint: ${keys.fingerprintHex}`);
    // The FP's word display (§3): the re-display path for reading /
    // carrying my word list in invite mutual confirmation (§6.5) and
    // device addition (`device approve`)
    const words = yield* fingerprintWords(keys.fingerprintHex, "The key fingerprint is malformed");
    yield* io.log(`fp words:               ${formatWordList(words)}`);
    // The reserve key (lives only in the ledger — the local record is public-side only)
    const reserves = yield* recordedReserves(input.session);
    const reserve = reserves[0];
    yield* io.log(
      `reserve key fingerprint: ${reserve === undefined ? "not recorded on this machine" : reserve.keyFingerprintHex}`,
    );
    // Custody reminder (ROADMAP's loss-proofing UX): always show the
    // registration state; when unregistered, guide the issuing
    // command. status carries no blob (AUTH_SPEC §13-2).
    // show's job is displaying the local key, so a failure to check
    // the state does not fail the command — degrade with an explicit
    // "could not check" (usable offline and with an expired token)
    const status = yield* input.client.auth
      .recoveryStatus({})
      .pipe(Effect.catch(() => Effect.succeed(null)));
    if (status === null) {
      yield* io.log("recovery:               could not be checked");
      yield* logNote(
        "the recovery registration status could not be checked (the server is unreachable or the token is revoked). This does not affect the key information shown above",
      );
    } else if (status.registered) {
      const updated =
        status.updatedAtMs === null ? "" : ` (updated: ${formatUtcDate(status.updatedAtMs)})`;
      yield* io.log(`recovery:               registered${updated}`);
      if (reserve === undefined) {
        yield* logNote(
          "the recovery ledger is registered but this machine has no record of the reserve key it holds. `maruhi key recovery` opens the ledger (recovery code or --passkey) and restores the record",
        );
      }
    } else {
      yield* io.log("recovery:               not registered");
      yield* logNote(
        "no reserve key is sealed in the recovery ledger. If you lose this device you lose access — create one with `maruhi key recovery`",
      );
    }
  });
}

/** Whether the account's recovery ledger is registered (typed failure when it cannot be checked). */
export function recoveryRegistered(
  client: MaruhiClient,
): Effect.Effect<boolean, CliError, HttpClient.HttpClient> {
  return client.auth.recoveryStatus({}).pipe(
    Effect.map((status) => status.registered),
    Effect.mapError(toCliError),
  );
}
