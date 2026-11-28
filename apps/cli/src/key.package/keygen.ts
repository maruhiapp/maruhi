import { Effect, Stdio } from "effect";
import type { HttpClient } from "effect/http";

import type { MaruhiClient } from "../api.ts";
import type { IdentityBacking } from "../config.ts";
import { displayText, formatUtcDate } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import { toCliError } from "../failure.ts";
import { fingerprintWords, formatWordList } from "../fp-words.ts";
import { CliIo } from "../io.ts";
import { generateKeyRecord } from "../key-record.ts";
import { Keychain, serializeStoredMasterKey } from "../keychain.ts";
import { logNote } from "../notice.ts";
import { OwnDeviceStore } from "../own-devices.ts";
import { issueRecoveryAfterKeygen, recordedReserves } from "../reserve.package/index.ts";
import type { ProcessRunner } from "../run.ts";
import {
  type CliSession,
  ensureNoStoredMasterKey,
  cryptoBackendUsable,
  importMasterKeys,
  retryOnSupportedRuntime,
  storeMasterKeyAndReport,
  unsupportedCryptoCause,
  loadMasterKeys,
} from "../session.ts";
import { offerGithubRegistration } from "./key-publish.ts";

export const keyGenerateOp = Effect.fn("keygen.keyGenerateOp")(function* (input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly identityBacking: IdentityBacking;
  readonly newIdentity: boolean;
}): Effect.fn.Return<
  void,
  CliError,
  Keychain | CliIo | ProcessRunner | Stdio.Stdio | HttpClient.HttpClient | OwnDeviceStore
> {
  const entryName = yield* ensureNoStoredMasterKey(
    input.session,
    "A device key already exists on this machine. Overwriting it would destroy the ability to decrypt existing projects, so this is refused (check it with `maruhi key show`)",
  );
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
  const validated = yield* importMasterKeys(record).pipe(
    Effect.catch(() =>
      Effect.flatMap(cryptoBackendUsable(), (usable) =>
        Effect.fail(
          cliError(
            usable
              ? "Could not load the generated key back (nothing was stored in the keychain). Report this as a maruhi bug"
              : `${unsupportedCryptoCause}. Nothing was stored in the keychain. ${retryOnSupportedRuntime}`,
          ),
        ),
      ),
    ),
  );
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
  if (input.identityBacking !== "none") {
    yield* offerGithubRegistration({ session: input.session });
  }
});

export const keyShowOp = Effect.fn("keygen.keyShowOp")(function* (input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
}): Effect.fn.Return<void, CliError, Keychain | CliIo | HttpClient.HttpClient | OwnDeviceStore> {
  const io = yield* CliIo;
  const keys = yield* loadMasterKeys(input.session);
  yield* io.log(`user:                   ${displayText(input.session.userId)}`);
  yield* io.log(`device enc public key:  ${keys.record.encPubHex}`);
  yield* io.log(`device sig public key:  ${keys.record.sigPubHex}`);
  yield* io.log(`device key fingerprint: ${keys.fingerprintHex}`);
  const words = yield* fingerprintWords(keys.fingerprintHex, "The key fingerprint is malformed");
  yield* io.log(`fp words:               ${formatWordList(words)}`);
  const reserves = yield* recordedReserves(input.session);
  const reserve = reserves[0];
  yield* io.log(
    `reserve key fingerprint: ${reserve === undefined ? "not recorded on this machine" : reserve.keyFingerprintHex}`,
  );
  const status = yield* input.client.auth.recoveryStatus({}).pipe(Effect.orElseSucceed(() => null));
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

export function recoveryRegistered(
  client: MaruhiClient,
): Effect.Effect<boolean, CliError, HttpClient.HttpClient> {
  return client.auth.recoveryStatus({}).pipe(
    Effect.map((status) => status.registered),
    Effect.mapError(toCliError),
  );
}
