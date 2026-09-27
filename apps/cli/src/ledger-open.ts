// Opening the ledger (CRYPTO_SPEC §8 revision (4) — 2026-09-19 DK;
// design record dk-design.md §9 K4-2).
//
// Changing the ledger (re-issuing a code, sealing a passkey, naming
// guardians, rotating the reserve key) is done only after opening
// reserve key B via a code entry or a passkey (only one who can
// open the ledger may change it). The opened B is handed to the
// caller as {@link ReserveKeys} (memory only — reserve.ts) and
// discarded when done.
//
// A ledger key is treated as a reserve key only when the ledger's
// contents carry the reserve-key mark (`kind: "reserve"` — written
// when this CLI generated it. CRYPTO_SPEC §8) and it is revoked
// nowhere on the chain (DK K16).

import { Effect, Stdio } from "effect";
import type { HttpClient } from "effect/unstable/http";

import type { MaruhiClient } from "./api.ts";
import type { CliServices } from "./context.ts";
import { ledgerKeyVerdictOf, type ReserveVerdict } from "./device-standing.ts";
import { describeProjects, describeUnmarkedLedgerKey } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import type { StoredMasterKey } from "./keychain.ts";
import { logNote } from "./notice.ts";
import type { OwnDeviceStore } from "./own-devices.ts";
import { openReserveWithPasskey } from "./passkey.ts";
import { mapUnloadableRecoveryBlob, unwrapRecoveryBlobWithCode } from "./recovery.ts";
import {
  isMarkedReserve,
  markRevokedReserveRecord,
  recordReserveLocally,
  type ReserveKeys,
} from "./reserve.ts";
import { type CliSession, importMasterKeys, loadMasterKeys } from "./session.ts";

/** How the ledger is opened: the recovery code (default) or a registered passkey. */
export type LedgerOpenVia = "code" | "passkey";

/** Opens the ledger blob B and loads it as the reserve key (memory only). */
export function openLedgerReserve(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly via: LedgerOpenVia;
}): Effect.Effect<ReserveKeys, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const record: StoredMasterKey =
      input.via === "passkey"
        ? yield* openReserveWithPasskey({ session: input.session, client: input.client })
        : yield* unwrapRecoveryBlobWithCode({ session: input.session, client: input.client });
    const keys = yield* mapUnloadableRecoveryBlob(importMasterKeys(record));
    return {
      reserve: true,
      record: keys.record,
      encKeyPair: keys.encKeyPair,
      sigKeyPair: keys.sigKeyPair,
      fingerprintHex: keys.fingerprintHex,
    } satisfies ReserveKeys;
  });
}

/**
 * Opens the ledger for a change (passkey sealing / guardian designation): the key
 * must carry the reserve-key mark and be revoked nowhere (DK K16); it is then
 * recorded locally as the reserve key (state restoration — K4-2 counterexample 2).
 */
export function openLedgerReserveForChange(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly via: LedgerOpenVia;
  /** The re-run command embedded in the refusal wording (e.g. "maruhi guardian add …"). */
  readonly command: string;
}): Effect.Effect<ReserveKeys, CliError, CliServices> {
  return Effect.gen(function* () {
    // Loading the device key comes before opening (a device without a key is not qualified to change the ledger)
    yield* loadMasterKeys(input.session);
    const reserve = yield* openLedgerReserve(input);
    const verdict = yield* ledgerKeyVerdictOf({
      session: input.session,
      client: input.client,
      fingerprintHex: reserve.fingerprintHex,
    });
    yield* settleLedgerKeyForChange({ ...input, reserve, verdict });
    return reserve;
  });
}

/**
 * Whether the opened ledger key may be used by a ledger-changing
 * command (DK K16): if it is revoked anywhere or lacks the
 * reserve-key mark, stop without recording and name `key
 * recovery`. Otherwise record it.
 */
export function settleLedgerKeyForChange(input: {
  readonly session: CliSession;
  readonly reserve: ReserveKeys;
  readonly verdict: ReserveVerdict;
  readonly command: string;
}): Effect.Effect<void, CliError, CliIo | OwnDeviceStore> {
  return Effect.gen(function* () {
    const { reserve, verdict } = input;
    const fingerprintHex = reserve.fingerprintHex;
    if (verdict.kind === "revoked") {
      yield* markRevokedReserveRecord(input.session, fingerprintHex);
      return yield* Effect.fail(
        cliError(
          `The recovery ledger holds key ${fingerprintHex}, which is revoked on ${describeProjects(verdict.projectIds)}, so it cannot serve as your reserve key. Run \`maruhi key recovery\` first: it seals a new reserve key in its place. Then re-run \`${input.command}\``,
        ),
      );
    }
    if (!isMarkedReserve(reserve)) {
      return yield* Effect.fail(
        cliError(
          `The recovery ledger holds key ${fingerprintHex}, which ${describeUnmarkedLedgerKey()}. Run \`maruhi key recovery\` first: it creates a reserve key, seals it with a new recovery code and replaces the ledger. Then re-run \`${input.command}\``,
        ),
      );
    }
    yield* noteUncheckedLedgerKey(fingerprintHex, verdict);
    yield* recordReserveLocally(input.session, reserve);
    yield* logNote(`opened the reserve key (fingerprint ${fingerprintHex}) for this change`);
  });
}

/**
 * Names, in a Note, the range where the ledger key's revocation could not be checked
 * (DK K16-6: unverifiable projects do not stop the operation — but they are not
 * passed over in silence).
 */
export function noteUncheckedLedgerKey(
  fingerprintHex: string,
  verdict: ReserveVerdict,
): Effect.Effect<void, never, CliIo> {
  if (verdict.kind !== "usable") {
    return Effect.void;
  }
  if (verdict.listFailure !== null) {
    return logNote(
      `your projects could not be listed (${verdict.listFailure}), so whether the key ${fingerprintHex} is revoked on any of them was not checked`,
    );
  }
  if (verdict.uncheckedProjectIds.length > 0) {
    return logNote(
      `${describeProjects(verdict.uncheckedProjectIds)} could not be synced, so whether the key ${fingerprintHex} is revoked there was not checked`,
    );
  }
  return Effect.void;
}
