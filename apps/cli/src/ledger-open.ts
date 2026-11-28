import { Effect, Stdio } from "effect";
import type { HttpClient } from "effect/http";

import type { MaruhiClient } from "./api.ts";
import type { CliServices } from "./cli.ts";
import { ledgerKeyVerdictOf, type ReserveVerdict } from "./device-standing.ts";
import { describeProjects, describeUnmarkedLedgerKey } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import type { StoredMasterKey } from "./keychain.ts";
import { logNote } from "./notice.ts";
import type { OwnDeviceStore } from "./own-devices.ts";
import { openReserveWithPasskey } from "./passkey.package/index.ts";
import { mapUnloadableRecoveryBlob, unwrapRecoveryBlobWithCode } from "./recovery.ts";
import {
  isMarkedReserve,
  markRevokedReserveRecord,
  recordReserveLocally,
  type ReserveKeys,
} from "./reserve.ts";
import { type CliSession, importMasterKeys, loadMasterKeys } from "./session.ts";

export type LedgerOpenVia = "code" | "passkey";

export const openLedgerReserve = Effect.fn("ledger-open.openLedgerReserve")(function* (input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly via: LedgerOpenVia;
}): Effect.fn.Return<ReserveKeys, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient> {
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

export const openLedgerReserveForChange = Effect.fn("ledger-open.openLedgerReserveForChange")(
  function* (input: {
    readonly session: CliSession;
    readonly client: MaruhiClient;
    readonly via: LedgerOpenVia;
    readonly command: string;
  }): Effect.fn.Return<ReserveKeys, CliError, CliServices> {
    yield* loadMasterKeys(input.session);
    const reserve = yield* openLedgerReserve(input);
    const verdict = yield* ledgerKeyVerdictOf({
      session: input.session,
      client: input.client,
      fingerprintHex: reserve.fingerprintHex,
    });
    yield* settleLedgerKeyForChange({ ...input, reserve, verdict });
    return reserve;
  },
);

export const settleLedgerKeyForChange = Effect.fn("ledger-open.settleLedgerKeyForChange")(
  function* (input: {
    readonly session: CliSession;
    readonly reserve: ReserveKeys;
    readonly verdict: ReserveVerdict;
    readonly command: string;
  }): Effect.fn.Return<void, CliError, CliIo | OwnDeviceStore> {
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
  },
);

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
