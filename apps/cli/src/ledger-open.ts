// Opening the ledger (CRYPTO_SPEC §8 revision (4) — 2026-09-19 DK;
// design record dk-design.md §9 K4-2).
//
// Changing the ledger (re-issuing a code, sealing a passkey, naming
// guardians, rotating the reserve key) is done only after opening
// reserve key B via a code entry or a passkey (only one who can open
// the ledger may change it). The opened B is handed to the caller as
// {@link ReserveKeys} (memory only — reserve.ts) and discarded when
// done.
//
// Distinguishing a pre-DK ledger: when the opened B's FP **matches
// the FP of the device key at hand**, the ledger holds a copy of the
// device key (the old "master key"). Only `maruhi key recovery`
// performs that separation (key-recover.ts); every other ledger
// change refuses with "run `key recovery` first". The judgment uses
// a cryptographic fact (B's content), not local state or
// declarations. Even without a match, when the opened B is some
// first key on a verified chain (a pre-DK copy as seen from another
// device) or a revoked key, it is likewise stopped (DK K14-4 — the
// same judgment as `key recover` / `key recovery`,
// `reserveVerdictOf`). A key that was the first key on a project the
// server hid from the list is likewise stopped when it is in this
// device's observation record (DK K15 — `recorded-first-key`). The
// only case that is recorded as a reserve key and proceeds is when
// the ledger's content carries the reserve mark (`kind: "reserve"` —
// written when this CLI generated it) (DK K16-6).

import { Effect, Stdio } from "effect";
import type { HttpClient } from "effect/unstable/http";

import type { MaruhiClient } from "./api.ts";
import type { CliServices } from "./context.ts";
import {
  type LedgerKeyCheck,
  ledgerKeyVerdictOf,
  type ReserveVerdict,
  stopsLedgerKey,
} from "./device-standing.ts";
import {
  describeProjects,
  describeRecordedFirstKey,
  describeUnmarkedLedgerKey,
} from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import type { StoredMasterKey } from "./keychain.ts";
import { logNote } from "./notice.ts";
import type { OwnDeviceStore } from "./own-devices.ts";
import { openReserveWithPasskey } from "./passkey.ts";
import { mapUnloadableRecoveryBlob, unwrapRecoveryBlobWithCode } from "./recovery.ts";
import {
  isMarkedReserve,
  recordReserveLocally,
  type ReserveKeys,
  retractReserveRecord,
} from "./reserve.ts";
import { type CliSession, importMasterKeys, type MasterKeys } from "./session.ts";

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

/** Refusal wording for when the ledger holds a copy of the device key (pre-DK). */
function ledgerHoldsDeviceKeyMessage(command: string): string {
  return `The recovery ledger holds a copy of this device's key (an install from before device keys), not a separate reserve key. Run \`maruhi key recovery\` first: it creates a reserve key, seals it with a new recovery code and replaces the ledger. Then re-run \`${command}\``;
}

/**
 * Refusal wording for when the ledger's key does not work as a
 * reserve key on the chain (DK K14-4 4-f — same shape as the
 * FP-match refusal: what → why → `key recovery` first → re-run).
 */
function ledgerKeyUnusableMessage(
  fingerprintHex: string,
  verdict: Extract<
    ReserveVerdict,
    { readonly kind: "first-key" | "recorded-first-key" | "revoked" }
  >,
  command: string,
): string {
  const separate = `Run \`maruhi key recovery\` first: it creates a reserve key, seals it with a new recovery code and replaces the ledger. Then re-run \`${command}\``;
  switch (verdict.kind) {
    case "first-key":
      return `The recovery ledger holds key ${fingerprintHex}, your first key on ${describeProjects(verdict.projectIds)} (the key you created or joined that project with): a copy of a device key from an install before device keys, not a separate reserve key. ${separate}`;
    case "recorded-first-key":
      return `The recovery ledger holds key ${fingerprintHex}. This machine's records show it ${describeRecordedFirstKey(verdict.projectId)}: a copy of a device key from an install before device keys, not a separate reserve key. ${separate}`;
    case "revoked":
      return `The recovery ledger holds key ${fingerprintHex}, which is revoked on ${describeProjects(verdict.projectIds)}, so it cannot serve as your reserve key. Run \`maruhi key recovery\` first: it seals a new reserve key in its place. Then re-run \`${command}\``;
  }
}

/** The clause for the range that could not be checked (projects that cannot be synced, or a list failure) (K14-13 — do not make copies). */
export function describeUncheckedLedgerKey(
  key: string,
  verdict: Extract<ReserveVerdict, { readonly kind: "unchecked" }>,
): string {
  return verdict.listFailure === null
    ? `could not check ${key} on ${describeProjects(verdict.projectIds)}`
    : `could not list your projects to check ${key} (${verdict.listFailure})`;
}

/** Input of a ledger-changing command (the opening means, the device key to compare, the re-run command embedded in the refusal). */
interface LedgerChangeInput {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly via: LedgerOpenVia;
  /** This device's device key (the comparison target of the pre-DK judgment). */
  readonly masterKeys: MasterKeys;
  /** The re-run command embedded in the refusal wording (e.g. "maruhi guardian add …"). */
  readonly command: string;
}

/**
 * Opens the ledger for a change (passkey sealing / guardian designation / reserve
 * rotation): refuses a pre-DK ledger (B = this device's key, or — from the
 * project chains — a first key or a revoked key: DK K14-4) and records the
 * reserve key's public side locally (state restoration — K4-2 counterexample 2).
 */
export function openLedgerReserveForChange(
  input: LedgerChangeInput,
): Effect.Effect<ReserveKeys, CliError, CliServices> {
  return Effect.gen(function* () {
    const reserve = yield* openLedgerKeyForChange(input);
    const check = yield* ledgerKeyVerdictOf({
      session: input.session,
      client: input.client,
      fingerprintHex: reserve.fingerprintHex,
    });
    yield* settleLedgerKeyForChange({ ...input, reserve, check });
    return reserve;
  });
}

/**
 * Opens the ledger and refuses when it is a copy of the device key
 * at hand (an FP match) (the first half of the judgment — the
 * second half that looks at the chain is `settleLedgerKeyForChange`).
 * rotate calls the halves separately so it can check the opened key
 * and the record's rows together in one pass (DK K14-16).
 */
export function openLedgerKeyForChange(
  input: LedgerChangeInput,
): Effect.Effect<ReserveKeys, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const reserve = yield* openLedgerReserve(input);
    if (reserve.fingerprintHex === input.masterKeys.fingerprintHex) {
      return yield* Effect.fail(cliError(ledgerHoldsDeviceKeyMessage(input.command)));
    }
    return reserve;
  });
}

/**
 * Follows the judgment of the opened ledger key (the second half —
 * DK K16-6): when a stopping fact exists (the chain's first key,
 * this device's witness, revocation), stop without recording (fix
 * this device's wrong reserve row); when the reserve mark is
 * absent, stop without recording (`key recovery` separates it).
 * When the mark is present, record regardless of the range that
 * could not be checked (a marked key cannot be a device key —
 * CRYPTO_SPEC §8).
 */
export function settleLedgerKeyForChange(input: {
  readonly session: CliSession;
  readonly reserve: ReserveKeys;
  readonly check: LedgerKeyCheck;
  readonly command: string;
}): Effect.Effect<void, CliError, CliIo | OwnDeviceStore> {
  return Effect.gen(function* () {
    const { reserve, check } = input;
    const fingerprintHex = reserve.fingerprintHex;
    const { verdict, groups } = check;
    // Even without matching the key at hand, a key known not to work
    // as a reserve key on the chain is stopped without recording
    // (the same judgment as `key recovery` — recording a copy as
    // reserve makes rotate / --replace an input that silently
    // revokes the original device)
    if (stopsLedgerKey(verdict)) {
      yield* retractReserveRecord({ session: input.session, fingerprintHex, verdict, groups });
      return yield* Effect.fail(
        cliError(ledgerKeyUnusableMessage(fingerprintHex, verdict, input.command)),
      );
    }
    if (!isMarkedReserve(reserve)) {
      return yield* Effect.fail(
        cliError(
          `The recovery ledger holds key ${fingerprintHex}, which ${describeUnmarkedLedgerKey()}: a copy of a device key from an install before device keys, or a key sealed by another client, not a separate reserve key. Run \`maruhi key recovery\` first: it creates a reserve key, seals it with a new recovery code and replaces the ledger. Then re-run \`${input.command}\``,
        ),
      );
    }
    yield* recordReserveLocally(input.session, reserve);
    yield* logNote(`opened the reserve key (fingerprint ${fingerprintHex}) for this change`);
  });
}
