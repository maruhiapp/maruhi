// Recovery (`maruhi key recover`) and the reserve key's resealing /
// separation (`key recovery`) / rotate (`key reserve rotate`) —
// CRYPTO_SPEC §3 / §8, design record dk-design.md §9 K4-2 / K4-9 / K4-10 /
// K4-11.
//
// Recovery's tail `finishRecovery` (K4-10): the reserve key B obtained
// from the ledger is used **only for issuing the device key** (§8.1) —
// (1) generate this device's new device key and save it to the keychain,
// (2) on every project where B is a current device, sign
// `add_device(new device)` with B's sig key and open one's own wraps
// with B's enc key to backfill the new device, (3) discard B (release
// the in-memory reference — written to neither the keychain nor agent
// memory). B is recorded as the reserve key only when the ledger's
// content carries the reserve mark (CRYPTO_SPEC §8 — DK K16) and it is
// revoked nowhere on the chains opened for registration.
//
// `key recovery` (K4-2 / K4-9 / K16): without a ledger, generate and
// seal a reserve key (first time). With one, open it; if it lacks the
// reserve mark or is a key revoked somewhere, generate a fresh reserve
// key and reseal (separating). Otherwise reseal the same B under a
// fresh code and restore the record. `--replace` replaces without
// opening (the escape route for a lost code).
//
// `key reserve rotate` (K4-11): open → generate / seal / record a new
// reserve key → on every project `add_device(new)` + backfill →
// `revoke_device(old)` + sweep → delete old B's passkey / guardian rows
// (rows that can only restore a revoked key — leave no false trust).

import { ALL_SCOPE, type ChainDevice } from "@maruhi/crypto";
import { Effect } from "effect";
import type { HttpClient } from "effect/http";

import type { MaruhiClient } from "./api.ts";
import {
  type CliServices,
  openProject,
  type ProjectContext,
  type ProjectContextBase,
} from "./context.ts";
import type { DekRecipient } from "./deks.ts";
import { describeGapFillRoute } from "./device-gaps.ts";
import { findOwnDevice } from "./device-key.ts";
import {
  appendAddDevice,
  appendRevokeDevice,
  backfillToDevice,
  DEVICE_REVOKED_ROTATION_REASON,
  type DeviceBackfillOutcome,
  type DeviceSweepOutcome,
  sweepAfterDeviceRevoke,
} from "./device-ops.ts";
import {
  type KeyStanding,
  keyStandingOnProject,
  ledgerKeyVerdictOf,
  type ReserveVerdict,
  reserveVerdictOf,
} from "./device-standing.ts";
import { describeBackfill, reportRegisteredDevice } from "./device.ts";
import {
  countNoun,
  describeListedScope,
  describeProjects,
  describeUnmarkedLedgerKey,
  displayText,
} from "./display.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { requestHandoffReserve } from "./handoff.ts";
import { CliIo } from "./io.ts";
import { generateKeyRecord } from "./key-record.ts";
import { Keychain, masterKeyEntryName, serializeStoredMasterKey } from "./keychain.ts";
import { recoveryRegistered } from "./keygen.ts";
import {
  type LedgerOpenVia,
  noteUncheckedLedgerKey,
  openLedgerReserve,
  settleLedgerKeyForChange,
} from "./ledger-open.ts";
import { logNote, logWarning } from "./notice.ts";
import { OwnDeviceStore } from "./own-devices.ts";
import { fetchProjectMemberships } from "./project-list.ts";
import { issueRecoveryCodeOp, mapUnloadableRecoveryBlob, sealNewReserve } from "./recovery.ts";
import {
  generateReserveKeys,
  isMarkedReserve,
  markRevokedReserveRecord,
  recordReserveLocally,
  type ReserveKeys,
} from "./reserve.ts";
import {
  type CliSession,
  ensureNoStoredMasterKey,
  importMasterKeys,
  loadMasterKeys,
  type MasterKeys,
  storeMasterKeyAndReport,
} from "./session.ts";
import { sweepRotateFor } from "./sweep-rotate.ts";

/** How `maruhi key recover` opens the reserve key. */
export type RecoverVia = LedgerOpenVia | "handoff";

/** This device's new device key (issued after recovery — if one already exists, `--resume` reuses it). */
function newOrExistingDeviceKeys(input: {
  readonly session: CliSession;
  readonly resume: boolean;
}): Effect.Effect<MasterKeys, CliError, Keychain | CliIo> {
  return Effect.gen(function* () {
    const keychain = yield* Keychain;
    const existing = yield* keychain.get(
      masterKeyEntryName(input.session.origin, input.session.userId),
    );
    if (existing !== null) {
      if (!input.resume) {
        return yield* Effect.fail(
          cliError(
            "A device key already exists on this machine. If an earlier `maruhi key recover` was interrupted before every project registered this device, re-run with --resume (it reuses the existing key and registers it where it is missing); otherwise add this machine as a device from a registered one (`maruhi device add`)",
          ),
        );
      }
      return yield* loadMasterKeys(input.session);
    }
    const entryName = yield* ensureNoStoredMasterKey(
      input.session,
      "A device key already exists on this machine (check it with `maruhi key show`)",
    );
    const record = yield* generateKeyRecord();
    const validated = yield* importMasterKeys(record).pipe(
      Effect.mapError(() =>
        cliError(
          "Could not load the generated device key back (nothing was stored in the keychain). Report this as a maruhi bug",
        ),
      ),
    );
    yield* storeMasterKeyAndReport({
      entryName,
      serialized: serializeStoredMasterKey(record),
      action: "Generated this device's key",
      fingerprintHex: validated.fingerprintHex,
    });
    return validated;
  });
}

/** The result of the post-recovery registration on one project. */
interface ProjectRecoveryOutcome {
  readonly projectId: string;
  readonly state: "registered" | "already" | "reserve-missing" | "reserve-revoked" | "failed";
  readonly backfill: DeviceBackfillOutcome | null;
  readonly message: string | null;
  /** The opened key's standing on this project (the chain opened before registering — the judgment's material. DK K14-1). */
  readonly standing: KeyStanding;
}

/** Register the new device key to one project with B (the recovered reserve key) and backfill it. */
function registerDeviceWithReserve(input: {
  readonly session: CliSession;
  readonly projectId: string;
  readonly reserve: ReserveKeys;
  readonly device: MasterKeys;
}): Effect.Effect<ProjectRecoveryOutcome, never, CliServices> {
  return Effect.gen(function* () {
    // The keyless prologue (floor, anchors, and gossip do run. Submitting
    // attestations and the first-sync registration do not run — the new
    // device is not yet on the chain; signing is done manually with B).
    // The standing judgment lives in one place, device-standing.ts (a
    // sync failure folds into "could not sync" — DK K14-1)
    const standing = yield* keyStandingOnProject({
      session: input.session,
      projectId: input.projectId,
      fingerprintHex: input.reserve.fingerprintHex,
    });
    const base = { projectId: input.projectId, backfill: null, standing };
    if (standing.kind === "unsynced") {
      return {
        ...base,
        state: "failed",
        message: standing.message,
      } satisfies ProjectRecoveryOutcome;
    }
    if (standing.kind !== "active") {
      return {
        ...base,
        state: standing.kind === "revoked" ? "reserve-revoked" : "reserve-missing",
        message: null,
      } satisfies ProjectRecoveryOutcome;
    }
    return yield* addDeviceWithReserve({ ...input, context: standing.context }).pipe(
      Effect.map(({ appended, backfill }): ProjectRecoveryOutcome => ({
        ...base,
        state: appended ? "registered" : "already",
        backfill,
        message: null,
      })),
      Effect.catch((error) =>
        Effect.succeed<ProjectRecoveryOutcome>({
          ...base,
          state: "failed",
          message: error.message,
        }),
      ),
    );
  });
}

/** On a project where B is a current device, `add_device(new device)` signed by B → backfill with B's enc key. */
function addDeviceWithReserve(input: {
  readonly session: CliSession;
  readonly reserve: ReserveKeys;
  readonly device: MasterKeys;
  readonly context: ProjectContextBase;
}): Effect.Effect<
  { readonly appended: boolean; readonly backfill: DeviceBackfillOutcome },
  CliError,
  CliServices
> {
  return Effect.gen(function* () {
    const { context } = input;
    const outcome = yield* appendAddDevice({
      client: context.client,
      verified: context.verified,
      resync: context.resync,
      signer: { userId: input.session.userId, signingKeyPair: input.reserve.sigKeyPair },
      candidate: {
        encPubHex: input.device.record.encPubHex,
        sigPubHex: input.device.record.sigPubHex,
        cap: { roleCap: "owner", scope: ALL_SCOPE },
      },
    });
    const verified = yield* context.resync;
    const current = verified.state.members.get(input.session.userId);
    const targetDevice =
      current === undefined
        ? undefined
        : findOwnDevice(current, { keyFingerprintHex: input.device.fingerprintHex });
    if (current === undefined || targetDevice === undefined) {
      return yield* Effect.fail(
        cliError(
          "The resync after add_device was accepted does not show this device on the chain (the server's response contradicts the chain). Investigate the served chain",
        ),
      );
    }
    const recipient: DekRecipient = {
      userId: input.session.userId,
      encPubHex: input.reserve.record.encPubHex,
      encKeyPair: input.reserve.encKeyPair,
    };
    const backfill = yield* backfillToDevice({
      client: context.client,
      verified,
      recipient,
      targetMember: current,
      targetDevice,
      signerUserId: input.session.userId,
      signingKeyPair: input.reserve.sigKeyPair,
    });
    return { appended: outcome.appended, backfill };
  });
}

/**
 * Deciding whether to record the opened key as the reserve key (DK
 * K16): if it is revoked somewhere, or it lacks the reserve mark (the
 * `kind: "reserve"` this CLI writes into the ledger's content when it
 * generates one — CRYPTO_SPEC §8), say so and record nothing. Otherwise
 * record it without asking.
 */
function settleOpenedKey(input: {
  readonly session: CliSession;
  readonly reserve: ReserveKeys;
  readonly verdict: ReserveVerdict;
}): Effect.Effect<void, CliError, CliIo | OwnDeviceStore> {
  return Effect.gen(function* () {
    const fp = input.reserve.fingerprintHex;
    const { verdict } = input;
    if (verdict.kind === "revoked") {
      yield* markRevokedReserveRecord(input.session, fp);
      return yield* logWarning(
        `the opened key ${fp} is revoked on ${describeProjects(verdict.projectIds)}, so it was not recorded as your reserve key. Run \`maruhi key recovery\`: it seals a new reserve key in its place`,
      );
    }
    if (!isMarkedReserve(input.reserve)) {
      return yield* logWarning(
        `the opened key ${fp} ${describeUnmarkedLedgerKey()}, and it was not recorded as one. Run \`maruhi key recovery\`: it seals a reserve key in its place`,
      );
    }
    yield* recordReserveLocally(input.session, input.reserve);
    yield* logNote(`recorded ${fp} on this machine as your reserve key`);
  });
}

/**
 * The common tail of every recovery path: new device key → `add_device` signed
 * by the reserve key on every project where it is registered → backfill →
 * decide from the chains whether to record the opened key as the reserve key →
 * discard the reserve key (K4-10, revised by DK K14).
 */
function finishRecovery(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly reserve: ReserveKeys;
  readonly resume: boolean;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const device = yield* newOrExistingDeviceKeys({ session: input.session, resume: input.resume });
    yield* io.log(
      `Opened key ${input.reserve.fingerprintHex} from the recovery ledger. It is used only to register this machine's new device key, then discarded`,
    );
    const projects = yield* fetchProjectMemberships(input.client);
    const outcomes: ProjectRecoveryOutcome[] = [];
    for (const project of projects) {
      outcomes.push(
        yield* registerDeviceWithReserve({
          session: input.session,
          projectId: project.projectId,
          reserve: input.reserve,
          device,
        }),
      );
    }
    for (const outcome of outcomes) {
      yield* reportRecoveryOutcome(outcome);
    }
    // The judgment runs on the chains opened for registration (no doubled syncs — DK K14-1 / K14-5)
    // Projects that could not sync are already named in each project's
    // report, so no Note for the unchecked range is emitted
    yield* settleOpenedKey({
      session: input.session,
      reserve: input.reserve,
      verdict: reserveVerdictOf({
        projects: outcomes.map(({ projectId, standing }) => ({ projectId, standing })),
        listFailure: null,
      }),
    });
    // B's secret finishes its duty here (release the reference. The save paths are closed by types — reserve.ts)
    yield* logNote(
      "the reserve key was discarded from memory; it stays sealed in the recovery ledger only. This device now signs with its own key",
    );
  });
}

/** Reporting one project's post-recovery registration (registered / already / reserve-unregistered / revoked / failed). */
function reportRecoveryOutcome(outcome: ProjectRecoveryOutcome): Effect.Effect<void, never, CliIo> {
  const label = displayText(outcome.projectId);
  switch (outcome.state) {
    case "registered":
    case "already":
      return reportRegisteredDevice({
        label,
        action:
          outcome.state === "registered"
            ? "registered this device"
            : "this device was already registered",
        backfill: outcome.backfill,
        // `--resume` backfills even when already registered (with the
        // reserve key — the only route in a recovery situation where no
        // other device exists). A registered key cannot create a request,
        // so `device approve` is not named (DK K11-5)
        rerun: (environmentId) =>
          `Re-run \`maruhi key recover --resume\`. ${describeGapFillRoute(outcome.projectId, environmentId)}`,
      }).pipe(Effect.asVoid);
    case "reserve-missing":
      return logWarning(
        `${label}: the opened key is not registered on this project, so this device could not be added there. Ask an admin of the project to re-invite you (\`maruhi invite create\`)`,
      );
    case "reserve-revoked":
      return logWarning(
        `${label}: the opened key was revoked on this project, so this device could not be added there. Ask an admin of the project to re-invite you (\`maruhi invite create\`)`,
      );
    case "failed":
      return logWarning(`${label}: could not register this device (${outcome.message ?? ""})`);
  }
}

/**
 * `maruhi key recover [--passkey|--handoff] [--resume]`: open the reserve key,
 * then register this machine as a new device with it (K4-10).
 */
export function keyRecoverOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly via: RecoverVia;
  readonly resume: boolean;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    // A machine that already has a key is refused before touching the
    // ceremony (code entry, passkey, creating a request) or the server
    // (--resume is the only exception — continuing an interrupted
    // recovery)
    if (!input.resume) {
      const keychain = yield* Keychain;
      const existing = yield* keychain.get(
        masterKeyEntryName(input.session.origin, input.session.userId),
      );
      if (existing !== null) {
        return yield* Effect.fail(
          cliError(
            "A device key already exists on this machine, so there is nothing to recover here. To add this machine as another device of yours, run `maruhi device add` and approve it from a registered device; if an earlier `maruhi key recover` was interrupted before every project registered this device, re-run with --resume",
          ),
        );
      }
    }
    const reserve =
      input.via === "handoff"
        ? yield* Effect.flatMap(
            requestHandoffReserve({ session: input.session, client: input.client }),
            (record) => mapUnloadableRecoveryBlob(importMasterKeys(record)),
          ).pipe(
            Effect.map((keys): ReserveKeys => ({
              reserve: true,
              record: keys.record,
              encKeyPair: keys.encKeyPair,
              sigKeyPair: keys.sigKeyPair,
              fingerprintHex: keys.fingerprintHex,
            })),
          )
        : yield* openLedgerReserve({
            session: input.session,
            client: input.client,
            via: input.via,
          });
    yield* finishRecovery({
      session: input.session,
      client: input.client,
      reserve,
      resume: input.resume,
    });
  });
}

/**
 * `maruhi key recovery [--passkey] [--replace]`: create the reserve key (first
 * sealing), replace a ledger key that cannot serve as the reserve key, or reissue its recovery code
 * (K4-2 / DK K16).
 */
export function keyRecoveryOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly via: LedgerOpenVia;
  readonly replace: boolean;
}): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const registered = yield* recoveryRegistered(input.client);
    if (!registered) {
      yield* io.log("No reserve key is sealed yet — creating one");
      yield* sealNewReserve({ session: input.session, client: input.client });
      return 0;
    }
    if (input.replace) {
      if (input.via === "passkey") {
        // --passkey is a way to open the ledger. --replace presumes never
        // opening it, so they cannot combine — with a passkey, opening and
        // reissuing keeps the same reserve key (noted by pullfrog)
        return yield* Effect.fail(
          usageError(
            "--passkey cannot be combined with --replace: --replace never opens the ledger. If you still have a passkey, run `maruhi key recovery --passkey` (without --replace) to reissue the recovery code for the same reserve key",
          ),
        );
      }
      return yield* replaceReserveWithoutOpening(input);
    }
    const opened = yield* openLedgerReserve({
      session: input.session,
      client: input.client,
      via: input.via,
    });
    // When the ledger's key cannot serve as a reserve key (no mark, or revoked somewhere), separate it (DK K16)
    const verdict = yield* separateUnusableLedgerKey({ ...input, opened });
    if (verdict === "separated") {
      return 0;
    }
    // Resealing the reserve key (same B, a fresh code — the reserve mark is carried along too) + restoring the record
    yield* issueRecoveryCodeOp({
      session: input.session,
      client: input.client,
      record: opened.record,
    });
    yield* recordReserveLocally(input.session, opened);
    yield* logNote(
      `reissued the recovery code for your reserve key (fingerprint ${opened.fingerprintHex}); the previous code no longer works`,
    );
    return 0;
  });
}

/**
 * If the ledger's key cannot serve as a reserve key, seal a new reserve
 * key and separate it (DK K16): the targets are a key without the
 * reserve mark or a key revoked somewhere (→ "separated"). Everything
 * else goes to resealing and recording (→ "record").
 */
function separateUnusableLedgerKey(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly opened: ReserveKeys;
}): Effect.Effect<"separated" | "record", CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const fp = input.opened.fingerprintHex;
    if (!isMarkedReserve(input.opened)) {
      yield* io.log(
        `The recovery ledger holds key ${fp}, which ${describeUnmarkedLedgerKey()}. Creating a reserve key and sealing it instead`,
      );
      yield* sealNewReserve({ session: input.session, client: input.client });
      return "separated";
    }
    const verdict = yield* ledgerKeyVerdictOf({
      session: input.session,
      client: input.client,
      fingerprintHex: fp,
    });
    if (verdict.kind === "revoked") {
      yield* markRevokedReserveRecord(input.session, fp);
      yield* io.log(
        `The recovery ledger holds key ${fp}, which is revoked on ${describeProjects(verdict.projectIds)}, so it cannot serve as your reserve key. Creating a new reserve key and sealing it instead`,
      );
      yield* sealNewReserve({ session: input.session, client: input.client });
      if (verdict.activeProjectIds.length > 0) {
        yield* logNote(
          `the key ${fp} is still registered on ${describeProjects(verdict.activeProjectIds)}; revoke it there too: \`maruhi device revoke ${fp}\``,
        );
      }
      return "separated";
    }
    yield* noteUncheckedLedgerKey(fp, verdict);
    return "record";
  });
}

/**
 * `key recovery --replace` (the escape route for a lost / leaked code):
 * seals a new reserve key without opening the ledger and revokes the old
 * reserve keys in this machine's records on every project (K4-38). Since
 * the old B cannot be opened, the revocations are signed by this device
 * key (the same route as rotate). An old reserve key absent from the
 * records cannot be revoked, which is warned about.
 */
function replaceReserveWithoutOpening(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
}): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    // Before writing, name what disappears: the code, the registrations
    // of the reserve keys in the records, and the ledger's rows that
    // sealed the old B (passkeys / guardians). If a passkey survives,
    // --passkey keeps the same reserve key (noted by pullfrog)
    // The ledger rows' counts are read only for the warning's wording: an
    // unreadable listing does not stop the replacement (it is the escape
    // route of a user who lost the code — not plugged by a listing
    // failure — noted by Bugbot). The fact it could not be read becomes a
    // Note
    const status = yield* input.client.keyWraps.status({}).pipe(
      Effect.mapError(toCliError),
      Effect.catch((error) =>
        logNote(
          `could not read the ledger's passkey wraps and guardian groups (${error.message}); the warning below names them generically`,
        ).pipe(Effect.as(null)),
      ),
    );
    yield* logWarning(
      `replacing the recovery ledger without opening it: the previous recovery code stops working, and the reserve keys recorded on this machine are revoked on every project the server lists for you${describeSealedRows(status)}. A previous reserve key that is not recorded here stays registered until you revoke it with \`maruhi device revoke <fingerprint>\` (\`maruhi device list\` shows your devices)`,
    );
    const next = yield* generateReserveKeys();
    const retiring = yield* staleReserveFingerprints(input.session, null, next.fingerprintHex);
    yield* issueRecoveryCodeOp({
      session: input.session,
      client: input.client,
      record: next.record,
    });
    if (retiring.length === 0) {
      yield* logWarning(
        "no previous reserve key is recorded on this machine, so none was revoked. Check `maruhi device list` and revoke any reserve device you do not recognise with `maruhi device revoke <fingerprint>`",
      );
    }
    return yield* registerReserveAndRetire({ ...input, next, retiring, ledgerRows: status });
  });
}

/**
 * The description of the ledger rows that sealed the old B, attached to
 * `--replace`'s warning (noted by pullfrog): the generic form when the
 * listing cannot be read, nothing said when there are no rows (no
 * deletion of absent rows, no guidance for the unusable `--passkey`),
 * and when present their count plus — if a passkey exists — the
 * `--passkey` alternative.
 */
function describeSealedRows(
  status: {
    readonly passkeys: readonly unknown[];
    readonly guardianGroups: readonly unknown[];
  } | null,
): string {
  if (status === null) {
    return ", and any passkey wraps and guardian groups that seal the current reserve key are deleted. If you still have a passkey for the current reserve key, stop here and run `maruhi key recovery --passkey` instead: it reissues the code for the same reserve key";
  }
  const passkeys = status.passkeys.length;
  const groups = status.guardianGroups.length;
  if (passkeys + groups === 0) {
    return "";
  }
  const passkeyAdvice =
    passkeys === 0
      ? ""
      : ". If you still have that passkey, stop here and run `maruhi key recovery --passkey` instead: it reissues the code for the same reserve key";
  return `, and ${countNoun(passkeys, "passkey wrap")} and ${countNoun(groups, "guardian group")} that seal the current reserve key are deleted${passkeyAdvice}`;
}

/**
 * Recording the new reserve key → the recorded revocation of the old
 * reserve keys → per project add_device / revoke_device / sweep →
 * deleting the ledger rows that sealed the old B (the shared tail of
 * rotate and `--replace`).
 */
function registerReserveAndRetire(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly next: ReserveKeys;
  readonly retiring: readonly string[];
  /** The ledger rows read ahead of time (`--replace`). undefined = read at the tail (rotate). */
  readonly ledgerRows?: LedgerRows;
}): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const store = yield* OwnDeviceStore;
    yield* recordReserveLocally(input.session, input.next);
    yield* store.markRevoked(
      input.session.origin,
      input.session.userId,
      input.retiring,
      Date.now(),
    );
    const projects = yield* fetchProjectMemberships(input.client);
    yield* io.log(
      `Sealed the new reserve key ${input.next.fingerprintHex}; registering it${input.retiring.length === 0 ? "" : ` and revoking the previous reserve ${input.retiring.length === 1 ? "key" : "keys"} ${input.retiring.join(", ")}`} on ${describeListedScope(projects.length)}`,
    );
    let exitCode = 0;
    for (const project of projects) {
      const outcome = yield* rotateReserveOnProject({
        session: input.session,
        projectId: project.projectId,
        newReserve: input.next,
        oldFingerprintsHex: input.retiring,
      });
      if ((yield* reportReserveRotateOutcome(outcome)) !== 0) {
        exitCode = 1;
      }
    }
    yield* retireOldLedgerRows(input.client, input.ledgerRows);
    return exitCode;
  });
}

/** The listing of the ledger's rows (`GET /auth/key-wraps`). null = unreadable (already Noted by the advance warning). */
type LedgerRows = {
  readonly passkeys: readonly { readonly wrapId: string }[];
  readonly guardianGroups: readonly { readonly groupId: string }[];
} | null;

/** The result of the reserve-key rotate on one project. */
interface ReserveRotateOutcome {
  readonly projectId: string;
  readonly added: boolean;
  readonly backfill: DeviceBackfillOutcome | null;
  readonly revoked: readonly string[];
  readonly sweep: DeviceSweepOutcome | null;
  readonly failure: string | null;
}

/** On one project, add the new reserve key, revoke the old ones, and sweep (K4-11's order). */
function rotateReserveOnProject(input: {
  readonly session: CliSession;
  readonly projectId: string;
  readonly newReserve: ReserveKeys;
  /** The FPs of the old reserve keys to revoke (the opened B + the recorded old reserve keys — left behind by nothing on a re-run after interruption). */
  readonly oldFingerprintsHex: readonly string[];
}): Effect.Effect<ReserveRotateOutcome, never, CliServices> {
  return Effect.gen(function* () {
    const context: ProjectContext = yield* openProject(
      { server: input.session.origin, project: input.projectId },
      { quietMandateWarning: true },
    );
    const added = yield* appendAddDevice({
      client: context.client,
      verified: context.verified,
      resync: context.resync,
      signer: { userId: context.session.userId, signingKeyPair: context.masterKeys.sigKeyPair },
      candidate: {
        encPubHex: input.newReserve.record.encPubHex,
        sigPubHex: input.newReserve.record.sigPubHex,
        cap: { roleCap: "owner", scope: ALL_SCOPE },
      },
    });
    let verified = yield* context.resync;
    const member = verified.state.members.get(context.session.userId);
    const target: ChainDevice | undefined =
      member === undefined
        ? undefined
        : findOwnDevice(member, { keyFingerprintHex: input.newReserve.fingerprintHex });
    if (member === undefined || target === undefined) {
      return yield* Effect.fail(
        cliError(
          "The resync after add_device was accepted does not show the new reserve key on the chain (the server's response contradicts the chain)",
        ),
      );
    }
    const backfill = yield* backfillToDevice({
      client: context.client,
      verified,
      recipient: context.recipient,
      targetMember: member,
      targetDevice: target,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
    });
    const revoke = yield* appendRevokeDevice({
      client: context.client,
      verified,
      resync: context.resync,
      signer: { userId: context.session.userId, signingKeyPair: context.masterKeys.sigKeyPair },
      targetUserId: context.session.userId,
      fingerprintsHex: input.oldFingerprintsHex,
    });
    verified = yield* context.resync;
    const actorMember = verified.state.members.get(context.session.userId);
    const actorDevice =
      actorMember === undefined
        ? undefined
        : findOwnDevice(actorMember, { keyFingerprintHex: context.masterKeys.fingerprintHex });
    const sweep =
      revoke.revoked.length === 0 || actorDevice === undefined
        ? null
        : yield* sweepAfterDeviceRevoke({
            client: context.client,
            verified,
            targetUserId: context.session.userId,
            actorUserId: context.session.userId,
            actorDevice,
            rotate: sweepRotateFor(
              { ...context, verified, resync: context.resync },
              DEVICE_REVOKED_ROTATION_REASON,
            ),
          });
    return {
      projectId: input.projectId,
      added: added.appended,
      backfill,
      revoked: revoke.revoked,
      sweep,
      failure: null,
    } satisfies ReserveRotateOutcome;
  }).pipe(
    Effect.catch((error) =>
      Effect.succeed({
        projectId: input.projectId,
        added: false,
        backfill: null,
        revoked: [],
        sweep: null,
        failure: error.message,
      } satisfies ReserveRotateOutcome),
    ),
  );
}

/** Reporting one project's reserve-key rotate (exit code: 1 on any failure). */
function reportReserveRotateOutcome(
  outcome: ReserveRotateOutcome,
): Effect.Effect<number, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const label = displayText(outcome.projectId);
    if (outcome.failure !== null) {
      yield* logWarning(`${label}: ${outcome.failure} — re-run to continue`);
      return 1;
    }
    yield* io.log(
      `${label}: new reserve key ${outcome.added ? "registered" : "already registered"}${describeBackfill(outcome.backfill)}; previous reserve key ${outcome.revoked.length > 0 ? "revoked" : "already revoked"}`,
    );
    // A failed backfill to the new reserve key used to be folded into the
    // count and invisible (DK K11's G9 — an environment the reserve key
    // cannot open at recovery would silently remain). Like the
    // approve / recover backfill failures it is exit code 1 (K11-14 —
    // the owner's ruling: align. The old reserve key is revoked right
    // after, so a script must be able to detect the new reserve key's
    // gap)
    const failed = outcome.backfill?.failed ?? [];
    for (const failure of failed) {
      yield* logWarning(
        `${label}: backfill of environment ${displayText(failure.environmentId)} to the new reserve key failed (${failure.message}). ${describeGapFillRoute(outcome.projectId, failure.environmentId)}`,
      );
    }
    const sweepCode = outcome.sweep === null ? 0 : yield* reportReserveSweep(label, outcome.sweep);
    return failed.length > 0 ? 1 : sweepCode;
  });
}

/** Reporting the sweep (K4-8) that follows the old reserve key's revocation (1 on any failure). */
function reportReserveSweep(
  label: string,
  sweep: DeviceSweepOutcome,
): Effect.Effect<number, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const failures =
      sweep.failed.length > 0 ? `, ${countNoun(sweep.failed.length, "failure")}` : "";
    yield* io.log(
      `${label}: rotated ${countNoun(sweep.rotated.length, "environment")}, ${sweep.alreadyRotated.length} already rotated${failures}`,
    );
    for (const failure of sweep.failed) {
      yield* logWarning(
        `${label}: environment ${displayText(failure.environmentId)}: ${failure.message}`,
      );
    }
    if (sweep.outOfScope.length > 0) {
      yield* logWarning(
        `${label}: ${countNoun(sweep.outOfScope.length, "environment")} with a rotation mandate cannot be rotated from this device (${sweep.outOfScope.map(displayText).join(", ")}) — a member holding those DEKs converges them with \`maruhi env rotate <environment> --new-epoch --reason <text>\``,
      );
    }
    return sweep.failed.length > 0 ? 1 : 0;
  });
}

/**
 * The FP set of old reserve keys to revoke (ascending): the opened B
 * and every locally-recorded row of provenance "reserve" (regardless of
 * a revoked mark — picks up a key that got only the mark written before
 * the last interruption), minus the new key.
 */
function staleReserveFingerprints(
  session: CliSession,
  openedFingerprintHex: string | null,
  /** The new reserve key (null on rotate, which computes this before generating — a just-generated key is absent from the records). */
  nextFingerprintHex: string | null,
): Effect.Effect<readonly string[], CliError, OwnDeviceStore> {
  return Effect.gen(function* () {
    const store = yield* OwnDeviceStore;
    const lookup = yield* store.load(session.origin, session.userId);
    const recorded =
      lookup.state === "loaded"
        ? lookup.devices
            .filter((entry) => entry.source === "reserve")
            .map((entry) => entry.keyFingerprintHex)
        : [];
    return [
      ...new Set([...(openedFingerprintHex === null ? [] : [openedFingerprintHex]), ...recorded]),
    ]
      .filter((fingerprintHex) => fingerprintHex !== nextFingerprintHex)
      .toSorted();
  });
}

/**
 * Deleting the old B's passkey rows and guardian groups (rows that can
 * only ever restore a revoked key — K4-11). `rows` undefined = read it
 * now. null (unreadable beforehand — `--replace`) = the intervening
 * writes never touched these rows so the same failure is not hit twice;
 * skip the deletion and put the removal procedure into a Note (noted by
 * pullfrog: do not fail the command on the same failure after the writes
 * are done).
 */
function retireOldLedgerRows(
  client: MaruhiClient,
  rows?: LedgerRows,
): Effect.Effect<void, CliError, CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    if (rows === null) {
      yield* logNote(
        "the ledger's passkey wraps and guardian groups could not be listed, so any that sealed the previous reserve key were left in place (they can only restore a revoked key). Remove them later with `maruhi key seal list` / `maruhi key seal remove <wrap-id>` and `maruhi guardian list` / `maruhi guardian remove <group-id>`",
      );
      return;
    }
    const status = rows ?? (yield* client.keyWraps.status({}).pipe(Effect.mapError(toCliError)));
    for (const passkey of status.passkeys) {
      yield* client.keyWraps.passkeyDelete({ params: { wrapId: passkey.wrapId } }).pipe(
        Effect.catchTag("KeyWrapNotFound", () => Effect.void),
        Effect.mapError(toCliError),
      );
    }
    for (const group of status.guardianGroups) {
      yield* client.keyWraps.guardianDelete({ params: { groupId: group.groupId } }).pipe(
        Effect.catchTag("KeyWrapNotFound", () => Effect.void),
        Effect.mapError(toCliError),
      );
    }
    if (status.passkeys.length > 0 || status.guardianGroups.length > 0) {
      yield* logNote(
        `removed ${countNoun(status.passkeys.length, "passkey wrap")} and ${countNoun(status.guardianGroups.length, "guardian group")} that sealed the previous reserve key (they could only restore a revoked key). Seal the new reserve key again with \`maruhi key seal passkey\` / \`maruhi guardian add\``,
      );
    }
  });
}

/**
 * `maruhi key reserve rotate [--passkey]`: register a new reserve key and revoke
 * the previous one on every project (K4-11).
 */
export function keyReserveRotateOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly via: LedgerOpenVia;
}): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    // The old reserve key's revocation and the new reserve key's registration are signed by this device key: verify before opening the ledger (the code entry)
    yield* loadMasterKeys(input.session);
    const command = "maruhi key reserve rotate";
    const old = yield* openLedgerReserve(input);
    // The opened B proceeds only when it carries the reserve mark and is
    // revoked nowhere (DK K16 — an unmarked one is left untouched)
    const verdict = yield* ledgerKeyVerdictOf({
      session: input.session,
      client: input.client,
      fingerprintHex: old.fingerprintHex,
    });
    yield* settleLedgerKeyForChange({ session: input.session, reserve: old, verdict, command });
    // The revocation targets = the opened B + the locally recorded
    // reserve keys (revoked marks included), minus the new key. If a
    // previous run was interrupted having replaced only the ledger, B is
    // the previous run's new key while the original reserve key stays in
    // the records as revoked but is still on the chains (Bugbot
    // finding). appendRevokeDevice revokes only devices still valid on a
    // chain (idempotent)
    const retiring = yield* staleReserveFingerprints(input.session, old.fingerprintHex, null);
    const next = yield* generateReserveKeys();
    yield* issueRecoveryCodeOp({
      session: input.session,
      client: input.client,
      record: next.record,
    });
    return yield* registerReserveAndRetire({ ...input, next, retiring });
  });
}
