// Device registration on first sync and observing the device set
// (CRYPTO_SPEC §6.2 / §7 — 2026-09-19 DK; design record dk-design.md
// §9 K4-3 / K4-4 / K4-9 / K4-14).
//
// The keyed pre-stage (context.ts's openProjectWith) calls this after
// every sync (idempotent — K4-3 third pass). What it does:
//   (a) Observation: my devices on the verified chain that are not in
//       the local record are recorded as "observed", and the
//       provenance (whose device added them at which seq) is shown in
//       a Note (K4-4 d-2). A device recorded as revoked that is on the
//       chain again gets a Note (only an explicit re-approval restores
//       the record)
//   (b) Revocation observation: record rows contained in a
//       my-addressed `revoke_device` on the chain become revoked
//       (K4-3 counterexample 1 — do not resurrect on another project)
//   (c) Registration: among the local record, devices not revoked and
//       not on this chain (reserve keys, approved devices, devices
//       observed on other projects) are `add_device`'d with this
//       device's signature and backfilled. Rows that cannot be added
//       by the pre-flight judgment (cap monotonicity, existence of
//       `listed` environments) and the server's acceptance policy
//       (DeviceLimit) become Notes and continue. It does not change
//       the command's success (an adjunct of a SHOULD)
//   (d) Warning of a missing reserve key (K4-9): when this device is
//       my only device and the record has no reserve key
//
// The device registry (`GET /auth/devices`) is neither read nor
// written here (K4-3 counterexample 2 — pinned by a test).

import { type EnvironmentId, type ProjectId } from "@maruhi/core";
import type { ChainDevice, ChainMember } from "@maruhi/crypto";
import { Clock, Effect, type Stdio } from "effect";

import { ensureHumanCeremonyAllowed } from "./agent-gate.ts";
import type { VerifiedProject } from "./chain-sync.ts";
import type { ProjectContext } from "./context.ts";
import { gapFillCommandOf } from "./device-gaps.ts";
import {
  capWithinSignerCap,
  describeCap,
  deviceProvenanceOf,
  devicesOf,
  findOwnDevice,
  reAddDeviceRoute,
  revokedFingerprintsOf,
} from "./device-key.ts";
import { appendAddDevice, backfillToDevice } from "./device-ops.ts";
import { countNoun, displayText } from "./display.ts";
import type { CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import { logNote, logWarning } from "./notice.ts";
import {
  capOfRecord,
  type OwnDeviceEntry,
  OwnDeviceStore,
  type OwnDeviceStoreShape,
} from "./own-devices.ts";
import { requireScopeEnvironmentsExist } from "./scope.ts";

/**
 * Runs the device-set reconciliation for one keyed command (idempotent). Returns
 * the context with a resynced view when this device appended anything. Never
 * fails the command: every problem becomes a Note / Warning.
 */
export const syncOwnDevices = Effect.fn("device-sync.syncOwnDevices")(function* (
  context: ProjectContext,
): Effect.fn.Return<ProjectContext, never, OwnDeviceStore | CliIo | Stdio.Stdio> {
  const store = yield* OwnDeviceStore;
  const { session } = context;
  const self = context.verified.state.members.get(session.userId);
  if (self === undefined) {
    return context;
  }
  const lookup = yield* store
    .load(session.origin, session.userId)
    .pipe(Effect.orElseSucceed(() => ({ state: "corrupt" }) as const));
  if (lookup.state === "corrupt") {
    yield* logWarning(
      `the own-devices record is corrupt and was ignored: ${store.filePath} — inspect it, and delete it if the change was not intentional (device keys are re-observed from the project chains)`,
    );
    return context;
  }
  const records = lookup.state === "loaded" ? lookup.devices : [];
  // (a)(b): observation and revocation observation (record updates are fail-open — a Note when unwritable)
  yield* observeDevices({ context, self, records, store });
  // (c): registration (can sign only when this device is my device on the chain)
  const own = findOwnDevice(self, { keyFingerprintHex: context.masterKeys.fingerprintHex });
  if (own === undefined) {
    return context;
  }
  let current = context;
  const candidates = registrationCandidates(context.verified, self, records);
  // Registration involves signing (add_device + DEK wraps), so it is
  // done only in a human session that passes the same ceremony gate
  // as `device approve` (known agent → whether stdin / stdout is a
  // terminal). The local record is an unsigned file: in an agent
  // environment a planted row would add a signer without this gate
  // (K4-37 — security review point)
  if (candidates.length > 0 && (yield* registrationAllowed(context.projectId, candidates))) {
    for (const candidate of candidates) {
      current = yield* registerRecorded({ context: current, self, own, candidate });
    }
  }
  // (d): missing reserve key (K4-9)
  yield* warnReserveMissing({
    self: current.verified.state.members.get(session.userId) ?? self,
    own,
    records,
  });
  return current;
});

/**
 * (c)'s ceremony gate (K4-37): emits a Note and returns false when
 * not passed (the command body is not stopped — registration is an
 * adjunct of a SHOULD). The material is the same two layers as
 * `ensureDeviceApproveAllowed`.
 */
function registrationAllowed(
  projectId: ProjectId,
  candidates: readonly OwnDeviceEntry[],
): Effect.Effect<boolean, never, CliIo | Stdio.Stdio> {
  return ensureHumanCeremonyAllowed({
    agentRefusal: (detected) => `an AI agent environment was detected${detected}`,
    terminalRefusal: (reason) => reason,
  }).pipe(
    Effect.as(true),
    Effect.catch((error) =>
      logNote(
        `${countNoun(candidates.length, "device key")} recorded on this machine (${candidates.map((candidate) => candidate.keyFingerprintHex).join(", ")}) ${candidates.length === 1 ? "is" : "are"} not registered on project ${displayText(projectId)} yet. Registering a device key adds a signer and wraps DEKs to it, so it is done only when a person runs maruhi at an interactive terminal — skipped here because ${error.message}. Run a keyed maruhi command on this project yourself in a terminal (for example \`maruhi pull --project ${displayText(projectId)}\`) to register ${candidates.length === 1 ? "it" : "them"}, or remove the record if you do not recognise it (\`maruhi device list\`)`,
      ).pipe(Effect.as(false)),
    ),
  );
}

/** (c)'s candidates: records that are not revoked, not on this chain, and not revoked on this chain either. */
function registrationCandidates(
  verified: VerifiedProject,
  self: ChainMember,
  records: readonly OwnDeviceEntry[],
): readonly OwnDeviceEntry[] {
  const revokedHere = revokedFingerprintsOf(verified, self.userId);
  return records.filter(
    (record) =>
      record.revokedAtMs === null &&
      !self.devices.has(record.keyFingerprintHex) &&
      !revokedHere.has(record.keyFingerprintHex),
  );
}

/** (d) K4-9: warning when this device is my only device and the record has no reserve key (one piece of guidance per fact). */
function warnReserveMissing(input: {
  readonly self: ChainMember;
  readonly own: ChainDevice;
  readonly records: readonly OwnDeviceEntry[];
}): Effect.Effect<void, never, CliIo> {
  const onlyThisDevice =
    input.self.devices.size === 1 && input.self.devices.has(input.own.keyFingerprintHex);
  const hasReserveRecord = input.records.some(
    (record) => record.source === "reserve" && record.revokedAtMs === null,
  );
  if (!onlyThisDevice || hasReserveRecord) {
    return Effect.void;
  }
  return logWarning(
    "no reserve key is registered for you on this project (only this device's key). Run `maruhi key recovery` to create a reserve key and seal it. Without a reserve key, losing this device means losing access",
  );
}

/** (a)(b) Observation: records my devices on the chain and writes revocations into the record. */
const observeDevices = Effect.fn("device-sync.observeDevices")(function* (input: {
  readonly context: ProjectContext;
  readonly self: ChainMember;
  readonly records: readonly OwnDeviceEntry[];
  readonly store: OwnDeviceStoreShape;
}): Effect.fn.Return<void, never, CliIo> {
  const { context, self, records, store } = input;
  const { session } = context;
  const byFp = new Map(records.map((record) => [record.keyFingerprintHex, record]));
  for (const device of devicesOf(self)) {
    const known = byFp.get(device.keyFingerprintHex);
    const provenance = deviceProvenanceOf(context.verified, session.userId, device);
    if (known === undefined) {
      // First observation (K4-4 d-2): a Note with provenance. My own device is recorded silently
      const entry: OwnDeviceEntry = {
        keyFingerprintHex: device.keyFingerprintHex,
        encPubHex: device.encPubHex,
        sigPubHex: device.sigPubHex,
        roleCap: device.roleCap,
        scope: device.scope,
        source: "observed",
        label: null,
        addedByFingerprintHex: provenance.addedByFingerprintHex,
        observedProjectId: context.projectId,
        recordedAtMs: yield* Clock.currentTimeMillis,
        revokedAtMs: null,
      };
      yield* store
        .record(session.origin, session.userId, entry)
        .pipe(Effect.catch((error) => noteWriteFailure(error)));
      if (device.keyFingerprintHex !== context.masterKeys.fingerprintHex) {
        yield* logNote(describeObservation(context.projectId, device, provenance));
      }
    } else if (known.revokedAtMs !== null) {
      // Only re-approval clears the revocation mark, and a
      // registered key cannot recreate a request (DK K10-5), so it
      // does not say "approve it again" (a procedure the user cannot
      // follow). If the device is needed on other projects, use a
      // new key
      yield* logNote(
        `device ${device.keyFingerprintHex} was revoked from this machine's records but is active on project ${displayText(context.projectId)} (${describeAdder(provenance)}). It is not re-added to other projects from here (a revoked record is never cleared by syncing). If it should not be active, revoke it with \`maruhi device revoke ${device.keyFingerprintHex}\`; if that machine should be on more projects, revoke it, then ${reAddDeviceRoute("that machine")}`,
      );
    }
  }
  // (b): write this chain's revocations into the record (among
  // the revoked FPs not the current device, those whose record is
  // active)
  const revokedHere = revokedFingerprintsOf(context.verified, session.userId);
  const toMark = records
    .filter(
      (record) =>
        record.revokedAtMs === null &&
        revokedHere.has(record.keyFingerprintHex) &&
        !self.devices.has(record.keyFingerprintHex),
    )
    .map((record) => record.keyFingerprintHex);
  if (toMark.length > 0) {
    yield* store
      .markRevoked(session.origin, session.userId, toMark, yield* Clock.currentTimeMillis)
      .pipe(Effect.catch((error) => noteWriteFailure(error)));
    yield* logNote(
      `device ${toMark.join(", ")} is revoked on project ${displayText(context.projectId)}; marked as revoked in this machine's records (it will not be added to other projects from here)`,
    );
  }
});

function describeAdder(provenance: {
  readonly addedByFingerprintHex: string | null;
  readonly seq: number;
  readonly adderStillActive: boolean;
}): string {
  return provenance.addedByFingerprintHex === null
    ? `your first key on the chain, seq ${provenance.seq}`
    : `added by device ${provenance.addedByFingerprintHex} at seq ${provenance.seq}${provenance.adderStillActive ? "" : " — that device is now revoked"}`;
}

function describeObservation(
  projectId: ProjectId,
  device: ChainDevice,
  provenance: {
    readonly addedByFingerprintHex: string | null;
    readonly seq: number;
    readonly adderStillActive: boolean;
  },
): string {
  return `observed your device ${device.keyFingerprintHex} (cap ${describeCap(device)}) on project ${displayText(projectId)}: ${describeAdder(provenance)}. It was not approved from this machine; compare it with \`maruhi device list\` and, if you do not recognise it, revoke it with \`maruhi device revoke ${device.keyFingerprintHex}\``;
}

function noteWriteFailure(error: CliError): Effect.Effect<void, never, CliIo> {
  return logNote(
    `could not update this machine's own-devices record (${error.message}); the device set is re-observed on the next sync`,
  );
}

/** (c) Registering one row (every failure is a Note — one device's failure does not stop the sync). */
function registerRecorded(input: {
  readonly context: ProjectContext;
  readonly self: ChainMember;
  readonly own: ChainDevice;
  readonly candidate: OwnDeviceEntry;
}): Effect.Effect<ProjectContext, never, CliIo> {
  const { context, candidate, own } = input;
  const label = `${candidate.keyFingerprintHex} (${candidate.source}${candidate.label === null ? "" : `, "${displayText(candidate.label)}"`})`;
  const cap = capOfRecord(candidate);
  return Effect.gen(function* () {
    if (!capWithinSignerCap(cap, own)) {
      yield* logNote(
        `your device ${label} is not registered on project ${displayText(context.projectId)} yet, and this device's cap ${describeCap(own)} cannot register a device with cap ${describeCap(cap)}. Sync from a device with a wider cap to register it`,
      );
      return context;
    }
    yield* requireScopeEnvironmentsExist(context.verified, cap.scope);
    const { appended } = yield* appendAddDevice({
      client: context.client,
      verified: context.verified,
      resync: context.resync,
      signer: { userId: context.session.userId, signingKeyPair: context.masterKeys.sigKeyPair },
      candidate: { encPubHex: candidate.encPubHex, sigPubHex: candidate.sigPubHex, cap },
    });
    const verified = yield* context.resync;
    const current = verified.state.members.get(context.session.userId);
    const targetDevice = current?.devices.get(candidate.keyFingerprintHex);
    if (current === undefined || targetDevice === undefined) {
      yield* logNote(
        `registered your device ${label} on project ${displayText(context.projectId)}, but the resync does not show it yet, so its keys were not distributed. Once it appears there, \`${gapFillCommandOf(context.projectId, "<environment>")}\` on a registered device of yours whose cap covers the environment fills its keys, for each environment it should read`,
      );
      return { ...context, verified };
    }
    const backfill = yield* backfillToDevice({
      client: context.client,
      verified,
      recipient: context.recipient,
      targetMember: current,
      targetDevice,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
    });
    // The only point where the record's cap works, so the added
    // (found) cap is reported from the chain (DK K10-3)
    yield* logNote(
      `${appended ? "registered" : "found"} your device ${label} with cap ${describeCap(targetDevice)} on project ${displayText(context.projectId)} and backfilled ${backfill.registered} DEK wraps (${backfill.alreadyRegistered} already present)${describeFailedBackfill(context.projectId, backfill.failed)}`,
    );
    return { ...context, verified };
  }).pipe(
    Effect.catch((error) =>
      Effect.gen(function* () {
        yield* logNote(describeRegistrationFailure(context.projectId, label, error));
        return context;
      }),
    ),
  );
}

/**
 * The failure of backfilling a registered device (DK K11-5): the
 * sync's candidates are only records not on the chain, so the next
 * sync does not fill. Filling is done by a pull from a device whose
 * cap covers it (`device-gaps.ts`).
 */
function describeFailedBackfill(
  projectId: ProjectId,
  failed: readonly { readonly environmentId: EnvironmentId }[],
): string {
  if (failed.length === 0) {
    return "";
  }
  const environments = failed.map((failure) => displayText(failure.environmentId)).join(", ");
  // The failed environments are known, so commands are emitted per
  // environment with the real id (a copyable form — Cursor Bugbot
  // point. The `<environment>` placeholder is only for situations
  // where the environment is unknown)
  const commands = failed
    .map((failure) => `\`${gapFillCommandOf(projectId, failure.environmentId)}\``)
    .join(", ");
  return `; the backfill failed for ${countNoun(failed.length, "environment")} (${environments}) — a registered device of yours whose cap covers ${failed.length === 1 ? "it" : "them"} fills the missing epochs when it runs ${commands}`;
}

function describeRegistrationFailure(projectId: ProjectId, label: string, error: CliError): string {
  // The append path already mapped the typed error onto failure.ts's
  // wording (one place), so here we only append K4-14's carry-over
  // (the local record is kept) to that wording
  if (error.message.startsWith("This server does not accept device operations")) {
    return `your device ${label} is recorded on this machine but project ${displayText(projectId)}'s server does not accept device operations yet. ${error.message}. The registration is retried by a sync after the server is updated`;
  }
  return `your device ${label} could not be registered on project ${displayText(projectId)} (${error.message}); the registration is retried on the next sync`;
}
