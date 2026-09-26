// Shared command prologue: ID validation → session → master key → §6.3 sync
// check → floor check → environment floor handle. The config file is read
// exactly once per command, in the prologue.
//
// The prologue splits on whether the master key is needed, but **the sync and
// floor semantics are unified in attachProject**:
//   openProjectWith         = with key (commands that encrypt / decrypt / sign values)
//   openMetadataProjectWith = without key (commands that read only plaintext metadata — env diff)

import { type EnvironmentId, isEnvironmentId, isProjectId } from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { Effect, type Stdio } from "effect";
import type { HttpClient } from "effect/unstable/http";

import { makeApiClient, type MaruhiClient } from "./api.ts";
import {
  reconcileDistributedAttestations,
  submitHeadAttestationIfAdvanced,
} from "./attestation.ts";
import type { CliConfig } from "./config.ts";
import { ConfigStore } from "./config.ts";
import type { DekRecipient } from "./deks.ts";
import { ownDeviceOrFail } from "./device-key.ts";
import { syncOwnDevices } from "./device-sync.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { checkChainFloor, type FloorHandle, makeFloorHandle } from "./floor-check.ts";
import { formatFloorConflicts, formatFloorViolation } from "./floor-evidence.ts";
import {
  type FloorIntent,
  floorRecordGet,
  FloorStore,
  type FloorStoreShape,
  type ProjectFloor,
} from "./floor.ts";
import { CliIo } from "./io.ts";
import type { Keychain } from "./keychain.ts";
import type { FingerprintBook } from "./known-fingerprints.ts";
import { logNote, logWarning } from "./notice.ts";
import type { OwnDeviceStore } from "./own-devices.ts";
import { type InviteAnchor, PinStore } from "./pins.ts";
import { warnUnconvergedMandates } from "./rotation-sweep.ts";
import type { ProcessRunner } from "./run.ts";
import { requireEnvironmentInScope } from "./scope.ts";
import {
  type CliSession,
  loadMasterKeys,
  type MasterKeys,
  resolveServerOrigin,
  resolveSession,
} from "./session.ts";
import { resyncExtended, syncProject, type VerifiedProject } from "./sync.ts";

/**
 * Services every CLI command may need (production wiring lives in live.ts).
 *
 * `Stdio` is the source of the argument layer's (ADR-0016) decision inputs —
 * argv and terminal presence. It is the boundary that keeps
 * `process.argv` / `process.stdout.isTTY` from being read directly, and it
 * lives here where the command body can see it because the value-display gate
 * (agent-gate.ts) requires it. Production is `@effect/platform-bun`; tests use
 * `Stdio.layerTest`.
 */
export type CliServices =
  | Keychain
  | ConfigStore
  | FloorStore
  | PinStore
  | FingerprintBook
  | CliIo
  | ProcessRunner
  | Stdio.Stdio
  | HttpClient.HttpClient
  | OwnDeviceStore;

/** Flags shared by data commands (server / project / environment overrides). */
export interface CommonFlags {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly env?: string | undefined;
}

// ID format validation (the client-side early check of AUTH_SPEC §12-1) uses
// @maruhi/core's isProjectId / isEnvironmentId (no duplicated pattern definitions)

export function resolveProjectId(
  flag: string | undefined,
  config: CliConfig,
): Effect.Effect<string, CliError> {
  const value = flag ?? config.defaultProject;
  if (value === undefined) {
    return Effect.fail(
      cliError(
        "No project specified. Use --project <id> or `maruhi config set defaultProject <id>`",
      ),
    );
  }
  if (!isProjectId(value)) {
    // The supplied value itself is not returned (a flag can also carry a
    // value — the same discipline as ADR-0016 decision 2's Flag declarations).
    // Split by origin: from the command line it is a usage error (2); from
    // config it is an execution failure (1) that says what to fix — the config file
    const shape = "Invalid project ID (64 hex digits)";
    return Effect.fail(
      flag === undefined
        ? cliError(`${shape} — fix defaultProject in your config`)
        : usageError(shape),
    );
  }
  return Effect.succeed(value);
}

function resolveEnvironmentId(
  flag: string | undefined,
  config: CliConfig,
): Effect.Effect<string, CliError> {
  const value = flag ?? config.defaultEnvironment;
  if (value === undefined) {
    return Effect.fail(
      cliError(
        "No environment specified. Use --env <id> or `maruhi config set defaultEnvironment <id>`",
      ),
    );
  }
  if (!isEnvironmentId(value)) {
    const shape =
      "Invalid environment ID (must start with an alphanumeric character, followed by up to 63 alphanumerics, _ or -)";
    return Effect.fail(
      flag === undefined
        ? cliError(`${shape} — fix defaultEnvironment in your config`)
        : usageError(shape),
    );
  }
  return Effect.succeed(value);
}

export interface SessionContext {
  readonly config: CliConfig;
  readonly origin: string;
  readonly session: CliSession;
  readonly client: MaruhiClient;
}

/** Session resolution from an already-loaded config (the inner half that does not re-read config). */
function openSessionWith(
  config: CliConfig,
  serverFlag: string | undefined,
): Effect.Effect<SessionContext, CliError, CliServices> {
  return Effect.gen(function* () {
    const origin = yield* resolveServerOrigin(serverFlag, config);
    const session = yield* resolveSession(origin);
    const client = yield* makeApiClient({ baseUrl: origin, token: session.token });
    return { config, origin, session, client };
  });
}

export function openSession(
  serverFlag: string | undefined,
): Effect.Effect<SessionContext, CliError, CliServices> {
  return Effect.gen(function* () {
    const store = yield* ConfigStore;
    return yield* openSessionWith(yield* store.load, serverFlag);
  });
}

/**
 * The product of the prologue that needs no key material (ID validation →
 * session → §6.3 sync check → floor check). Commands that read only plaintext
 * metadata need no more than this (env diff).
 */
export interface ProjectContextBase extends SessionContext {
  readonly projectId: string;
  readonly verified: VerifiedProject;
  /** The local floor at openProject time (§6.3; null when there is no floor). */
  readonly floor: ProjectFloor | null;
  /** Resync (full chain re-verification). pull / push / env create use it on conflicts and future heads. */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
}

/** The prologue's product for commands that handle values (the above + the master key and the self-addressed wrap recipient). */
export interface ProjectContext extends ProjectContextBase {
  readonly masterKeys: MasterKeys;
  readonly recipient: DekRecipient;
}

export interface CheckedFloor {
  readonly floor: ProjectFloor | null;
  /** The view that passed the chain floor check (it may have advanced via a bounded resync when shortening was suspected). */
  readonly verified: VerifiedProject;
}

/**
 * Loads the local floor (fail-open — first-run and corruption are told apart
 * and reported) + the chain floor check (the chain part of §6.3 rule (a)).
 * The rule (c) basis (pullEpoch) is not moved here (the norm that a chain
 * sync alone does not advance it).
 *
 * **The floor head is not advanced here**: advancing happens only after the
 * head-gossip reconciliation (reconcileGossip) passes. Recording before the
 * check would make the head of a view the reconciliation interrupted on hard
 * evidence the floor's permanent record, letting it reject every future
 * honest chain as a floor hash mismatch (floor pollution by a rejected view).
 *
 * A floor head ahead of our view (headSeq regression) also occurs as an
 * honest race where a sibling process advanced the floor between sync and
 * floor load, so it is not immediate evidence — a bounded resync (once) of
 * the same shape as §6.3-2b attempts to resolve it. A hash mismatch at the
 * floor's seq position is a contradiction of two verified artifacts (hard
 * evidence), so it stays an immediate rejection.
 */
export function loadCheckedFloor(
  projectId: string,
  verified: VerifiedProject,
  resync: Effect.Effect<VerifiedProject, CliError>,
): Effect.Effect<CheckedFloor, CliError, CliServices> {
  return Effect.gen(function* () {
    const store = yield* FloorStore;
    const loaded = yield* store.load(projectId);
    if (loaded.state === "missing") {
      yield* logNote(
        "this project has no local floor yet (first sync). Persistent rollback / omission detection takes effect from the next run",
      );
    } else if (loaded.state === "corrupt") {
      yield* logWarning(
        "cannot read the local floor file (it is corrupt). Continuing without a floor — your local state may have been modified or deleted unintentionally. Be careful if you do not recognize this",
      );
    } else if (loaded.droppedRecords > 0) {
      // Partial corruption can continue via the fold's self-healing, but it
      // is not left silent: if the dropped line was the latest head / manifest
      // observation, the detection material at that coordinate is one
      // generation thinner until the next verified observation (the same
      // visibility level as the old storage format's corrupt warning)
      yield* logWarning(
        `${loaded.droppedRecords} record(s) in the local floor log could not be decoded and were skipped (a torn write from an interrupted process is self-healing, but if you do not recognize an interruption, the log may have been damaged). Rollback detection for the affected coordinates resumes from the next verified observation`,
      );
    }
    let view = verified;
    if (loaded.floor !== null) {
      if (loaded.floor.conflicts.length > 0) {
        // A same-coordinate conflict surfaced by the fold (§6.3 — a pair of
        // verified observations with the same version but different hashes)
        // is hard evidence of equivocation. Refuse to use or advance the floor
        return yield* Effect.fail(
          cliError(formatFloorConflicts(projectId, loaded.floor.conflicts)),
        );
      }
      let violation = checkChainFloor(loaded.floor, view);
      if (violation !== null && violation.kind === "chain-shortened") {
        // Resync with an extension check: if the initial view was merely
        // stale, the resynced view should have it as a prefix. If it is not an
        // extension, reject as evidence that the initial view itself was a
        // fork (a shortening + fork composite)
        view = yield* resyncExtended(resync, view);
        violation = checkChainFloor(loaded.floor, view);
      }
      if (violation !== null) {
        // Reject + presentable evidence (the floor's recorded head and this sync's head)
        return yield* Effect.fail(cliError(formatFloorViolation({ projectId }, violation)));
      }
    }
    return { floor: loaded.floor, verified: view };
  });
}

/**
 * The reconciliation result of an intent's composite entry. accepted /
 * rejected are decided by entry identity at the declared-head position, and
 * **pending (empty slot) is never finalized**: if the chain is still at the
 * declared head, another CLI may simply have synced before the sent composite
 * landed, and collapsing it to not-accepted there would leave nobody to
 * promote the manifest when the entry lands later (losing the recovery path
 * for the case where the sender crashed).
 */
type IntentEntryState = "accepted" | "rejected" | "pending";

/**
 * Whether the intent's composite entry exists on the chain **as that
 * attempt's**. It is not decided by the (environment, epoch) DEK commitment
 * match alone: a CAS retry re-signs the declared head and manifest with the
 * same DEK (= same commitment), so a rejected old attempt's intent (left
 * behind by a failed resolution append or a crash) cannot be told apart from
 * a later attempt's acceptance by commitment alone, and promoting the old
 * attempt's manifest (same version, different hash) drops the floor into a
 * permanent rejection as a typed conflict. The composite's landing position
 * is uniquely fixed by the declared head (entry prev = declared head, seq =
 * declared head + 1 — the §12-4 CAS; since prev is signed, landing anywhere
 * else does not exist), so the entry at that position holding this intent's
 * op, coordinates, and commitment is accepted, **occupied by a different
 * entry** is rejected (this attempt can never land), and empty is pending.
 */
function intentEntryState(verified: VerifiedProject, intent: FloorIntent): IntentEntryState {
  // entries are in seq order (entries[0].seq === 1) — look at the declared head + 1 slot
  const entry = verified.entries[intent.declaredHead.seq];
  if (entry === undefined) {
    return "pending";
  }
  if (entry.prevHashHex !== intent.declaredHead.hashHex) {
    return "rejected";
  }
  return intentEntryMatches(entry, intent) ? "accepted" : "rejected";
}

/** Whether the slot's entry is the intent's composite itself (op, coordinates, commitment). */
function intentEntryMatches(entry: ChainEntry, intent: FloorIntent): boolean {
  if (intent.op === "create_environment") {
    return (
      entry.op === "create_environment" &&
      entry.payload.environmentId === intent.environmentId &&
      entry.payload.dekCommitmentHex === intent.dekCommitmentHex
    );
  }
  return (
    entry.op === "rotate_epoch" &&
    entry.payload.environmentId === intent.environmentId &&
    entry.payload.newEpoch === intent.epoch &&
    entry.payload.dekCommitmentHex === intent.dekCommitmentHex
  );
}

/**
 * Startup reconciliation of unresolved composite intents (create / rotate —
 * 3-F). A composite's effect is confirmed by chain sync (§12-10 (3)), and the
 * command prologue fully verifies the chain every run, so it can be resolved
 * here: if the intent's composite entry exists on the chain it was accepted —
 * promote the self-issued manifest to the floor (recovering "floor commits
 * that span an error exit / crash"). If it does not exist it was not accepted
 * (the chain is fully synced = the complete source of truth). meta-op intents
 * leave no trace on the chain, so the next verified pull (values.ts)
 * reconciles them.
 */
function reconcileCompositeIntents(input: {
  readonly store: FloorStoreShape;
  readonly projectId: string;
  readonly verified: VerifiedProject;
  readonly intents: readonly FloorIntent[];
}): Effect.Effect<boolean, CliError, CliServices> {
  return Effect.gen(function* () {
    let resolved = false;
    for (const intent of input.intents) {
      if (intent.op === "meta-op" || intent.dekCommitmentHex === null) {
        continue;
      }
      const state = intentEntryState(input.verified, intent);
      if (state === "pending") {
        // An empty slot cannot be told apart: a crash before sending, or our
        // own sync before the composite landed. Leave it unreconciled without
        // deciding (once the chain advances past the declared head, the next
        // reconciliation decides accepted / rejected)
        yield* logNote(
          `an earlier ${intent.op} for environment ${intent.environmentId} is still awaiting confirmation (its chain slot is empty — the request may not have been sent, or may still be in flight). It will be reconciled once the chain advances`,
        );
        continue;
      }
      const environment = input.verified.state.environments.get(intent.environmentId);
      if (state === "accepted") {
        // Confirmed as accepted — promote the self-issued manifest to the floor (joining a verified fact)
        yield* input.store.commitManifest(input.projectId, {
          chainHead: {
            seq: input.verified.state.headSeq,
            hashHex: input.verified.state.headHashHex,
          },
          environmentId: intent.environmentId,
          manifest: {
            manifestVersion: intent.manifestVersion,
            epoch: intent.epoch,
            manifestSigHashHex: intent.manifestSigHashHex,
          },
        });
        yield* input.store.resolveIntent(
          input.projectId,
          intent.id,
          environment !== undefined && environment.currentEpoch === intent.epoch
            ? "accepted"
            : "accepted-superseded",
        );
        yield* logNote(
          `an earlier ${intent.op} for environment ${intent.environmentId} (interrupted before its confirmation) is confirmed as accepted on the chain. The local floor has been advanced with its manifest (manifestVersion ${intent.manifestVersion})`,
        );
      } else {
        yield* input.store.resolveIntent(input.projectId, intent.id, "not-accepted");
        yield* logNote(
          `an earlier ${intent.op} for environment ${intent.environmentId} (interrupted before its confirmation) is not on the verified chain — it was not accepted. No floor change`,
        );
      }
      resolved = true;
    }
    return resolved;
  });
}

/**
 * The anchor reconciliation's 3 checks (head inclusion → inviter FP →
 * inviter sig key). Failure = rejection wording (hard evidence); success =
 * null. The rejection wording includes where the verification material lives
 * (the pin file): against a permanent halt, it keeps a path to investigation
 * and recovery (manual handling after out-of-band confirmation).
 */
function anchorFailureOf(
  projectId: string,
  anchor: InviteAnchor,
  verified: VerifiedProject,
): string | null {
  const evidenceHint = `The verification material is invites/${projectId}.json (the pinned anchor) in the config directory, plus the distributed chain`;
  if (verified.history.entryHashAt(anchor.headSeq) !== anchor.headHashHex) {
    return `Invite-link anchor check failed: the distributed chain does not contain the verified head pinned in the invite link (seq=${anchor.headSeq}) (CRYPTO_SPEC §6.3 out-of-band anchor (a)). This suggests a server-side rollback or fork distribution — do not trust this chain; confirm with the inviter out of band. ${evidenceHint}`;
  }
  // The inviter's key = a device that was valid at the pinned head (2026-09-19 DK — drawn over the device's validity interval)
  const inviter = verified.history.deviceStateAt(
    anchor.inviterUserId,
    anchor.inviterKeyFingerprintHex,
    anchor.headSeq,
  );
  if (inviter === undefined) {
    return `Invite-link anchor check failed: the link's inviter (user_id + key FP) does not match the chain member at the pinned head (the CRYPTO_SPEC §6.5 mechanical check). The invite link or the distributed chain may be forged — do not trust this chain; confirm with the inviter out of band. ${evidenceHint}`;
  }
  // IV revision: if the link's `is=` (the inviter's sig public key) is also
  // pinned, check the key itself matches in addition to the FP (fixing that
  // the issuance signature's verification key is the key on the chain)
  if (inviter.device.sigPubHex !== anchor.inviterSigPubHex) {
    return `Invite-link anchor check failed: the link's inviter signing key (is=) does not match the chain member's key at the pinned head (CRYPTO_SPEC §6.3 (a) / §6.5). The invite link or the distributed chain may be forged — do not trust this chain; confirm with the inviter out of band. ${evidenceHint}`;
  }
  return null;
}

/**
 * Mechanical reconciliation of the invite-link anchor (CRYPTO_SPEC §6.3
 * out-of-band anchor (a) / §6.5). The values pinned at acceptance — "genesis
 * (= projectId, covered by syncProject's genesis-match check), the inviter's
 * verified head, inviter user_id + key FP" — are checked against the verified
 * chain:
 *   (i) head inclusion — the distributed chain contains the pinned head at that seq
 *   (ii) inviter FP — at the pinned head, the inviter is a member with that key
 * Before add_member (a non-member) the sync itself is a 404, so this is never
 * reached — the first sync doubles as the first reconciliation (a design that
 * follows §11-2's timing constraint). Checked on every sync while an anchor
 * exists (the check is 2 references only, and an always-on check is strictly
 * stronger).
 */
export function checkInviteAnchor(
  projectId: string,
  verified: VerifiedProject,
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const store = yield* PinStore;
    const loaded = yield* store.load(projectId);
    if (loaded.state === "corrupt") {
      yield* logWarning(
        "cannot read the invite-pin file (it is corrupt). Continuing without the anchor check — your local state may have been modified or deleted unintentionally. Be careful if you do not recognize this. If the file predates this release, delete `invites/<projectId>.json` in the maruhi configuration directory and accept the invite again",
      );
      return;
    }
    const anchor: InviteAnchor | null = loaded.pins?.anchor ?? null;
    if (anchor === null) {
      return;
    }
    const failure = anchorFailureOf(projectId, anchor, verified);
    if (failure !== null) {
      return yield* Effect.fail(cliError(failure));
    }
    if (anchor.verifiedAtSeq === null) {
      yield* io.log(
        "Invite-link anchor check passed (genesis match, head inclusion, inviter key — CRYPTO_SPEC §6.3 / §6.5)",
      );
      yield* store.saveAnchor(projectId, { ...anchor, verifiedAtSeq: verified.state.headSeq });
    }
  });
}

/**
 * Prologue options. `quietMandateWarning` suppresses the standing warning of
 * unconverged rotation mandates (rotation-sweep.ts — B2 ruling) and is
 * **only for converging commands** (member remove / change-role / server
 * revoke / env rotate — the command's own sweep report conveys the same fact
 * more accurately, so the sync-time warning becomes double-reporting noise).
 */
export interface OpenProjectOptions {
  readonly quietMandateWarning?: boolean;
}

/**
 * Head-gossip reconciliation (§6.3 / §6.6): a contradiction report = abort on
 * hard evidence; a future report is resolved by a bounded resync (once). If
 * the view advanced, the anchor mechanical check is re-applied on the new
 * view (the check is 2 references only).
 *
 * **The floor head advances here, after all checks (floor / anchor / gossip)
 * have passed**. Leaving an aborted view's head in the floor would make the
 * supposedly rejected fork the floor's permanent record and let it reject
 * every future honest chain as a hash mismatch (floor pollution by a rejected
 * view).
 */
export function reconcileGossip(
  projectId: string,
  verified: VerifiedProject,
  resync: Effect.Effect<VerifiedProject, CliError>,
): Effect.Effect<VerifiedProject, CliError, CliServices> {
  return Effect.gen(function* () {
    const reconciled = yield* reconcileDistributedAttestations({
      projectId,
      view: verified,
      resync,
    });
    if (reconciled !== verified) {
      yield* checkInviteAnchor(projectId, reconciled);
    }
    yield* commitVerifiedHead(projectId, reconciled);
    return reconciled;
  });
}

/**
 * The common prologue after session establishment: §6.3 sync → chain floor
 * check → anchor mechanical reconciliation → head-gossip reconciliation
 * (§6.3 / §6.6 — a contradiction report aborts use of the artifact) → floor
 * head advance → standing warning of unconverged rotation mandates (§7 / B2
 * ruling — the same discipline as §9's always-on disclosure) → submission of
 * the verified-head attestation (SHOULD — prologues holding a signing key
 * only). Only the caller differs by whether a key is held; the floor and
 * gossip semantics are unified here (split into two tracks, they would
 * silently diverge sooner or later). The floor head advance is common to all
 * commands and happens as before even for commands that read no values, like
 * env diff.
 *
 * `attester` is the signing material for attestation submission
 * (openProjectWith passes it from the master key). A prologue not given one
 * (openMetadataProjectWith — commands that do not require the master key)
 * only reconciles and does not submit (submission is SHOULD, and keyless
 * execution — MARUHI_TOKEN — must not be broken for its sake).
 */
function attachProject(
  context: SessionContext,
  projectId: string,
  options?: OpenProjectOptions,
  attester?: { readonly userId: string; readonly signingKey: CryptoKey },
): Effect.Effect<ProjectContextBase, CliError, CliServices> {
  return Effect.gen(function* () {
    const resync = syncProject(context.client, projectId);
    const synced = yield* resync;
    const checked = yield* loadCheckedFloor(projectId, synced, resync);
    yield* checkInviteAnchor(projectId, checked.verified);
    const verified = yield* reconcileGossip(projectId, checked.verified, resync);
    // An unresolved composite intent (3-F) is "resolved by reconciliation
    // before the next mutation to the same environment reports success" — the
    // prologue fully syncs and verifies the chain every run, so this is that
    // reconciliation point (if accepted, the floor's manifest advance is also
    // recovered here)
    let floor = checked.floor;
    if (floor !== null && floor.intents.length > 0) {
      const store = yield* FloorStore;
      const resolved = yield* reconcileCompositeIntents({
        store,
        projectId,
        verified,
        intents: floor.intents,
      });
      if (resolved) {
        // The reconciliation may have advanced the floor — re-read the fold.
        // The conflict check is re-applied to the reloaded floor too: if a
        // concurrent process appended a same-coordinate contradictory
        // observation during or right after reconciliation, proceeding without
        // the check would run the rest of this command on a representative
        // value that ignored equivocation evidence (the same fail-closed as
        // loadCheckedFloor, kept intact at every point that re-reads the floor)
        const reloaded = (yield* store.load(projectId)).floor;
        if (reloaded !== null && reloaded.conflicts.length > 0) {
          return yield* Effect.fail(cliError(formatFloorConflicts(projectId, reloaded.conflicts)));
        }
        floor = reloaded;
      }
    }
    if (options?.quietMandateWarning !== true) {
      yield* warnUnconvergedMandates({ client: context.client, verified });
    }
    // Submission of the verified-head attestation (§6.3 head gossip —
    // SHOULD; only views that passed every reconciliation are attested.
    // Failure is a non-fatal warning — attestation.ts)
    if (attester !== undefined) {
      yield* submitHeadAttestationIfAdvanced({
        client: context.client,
        projectId,
        view: verified,
        attesterUserId: attester.userId,
        signingKey: attester.signingKey,
      });
    }
    return { ...context, projectId, verified, floor, resync };
  });
}

/** The prologue shared by data commands (loaded-config version). */
function openProjectWith(
  config: CliConfig,
  flags: CommonFlags,
  options?: OpenProjectOptions,
): Effect.Effect<ProjectContext, CliError, CliServices> {
  return Effect.gen(function* () {
    // The project ID format check runs before any network access
    const projectId = yield* resolveProjectId(flags.project, config);
    const context = yield* openSessionWith(config, flags.server);
    // Loading the master key stays **before** sync (traffic) and floor
    // advance: a write command run on a keyless device must not be made to
    // round-trip the server before it fails
    const masterKeys = yield* loadMasterKeys(context.session);
    const base = yield* attachProject(context, projectId, options, {
      userId: context.session.userId,
      signingKey: masterKeys.sigKeyPair.privateKey,
    });
    const recipient: DekRecipient = {
      userId: context.session.userId,
      encPubHex: masterKeys.record.encPubHex,
      encKeyPair: masterKeys.encKeyPair,
    };
    // Observation of the device set and registration of the first sync (DK K4-3 — keyed prologues only; idempotent, non-fatal)
    return yield* syncOwnDevices({ ...base, masterKeys, recipient });
  });
}

/**
 * The prologue for commands that read only plaintext metadata (**does not
 * require the master key**).
 *
 * The only difference from openProject is the presence of loadMasterKeys;
 * sync and floor checks are unified in attachProject. Not requiring the key
 * is not only "because it does not decrypt": it lets sessions via
 * MARUHI_TOKEN (keychain-less execution — session.ts) run the parity checks
 * too, and `project verify` already is a keyless read command of the same
 * shape.
 */
function openMetadataProjectWith(
  config: CliConfig,
  flags: CommonFlags,
): Effect.Effect<ProjectContextBase, CliError, CliServices> {
  return Effect.gen(function* () {
    const projectId = yield* resolveProjectId(flags.project, config);
    const context = yield* openSessionWith(config, flags.server);
    return yield* attachProject(context, projectId);
  });
}

/** The prologue shared by data commands: ID validation → session → master key → §6.3 sync check → floor check. */
export function openProject(
  flags: CommonFlags,
  options?: OpenProjectOptions,
): Effect.Effect<ProjectContext, CliError, CliServices> {
  return Effect.gen(function* () {
    const store = yield* ConfigStore;
    return yield* openProjectWith(yield* store.load, flags, options);
  });
}

/**
 * The prologue for commands that read only plaintext metadata and the chain
 * (does not require the master key). invite list / revoke use it: every
 * reconciliation input (heads, keys) is chain-derived, so a device with no
 * key material (a MARUHI_TOKEN run) can still manage invites (the same
 * keyless class as env diff / project verify). invite create needs the sig
 * key for the issuance signature (CRYPTO_SPEC §6.5), so it is on the
 * openProject side (2026-09-13 IV revision).
 */
export function openMetadataProject(
  flags: CommonFlags,
): Effect.Effect<ProjectContextBase, CliError, CliServices> {
  return Effect.gen(function* () {
    const store = yield* ConfigStore;
    return yield* openMetadataProjectWith(yield* store.load, flags);
  });
}

/** Per-environment floor handle (used by pull / push in the command for checks and commits). */
export function floorHandleFor(
  context: ProjectContextBase,
  environmentId: string,
): Effect.Effect<FloorHandle, never, CliServices> {
  return Effect.map(FloorStore, (store) =>
    makeFloorHandle({
      store,
      projectId: context.projectId,
      environmentId,
      // own-property lookup (prevents a legitimate environment ID like
      // `constructor` from resolving to an inherited property — see
      // floor.ts's floorRecordGet)
      initial: floorRecordGet(context.floor?.environments, environmentId) ?? null,
      // This environment's unresolved intents (only meta-ops remain after
      // the prologue's reconciliation — values.ts reconciles them when a
      // verified pull arrives)
      intents:
        context.floor?.intents.filter((intent) => intent.environmentId === environmentId) ?? [],
    }),
  );
}

export interface EnvironmentContext extends ProjectContext {
  readonly environmentId: string;
  /** Per-environment floor handle (§6.3 — pull / push checks and commits). */
  readonly floorHandle: FloorHandle;
}

/**
 * The common prologue of environment commands (pull / push / run / var rm /
 * schema set / import / env rotate): environment ID format check (before any
 * network) → openProject → **target environment ∈ own scope** (CRYPTO_SPEC
 * §6.3 "do not wait for the server's 403" — 2026-09-15 ES K4. Every value
 * command passes through here and metadata-only commands go through
 * openMetadataEnvironment, so "not asked" is visible as a function
 * difference — design note K4-C) → environment floor handle. Config is read
 * exactly once here.
 */
export function openEnvironment(
  flags: CommonFlags,
  options?: OpenProjectOptions,
): Effect.Effect<EnvironmentContext, CliError, CliServices> {
  return Effect.gen(function* () {
    const store = yield* ConfigStore;
    const config = yield* store.load;
    const environmentId = yield* resolveEnvironmentId(flags.env, config);
    const context = yield* openProjectWith(config, flags, options);
    // The check is **this device's effective scope** (person ∩ device — DK
    // K4-17). If the key at hand is not on the chain (unregistered / revoked),
    // guide to the registration path (approving the pending request, or
    // syncing the device listed here — DK K10-5) before fetching values
    const self = context.verified.state.members.get(context.session.userId);
    const device =
      self === undefined
        ? undefined
        : yield* ownDeviceOrFail(context.verified, self, {
            encPubHex: context.masterKeys.record.encPubHex,
          });
    yield* requireEnvironmentInScope({
      verified: context.verified,
      userId: context.session.userId,
      environmentId,
      operation: "operate on",
      device,
    });
    const floorHandle = yield* floorHandleFor(context, environmentId);
    return { ...context, environmentId, floorHandle };
  });
}

/**
 * Records the verified view's chain head to the floor (material for §6.3
 * rule (a)). `mergeHead` is monotonic — never regresses, idempotent.
 *
 * pull / push write the same head inside commitPull / commitPush, but
 * **commands that read no values never pass through those paths**. When a
 * bounded resync advanced the view, not recording it would leave "the latest
 * verified head" as of openProject time, and a rollback to in between could
 * not be detected on later runs (the floor is a SHOULD, but there is no
 * reason for this command alone to drop the material pull / push keep).
 */
export function commitVerifiedHead(
  projectId: string,
  verified: VerifiedProject,
): Effect.Effect<void, CliError, CliServices> {
  return Effect.flatMap(FloorStore, (store) =>
    store.commitHead(projectId, {
      seq: verified.state.headSeq,
      hashHex: verified.state.headHashHex,
    }),
  );
}

/** Keyless environment context (commands that read only metadata — maruhi schema). */
export interface MetadataEnvironmentContext extends ProjectContextBase {
  readonly environmentId: string;
  /** Per-environment floor handle (§6.3 — metadata-only pull checks and environment-level commits). */
  readonly floorHandle: FloorHandle;
}

/**
 * The prologue of per-environment metadata-only commands (`maruhi schema`):
 * environment ID format check (before any network) → openMetadataProject
 * (**does not require the master key** — the keyless class that works under
 * MARUHI_TOKEN runs and agent environments) → environment floor handle.
 * **Scope is not checked** (AUTH_SPEC §12-7 — a metadata-only pull is allowed
 * outside scope; ruling G-2).
 */
export function openMetadataEnvironment(
  flags: CommonFlags,
): Effect.Effect<MetadataEnvironmentContext, CliError, CliServices> {
  return Effect.gen(function* () {
    const store = yield* ConfigStore;
    const config = yield* store.load;
    const environmentId = yield* resolveEnvironmentId(flags.env, config);
    const context = yield* openMetadataProjectWith(config, flags);
    const floorHandle = yield* floorHandleFor(context, environmentId);
    return { ...context, environmentId, floorHandle };
  });
}

/** A floor handle for one environment (held paired with the environment ID so it cannot be mixed up). */
export interface EnvironmentHandle {
  readonly environmentId: EnvironmentId;
  /** Per-environment floor handle (§6.3). */
  readonly floorHandle: FloorHandle;
}

/** The result of opening 2 environments under a single project prologue (env diff). */
export interface EnvironmentPairContext extends ProjectContextBase {
  readonly first: EnvironmentHandle;
  readonly second: EnvironmentHandle;
}

/**
 * The prologue of the metadata-only command spanning 2 environments
 * (env diff): **1 project + a floor handle per environment**. Config is read
 * exactly once here.
 *
 * Calling openEnvironment per environment would run the chain sync and §6.3
 * verification once per environment. Comparing **two verified views that
 * disagree** makes it impossible to say which history the comparison is
 * against (it could report as a "diff" a state where only one side advanced
 * by resync). The project prologue runs only once.
 *
 * Environment ID format validation is assumed already done by the caller
 * (the side taking positional arguments). Note `EnvironmentId` is **not
 * branded** (an alias of Schema.String.check), so the type does not enforce
 * validation — the display side passes environment IDs through displayText
 * too (env-diff.ts).
 */
export function openMetadataEnvironmentPair(
  flags: CommonFlags,
  first: EnvironmentId,
  second: EnvironmentId,
): Effect.Effect<EnvironmentPairContext, CliError, CliServices> {
  return Effect.gen(function* () {
    const store = yield* ConfigStore;
    const config = yield* store.load;
    const context = yield* openMetadataProjectWith(config, flags);
    return {
      ...context,
      first: { environmentId: first, floorHandle: yield* floorHandleFor(context, first) },
      second: { environmentId: second, floorHandle: yield* floorHandleFor(context, second) },
    };
  });
}
