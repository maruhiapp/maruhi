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
import { Duration, Effect, type Stdio } from "effect";
import type { HttpClient } from "effect/http";

import { makeApiClient, type MaruhiClient } from "./api.ts";
import {
  reconcileDistributedAttestations,
  submitHeadAttestationIfAdvanced,
} from "./attestation.ts";
import { resyncExtended, syncProject, type VerifiedProject } from "./chain-sync.ts";
import type { CliConfig } from "./config.ts";
import { ConfigStore, loadCliConfig } from "./config.ts";
import type { DekRecipient } from "./deks.ts";
import { ownDeviceOrFail } from "./device-key.ts";
import { syncOwnDevices } from "./device-sync.ts";
import { cliError, type CliError, evidenceError, usageError } from "./errors.ts";
import { toCliError } from "./failure.ts";
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
import type { ProxyAcceptStore } from "./proxy.package/index.ts";
import type { SqlRunner } from "./rotate-connector.ts";
import { warnUnconvergedMandates } from "./rotation-sweep.ts";
import type { ProcessRunner } from "./run.ts";
import { requireEnvironmentInScope } from "./scope.ts";
import {
  type CliSession,
  loadMasterKeys,
  type MasterKeys,
  normalizeHttpOrigin,
  resolveServerOrigin,
  resolveSession,
  type SessionCredential,
} from "./session.ts";

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
  | OwnDeviceStore
  | ProxyAcceptStore
  | SqlRunner;

/** Flags shared by data commands (server / project / environment overrides). */
export interface CommonFlags {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly env?: string | undefined;
  /** `--mirror <url>` (PF2 — AUTH_SPEC §11-7): the read-only replica a read falls back to (default: the `mirror` setting). */
  readonly mirror?: string | undefined;
  /**
   * Set by {@link withMirrorFallback} on the retry (never a flag): the
   * server origin this read fell back from. The session then opens the
   * mirror's own credential, the device key is the one stored for the
   * server origin (the key is the person's, not the deployment's), and
   * nothing is written to the mirror (no attestation, no device sync).
   */
  readonly mirrorOf?: string | undefined;
}

/** The mirror origin a read falls back to: `--mirror` → the `mirror` setting (null when none is configured). */
export function resolveMirrorOrigin(
  flag: string | undefined,
  config: CliConfig,
): Effect.Effect<string | null, CliError> {
  const raw = flag ?? config.mirror;
  if (raw === undefined) {
    return Effect.succeed(null);
  }
  return normalizeHttpOrigin(
    raw,
    "the mirror URL",
    flag === undefined ? { fix: "mirror in your config" } : "flag",
  );
}

/**
 * Runs a read against the configured server and, when that server is
 * unreachable (no answer, or a gateway error in front of it — never an
 * answer of its own such as a 403 or a 404), once more against the
 * configured mirror with the mirror's own credential (PF2 — AUTH_SPEC
 * §11-7 ruling E). The retry is announced on stderr. Read-only commands
 * only: every verification duty runs unchanged against the mirror, and a
 * mirror behind the local floor is refused like any server.
 */
export const withMirrorFallback = Effect.fn("context.withMirrorFallback")(function* <A>(
  flags: CommonFlags,
  read: (flags: CommonFlags) => Effect.Effect<A, CliError, CliServices>,
): Effect.fn.Return<A, CliError, CliServices> {
  const config = yield* loadCliConfig;
  const mirror = yield* resolveMirrorOrigin(flags.mirror, config);
  if (mirror === null) {
    return yield* read(flags);
  }
  const primary = yield* resolveServerOrigin(flags.server, config);
  if (mirror === primary) {
    yield* logWarning(
      "the mirror URL is the server URL itself — no fallback is possible (point `mirror` at the mirror deployment)",
    );
    return yield* read(flags);
  }
  return yield* read(flags).pipe(
    Effect.catch((error: CliError) =>
      error.unreachable === true
        ? Effect.gen(function* () {
            const io = yield* CliIo;
            yield* io.logError(
              `${error.message}. Retrying this read against the mirror ${mirror} (a read-only replica that may be behind the server; writes are never retried)`,
            );
            yield* ensureMirrorOf(config, mirror, primary, flags.project);
            return yield* read({ ...flags, server: mirror, mirrorOf: primary });
          })
        : Effect.fail(error),
    ),
  );
});

/**
 * Before a fallback read: the mirror must say it is a mirror of this
 * server (ruling E revision). A project that was promoted there is a
 * primary now (the member's config should point at it); a mirror of
 * another deployment is not this project's replica. The check reads the
 * mark with the mirror's own credential, like the read that follows.
 */
const ensureMirrorOf = Effect.fn("context.ensureMirrorOf")(function* (
  config: CliConfig,
  mirror: string,
  primary: string,
  projectFlag: string | undefined,
): Effect.fn.Return<void, CliError, CliServices> {
  const projectId = yield* resolveProjectId(projectFlag, config);
  const session = yield* openSessionWith(config, mirror, "mirror");
  const status = yield* session.client.mirror
    .status({ params: { projectId } })
    .pipe(Effect.mapError(toCliError));
  if (!status.mirror) {
    return yield* Effect.fail(
      cliError(
        `${mirror} does not hold this project as a mirror (it was promoted, or never marked), so the read is not retried there. Confirm with an owner whether the project was promoted before pointing \`config set server\` at it — a mirror's own word is not what moves a member's writes`,
      ),
    );
  }
  if (status.sourceOrigin !== primary) {
    return yield* Effect.fail(
      cliError(
        `${mirror} holds this project as a mirror of ${status.sourceOrigin ?? "another deployment"}, not of ${primary}: it is not this server's replica, so the read is not retried there (fix \`mirror\` in your config)`,
      ),
    );
  }
});

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
/** The client's bounds a session may be opened with (an uploader takes the body bound on its headers — ruling H revision, round 4). */
interface SessionClientOptions {
  readonly timeout?: Duration.Duration;
}

export const openSessionWith = Effect.fn("context.openSessionWith")(function* (
  config: CliConfig,
  serverFlag: string | undefined,
  credential: SessionCredential = "server",
  clientOptions: SessionClientOptions = {},
): Effect.fn.Return<SessionContext, CliError, CliServices> {
  const origin = yield* resolveServerOrigin(serverFlag, config);
  const session = yield* resolveSession(origin, credential);
  const client = yield* makeApiClient({
    baseUrl: origin,
    token: session.token,
    ...(clientOptions.timeout === undefined ? {} : { timeout: clientOptions.timeout }),
  });
  return { config, origin, session, client };
});

export const openSession = Effect.fn("context.openSession")(function* (
  serverFlag: string | undefined,
  credential: SessionCredential = "server",
  clientOptions: SessionClientOptions = {},
): Effect.fn.Return<SessionContext, CliError, CliServices> {
  return yield* openSessionWith(yield* loadCliConfig, serverFlag, credential, clientOptions);
});

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

interface CheckedFloor {
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
export const loadCheckedFloor = Effect.fn("context.loadCheckedFloor")(function* (
  projectId: string,
  verified: VerifiedProject,
  resync: Effect.Effect<VerifiedProject, CliError>,
): Effect.fn.Return<CheckedFloor, CliError, CliServices> {
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
    // visibility level as the corrupt warning for whole-log corruption)
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
        evidenceError(formatFloorConflicts(projectId, loaded.floor.conflicts)),
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
      // Reject + presentable evidence (the floor's recorded head and this
      // sync's head): a contradiction between signed data, as the value
      // pull's floor check flags it (round 11)
      return yield* Effect.fail(evidenceError(formatFloorViolation({ projectId }, violation)));
    }
  }
  return { floor: loaded.floor, verified: view };
});

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
const reconcileCompositeIntents = Effect.fn("context.reconcileCompositeIntents")(function* (input: {
  readonly store: FloorStoreShape;
  readonly projectId: string;
  readonly verified: VerifiedProject;
  readonly intents: readonly FloorIntent[];
}): Effect.fn.Return<boolean, CliError, CliServices> {
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
export const checkInviteAnchor = Effect.fn("context.checkInviteAnchor")(function* (
  projectId: string,
  verified: VerifiedProject,
): Effect.fn.Return<void, CliError, CliServices> {
  const io = yield* CliIo;
  const store = yield* PinStore;
  const loaded = yield* store.load(projectId);
  if (loaded.state === "corrupt") {
    yield* logWarning(
      "cannot read the invite-pin file (it is corrupt). Continuing without the anchor check — your local state may have been modified or deleted unintentionally. Be careful if you do not recognize this",
    );
    return;
  }
  const anchor: InviteAnchor | null = loaded.pins?.anchor ?? null;
  if (anchor === null) {
    return;
  }
  const failure = anchorFailureOf(projectId, anchor, verified);
  if (failure !== null) {
    return yield* Effect.fail(evidenceError(failure));
  }
  if (anchor.verifiedAtSeq === null) {
    yield* io.log(
      "Invite-link anchor check passed (genesis match, head inclusion, inviter key — CRYPTO_SPEC §6.3 / §6.5)",
    );
    yield* store.saveAnchor(projectId, { ...anchor, verifiedAtSeq: verified.state.headSeq });
  }
});

/**
 * Prologue options. `quietMandateWarning` suppresses the standing warning of
 * unconverged rotation mandates (rotation-sweep.ts — B2 ruling) and is
 * **only for converging commands** (member remove / change-role / server
 * revoke / env rotate — the command's own sweep report conveys the same fact
 * more accurately, so the sync-time warning becomes double-reporting noise).
 */
interface OpenProjectOptions {
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
export const reconcileGossip = Effect.fn("context.reconcileGossip")(function* (
  projectId: string,
  verified: VerifiedProject,
  resync: Effect.Effect<VerifiedProject, CliError>,
): Effect.fn.Return<VerifiedProject, CliError, CliServices> {
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
const attachProject = Effect.fn("context.attachProject")(function* (
  context: SessionContext,
  projectId: string,
  options?: OpenProjectOptions,
  attester?: { readonly userId: string; readonly signingKey: CryptoKey },
): Effect.fn.Return<ProjectContextBase, CliError, CliServices> {
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
        return yield* Effect.fail(
          evidenceError(formatFloorConflicts(projectId, reloaded.conflicts)),
        );
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

/** The prologue shared by data commands (loaded-config version). */
const openProjectWith = Effect.fn("context.openProjectWith")(function* (
  config: CliConfig,
  flags: CommonFlags,
  options?: OpenProjectOptions,
): Effect.fn.Return<ProjectContext, CliError, CliServices> {
  // The project ID format check runs before any network access
  const projectId = yield* resolveProjectId(flags.project, config);
  const mirrorRead = flags.mirrorOf !== undefined;
  const context = yield* openSessionWith(config, flags.server, mirrorRead ? "mirror" : "server");
  // Loading the master key stays **before** sync (traffic) and floor
  // advance: a write command run on a keyless device must not be made to
  // round-trip the server before it fails. On a mirror read the key is
  // the one stored for the server origin (the key is the person's)
  const masterKeys = yield* loadMasterKeys({
    ...context.session,
    origin: flags.mirrorOf ?? context.session.origin,
  });
  // A mirror refuses attestations (AUTH_SPEC §11-7): the fallback read
  // reconciles the gossip it serves but submits nothing there
  const base = yield* attachProject(
    context,
    projectId,
    options,
    mirrorRead
      ? undefined
      : { userId: context.session.userId, signingKey: masterKeys.sigKeyPair.privateKey },
  );
  const recipient: DekRecipient = {
    userId: context.session.userId,
    encPubHex: masterKeys.record.encPubHex,
    encKeyPair: masterKeys.encKeyPair,
  };
  const opened: ProjectContext = { ...base, masterKeys, recipient };
  // Observation of the device set and registration of the first sync (DK
  // K4-3 — keyed prologues only; idempotent, non-fatal). A mirror refuses
  // the registration, so the fallback read skips it
  return mirrorRead ? opened : yield* syncOwnDevices(opened);
});

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
const openMetadataProjectWith = Effect.fn("context.openMetadataProjectWith")(function* (
  config: CliConfig,
  flags: CommonFlags,
): Effect.fn.Return<ProjectContextBase, CliError, CliServices> {
  const projectId = yield* resolveProjectId(flags.project, config);
  const context = yield* openSessionWith(
    config,
    flags.server,
    flags.mirrorOf === undefined ? "server" : "mirror",
  );
  return yield* attachProject(context, projectId);
});

/** The prologue shared by data commands: ID validation → session → master key → §6.3 sync check → floor check. */
export const openProject = Effect.fn("context.openProject")(function* (
  flags: CommonFlags,
  options?: OpenProjectOptions,
): Effect.fn.Return<ProjectContext, CliError, CliServices> {
  return yield* openProjectWith(yield* loadCliConfig, flags, options);
});

/**
 * The prologue for commands that read only plaintext metadata and the chain
 * (does not require the master key). invite list / revoke use it: every
 * reconciliation input (heads, keys) is chain-derived, so a device with no
 * key material (a MARUHI_TOKEN run) can still manage invites (the same
 * keyless class as env diff / project verify). invite create needs the sig
 * key for the issuance signature (CRYPTO_SPEC §6.5), so it is on the
 * openProject side (2026-09-13 IV revision).
 */
export const openMetadataProject = Effect.fn("context.openMetadataProject")(function* (
  flags: CommonFlags,
): Effect.fn.Return<ProjectContextBase, CliError, CliServices> {
  return yield* openMetadataProjectWith(yield* loadCliConfig, flags);
});

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
      // the prologue's reconciliation — values-floor.ts reconciles them when a
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
export const openEnvironment = Effect.fn("context.openEnvironment")(function* (
  flags: CommonFlags,
  options?: OpenProjectOptions,
): Effect.fn.Return<EnvironmentContext, CliError, CliServices> {
  const config = yield* loadCliConfig;
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
interface MetadataEnvironmentContext extends ProjectContextBase {
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
export const openMetadataEnvironment = Effect.fn("context.openMetadataEnvironment")(function* (
  flags: CommonFlags,
): Effect.fn.Return<MetadataEnvironmentContext, CliError, CliServices> {
  const config = yield* loadCliConfig;
  const environmentId = yield* resolveEnvironmentId(flags.env, config);
  const context = yield* openMetadataProjectWith(config, flags);
  const floorHandle = yield* floorHandleFor(context, environmentId);
  return { ...context, environmentId, floorHandle };
});

/** A floor handle for one environment (held paired with the environment ID so it cannot be mixed up). */
interface EnvironmentHandle {
  readonly environmentId: EnvironmentId;
  /** Per-environment floor handle (§6.3). */
  readonly floorHandle: FloorHandle;
}

/** The result of opening 2 environments under a single project prologue (env diff). */
interface EnvironmentPairContext extends ProjectContextBase {
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
export const openMetadataEnvironmentPair = Effect.fn("context.openMetadataEnvironmentPair")(
  function* (
    flags: CommonFlags,
    first: EnvironmentId,
    second: EnvironmentId,
  ): Effect.fn.Return<EnvironmentPairContext, CliError, CliServices> {
    const config = yield* loadCliConfig;
    const context = yield* openMetadataProjectWith(config, flags);
    return {
      ...context,
      first: { environmentId: first, floorHandle: yield* floorHandleFor(context, first) },
      second: { environmentId: second, floorHandle: yield* floorHandleFor(context, second) },
    };
  },
);
