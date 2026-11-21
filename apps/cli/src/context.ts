import {
  decodeEnvironmentId,
  decodeProjectId,
  type EnvironmentId,
  isEnvironmentId,
  isProjectId,
  type ProjectId,
  type UserId,
} from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { Duration, Effect, type Stdio } from "effect";
import type { Digest, SecureRandom } from "effect/crypto";
import type { HttpClient } from "effect/http";

import { makeApiClient, type MaruhiClient } from "./api.ts";
import {
  reconcileDistributedAttestations,
  submitHeadAttestationIfAdvanced,
} from "./attestation.ts";
import { resyncExtended, syncProject, type VerifiedProject } from "./chain-sync.ts";
import type { CliConfig } from "./config.ts";
import { ConfigStore, loadCliConfig } from "./config.ts";
import type { SqlRunner } from "./connector.package/index.ts";
import type { DekRecipient } from "./deks.ts";
import { ownDeviceOrFail } from "./device-key.ts";
import { syncOwnDevices } from "./device-sync.ts";
import { cliError, type CliError, evidenceError, usageError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { checkChainFloor, type FloorHandle, makeFloorHandle } from "./floor-check.ts";
import { formatFloorConflicts, formatFloorViolation } from "./floor-evidence.ts";
import {
  type DeletionFloorIntent,
  type FloorIntent,
  floorRecordGet,
  FloorStore,
  type FloorStoreShape,
  type ManifestFloorIntent,
  type ProjectFloor,
} from "./floor.ts";
import { CliIo } from "./io.ts";
import type { Keychain } from "./keychain.ts";
import type { FingerprintBook } from "./known-fingerprints.ts";
import { logNote, logWarning } from "./notice.ts";
import type { OwnDeviceStore } from "./own-devices.ts";
import { type InviteAnchor, PinStore } from "./pins.ts";
import type { ProxyAcceptStore } from "./proxy.package/index.ts";
import { warnUnconvergedMandates } from "./rotation-sweep.ts";
import type { ProcessRunner } from "./run.ts";
import { refuseChainDeletedEnvironment, requireEnvironmentInScope } from "./scope.ts";
import { noteServerDisclosure } from "./server-disclosure.ts";
import {
  type CliSession,
  loadMasterKeys,
  type MasterKeys,
  normalizeHttpOrigin,
  resolveServerOrigin,
  resolveSession,
  type SessionCredential,
} from "./session.ts";

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
  | SqlRunner
  | SecureRandom.SecureRandom
  | Digest.Digest;

export interface CommonFlags {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly env?: string | undefined;
  readonly mirror?: string | undefined;
  readonly mirrorOf?: string | undefined;
}

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

export function resolveProjectId(
  flag: string | undefined,
  config: CliConfig,
): Effect.Effect<ProjectId, CliError> {
  const value = flag ?? config.defaultProject;
  if (value === undefined) {
    return Effect.fail(
      cliError(
        "No project specified. Use --project <id> or `maruhi config set defaultProject <id>`",
      ),
    );
  }
  if (!isProjectId(value)) {
    const shape = "Invalid project ID (64 hex digits)";
    return Effect.fail(
      flag === undefined
        ? cliError(`${shape} — fix defaultProject in your config`)
        : usageError(shape),
    );
  }
  return Effect.succeed(decodeProjectId(value));
}

function resolveEnvironmentId(
  flag: string | undefined,
  config: CliConfig,
): Effect.Effect<EnvironmentId, CliError> {
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
  return Effect.succeed(decodeEnvironmentId(value));
}

export interface SessionContext {
  readonly config: CliConfig;
  readonly origin: string;
  readonly session: CliSession;
  readonly client: MaruhiClient;
}

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

export interface ProjectContextBase extends SessionContext {
  readonly projectId: ProjectId;
  readonly verified: VerifiedProject;
  readonly floor: ProjectFloor | null;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
}

export interface ProjectContext extends ProjectContextBase {
  readonly masterKeys: MasterKeys;
  readonly recipient: DekRecipient;
}

interface CheckedFloor {
  readonly floor: ProjectFloor | null;
  readonly verified: VerifiedProject;
}

export const loadCheckedFloor = Effect.fn("context.loadCheckedFloor")(function* (
  projectId: ProjectId,
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
    yield* logWarning(
      `${loaded.droppedRecords} record(s) in the local floor log could not be decoded and were skipped (a torn write from an interrupted process is self-healing, but if you do not recognize an interruption, the log may have been damaged). Rollback detection for the affected coordinates resumes from the next verified observation`,
    );
  }
  let view = verified;
  if (loaded.floor !== null) {
    if (loaded.floor.conflicts.length > 0) {
      return yield* Effect.fail(
        evidenceError(formatFloorConflicts(projectId, loaded.floor.conflicts)),
      );
    }
    let violation = checkChainFloor(loaded.floor, view);
    if (violation !== null && violation.kind === "chain-shortened") {
      view = yield* resyncExtended(resync, view);
      violation = checkChainFloor(loaded.floor, view);
    }
    if (violation !== null) {
      return yield* Effect.fail(evidenceError(formatFloorViolation({ projectId }, violation)));
    }
  }
  return { floor: loaded.floor, verified: view };
});

type IntentEntryState = "accepted" | "rejected" | "pending";

function intentEntryState(verified: VerifiedProject, intent: FloorIntent): IntentEntryState {
  const entry = verified.entries[intent.declaredHead.seq];
  if (entry === undefined) {
    return "pending";
  }
  if (entry.prevHashHex !== intent.declaredHead.hashHex) {
    return "rejected";
  }
  return intentEntryMatches(entry, intent) ? "accepted" : "rejected";
}

function intentEntryMatches(entry: ChainEntry, intent: FloorIntent): boolean {
  if (intent.op === "delete_environment") {
    return (
      entry.op === "delete_environment" && entry.payload.environmentId === intent.environmentId
    );
  }
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

const reconcileCompositeIntents = Effect.fn("context.reconcileCompositeIntents")(function* (input: {
  readonly store: FloorStoreShape;
  readonly projectId: ProjectId;
  readonly verified: VerifiedProject;
  readonly intents: readonly FloorIntent[];
}): Effect.fn.Return<boolean, CliError, CliServices> {
  let resolved = false;
  for (const intent of input.intents.filter(isChainReconcilable)) {
    const state = intentEntryState(input.verified, intent);
    if (state === "pending") {
      yield* logNote(
        `an earlier ${intent.op} for environment ${intent.environmentId} is still awaiting confirmation (its chain slot is empty — the request may not have been sent, or may still be in flight). It will be reconciled once the chain advances`,
      );
      continue;
    }
    yield* intent.op === "delete_environment"
      ? settleDeletionIntent(input, intent, state)
      : settleManifestIntent(input, intent, state);
    resolved = true;
  }
  return resolved;
});

function isChainReconcilable(intent: FloorIntent): boolean {
  return intent.op === "delete_environment"
    ? true
    : intent.op !== "meta-op" && intent.dekCommitmentHex !== null;
}

interface IntentSettlementInput {
  readonly store: FloorStoreShape;
  readonly projectId: ProjectId;
  readonly verified: VerifiedProject;
}

function settleDeletionIntent(
  input: IntentSettlementInput,
  intent: DeletionFloorIntent,
  state: Exclude<IntentEntryState, "pending">,
): Effect.Effect<void, CliError, CliServices> {
  return Effect.andThen(
    input.store.resolveIntent(
      input.projectId,
      intent.id,
      state === "accepted" ? "accepted" : "not-accepted",
    ),
    logNote(
      state === "accepted"
        ? `an earlier delete_environment for environment ${intent.environmentId} (interrupted before its confirmation) is confirmed as accepted on the chain`
        : `an earlier delete_environment for environment ${intent.environmentId} (interrupted before its confirmation) is not on the verified chain — it was not accepted`,
    ),
  );
}

const settleManifestIntent = Effect.fn("context.settleManifestIntent")(function* (
  input: IntentSettlementInput,
  intent: ManifestFloorIntent,
  state: Exclude<IntentEntryState, "pending">,
): Effect.fn.Return<void, CliError, CliServices> {
  if (state !== "accepted") {
    yield* input.store.resolveIntent(input.projectId, intent.id, "not-accepted");
    yield* logNote(
      `an earlier ${intent.op} for environment ${intent.environmentId} (interrupted before its confirmation) is not on the verified chain — it was not accepted. No floor change`,
    );
    return;
  }
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
  const environment = input.verified.state.environments.get(intent.environmentId);
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
});

function anchorFailureOf(
  projectId: ProjectId,
  anchor: InviteAnchor,
  verified: VerifiedProject,
): string | null {
  const evidenceHint = `The verification material is invites/${projectId}.json (the pinned anchor) in the config directory, plus the distributed chain`;
  if (verified.history.entryHashAt(anchor.headSeq) !== anchor.headHashHex) {
    return `Invite-link anchor check failed: the distributed chain does not contain the verified head pinned in the invite link (seq=${anchor.headSeq}) (CRYPTO_SPEC §6.3 out-of-band anchor (a)). This suggests a server-side rollback or fork distribution — do not trust this chain; confirm with the inviter out of band. ${evidenceHint}`;
  }
  const inviter = verified.history.deviceStateAt(
    anchor.inviterUserId,
    anchor.inviterKeyFingerprintHex,
    anchor.headSeq,
  );
  if (inviter === undefined) {
    return `Invite-link anchor check failed: the link's inviter (user_id + key FP) does not match the chain member at the pinned head (the CRYPTO_SPEC §6.5 mechanical check). The invite link or the distributed chain may be forged — do not trust this chain; confirm with the inviter out of band. ${evidenceHint}`;
  }
  if (inviter.device.sigPubHex !== anchor.inviterSigPubHex) {
    return `Invite-link anchor check failed: the link's inviter signing key (is=) does not match the chain member's key at the pinned head (CRYPTO_SPEC §6.3 (a) / §6.5). The invite link or the distributed chain may be forged — do not trust this chain; confirm with the inviter out of band. ${evidenceHint}`;
  }
  return null;
}

export const checkInviteAnchor = Effect.fn("context.checkInviteAnchor")(function* (
  projectId: ProjectId,
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

interface OpenProjectOptions {
  readonly quietMandateWarning?: boolean;
}

export const reconcileGossip = Effect.fn("context.reconcileGossip")(function* (
  projectId: ProjectId,
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

const attachProject = Effect.fn("context.attachProject")(function* (
  context: SessionContext,
  projectId: ProjectId,
  options?: OpenProjectOptions,
  attester?: { readonly userId: UserId; readonly signingKey: CryptoKey },
): Effect.fn.Return<ProjectContextBase, CliError, CliServices> {
  const resync = syncProject(context.client, projectId);
  const synced = yield* resync;
  const checked = yield* loadCheckedFloor(projectId, synced, resync);
  yield* checkInviteAnchor(projectId, checked.verified);
  const verified = yield* reconcileGossip(projectId, checked.verified, resync);
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
    yield* warnUnconvergedMandates({ verified });
  }
  yield* noteServerDisclosure(verified);
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

const openProjectWith = Effect.fn("context.openProjectWith")(function* (
  config: CliConfig,
  flags: CommonFlags,
  options?: OpenProjectOptions,
): Effect.fn.Return<ProjectContext, CliError, CliServices> {
  const projectId = yield* resolveProjectId(flags.project, config);
  const mirrorRead = flags.mirrorOf !== undefined;
  const context = yield* openSessionWith(config, flags.server, mirrorRead ? "mirror" : "server");
  const masterKeys = yield* loadMasterKeys({
    ...context.session,
    origin: flags.mirrorOf ?? context.session.origin,
  });
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
  return mirrorRead ? opened : yield* syncOwnDevices(opened);
});

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

export const openProject = Effect.fn("context.openProject")(function* (
  flags: CommonFlags,
  options?: OpenProjectOptions,
): Effect.fn.Return<ProjectContext, CliError, CliServices> {
  return yield* openProjectWith(yield* loadCliConfig, flags, options);
});

export const openMetadataProject = Effect.fn("context.openMetadataProject")(function* (
  flags: CommonFlags,
): Effect.fn.Return<ProjectContextBase, CliError, CliServices> {
  return yield* openMetadataProjectWith(yield* loadCliConfig, flags);
});

export function floorHandleFor(
  context: ProjectContextBase,
  environmentId: EnvironmentId,
): Effect.Effect<FloorHandle, never, CliServices> {
  return Effect.map(FloorStore, (store) =>
    makeFloorHandle({
      store,
      projectId: context.projectId,
      environmentId,
      initial: floorRecordGet(context.floor?.environments, environmentId) ?? null,
      intents:
        context.floor?.intents.filter((intent) => intent.environmentId === environmentId) ?? [],
    }),
  );
}

export interface EnvironmentContext extends ProjectContext {
  readonly environmentId: EnvironmentId;
  readonly floorHandle: FloorHandle;
}

export const openEnvironment = Effect.fn("context.openEnvironment")(function* (
  flags: CommonFlags,
  options?: OpenProjectOptions,
): Effect.fn.Return<EnvironmentContext, CliError, CliServices> {
  const config = yield* loadCliConfig;
  const environmentId = yield* resolveEnvironmentId(flags.env, config);
  const context = yield* openProjectWith(config, flags, options);
  yield* refuseChainDeletedEnvironment(context.verified, environmentId);
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

export function commitVerifiedHead(
  projectId: ProjectId,
  verified: VerifiedProject,
): Effect.Effect<void, CliError, CliServices> {
  return Effect.flatMap(FloorStore, (store) =>
    store.commitHead(projectId, {
      seq: verified.state.headSeq,
      hashHex: verified.state.headHashHex,
    }),
  );
}

interface MetadataEnvironmentContext extends ProjectContextBase {
  readonly environmentId: EnvironmentId;
  readonly floorHandle: FloorHandle;
}

export const openMetadataEnvironment = Effect.fn("context.openMetadataEnvironment")(function* (
  flags: CommonFlags,
): Effect.fn.Return<MetadataEnvironmentContext, CliError, CliServices> {
  const config = yield* loadCliConfig;
  const environmentId = yield* resolveEnvironmentId(flags.env, config);
  const context = yield* openMetadataProjectWith(config, flags);
  yield* refuseChainDeletedEnvironment(context.verified, environmentId);
  const floorHandle = yield* floorHandleFor(context, environmentId);
  return { ...context, environmentId, floorHandle };
});

interface EnvironmentHandle {
  readonly environmentId: EnvironmentId;
  readonly floorHandle: FloorHandle;
}

interface EnvironmentPairContext extends ProjectContextBase {
  readonly first: EnvironmentHandle;
  readonly second: EnvironmentHandle;
}

export const openMetadataEnvironmentPair = Effect.fn("context.openMetadataEnvironmentPair")(
  function* (
    flags: CommonFlags,
    first: EnvironmentId,
    second: EnvironmentId,
  ): Effect.fn.Return<EnvironmentPairContext, CliError, CliServices> {
    const config = yield* loadCliConfig;
    const context = yield* openMetadataProjectWith(config, flags);
    yield* refuseChainDeletedEnvironment(context.verified, first);
    yield* refuseChainDeletedEnvironment(context.verified, second);
    return {
      ...context,
      first: { environmentId: first, floorHandle: yield* floorHandleFor(context, first) },
      second: { environmentId: second, floorHandle: yield* floorHandleFor(context, second) },
    };
  },
);
