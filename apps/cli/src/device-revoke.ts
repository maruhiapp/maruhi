// `maruhi device revoke <ref...>`: the confirmation -> revoke_device per project ->
// the kind-5 sweep -> the local record -> registry row deletion -> the
// token-revocation proposal (the group's overview lives in device.ts).

import { decodeUserId, type EnvironmentId, type ProjectId, type UserId } from "@maruhi/core";
import type { ChainDevice, ChainMember, MemberScope, Role } from "@maruhi/crypto";
import { effectivePermissionOf, scopeIncludesEnvironment } from "@maruhi/crypto";
import { Clock, Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { resyncExtended, type VerifiedProject } from "./chain-sync.ts";
import { type CliServices, openProject, type ProjectContext } from "./context.ts";
import { ROLE_RANK } from "./dek-wrap.ts";
import { chainEnvironmentIds } from "./deks.ts";
import { describeCap, describeDevice, devicesOf, findOwnDevice } from "./device-key.ts";
import {
  appendRevokeDevice,
  DEVICE_REVOKED_ROTATION_REASON,
  type DeviceSweepOutcome,
  sweepAfterDeviceRevoke,
} from "./device-ops.ts";
import {
  FINGERPRINT_PREFIX,
  fetchRegistry,
  type RegistryRow,
  resolveProjectIds,
} from "./device.ts";
import { displayText, formatUtcMinutes } from "./display.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import { logNote } from "./notice.ts";
import { OwnDeviceStore } from "./own-devices.ts";
import { compareCodePoints } from "./scope.ts";
import { type CliSession, loadMasterKeys, type MasterKeys } from "./session.ts";
import { sweepRotateFor } from "./sweep-rotate.ts";

// ---------------------------------------------------------------------------
// device revoke
// ---------------------------------------------------------------------------

/** Interpreting the references (K4-7: an FP prefix of 8+ chars, or the registry's display name — your own only). */
const resolveRevokeRefs = Effect.fn("device-revoke.resolveRevokeRefs")(function* (input: {
  readonly refs: readonly string[];
  readonly registry: readonly RegistryRow[] | null;
  readonly self: boolean;
}): Effect.fn.Return<readonly RevokeRef[], CliError> {
  const resolved: RevokeRef[] = [];
  for (const ref of input.refs) {
    const lowered = ref.trim().toLowerCase();
    if (FINGERPRINT_PREFIX.test(lowered)) {
      resolved.push({ ref, prefix: lowered, viaLabel: false });
      continue;
    }
    if (!input.self) {
      return yield* Effect.fail(
        usageError(
          `"${displayText(ref)}" is not a fingerprint prefix (at least 8 hex characters). Another member's devices are named by fingerprint only (see \`maruhi member list\`)`,
        ),
      );
    }
    const byLabel = (input.registry ?? []).filter((row) => row.label === ref.trim());
    if (byLabel.length !== 1) {
      return yield* Effect.fail(
        usageError(
          byLabel.length === 0
            ? `"${displayText(ref)}" matches neither a fingerprint prefix (at least 8 hex characters) nor a label in your device registry (\`maruhi device list\`)`
            : `label "${displayText(ref)}" names ${byLabel.length} registry rows; use the fingerprint instead`,
        ),
      );
    }
    resolved.push({ ref, prefix: byLabel[0]!.keyFingerprintHex, viaLabel: true });
  }
  return resolved;
});

/** One project's revocation plan (one stage of the confirmation table). */
interface ProjectRevokePlan {
  readonly context: ProjectContext;
  readonly target: ChainMember;
  readonly revoking: readonly ChainDevice[];
  readonly remaining: readonly ChainDevice[];
  readonly warnings: readonly string[];
}

/** The revocation result on one project (reported by commands/device.ts). */
export interface ProjectRevokeOutcome {
  readonly projectId: ProjectId;
  readonly revoked: readonly string[];
  readonly sweep: DeviceSweepOutcome | null;
  readonly skipped: string | null;
  /** The `revoke_device` append failed (nothing was revoked). */
  readonly failed: string | null;
  /** The append was accepted, but the post-acceptance resync or sweep failed (the revocation is on the chain). */
  readonly sweepFailed: string | null;
}

/** The overall result of `device revoke`. */
export interface DeviceRevokeSummary {
  readonly projects: readonly ProjectRevokeOutcome[];
  /** Tokens proposed but not revoked (name, expiry — K4-13). */
  readonly tokenProposal: readonly string[];
}

/** The reference-resolution result (whether it came via a display name goes on the confirmation table). */
type RevokeRef = { readonly ref: string; readonly prefix: string; readonly viaLabel: boolean };

/** The confirmation table (K4-7): per-project revoked FPs (full) and remaining devices, and the derived warnings. */
const printRevokePlans = Effect.fn("device-revoke.printRevokePlans")(function* (input: {
  readonly targetUserId: UserId;
  readonly plans: readonly ProjectRevokePlan[];
  readonly refs: readonly RevokeRef[];
}): Effect.fn.Return<void, never, CliIo> {
  const io = yield* CliIo;
  yield* io.log(`Revoking devices of ${displayText(input.targetUserId)}:`);
  for (const plan of input.plans) {
    yield* io.log(`  ${displayText(plan.context.projectId)}:`);
    for (const device of plan.revoking) {
      const via = input.refs.find((ref) => device.keyFingerprintHex.startsWith(ref.prefix));
      yield* io.log(
        `    revoke  ${device.keyFingerprintHex} (cap ${describeCap(device)})${via?.viaLabel === true ? ` — matched registry label "${displayText(via.ref)}"; check the fingerprint against \`maruhi device list\`` : ""}`,
      );
    }
    yield* io.log(`    remain  ${plan.remaining.map(describeDevice).join(", ")}`);
    for (const warning of plan.warnings) {
      yield* io.log(`    warning ${warning}`);
    }
  }
});

/** The cleanup after revoking your own device: revoked in the local record, delete the registry row (advisory). */
const finishOwnRevocation = Effect.fn("device-revoke.finishOwnRevocation")(function* (input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly revoked: readonly string[];
}): Effect.fn.Return<void, CliError, OwnDeviceStore> {
  const store = yield* OwnDeviceStore;
  // revoked in the local record (prevents re-registering — K4-3 counterexample 1)
  yield* store.markRevoked(
    input.session.origin,
    input.session.userId,
    input.revoked,
    yield* Clock.currentTimeMillis,
  );
  for (const fp of input.revoked) {
    yield* input.client.devices.remove({ params: { fp } }).pipe(Effect.asVoid, Effect.ignore);
  }
});

/** `maruhi device revoke <ref…> [--user] [--project] [--yes] [--revoke-token]`. */
export const deviceRevokeOp = Effect.fn("device-revoke.deviceRevokeOp")(function* (input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly refs: readonly string[];
  readonly user: string | undefined;
  readonly project: ProjectId | undefined;
  readonly yes: boolean;
  readonly revokeToken: boolean;
}): Effect.fn.Return<DeviceRevokeSummary, CliError, CliServices> {
  const io = yield* CliIo;
  const targetUserId = input.user === undefined ? input.session.userId : decodeUserId(input.user);
  const self = targetUserId === input.session.userId;
  const masterKeys = yield* loadMasterKeys(input.session);
  const { registry, refs, reserveFps } = yield* prepareRevokeRefs({
    session: input.session,
    client: input.client,
    refs: input.refs,
    self,
  });
  const projectIds = yield* resolveProjectIds(input.client, input.project);
  const { plans, outcomes } = yield* planRevokeAll({
    session: input.session,
    projectIds,
    targetUserId,
    refs,
    reserveFps,
    ownFingerprintHex: masterKeys.fingerprintHex,
  });
  if (plans.length === 0) {
    yield* io.log("Nothing to revoke: no synced project lists a matching active device");
  } else {
    yield* printRevokePlans({ targetUserId, plans, refs });
  }
  for (const outcome of outcomes) {
    yield* logNote(`${displayText(outcome.projectId)}: ${outcome.skipped ?? ""}`);
  }
  if (plans.length === 0) {
    return { projects: outcomes, tokenProposal: [] };
  }
  yield* confirmRevoke(input.yes);
  const revoked = yield* executeRevokeAll({
    session: input.session,
    plans,
    targetUserId,
    masterKeys,
    outcomes,
  });
  if (!self) {
    return { projects: outcomes, tokenProposal: [] };
  }
  if (revoked.length > 0) {
    yield* finishOwnRevocation({ session: input.session, client: input.client, revoked });
  }
  const tokenProposal = yield* proposeTokenRevocation({
    client: input.client,
    registry,
    revoked,
    revokeToken: input.revokeToken,
    interactive: !input.yes,
  });
  return { projects: outcomes, tokenProposal };
});

/** The material needed to resolve a reference (for your own device the registry and reserve-key records; for others' just the FP). */
const prepareRevokeRefs = Effect.fn("device-revoke.prepareRevokeRefs")(function* (input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly refs: readonly string[];
  readonly self: boolean;
}): Effect.fn.Return<
  {
    readonly registry: readonly RegistryRow[] | null;
    readonly refs: readonly RevokeRef[];
    readonly reserveFps: ReadonlySet<string>;
  },
  CliError,
  OwnDeviceStore
> {
  const registry = input.self ? yield* fetchRegistry(input.client) : null;
  const refs = yield* resolveRevokeRefs({ refs: input.refs, registry, self: input.self });
  const reserveFps = input.self
    ? yield* recordedReserveFingerprints(input.session)
    : new Set<string>();
  return { registry, refs, reserveFps };
});

/** Executes the revocation on each project and accumulates the results. Return value = the union of revoked FPs. */
const executeRevokeAll = Effect.fn("device-revoke.executeRevokeAll")(function* (input: {
  readonly session: CliSession;
  readonly plans: readonly ProjectRevokePlan[];
  readonly targetUserId: UserId;
  readonly masterKeys: MasterKeys;
  readonly outcomes: ProjectRevokeOutcome[];
}): Effect.fn.Return<readonly string[], never, CliServices> {
  const revokedAll = new Set<string>();
  for (const plan of input.plans) {
    const outcome = yield* executeRevoke({
      session: input.session,
      plan,
      targetUserId: input.targetUserId,
      masterKeys: input.masterKeys,
    });
    for (const fp of outcome.revoked) {
      revokedAll.add(fp);
    }
    input.outcomes.push(outcome);
  }
  return [...revokedAll];
});

/** Each project's revocation plan (a skipped project is accumulated into the result as skipped first). */
const planRevokeAll = Effect.fn("device-revoke.planRevokeAll")(function* (input: {
  readonly session: CliSession;
  readonly projectIds: readonly ProjectId[];
  readonly targetUserId: UserId;
  readonly refs: readonly RevokeRef[];
  readonly reserveFps: ReadonlySet<string>;
  readonly ownFingerprintHex: string;
}): Effect.fn.Return<
  { readonly plans: ProjectRevokePlan[]; readonly outcomes: ProjectRevokeOutcome[] },
  CliError,
  CliServices
> {
  const plans: ProjectRevokePlan[] = [];
  const outcomes: ProjectRevokeOutcome[] = [];
  for (const projectId of input.projectIds) {
    const planned = yield* planRevoke({ ...input, projectId });
    if (typeof planned === "string") {
      outcomes.push({
        projectId,
        revoked: [],
        sweep: null,
        skipped: planned,
        failed: null,
        sweepFailed: null,
      });
    } else {
      plans.push(planned);
    }
  }
  return { plans, outcomes };
});

/** The yes confirmation (skipped by `--yes` — a revocation is not a ceremony. K4-7). */
function confirmRevoke(yes: boolean): Effect.Effect<void, CliError, CliIo> {
  if (yes) {
    return Effect.void;
  }
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const answer = yield* io.promptLine({ prompt: "Type yes to revoke: " });
    if (answer.trim().toLowerCase() !== "yes") {
      return yield* Effect.fail(cliError("Cancelled: nothing was revoked"));
    }
  });
}

/** The FP set of the local records' reserve keys (the non-revoked ones) (warning material for the confirmation table — K4-7). */
const recordedReserveFingerprints = Effect.fn("device-revoke.recordedReserveFingerprints")(
  function* (session: CliSession): Effect.fn.Return<ReadonlySet<string>, CliError, OwnDeviceStore> {
    const store = yield* OwnDeviceStore;
    const lookup = yield* store.load(session.origin, session.userId);
    return new Set(
      (lookup.state === "loaded" ? lookup.devices : [])
        .filter((entry) => entry.source === "reserve" && entry.revokedAtMs === null)
        .map((entry) => entry.keyFingerprintHex),
    );
  },
);

/** The current devices matching a reference (a non-unique prefix is a usage error). */
const matchRevokeTargets = Effect.fn("device-revoke.matchRevokeTargets")(function* (input: {
  readonly projectId: ProjectId;
  readonly devices: readonly ChainDevice[];
  readonly refs: readonly { readonly prefix: string }[];
}): Effect.fn.Return<readonly ChainDevice[], CliError> {
  const revoking: ChainDevice[] = [];
  for (const ref of input.refs) {
    const hits = input.devices.filter((device) => device.keyFingerprintHex.startsWith(ref.prefix));
    if (hits.length > 1) {
      return yield* Effect.fail(
        usageError(
          `fingerprint prefix ${ref.prefix} matches ${hits.length} devices on ${displayText(input.projectId)}; use a longer prefix`,
        ),
      );
    }
    const hit = hits[0];
    if (hit !== undefined && !revoking.includes(hit)) {
      revoking.push(hit);
    }
  }
  return revoking;
});

/** Warnings derived from the remaining devices' caps (K4-7 / K4-8 / §2-bis). */
function revokeWarnings(input: {
  readonly verified: VerifiedProject;
  readonly target: ChainMember;
  readonly remaining: readonly ChainDevice[];
  readonly revokingFps: ReadonlySet<string>;
  readonly self: boolean;
  readonly reserveFps: ReadonlySet<string>;
  readonly ownFingerprintHex: string;
}): readonly string[] {
  const { target, remaining } = input;
  const warnings: string[] = [];
  if (
    target.role === "owner" &&
    remaining.every((device) => ROLE_RANK[device.roleCap] < ROLE_RANK.owner)
  ) {
    warnings.push(
      "no remaining device carries an owner cap — the owner could no longer act as owner (approve proposals, change roles) from any device until a device without the cap is added",
    );
  }
  const uncovered = uncoveredEnvironments(input.verified, target, remaining);
  if (uncovered.length > 0) {
    warnings.push(
      `no remaining device's cap covers ${uncovered.map(displayText).join(", ")} — the person keeps those environments in scope but no device could open them`,
    );
  }
  if (input.self && !remaining.some((device) => input.reserveFps.has(device.keyFingerprintHex))) {
    warnings.push(
      "no remaining device is recorded as your reserve key on this machine — if the reserve key is among the revoked ones, create a new one afterwards with `maruhi key recovery --replace`",
    );
  }
  if (input.revokingFps.has(input.ownFingerprintHex)) {
    warnings.push(
      "this revokes the device you are running on: after the entry lands this machine can no longer sign here, and the rotation sweep cannot be fulfilled from it (another of your devices, or a member whose scope covers the environments, must rotate)",
    );
  }
  if (ROLE_RANK[target.role] < ROLE_RANK.member) {
    warnings.push(
      "the person is a reader, so the rotation the revocation mandates cannot be run by them — a member whose scope covers the environments converges it",
    );
  }
  return warnings;
}

/** Assembles one project's worth of confirmation-table material (string = the skip reason). */
const planRevoke = Effect.fn("device-revoke.planRevoke")(function* (input: {
  readonly session: CliSession;
  readonly projectId: ProjectId;
  readonly targetUserId: UserId;
  readonly refs: readonly { readonly prefix: string }[];
  readonly reserveFps: ReadonlySet<string>;
  readonly ownFingerprintHex: string;
}): Effect.fn.Return<ProjectRevokePlan | string, CliError, CliServices> {
  const context = yield* openProject({ server: input.session.origin, project: input.projectId });
  const target = context.verified.state.members.get(input.targetUserId);
  if (target === undefined) {
    return `${displayText(input.targetUserId)} is not a member of this project`;
  }
  const self = context.verified.state.members.get(input.session.userId);
  if (
    self === undefined ||
    findOwnDevice(self, { keyFingerprintHex: input.ownFingerprintHex }) === undefined
  ) {
    return "this machine's key is not one of your registered devices here (revoke from a device that is)";
  }
  const devices = devicesOf(target);
  const revoking = yield* matchRevokeTargets({
    projectId: input.projectId,
    devices,
    refs: input.refs,
  });
  if (revoking.length === 0) {
    return "no active device matches the reference (already revoked, or never registered here)";
  }
  const revokingFps = new Set(revoking.map((device) => device.keyFingerprintHex));
  const remaining = devices.filter((device) => !revokingFps.has(device.keyFingerprintHex));
  if (remaining.length === 0) {
    return "it would revoke the last device (last-device-protected — CRYPTO_SPEC §6.2). To remove the person, use `maruhi member remove`";
  }
  const warnings = revokeWarnings({
    verified: context.verified,
    target,
    remaining,
    revokingFps,
    self: input.targetUserId === input.session.userId,
    reserveFps: input.reserveFps,
    ownFingerprintHex: input.ownFingerprintHex,
  });
  return { context, target, revoking, remaining, warnings };
});

/** Within the target scope, the environments no remaining device's effective scope includes (K4-7's warning material). */
function uncoveredEnvironments(
  verified: VerifiedProject,
  target: ChainMember,
  remaining: readonly ChainDevice[],
): readonly EnvironmentId[] {
  const covered = remaining.map((device) => effectivePermissionOf(target, device).scope);
  return chainEnvironmentIds(verified)
    .filter(
      (environmentId) =>
        scopeIncludesEnvironment(target.scope, environmentId) &&
        !covered.some((scope: MemberScope) => scopeIncludesEnvironment(scope, environmentId)),
    )
    .toSorted(compareCodePoints);
}

/** `revoke_device` → sweep on one project (a failure folds into the result). */
function executeRevoke(input: {
  readonly session: CliSession;
  readonly plan: ProjectRevokePlan;
  readonly targetUserId: UserId;
  readonly masterKeys: MasterKeys;
}): Effect.Effect<ProjectRevokeOutcome, never, CliServices> {
  const { context } = input.plan;
  const base = {
    projectId: context.projectId,
    revoked: [] as readonly string[],
    sweep: null,
    skipped: null,
    failed: null,
    sweepFailed: null,
  } satisfies ProjectRevokeOutcome;
  return Effect.gen(function* () {
    const appended = yield* appendRevokeDevice({
      client: context.client,
      verified: context.verified,
      resync: context.resync,
      signer: { userId: input.session.userId, signingKeyPair: input.masterKeys.sigKeyPair },
      targetUserId: input.targetUserId,
      fingerprintsHex: input.plan.revoking.map((device) => device.keyFingerprintHex),
    });
    const { revoked } = appended;
    // After the append is accepted the revocation is on the chain: a
    // resync / sweep failure is not folded into "revocation failed" — the
    // revocation stays and it is reported as a sweep failure (never skip
    // the local-record / registry aftermath)
    return yield* sweepAfterRevoke({ ...input, appended }).pipe(
      Effect.map((sweep) => ({ ...base, revoked, sweep })),
      Effect.catch((error) =>
        Effect.succeed({
          ...base,
          revoked,
          sweepFailed: error.message,
        } satisfies ProjectRevokeOutcome),
      ),
    );
  }).pipe(Effect.catch((error) => Effect.succeed({ ...base, failed: error.message })));
}

/** The post-acceptance resync and sweep (failures are returned as-is — the caller folds them into sweepFailed). */
function sweepAfterRevoke(input: {
  readonly session: CliSession;
  readonly plan: ProjectRevokePlan;
  readonly targetUserId: UserId;
  readonly masterKeys: MasterKeys;
  readonly appended: { readonly verified: VerifiedProject; readonly revoked: readonly string[] };
}): Effect.Effect<DeviceSweepOutcome | null, CliError, CliServices> {
  const { context } = input.plan;
  return Effect.gen(function* () {
    // The post-acceptance resync (the pre-append view has no revocation
    // duty — the sweep is derived on the view that confirmed the listing.
    // Same discipline as member remove: the server's claim is never the
    // source of truth)
    const verified =
      input.appended.revoked.length === 0
        ? input.appended.verified
        : yield* resyncExtended(context.resync, input.appended.verified);
    const self = verified.state.members.get(input.session.userId);
    const actorDevice =
      self === undefined
        ? undefined
        : findOwnDevice(self, { keyFingerprintHex: input.masterKeys.fingerprintHex });
    // When this device revoked itself, the sweep cannot be fulfilled from this device (K4-7 counterexample 5)
    return actorDevice === undefined
      ? null
      : yield* sweepAfterDeviceRevoke({
          client: context.client,
          verified,
          targetUserId: input.targetUserId,
          actorUserId: input.session.userId,
          actorDevice,
          rotate: sweepRotateFor({ ...context, verified }, DEVICE_REVOKED_ROTATION_REASON),
        });
  });
}

/**
 * Proposing token revocation (K4-13): the candidate is the registry's
 * `tokenId`, else the name `cli:<label>`. With `--revoke-token` it revokes;
 * interactively it asks for yes; non-interactively (`--yes`) it only
 * returns the proposal. A 403 on the list (a non-admin token) reports only
 * the fact.
 */
const proposeTokenRevocation = Effect.fn("device-revoke.proposeTokenRevocation")(function* (input: {
  readonly client: MaruhiClient;
  readonly registry: readonly RegistryRow[] | null;
  readonly revoked: readonly string[];
  readonly revokeToken: boolean;
  readonly interactive: boolean;
}): Effect.fn.Return<readonly string[], CliError, CliIo> {
  const io = yield* CliIo;
  if (input.revoked.length === 0) {
    return [];
  }
  const listed = yield* input.client.auth.listTokens({}).pipe(
    Effect.map((response) => response.tokens),
    Effect.catchTag(
      "Forbidden",
      () => Effect.succeed(null),
      (error) => Effect.fail(toCliError(error)),
    ),
  );
  if (listed === null) {
    yield* logNote(
      "revoking a device does not revoke its API token (AUTH_SPEC §6). This token cannot list tokens; revoke the lost device's token from the web dashboard or with an admin token (`maruhi token revoke <id>`)",
    );
    return [];
  }
  const rows = (input.registry ?? []).filter((row) =>
    input.revoked.includes(row.keyFingerprintHex),
  );
  const candidates = listed.filter((token) =>
    rows.some((row) =>
      row.tokenId === undefined ? token.name === `cli:${row.label}` : row.tokenId === token.id,
    ),
  );
  if (candidates.length === 0) {
    yield* logNote(
      "revoking a device does not revoke its API token (AUTH_SPEC §6). No token could be matched to the revoked devices (the registry row carries no token id and no token is named after its label) — check `maruhi token list`",
    );
    return [];
  }
  const describe = describeToken;
  yield* io.log(
    `The revoked devices' API tokens are still valid (the match is server-reported): ${candidates.map(describe).join("; ")}`,
  );
  let revoke = input.revokeToken;
  if (!revoke && input.interactive) {
    const answer = yield* io.promptLine({ prompt: "Revoke these tokens too? Type yes: " });
    revoke = answer.trim().toLowerCase() === "yes";
  }
  if (!revoke) {
    yield* logNote(
      "tokens were left as they are — revoke them later with `maruhi token revoke <id>` (pass --revoke-token to do it in the same run)",
    );
    return candidates.map(describe);
  }
  for (const token of candidates) {
    yield* input.client.auth.revokeTokenById({ params: { tokenId: token.id } }).pipe(
      Effect.asVoid,
      Effect.catchTag(
        "TokenNotFound",
        () => Effect.void,
        (error) => Effect.fail(toCliError(error)),
      ),
    );
    yield* io.log(`Revoked token ${describe(token)}`);
  }
  return [];
});

/** One token-candidate row (id, name, expiry — K4-13's proposal display). */
function describeToken(token: {
  readonly id: string;
  readonly name: string;
  readonly expiresAtMs: number;
}): string {
  return `${displayText(token.id)} (${displayText(token.name)}, expires ${formatUtcMinutes(token.expiresAtMs)})`;
}

/** Assembling the cap (`--cap <role>` + the scope flags). */
export function parseCapRole(raw: string | undefined): Effect.Effect<Role, CliError> {
  if (raw === undefined) {
    return Effect.succeed("owner");
  }
  const roles: readonly Role[] = ["owner", "admin", "member", "reader"];
  const role = roles.find((candidate) => candidate === raw);
  return role === undefined
    ? Effect.fail(usageError(`--cap must be one of ${roles.join(", ")}`))
    : Effect.succeed(role);
}
