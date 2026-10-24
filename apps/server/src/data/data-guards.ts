// The data plane's authorization guards (chain-derived role and environment
// scope — CRYPTO_SPEC §6.2 / AUTH_SPEC §12-3): the role floor and the scope
// predicate, the request's signing device and its effective permission, and
// the front stages that load and derive the chain for a data operation.

import type { EnvironmentId, ProjectId, UserId } from "@maruhi/core";
import type {
  ChainDevice,
  ChainHistoryIndex,
  ChainMember,
  ChainState,
  EffectivePermission,
  KeyFingerprintHex,
  Role,
} from "@maruhi/crypto";
import { effectivePermissionOf, scopeIncludesEnvironment } from "@maruhi/crypto";
import { Effect } from "effect";

import type { StateCache, StoredChain } from "../do/chain-store.ts";
import { ChainStore, deriveStoredState } from "../do/chain-store.ts";
import { projectIdOf } from "./data-plane.ts";
import type { DataRejectedError, DataRejection } from "./data-rejection.ts";
import { rejectData } from "./data-rejection.ts";

const ROLE_RANK: Record<Role, number> = { reader: 1, member: 2, admin: 3, owner: 4 };

/**
 * The lower-bound check of a chain role (reader < member < admin <
 * owner). Also shared with the invites API's worker-side level judgment
 * (handlers-invites.ts) — do not proliferate the rank table.
 */
export function roleAtLeast(role: Role, minimum: Role): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[minimum];
}

/**
 * A chain member together with **the device that signed this request** (2026-09-19
 * DK — K3; design record dk-design.md §8 K3-1): the key every chain-external signature of
 * the request is attributed to (the signer FP at acceptance time, the DEK
 * wrap's recipient key, the audit row's FP) and the effective permission that device holds — `(min(role, role_cap), scope ∩
 * device scope)` (CRYPTO_SPEC §6.2). The device is resolved **from the signature
 * itself** (`withSigningDevice` — the caller's active devices are tried in
 * fingerprint order; key uniqueness across current members makes at most one
 * verify) or, for chain entries, from `entry.actor.keyFingerprintHex` (`deviceOf`).
 * The advisory device registry (AUTH_SPEC §13-11) is never an input here.
 */
export interface MemberWithDevice extends ChainMember {
  readonly device: ChainDevice;
  readonly keyFingerprintHex: KeyFingerprintHex;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  /** The signing device's effective permission (§6.2 — the input of the second-stage authorization). */
  readonly permission: EffectivePermission;
}

/** `member` + the valid device of the given FP (undefined when absent — the caller picks the reason code). */
export function deviceOf(
  member: ChainMember,
  keyFingerprintHex: KeyFingerprintHex,
): MemberWithDevice | undefined {
  const device = member.devices.get(keyFingerprintHex);
  return device === undefined ? undefined : withDevice(member, device);
}

function withDevice(member: ChainMember, device: ChainDevice): MemberWithDevice {
  return {
    ...member,
    device,
    keyFingerprintHex: device.keyFingerprintHex,
    encPubHex: device.encPubHex,
    sigPubHex: device.sigPubHex,
    permission: effectivePermissionOf(member, device),
  };
}

/** The calling principal's valid devices in ascending FP order (makes the trial order deterministic — the result does not depend on it). */
function activeDevicesOf(member: ChainMember): readonly MemberWithDevice[] {
  return [...member.devices.values()]
    .toSorted((a, b) => (a.keyFingerprintHex < b.keyFingerprintHex ? -1 : 1))
    .map((device) => withDevice(member, device));
}

/**
 * A rejection that only says "this signature does not verify under this key" —
 * the one outcome that makes `withSigningDevice` try the caller's next device.
 * Every other rejection (head unknown, state mismatch, CAS, …) is final for the
 * device that produced it: a signature that verified under one key has found
 * its device, and a non-signature rejection cannot be cured by another key.
 */
function isSignatureInvalidRejection(rejection: DataRejection): boolean {
  switch (rejection.kind) {
    case "value-rejected":
    case "meta-rejected":
    case "manifest-rejected":
    case "attestation-rejected":
    case "dek-wrap-rejected":
      return rejection.reason === "signature-invalid";
    default:
      return false;
  }
}

/**
 * Resolves the request's signing device from a signature (design record
 * §8 K3-1 — option a-3): runs `attempt` with each of the member's active devices in
 * fingerprint order until one does not answer `signature-invalid`. Returns that
 * device with the attempt's value. When every device answers `signature-invalid`
 * the last such rejection is returned (fail-closed — the signature belongs to no
 * active device of the caller: a revoked device, a foreign key, or garbage).
 * At most 16 devices (AUTH_SPEC §12-8) bound the trial.
 */
export const withSigningDevice = Effect.fn("data-guards.withSigningDevice")(function* <A, R>(
  member: ChainMember,
  attempt: (device: MemberWithDevice) => Effect.Effect<A, DataRejectedError, R>,
): Effect.fn.Return<
  { readonly device: MemberWithDevice; readonly value: A },
  DataRejectedError,
  R
> {
  const candidates = activeDevicesOf(member);
  if (candidates.length === 0) {
    // A current member of a verified chain holds at least one device (§6.2 last-device-protected)
    return yield* Effect.die(new Error("internal: a current member has no active device"));
  }
  let lastRejection: DataRejectedError | null = null;
  for (const device of candidates) {
    // Only signature-invalid folds into "try the next device". Every
    // other rejection is final for that device
    const outcome: { readonly verified: A } | { readonly retry: DataRejectedError } =
      yield* attempt(device).pipe(
        Effect.map((value) => ({ verified: value })),
        Effect.catchTag("DataRejected", (error) =>
          isSignatureInvalidRejection(error.rejection)
            ? Effect.succeed({ retry: error })
            : Effect.fail(error),
        ),
      );
    if ("verified" in outcome) {
      return { device, value: outcome.verified };
    }
    lastRejection = outcome.retry;
  }
  // candidates is non-empty, so lastRejection is always set
  return yield* Effect.fail(
    lastRejection ?? rejectData({ kind: "value-rejected", reason: "signature-invalid" }),
  );
});

/**
 * Second-stage authorization (design record §8 K3-1): the signing device's **effective**
 * permission must satisfy the same role floor and (when an environment is
 * targeted) the same scope predicate the person already passed at the first
 * stage. Same reason codes as the first stage (403 — AUTH_SPEC §12-3). A device
 * never exceeds its person, so this can only narrow what the first stage let
 * through.
 *
 * Reachability (design record §8 K3 implementation note): on the composite, checkpoint and DEK-register
 * paths this is the check that produces the 403 (pinned by
 * membership-negatives-composite / device-ops tests). On the value push, metadata
 * statement and manifest paths the crypto layer's declared-head authorization
 * (CRYPTO_SPEC §6.3 — `deviceStateAt`, effective permission since DK K2) runs
 * first inside signature verification and rejects a capped device with 422
 * `chain-head-state-mismatch`; a device cap is immutable and the person's role
 * is bounded by the first stage, so no request passes the declared-head check
 * and fails here. Those call sites are defense in depth by construction, not a
 * coverage gap — do not delete them, and do not expect a test to reach them.
 * The head-attestation path has no second-stage call at all: `reader` is the
 * floor of the role enum, so no device's effective role can fall below the
 * op's requirement, and the op is chain-wide (no environment to scope).
 */
export function ensureDevicePermission(
  device: MemberWithDevice,
  minimum: Role,
  environmentId?: EnvironmentId,
): Effect.Effect<void, DataRejectedError> {
  if (!roleAtLeast(device.permission.role, minimum)) {
    return Effect.fail(rejectData({ kind: "insufficient-role" }));
  }
  if (
    environmentId !== undefined &&
    !scopeIncludesEnvironment(device.permission.scope, environmentId)
  ) {
    return Effect.fail(rejectData({ kind: "insufficient-scope" }));
  }
  return Effect.void;
}

/**
 * The lower-bound check of a chain-derived role (shared with the
 * composite programs — composite-programs.ts).
 * First stage (the person's role — design record §8 K3-1): since a
 * device's effective permission never exceeds the person's, a principal
 * that fails here also fails on its device. The effective permission of
 * the signing device (second stage) is judged after signature
 * verification by ensureDevicePermission.
 */
export function requireRole(
  state: ChainState,
  callerUserId: UserId,
  minimum: Role,
): Effect.Effect<ChainMember, DataRejectedError> {
  const member = state.members.get(callerUserId);
  if (member === undefined) {
    // §11-2: a non-member gets nothing back, including the current head
    // and the acceptance decision (the worker maps it to 404)
    return Effect.fail(rejectData({ kind: "not-member" }));
  }
  return roleAtLeast(member.role, minimum)
    ? Effect.succeed(member)
    : Effect.fail(rejectData({ kind: "insufficient-role" }));
}

/**
 * The scope judgment of an environment-targeted op (the "environment ∈
 * scope" column of AUTH_SPEC §12-3 — the scope derived by the verified
 * state of CRYPTO_SPEC §6.2; 2026-09-15 ES K3): placed right after the
 * role floor and before the environment's existence (a data row)
 * (design record es-design.md §9 K3-C — a check decided by chain-derived
 * state alone goes before one that reads stored state). The judgment is
 * the single predicate `scopeIncludesEnvironment` (`all` = every
 * environment), and environment creation (the §12-3 "scope = all" row)
 * is judged by the same predicate — since a `listed` scope cannot
 * contain a not-yet-existent environment id, only an `all` principal
 * passes (the same shape as §6.2).
 */
function requireEnvironmentInScope<M extends ChainMember>(
  member: M,
  environmentId: EnvironmentId,
): Effect.Effect<M, DataRejectedError> {
  return scopeIncludesEnvironment(member.scope, environmentId)
    ? Effect.succeed(member)
    : Effect.fail(rejectData({ kind: "insufficient-scope" }));
}

/**
 * The two stages role floor → scope (the §12-3 check order). Used by the
 * environment-targeted ops that load the whole chain themselves (the
 * composite — composite-programs.ts — and the standalone checkpoint —
 * checkpoint-accept.ts). Data-plane programs use
 * requireEnvironmentAccess (below).
 */
export function requireRoleInScope(
  state: ChainState,
  callerUserId: UserId,
  minimum: Role,
  environmentId: EnvironmentId,
): Effect.Effect<ChainMember, DataRejectedError> {
  return Effect.flatMap(requireRole(state, callerUserId, minimum), (member) =>
    requireEnvironmentInScope(member, environmentId),
  );
}

/**
 * The result of requireMemberState: besides the derived state and the
 * history index (the input of the value signature's declared-head-time
 * verification — CRYPTO_SPEC §4.1 / §6.4), returns the calling
 * principal's chain member (the source of the verification key and
 * signer FP of registration and value signatures — §5.1 / §4.1) and the
 * project ID (= the genesis entry hash; the coordinate being signed).
 */
interface MemberContext {
  readonly state: ChainState;
  readonly history: ChainHistoryIndex;
  /**
   * The caller as a **person** (role, scope, the device set). The device that signed the
   * request is resolved later from the signature (`withSigningDevice`) or the
   * entry actor (`deviceOf`) — design record §8 K3-1. Unsigned operations (reads,
   * deletions, dismissals) have no device and are judged on the person alone.
   */
  readonly member: ChainMember;
  readonly projectId: ProjectId;
}

/** An initialized chain (a StoredChain whose type guarantees the genesis hash exists). */
export type InitializedChain = StoredChain & {
  readonly headHashHex: string;
  readonly genesisHashHex: string;
};

/**
 * Chain loading and the initialization check (the shared front stage of
 * data operations and composite acceptance). Uninitialized is
 * not-initialized; headSeq > 0 with genesis / head missing is storage
 * corruption (a defect).
 */
export const loadInitializedChain: Effect.Effect<InitializedChain, DataRejectedError, ChainStore> =
  Effect.gen(function* () {
    const store = yield* ChainStore;
    const chain = yield* store.load;
    if (chain.headSeq === 0 || chain.headHashHex === null) {
      return yield* rejectData({ kind: "not-initialized" });
    }
    if (chain.genesisHashHex === null) {
      return yield* Effect.die(new Error("initialized chain is missing its genesis hash"));
    }
    return { ...chain, headHashHex: chain.headHashHex, genesisHashHex: chain.genesisHashHex };
  });

/**
 * The front stage shared by data operations: initialization check →
 * chain derivation → membership and role-floor check (the §12-3 check
 * order). Derivation reuses the same cache as the chain API.
 */
export const requireMemberState = Effect.fn("data-guards.requireMemberState")(function* (
  callerUserId: UserId,
  minimum: Role,
  cache: StateCache,
): Effect.fn.Return<MemberContext, DataRejectedError, ChainStore> {
  const chain = yield* loadInitializedChain;
  const { state, history } = yield* deriveStoredState(chain, cache);
  const member = yield* requireRole(state, callerUserId, minimum);
  return { state, history, member, projectId: projectIdOf(chain) };
});

/**
 * The front stage shared by environment-targeted data operations
 * (§12-3): requireMemberState (uninitialized → membership → role floor)
 * → **environment ∈ the calling principal's scope** (403
 * insufficient-scope). The environment's existence (a data row —
 * requireActiveEnvironment) is checked by the caller after this
 * (design record §9 K3-C: role → scope → existence).
 * Paths without an environment / where scope does not apply
 * (environment list, metadata-only pull, flags, audit) use
 * requireMemberState as-is — splitting the functions lets the type
 * distinguish "does not apply" from "forgot to call".
 */
export const requireEnvironmentAccess = Effect.fn("data-guards.requireEnvironmentAccess")(
  function* (
    callerUserId: UserId,
    minimum: Role,
    environmentId: EnvironmentId,
    cache: StateCache,
  ): Effect.fn.Return<MemberContext, DataRejectedError, ChainStore> {
    const context = yield* requireMemberState(callerUserId, minimum, cache);
    yield* requireEnvironmentInScope(context.member, environmentId);
    return context;
  },
);

/**
 * An environment's current epoch = the chain-derived value (CRYPTO_SPEC
 * §6.2 / §6.3).
 * Since the environment's very existence is chain-derived
 * (`create_environment`), there is no "default to 1 when unobserved"
 * fallback. A data row is created atomically with the chain entry in
 * composite acceptance (§12-4), so having an active data row while the
 * chain has no environment is an invariant violation (a storage /
 * implementation bug) and is dropped as a defect.
 */
export function currentEpochOf(state: ChainState, environmentId: EnvironmentId): number {
  const environment = state.environments.get(environmentId);
  if (environment === undefined) {
    throw new Error("environment missing from chain-derived state");
  }
  return environment.currentEpoch;
}
