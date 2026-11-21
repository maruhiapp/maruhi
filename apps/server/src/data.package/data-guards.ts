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

export function roleAtLeast(role: Role, minimum: Role): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[minimum];
}

export interface MemberWithDevice extends ChainMember {
  readonly device: ChainDevice;
  readonly keyFingerprintHex: KeyFingerprintHex;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly permission: EffectivePermission;
}

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

function activeDevicesOf(member: ChainMember): readonly MemberWithDevice[] {
  return [...member.devices.values()]
    .toSorted((a, b) => (a.keyFingerprintHex < b.keyFingerprintHex ? -1 : 1))
    .map((device) => withDevice(member, device));
}

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
    return yield* Effect.die(new Error("internal: a current member has no active device"));
  }
  let lastRejection: DataRejectedError | null = null;
  for (const device of candidates) {
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
  return yield* Effect.fail(
    lastRejection ?? rejectData({ kind: "value-rejected", reason: "signature-invalid" }),
  );
});

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

export function requireRole(
  state: ChainState,
  callerUserId: UserId,
  minimum: Role,
): Effect.Effect<ChainMember, DataRejectedError> {
  const member = state.members.get(callerUserId);
  if (member === undefined) {
    return Effect.fail(rejectData({ kind: "not-member" }));
  }
  return roleAtLeast(member.role, minimum)
    ? Effect.succeed(member)
    : Effect.fail(rejectData({ kind: "insufficient-role" }));
}

function requireEnvironmentInScope<M extends ChainMember>(
  member: M,
  environmentId: EnvironmentId,
): Effect.Effect<M, DataRejectedError> {
  return scopeIncludesEnvironment(member.scope, environmentId)
    ? Effect.succeed(member)
    : Effect.fail(rejectData({ kind: "insufficient-scope" }));
}

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

interface MemberContext {
  readonly state: ChainState;
  readonly history: ChainHistoryIndex;
  readonly member: ChainMember;
  readonly projectId: ProjectId;
}

export type InitializedChain = StoredChain & {
  readonly headHashHex: string;
  readonly genesisHashHex: string;
};

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

export function currentEpochOf(state: ChainState, environmentId: EnvironmentId): number {
  const environment = state.environments.get(environmentId);
  if (environment === undefined) {
    throw new Error("environment missing from chain-derived state");
  }
  return environment.currentEpoch;
}
