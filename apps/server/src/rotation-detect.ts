import type {
  AuditEventRecordOf,
  KeyFingerprintHex,
  ROTATION_BASES,
  ROTATION_TRIGGERS,
  UserId,
} from "@maruhi/core";

import type {
  AuditRotationRead,
  DeviceEventRow,
  EnvironmentEpochRow,
  MembershipEventRow,
  RotationFlagSourceRow,
  ScopeSnapshot,
  VariableLifecycleRow,
} from "./audit-store-rotation-read.ts";
import { MAX_ROTATION_RECOMMENDED_VARIABLES_PER_ROW } from "./policy.ts";

export type RotationBasis = (typeof ROTATION_BASES)[number];

export type RotationTrigger = (typeof ROTATION_TRIGGERS)[number];

export type RecommendedEvent = AuditEventRecordOf<"rotation.recommended">;

export interface EffectiveRotationFlag {
  readonly environmentId: string;
  readonly variableId: string;
  readonly basis: RotationBasis;
  readonly targetUserId?: UserId;
  readonly targetServerKeyFingerprintHex?: string;
  readonly recommendedAtMs: number;
  readonly triggerChainSeq: number;
  readonly trigger: RotationTrigger;
  readonly reopenedByVersion?: number;
}

interface SeqInterval {
  readonly start: number;
  readonly end: number;
}

interface VariableLifetime {
  readonly environmentId: string;
  readonly variableId: string;
  readonly start: number;
  end: number;
}

const pairKey = (row: { readonly environmentId: string; readonly variableId: string }): string =>
  `${row.environmentId}\u0000${row.variableId}`;

function overlaps(a: SeqInterval, bStart: number, bEnd: number): boolean {
  return Math.max(a.start, bStart) < Math.min(a.end, bEnd);
}

function within(seq: number, interval: SeqInterval): boolean {
  return interval.start < seq && seq < interval.end;
}

interface ScopeTransition {
  readonly seq: number;
  readonly kind: "open" | "update" | "close";
  readonly scope: ScopeSnapshot;
}

const ALL_SCOPE: ScopeSnapshot = { kind: "all" };

function scopeIncludes(scope: ScopeSnapshot, environmentId: string): boolean {
  return scope.kind === "all" || scope.environmentIds.includes(environmentId);
}

function accessWindows(
  transitions: readonly ScopeTransition[],
  environmentId: string,
): readonly SeqInterval[] {
  const windows: SeqInterval[] = [];
  const state = { openedAt: null as number | null };
  const closeWindow = (seq: number): void => {
    if (state.openedAt !== null) {
      windows.push({ start: state.openedAt, end: seq });
      state.openedAt = null;
    }
  };
  for (const transition of transitions) {
    if (transition.kind === "close") {
      closeWindow(transition.seq);
      continue;
    }
    if (scopeIncludes(transition.scope, environmentId)) {
      state.openedAt ??= transition.seq;
    } else {
      closeWindow(transition.seq);
    }
  }
  if (state.openedAt !== null) {
    windows.push({ start: state.openedAt, end: Number.POSITIVE_INFINITY });
  }
  return windows;
}

function membershipTransitions(events: readonly MembershipEventRow[]): readonly ScopeTransition[] {
  return events.map((event) => {
    if (event.event === "chain.member_removed") {
      return { seq: event.seq, kind: "close", scope: ALL_SCOPE };
    }
    const scope = event.scope ?? ALL_SCOPE;
    return {
      seq: event.seq,
      kind: event.event === "chain.role_changed" ? "update" : "open",
      scope,
    };
  });
}

function grantTransitions(
  events: readonly {
    readonly seq: number;
    readonly event: string;
    readonly scopeEnvironmentIds: readonly string[] | null;
  }[],
): readonly ScopeTransition[] {
  const transitions: ScopeTransition[] = [];
  let disclosed: Set<string> | "all" | null = null;
  for (const event of events) {
    if (event.event === "chain.server_revoked") {
      transitions.push({ seq: event.seq, kind: "close", scope: ALL_SCOPE });
      disclosed = null;
      continue;
    }
    const kind = disclosed === null ? "open" : "update";
    disclosed =
      disclosed === "all" || event.scopeEnvironmentIds === null
        ? "all"
        : new Set([...(disclosed ?? []), ...event.scopeEnvironmentIds]);
    transitions.push({
      seq: event.seq,
      kind,
      scope: disclosed === "all" ? ALL_SCOPE : { kind: "listed", environmentIds: [...disclosed] },
    });
  }
  return transitions;
}

function variableLifetimes(
  rows: readonly VariableLifecycleRow[],
): ReadonlyMap<string, VariableLifetime> {
  const lifetimes = new Map<string, VariableLifetime>();
  for (const row of rows) {
    const key = pairKey(row);
    if (row.event === "var.created") {
      if (!lifetimes.has(key)) {
        lifetimes.set(key, {
          environmentId: row.environmentId,
          variableId: row.variableId,
          start: row.seq,
          end: Number.POSITIVE_INFINITY,
        });
      }
      continue;
    }
    const lifetime = lifetimes.get(key);
    if (lifetime !== undefined) {
      lifetime.end = row.seq;
    }
  }
  return lifetimes;
}

function windowsByEnvironment(
  transitions: readonly ScopeTransition[],
): (environmentId: string) => readonly SeqInterval[] {
  const memo = new Map<string, readonly SeqInterval[]>();
  return (environmentId) => {
    const cached = memo.get(environmentId);
    if (cached !== undefined) {
      return cached;
    }
    const windows = accessWindows(transitions, environmentId);
    memo.set(environmentId, windows);
    return windows;
  };
}

function exposureBound(
  epochRows: readonly EnvironmentEpochRow[],
  environmentId: string,
  windows: readonly SeqInterval[],
): number {
  const end = Math.max(...windows.map((window) => window.end));
  let bound = Number.POSITIVE_INFINITY;
  for (const row of epochRows) {
    if (row.environmentId === environmentId && row.seq < end) {
      bound = row.epoch;
    }
  }
  return bound;
}

interface DetectedPairFlag {
  readonly environmentId: string;
  readonly variableId: string;
  readonly basis: RotationBasis;
  readonly epochBound: number;
}

function aggregateRecommended(input: {
  readonly nowMs: number;
  readonly flags: readonly DetectedPairFlag[];
  readonly trigger: RotationTrigger;
  readonly triggerChainSeq: number;
  readonly targetUserId?: UserId;
  readonly targetKeyFingerprintHex?: KeyFingerprintHex;
  readonly revokedDeviceKeyFingerprints?: readonly KeyFingerprintHex[];
}): readonly RecommendedEvent[] {
  const byEnvironment = new Map<string, DetectedPairFlag[]>();
  for (const flag of input.flags) {
    const bucket = byEnvironment.get(flag.environmentId);
    if (bucket === undefined) {
      byEnvironment.set(flag.environmentId, [flag]);
    } else {
      bucket.push(flag);
    }
  }
  return [...byEnvironment.entries()]
    .toSorted(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .flatMap(([environmentId, flags]): RecommendedEvent[] => {
      const epochBound = flags[0]?.epochBound ?? Number.POSITIVE_INFINITY;
      const variables = flags
        .map((flag) => ({ variableId: flag.variableId, basis: flag.basis }))
        .toSorted((a, b) =>
          a.variableId < b.variableId ? -1 : a.variableId > b.variableId ? 1 : 0,
        );
      const rows: RecommendedEvent[] = [];
      for (
        let offset = 0;
        offset < variables.length;
        offset += MAX_ROTATION_RECOMMENDED_VARIABLES_PER_ROW
      ) {
        rows.push({
          event: "rotation.recommended",
          serverTs: input.nowMs,
          actorType: "system",
          ...(Number.isFinite(epochBound) ? { epoch: epochBound } : {}),
          ...(input.targetUserId === undefined ? {} : { targetUserId: input.targetUserId }),
          ...(input.targetKeyFingerprintHex === undefined
            ? {}
            : { targetKeyFingerprintHex: input.targetKeyFingerprintHex }),
          environmentId,
          payload: {
            triggerChainSeq: input.triggerChainSeq,
            trigger: input.trigger,
            variables: variables.slice(offset, offset + MAX_ROTATION_RECOMMENDED_VARIABLES_PER_ROW),
            ...(input.revokedDeviceKeyFingerprints === undefined
              ? {}
              : { revokedDeviceKeyFingerprints: input.revokedDeviceKeyFingerprints }),
          },
        });
      }
      return rows;
    });
}

function detectForMember(input: {
  readonly read: AuditRotationRead;
  readonly targetUserId: UserId;
  readonly trigger: RotationTrigger;
  readonly triggerChainSeq: number;
  readonly nowMs: number;
  readonly selectWindows: (
    windows: readonly SeqInterval[],
    environmentId: string,
  ) => readonly SeqInterval[];
  readonly transitions: readonly ScopeTransition[];
  readonly revokedDeviceKeyFingerprints?: readonly KeyFingerprintHex[];
}): readonly RecommendedEvent[] {
  const windowsOf = windowsByEnvironment(input.transitions);
  const selected = new Map<string, readonly SeqInterval[]>();
  const candidates = [...variableLifetimes(input.read.variableLifecycles()).values()].filter(
    (lifetime) => {
      let windows = selected.get(lifetime.environmentId);
      if (windows === undefined) {
        windows = input.selectWindows(windowsOf(lifetime.environmentId), lifetime.environmentId);
        selected.set(lifetime.environmentId, windows);
      }
      return windows.some((window) => overlaps(window, lifetime.start, lifetime.end));
    },
  );
  if (candidates.length === 0) {
    return [];
  }
  const envelope = [...selected.values()].flat().reduce(
    (range, window) => ({
      afterSeq: Math.min(range.afterSeq, window.start),
      beforeSeq: Math.max(range.beforeSeq, window.end),
    }),
    { afterSeq: Number.POSITIVE_INFINITY, beforeSeq: Number.NEGATIVE_INFINITY },
  );
  const readPairs = new Set(
    input.read
      .variableReadsBy(input.targetUserId, envelope)
      .filter((row) =>
        (selected.get(row.environmentId) ?? []).some((window) => within(row.seq, window)),
      )
      .map(pairKey),
  );
  const epochRows = input.read.environmentEpochEvents();
  return aggregateRecommended({
    nowMs: input.nowMs,
    flags: candidates.map((lifetime): DetectedPairFlag => ({
      environmentId: lifetime.environmentId,
      variableId: lifetime.variableId,
      basis: readPairs.has(pairKey(lifetime)) ? "read" : "readable",
      epochBound: exposureBound(
        epochRows,
        lifetime.environmentId,
        selected.get(lifetime.environmentId) ?? [],
      ),
    })),
    trigger: input.trigger,
    triggerChainSeq: input.triggerChainSeq,
    targetUserId: input.targetUserId,
    ...(input.revokedDeviceKeyFingerprints === undefined
      ? {}
      : { revokedDeviceKeyFingerprints: input.revokedDeviceKeyFingerprints }),
  });
}

export function detectMemberRemoval(input: {
  readonly read: AuditRotationRead;
  readonly targetUserId: UserId;
  readonly triggerChainSeq: number;
  readonly nowMs: number;
}): readonly RecommendedEvent[] {
  const events = input.read.membershipEventsFor(input.targetUserId);
  if (events.length === 0) {
    return [];
  }
  return detectForMember({
    ...input,
    trigger: "remove_member",
    transitions: membershipTransitions(events),
    selectWindows: (windows) => windows,
  });
}

const WRITER_ROLES: ReadonlySet<string> = new Set(["member", "admin", "owner"]);

export function detectRoleChange(input: {
  readonly read: AuditRotationRead;
  readonly targetUserId: UserId;
  readonly triggerChainSeq: number;
  readonly nowMs: number;
}): readonly RecommendedEvent[] {
  const events = input.read.membershipEventsFor(input.targetUserId);
  const trigger = events.at(-1);
  if (trigger === undefined || trigger.event !== "chain.role_changed") {
    return [];
  }
  const previousRole =
    events.toReversed().find((event) => event.seq < trigger.seq && event.role !== null)?.role ??
    null;
  const demoted =
    (previousRole === null || WRITER_ROLES.has(previousRole)) &&
    (trigger.role === null || !WRITER_ROLES.has(trigger.role));
  const closeAll = demoted || trigger.scope === null;
  return detectForMember({
    ...input,
    trigger: "change_role",
    transitions: membershipTransitions(events),
    selectWindows: (windows) =>
      windows.flatMap((window) => {
        if (window.end === trigger.seq) {
          return [window];
        }
        if (closeAll && window.start < trigger.seq && window.end > trigger.seq) {
          return [{ start: window.start, end: trigger.seq }];
        }
        return [];
      }),
  });
}

function intersect(a: SeqInterval, b: SeqInterval): SeqInterval | null {
  const start = Math.max(a.start, b.start);
  const end = Math.min(a.end, b.end);
  return start < end ? { start, end } : null;
}

function revokedDeviceSpans(
  membership: readonly MembershipEventRow[],
  devices: readonly DeviceEventRow[],
  fingerprintsHex: readonly string[],
  triggerSeq: number,
): readonly { readonly interval: SeqInterval; readonly scope: ScopeSnapshot }[] {
  const tenureStart =
    membership
      .filter(
        (event) =>
          event.seq < triggerSeq &&
          (event.event === "chain.genesis" || event.event === "chain.member_added"),
      )
      .at(-1)?.seq ?? 0;
  return fingerprintsHex.map((fingerprintHex) => {
    const added = devices
      .filter(
        (event) =>
          event.seq < triggerSeq &&
          event.event === "chain.device_added" &&
          event.fingerprintsHex.includes(fingerprintHex),
      )
      .at(-1);
    return {
      interval: { start: added?.seq ?? tenureStart, end: triggerSeq },
      scope: added?.scope ?? ALL_SCOPE,
    };
  });
}

export function detectDeviceRevocation(input: {
  readonly read: AuditRotationRead;
  readonly targetUserId: UserId;
  readonly deviceFingerprintsHex: readonly KeyFingerprintHex[];
  readonly triggerChainSeq: number;
  readonly nowMs: number;
}): readonly RecommendedEvent[] {
  const membership = input.read.membershipEventsFor(input.targetUserId);
  if (membership.length === 0) {
    return [];
  }
  const trigger = input.read.deviceEventsFor(input.targetUserId).at(-1);
  if (trigger === undefined || trigger.event !== "chain.device_revoked") {
    return [];
  }
  const spans = revokedDeviceSpans(
    membership,
    input.read.deviceEventsFor(input.targetUserId),
    input.deviceFingerprintsHex,
    trigger.seq,
  );
  return detectForMember({
    ...input,
    trigger: "revoke_device",
    transitions: membershipTransitions(membership),
    revokedDeviceKeyFingerprints: input.deviceFingerprintsHex,
    selectWindows: (windows, environmentId) =>
      windows.flatMap((window) =>
        spans
          .filter((span) => scopeIncludes(span.scope, environmentId))
          .flatMap((span) => {
            const clipped = intersect(window, span.interval);
            return clipped === null ? [] : [clipped];
          }),
      ),
  });
}

export function detectServerRevocation(input: {
  readonly read: AuditRotationRead;
  readonly serverKeyFingerprintHex: KeyFingerprintHex;
  readonly triggerChainSeq: number;
  readonly nowMs: number;
}): readonly RecommendedEvent[] {
  const events = input.read.serverGrantEventsFor(input.serverKeyFingerprintHex);
  if (events.length === 0) {
    return [];
  }
  const windowsOf = windowsByEnvironment(grantTransitions(events));
  const lifetimes = [...variableLifetimes(input.read.variableLifecycles()).values()];
  const access = input.read.serverAccessEventsBy(input.serverKeyFingerprintHex);
  const epochRows = input.read.environmentEpochEvents();
  const flags: DetectedPairFlag[] = [];
  for (const lifetime of lifetimes) {
    const windows = windowsOf(lifetime.environmentId).filter((window) =>
      overlaps(window, lifetime.start, lifetime.end),
    );
    if (windows.length === 0) {
      continue;
    }
    const fetched = access.some((row) => {
      if (row.environmentId !== lifetime.environmentId) {
        return false;
      }
      if (!windows.some((window) => within(row.seq, window))) {
        return false;
      }
      if (row.event === "server.lease_issued") {
        return lifetime.start < row.seq && row.seq < lifetime.end;
      }
      return row.variableId === lifetime.variableId;
    });
    flags.push({
      environmentId: lifetime.environmentId,
      variableId: lifetime.variableId,
      basis: fetched ? "read" : "readable",
      epochBound: exposureBound(
        epochRows,
        lifetime.environmentId,
        windowsOf(lifetime.environmentId),
      ),
    });
  }
  return aggregateRecommended({
    nowMs: input.nowMs,
    flags,
    trigger: "revoke_server",
    triggerChainSeq: input.triggerChainSeq,
    targetKeyFingerprintHex: input.serverKeyFingerprintHex,
  });
}

function triggerOf(row: RotationFlagSourceRow): RotationTrigger {
  const trigger = row.payload?.["trigger"];
  if (
    trigger === "remove_member" ||
    trigger === "change_role" ||
    trigger === "revoke_server" ||
    trigger === "revoke_device"
  ) {
    return trigger;
  }
  throw new Error(`rotation.recommended row has no valid trigger: ${String(trigger)}`);
}

function flagOf(row: RotationFlagSourceRow): EffectiveRotationFlag {
  const basis = row.payload?.["basis"] === "read" ? "read" : "readable";
  const trigger = row.payload?.["triggerChainSeq"];
  return {
    environmentId: row.environmentId,
    variableId: row.variableId,
    basis,
    ...(row.targetUserId === null ? {} : { targetUserId: row.targetUserId }),
    ...(row.targetKeyFingerprintHex === null
      ? {}
      : { targetServerKeyFingerprintHex: row.targetKeyFingerprintHex }),
    recommendedAtMs: row.serverTs,
    triggerChainSeq: typeof trigger === "number" && trigger >= 1 ? trigger : 1,
    trigger: triggerOf(row),
  };
}

function originEpochOf(row: RotationFlagSourceRow, origins: ReadonlyMap<number, number>): number {
  const sameValueAs = row.payload?.["sameValueAs"];
  if (typeof sameValueAs === "number" && Number.isInteger(sameValueAs) && sameValueAs >= 1) {
    return origins.get(sameValueAs) ?? 0;
  }
  return row.epoch ?? 0;
}

interface FlagState {
  readonly flag: EffectiveRotationFlag;
  readonly epochBound: number;
  dismissed: boolean;
  resolved: boolean;
  reopenedByVersion: number | undefined;
}

interface PairState {
  readonly flags: FlagState[];
  readonly origins: Map<number, number>;
  liveOrigin: number | null;
}

function applyPush(pair: PairState, row: RotationFlagSourceRow): void {
  const origin = originEpochOf(row, pair.origins);
  if (row.version !== null) {
    pair.origins.set(row.version, origin);
  }
  pair.liveOrigin = origin;
  for (const flag of pair.flags.filter((candidate) => !candidate.dismissed)) {
    const effective = origin <= flag.epochBound;
    if (!effective) {
      flag.reopenedByVersion = undefined;
    } else if (flag.resolved) {
      flag.reopenedByVersion = row.version ?? undefined;
    }
    flag.resolved = !effective;
  }
}

function foldPairs(rows: readonly RotationFlagSourceRow[]): Map<string, PairState> {
  const pairs = new Map<string, PairState>();
  for (const row of rows) {
    const key = pairKey(row);
    const pair: PairState = pairs.get(key) ?? { flags: [], origins: new Map(), liveOrigin: null };
    pairs.set(key, pair);
    if (row.event === "rotation.recommended") {
      const epochBound = row.epoch ?? Number.POSITIVE_INFINITY;
      pair.flags.push({
        flag: flagOf(row),
        epochBound,
        dismissed: false,
        resolved: pair.liveOrigin !== null && pair.liveOrigin > epochBound,
        reopenedByVersion: undefined,
      });
    } else if (row.event === "rotation.dismissed") {
      for (const flag of pair.flags) {
        flag.dismissed ||= !flag.resolved;
      }
    } else {
      applyPush(pair, row);
    }
  }
  return pairs;
}

export function deriveEffectiveFlags(
  rows: readonly RotationFlagSourceRow[],
): readonly EffectiveRotationFlag[] {
  const effective: EffectiveRotationFlag[] = [];
  for (const pair of foldPairs(rows).values()) {
    for (const state of pair.flags) {
      if (state.dismissed || state.resolved) {
        continue;
      }
      effective.push(
        state.reopenedByVersion === undefined
          ? state.flag
          : { ...state.flag, reopenedByVersion: state.reopenedByVersion },
      );
    }
  }
  return effective;
}

export function flagsIfCurrentByVersion(
  rows: readonly RotationFlagSourceRow[],
  versions: readonly number[],
): ReadonlyMap<number, number> {
  const pair = [...foldPairs(rows).values()][0];
  const live = pair?.flags.filter((flag) => !flag.dismissed) ?? [];
  return new Map(
    versions.map((version) => {
      const origin = pair?.origins.get(version) ?? 0;
      return [version, live.filter((flag) => origin <= flag.epochBound).length];
    }),
  );
}
