// Detection of rotation-needed flags (AUDIT_SPEC §4.1 = the implementation of
// CRYPTO_SPEC §7) and derivation of flag dismissal (§4.1 step 5).
//
// - Detection runs inside the project DO at the acceptance of `remove_member` /
//   `change_role` (demotion, scope reduction — 2026-09-14 ES) / `revoke_server`
//   / `revoke_device` (device windows — 2026-09-19 DK), and appends
//   `rotation.recommended` (one row per (variable × environment) — §3.3) in
//   the same synchronous task as the mirror append (chain-accept.ts wires it).
//   The coordinate system is the audit seq (the total order inside the DO —
//   chain acceptance and data operations ride on the same sequence)
// - The candidate set (§4.1 step 2) is **per-environment access windows**: the
//   list of seq intervals during which the subject could have held
//   environment E's DEK. A window is determined only by the transition points
//   of the scope state (`all` / `listed`) in the chain mirror's payload, and
//   member (genesis / member_added / role_changed / member_removed) and server
//   (server_granted / server_revoked) **share a single window derivation**
//   (§4.1 "the implementation shares one window derivation" — design record
//   es-design.md §9 K3-E). `all` = every environment (including future ones),
//   so a variable created during an `all` period naturally becomes a candidate
//   by overlap with its existence interval
// - Interval overlap is an open-interval check: max(start) < min(end). Even
//   between adjacent events (e.g. a delete accepted right after a variable's
//   creation) there is a real-time window and "could have been obtained"
//   holds (the actual fetch is sandwiched between events, so rank (a) is
//   correctly empty)
// - Resolution derivation is a pure fold over the event sequence (flags do not
//   live in a mutable store — §4.1). It follows the value lineage (§4.1-5 —
//   2026-09-27 VH): every pushed version carries a plaintext origin epoch
//   (its own epoch, or — for a push declaring sameValueAs — the origin epoch
//   of the version it names), and a flag is effective while the live value's
//   origin epoch is within the flag's exposure bound (the environment's epoch
//   at the end of the subject's window — the recommended row's epoch column).
//   A re-encryption therefore neither resolves nor un-resolves (blocks a
//   mandatory-rotation sweep from auto-resolving everything), and a rollback to
//   a value the subject could read re-opens a resolved flag. A dismissal
//   covers the flags effective when it is recorded and is sticky

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
} from "./audit-store.ts";

/** Basis rank (§4.1 step 3): read = definitely obtained / readable = could have been obtained. */
export type RotationBasis = (typeof ROTATION_BASES)[number];

/**
 * The op that triggered detection (§3.3 `rotation.recommended`'s
 * payload.trigger — 2026-09-14 ES): remove_member / change_role
 * (demotion/shrink) / revoke_server / revoke_device.
 */
export type RotationTrigger = (typeof ROTATION_TRIGGERS)[number];

/** One `rotation.recommended` row (§3.3) — what every detection variant returns. */
export type RecommendedEvent = AuditEventRecordOf<"rotation.recommended">;

/** A currently-effective rotation-needed flag (the §4.1 step 5 derivation result; crosses the RPC boundary). */
export interface EffectiveRotationFlag {
  readonly environmentId: string;
  readonly variableId: string;
  readonly basis: RotationBasis;
  /** Only on the remove_member / change_role variants. */
  readonly targetUserId?: UserId;
  /** Only on the revoke_server variant. */
  readonly targetServerKeyFingerprintHex?: string;
  // No audit seq is carried (the 2026-08-16 ruling C1): the gapless sequence
  // number cannot go on the wire (it would leak the class-2 row count — §7),
  // and the dismissal order is already guaranteed by the derivation's input
  // row order (the seq order of rotationFlagEvents), so the output does not
  // need it
  readonly recommendedAtMs: number;
  /** The chain seq of the deletion / demotion-or-shrink / revocation entry that triggered detection (from the payload). */
  readonly triggerChainSeq: number;
  /** The op that triggered detection (the payload's trigger). */
  readonly trigger: RotationTrigger;
  /**
   * The version whose push restored a value from before this flag after the
   * flag had been resolved (§4.1-5 / §7 — 2026-09-27 VH). Absent when the flag
   * was never resolved.
   */
  readonly reopenedByVersion?: number;
}

/** A half-open interval on the audit seq (end = +Infinity means unclosed). */
interface SeqInterval {
  readonly start: number;
  readonly end: number;
}

/** A variable's existence interval (Q2 of §4.1 step 2 — var.created to var.deleted). */
interface VariableLifetime {
  readonly environmentId: string;
  readonly variableId: string;
  readonly start: number;
  end: number;
}

const pairKey = (row: { readonly environmentId: string; readonly variableId: string }): string =>
  `${row.environmentId}\u0000${row.variableId}`;

/** Overlap of two open intervals (includes the real-time window between integer seqs — see the header comment). */
function overlaps(a: SeqInterval, bStart: number, bEnd: number): boolean {
  return Math.max(a.start, bStart) < Math.min(a.end, bEnd);
}

/** Whether seq lies inside an event interval (excluding the boundary events themselves). */
function within(seq: number, interval: SeqInterval): boolean {
  return interval.start < seq && seq < interval.end;
}

// ---------------------------------------------------------------------------
// Per-environment access windows (§4.1 step 2 — the window derivation shared
// by member / server)
// ---------------------------------------------------------------------------

/**
 * A scope-state transition (one mirror row = one transition): open = start of
 * membership / grant (with a scope), update = replacement of the scope during
 * the interval (change_role, enlarging re-grant), close = end of membership /
 * grant. The window derivation looks only at these three kinds (identical
 * across recipient classes).
 */
interface ScopeTransition {
  readonly seq: number;
  readonly kind: "open" | "update" | "close";
  readonly scope: ScopeSnapshot;
}

const ALL_SCOPE: ScopeSnapshot = { kind: "all" };

function scopeIncludes(scope: ScopeSnapshot, environmentId: string): boolean {
  return scope.kind === "all" || scope.environmentIds.includes(environmentId);
}

/**
 * The list of access windows for environment E (§4.1 step 2): opens on the
 * transition where E enters scope; closes on the transition (update) where E
 * leaves scope, or on close. A restart spanning a membership / grant interval
 * boundary is a separate window. Chain consensus rules reject double-add and
 * double-grant, but the derivation defensively treats "an open while an
 * interval is open" the same as update, and "an update outside an interval"
 * the same as open (for corrupt input, err toward not missing — design record
 * §9 K3-F. Only a close outside an interval is ignored = a post-deletion
 * transition).
 */
function accessWindows(
  transitions: readonly ScopeTransition[],
  environmentId: string,
): readonly SeqInterval[] {
  const windows: SeqInterval[] = [];
  // Window-derivation state: whether inside a membership / grant interval, and
  // from which seq E's window is open
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

/**
 * Map Q1's membership-interval events (genesis / member_added / role_changed /
 * member_removed) onto scope transitions. genesis is structurally `all`
 * (CRYPTO_SPEC §6.2). A row whose scope cannot be read (a corrupt payload)
 * fails safe and opens the window as `all` (for detection, the safe side is
 * not missing — design record §9 K3-F).
 */
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

/**
 * Map Q6's grant-interval events (server_granted / server_revoked) onto scope
 * transitions. A re-grant to the same key FP is an update inside the interval;
 * a re-grant after revocation is an open of a new interval. Inside an
 * interval, the scope accumulates **monotonically as a union** (the consensus
 * rules only accept enlargement — CRYPTO_SPEC §6.3. Even if a shrinking
 * re-grant slipped through, never close the disclosure window of a DEK the
 * server already knows before revocation = a fail-safe that also blocks a
 * "cosmetic shrink" on the detection side).
 */
function grantTransitions(
  events: readonly {
    readonly seq: number;
    readonly event: string;
    readonly scopeEnvironmentIds: readonly string[] | null;
  }[],
): readonly ScopeTransition[] {
  const transitions: ScopeTransition[] = [];
  // The disclosed set inside the interval. null = outside an interval. "all" =
  // an interval containing a grant row whose scope is unreadable (fail-safe to
  // all environments — the same handling as an unknown scope on the member
  // axis. K3-F)
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

/** Reconstruction of variable existence intervals (Q2; variable_id is never reused — AUTH_SPEC §12-1). */
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

/** Lazily derive and memoize windows per environment (candidates are judged per variable; windows are per environment). */
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

/**
 * The exposure bound of a flag (§4.1-5 — 2026-09-27 VH): the environment's
 * epoch at the end of the subject's last window on it — the newest epoch
 * whose DEK the subject could hold (all-epoch backfill gives every epoch up
 * to it). A window that closed before the trigger (an earlier shrink, a
 * device scope) bounds at that earlier epoch, not the current one. An
 * environment with no epoch row is unbounded (+Infinity — the safe side: the
 * flag then resolves only by dismissal).
 */
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

/** Assemble one rotation.recommended row (the §3.3 recording rules — actor is system). */
function recommendedEvent(input: {
  readonly nowMs: number;
  readonly lifetime: VariableLifetime;
  readonly basis: RotationBasis;
  readonly trigger: RotationTrigger;
  readonly triggerChainSeq: number;
  readonly targetUserId?: UserId;
  readonly targetKeyFingerprintHex?: KeyFingerprintHex;
  /** Only on the revoke_device variant: the revoked FP set (AUDIT_SPEC §4.1 — copied to the payload). */
  readonly revokedDeviceKeyFingerprints?: readonly KeyFingerprintHex[];
  /** The exposure bound (§4.1-5 — VH): written to the epoch column when known. */
  readonly epochBound: number;
}): RecommendedEvent {
  return {
    event: "rotation.recommended",
    serverTs: input.nowMs,
    actorType: "system",
    ...(Number.isFinite(input.epochBound) ? { epoch: input.epochBound } : {}),
    ...(input.targetUserId === undefined ? {} : { targetUserId: input.targetUserId }),
    ...(input.targetKeyFingerprintHex === undefined
      ? {}
      : { targetKeyFingerprintHex: input.targetKeyFingerprintHex }),
    environmentId: input.lifetime.environmentId,
    variableId: input.lifetime.variableId,
    payload: {
      basis: input.basis,
      triggerChainSeq: input.triggerChainSeq,
      trigger: input.trigger,
      ...(input.revokedDeviceKeyFingerprints === undefined
        ? {}
        : { revokedDeviceKeyFingerprints: input.revokedDeviceKeyFingerprints }),
    },
  };
}

/**
 * The shared skeleton of the member variants (remove_member / change_role):
 * candidates = every (variable × environment) whose existence interval
 * overlaps a subject window (including deleted variables — an upstream
 * credential does not expire just because the variable is deleted), and (a) =
 * the subject's var.read inside a subject window (including reads via API
 * token — matched by actor.user_id; a read is itself an event, so judge
 * strictly inside the interval). `selectWindows` decides per variant "which
 * windows are detection targets" (remove = all windows, change_role = windows
 * closed by the trigger).
 */
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
  // Reads are only counted "inside one of the selected windows" (within —
  // open interval), so rows outside the envelope of all windows (smallest
  // start, largest end) are always dropped by the filter below. Pass the
  // envelope to Q3 to make it a range scan over ae_actor (the result is
  // identical to not narrowing)
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
  return candidates.map((lifetime) =>
    recommendedEvent({
      nowMs: input.nowMs,
      lifetime,
      basis: readPairs.has(pairKey(lifetime)) ? "read" : "readable",
      trigger: input.trigger,
      triggerChainSeq: input.triggerChainSeq,
      targetUserId: input.targetUserId,
      epochBound: exposureBound(
        epochRows,
        lifetime.environmentId,
        selected.get(lifetime.environmentId) ?? [],
      ),
      ...(input.revokedDeviceKeyFingerprints === undefined
        ? {}
        : { revokedDeviceKeyFingerprints: input.revokedDeviceKeyFingerprints }),
    }),
  );
}

/**
 * Detection at `remove_member` acceptance (§4.1 steps 1-3). Called after the
 * mirror append (the membership interval is closed by the mirror row written
 * just before). Candidates are **all windows** inside the membership interval
 * (including windows previously closed by a shrink — per the letter of §4.1
 * step 2. Rows overlapping what the shrink-time detection emitted remain as
 * multiple effective recommendeds for the same pair = same treatment as a
 * re-delete). Feeding the return value to appendManySync as-is performs step
 * 4.
 */
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

/** Whether a role is member-or-higher (a writer) — used to judge demotion (down to below member). */
const WRITER_ROLES: ReadonlySet<string> = new Set(["member", "admin", "owner"]);

/**
 * Detection at `change_role` acceptance (the §4.1 change_role variant —
 * 2026-09-14 ES). Called after the mirror append (the `chain.role_changed`
 * row written just before is the tail of Q1).
 * - **Shrink** (old scope \ new scope ≠ ∅): environments of windows closed by
 *   the trigger's mirror row are candidates (CRYPTO_SPEC §7 — the shrunk part
 *   is equivalent to a removal)
 * - **Demotion** (old role ≥ member, new role = reader): all windows open just
 *   before the trigger (= all environments of the old scope). The windows
 *   themselves do not close because environments remaining in the new scope
 *   keep receiving DEKs as a reader, but detection runs on windows clipped at
 *   the trigger seq — detection of the fact "someone who knew upstream
 *   credentials lost the privilege" (§4.1). If a shrink happened at the same
 *   time, the union still yields one row per (variable × environment) (the
 *   §3.3 granularity)
 * - Promotion, enlargement, and scope-unchanged role changes (not demotions)
 *   produce no candidates
 */
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
  // A row whose role cannot be read (corrupt payload — unreachable) is judged
  // as "was a demotion" (the not-missing side — design record §9 K3-F):
  // unknown old role = was a writer; unknown new role = no longer a writer
  const demoted =
    (previousRole === null || WRITER_ROLES.has(previousRole)) &&
    (trigger.role === null || !WRITER_ROLES.has(trigger.role));
  // If the trigger row's scope cannot be read, the window derivation falls to
  // all and the "shrunk part" cannot be detected (windows never close), so use
  // every window open just before the trigger as candidates, same as demotion
  // (the not-missing side)
  const closeAll = demoted || trigger.scope === null;
  return detectForMember({
    ...input,
    trigger: "change_role",
    transitions: membershipTransitions(events),
    selectWindows: (windows) =>
      windows.flatMap((window) => {
        // A window closed by the trigger's mirror row = the shrunk part
        if (window.end === trigger.seq) {
          return [window];
        }
        // Demotion: clip a window still open at the trigger (environments
        // remaining in the new scope) at the trigger seq (the transition list
        // ends at the trigger row, so a window continuing past the trigger =
        // an unclosed window)
        if (closeAll && window.start < trigger.seq && window.end > trigger.seq) {
          return [{ start: window.start, end: trigger.seq }];
        }
        return [];
      }),
  });
}

/** Intersection of two intervals (null when empty). */
function intersect(a: SeqInterval, b: SeqInterval): SeqInterval | null {
  const start = Math.max(a.start, b.start);
  const end = Math.min(a.end, b.end);
  return start < end ? { start, end } : null;
}

/**
 * The live interval and device scope of a revoked device (the §4.1
 * revoke_device variant — step 1; design record dk-design.md §8 K3-11): from
 * the latest `chain.device_added` before the trigger (matching FP in the
 * payload) to the trigger. A FP absent from every device_added is the first
 * key of an `add_member` / `genesis`, whose interval runs from the start of
 * the membership interval (the latest open transition before the trigger),
 * with scope all (a first key's cap is structurally (owner, all) — CRYPTO_SPEC
 * §6.2). A row whose scope cannot be read is all (the not-missing side —
 * ES K3-F).
 */
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

/**
 * Detection at `revoke_device` acceptance (the §4.1 revoke_device variant —
 * 2026-09-19 DK). Called after the mirror append (the `chain.device_revoked`
 * row written just before is the trigger). Candidates = each revoked device's
 * live interval ∩ the person's per-environment access windows ∩ the device
 * scope (a device whose device scope does not contain E has no window =
 * revoking a vote-only device [empty scope] writes no row). (a) is, same as
 * the remove variant, a match of the subject's `var.read` inside the interval
 * by actor.user_id (`var.read` carries no FP — K1-12). The subject stays a
 * member, so the membership interval does not close (detect on windows
 * clipped at the trigger seq — same shape as the demotion variant).
 */
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

/**
 * Detection at `revoke_server` acceptance (the §4.1 revoke_server variant).
 * The interval = the grant intervals of the given server key FP (each
 * interval separately if re-granted); candidates = the variables of
 * environments inside each interval's **per-environment disclosure windows**
 * (an environment that entered later via an enlarging re-grant counts from the
 * enlargement seq — the same window derivation as member); (a) =
 * `server.lease_issued` (every variable active in the environment at issuance
 * — environment-granularity distribution) + `server.value_decrypted`
 * (reserved).
 */
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
  const results: RecommendedEvent[] = [];
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
        // Environment-granularity distribution (§3.5): every variable active
        // at issuance counts as (a)
        return lifetime.start < row.seq && row.seq < lifetime.end;
      }
      // server.value_decrypted (reserved — never occurs in v1): variable-granularity matching
      return row.variableId === lifetime.variableId;
    });
    results.push(
      recommendedEvent({
        nowMs: input.nowMs,
        lifetime,
        basis: fetched ? "read" : "readable",
        trigger: "revoke_server",
        triggerChainSeq: input.triggerChainSeq,
        targetKeyFingerprintHex: input.serverKeyFingerprintHex,
        epochBound: exposureBound(
          epochRows,
          lifetime.environmentId,
          windowsOf(lifetime.environmentId),
        ),
      }),
    );
  }
  return results;
}

/** Read payload.trigger (rows written by this server itself — check the type defensively). */
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
  // This server is the only writer, so trigger is always present — a missing
  // or unknown row is corruption (defect)
  throw new Error(`rotation.recommended row has no valid trigger: ${String(trigger)}`);
}

/** Read the detection-time values from a recommended row's payload (rows written by this server itself — check the type defensively). */
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

/**
 * The plaintext origin epoch of a pushed version (§4.1-5 — 2026-09-27 VH):
 * the epoch its value was first encrypted under — the version's own epoch,
 * or, when the push declared `sameValueAs` (the writer's lineage
 * declaration, AUTH_SPEC §12-5), the origin epoch of the version it names (a
 * re-encryption carries an old plaintext into a new epoch; the old epoch's
 * key holders could still read it). A named version with no row falls to 0
 * (the oldest possible origin = the safe side: flags stay effective). The
 * acceptance check keeps sameValueAs below the pushed version, so a named
 * version was always pushed earlier in the same pair.
 */
function originEpochOf(row: RotationFlagSourceRow, origins: ReadonlyMap<number, number>): number {
  const sameValueAs = row.payload?.["sameValueAs"];
  if (typeof sameValueAs === "number" && Number.isInteger(sameValueAs) && sameValueAs >= 1) {
    return origins.get(sameValueAs) ?? 0;
  }
  return row.epoch ?? 0;
}

interface FlagState {
  readonly flag: EffectiveRotationFlag;
  /**
   * The exposure bound: the environment's current epoch when the flag was
   * detected (the recommended row's epoch column). The subject held the DEKs
   * of every epoch up to it, so a value whose origin epoch is at or below it
   * is one the subject could read. A row without it (corruption) never
   * resolves by a push — the safe side.
   */
  readonly epochBound: number;
  dismissed: boolean;
  resolved: boolean;
  reopenedByVersion: number | undefined;
}

interface PairState {
  readonly flags: FlagState[];
  /** version → plaintext origin epoch. */
  readonly origins: Map<number, number>;
  /** The live (latest pushed) value's origin epoch — null while no version was pushed. */
  liveOrigin: number | null;
}

/**
 * One var.version_pushed in the lineage fold: record the version's origin
 * epoch and move each non-dismissed flag between resolved and effective. A
 * transition from resolved to effective is a re-exposure (a restore of a
 * value the subject could read).
 */
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

/**
 * The lineage fold shared by the flag view and the history's per-version
 * count: one pass over the rows in seq order, grouped by (variable ×
 * environment).
 */
function foldPairs(rows: readonly RotationFlagSourceRow[]): Map<string, PairState> {
  const pairs = new Map<string, PairState>();
  for (const row of rows) {
    const key = pairKey(row);
    const pair: PairState = pairs.get(key) ?? { flags: [], origins: new Map(), liveOrigin: null };
    pairs.set(key, pair);
    if (row.event === "rotation.recommended") {
      // A new flag starts effective unless the live value was already first
      // encrypted above its bound (a window that closed earlier — an old
      // shrink — whose environment was rotated and re-pushed since)
      const epochBound = row.epoch ?? Number.POSITIVE_INFINITY;
      pair.flags.push({
        flag: flagOf(row),
        epochBound,
        dismissed: false,
        resolved: pair.liveOrigin !== null && pair.liveOrigin > epochBound,
        reopenedByVersion: undefined,
      });
    } else if (row.event === "rotation.dismissed") {
      // A dismissal covers only the flags effective at that point — what
      // the dismissing admin saw and accepted. A flag resolved at the time
      // stays resolved and can still be re-opened by a later restore
      // (§4.1-5 — 2026-09-27 VH re-check round)
      for (const flag of pair.flags) {
        flag.dismissed ||= !flag.resolved;
      }
    } else {
      applyPush(pair, row);
    }
  }
  return pairs;
}

/**
 * Derivation of flag resolution (§4.1 step 5 — the lineage derivation,
 * 2026-09-27 VH): a flag is effective while it is not dismissed and the live
 * value's plaintext origin predates it. Multiple effective recommendeds on
 * the same pair (a re-delete, departures of different subjects) are all
 * returned (the UI bundles them).
 */
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

/**
 * The history's `flagsIfCurrent` (AUTH_SPEC §12-7 — 2026-09-27 VH): for each
 * listed version of one pair, the number of non-dismissed flags that are
 * effective while that version's value is the live one (= flags whose
 * exposure bound is at or above the version's origin epoch). `rows` are the
 * pair's own rows in seq order. A version with no push row falls to origin 0
 * — the same safe side as {@link originEpochOf} (every non-dismissed flag
 * counts).
 */
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
