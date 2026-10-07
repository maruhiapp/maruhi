// The shared implementation of sweeping rotation mandates (CRYPTO_SPEC
// §7).
//
// revoke_server (server-revoke) and remove_member / demotion below
// member / scope narrowing (member remove / change-role) all share the
// same interruption-recovery structure: "of the mandate's environment
// set, an environment whose current epoch has not begun after the
// on-chain baseline seq gets a forced rotation; the rest get a
// verification pass (resuming an unfinished re-encryption or confirming
// completion)". No progress file is kept — the targets are decided from
// chain-derived state alone (resuming from another device or member
// just works — the sharing of server-revoke's discipline).
//
// **The mandate's environment set (2026-09-15 ES K4 — design record
// K4-J)**: remove = the target's current scope (just before removal),
// demotion = the target's new scope, narrowing = old scope \ new scope,
// revoke_server = all environments (invariant — design record §6),
// device revocation (2026-09-19 DK — design record dk-design.md §9
// K4-8) = the union of each revoked device's **effective scope** (person
// ∩ device, at seq−1 just before revocation). `all` is concretized to
// the environment set that existed at the mandate's seq (a target cannot
// hold a DEK for an environment created later). When one target carries
// several mandates (a narrowing followed by a remove), take the maximum
// baseline seq per environment.
//
// Excluding a deleted environment is grounded only in its
// **delete_environment entry on the verified chain** (never silently
// skipped on the server's 404 claim alone — §7; CRYPTO_SPEC §6.2).

import {
  ALL_SCOPE,
  type ChainMember,
  type MemberScope,
  memberScopeOf,
  type ProposableOperation,
  type RevokeDevicePayload,
  scopeIncludesEnvironment,
} from "@maruhi/crypto";
import { Effect } from "effect";

import type { AppliedOperation } from "./chain-applied.ts";
import type { VerifiedProject } from "./chain-sync.ts";
import { ROLE_RANK } from "./dek-wrap.ts";
import { chainDeletedEnvironments } from "./deks.ts";
import { displayText } from "./display.ts";
import type { RotationSummary } from "./env-rotate.ts";
import type { CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import { logWarning } from "./notice.ts";
import { compareCodePoints, environmentsOfScopeAt, scopeChangeAt } from "./scope.ts";

/** The injected rotation's mode: force = a new epoch is mandatory / verify = resume-or-confirm only. */
export type SweepRotateMode = "force" | "verify";

/** Injection of one environment's rotation (cli.ts passes envRotateOp wrapped with a floor). */
export type SweepRotate<R> = (
  environmentId: string,
  mode: SweepRotateMode,
) => Effect.Effect<RotationSummary, CliError, R>;

/** The all-environment sweep's result (the reporting material shared by revoke / remove / demotion / narrowing). */
export interface SweepOutcome {
  /** Environments where a rotation (forced or resumed) ran (environment ID → result). */
  readonly rotated: readonly {
    readonly environmentId: string;
    readonly summary: RotationSummary;
    /** Whether the run demanded a new epoch (true = forced / false = a verification-pass resumption). */
    readonly forcedNewEpoch: boolean;
  }[];
  /** Environments whose rotation failed (§7 — never silently skipped). */
  readonly failed: readonly { readonly environmentId: string; readonly message: string }[];
  /** Environments **confirmed** to have an epoch after the baseline and no unfinished re-encryption. */
  readonly alreadyRotated: readonly string[];
}

/** Environment → the mandate's baseline seq (the maximum when several mandates apply). */
export type EnvironmentBaselines = ReadonlyMap<string, number>;

/**
 * Folds a mandate list into "environment → baseline seq" (the shared
 * input of the sweep and the unconverged judgment). Several mandates on
 * the same environment take the maximum seq (if it rotated after the
 * last mandate, every earlier mandate closes with it — epochs are
 * per-environment).
 */
export function baselinesOf(mandates: readonly RotationMandate[]): EnvironmentBaselines {
  const baselines = new Map<string, number>();
  for (const mandate of mandates) {
    for (const environmentId of mandate.environmentIds) {
      const current = baselines.get(environmentId);
      if (current === undefined || current < mandate.seq) {
        baselines.set(environmentId, mandate.seq);
      }
    }
  }
  return baselines;
}

/** The sweep's targets and carry-overs (split by the actor's fulfillment range — shared by the member family and device revocation). */
export interface SweepPartition {
  /** Mandate environments the actor can fulfill → baseline seq. */
  readonly baselines: EnvironmentBaselines;
  /** Mandate environments outside the actor's (effective) scope that are undeleted and unconverged (noted — left to other fulfillers). */
  readonly outOfScope: readonly string[];
  /** Of the targets, environments skipped as verified-deleted. */
  readonly skippedDeleted: readonly string[];
}

/**
 * Splits the mandate's environment set by "the range the actor can
 * fulfill" (CRYPTO_SPEC §7 — even the executor cannot rotate outside
 * their scope. Independent review S2 / S7): the note is limited to
 * "outside scope ∧ undeleted ∧ unconverged" (the same judgment as the
 * standing warning). `actorScope` is the signing device's effective
 * scope (DK K4-17).
 */
export function partitionSweepBaselines(input: {
  readonly verified: VerifiedProject;
  readonly all: EnvironmentBaselines;
  readonly actorScope: MemberScope;
  readonly deletedVerified: ReadonlySet<string>;
}): SweepPartition {
  const inScope = (environmentId: string) =>
    scopeIncludesEnvironment(input.actorScope, environmentId);
  const outOfScope = [...input.all]
    .filter(
      ([environmentId, baselineSeq]) =>
        !inScope(environmentId) &&
        !input.deletedVerified.has(environmentId) &&
        isPendingAt(input.verified, environmentId, baselineSeq),
    )
    .map(([environmentId]) => environmentId)
    .toSorted(compareCodePoints);
  const baselines = new Map([...input.all].filter(([environmentId]) => inScope(environmentId)));
  const skippedDeleted = [...baselines.keys()]
    .filter((environmentId) => input.deletedVerified.has(environmentId))
    .toSorted(compareCodePoints);
  return { baselines, outOfScope, skippedDeleted };
}

/**
 * Whether environment E is unconverged against a baseline seq: E's
 * current epoch's start seq being before the baseline = E's current DEK
 * was still distributed before the baseline event (revocation / removal
 * / demotion / narrowing). An environment whose start seq cannot be
 * derived is fail-closed into unconverged (never shaped so an
 * environment silently leaves the target set).
 */
function isPendingAt(
  verified: VerifiedProject,
  environmentId: string,
  baselineSeq: number,
): boolean {
  const environment = verified.state.environments.get(environmentId);
  if (environment === undefined) {
    return true;
  }
  const startSeq = environment.epochStartSeqs.get(environment.currentEpoch);
  return startSeq === undefined || startSeq < baselineSeq;
}

// ---------------------------------------------------------------------------
// The generalized derivation of rotation mandates (§7's kinds) and the
// standing warning for unconverged ones (the B2 ruling — "a
// verify-only warning nobody sees is not detection". The same
// discipline as §9's standing disclosure)
// ---------------------------------------------------------------------------

/** §7's rotation mandate kinds (all 5 — `device-revoked` added in DK K4). */
export type RotationMandateKind =
  | "member-removed"
  | "role-demoted"
  | "scope-narrowed"
  | "server-revoked"
  | "device-revoked";

/** A §7 rotation mandate entry (all 5 kinds — `scope-narrowed` added in 2026-09-15 ES K4, `device-revoked` in DK K4). */
export interface RotationMandate {
  readonly kind: RotationMandateKind;
  /** The member family / device-revoked = the target user_id / server-revoked = the server key FP. */
  readonly target: string;
  readonly seq: number;
  /**
   * The mandate's environment set (CRYPTO_SPEC §7 — concretized to the
   * chain-derived environment set at seq. Ascending). remove = the
   * target's current scope, demotion = the target's new scope, narrowing
   * = old \ new, revoke = all environments, device-revoked = the union of
   * the revoked devices' effective scopes (K4-8).
   */
  readonly environmentIds: readonly string[];
  /** `device-revoked` only: the revoked devices' FPs (ascending — for display and re-registration checks). */
  readonly deviceFingerprintsHex?: readonly string[];
}

/**
 * Every rotation mandate entry on the chain (§7): `remove_member`
 * (always), a `change_role` demoting below member (judged by whether
 * the role just before was member or above — via the verified history's
 * memberStateAt), a `change_role` narrowing the scope (old \ new ≠ ∅),
 * and `revoke_server` (always). member.ts's target-scope judgment and
 * the unconverged warning (below) share this single derivation
 * (structurally preventing the judgments from drifting). A simultaneous
 * demotion and narrowing produce two mandates (same seq).
 *
 * The input is the **applied operation list** (design record K6-C): an
 * op applied via a proposal rides at the seq of the `approve` that
 * reached quorum (ruling P7 — a mandate's origin = the moment of
 * application).
 */
export function rotationMandates(verified: VerifiedProject): readonly RotationMandate[] {
  return verified.applied.flatMap((applied) => mandatesOfApplied(verified, applied));
}

/** The mandates one applied operation produces (0–2 — a simultaneous demotion and narrowing make 2). */
function mandatesOfApplied(
  verified: VerifiedProject,
  applied: AppliedOperation,
): readonly RotationMandate[] {
  const { seq, operation } = applied;
  if (operation.op === "remove_member") {
    const before = verified.history.memberStateAt(operation.payload.targetUserId, seq - 1);
    // If the state just before cannot be derived, fail-closed to all environments (never silently narrowed)
    const scope: MemberScope = before?.scope ?? ALL_SCOPE;
    return [
      {
        kind: "member-removed",
        target: operation.payload.targetUserId,
        seq,
        environmentIds: environmentsOfScopeAt(verified, scope, seq),
      },
    ];
  }
  if (operation.op === "revoke_server") {
    return [
      {
        kind: "server-revoked",
        target: operation.payload.serverKeyFingerprintHex,
        seq,
        environmentIds: environmentsOfScopeAt(verified, ALL_SCOPE, seq),
      },
    ];
  }
  if (operation.op === "revoke_device") {
    return [revokeDeviceMandate(verified, seq, operation.payload)];
  }
  return operation.op === "change_role" ? changeRoleMandates(verified, seq, operation) : [];
}

/**
 * A device revocation's mandate (CRYPTO_SPEC §7 "revoking a device" —
 * design record K4-8): each revoked device's **effective scope** (the
 * person's scope ∩ the device's scope — `deviceStateAt` at seq−1 just
 * before revocation) is concretized to the environment set at seq, and
 * their union is taken. A device that cannot be derived (a FP absent
 * from history) fails closed to all environments (never silently
 * narrowed — the same discipline as the remove branch). Revoking a
 * device whose scope is empty (a votes-only device) yields the empty
 * set = carries no mandate (the canonical text's literal reading).
 */
function revokeDeviceMandate(
  verified: VerifiedProject,
  seq: number,
  payload: RevokeDevicePayload,
): RotationMandate {
  const environmentIds = new Set<string>();
  for (const fingerprintHex of payload.deviceFingerprintsHex) {
    const before = verified.history.deviceStateAt(payload.targetUserId, fingerprintHex, seq - 1);
    const scope: MemberScope = before?.permission.scope ?? ALL_SCOPE;
    for (const environmentId of environmentsOfScopeAt(verified, scope, seq)) {
      environmentIds.add(environmentId);
    }
  }
  return {
    kind: "device-revoked",
    target: payload.targetUserId,
    seq,
    environmentIds: [...environmentIds].toSorted(compareCodePoints),
    deviceFingerprintsHex: [...payload.deviceFingerprintsHex].toSorted(compareCodePoints),
  };
}

/** change_role's mandates: demotion (all environments of the new scope) and narrowing (old \ new) — two when simultaneous. */
function changeRoleMandates(
  verified: VerifiedProject,
  seq: number,
  entry: Extract<ProposableOperation, { readonly op: "change_role" }>,
): readonly RotationMandate[] {
  const before = verified.history.memberStateAt(entry.payload.targetUserId, seq - 1);
  // If the state just before cannot be derived, fail closed (the same
  // discipline as the remove branch — noted by pullfrog): fall to the
  // "was a writer, held every environment" side rather than dropping the
  // mandate
  const beforeScope: MemberScope = before?.scope ?? ALL_SCOPE;
  const wasWriter = before === undefined || ROLE_RANK[before.role] >= ROLE_RANK.member;
  const after = memberScopeOf(entry.payload);
  const mandates: RotationMandate[] = [];
  if (ROLE_RANK[entry.payload.newRole] < ROLE_RANK.member && wasWriter) {
    mandates.push({
      kind: "role-demoted",
      target: entry.payload.targetUserId,
      seq,
      environmentIds: environmentsOfScopeAt(verified, after, seq),
    });
  }
  const { narrowed } = scopeChangeAt(verified, beforeScope, after, seq);
  if (narrowed.length > 0) {
    mandates.push({
      kind: "scope-narrowed",
      target: entry.payload.targetUserId,
      seq,
      environmentIds: narrowed,
    });
  }
  return mandates;
}

/** An unconverged mandate (environments remain whose current epoch has not begun after the mandate entry). */
export interface UnconvergedMandate extends RotationMandate {
  readonly pendingEnvironmentIds: readonly string[];
}

/**
 * Deriving unconverged rotation mandates (chain-derived only).
 * Environment E is unconverged for mandate M = E ∈ M's environment set
 * (the environments inside the scope that existed at M) and E's current
 * epoch's start seq is before M (= no rotation since M). An environment
 * whose start seq cannot be derived is fail-closed into unconverged.
 * Verified-deleted environments are excluded. Note that "the epoch
 * advanced but the re-encryption is unfinished" is a remainder invisible
 * from the chain — detecting it is the job of each mandate command's
 * re-run (the sweep's verification pass).
 */
function unconvergedMandates(
  verified: VerifiedProject,
  deletedVerified: ReadonlySet<string>,
): readonly UnconvergedMandate[] {
  const results: UnconvergedMandate[] = [];
  for (const mandate of rotationMandates(verified)) {
    const pending = mandate.environmentIds.filter(
      (environmentId) =>
        !deletedVerified.has(environmentId) && isPendingAt(verified, environmentId, mandate.seq),
    );
    if (pending.length > 0) {
      results.push({ ...mandate, pendingEnvironmentIds: pending });
    }
  }
  return results;
}

/**
 * The guidance for a mandate that was rolled back (the target has been
 * re-added / re-promoted / re-widened / re-granted). Guiding toward a
 * re-run of the mandate command would **re-apply the original
 * destructive operation to a now-active target**, so make explicit that
 * what is owed is only the rotation and steer toward the non-destructive
 * env rotate. The mandate itself survives (the remainder of a
 * remove/demotion is the epoch anchors' soundness — §7 — and the
 * target's return does not erase it).
 */
function reversedAdvice(state: string): string {
  return `${state} — do not re-run the operation against the target; rotating the affected environment individually with \`maruhi env rotate <environment> --new-epoch --reason <text>\` converges the mandate`;
}

/**
 * Per-kind guidance for the converging command (an actionable warning —
 * the B2 ruling). Looks at the target's current state; when it was
 * rolled back (re-added / re-promoted / re-widened / re-granted), never
 * guide toward re-running the destructive operation.
 */
function mandateAdvice(verified: VerifiedProject, mandate: UnconvergedMandate): string {
  switch (mandate.kind) {
    case "member-removed":
      return verified.state.members.has(mandate.target)
        ? reversedAdvice("the target has been re-added")
        : `re-running \`maruhi member remove ${displayText(mandate.target)}\` converges the mandate`;
    case "role-demoted":
      return demotionAdvice(verified.state.members.get(mandate.target), mandate);
    case "scope-narrowed":
      return narrowingAdvice(verified, verified.state.members.get(mandate.target), mandate);
    case "server-revoked":
      return verified.state.serverGrants.has(mandate.target)
        ? reversedAdvice("the target server key has been re-granted")
        : "re-running `maruhi server revoke` converges the mandate";
    case "device-revoked":
      return deviceRevocationAdvice(verified.state.members.get(mandate.target), mandate);
  }
}

/**
 * The guidance for a device-revocation mandate (K4-8 turn 2): since a
 * revocation is not an operation that can be re-run, always steer toward
 * the non-destructive env rotate. If a revoked device has been
 * re-registered, say so distinctly.
 */
function deviceRevocationAdvice(
  member: ChainMember | undefined,
  mandate: UnconvergedMandate,
): string {
  const readded = (mandate.deviceFingerprintsHex ?? []).filter(
    (fingerprintHex) => member?.devices.has(fingerprintHex) === true,
  );
  if (readded.length > 0) {
    return reversedAdvice(`the revoked device ${readded.join(", ")} has been re-added`);
  }
  return `the device revocation itself is complete (revoked: ${(mandate.deviceFingerprintsHex ?? []).join(", ")}); rotating each listed environment with \`maruhi env rotate <environment> --new-epoch --reason <text>\` converges the mandate (any device of a member whose effective scope covers the environment can run it)`;
}

function demotionAdvice(member: ChainMember | undefined, mandate: UnconvergedMandate): string {
  if (member === undefined) {
    // change-role cannot be re-run against a target deleted after the demotion (current members only)
    return reversedAdvice("the target has been removed");
  }
  if (ROLE_RANK[member.role] >= ROLE_RANK.member) {
    return reversedAdvice("the target has been re-promoted to member or above");
  }
  return `re-running \`maruhi member change-role ${displayText(mandate.target)} --role ${member.role}\` converges the mandate`;
}

function narrowingAdvice(
  verified: VerifiedProject,
  member: ChainMember | undefined,
  mandate: UnconvergedMandate,
): string {
  if (member === undefined) {
    return reversedAdvice("the target has been removed");
  }
  const current = new Set(environmentsOfScopeAt(verified, member.scope, verified.state.headSeq));
  if (mandate.pendingEnvironmentIds.some((environmentId) => current.has(environmentId))) {
    return reversedAdvice("the target's scope has been widened again");
  }
  return `re-running \`maruhi member change-role ${displayText(mandate.target)}\` with the target's current scope (\`--env …\`) converges the mandate`;
}

/**
 * Resolving unconverged mandates — chain-derived only, so no request is
 * made (deleted environments come from the verified chain's
 * delete_environment entries — CRYPTO_SPEC §6.2). Shared by the standing
 * warning (warnUnconvergedMandates) and project verify's detail display.
 */
export function resolveUnconvergedMandates(input: {
  readonly verified: VerifiedProject;
}): readonly UnconvergedMandate[] {
  return unconvergedMandates(input.verified, chainDeletedEnvironments(input.verified));
}

/** One mandate's warning line (shared by the standing warning and project verify's detail display). */
export function describeUnconvergedMandate(
  verified: VerifiedProject,
  mandate: UnconvergedMandate,
): string {
  return `${mandate.kind} (target=${displayText(mandate.target)}, seq=${mandate.seq}): environments ${mandate.pendingEnvironmentIds.map(displayText).join(", ")} — ${mandateAdvice(verified, mandate)}`;
}

/**
 * The standing warning for unconverged rotation mandates (the B2
 * ruling). Called after every command's chain sync (converging commands
 * — member remove / change-role / server revoke / env rotate — do not
 * call it, since their own sweep report carries it). Chain-derived only
 * (no request).
 */
export const warnUnconvergedMandates = Effect.fn("rotation-sweep.warnUnconvergedMandates")(
  function* (input: { readonly verified: VerifiedProject }): Effect.fn.Return<void, never, CliIo> {
    const filtered = resolveUnconvergedMandates(input);
    if (filtered.length === 0) {
      return;
    }
    const io = yield* CliIo;
    yield* logWarning(
      "there are unconverged rotation mandates (CRYPTO_SPEC §7) — holders of the old DEKs may still be able to read current values:",
    );
    for (const mandate of filtered) {
      yield* io.logError(`  ${describeUnconvergedMandate(input.verified, mandate)}`);
    }
  },
);

/** Turning one environment's rotation into a result (failures are collected, not thrown — for §7's all-environment sweep). */
function rotateOutcome<R>(
  rotate: SweepRotate<R>,
  environmentId: string,
  mode: SweepRotateMode,
): Effect.Effect<
  | { readonly kind: "ok"; readonly summary: RotationSummary }
  | { readonly kind: "failed"; readonly message: string },
  never,
  R
> {
  return rotate(environmentId, mode).pipe(
    Effect.map((summary) => ({ kind: "ok", summary }) as const),
    Effect.catch((error) => Effect.succeed({ kind: "failed", message: error.message } as const)),
  );
}

/**
 * The sweep of §7's mandate environments: an environment whose current
 * epoch began before the baseline gets a forced rotation; the rest get
 * the verification pass (resuming an unfinished re-encryption or
 * confirming completion). One environment's failure never stops the
 * rest (failures are collected and reported; a re-run resumes where it
 * left off). Targets are limited to `baselines` (the mandate's
 * environment set → baseline seq. baselinesOf) — an environment outside
 * the scope is never included among rotate's targets (CRYPTO_SPEC §7).
 */
export const sweepRotations = Effect.fn("rotation-sweep.sweepRotations")(function* <R>(input: {
  readonly rotate: SweepRotate<R>;
  readonly verified: VerifiedProject;
  /** The mandate's environment set → baseline seq (revoke / remove / demotion / narrowing). */
  readonly baselines: EnvironmentBaselines;
  readonly deletedVerified: ReadonlySet<string>;
}): Effect.fn.Return<SweepOutcome, never, R> {
  const candidates = [...input.baselines.keys()]
    .filter((environmentId) => !input.deletedVerified.has(environmentId))
    .toSorted(compareCodePoints);
  const isPending = (environmentId: string) =>
    isPendingAt(input.verified, environmentId, input.baselines.get(environmentId) ?? 0);
  const rotated: {
    readonly environmentId: string;
    readonly summary: RotationSummary;
    readonly forcedNewEpoch: boolean;
  }[] = [];
  const failed: { readonly environmentId: string; readonly message: string }[] = [];
  const alreadyRotated: string[] = [];
  for (const environmentId of candidates.filter(isPending)) {
    const result = yield* rotateOutcome(input.rotate, environmentId, "force");
    if (result.kind === "ok") {
      rotated.push({ environmentId, summary: result.summary, forcedNewEpoch: true });
    } else {
      failed.push({ environmentId, message: result.message });
    }
  }
  // The epoch began after the baseline, but whether that round's
  // **re-encryption completed** is not knowable from the chain (§12-7's
  // transitional state). Confirm it via the verification pass
  for (const environmentId of candidates.filter((id) => !isPending(id))) {
    const result = yield* rotateOutcome(input.rotate, environmentId, "verify");
    if (result.kind !== "ok") {
      failed.push({ environmentId, message: result.message });
    } else if (
      result.summary.mode === "up-to-date" &&
      result.summary.remaining === 0 &&
      result.summary.failure === null
    ) {
      alreadyRotated.push(environmentId);
    } else {
      // Resumed (or a partial completion remains) — the display and
      // exit code are derived from RotationSummary by the caller's
      // reportRotation
      rotated.push({ environmentId, summary: result.summary, forcedNewEpoch: false });
    }
  }
  return { rotated, failed, alreadyRotated: alreadyRotated.toSorted(compareCodePoints) };
});
