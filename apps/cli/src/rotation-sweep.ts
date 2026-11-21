import type { EnvironmentId, KeyFingerprintHex, UserId } from "@maruhi/core";
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
import type { RotationSummary } from "./env.package/index.ts";
import type { CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import { logWarning } from "./notice.ts";
import { compareCodePoints, environmentsOfScopeAt, scopeChangeAt } from "./scope.ts";

export type SweepRotateMode = "force" | "verify";

export type SweepRotate<R> = (
  environmentId: EnvironmentId,
  mode: SweepRotateMode,
) => Effect.Effect<RotationSummary, CliError, R>;

export interface SweepOutcome {
  readonly rotated: readonly {
    readonly environmentId: EnvironmentId;
    readonly summary: RotationSummary;
    readonly forcedNewEpoch: boolean;
  }[];
  readonly failed: readonly { readonly environmentId: EnvironmentId; readonly message: string }[];
  readonly alreadyRotated: readonly EnvironmentId[];
}

export type EnvironmentBaselines = ReadonlyMap<EnvironmentId, number>;

export function baselinesOf(mandates: readonly RotationMandate[]): EnvironmentBaselines {
  const baselines = new Map<EnvironmentId, number>();
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

export interface SweepPartition {
  readonly baselines: EnvironmentBaselines;
  readonly outOfScope: readonly EnvironmentId[];
  readonly skippedDeleted: readonly EnvironmentId[];
}

export function partitionSweepBaselines(input: {
  readonly verified: VerifiedProject;
  readonly all: EnvironmentBaselines;
  readonly actorScope: MemberScope;
  readonly deletedVerified: ReadonlySet<EnvironmentId>;
}): SweepPartition {
  const inScope = (environmentId: EnvironmentId) =>
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

function isPendingAt(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
  baselineSeq: number,
): boolean {
  const environment = verified.state.environments.get(environmentId);
  if (environment === undefined) {
    return true;
  }
  const startSeq = environment.epochStartSeqs.get(environment.currentEpoch);
  return startSeq === undefined || startSeq < baselineSeq;
}

export type RotationMandateKind =
  | "member-removed"
  | "role-demoted"
  | "scope-narrowed"
  | "server-revoked"
  | "device-revoked";

export type RotationMandate =
  | (RotationMandateFields & {
      readonly kind: Exclude<RotationMandateKind, "server-revoked">;
      readonly target: UserId;
    })
  | (RotationMandateFields & {
      readonly kind: "server-revoked";
      readonly target: KeyFingerprintHex;
    });

interface RotationMandateFields {
  readonly seq: number;
  readonly environmentIds: readonly EnvironmentId[];
  readonly deviceFingerprintsHex?: readonly string[];
}

export function rotationMandates(verified: VerifiedProject): readonly RotationMandate[] {
  return verified.applied.flatMap((applied) => mandatesOfApplied(verified, applied));
}

function mandatesOfApplied(
  verified: VerifiedProject,
  applied: AppliedOperation,
): readonly RotationMandate[] {
  const { seq, operation } = applied;
  if (operation.op === "remove_member") {
    const before = verified.history.memberStateAt(operation.payload.targetUserId, seq - 1);
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

function revokeDeviceMandate(
  verified: VerifiedProject,
  seq: number,
  payload: RevokeDevicePayload,
): RotationMandate {
  const environmentIds = new Set<EnvironmentId>();
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

function changeRoleMandates(
  verified: VerifiedProject,
  seq: number,
  entry: Extract<ProposableOperation, { readonly op: "change_role" }>,
): readonly RotationMandate[] {
  const before = verified.history.memberStateAt(entry.payload.targetUserId, seq - 1);
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

export type UnconvergedMandate = RotationMandate & {
  readonly pendingEnvironmentIds: readonly string[];
};

function unconvergedMandates(
  verified: VerifiedProject,
  deletedVerified: ReadonlySet<EnvironmentId>,
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

function reversedAdvice(state: string): string {
  return `${state} — do not re-run the operation against the target; rotating the affected environment individually with \`maruhi env rotate <environment> --new-epoch --reason <text>\` converges the mandate`;
}

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
  const current = new Set<string>(
    environmentsOfScopeAt(verified, member.scope, verified.state.headSeq),
  );
  if (mandate.pendingEnvironmentIds.some((environmentId) => current.has(environmentId))) {
    return reversedAdvice("the target's scope has been widened again");
  }
  return `re-running \`maruhi member change-role ${displayText(mandate.target)}\` with the target's current scope (\`--env …\`) converges the mandate`;
}

export function resolveUnconvergedMandates(input: {
  readonly verified: VerifiedProject;
}): readonly UnconvergedMandate[] {
  return unconvergedMandates(input.verified, chainDeletedEnvironments(input.verified));
}

export function describeUnconvergedMandate(
  verified: VerifiedProject,
  mandate: UnconvergedMandate,
): string {
  return `${mandate.kind} (target=${displayText(mandate.target)}, seq=${mandate.seq}): environments ${mandate.pendingEnvironmentIds.map(displayText).join(", ")} — ${mandateAdvice(verified, mandate)}`;
}

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

function rotateOutcome<R>(
  rotate: SweepRotate<R>,
  environmentId: EnvironmentId,
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

export const sweepRotations = Effect.fn("rotation-sweep.sweepRotations")(function* <R>(input: {
  readonly rotate: SweepRotate<R>;
  readonly verified: VerifiedProject;
  readonly baselines: EnvironmentBaselines;
  readonly deletedVerified: ReadonlySet<EnvironmentId>;
}): Effect.fn.Return<SweepOutcome, never, R> {
  const candidates = [...input.baselines.keys()]
    .filter((environmentId) => !input.deletedVerified.has(environmentId))
    .toSorted(compareCodePoints);
  const isPending = (environmentId: EnvironmentId) =>
    isPendingAt(input.verified, environmentId, input.baselines.get(environmentId) ?? 0);
  const rotated: {
    readonly environmentId: EnvironmentId;
    readonly summary: RotationSummary;
    readonly forcedNewEpoch: boolean;
  }[] = [];
  const failed: { readonly environmentId: EnvironmentId; readonly message: string }[] = [];
  const alreadyRotated: EnvironmentId[] = [];
  for (const environmentId of candidates.filter(isPending)) {
    const result = yield* rotateOutcome(input.rotate, environmentId, "force");
    if (result.kind === "ok") {
      rotated.push({ environmentId, summary: result.summary, forcedNewEpoch: true });
    } else {
      failed.push({ environmentId, message: result.message });
    }
  }
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
      rotated.push({ environmentId, summary: result.summary, forcedNewEpoch: false });
    }
  }
  return { rotated, failed, alreadyRotated: alreadyRotated.toSorted(compareCodePoints) };
});
