import {
  decodeEnvironmentId,
  isEnvironmentId,
  type EnvironmentId,
  type UserId,
} from "@maruhi/core";
import type { ChainMember, DeviceCap, MemberScope, ScopePayloadFields } from "@maruhi/crypto";
import {
  ALL_SCOPE,
  effectivePermissionOf,
  MAX_SCOPE_ENVIRONMENTS,
  scopeIncludesEnvironment,
} from "@maruhi/crypto";
import { Effect } from "effect";

import type { VerifiedProject } from "./chain-sync.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError, usageError } from "./errors.ts";

export function describeScope(scope: MemberScope | ScopePayloadFields): string {
  const member = toMemberScope(scope);
  if (member.kind === "all") {
    return "all environments";
  }
  return member.environmentIds.length === 0
    ? "no environments"
    : member.environmentIds.map((id) => displayText(id)).join(", ");
}

export function sameScope(
  a: MemberScope | ScopePayloadFields,
  b: MemberScope | ScopePayloadFields,
): boolean {
  const left = toMemberScope(a);
  const right = toMemberScope(b);
  if (left.kind === "all" || right.kind === "all") {
    return left.kind === right.kind;
  }
  const ids = new Set(left.environmentIds);
  return (
    ids.size === new Set(right.environmentIds).size &&
    right.environmentIds.every((id) => ids.has(id))
  );
}

function toMemberScope(scope: MemberScope | ScopePayloadFields): MemberScope {
  if ("kind" in scope) {
    return scope;
  }
  return scope.scopeKind === "all"
    ? ALL_SCOPE
    : { kind: "listed", environmentIds: [...scope.scopeEnvironmentIds] };
}

export function scopeContains(actor: MemberScope, target: MemberScope): boolean {
  if (target.kind === "all") {
    return actor.kind === "all";
  }
  return target.environmentIds.every((id) => scopeIncludesEnvironment(actor, id));
}

export function scopeFromFlags(input: {
  readonly env: readonly string[];
  readonly allEnvs: boolean;
  readonly noEnvs?: boolean;
}): Effect.Effect<MemberScope | null, CliError> {
  if (input.allEnvs) {
    return Effect.succeed(ALL_SCOPE);
  }
  if (input.noEnvs === true) {
    return Effect.succeed({ kind: "listed", environmentIds: [] });
  }
  if (input.env.length === 0) {
    return Effect.succeed(null);
  }
  if (input.env.length > MAX_SCOPE_ENVIRONMENTS) {
    return Effect.fail(
      usageError(`--env accepts at most ${MAX_SCOPE_ENVIRONMENTS} environments (CRYPTO_SPEC §6.2)`),
    );
  }
  const invalid = input.env.find((id) => !isEnvironmentId(id));
  if (invalid !== undefined) {
    return Effect.fail(
      usageError(
        "Invalid --env value (an environment ID must start with an alphanumeric character, followed by up to 63 alphanumerics, _ or -)",
      ),
    );
  }
  const unique = new Set(input.env);
  if (unique.size !== input.env.length) {
    return Effect.fail(usageError("--env lists the same environment more than once"));
  }
  return Effect.succeed({
    kind: "listed",
    environmentIds: [...unique].map(decodeEnvironmentId).toSorted(compareCodePoints),
  });
}

export function compareCodePoints(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function requireScopeEnvironmentsExist(
  verified: VerifiedProject,
  scope: MemberScope,
): Effect.Effect<void, CliError> {
  if (scope.kind === "all") {
    return Effect.void;
  }
  const unknown = scope.environmentIds.filter((id) => !verified.state.environments.has(id));
  if (unknown.length > 0) {
    return Effect.fail(
      cliError(
        `Environment ${unknown.map((id) => displayText(id)).join(", ")} does not exist on this project's chain (a scope may list only environments whose create_environment entry precedes it — CRYPTO_SPEC §6.2 unknown-environment). Check the ID with \`maruhi env list\``,
      ),
    );
  }
  const deleted = scope.environmentIds.filter(
    (id) => (verified.state.environments.get(id)?.deletedAtSeq ?? null) !== null,
  );
  if (deleted.length > 0) {
    return Effect.fail(
      cliError(
        `Environment ${deleted.map((id) => displayText(id)).join(", ")} is deleted on this project's chain (a scope may not list a deleted environment — CRYPTO_SPEC §6.2 environment-deleted). Check the IDs with \`maruhi env list\``,
      ),
    );
  }
  return Effect.void;
}

export function deletedEnvironmentMessage(
  environmentId: EnvironmentId,
  deletedAtSeq: number,
): string {
  return `Environment ${displayText(environmentId)} is deleted (delete_environment at chain seq ${deletedAtSeq}). Deletion is terminal: a deleted environment cannot be restored, and its ID can never be reused`;
}

export function refuseChainDeletedEnvironment(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
): Effect.Effect<void, CliError> {
  const deletedAtSeq = verified.state.environments.get(environmentId)?.deletedAtSeq ?? null;
  return deletedAtSeq === null
    ? Effect.void
    : Effect.fail(cliError(deletedEnvironmentMessage(environmentId, deletedAtSeq)));
}

export function outOfScopeMessage(input: {
  readonly member: ChainMember;
  readonly device?: DeviceCap | undefined;
  readonly environmentId: EnvironmentId;
  readonly operation: string;
}): string {
  const environment = displayText(input.environmentId);
  if (
    input.device !== undefined &&
    scopeIncludesEnvironment(input.member.scope, input.environmentId)
  ) {
    return `Cannot ${input.operation} environment ${environment}: this device's key is capped to ${describeScope(input.device.scope)} on this project's chain, which excludes it (your own scope: ${describeScope(input.member.scope)}). Use one of your devices whose cap covers it (\`maruhi device list\`), or re-register this device with a wider cap (\`maruhi device revoke\` then \`maruhi device add\` / \`maruhi device approve --env …\`)`;
  }
  return `Cannot ${input.operation} environment ${environment}: it is outside your environment scope on this project's chain (your scope: ${describeScope(input.member.scope)}). Ask a project admin to widen it (\`maruhi member change-role ${displayText(input.member.userId)} --env ${environment} …\`). Metadata-only commands such as \`maruhi schema\` still work`;
}

export function requireEnvironmentInScope(input: {
  readonly verified: VerifiedProject;
  readonly userId: UserId;
  readonly environmentId: EnvironmentId;
  readonly operation: string;
  readonly device?: DeviceCap | undefined;
}): Effect.Effect<ChainMember, CliError> {
  const member = input.verified.state.members.get(input.userId);
  if (member === undefined) {
    return Effect.fail(cliError("You are not a chain-derived member of this project"));
  }
  const deletedAtSeq =
    input.verified.state.environments.get(input.environmentId)?.deletedAtSeq ?? null;
  if (deletedAtSeq !== null) {
    return Effect.fail(cliError(deletedEnvironmentMessage(input.environmentId, deletedAtSeq)));
  }
  const scope =
    input.device === undefined ? member.scope : effectivePermissionOf(member, input.device).scope;
  if (!scopeIncludesEnvironment(scope, input.environmentId)) {
    return Effect.fail(
      cliError(
        outOfScopeMessage({
          member,
          device: input.device,
          environmentId: input.environmentId,
          operation: input.operation,
        }),
      ),
    );
  }
  return Effect.succeed(member);
}

export function environmentsOfScopeAt(
  verified: VerifiedProject,
  scope: MemberScope,
  seq: number,
): readonly EnvironmentId[] {
  const ids: EnvironmentId[] = [];
  for (const [environmentId, environment] of verified.state.environments) {
    if (environment.createdAtSeq <= seq && scopeIncludesEnvironment(scope, environmentId)) {
      ids.push(environmentId);
    }
  }
  return ids.toSorted(compareCodePoints);
}

export function scopeChangeAt(
  verified: VerifiedProject,
  previous: MemberScope,
  next: MemberScope,
  seq: number,
): { readonly widened: readonly EnvironmentId[]; readonly narrowed: readonly EnvironmentId[] } {
  const before = new Set(environmentsOfScopeAt(verified, previous, seq));
  const after = new Set(environmentsOfScopeAt(verified, next, seq));
  return {
    widened: [...after].filter((id) => !before.has(id)).toSorted(compareCodePoints),
    narrowed: [...before].filter((id) => !after.has(id)).toSorted(compareCodePoints),
  };
}
