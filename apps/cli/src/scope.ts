// The CLI-side shared predicates of a member's environment scope
// (CRYPTO_SPEC §6.2 / §6.3, AUTH_SPEC §9-2 / §12-3) (2026-09-15 ES
// K4 — design record es-design.md §10).
//
// - Containment (K4-I): derived from `packages/crypto`'s public API
//   `scopeIncludesEnvironment` (the internal set algebra is not
//   copied). Equivalent to §6.2's set algebra: `all ⊇ any`,
//   `listed ⊇ all` is false (all is U, which includes future
//   environments), `listed{X} ⊇ listed{Y}` ⇔ Y ⊆ X
// - Pre-communication judgment (K4-C): target environment ∈ my
//   scope is judged at the earliest shared paths where the
//   environment is settled (context.ts's openEnvironment /
//   dek-wrap.ts's requireWritingMember / deks.ts's
//   environmentKeysFor) plus explicit calls on multi-environment
//   paths (checkpoint / sync). Does not wait for the server's 403
//   `insufficient-scope` (§6.3)
// - The obligation's environment set (K4-J): `all` is concretized
//   to the environment set that existed at the obligation's seq
//   (the target cannot hold the DEK of an environment created
//   later — the same line as rotation-sweep.ts's `createdAtSeq >
//   seq` exclusion)

import { isEnvironmentId } from "@maruhi/core";
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

/** The user-facing scope display (`all` / `no environments` / an enumeration of environment ids. Ids are neutralized). */
export function describeScope(scope: MemberScope | ScopePayloadFields): string {
  const member = toMemberScope(scope);
  if (member.kind === "all") {
    return "all environments";
  }
  return member.environmentIds.length === 0
    ? "no environments"
    : member.environmentIds.map((id) => displayText(id)).join(", ");
}

/** scope equality (compared as sets — generation is ascending SHOULD, verification is set-based. CRYPTO_SPEC §6.2). */
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

/** Maps both the wire form (`scopeKind` / `scopeEnvironmentIds`) and the derived form to the derived form. */
function toMemberScope(scope: MemberScope | ScopePayloadFields): MemberScope {
  if ("kind" in scope) {
    return scope;
  }
  return scope.scopeKind === "all"
    ? ALL_SCOPE
    : { kind: "listed", environmentIds: [...scope.scopeEnvironmentIds] };
}

/**
 * Containment `actor ⊇ target` (CRYPTO_SPEC §6.2 principle 1's
 * predicate used for pre-communication guidance). `all` is U
 * including future environments, so a `listed` actor does not
 * contain `all`.
 */
export function scopeContains(actor: MemberScope, target: MemberScope): boolean {
  if (target.kind === "all") {
    return actor.kind === "all";
  }
  return target.environmentIds.every((id) => scopeIncludesEnvironment(actor, id));
}

/**
 * Assembling a scope from `--env <id>` (repeatable) / `--all-envs`
 * / `--no-envs` (shared by `invite create` / `member change-role`).
 * Format check (§12-1), duplicate refusal (§6.2's structural
 * rules), cap 256, code-point ascending (generation is ascending
 * SHOULD). When both are omitted, null (= the caller's default —
 * all for an invite, kept as-is for change-role).
 */
export function scopeFromFlags(input: {
  readonly env: readonly string[];
  readonly allEnvs: boolean;
  /** `--no-envs` = `listed{}` (§6.2's empty listed — an admin who only manages, or a member to be admitted later). */
  readonly noEnvs?: boolean;
}): Effect.Effect<MemberScope | null, CliError> {
  const modes = [input.allEnvs, input.noEnvs === true, input.env.length > 0].filter(Boolean);
  if (modes.length > 1) {
    return Effect.fail(usageError("--env, --all-envs and --no-envs cannot be combined"));
  }
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
    environmentIds: [...unique].toSorted(compareCodePoints),
  });
}

/** Code-point ascending order (§6.2's generation SHOULD. Locale-independent). */
export function compareCodePoints(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Each id of `listed` exists on the chain and is not deleted there
 * (the pre-communication judgment of the consensus rules
 * `unknown-environment` and `environment-deleted` — stops a typo or a
 * stale ID before issuance / append; §6.2).
 */
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

/** The wording for when I point at an environment outside my scope (K4-C — does not wait for the server's 403). */
export function outOfScopeMessage(input: {
  readonly member: ChainMember;
  /** The device that signs / opens (when given, distinguishes the device's scope cap — DK K4-17). */
  readonly device?: DeviceCap | undefined;
  readonly environmentId: string;
  /** E.g. "pull values from" — interpolated into the form "<operation> environment X". */
  readonly operation: string;
}): string {
  const environment = displayText(input.environmentId);
  // When the person's scope contains it but the device's scope cap
  // excludes it, the party to ask for expansion is different (not
  // an admin — my own uncapped device, or a `device approve` redo)
  if (
    input.device !== undefined &&
    scopeIncludesEnvironment(input.member.scope, input.environmentId)
  ) {
    return `Cannot ${input.operation} environment ${environment}: this device's key is capped to ${describeScope(input.device.scope)} on this project's chain, which excludes it (your own scope: ${describeScope(input.member.scope)}). Use one of your devices whose cap covers it (\`maruhi device list\`), or re-register this device with a wider cap (\`maruhi device revoke\` then \`maruhi device add\` / \`maruhi device approve --env …\`)`;
  }
  return `Cannot ${input.operation} environment ${environment}: it is outside your environment scope on this project's chain (your scope: ${describeScope(input.member.scope)}). Ask a project admin to widen it (\`maruhi member change-role ${displayText(input.member.userId)} --env ${environment} …\`). Metadata-only commands such as \`maruhi schema\` still work`;
}

/**
 * Target environment ∈ my scope (the pre-communication judgment
 * of AUTH_SPEC §12-3's "environment ∈ scope" row). When I am not a
 * current member it fails saying so. When `device` is given, the
 * judgment uses **the device's effective scope** (person ∩ device
 * — DK K4-17) (a device that opens values does not hold the DEK of
 * environments outside its cap). Environment existence is not
 * checked here (existence is each path's job — chain-derived and
 * known to every member, so ordering is unrelated to leakage).
 */
export function requireEnvironmentInScope(input: {
  readonly verified: VerifiedProject;
  readonly userId: string;
  readonly environmentId: string;
  readonly operation: string;
  readonly device?: DeviceCap | undefined;
}): Effect.Effect<ChainMember, CliError> {
  const member = input.verified.state.members.get(input.userId);
  if (member === undefined) {
    return Effect.fail(cliError("You are not a chain-derived member of this project"));
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

/**
 * Concretizing the obligation's environment set (K4-J): of the
 * environments that existed at `seq` (`createdAtSeq <= seq`),
 * those contained in `scope`. `all` = every environment at that
 * point. Ascending order.
 */
export function environmentsOfScopeAt(
  verified: VerifiedProject,
  scope: MemberScope,
  seq: number,
): readonly string[] {
  const ids: string[] = [];
  for (const [environmentId, environment] of verified.state.environments) {
    if (environment.createdAtSeq <= seq && scopeIncludesEnvironment(scope, environmentId)) {
      ids.push(environmentId);
    }
  }
  return ids.toSorted(compareCodePoints);
}

/**
 * Concretizes the diff of a scope replacement old → new onto the
 * environment set at `seq`: the grown part (new \ old — the
 * backfill obligation) and the shrunk part (old \ new — the rotate
 * obligation. CRYPTO_SPEC §7).
 */
export function scopeChangeAt(
  verified: VerifiedProject,
  previous: MemberScope,
  next: MemberScope,
  seq: number,
): { readonly widened: readonly string[]; readonly narrowed: readonly string[] } {
  const before = new Set(environmentsOfScopeAt(verified, previous, seq));
  const after = new Set(environmentsOfScopeAt(verified, next, seq));
  return {
    widened: [...after].filter((id) => !before.has(id)).toSorted(compareCodePoints),
    narrowed: [...before].filter((id) => !after.has(id)).toSorted(compareCodePoints),
  };
}
