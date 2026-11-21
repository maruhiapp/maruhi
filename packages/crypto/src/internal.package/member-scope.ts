import { encodeHex } from "./bytes.ts";
import type { EnvironmentId } from "./chain-types.ts";
import { encodeLengthPrefixed } from "./encoding.ts";

export type ScopeKind = "all" | "listed";

export interface ScopePayloadFields {
  readonly scopeKind: ScopeKind;
  readonly scopeEnvironmentIds: readonly EnvironmentId[];
}

export type MemberScope =
  | { readonly kind: "all" }
  | { readonly kind: "listed"; readonly environmentIds: readonly EnvironmentId[] };

export type EnvironmentSet =
  | { readonly kind: "all" }
  | { readonly kind: "listed"; readonly ids: ReadonlySet<string> };

export const ALL_SCOPE: MemberScope = { kind: "all" };

export const MAX_SCOPE_ENVIRONMENTS = 256;

export function memberScopeOf(fields: ScopePayloadFields): MemberScope {
  return fields.scopeKind === "all"
    ? ALL_SCOPE
    : { kind: "listed", environmentIds: [...fields.scopeEnvironmentIds] };
}

export function scopePayloadFieldsOf(scope: MemberScope): ScopePayloadFields {
  return scope.kind === "all"
    ? { scopeKind: "all", scopeEnvironmentIds: [] }
    : { scopeKind: "listed", scopeEnvironmentIds: [...scope.environmentIds] };
}

export function canonicalScopeEnvironmentsHex(environmentIds: readonly EnvironmentId[]): string {
  return encodeHex(encodeLengthPrefixed(environmentIds));
}

export function scopeShapeOk(
  scopeKind: unknown,
  scopeEnvironmentIds: unknown,
  isBoundedId: (value: unknown) => value is string,
): boolean {
  if (scopeKind !== "all" && scopeKind !== "listed") {
    return false;
  }
  if (!Array.isArray(scopeEnvironmentIds) || scopeEnvironmentIds.length > MAX_SCOPE_ENVIRONMENTS) {
    return false;
  }
  if (!scopeEnvironmentIds.every((id) => isBoundedId(id))) {
    return false;
  }
  if (scopeKind === "all") {
    return scopeEnvironmentIds.length === 0;
  }
  return new Set(scopeEnvironmentIds as readonly string[]).size === scopeEnvironmentIds.length;
}

export function scopeIncludesEnvironment(scope: MemberScope, environmentId: string): boolean {
  return scope.kind === "all" || scope.environmentIds.some((id) => id === environmentId);
}

export function scopeWithout(scope: MemberScope, environmentId: string): MemberScope {
  if (scope.kind === "all" || !scope.environmentIds.some((id) => id === environmentId)) {
    return scope;
  }
  return {
    kind: "listed",
    environmentIds: scope.environmentIds.filter((id) => id !== environmentId),
  };
}

export function scopeAsEnvironmentSet(scope: MemberScope): EnvironmentSet {
  return scope.kind === "all"
    ? { kind: "all" }
    : { kind: "listed", ids: new Set(scope.environmentIds) };
}

export function unionEnvironmentSets(a: EnvironmentSet, b: EnvironmentSet): EnvironmentSet {
  if (a.kind === "all" || b.kind === "all") {
    return { kind: "all" };
  }
  return { kind: "listed", ids: new Set([...a.ids, ...b.ids]) };
}

export function symmetricDifferenceEnvironmentSets(
  a: EnvironmentSet,
  b: EnvironmentSet,
): EnvironmentSet {
  if (a.kind === "all" && b.kind === "all") {
    return { kind: "listed", ids: new Set() };
  }
  if (a.kind === "all" || b.kind === "all") {
    return { kind: "all" };
  }
  const ids = new Set<string>();
  for (const id of a.ids) {
    if (!b.ids.has(id)) {
      ids.add(id);
    }
  }
  for (const id of b.ids) {
    if (!a.ids.has(id)) {
      ids.add(id);
    }
  }
  return { kind: "listed", ids };
}

export function scopeContainsEnvironmentSet(actor: MemberScope, set: EnvironmentSet): boolean {
  if (actor.kind === "all") {
    return true;
  }
  if (set.kind === "all") {
    return false;
  }
  for (const id of set.ids) {
    if (!actor.environmentIds.some((e) => e === id)) {
      return false;
    }
  }
  return true;
}
