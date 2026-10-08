// CRYPTO_SPEC §6.2 (2026-09-14 ES): a member's environment scope — encoding,
// structure rules, and set algebra.
//
// - The on-payload representation is `scope_kind` ("all" | "listed") +
//   `scope_environments_lp_hex` (the lowercase hex of the §2.1 LP of the
//   environment_id list — the same nested LP as grant_server's
//   scope_environments. The list order is part of the signed data; generation
//   SHOULD sort, verification treats a set)
// - Structure rules (the payload-structure-check stage — precedes
//   authorization): all ⇒ the list must be empty, at most 256 elements,
//   duplicate ids are invalid, an empty listed list is valid
// - Set algebra (principle 1's containment judgment): `all` is the set U of
//   all environments (including ones created later); `listed{X}` is the finite
//   set X. `all ⊇ anything`, `listed{X} ⊇ all` is false,
//   `listed{X} ⊇ listed{Y}` ⇔ Y ⊆ X. Shapes where `U \ X` appears in a
//   difference / symmetric difference are treated fail-closed as
//   EnvironmentSet's `all` side (= U or a cofinite subset of U — not
//   containable by any listed)

import type { EnvironmentId } from "./chain-types.ts";
import { encodeHex } from "./bytes.ts";
import { encodeLengthPrefixed } from "./encoding.ts";

/** Scope kind on the wire (CRYPTO_SPEC §6.2). */
export type ScopeKind = "all" | "listed";

/** The two wire fields every scope-carrying payload ends with (the §6.2 normalization field order). */
export interface ScopePayloadFields {
  readonly scopeKind: ScopeKind;
  /** Environment ids in as-signed order (empty when `scopeKind` is `all`). */
  readonly scopeEnvironmentIds: readonly EnvironmentId[];
}

/**
 * A member's derived environment scope (the CRYPTO_SPEC §6.2 verification state). `all`
 * includes environments created later; `listed` is the exact finite set (the
 * empty list is a valid scope that receives no DEK at all).
 */
export type MemberScope =
  | { readonly kind: "all" }
  | { readonly kind: "listed"; readonly environmentIds: readonly EnvironmentId[] };

/**
 * An environment set in the containment algebra of principle 1 (§6.2):
 * `all` stands for U or any cofinite subset of U (`U \ X`) — sets that no
 * `listed` scope can contain. `listed` is a finite set.
 */
export type EnvironmentSet =
  | { readonly kind: "all" }
  | { readonly kind: "listed"; readonly ids: ReadonlySet<string> };

/** The `all` scope (the genesis creator's / an owner's scope). */
export const ALL_SCOPE: MemberScope = { kind: "all" };

/** Upper bound of a listed scope (§6.1 — the same 256 as grant_server's scope_environments). */
export const MAX_SCOPE_ENVIRONMENTS = 256;

/** Builds the derived scope from payload fields already validated by `scopeShapeOk`. */
export function memberScopeOf(fields: ScopePayloadFields): MemberScope {
  return fields.scopeKind === "all"
    ? ALL_SCOPE
    : { kind: "listed", environmentIds: [...fields.scopeEnvironmentIds] };
}

/** The wire fields of a derived scope (the inverse transform when CLI / server build a payload). */
export function scopePayloadFieldsOf(scope: MemberScope): ScopePayloadFields {
  return scope.kind === "all"
    ? { scopeKind: "all", scopeEnvironmentIds: [] }
    : { scopeKind: "listed", scopeEnvironmentIds: [...scope.environmentIds] };
}

/** Lowercase hex of the nested LP of the environment id list (`scope_environments_lp_hex`). */
export function canonicalScopeEnvironmentsHex(environmentIds: readonly EnvironmentId[]): string {
  return encodeHex(encodeLengthPrefixed(environmentIds));
}

/**
 * Structure rule (§6.2 — the payload-structure-check stage): kind in the closed set, ids are
 * bounded non-empty strings (checked by the caller's `isBoundedId`), at most
 * 256, no duplicates, and an `all` scope carries the empty list. Runtime-typed
 * so that hostile chain JSON yields `invalid-payload` instead of throwing.
 */
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

/** Whether `environmentId` is inside `scope` (environment-targeting ops / §6.3's 3′ / the R(E) predicate). */
export function scopeIncludesEnvironment(scope: MemberScope, environmentId: string): boolean {
  return scope.kind === "all" || scope.environmentIds.some((id) => id === environmentId);
}

/**
 * A scope without a deleted environment (`delete_environment` — §6.2): a
 * `listed` scope stays `listed`, possibly empty; `all` is unchanged. The one
 * pruning rule shared by the verification state and the history index.
 */
export function scopeWithout(scope: MemberScope, environmentId: string): MemberScope {
  if (scope.kind === "all" || !scope.environmentIds.some((id) => id === environmentId)) {
    return scope;
  }
  return {
    kind: "listed",
    environmentIds: scope.environmentIds.filter((id) => id !== environmentId),
  };
}

/** A scope viewed as an environment set. */
export function scopeAsEnvironmentSet(scope: MemberScope): EnvironmentSet {
  return scope.kind === "all"
    ? { kind: "all" }
    : { kind: "listed", ids: new Set(scope.environmentIds) };
}

/** `a ∪ b` — `all` absorbs everything. */
export function unionEnvironmentSets(a: EnvironmentSet, b: EnvironmentSet): EnvironmentSet {
  if (a.kind === "all" || b.kind === "all") {
    return { kind: "all" };
  }
  return { kind: "listed", ids: new Set([...a.ids, ...b.ids]) };
}

/**
 * `a △ b` (symmetric difference). `all △ all = ∅`; `all △ listed{X} = U \ X`
 * which is cofinite and therefore reported as `all` (not containable by any
 * listed scope — the CRYPTO_SPEC §6.2 set algebra / addressing a Cursor Bugbot finding).
 */
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

/**
 * Principle 1's containment predicate (§6.2 `scope-not-contained`): the actor's
 * scope must contain the environment set whose permissions the entry changes.
 * `all ⊇ anything`; `listed{X}` contains only finite `listed{Y}` with `Y ⊆ X`
 * (never `all`, which may include environments not yet created).
 */
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
