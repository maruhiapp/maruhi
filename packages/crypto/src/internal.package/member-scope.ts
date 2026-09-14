// CRYPTO_SPEC §6.2(2026-09-14 ES): メンバーの環境スコープ — 符号化・構造規則・集合代数。
//
// - payload 上の表現は `scope_kind`("all" | "listed")+ `scope_environments_lp_hex`
//   (environment_id リストの §2.1 LP の hex 小文字 — grant_server の scope_environments と
//   同じ入れ子 LP。リスト順は署名対象の一部、生成は昇順 SHOULD・検証は集合)
// - 構造規則(payload 構造検査の段 — 認可に先行): all ⇒ 空リスト必須、256 要素以下、
//   重複 id は無効、listed の空リストは有効
// - 集合代数(原則 1 の包含判定): `all` は全環境の集合 U(将来作成される環境を含む)、
//   `listed{X}` は有限集合 X。`all ⊇ 任意`、`listed{X} ⊇ all` は偽、
//   `listed{X} ⊇ listed{Y}` ⇔ Y ⊆ X。差集合・対称差で `U \ X` が現れる形は
//   EnvironmentSet の `all` 側(= U または U の補有限部分集合 — listed には包含されない)
//   として fail-closed に扱う

import { encodeHex } from "./bytes.ts";
import { encodeLengthPrefixed } from "./encoding.ts";

/** Scope kind on the wire (CRYPTO_SPEC §6.2). */
export type ScopeKind = "all" | "listed";

/** The two wire fields every scope-carrying payload ends with (§6.2 の正規化フィールド順). */
export interface ScopePayloadFields {
  readonly scopeKind: ScopeKind;
  /** Environment ids in as-signed order (empty when `scopeKind` is `all`). */
  readonly scopeEnvironmentIds: readonly string[];
}

/**
 * A member's derived environment scope (CRYPTO_SPEC §6.2 の検証状態). `all`
 * includes environments created later; `listed` is the exact finite set (the
 * empty list is a valid scope that receives no DEK at all).
 */
export type MemberScope =
  | { readonly kind: "all" }
  | { readonly kind: "listed"; readonly environmentIds: readonly string[] };

/**
 * An environment set in the containment algebra of principle 1 (§6.2):
 * `all` stands for U or any cofinite subset of U (`U \ X`) — sets that no
 * `listed` scope can contain. `listed` is a finite set.
 */
export type EnvironmentSet =
  | { readonly kind: "all" }
  | { readonly kind: "listed"; readonly ids: ReadonlySet<string> };

/** The `all` scope (genesis の作成者・owner の scope). */
export const ALL_SCOPE: MemberScope = { kind: "all" };

/** Upper bound of a listed scope (§6.1 — grant_server の scope_environments と同じ 256). */
export const MAX_SCOPE_ENVIRONMENTS = 256;

/** Builds the derived scope from payload fields already validated by `scopeShapeOk`. */
export function memberScopeOf(fields: ScopePayloadFields): MemberScope {
  return fields.scopeKind === "all"
    ? ALL_SCOPE
    : { kind: "listed", environmentIds: [...fields.scopeEnvironmentIds] };
}

/** The wire fields of a derived scope (CLI / server が payload を組むときの逆変換). */
export function scopePayloadFieldsOf(scope: MemberScope): ScopePayloadFields {
  return scope.kind === "all"
    ? { scopeKind: "all", scopeEnvironmentIds: [] }
    : { scopeKind: "listed", scopeEnvironmentIds: [...scope.environmentIds] };
}

/** Lowercase hex of the nested LP of the environment id list (`scope_environments_lp_hex`). */
export function canonicalScopeEnvironmentsHex(environmentIds: readonly string[]): string {
  return encodeHex(encodeLengthPrefixed(environmentIds));
}

/**
 * Structure rule (§6.2 — payload 構造検査の段): kind in the closed set, ids are
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

/** Whether `environmentId` is inside `scope` (環境対象 op / §6.3 の 3′ / R(E) の述語). */
export function scopeIncludesEnvironment(scope: MemberScope, environmentId: string): boolean {
  return scope.kind === "all" || scope.environmentIds.includes(environmentId);
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
 * listed scope — CRYPTO_SPEC §6.2 の集合代数 / Cursor Bugbot 指摘対応).
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
    if (!actor.environmentIds.includes(id)) {
      return false;
    }
  }
  return true;
}
