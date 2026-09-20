// CRYPTO_SPEC §1 原則 7 / §3 / §6.2「端末鍵」(2026-09-19 DK): 端末鍵・cap・実効権限。
//
// 「鍵は端末に属し、権限は人に属する」— チェーン上のメンバー(user_id)は端末鍵の集合を
// 持ち、各端末は cap = (role_cap, scope) を宣言する。端末の**実効権限** =
// (min(人の role, role_cap), 人の scope ∩ 端末の scope) であり人の権限を超えない。
// 本仕様のあらゆる署名者(actor / writer / author / issuer / attester)の role・scope の
// 検査は、署名した端末の実効権限に対して行う(§6.2 / §6.3 / §6.6 / §5.1)。
//
// 実効権限は本モジュールの effectivePermissionOf **だけ**が計算し、`EffectivePermission`
// 型(brand 付き)でしか各検査へ渡せない — 人の (role, scope) を検査へ直接渡す置換漏れを
// 型で不可能にする(設計録 dk-design.md §7 K2-4)。

import type { Role } from "./chain-types.ts";
import { ALL_SCOPE, type MemberScope } from "./member-scope.ts";

/** Role order used by every role comparison (§6.2 の role 表)。 */
export const ROLE_RANK = { reader: 0, member: 1, admin: 2, owner: 3 } as const satisfies Record<
  Role,
  number
>;

/** The lower of two roles (min(人の role, role_cap) — §3). */
function minRole(a: Role, b: Role): Role {
  return ROLE_RANK[a] <= ROLE_RANK[b] ? a : b;
}

/**
 * A device's declared cap (CRYPTO_SPEC §3 / §6.2 `add_device` payload): the upper
 * bound on the role the device may act with, and the subset of environments it
 * may hold DEKs for. `owner` means "no role bound". The first key of a member
 * (`genesis` / `add_member`) is structurally `(owner, all)`.
 */
export interface DeviceCap {
  readonly roleCap: Role;
  readonly scope: MemberScope;
}

/** The structural cap of a member's first key (§6.2 — payload は不変なので構造的に (owner, all))。 */
export const FIRST_DEVICE_CAP: DeviceCap = { roleCap: "owner", scope: ALL_SCOPE };

/**
 * One device key of a current member derived from a verified chain (§6.2 の
 * 検証状態 — FP → 公開鍵・cap・追加 seq). Identified by its key fingerprint
 * (§3: FP = SHA-256(enc ‖ sig)[:16] — the fingerprint names the device).
 */
export interface ChainDevice extends DeviceCap {
  readonly keyFingerprintHex: string;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  /** Seq of the entry that put this key on the chain (genesis / add_member / add_device — inclusive). */
  readonly addedSeq: number;
}

/**
 * The permission a signing device actually holds: `(min(role, role_cap), scope ∩
 * device scope)` (§3 / §6.2). Branded so that a member's raw (role, scope) cannot
 * be passed where the signing device's effective permission is required.
 */
export interface EffectivePermission {
  readonly effective: true;
  readonly role: Role;
  readonly scope: MemberScope;
}

/** `a ∩ b` of two member scopes (`all` is the identity; listed ∩ listed keeps `a`'s order). */
function intersectScopes(a: MemberScope, b: MemberScope): MemberScope {
  if (a.kind === "all") {
    return b.kind === "all" ? ALL_SCOPE : { kind: "listed", environmentIds: [...b.environmentIds] };
  }
  if (b.kind === "all") {
    return { kind: "listed", environmentIds: [...a.environmentIds] };
  }
  const inB = new Set(b.environmentIds);
  return { kind: "listed", environmentIds: a.environmentIds.filter((id) => inB.has(id)) };
}

/**
 * The single place the effective permission is computed (§3 / §6.2「端末の実効権限」):
 * `(min(person.role, device.roleCap), person.scope ∩ device.scope)`.
 */
export function effectivePermissionOf(
  person: { readonly role: Role; readonly scope: MemberScope },
  device: DeviceCap,
): EffectivePermission {
  return {
    effective: true,
    role: minRole(person.role, device.roleCap),
    scope: intersectScopes(person.scope, device.scope),
  };
}

/**
 * Monotonicity (原則 D2 — §6.2 `add_device`): a new device's cap must not exceed the
 * signing device's **own** cap — `role_cap_new ≤ role_cap_signer` and
 * `scope_new ⊆ scope_signer` (`all` = U: listed never contains all, the empty list
 * is contained by everything). Compared cap to cap, never against the person's
 * effective permission (otherwise a member could not register an (owner, all)
 * reserve key from its first key — 2026-09-19 Cursor Bugbot 指摘対応).
 */
export function capWithinCap(candidate: DeviceCap, signer: DeviceCap): boolean {
  if (ROLE_RANK[candidate.roleCap] > ROLE_RANK[signer.roleCap]) {
    return false;
  }
  if (signer.scope.kind === "all") {
    return true;
  }
  if (candidate.scope.kind === "all") {
    return false;
  }
  const allowed = new Set(signer.scope.environmentIds);
  return candidate.scope.environmentIds.every((id) => allowed.has(id));
}

/**
 * The member's only device, or `undefined` when the member holds zero or more
 * than one active device. Fail-closed accessor for callers written under the
 * single-device assumption (K2 — サーバー / CLI / Web の機械的追随: 端末は 1 つの
 * まま): a caller that silently took "the first device" would pick an arbitrary
 * key once `add_device` lands (K3 / K4), so the multi-device case returns
 * `undefined` and callers must treat it as an error until they are device-aware.
 */
export function soleDeviceOf(member: {
  readonly devices: ReadonlyMap<string, ChainDevice>;
}): ChainDevice | undefined {
  if (member.devices.size !== 1) {
    return undefined;
  }
  return member.devices.values().next().value;
}
