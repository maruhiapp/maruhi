// CRYPTO_SPEC §1 principle 7 / §3 / §6.2 "device keys" (2026-09-19 DK): device
// keys, caps, and effective permission.
//
// "Keys belong to devices; permission belongs to the person" — a chain member
// (user_id) holds a set of device keys, and each device declares a
// cap = (role_cap, scope). A device's **effective permission** =
// (min(the person's role, role_cap), the person's scope ∩ the device's scope),
// never exceeding the person's permission.
// Every signer of this spec (actor / writer / author / issuer / attester) has
// its role / scope checked against the signing device's effective permission
// (§6.2 / §6.3 / §6.6 / §5.1).
//
// Only this module's effectivePermissionOf computes the effective permission,
// and only via the `EffectivePermission` type (branded) can it be passed to
// the checks — the type makes it impossible to accidentally pass the person's
// raw (role, scope) to a check (design log dk-design.md §7 K2-4).

import type { KeyFingerprintHex, Role } from "./chain-types.ts";
import { ALL_SCOPE, type MemberScope } from "./member-scope.ts";

/** Role order used by every role comparison (the §6.2 role table). */
export const ROLE_RANK = { reader: 0, member: 1, admin: 2, owner: 3 } as const satisfies Record<
  Role,
  number
>;

/** The lower of two roles (min(the person's role, role_cap) — §3). */
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

/** The structural cap of a member's first key (§6.2 — the payload is unchanged, so structurally (owner, all)). */
export const FIRST_DEVICE_CAP: DeviceCap = { roleCap: "owner", scope: ALL_SCOPE };

/**
 * One device key of a current member derived from a verified chain (the §6.2
 * verification state — FP → public keys, cap, added seq). Identified by its key fingerprint
 * (§3: FP = SHA-256(enc ‖ sig)[:16] — the fingerprint names the device).
 */
export interface ChainDevice extends DeviceCap {
  readonly keyFingerprintHex: KeyFingerprintHex;
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
 * The single place the effective permission is computed (§3 / §6.2 "device effective permission"):
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
 * Monotonicity (principle D2 — §6.2 `add_device`): a new device's cap must not exceed the
 * signing device's **own** cap — `role_cap_new ≤ role_cap_signer` and
 * `scope_new ⊆ scope_signer` (`all` = U: listed never contains all, the empty list
 * is contained by everything). Compared cap to cap, never against the person's
 * effective permission (otherwise a member could not register an (owner, all)
 * reserve key from its first key — 2026-09-19, addressing a Cursor Bugbot finding).
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
 * single-device assumption (K2 — the server / CLI / Web follow mechanically:
 * devices stay singular): a caller that silently took "the first device" would pick an arbitrary
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
