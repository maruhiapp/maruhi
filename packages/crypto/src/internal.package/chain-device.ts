import type { KeyFingerprintHex, Role } from "./chain-types.ts";
import { ALL_SCOPE, type MemberScope } from "./member-scope.ts";

export const ROLE_RANK = { reader: 0, member: 1, admin: 2, owner: 3 } as const satisfies Record<
  Role,
  number
>;

function minRole(a: Role, b: Role): Role {
  return ROLE_RANK[a] <= ROLE_RANK[b] ? a : b;
}

export interface DeviceCap {
  readonly roleCap: Role;
  readonly scope: MemberScope;
}

export const FIRST_DEVICE_CAP: DeviceCap = { roleCap: "owner", scope: ALL_SCOPE };

export interface ChainDevice extends DeviceCap {
  readonly keyFingerprintHex: KeyFingerprintHex;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly addedSeq: number;
}

export interface EffectivePermission {
  readonly effective: true;
  readonly role: Role;
  readonly scope: MemberScope;
}

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

export function soleDeviceOf(member: {
  readonly devices: ReadonlyMap<string, ChainDevice>;
}): ChainDevice | undefined {
  if (member.devices.size !== 1) {
    return undefined;
  }
  return member.devices.values().next().value;
}
