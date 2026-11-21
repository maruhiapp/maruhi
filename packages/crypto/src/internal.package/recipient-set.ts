import {
  type ChainDevice,
  type DeviceCap,
  effectivePermissionOf,
  ROLE_RANK,
} from "./chain-device.ts";
import type { ChainMember, ChainState, EnvironmentId, Role, ServerGrant } from "./chain-types.ts";
import { type MemberScope, scopeIncludesEnvironment } from "./member-scope.ts";

export interface MemberDevice {
  readonly member: ChainMember;
  readonly device: ChainDevice;
}

export type WrapRecipient =
  | ({ readonly kind: "member" } & MemberDevice)
  | { readonly kind: "server"; readonly grant: ServerGrant };

export type ProposalRecipient = MemberDevice;

function byCodeUnits(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function deviceReceivesEnvironment(
  person: { readonly role: Role; readonly scope: MemberScope },
  device: DeviceCap,
  environmentId: EnvironmentId,
): boolean {
  return scopeIncludesEnvironment(effectivePermissionOf(person, device).scope, environmentId);
}

function memberDevicesInOrder(members: ChainState["members"]): readonly MemberDevice[] {
  return [...members.values()]
    .toSorted((a, b) => byCodeUnits(a.userId, b.userId))
    .flatMap((member) =>
      [...member.devices.values()]
        .toSorted((a, b) => byCodeUnits(a.keyFingerprintHex, b.keyFingerprintHex))
        .map((device) => ({ member, device })),
    );
}

export function wrapRecipientsOf(
  state: Pick<ChainState, "members" | "serverGrants">,
  environmentId: EnvironmentId,
): readonly WrapRecipient[] {
  return [
    ...memberDevicesInOrder(state.members)
      .filter(({ member, device }) => deviceReceivesEnvironment(member, device, environmentId))
      .map(({ member, device }) => ({ kind: "member" as const, member, device })),
    ...[...state.serverGrants.values()]
      .filter((grant) => grant.scopeEnvironmentIds.includes(environmentId))
      .toSorted((a, b) => byCodeUnits(a.serverKeyFingerprintHex, b.serverKeyFingerprintHex))
      .map((grant) => ({ kind: "server" as const, grant })),
  ];
}

export function proposalRecipientsOf(
  state: Pick<ChainState, "members">,
  environmentId: EnvironmentId,
): readonly ProposalRecipient[] {
  return memberDevicesInOrder(state.members).filter(({ member, device }) => {
    const effective = effectivePermissionOf(member, device);
    return (
      ROLE_RANK[effective.role] >= ROLE_RANK.member &&
      scopeIncludesEnvironment(effective.scope, environmentId)
    );
  });
}
