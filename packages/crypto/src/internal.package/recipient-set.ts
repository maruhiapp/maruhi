// CRYPTO_SPEC §6.2 / §5.3: the recipient sets of an environment E, over a
// verification state (§6.2's current members with their active devices, and
// the valid grants).
//
//   R(E) = {(m, d) | m a current member, d ∈ devices(m), E ∈ scope(m) ∩ scope(d)}
//          ∪ {valid grant_server g | E ∈ scope_environments(g)}
//     — the destinations of E's complete DEK-wrap set (§6.2, the device axis):
//     what the creation and rotation composites wrap to, and what the server
//     matches a wrap set against (AUTH_SPEC §12-4 / §12-6)
//   W(E) = the member devices of R(E) whose effective role
//          min(role, role_cap) is member or above
//     — the recipients of E's sealed value proposals (§5.3): R(E) minus
//     readers, reader-capped devices and the grants
//
// A DEK wrap is addressed by (recipient id, recipient enc key): §5's info
// binds the recipient id (a server key's fingerprint — §9), the Seal goes to
// the enc key, §5.1's signed bytes bind both, and none of them carries the
// recipient class. So R(E) is listed once per address (AUTH_SPEC §12-6's
// storage slot): a member whose user id is a granted server key's
// fingerprint and whose device holds that server key shares the grant's
// address (add_member's target user id is free-form — AUTH_SPEC §11-1 — and
// member-key uniqueness does not cover server keys), and the address is
// listed as the member's. The spec does not decide which class a shared
// address takes; test-vectors/README.md convention 33 lists what this
// choice implies.
//
// Both lists come in one fixed order — members by user id, each member's
// devices by key fingerprint, then the server keys by fingerprint, all in
// UTF-16 code-unit order — so the same sets always give the same list (a CAS
// retry compares two lists). The vectors pin the sets, not the order.
// Test vectors: test-vectors/recipient-sets.json

import {
  type ChainDevice,
  type DeviceCap,
  effectivePermissionOf,
  ROLE_RANK,
} from "./chain-device.ts";
import type { ChainMember, ChainState, EnvironmentId, Role, ServerGrant } from "./chain-types.ts";
import { type MemberScope, scopeIncludesEnvironment } from "./member-scope.ts";

/** A current member and one of its active devices (R(E) is a set of (person, device) pairs — §6.2). */
export interface MemberDevice {
  readonly member: ChainMember;
  /** The device a wrap or a sealed value is sealed to. */
  readonly device: ChainDevice;
}

/** One element of R(E): a member's device or a valid grant's server key (AUTH_SPEC §12-6's recipient class). */
export type WrapRecipient =
  | ({ readonly kind: "member" } & MemberDevice)
  | { readonly kind: "server"; readonly grant: ServerGrant };

/** One element of W(E): a member's device. */
export type ProposalRecipient = MemberDevice;

/** UTF-16 code-unit order, the order of both lists. */
function byCodeUnits(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * The member side of R(E)'s predicate: E is in the device's effective scope,
 * the person's scope ∩ the device's scope (§6.2 — effectivePermissionOf is the
 * only place that computes it).
 */
export function deviceReceivesEnvironment(
  person: { readonly role: Role; readonly scope: MemberScope },
  device: DeviceCap,
  environmentId: EnvironmentId,
): boolean {
  return scopeIncludesEnvironment(effectivePermissionOf(person, device).scope, environmentId);
}

/** Every (member, device) pair: members by user id, each member's devices by key fingerprint. */
function memberDevicesInOrder(members: ChainState["members"]): readonly MemberDevice[] {
  return [...members.values()]
    .toSorted((a, b) => byCodeUnits(a.userId, b.userId))
    .flatMap((member) =>
      [...member.devices.values()]
        .toSorted((a, b) => byCodeUnits(a.keyFingerprintHex, b.keyFingerprintHex))
        .map((device) => ({ member, device })),
    );
}

/** A wrap's address: its recipient id (§5's info) and the enc key it is sealed to. */
function addressOf(recipient: WrapRecipient): { readonly id: string; readonly encPubHex: string } {
  return recipient.kind === "member"
    ? { id: recipient.member.userId, encPubHex: recipient.device.encPubHex }
    : { id: recipient.grant.serverKeyFingerprintHex, encPubHex: recipient.grant.serverEncPubHex };
}

/**
 * R(E) (CRYPTO_SPEC §6.2): the recipients of environment E's complete DEK-wrap
 * set, once per wrap address, in the order this file's header gives.
 */
export function wrapRecipientsOf(
  state: Pick<ChainState, "members" | "serverGrants">,
  environmentId: EnvironmentId,
): readonly WrapRecipient[] {
  // Members first, so that an address a member shares with a server key is
  // listed as the member's
  const candidates: readonly WrapRecipient[] = [
    ...memberDevicesInOrder(state.members)
      .filter(({ member, device }) => deviceReceivesEnvironment(member, device, environmentId))
      .map(({ member, device }) => ({ kind: "member" as const, member, device })),
    ...[...state.serverGrants.values()]
      .filter((grant) => grant.scopeEnvironmentIds.includes(environmentId))
      .toSorted((a, b) => byCodeUnits(a.serverKeyFingerprintHex, b.serverKeyFingerprintHex))
      .map((grant) => ({ kind: "server" as const, grant })),
  ];
  const keysById = new Map<string, Set<string>>();
  const recipients: WrapRecipient[] = [];
  for (const recipient of candidates) {
    const { id, encPubHex } = addressOf(recipient);
    const keys = keysById.get(id) ?? new Set<string>();
    if (!keys.has(encPubHex)) {
      keys.add(encPubHex);
      keysById.set(id, keys);
      recipients.push(recipient);
    }
  }
  return recipients;
}

/**
 * W(E) (CRYPTO_SPEC §5.3): the member devices of R(E) whose effective role is
 * member or above, in the order this file's header gives.
 */
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
