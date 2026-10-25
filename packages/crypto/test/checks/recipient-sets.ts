// Checks of the recipient sets R(E) (CRYPTO_SPEC §6.2) and W(E) (§5.3)
// against recipient-sets.json: wrapRecipientsOf and proposalRecipientsOf give
// each case's expected sets, deviceReceivesEnvironment agrees with R(E) on
// every member device, W(E) ⊆ R(E), and both lists come in the order
// recipient-set.ts documents, whatever order the state's maps were built in.
// The vectors pin the sets only; the order is pinned here.

import type {
  ChainDevice,
  ChainMember,
  ChainState,
  MemberScope,
  ProposalRecipient,
  Role,
  ServerGrant,
  UserId,
  WrapRecipient,
} from "../../src/index.ts";
import {
  deviceReceivesEnvironment,
  proposalRecipientsOf,
  wrapRecipientsOf,
} from "../../src/index.ts";
import recipientSets from "../../test-vectors/recipient-sets.json" with { type: "json" };
import { testEnvironmentId, testKeyFingerprintHex, testUserId } from "../support/fixture.ts";
import { type CheckResult, Checks } from "./support.ts";

interface VectorScope {
  readonly kind: string;
  readonly environments?: readonly string[];
}

interface VectorDevice {
  readonly label: string;
  readonly key_fingerprint_hex: string;
  readonly enc_pub_hex: string;
  readonly sig_pub_hex: string;
  readonly role_cap: string;
  readonly scope: VectorScope;
}

interface VectorMember {
  readonly user_id: string;
  readonly role: string;
  readonly scope: VectorScope;
  readonly devices: readonly VectorDevice[];
}

interface VectorGrant {
  readonly server_key_fingerprint_hex: string;
  readonly server_enc_pub_hex: string;
  readonly scope_environments: readonly string[];
}

interface VectorFixture {
  readonly members: readonly VectorMember[];
  readonly server_grants: readonly VectorGrant[];
}

interface VectorEntry {
  readonly recipient_class: string;
  readonly recipient_id: string;
  readonly key_fingerprint_hex?: string;
  readonly recipient_enc_pub_hex: string;
}

interface RecipientCase {
  readonly name: string;
  readonly fixture: string;
  readonly environment_id: string;
  readonly expected_wrap_recipients: readonly VectorEntry[];
  readonly expected_proposal_recipients: readonly VectorEntry[];
}

type RecipientState = Pick<ChainState, "members" | "serverGrants">;

const ROLES: readonly Role[] = ["owner", "admin", "member", "reader"];

function roleOf(value: string): Role {
  const role = ROLES.find((candidate) => candidate === value);
  if (role === undefined) {
    throw new Error(`recipient-sets.json: unknown role ${value}`);
  }
  return role;
}

function scopeOf(scope: VectorScope): MemberScope {
  return scope.kind === "all"
    ? { kind: "all" }
    : { kind: "listed", environmentIds: (scope.environments ?? []).map(testEnvironmentId) };
}

/**
 * The fixture as a verification state. `reversed` inserts members, devices and
 * grants in the opposite order, to check that the lists do not follow the maps'
 * insertion order. The sets read no seq and no lease policy, so those are fixed
 * placeholders.
 */
function stateOf(fixture: VectorFixture, reversed: boolean): RecipientState {
  const ordered = <T>(items: readonly T[]): readonly T[] => (reversed ? items.toReversed() : items);
  const members = new Map<UserId, ChainMember>();
  for (const member of ordered(fixture.members)) {
    const devices = new Map<string, ChainDevice>();
    for (const device of ordered(member.devices)) {
      devices.set(device.key_fingerprint_hex, {
        keyFingerprintHex: testKeyFingerprintHex(device.key_fingerprint_hex),
        encPubHex: device.enc_pub_hex,
        sigPubHex: device.sig_pub_hex,
        addedSeq: 1,
        roleCap: roleOf(device.role_cap),
        scope: scopeOf(device.scope),
      });
    }
    const userId = testUserId(member.user_id);
    members.set(userId, {
      userId,
      role: roleOf(member.role),
      scope: scopeOf(member.scope),
      devices,
    });
  }
  const serverGrants = new Map<ServerGrant["serverKeyFingerprintHex"], ServerGrant>();
  for (const grant of ordered(fixture.server_grants)) {
    const fingerprint = testKeyFingerprintHex(grant.server_key_fingerprint_hex);
    serverGrants.set(fingerprint, {
      serverKeyFingerprintHex: fingerprint,
      serverEncPubHex: grant.server_enc_pub_hex,
      grantSeq: 1,
      scopeEnvironmentIds: grant.scope_environments.map(testEnvironmentId),
      leasePolicy: [],
    });
  }
  return { members, serverGrants };
}

/** One recipient as a comparable key: class, id, device fingerprint (members only), enc key. */
function entryKey(
  recipientClass: string,
  recipientId: string,
  keyFingerprintHex: string | null,
  encPubHex: string,
): string {
  return JSON.stringify([recipientClass, recipientId, keyFingerprintHex, encPubHex]);
}

function wrapKey(recipient: WrapRecipient): string {
  return recipient.kind === "member"
    ? entryKey(
        "member",
        recipient.member.userId,
        recipient.device.keyFingerprintHex,
        recipient.device.encPubHex,
      )
    : entryKey(
        "server",
        recipient.grant.serverKeyFingerprintHex,
        null,
        recipient.grant.serverEncPubHex,
      );
}

function proposalKey(recipient: ProposalRecipient): string {
  return wrapKey({ kind: "member", ...recipient });
}

function vectorKey(entry: VectorEntry): string {
  return entryKey(
    entry.recipient_class,
    entry.recipient_id,
    entry.key_fingerprint_hex ?? null,
    entry.recipient_enc_pub_hex,
  );
}

/** Equal as sets (each list sorted; a duplicate on either side fails). */
function sameSet(actual: readonly string[], expected: readonly string[]): boolean {
  return JSON.stringify(actual.toSorted()) === JSON.stringify(expected.toSorted());
}

/** The documented position: members before server keys, then by user id and device fingerprint, or by server fingerprint. */
function positionOf(recipient: WrapRecipient): readonly [number, string, string] {
  return recipient.kind === "member"
    ? [0, recipient.member.userId, recipient.device.keyFingerprintHex]
    : [1, recipient.grant.serverKeyFingerprintHex, ""];
}

function precedes(
  a: readonly [number, string, string],
  b: readonly [number, string, string],
): boolean {
  if (a[0] !== b[0]) {
    return a[0] < b[0];
  }
  if (a[1] !== b[1]) {
    return a[1] < b[1];
  }
  return a[2] < b[2];
}

/** Strictly ascending in the documented order (so also free of duplicates). */
function inDocumentedOrder(recipients: readonly WrapRecipient[]): boolean {
  return recipients.every((recipient, index) => {
    const previous = recipients[index - 1];
    return previous === undefined || precedes(positionOf(previous), positionOf(recipient));
  });
}

export function recipientSetsChecks(): CheckResult[] {
  const c = new Checks();
  const fixtures = recipientSets.fixtures as Readonly<Record<string, VectorFixture>>;
  for (const recipientCase of recipientSets.cases as readonly RecipientCase[]) {
    const fixture = fixtures[recipientCase.fixture];
    if (fixture === undefined) {
      c.push(`recipient-sets ${recipientCase.name}: fixture exists`, false);
      continue;
    }
    const environmentId = testEnvironmentId(recipientCase.environment_id);
    const state = stateOf(fixture, false);
    const wrapRecipients = wrapRecipientsOf(state, environmentId);
    const proposalRecipients = proposalRecipientsOf(state, environmentId);
    const expectedWrap = recipientCase.expected_wrap_recipients.map(vectorKey);
    c.push(
      `recipient-sets ${recipientCase.name}: wrapRecipientsOf is R(E)`,
      sameSet(wrapRecipients.map(wrapKey), expectedWrap),
    );
    c.push(
      `recipient-sets ${recipientCase.name}: proposalRecipientsOf is W(E)`,
      sameSet(
        proposalRecipients.map(proposalKey),
        recipientCase.expected_proposal_recipients.map(vectorKey),
      ),
    );
    const wrapKeys = new Set(wrapRecipients.map(wrapKey));
    c.push(
      `recipient-sets ${recipientCase.name}: W(E) ⊆ R(E)`,
      proposalRecipients.every((recipient) => wrapKeys.has(proposalKey(recipient))),
    );
    c.push(
      `recipient-sets ${recipientCase.name}: R(E) in the documented order`,
      inDocumentedOrder(wrapRecipients),
    );
    c.push(
      `recipient-sets ${recipientCase.name}: W(E) in the documented order`,
      inDocumentedOrder(proposalRecipients.map((recipient) => ({ kind: "member", ...recipient }))),
    );
    // The order is the documented one, not the maps' insertion order
    const reversed = stateOf(fixture, true);
    c.push(
      `recipient-sets ${recipientCase.name}: R(E) is the same list from a reversed state`,
      JSON.stringify(wrapRecipientsOf(reversed, environmentId).map(wrapKey)) ===
        JSON.stringify(wrapRecipients.map(wrapKey)),
    );
    c.push(
      `recipient-sets ${recipientCase.name}: W(E) is the same list from a reversed state`,
      JSON.stringify(proposalRecipientsOf(reversed, environmentId).map(proposalKey)) ===
        JSON.stringify(proposalRecipients.map(proposalKey)),
    );
    // The member-side predicate is R(E)'s membership test for every device
    for (const vectorMember of fixture.members) {
      const member = state.members.get(testUserId(vectorMember.user_id));
      for (const vectorDevice of vectorMember.devices) {
        const device = member?.devices.get(vectorDevice.key_fingerprint_hex);
        c.push(
          `recipient-sets ${recipientCase.name}: deviceReceivesEnvironment agrees with R(E) for ${vectorDevice.label}`,
          member !== undefined &&
            device !== undefined &&
            deviceReceivesEnvironment(member, device, environmentId) ===
              expectedWrap.includes(wrapKey({ kind: "member", member, device })),
        );
      }
    }
  }
  return c.results;
}
