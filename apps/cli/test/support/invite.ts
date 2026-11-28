import {
  decodeHex,
  deriveInviteLinkKeyPair,
  encodeHex,
  encodeOpenSshEd25519PublicKey,
  signInviteAccept,
  signInviteIssue,
  signInviteLink,
  SUITE_ID,
  type ScopePayloadFields,
} from "@maruhi/crypto";
import type { GeneratedIdentity } from "@maruhi/test-kit";
import { testProjectId, testUserId } from "@maruhi/test-kit";
import { Redacted } from "effect";

import { buildInviteLink, type InviteLinkData, type InviteRole } from "../../src/invite-link.ts";
import { type MockHandler, onRequest } from "./server.ts";

export const INVITE_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
export const LINK_SEED_HEX = "d0".repeat(32);

export interface IssuedInviteFixture {
  readonly link: InviteLinkData;
  readonly linkPubHex: string;
  readonly issuance: {
    readonly linkPubHex: string;
    readonly headHashHex: string;
    readonly headSeq: number;
    readonly issueSignatureHex: string;
  };
}

export async function issueInviteFixture(input: {
  readonly inviter: GeneratedIdentity;
  readonly projectId: string;
  readonly headHashHex: string;
  readonly headSeq: number;
  readonly role?: InviteRole;
  readonly scope?: ScopePayloadFields;
  readonly inviteId?: string;
  readonly seedHex?: string;
  readonly inviterLogin?: string | null;
}): Promise<IssuedInviteFixture> {
  const role = input.role ?? "member";
  const scope: ScopePayloadFields = input.scope ?? { scopeKind: "all", scopeEnvironmentIds: [] };
  const inviteId = input.inviteId ?? INVITE_ID;
  const seedHex = input.seedHex ?? LINK_SEED_HEX;
  const seed = decodeHex(seedHex);
  if (seed === null) throw new Error("bad seed hex");
  const derived = await deriveInviteLinkKeyPair(seed);
  if (!derived.ok) throw new Error("link key derivation failed");
  const linkPubHex = encodeHex(derived.value.publicKeyRaw);
  const signed = await signInviteIssue({
    context: {
      suite: SUITE_ID,
      inviteId,
      projectId: testProjectId(input.projectId),
      linkPubHex,
      headHashHex: input.headHashHex,
      headSeq: input.headSeq,
      role,
      inviterUserId: input.inviter.userId,
      inviterEncPubHex: input.inviter.encPubHex,
      inviterSigPubHex: input.inviter.sigPubHex,
      ...scope,
    },
    signingKey: input.inviter.sigKeyPair.privateKey,
  });
  if (!signed.ok) throw new Error("issue signature failed");
  return {
    link: {
      inviteId,
      linkSeedHex: Redacted.make(seedHex, { label: "invite-link-seed" }),
      projectId: testProjectId(input.projectId),
      headHashHex: input.headHashHex,
      headSeq: input.headSeq,
      inviterUserId: input.inviter.userId,
      inviterEncPubHex: input.inviter.encPubHex,
      inviterSigPubHex: input.inviter.sigPubHex,
      role,
      ...scope,
      inviterLogin: input.inviterLogin ?? null,
      issueSignatureHex: signed.value,
    },
    linkPubHex,
    issuance: {
      linkPubHex,
      headHashHex: input.headHashHex,
      headSeq: input.headSeq,
      issueSignatureHex: signed.value,
    },
  };
}

export function inviteLinkText(origin: string, issued: IssuedInviteFixture): string {
  return Redacted.value(buildInviteLink({ origin, link: issued.link }));
}

export interface AcceptanceFixture {
  readonly inviteeUserId: string;
  readonly inviteeEncPubHex: string;
  readonly inviteeSigPubHex: string;
  readonly signatureHex: string;
  readonly linkSignatureHex: string;
  readonly acceptedAtMs: number;
}

export async function acceptanceFixture(input: {
  readonly projectId: string;
  readonly issued: IssuedInviteFixture;
  readonly invitee: GeneratedIdentity;
  readonly inviteeUserId?: string;
  readonly declared?: { readonly encPubHex: string; readonly sigPubHex: string };
  readonly signer?: GeneratedIdentity;
}): Promise<AcceptanceFixture> {
  const seed = decodeHex(Redacted.value(input.issued.link.linkSeedHex));
  if (seed === null) throw new Error("bad seed hex");
  const derived = await deriveInviteLinkKeyPair(seed);
  if (!derived.ok) throw new Error("link key derivation failed");
  const context = {
    suite: SUITE_ID,
    projectId: testProjectId(input.projectId),
    linkPubHex: input.issued.linkPubHex,
    inviteeUserId: testUserId(input.inviteeUserId ?? input.invitee.userId),
    inviteeEncPubHex: input.declared?.encPubHex ?? input.invitee.encPubHex,
    inviteeSigPubHex: input.declared?.sigPubHex ?? input.invitee.sigPubHex,
  };
  const signature = await signInviteAccept({
    context,
    signingKey: (input.signer ?? input.invitee).sigKeyPair.privateKey,
  });
  const linkSignature = await signInviteLink({
    context,
    linkPrivateKey: derived.value.privateKey,
  });
  if (!signature.ok || !linkSignature.ok) throw new Error("acceptance signatures failed");
  return {
    inviteeUserId: context.inviteeUserId,
    inviteeEncPubHex: context.inviteeEncPubHex,
    inviteeSigPubHex: context.inviteeSigPubHex,
    signatureHex: signature.value,
    linkSignatureHex: linkSignature.value,
    acceptedAtMs: 1755300000000,
  };
}

export function flipHex(hex: string): string {
  const first = Number.parseInt(hex.slice(0, 2), 16) ^ 0x01;
  return first.toString(16).padStart(2, "0") + hex.slice(2);
}

export function sshLineOf(user: GeneratedIdentity): string {
  const raw = decodeHex(user.sigPubHex);
  if (raw === null) throw new Error("sig pub hex");
  const encoded = encodeOpenSshEd25519PublicKey(raw);
  if (!encoded.ok) throw new Error("openssh encode");
  return encoded.value;
}

export function githubSigningKeysHandler(
  login: string,
  keys: readonly string[],
  status = 200,
): MockHandler {
  return onRequest("GET", `/users/${login}/ssh_signing_keys`, () => ({
    status,
    json: status === 200 ? keys.map((key, index) => ({ id: index + 1, key })) : { message: "x" },
  }));
}
