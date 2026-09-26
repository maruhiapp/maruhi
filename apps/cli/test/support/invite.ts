// Fixed material for invite tests (CRYPTO_SPEC §6.5 — 2026-09-13 IV revision,
// v2).
//
// Lets the invite / member add / redacted tests each build, in the same shape,
// "the issuance statement signed by the inviter" and "the acceptance block
// jointly signed by the invitee + link key". All seeds and keys are test-only
// fixed or generated values (no real secrets).

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
import { Redacted } from "effect";

import { buildInviteLink, type InviteLinkData, type InviteRole } from "../../src/invite-link.ts";
import type { TestUser } from "./crypto.ts";
import { type MockHandler, onRequest } from "./server.ts";

/** A fixed invite id (ULID format — satisfies api-schema's InviteIdSchema). */
export const INVITE_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
/** The fixed link-key seed (a test-only pattern value). */
export const LINK_SEED_HEX = "d0".repeat(32);

export interface IssuedInviteFixture {
  /** The data the link carries (issuance already signed). */
  readonly link: InviteLinkData;
  /** The link public key derived from the seed (hex). */
  readonly linkPubHex: string;
  /** The server-side issuance statement (the shape placed verbatim on the list row `issuance`). */
  readonly issuance: {
    readonly linkPubHex: string;
    readonly headHashHex: string;
    readonly headSeq: number;
    readonly issueSignatureHex: string;
  };
}

/** Builds an invite (link + issuance statement) signed for issuance by the inviter's chain sig key. */
export async function issueInviteFixture(input: {
  readonly inviter: TestUser;
  readonly projectId: string;
  readonly headHashHex: string;
  readonly headSeq: number;
  readonly role?: InviteRole;
  /** The scope to grant (2026-09-14 ES). Omitted = all (the only shape the K2 CLI issues). */
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
      projectId: input.projectId,
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
      projectId: input.projectId,
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

/** The link string of an issued invite (display form). */
export function inviteLinkText(origin: string, issued: IssuedInviteFixture): string {
  return Redacted.value(buildInviteLink({ origin, link: issued.link }));
}

/** The acceptance block of a server list row (wire form). */
export interface AcceptanceFixture {
  readonly inviteeUserId: string;
  readonly inviteeEncPubHex: string;
  readonly inviteeSigPubHex: string;
  readonly signatureHex: string;
  readonly linkSignatureHex: string;
  readonly acceptedAtMs: number;
}

/**
 * The acceptance block (joint signature: acceptance signature + link
 * signature). The declared keys and signing key default to the invitee's own,
 * but can be overridden to build a key-reuse shape (the signature is assembled
 * over the post-override declared keys — used to pin down that the verifier
 * "verifies with the declared keys").
 */
export async function acceptanceFixture(input: {
  readonly projectId: string;
  readonly issued: IssuedInviteFixture;
  readonly invitee: TestUser;
  readonly inviteeUserId?: string;
  readonly declared?: { readonly encPubHex: string; readonly sigPubHex: string };
  readonly signer?: TestUser;
}): Promise<AcceptanceFixture> {
  const seed = decodeHex(Redacted.value(input.issued.link.linkSeedHex));
  if (seed === null) throw new Error("bad seed hex");
  const derived = await deriveInviteLinkKeyPair(seed);
  if (!derived.ok) throw new Error("link key derivation failed");
  const context = {
    suite: SUITE_ID,
    projectId: input.projectId,
    linkPubHex: input.issued.linkPubHex,
    inviteeUserId: input.inviteeUserId ?? input.invitee.userId,
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

/** Flips the first byte of a signature hex (a tampered-signature shape). */
export function flipHex(hex: string): string {
  const first = Number.parseInt(hex.slice(0, 2), 16) ^ 0x01;
  return first.toString(16).padStart(2, "0") + hex.slice(2);
}

/** The OpenSSH line of a user's sig public key (the shape of the `key` field in GitHub's response — identity-backing source IV2). */
export function sshLineOf(user: TestUser): string {
  const raw = decodeHex(user.sigPubHex);
  if (raw === null) throw new Error("sig pub hex");
  const encoded = encodeOpenSshEd25519PublicKey(raw);
  if (!encoded.ok) throw new Error("openssh encode");
  return encoded.value;
}

/**
 * Fakes GitHub's `GET /users/{login}/ssh_signing_keys` (identity-backing
 * source IV2). Tests redirect the fixed host here via
 * `env.setVendorOrigin("api.github.com", server.origin)`.
 */
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
