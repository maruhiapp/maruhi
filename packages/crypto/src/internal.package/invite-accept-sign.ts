import { decodeHex } from "./bytes.ts";
import type { ProjectId, UserId } from "./chain-types.ts";
import { encodeLengthPrefixed } from "./encoding.ts";
import type { CryptoResult } from "./errors.ts";
import { importSigningPublicKey } from "./keys.ts";
import {
  invalidInput,
  isLowercaseHexOfLength,
  signEd25519Over,
  verifyEd25519Over,
} from "./validate.ts";

const PUB_KEY_HEX_LENGTH = 32 * 2;

export interface InviteAcceptSignatureContext {
  readonly suite: string;
  readonly projectId: ProjectId;
  readonly linkPubHex: string;
  readonly inviteeUserId: UserId;
  readonly inviteeEncPubHex: string;
  readonly inviteeSigPubHex: string;
}

function contextInvalidField(context: InviteAcceptSignatureContext): string | null {
  if (context.suite.length === 0) {
    return "context suite";
  }
  if (context.inviteeUserId.length === 0) {
    return "context inviteeUserId";
  }
  if (!isLowercaseHexOfLength(context.linkPubHex, PUB_KEY_HEX_LENGTH)) {
    return "context linkPubHex";
  }
  if (!isLowercaseHexOfLength(context.inviteeEncPubHex, PUB_KEY_HEX_LENGTH)) {
    return "context inviteeEncPubHex";
  }
  if (!isLowercaseHexOfLength(context.inviteeSigPubHex, PUB_KEY_HEX_LENGTH)) {
    return "context inviteeSigPubHex";
  }
  return null;
}

export function buildInviteAcceptSignedBytes(context: InviteAcceptSignatureContext): Uint8Array {
  return encodeLengthPrefixed([
    `${context.suite}/invite-accept-v2`,
    context.projectId,
    context.linkPubHex,
    context.inviteeUserId,
    context.inviteeEncPubHex,
    context.inviteeSigPubHex,
  ]);
}

export async function signInviteAccept(input: {
  readonly context: InviteAcceptSignatureContext;
  readonly signingKey: CryptoKey;
}): Promise<CryptoResult<string>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  return signEd25519Over(buildInviteAcceptSignedBytes(input.context), input.signingKey);
}

export async function signInviteLink(input: {
  readonly context: InviteAcceptSignatureContext;
  readonly linkPrivateKey: CryptoKey;
}): Promise<CryptoResult<string>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  return signEd25519Over(buildInviteAcceptSignedBytes(input.context), input.linkPrivateKey);
}

async function verifyDeclared(input: {
  readonly context: InviteAcceptSignatureContext;
  readonly signatureHex: string;
  readonly declaredKeyHex: string;
  readonly declaredField: string;
  readonly onInvalid: "InviteAcceptSignatureInvalid" | "InviteLinkSignatureInvalid";
}): Promise<CryptoResult<void>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  const keyBytes = decodeHex(input.declaredKeyHex);
  if (keyBytes === null) {
    return invalidInput(input.declaredField);
  }
  const publicKey = await importSigningPublicKey(keyBytes);
  if (!publicKey.ok) {
    return publicKey;
  }
  return verifyEd25519Over(
    buildInviteAcceptSignedBytes(input.context),
    input.signatureHex,
    publicKey.value,
    { kind: input.onInvalid },
  );
}

export async function verifyInviteAcceptSignature(input: {
  readonly context: InviteAcceptSignatureContext;
  readonly signatureHex: string;
}): Promise<CryptoResult<void>> {
  return verifyDeclared({
    context: input.context,
    signatureHex: input.signatureHex,
    declaredKeyHex: input.context.inviteeSigPubHex,
    declaredField: "context inviteeSigPubHex",
    onInvalid: "InviteAcceptSignatureInvalid",
  });
}

export async function verifyInviteLinkSignature(input: {
  readonly context: InviteAcceptSignatureContext;
  readonly linkSignatureHex: string;
}): Promise<CryptoResult<void>> {
  return verifyDeclared({
    context: input.context,
    signatureHex: input.linkSignatureHex,
    declaredKeyHex: input.context.linkPubHex,
    declaredField: "context linkPubHex",
    onInvalid: "InviteLinkSignatureInvalid",
  });
}
