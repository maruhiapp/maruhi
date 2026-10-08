// CRYPTO_SPEC §6.5 (2026-09-13 IV revision — v2): the invite-acceptance
// co-signature (Ed25519).
// signed_bytes = LP("<suite>/invite-accept-v2", project_id, link_pub_hex,
//                   invitee_user_id, invitee_enc_pub_hex, invitee_sig_pub_hex)
// The suite binding is carried by the domain string (same shape as §5.1).
// Binary values go onto the LP as lowercase hex strings (the binary_encoding
// convention of chain-entries).
// link_pub_hex = the public key of the per-invite link key (invite-link.ts —
// the inviter's client derives it from a seed that rides only in the link's
// fragment; the server never receives the seed).
//
// The same byte string carries two signatures:
//   - accept signature: the acceptor's chain sig key. The verification key is
//     invitee_sig_pub_hex inside the signed data (self-binding — a form where
//     the verification key were given from outside the signed data would
//     permit a "declared key / verification key mismatch", so it does not
//     exist). Semantics: the attribution and context binding of "the holder of
//     this key pair declared the intent to join this invite under this key"
//   - link signature: the link key's private key. The verification key is
//     link_pub_hex inside the signed data (likewise self-binding). Semantics:
//     "the holder of the link approved this acceptance under this key" —
//     since the server does not hold the link private key, replacing the
//     acceptance block's key while producing a valid link signature is
//     cryptographically impossible (the substance of IV1)
// The old v1 (domain "<suite>/invite-accept", invite_token_hash_hex binding)
// is not accepted (the 2026-09-13 owner ruling that creates no compatibility
// path; negative `legacy-domain` pins verification failure under the old
// domain string).
// Not part of the consensus rules of chain validity (additional evidence
// outside the chain — §6.5).
// Test vectors: test-vectors/invite-accept-signature.json

import { decodeHex } from "./bytes.ts";
import type { ProjectId } from "./chain-types.ts";
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

/**
 * Fields bound by the invite-acceptance co-signatures (CRYPTO_SPEC §6.5 v2):
 * the invite coordinates (project, link public key) and the invitee's
 * identity and full public key set. Binary values are carried as lowercase
 * hex strings, exactly as on the wire. The accept signature must verify
 * under `inviteeSigPubHex` and the link signature under `linkPubHex` — the
 * declared keys are the verification keys.
 */
export interface InviteAcceptSignatureContext {
  readonly suite: string;
  readonly projectId: ProjectId;
  /** The invite's link public key (Ed25519, lowercase hex — never the seed). */
  readonly linkPubHex: string;
  /** The acceptor's internal user id (the server requires caller == invitee). */
  readonly inviteeUserId: string;
  readonly inviteeEncPubHex: string;
  readonly inviteeSigPubHex: string;
}

// Structure validation of the signing target: hex fields are lowercase
// fixed-length (allowing uppercase hex would give one acceptance multiple
// normalized forms and break signature uniqueness — the same discipline as
// validate.ts). suite / invitee_user_id must be non-empty. project_id is a
// free-form bounded string (the vectors are format-agnostic — the same
// posture as AUTH_SPEC §11-1's independence from ID formats)
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

/**
 * Builds the canonical byte string co-signed for one invite acceptance
 * (CRYPTO_SPEC §6.5 v2). The domain string embeds the suite identifier, so a
 * signature never transplants across suites (nor from the retired v1 form).
 * Callers must validate the context first (sign / verify below do); this
 * builder assumes valid input.
 */
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

/**
 * Signs one invite acceptance with the invitee's chain signing key
 * (Ed25519, CRYPTO_SPEC §6.5). The private key must correspond to
 * `context.inviteeSigPubHex` — verification only ever uses the declared
 * key. Returns the signature as lowercase hex (the wire form of
 * `acceptSignatureHex` in AUTH_SPEC §15-2).
 */
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

/**
 * Co-signs the same acceptance statement with the invite's link private key
 * (CRYPTO_SPEC §6.5 — the "holder of the link approves this key" half). The
 * private key must correspond to `context.linkPubHex`. Returns lowercase hex
 * (the wire form of `linkSignatureHex` in AUTH_SPEC §15-2).
 */
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
  // contextInvalidField already guarantees the hex form (an unreachable defensive line for decodeHex)
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

/**
 * Verifies the invitee's acceptance signature (CRYPTO_SPEC §6.5). The
 * verification key is imported from `context.inviteeSigPubHex` — the
 * declared key is the verification key, so a swapped signing key can never
 * validate. The server verifies at acceptance time with project_id /
 * link_pub reconstructed from the stored invitation row (AUTH_SPEC §15-2);
 * the inviter's client re-verifies before `add_member`.
 */
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

/**
 * Verifies the link co-signature (CRYPTO_SPEC §6.5). The verification key is
 * imported from `context.linkPubHex`. The inviter's client checks this
 * against the link public key it issued (its own issue signature over the
 * stored issuance statement — `invite-link.ts`), which is what makes a
 * server-side key swap cryptographically impossible.
 */
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
