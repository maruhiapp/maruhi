import { decodeHex, encodeHex, utf8Encode } from "./bytes.ts";
import type { ProjectId, UserId } from "./chain-types.ts";
import { encodeLengthPrefixed } from "./encoding.ts";
import type { CryptoResult } from "./errors.ts";
import { importSigningPublicKey } from "./keys.ts";
import {
  canonicalScopeEnvironmentsHex,
  type ScopePayloadFields,
  scopeShapeOk,
} from "./member-scope.ts";
import {
  invalidInput,
  isLowercaseHexOfLength,
  ROLE_RANK,
  signEd25519Over,
  verifyEd25519Over,
} from "./validate.ts";

const ED25519_KEY_BYTES = 32;
const PUB_KEY_HEX_LENGTH = ED25519_KEY_BYTES * 2;
const SHA256_HEX_LENGTH = 32 * 2;
export const INVITE_LINK_SEED_BYTES = 32;
const PKCS8_ED25519_PREFIX = Uint8Array.of(
  0x30,
  0x2e,
  0x02,
  0x01,
  0x00,
  0x30,
  0x05,
  0x06,
  0x03,
  0x2b,
  0x65,
  0x70,
  0x04,
  0x22,
  0x04,
  0x20,
);
const OPENSSH_ED25519_TYPE = "ssh-ed25519";

export function generateInviteLinkSeed(): Uint8Array {
  const seed = new Uint8Array(INVITE_LINK_SEED_BYTES);
  crypto.getRandomValues(seed);
  return seed;
}

export interface InviteLinkKeyPair {
  readonly publicKey: CryptoKey;
  readonly privateKey: CryptoKey;
  readonly publicKeyRaw: Uint8Array;
}

function base64UrlToBytes(value: string): Uint8Array | null {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/");
  const remainder = padded.length % 4;
  return base64Decode(remainder === 0 ? padded : padded + "=".repeat(4 - remainder));
}

export async function deriveInviteLinkKeyPair(
  seed: Uint8Array,
): Promise<CryptoResult<InviteLinkKeyPair>> {
  if (seed.length !== INVITE_LINK_SEED_BYTES) {
    return invalidInput("link seed length");
  }
  const der = new Uint8Array(PKCS8_ED25519_PREFIX.length + INVITE_LINK_SEED_BYTES);
  der.set(PKCS8_ED25519_PREFIX, 0);
  der.set(seed, PKCS8_ED25519_PREFIX.length);
  try {
    const probe = await crypto.subtle.importKey("pkcs8", der as BufferSource, "Ed25519", true, [
      "sign",
    ]);
    const jwk = await crypto.subtle.exportKey("jwk", probe);
    const publicKeyRaw = typeof jwk.x === "string" ? base64UrlToBytes(jwk.x) : null;
    if (publicKeyRaw === null || publicKeyRaw.length !== ED25519_KEY_BYTES) {
      return { ok: false, error: { kind: "KeyImportFailed", key: "signing-private" } };
    }
    const publicKey = await importSigningPublicKey(publicKeyRaw);
    if (!publicKey.ok) {
      return publicKey;
    }
    const privateKey = await crypto.subtle.importKey(
      "pkcs8",
      der as BufferSource,
      "Ed25519",
      false,
      ["sign"],
    );
    return { ok: true, value: { publicKey: publicKey.value, privateKey, publicKeyRaw } };
  } catch {
    return { ok: false, error: { kind: "KeyImportFailed", key: "signing-private" } };
  }
}

export interface InviteIssueContext extends ScopePayloadFields {
  readonly suite: string;
  readonly inviteId: string;
  readonly projectId: ProjectId;
  readonly linkPubHex: string;
  readonly headHashHex: string;
  readonly headSeq: number;
  readonly role: string;
  readonly inviterUserId: UserId;
  readonly inviterEncPubHex: string;
  readonly inviterSigPubHex: string;
}

function issueContextTextInvalidField(context: InviteIssueContext): string | null {
  if (context.suite.length === 0) {
    return "context suite";
  }
  if (context.inviteId.length === 0) {
    return "context inviteId";
  }
  if (!Object.hasOwn(ROLE_RANK, context.role)) {
    return "context role";
  }
  if (context.inviterUserId.length === 0) {
    return "context inviterUserId";
  }
  if (!scopeShapeOk(context.scopeKind, context.scopeEnvironmentIds, isBoundedEnvironmentId)) {
    return "context scope";
  }
  return null;
}

const MAX_ENVIRONMENT_ID_BYTES = 1024;

function isBoundedEnvironmentId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_ENVIRONMENT_ID_BYTES &&
    utf8Encode(value).length <= MAX_ENVIRONMENT_ID_BYTES
  );
}

function issueContextBinaryInvalidField(context: InviteIssueContext): string | null {
  const hexFields: readonly (readonly [string, string, number])[] = [
    ["context linkPubHex", context.linkPubHex, PUB_KEY_HEX_LENGTH],
    ["context headHashHex", context.headHashHex, SHA256_HEX_LENGTH],
    ["context inviterEncPubHex", context.inviterEncPubHex, PUB_KEY_HEX_LENGTH],
    ["context inviterSigPubHex", context.inviterSigPubHex, PUB_KEY_HEX_LENGTH],
  ];
  for (const [name, value, length] of hexFields) {
    if (!isLowercaseHexOfLength(value, length)) {
      return name;
    }
  }
  if (!Number.isSafeInteger(context.headSeq) || context.headSeq < 1) {
    return "context headSeq";
  }
  return null;
}

function issueContextInvalidField(context: InviteIssueContext): string | null {
  return issueContextTextInvalidField(context) ?? issueContextBinaryInvalidField(context);
}

export function buildInviteIssueSignedBytes(context: InviteIssueContext): Uint8Array {
  return encodeLengthPrefixed([
    `${context.suite}/invite-issue`,
    context.inviteId,
    context.projectId,
    context.linkPubHex,
    context.headHashHex,
    context.headSeq,
    context.role,
    context.inviterUserId,
    context.inviterEncPubHex,
    context.inviterSigPubHex,
    context.scopeKind,
    canonicalScopeEnvironmentsHex(context.scopeEnvironmentIds),
  ]);
}

export async function signInviteIssue(input: {
  readonly context: InviteIssueContext;
  readonly signingKey: CryptoKey;
}): Promise<CryptoResult<string>> {
  const field = issueContextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  return signEd25519Over(buildInviteIssueSignedBytes(input.context), input.signingKey);
}

export async function verifyInviteIssueSignature(input: {
  readonly context: InviteIssueContext;
  readonly signatureHex: string;
}): Promise<CryptoResult<void>> {
  const field = issueContextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  const keyBytes = decodeHex(input.context.inviterSigPubHex);
  if (keyBytes === null) {
    return invalidInput("context inviterSigPubHex");
  }
  const publicKey = await importSigningPublicKey(keyBytes);
  if (!publicKey.ok) {
    return publicKey;
  }
  return verifyEd25519Over(
    buildInviteIssueSignedBytes(input.context),
    input.signatureHex,
    publicKey.value,
    { kind: "InviteIssueSignatureInvalid" },
  );
}

function base64Encode(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary);
}

function base64Decode(text: string): Uint8Array | null {
  if (text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) {
    return null;
  }
  try {
    const binary = atob(text);
    return Uint8Array.from(binary, (ch) => ch.charCodeAt(0));
  } catch {
    return null;
  }
}

export function encodeOpenSshEd25519PublicKey(publicKey: Uint8Array): CryptoResult<string> {
  if (publicKey.length !== ED25519_KEY_BYTES) {
    return invalidInput("signing public key length");
  }
  const blob = encodeLengthPrefixed([OPENSSH_ED25519_TYPE, publicKey]);
  return { ok: true, value: `${OPENSSH_ED25519_TYPE} ${base64Encode(blob)}` };
}

export function parseOpenSshEd25519PublicKey(line: string): CryptoResult<Uint8Array> {
  if (typeof line !== "string") {
    return invalidInput("openssh public key line");
  }
  const parts = line.trimEnd().split(" ");
  const type = parts[0];
  const encoded = parts[1];
  const expectedType = utf8Encode(OPENSSH_ED25519_TYPE);
  const expectedLength = 4 + expectedType.length + 4 + ED25519_KEY_BYTES;
  const expectedEncodedLength = Math.ceil(expectedLength / 3) * 4;
  if (
    type !== OPENSSH_ED25519_TYPE ||
    encoded === undefined ||
    encoded.length !== expectedEncodedLength
  ) {
    return invalidInput("openssh public key line");
  }
  const blob = base64Decode(encoded);
  if (blob === null || blob.length !== expectedLength) {
    return invalidInput("openssh public key line");
  }
  const view = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  if (view.getUint32(0, false) !== expectedType.length) {
    return invalidInput("openssh public key line");
  }
  const typeBytes = blob.subarray(4, 4 + expectedType.length);
  if (encodeHex(typeBytes) !== encodeHex(expectedType)) {
    return invalidInput("openssh public key line");
  }
  if (view.getUint32(4 + expectedType.length, false) !== ED25519_KEY_BYTES) {
    return invalidInput("openssh public key line");
  }
  return { ok: true, value: blob.slice(8 + expectedType.length) };
}
