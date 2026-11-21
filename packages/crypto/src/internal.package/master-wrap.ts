import { encodeHex } from "./bytes.ts";
import type { UserId } from "./chain-types.ts";
import type { WrappedDek } from "./dek-wrap.ts";
import { encodeLengthPrefixed } from "./encoding.ts";
import type { CryptoError, CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import { hpkeSuite } from "./hpke.ts";
import type { EncryptionKey, EncryptionKeyPair } from "./keys.ts";
import type { WrappedMasterSecret } from "./recovery.ts";
import { SUITE_ID } from "./suite.ts";

const MASTER_WRAP_DOMAIN = `${SUITE_ID}/master-wrap`;
const PASSKEY_HKDF_INFO = `${SUITE_ID}/passkey-prf`;
const GUARDIAN_WRAP_DOMAIN = `${SUITE_ID}/guardian-wrap`;
const HANDOFF_WRAP_DOMAIN = `${SUITE_ID}/handoff-wrap`;
const HANDOFF_ID_DOMAIN = `${SUITE_ID}/handoff-id`;

const KEK_BYTES = 32;
const PRF_OUTPUT_BYTES = 32;
const NONCE_BYTES = 12;
const X25519_PUBLIC_KEY_BYTES = 32;
const HANDOFF_CODE_CHECKSUM_BYTES = 4;
const HANDOFF_CODE_PAYLOAD_BYTES = X25519_PUBLIC_KEY_BYTES + HANDOFF_CODE_CHECKSUM_BYTES;
const HANDOFF_CODE_SYMBOLS = Math.ceil((HANDOFF_CODE_PAYLOAD_BYTES * 8) / 5);
const HANDOFF_CODE_GROUP = 4;
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const MAX_SHARES = 5;

export type MasterWrapKind = "passkey-prf" | "guardian";

export type GuardianMode = "any" | "all";

export interface MasterWrapContext {
  readonly userId: UserId;
  readonly kind: MasterWrapKind;
  readonly wrapRef: string;
  readonly mode?: GuardianMode | undefined;
}

export interface GuardianWrapContext {
  readonly userId: UserId;
  readonly groupId: string;
  readonly mode: GuardianMode;
  readonly shareIndex: number;
  readonly guardianUserId: UserId;
}

export interface HandoffWrapContext {
  readonly userId: UserId;
  readonly requestId: string;
  readonly source: string;
  readonly shareIndex: number;
  readonly approverUserId: UserId;
}

function invalidInput(field: string): { readonly ok: false; readonly error: CryptoError } {
  return { ok: false, error: { kind: "InvalidInput", field } };
}

function isShareIndex(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

function masterWrapContextInvalidField(context: MasterWrapContext): string | null {
  if (context.kind === "guardian") {
    if (context.mode !== "any" && context.mode !== "all") {
      return "context mode";
    }
  } else if (context.mode !== undefined) {
    return "context mode";
  }
  return null;
}

export function buildMasterWrapAad(context: MasterWrapContext): Uint8Array {
  return encodeLengthPrefixed([
    MASTER_WRAP_DOMAIN,
    context.userId,
    context.kind,
    context.wrapRef,
    context.kind === "guardian" ? (context.mode ?? "") : "",
  ]);
}

export async function derivePasskeyKek(prfOutput: Uint8Array): Promise<CryptoResult<Uint8Array>> {
  if (prfOutput.length !== PRF_OUTPUT_BYTES) {
    return invalidInput("prf output length");
  }
  try {
    const ikm = await crypto.subtle.importKey("raw", prfOutput as BufferSource, "HKDF", false, [
      "deriveBits",
    ]);
    const bits = await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(0),
        info: new TextEncoder().encode(PASSKEY_HKDF_INFO) as BufferSource,
      },
      ikm,
      KEK_BYTES * 8,
    );
    return { ok: true, value: new Uint8Array(bits) };
  } catch {
    return { ok: false, error: { kind: "EncryptFailed", operation: "master-wrap" } };
  }
}

export function generateMasterWrapKek(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(KEK_BYTES));
}

async function importKek(kek: Uint8Array, usage: "encrypt" | "decrypt"): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", kek as BufferSource, "AES-GCM", false, [usage]);
}

export async function wrapMasterBlob(input: {
  readonly kek: Uint8Array;
  readonly masterSecretBlob: Uint8Array;
  readonly context: MasterWrapContext;
}): Promise<CryptoResult<WrappedMasterSecret>> {
  if (input.kek.length !== KEK_BYTES) {
    return invalidInput("kek length");
  }
  const invalid = masterWrapContextInvalidField(input.context);
  if (invalid !== null) {
    return invalidInput(invalid);
  }
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  try {
    const key = await importKek(input.kek, "encrypt");
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: nonce as BufferSource,
          additionalData: buildMasterWrapAad(input.context) as BufferSource,
        },
        key,
        input.masterSecretBlob as BufferSource,
      ),
    );
    return { ok: true, value: { nonce, ciphertext } };
  } catch {
    return { ok: false, error: { kind: "EncryptFailed", operation: "master-wrap" } };
  }
}

export async function unwrapMasterBlob(input: {
  readonly kek: Uint8Array;
  readonly wrapped: WrappedMasterSecret;
  readonly context: MasterWrapContext;
}): Promise<CryptoResult<Uint8Array>> {
  if (input.kek.length !== KEK_BYTES) {
    return invalidInput("kek length");
  }
  if (input.wrapped.nonce.length !== NONCE_BYTES) {
    return invalidInput("nonce length");
  }
  const invalid = masterWrapContextInvalidField(input.context);
  if (invalid !== null) {
    return invalidInput(invalid);
  }
  try {
    const key = await importKek(input.kek, "decrypt");
    const blob = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: input.wrapped.nonce as BufferSource,
          additionalData: buildMasterWrapAad(input.context) as BufferSource,
        },
        key,
        input.wrapped.ciphertext as BufferSource,
      ),
    );
    return { ok: true, value: blob };
  } catch {
    return { ok: false, error: { kind: "DecryptFailed", operation: "master-wrap" } };
  }
}

function xorInto(target: Uint8Array, source: Uint8Array): void {
  for (let i = 0; i < target.length; i++) {
    target[i] = (target[i] ?? 0) ^ (source[i] ?? 0);
  }
}

export function splitGuardianKek(input: {
  readonly kek: Uint8Array;
  readonly mode: GuardianMode;
  readonly count: number;
}): CryptoResult<readonly Uint8Array[]> {
  if (input.kek.length !== KEK_BYTES) {
    return invalidInput("kek length");
  }
  if (!Number.isSafeInteger(input.count) || input.count < 1 || input.count > MAX_SHARES) {
    return invalidInput("share count");
  }
  if (input.mode === "any") {
    return {
      ok: true,
      value: Array.from({ length: input.count }, () => Uint8Array.from(input.kek)),
    };
  }
  if (input.mode !== "all") {
    return invalidInput("mode");
  }
  if (input.count < 2) {
    return invalidInput("share count");
  }
  const shares: Uint8Array[] = [];
  const last = Uint8Array.from(input.kek);
  for (let i = 0; i < input.count - 1; i++) {
    const share = crypto.getRandomValues(new Uint8Array(KEK_BYTES));
    xorInto(last, share);
    shares.push(share);
  }
  shares.push(last);
  return { ok: true, value: shares };
}

export function joinGuardianShares(input: {
  readonly mode: GuardianMode;
  readonly shares: readonly Uint8Array[];
  readonly expectedCount: number;
}): CryptoResult<Uint8Array> {
  if (
    !Number.isSafeInteger(input.expectedCount) ||
    input.expectedCount < 1 ||
    input.expectedCount > MAX_SHARES
  ) {
    return invalidInput("share count");
  }
  if (input.shares.some((share) => share.length !== KEK_BYTES)) {
    return invalidInput("share length");
  }
  if (input.mode === "any") {
    const [only] = input.shares;
    if (input.shares.length !== 1 || only === undefined) {
      return invalidInput("share count");
    }
    return { ok: true, value: Uint8Array.from(only) };
  }
  if (input.mode !== "all") {
    return invalidInput("mode");
  }
  if (input.shares.length !== input.expectedCount || input.expectedCount < 2) {
    return invalidInput("share count");
  }
  const kek = new Uint8Array(KEK_BYTES);
  for (const share of input.shares) {
    xorInto(kek, share);
  }
  return { ok: true, value: kek };
}

function guardianContextInvalidField(context: GuardianWrapContext): string | null {
  if (context.mode !== "any" && context.mode !== "all") {
    return "context mode";
  }
  if (!isShareIndex(context.shareIndex) || context.shareIndex < 1) {
    return "context shareIndex";
  }
  return null;
}

export function buildGuardianWrapInfo(context: GuardianWrapContext): Uint8Array {
  return encodeLengthPrefixed([
    GUARDIAN_WRAP_DOMAIN,
    context.userId,
    context.groupId,
    context.mode,
    context.shareIndex,
    context.guardianUserId,
  ]);
}

export async function sealGuardianShare(input: {
  readonly guardianPublicKey: EncryptionKey;
  readonly share: Uint8Array;
  readonly context: GuardianWrapContext;
}): Promise<CryptoResult<WrappedDek>> {
  if (input.share.length !== KEK_BYTES) {
    return invalidInput("share length");
  }
  const invalid = guardianContextInvalidField(input.context);
  if (invalid !== null) {
    return invalidInput(invalid);
  }
  try {
    const { encapsulatedSecret, ciphertext } = await hpkeSuite().Seal(
      input.guardianPublicKey,
      input.share,
      { info: buildGuardianWrapInfo(input.context) },
    );
    return { ok: true, value: { enc: encapsulatedSecret, ciphertext } };
  } catch {
    return { ok: false, error: { kind: "DekWrapFailed" } };
  }
}

export async function openGuardianShare(input: {
  readonly guardianKeyPair: EncryptionKeyPair;
  readonly wrapped: WrappedDek;
  readonly context: GuardianWrapContext;
}): Promise<CryptoResult<Uint8Array>> {
  const invalid = guardianContextInvalidField(input.context);
  if (invalid !== null) {
    return invalidInput(invalid);
  }
  try {
    const share = await hpkeSuite().Open(
      input.guardianKeyPair,
      input.wrapped.enc,
      input.wrapped.ciphertext,
      { info: buildGuardianWrapInfo(input.context) },
    );
    if (share.length !== KEK_BYTES) {
      return { ok: false, error: { kind: "DekUnwrapFailed" } };
    }
    return { ok: true, value: share };
  } catch {
    return { ok: false, error: { kind: "DekUnwrapFailed" } };
  }
}

function handoffContextInvalidField(context: HandoffWrapContext): string | null {
  if (!isShareIndex(context.shareIndex)) {
    return "context shareIndex";
  }
  if (context.source.length === 0) {
    return "context source";
  }
  return null;
}

export function buildHandoffWrapInfo(context: HandoffWrapContext): Uint8Array {
  return encodeLengthPrefixed([
    HANDOFF_WRAP_DOMAIN,
    context.userId,
    context.requestId,
    context.source,
    context.shareIndex,
    context.approverUserId,
  ]);
}

export async function sealHandoffValue(input: {
  readonly ephemeralPublicKey: EncryptionKey;
  readonly value: Uint8Array;
  readonly context: HandoffWrapContext;
}): Promise<CryptoResult<WrappedDek>> {
  if (input.value.length !== KEK_BYTES) {
    return invalidInput("value length");
  }
  const invalid = handoffContextInvalidField(input.context);
  if (invalid !== null) {
    return invalidInput(invalid);
  }
  try {
    const { encapsulatedSecret, ciphertext } = await hpkeSuite().Seal(
      input.ephemeralPublicKey,
      input.value,
      { info: buildHandoffWrapInfo(input.context) },
    );
    return { ok: true, value: { enc: encapsulatedSecret, ciphertext } };
  } catch {
    return { ok: false, error: { kind: "DekWrapFailed" } };
  }
}

export async function openHandoffValue(input: {
  readonly ephemeralKeyPair: EncryptionKeyPair;
  readonly wrapped: WrappedDek;
  readonly context: HandoffWrapContext;
}): Promise<CryptoResult<Uint8Array>> {
  const invalid = handoffContextInvalidField(input.context);
  if (invalid !== null) {
    return invalidInput(invalid);
  }
  try {
    const value = await hpkeSuite().Open(
      input.ephemeralKeyPair,
      input.wrapped.enc,
      input.wrapped.ciphertext,
      { info: buildHandoffWrapInfo(input.context) },
    );
    if (value.length !== KEK_BYTES) {
      return { ok: false, error: { kind: "DekUnwrapFailed" } };
    }
    return { ok: true, value };
  } catch {
    return { ok: false, error: { kind: "DekUnwrapFailed" } };
  }
}

export async function computeHandoffRequestId(
  ephemeralPublicKey: Uint8Array,
): Promise<CryptoResult<string>> {
  if (ephemeralPublicKey.length !== X25519_PUBLIC_KEY_BYTES) {
    return invalidInput("ephemeral public key length");
  }
  const preimage = encodeLengthPrefixed([HANDOFF_ID_DOMAIN, encodeHex(ephemeralPublicKey)]);
  return { ok: true, value: encodeHex(await sha256(preimage)) };
}

function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let acc = 0;
  let out = "";
  for (const byte of bytes) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32_ALPHABET[(acc >> bits) & 0b11111];
      acc &= (1 << bits) - 1;
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(acc << (5 - bits)) & 0b11111];
  }
  return out;
}

export async function encodeHandoffCode(
  ephemeralPublicKey: Uint8Array,
): Promise<CryptoResult<string>> {
  if (ephemeralPublicKey.length !== X25519_PUBLIC_KEY_BYTES) {
    return invalidInput("ephemeral public key length");
  }
  const payload = new Uint8Array(HANDOFF_CODE_PAYLOAD_BYTES);
  payload.set(ephemeralPublicKey, 0);
  payload.set(
    (await sha256(ephemeralPublicKey)).slice(0, HANDOFF_CODE_CHECKSUM_BYTES),
    X25519_PUBLIC_KEY_BYTES,
  );
  const symbols = base32Encode(payload);
  const groups: string[] = [];
  for (let i = 0; i < symbols.length; i += HANDOFF_CODE_GROUP) {
    groups.push(symbols.slice(i, i + HANDOFF_CODE_GROUP));
  }
  return { ok: true, value: groups.join("-") };
}

export async function decodeHandoffCode(text: string): Promise<CryptoResult<Uint8Array>> {
  const symbols = text.replace(/[\s-]/g, "").toUpperCase();
  if (symbols.length !== HANDOFF_CODE_SYMBOLS) {
    return invalidInput("handoff code");
  }
  const payload = new Uint8Array(HANDOFF_CODE_PAYLOAD_BYTES);
  let bits = 0;
  let acc = 0;
  let offset = 0;
  for (const symbol of symbols) {
    const value = BASE32_ALPHABET.indexOf(symbol);
    if (value < 0) {
      return invalidInput("handoff code");
    }
    acc = (acc << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      payload[offset] = (acc >> bits) & 0xff;
      offset += 1;
      acc &= (1 << bits) - 1;
    }
  }
  if (acc !== 0 || offset !== HANDOFF_CODE_PAYLOAD_BYTES) {
    return invalidInput("handoff code");
  }
  const publicKey = payload.slice(0, X25519_PUBLIC_KEY_BYTES);
  const expected = (await sha256(publicKey)).slice(0, HANDOFF_CODE_CHECKSUM_BYTES);
  const actual = payload.slice(X25519_PUBLIC_KEY_BYTES);
  let diff = 0;
  for (let i = 0; i < HANDOFF_CODE_CHECKSUM_BYTES; i++) {
    diff |= (expected[i] ?? 0) ^ (actual[i] ?? 0);
  }
  if (diff !== 0) {
    return invalidInput("handoff code");
  }
  return { ok: true, value: publicKey };
}
