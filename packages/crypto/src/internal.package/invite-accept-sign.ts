// CRYPTO_SPEC §6.5: 招待受諾署名(Ed25519)。
// signed_bytes = LP("<suite>/invite-accept", project_id, invite_token_hash_hex,
//                   invitee_user_id, invitee_enc_pub_hex, invitee_sig_pub_hex)
// suite の束縛はドメイン文字列が担う(§5.1 と同型)。バイナリ列は hex 小文字
// 文字列として LP に載せる(chain-entries の binary_encoding 規約)。
// invite_token_hash_hex = 招待トークン(256-bit 乱数)の SHA-256 — トークン
// 生値は署名対象にもサーバー保存にも載せない(AUTH_SPEC §15)。
//
// 意味論は「この鍵ペアの保持者が、この招待に対してこの鍵で参加する意思を
// 表明した」の帰属・文脈束縛(§6.5)。検証鍵は署名対象自身が運ぶ
// invitee_sig_pub_hex から導く(自己束縛): 検証鍵を署名対象外から与える形は
// 「宣言鍵と検証鍵の不一致」を許すため、API として作らない。
// チェーン有効性の合意規則には含めない(チェーン外の追加証跡 — §6.5)。
// テストベクター: test-vectors/invite-accept-signature.json

import { decodeHex } from "./bytes.ts";
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
const TOKEN_HASH_HEX_LENGTH = 32 * 2;

/**
 * Fields bound by an invite-acceptance signature (CRYPTO_SPEC §6.5): the
 * invite coordinates (project, token hash) and the invitee's identity and
 * full public key set. Binary values are carried as lowercase hex strings,
 * exactly as on the wire. The signature must verify under
 * `inviteeSigPubHex` — the declared key is the verification key.
 */
export interface InviteAcceptSignatureContext {
  readonly suite: string;
  readonly projectId: string;
  /** SHA-256 of the raw invite token, lowercase hex (never the raw token). */
  readonly inviteTokenHashHex: string;
  /** The acceptor's internal user id (the server requires caller == invitee). */
  readonly inviteeUserId: string;
  readonly inviteeEncPubHex: string;
  readonly inviteeSigPubHex: string;
}

// 署名対象の構造検証: hex フィールドは小文字・固定長(大文字 hex を許すと
// 同一受諾に複数の正規形が生まれ、署名の一意性が壊れる — validate.ts の規律)。
// suite / invitee_user_id は非空。project_id は自由形式の bounded string
// (ベクターは任意形式 — AUTH_SPEC §11-1 の ID 形式非依存と同じ姿勢)
function contextInvalidField(context: InviteAcceptSignatureContext): string | null {
  if (context.suite.length === 0) {
    return "context suite";
  }
  if (context.inviteeUserId.length === 0) {
    return "context inviteeUserId";
  }
  if (!isLowercaseHexOfLength(context.inviteTokenHashHex, TOKEN_HASH_HEX_LENGTH)) {
    return "context inviteTokenHashHex";
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
 * Builds the canonical byte string signed for one invite acceptance
 * (CRYPTO_SPEC §6.5). The domain string embeds the suite identifier, so a
 * signature never transplants across suites. Callers must validate the
 * context first (sign / verify below do); this builder assumes valid input.
 */
export function buildInviteAcceptSignedBytes(context: InviteAcceptSignatureContext): Uint8Array {
  return encodeLengthPrefixed([
    `${context.suite}/invite-accept`,
    context.projectId,
    context.inviteTokenHashHex,
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
 * `signatureHex` in AUTH_SPEC §15-2).
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
 * Verifies one invite-acceptance signature (CRYPTO_SPEC §6.5). The
 * verification key is imported from `context.inviteeSigPubHex` — the
 * declared key is the verification key, so a swapped signing key can never
 * validate. The server verifies at acceptance time with project_id /
 * token hash reconstructed from the stored invitation row (AUTH_SPEC
 * §15-2); the inviter's client re-verifies before `add_member`.
 */
export async function verifyInviteAcceptSignature(input: {
  readonly context: InviteAcceptSignatureContext;
  readonly signatureHex: string;
}): Promise<CryptoResult<void>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  // contextInvalidField が hex 形式を保証済み(decodeHex は到達しない防衛線)
  const keyBytes = decodeHex(input.context.inviteeSigPubHex);
  if (keyBytes === null) {
    return invalidInput("context inviteeSigPubHex");
  }
  const publicKey = await importSigningPublicKey(keyBytes);
  if (!publicKey.ok) {
    return publicKey;
  }
  return verifyEd25519Over(
    buildInviteAcceptSignedBytes(input.context),
    input.signatureHex,
    publicKey.value,
    {
      kind: "InviteAcceptSignatureInvalid",
    },
  );
}
