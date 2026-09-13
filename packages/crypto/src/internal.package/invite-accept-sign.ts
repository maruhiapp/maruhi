// CRYPTO_SPEC §6.5(2026-09-13 IV 改訂 — v2): 招待受諾の共同署名(Ed25519)。
// signed_bytes = LP("<suite>/invite-accept-v2", project_id, link_pub_hex,
//                   invitee_user_id, invitee_enc_pub_hex, invitee_sig_pub_hex)
// suite の束縛はドメイン文字列が担う(§5.1 と同型)。バイナリ列は hex 小文字
// 文字列として LP に載せる(chain-entries の binary_encoding 規約)。
// link_pub_hex = 招待ごとのリンク鍵(invite-link.ts — 招待者クライアントが種から
// 導出し、種はリンクのフラグメントにのみ載る。サーバーは種を受け取らない)の公開鍵。
//
// 同一バイト列に 2 つの署名を付ける:
//   - 受諾署名(accept signature): 受諾者のチェーン sig 鍵。検証鍵は署名対象内の
//     invitee_sig_pub_hex(自己束縛 — 検証鍵を署名対象外から与える形は「宣言鍵と
//     検証鍵の不一致」を許すため作らない)。意味論は「この鍵ペアの保持者が、この
//     招待に対してこの鍵で参加する意思を表明した」の帰属・文脈束縛
//   - リンク署名(link signature): リンク鍵の秘密鍵。検証鍵は署名対象内の
//     link_pub_hex(同じく自己束縛)。意味論は「リンクを持つ者がこの鍵での受諾を
//     承認した」— サーバーはリンク秘密鍵を持たないため、受諾ブロックの鍵を差し替えて
//     有効なリンク署名を作ることが暗号的に不可能になる(IV1 の本体)
// 旧 v1(ドメイン "<suite>/invite-accept"、invite_token_hash_hex 束縛)は受け付けない
// (互換経路を作らない 2026-09-13 所有者裁定。旧ドメイン文字列は negative
// `legacy-domain` が検証失敗を固定する)。
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
  readonly projectId: string;
  /** The invite's link public key (Ed25519, lowercase hex — never the seed). */
  readonly linkPubHex: string;
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
  // contextInvalidField が hex 形式を保証済み(decodeHex は到達しない防衛線)
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
