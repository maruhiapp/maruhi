// CRYPTO_SPEC §6.5(2026-09-13 IV): リンク鍵・発行文と発行署名・OpenSSH 公開鍵行。
//
// - リンク鍵: 招待ごとに招待者クライアントが生成する 32 バイトの種 k を RFC 8032 の
//   seed とする Ed25519 鍵ペア。種はリンクのフラグメントにのみ載り(サーバーは
//   受け取らない)、公開鍵は発行文としてサーバー行に置く。WebCrypto は Ed25519 の
//   seed 単独 import を持たないため、RFC 8410 の OneAsymmetricKey(PKCS#8)固定
//   プレフィックス + seed を pkcs8 として import し、公開鍵は JWK の x から読む
//   (keys.ts の exportSigningPrivateSeed と同じ手口の逆方向)。これは符号化であり
//   新しい鍵導出ではない(seed → 鍵ペアは §3 の署名鍵と同じ)
// - 発行署名: 招待者のチェーン sig 鍵による発行文の署名。
//   invite_issue_signed_bytes = LP("<suite>/invite-issue", invite_id, project_id,
//     link_pub_hex, head_hash_hex, head_seq, role, inviter_user_id,
//     inviter_enc_pub_hex, inviter_sig_pub_hex, scope_kind, scope_environments_lp_hex)
//   (scope の 2 フィールドは 2026-09-14 ES で末尾に追加 — §6.2 と同じ符号化。
//   受諾者は「どの環境に入るか」を受諾前に読み、招待者は発行時に同意の範囲を固定する)
//   検証鍵は署名対象内の inviter_sig_pub_hex(自己束縛)。受諾者はリンクで受け取った
//   発行文を検証し(ゴースト追加者は招待者名義の署名を作れない)、招待者は
//   サーバー行の発行文を**自分の鍵で**検証して「自分が発行した行か」を確かめる
//   (発行ピンに依存しない — 補足 21 裁定 A ⑦)
// - OpenSSH 公開鍵行: "ssh-ed25519 " + base64(uint32-BE 長さ ‖ "ssh-ed25519" ‖
//   uint32-BE 長さ ‖ 32 バイト鍵)(RFC 4253 §6.6 / RFC 8709)。裏付け元 = GitHub の
//   SSH 署名鍵一覧との相互運用のための符号化であり、新しい暗号プリミティブでは
//   ない(§3 の FP ワード・§8.4 のハンドオフコードと同じ位置づけ)。解析は
//   第三者データ(GitHub 応答)の復号なのでテストベクターで受理境界を固定する
// テストベクター: test-vectors/invite-link.json

import { decodeHex, encodeHex, utf8Encode } from "./bytes.ts";
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
/** Link seed = RFC 8032 Ed25519 private key seed (32 bytes). */
export const INVITE_LINK_SEED_BYTES = 32;
/**
 * RFC 8410 OneAsymmetricKey (PKCS#8 v1) prefix for an Ed25519 private key; the
 * 32-byte seed follows. Spelled out as bytes so a typo cannot degrade to an
 * empty prefix: SEQUENCE(46) { INTEGER 0, SEQUENCE { OID 1.3.101.112 },
 * OCTET STRING(34) { OCTET STRING(32) ... } }.
 */
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

/** Generates a fresh 32-byte link seed (CRYPTO_SPEC §6.5). Lives only in the link. */
export function generateInviteLinkSeed(): Uint8Array {
  const seed = new Uint8Array(INVITE_LINK_SEED_BYTES);
  crypto.getRandomValues(seed);
  return seed;
}

/** The link key pair derived from a seed; `publicKeyRaw` is the wire form (`linkPubHex` = hex of it). */
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

/**
 * Derives the Ed25519 link key pair from its 32-byte seed (CRYPTO_SPEC §6.5).
 * The returned private key is non-extractable; the public key is also
 * returned raw for the wire (`linkPubHex`). Test vector: `invite-link.json`
 * `link_key` (seed → expected public key).
 */
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
    // 公開鍵の取り出しにだけ抽出可能な一時 import を使い、署名鍵は非抽出で別途 import。
    // WebCrypto には「種 → 公開鍵」の直接経路が無いため、この JWK は `d`(= 種。
    // 呼び出し側が既に持つ値)も運ぶ — `x` だけ読んで捨てる。返す privateKey は
    // 非抽出
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

// ---------------------------------------------------------------------------
// 発行文と発行署名

/**
 * Fields bound by the inviter's issue signature (CRYPTO_SPEC §6.5): the
 * invite id, the invite coordinates (project, link public key), the
 * inviter's verified chain head (the §6.3 (a) anchor), the (role, scope) to be
 * granted (scope as the two trailing §6.2 fields — 2026-09-14 ES), and the
 * inviter's identity and full public key set. Binary values are lowercase
 * hex; `headSeq` is a positive safe integer. The signature must verify under
 * `inviterSigPubHex` — the declared key is the verification key.
 */
export interface InviteIssueContext extends ScopePayloadFields {
  readonly suite: string;
  readonly inviteId: string;
  readonly projectId: string;
  readonly linkPubHex: string;
  readonly headHashHex: string;
  readonly headSeq: number;
  readonly role: string;
  readonly inviterUserId: string;
  readonly inviterEncPubHex: string;
  readonly inviterSigPubHex: string;
}

/** 文字列フィールドの検査(非空・閉集合)。 */
function issueContextTextInvalidField(context: InviteIssueContext): string | null {
  if (context.suite.length === 0) {
    return "context suite";
  }
  if (context.inviteId.length === 0) {
    return "context inviteId";
  }
  // role は §6.2 の閉集合(綴り違いが別の有効な署名にならないよう正規形だけを署名する)
  if (!Object.hasOwn(ROLE_RANK, context.role)) {
    return "context role";
  }
  if (context.inviterUserId.length === 0) {
    return "context inviterUserId";
  }
  // scope は §6.2 の構造規則(閉集合の kind・all ⇒ 空リスト・256 以下・重複なし)
  if (!scopeShapeOk(context.scopeKind, context.scopeEnvironmentIds, isNonEmptyString)) {
    return "context scope";
  }
  return null;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

/** 公開値(hex)と head_seq の形式検査。 */
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

/**
 * Builds the canonical byte string signed for one invite issuance
 * (CRYPTO_SPEC §6.5). Callers must validate the context first (sign /
 * verify below do); this builder assumes valid input.
 */
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

/**
 * Signs one invite issuance with the inviter's chain signing key (Ed25519).
 * The private key must correspond to `context.inviterSigPubHex`. Returns
 * lowercase hex (the `sig=` link parameter and `issueSignatureHex` on the
 * wire — AUTH_SPEC §15-2 / §15-3).
 */
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

/**
 * Verifies an invite issue signature (CRYPTO_SPEC §6.5) under the declared
 * `context.inviterSigPubHex`. This proves only that the statement is
 * self-consistent with the key named in `context`, so what the caller puts in
 * `context` decides what is proven. The acceptor fills the inviter fields
 * from the link (`ie` / `is`) and verifies before anything else. The inviter
 * MUST fill `inviterUserId` / `inviterEncPubHex` / `inviterSigPubHex` from its
 * own key or the verified membership chain — never from the server row — so
 * that a passing check proves the row is its own issuance without a local pin.
 */
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

// ---------------------------------------------------------------------------
// OpenSSH 公開鍵行(RFC 4253 §6.6 / RFC 8709)

/** Standard base64 (RFC 4648 §4) via the Web platform `btoa` (keys.ts と同じ経路)。 */
function base64Encode(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary);
}

/**
 * Strict standard base64 (RFC 4648 §4): alphabet only, `=` padding only at the
 * end, length % 4 == 0. `atob` is lenient (whitespace, missing padding), so the
 * shape is checked first and `atob` only performs the decoding.
 */
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

/**
 * Encodes a raw 32-byte Ed25519 public key as an OpenSSH public key line
 * (`ssh-ed25519 <base64 blob>`, no comment) — the form GitHub accepts as an
 * SSH signing key and returns from `ssh_signing_keys` (CRYPTO_SPEC §6.5).
 */
export function encodeOpenSshEd25519PublicKey(publicKey: Uint8Array): CryptoResult<string> {
  if (publicKey.length !== ED25519_KEY_BYTES) {
    return invalidInput("signing public key length");
  }
  const blob = encodeLengthPrefixed([OPENSSH_ED25519_TYPE, publicKey]);
  return { ok: true, value: `${OPENSSH_ED25519_TYPE} ${base64Encode(blob)}` };
}

/**
 * Parses one OpenSSH public key line and returns the raw 32-byte Ed25519
 * key. Accepts only `ssh-ed25519` (an optional comment and trailing
 * whitespace are ignored); every other key type, a length mismatch, a blob
 * whose inner type string disagrees, trailing bytes, or malformed base64 is
 * `InvalidInput` — third-party data (a GitHub response) is never guessed at.
 */
export function parseOpenSshEd25519PublicKey(line: string): CryptoResult<Uint8Array> {
  // 第三者データ(JSON)の実行時の型ずれは例外にせず InvalidInput(bytes.ts の decodeHex と同じ規律)
  if (typeof line !== "string") {
    return invalidInput("openssh public key line");
  }
  const parts = line.trimEnd().split(" ");
  const type = parts[0];
  const encoded = parts[1];
  const expectedType = utf8Encode(OPENSSH_ED25519_TYPE);
  const expectedLength = 4 + expectedType.length + 4 + ED25519_KEY_BYTES;
  // 正しい blob は 51 バイト = base64 で 68 文字(パディングなし)。長さが違う入力は
  // 復号せずに拒否する(巨大な文字列を丸ごと復号しない)
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
