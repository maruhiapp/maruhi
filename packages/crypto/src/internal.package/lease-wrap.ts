// CRYPTO_SPEC §9.1: ワークロードリースのリースラップ(HPKE Base mode 単発
// Seal / Open — §5 と**同一プリミティブ**。新しいプリミティブは導入しない)。
//
//   info = LP("<suite>/lease-wrap", project_id, environment_id, epoch,
//             claims_digest_hex)
//   claims_digest_hex = lower_hex(SHA-256(LP("<suite>/lease-claims",
//                                            issuer_url, subject, audience)))
//
// §5 の永続ラップとの違いは 2 点だけ:
//   1. info の recipient 位置が「受信者の同定子(user_id / サーバー鍵 FP)」では
//      なく claims_digest。受信者はワークロードがメモリ内で生成する一時鍵であり
//      チェーン上に同定子を持たないため、束縛対象を「どのワークロード文脈へ
//      発行したか」= 検証済み OIDC トークンの issuer / sub / aud に置き換える。
//      サーバーとワークロードが独立に同じ値を計算でき、リース応答の別ジョブへの
//      転用は復号失敗になる(設計原則 3 の一貫適用)
//   2. ドメイン文字列が `<suite>/lease-wrap`。§5 の `<suite>/dek-wrap` との
//      ドメイン分離により、永続ラップとリースラップは相互に移植できない
//
// リースラップは**永続化しない**(dek_wraps に入らない — §9.1)。応答スコープに
// のみ存在するため、§5.1 の登録署名は伴わない(署名者はチェーン上のメンバーで
// あり、サーバー生成のラップに帰属署名は存在しえない)。
//
// aad は §5 と同じく空(文脈束縛は info が担う)。
// テストベクター: test-vectors/lease-wrap.json

import { encodeHex } from "./bytes.ts";
import type { WrappedDek } from "./dek-wrap.ts";
import { encodeLengthPrefixed } from "./encoding.ts";
import type { CryptoError, CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import { hpkeSuite } from "./hpke.ts";
import type { EncryptionKey, EncryptionKeyPair } from "./keys.ts";
import { SUITE_ID } from "./suite.ts";

const LEASE_WRAP_DOMAIN = `${SUITE_ID}/lease-wrap`;
const LEASE_CLAIMS_DOMAIN = `${SUITE_ID}/lease-claims`;
const DEK_BYTES = 32;
const CLAIMS_DIGEST_HEX_LENGTH = 32 * 2;

/**
 * The verified OIDC claims a lease is issued against (CRYPTO_SPEC §9.1).
 * These are the *verified* token claims — the server takes them from a token
 * whose signature, issuer and time bounds it has already checked (AUTH_SPEC
 * §14-1), and the workload takes them from the token it minted. Neither side
 * transmits the digest: both compute it.
 */
export interface LeaseClaims {
  readonly issuerUrl: string;
  readonly subject: string;
  readonly audience: string;
}

/**
 * Context a lease wrap is cryptographically bound to (CRYPTO_SPEC §9.1).
 * `claimsDigestHex` is the lowercase-hex digest from `computeLeaseClaimsDigest`.
 */
export interface LeaseWrapContext {
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly claimsDigestHex: string;
}

function invalidInput(field: string): { readonly ok: false; readonly error: CryptoError } {
  return { ok: false, error: { kind: "InvalidInput", field } };
}

/**
 * Builds the canonical preimage of the claims digest (CRYPTO_SPEC §9.1):
 * `LP("<suite>/lease-claims", issuer_url, subject, audience)`. Exposed so the
 * length-prefixed field order is fixed by the test vector rather than by an
 * implementation detail — `("ab","c")` and `("a","bc")` must not collide.
 */
export function buildLeaseClaimsBytes(claims: LeaseClaims): Uint8Array {
  return encodeLengthPrefixed([
    LEASE_CLAIMS_DOMAIN,
    claims.issuerUrl,
    claims.subject,
    claims.audience,
  ]);
}

/**
 * Computes `claims_digest_hex` (CRYPTO_SPEC §9.1). Empty fields are rejected:
 * an OIDC token always carries a non-empty `iss` / `sub` / `aud`, and letting
 * an empty value through would let distinct contexts collide into one digest.
 */
export async function computeLeaseClaimsDigest(claims: LeaseClaims): Promise<CryptoResult<string>> {
  if (claims.issuerUrl.length === 0) {
    return invalidInput("claims issuerUrl");
  }
  if (claims.subject.length === 0) {
    return invalidInput("claims subject");
  }
  if (claims.audience.length === 0) {
    return invalidInput("claims audience");
  }
  return { ok: true, value: encodeHex(await sha256(buildLeaseClaimsBytes(claims))) };
}

function contextInvalidField(context: LeaseWrapContext): string | null {
  // epoch は LP エンコーダの前提(非負の安全な整数)を Result で検証する。
  // エポックは 1 始まり(§3)だが、dek-wrap の checkEpoch と同じく境界は
  // 呼び出し側(チェーン導出状態)が握るため、ここでは形式のみを見る
  if (!Number.isSafeInteger(context.epoch) || context.epoch < 0) {
    return "context epoch";
  }
  // digest の形を検査する: 生の claims を渡す誤用と、大文字 hex による
  // 「同じ digest なのに info が食い違う」実装差を構造的に排除する
  if (!new RegExp(`^[0-9a-f]{${CLAIMS_DIGEST_HEX_LENGTH}}$`).test(context.claimsDigestHex)) {
    return "context claimsDigestHex";
  }
  return null;
}

/**
 * Builds the HPKE info for a lease wrap (CRYPTO_SPEC §9.1):
 * `LP("<suite>/lease-wrap", project_id, environment_id, epoch, claims_digest_hex)`.
 * Opening under any other context — another project, environment, epoch or
 * workload identity, or a §5 persistent-wrap info — fails. Callers must
 * validate the context first (wrap / unwrap below do).
 */
export function buildLeaseWrapInfo(context: LeaseWrapContext): Uint8Array {
  return encodeLengthPrefixed([
    LEASE_WRAP_DOMAIN,
    context.projectId,
    context.environmentId,
    context.epoch,
    context.claimsDigestHex,
  ]);
}

/**
 * Wraps an epoch DEK to a workload's ephemeral public key (single-shot HPKE
 * Seal). The result is response-scoped: it must never be persisted into the
 * DEK wrap store (CRYPTO_SPEC §9.1 / AUTH_SPEC §12-6).
 */
export async function wrapLeaseDek(input: {
  readonly workloadPublicKey: EncryptionKey;
  readonly dek: Uint8Array;
  readonly context: LeaseWrapContext;
}): Promise<CryptoResult<WrappedDek>> {
  if (input.dek.length !== DEK_BYTES) {
    return invalidInput("dek length");
  }
  const invalidField = contextInvalidField(input.context);
  if (invalidField !== null) {
    return invalidInput(invalidField);
  }
  try {
    const { encapsulatedSecret, ciphertext } = await hpkeSuite().Seal(
      input.workloadPublicKey,
      input.dek,
      { info: buildLeaseWrapInfo(input.context) },
    );
    return { ok: true, value: { enc: encapsulatedSecret, ciphertext } };
  } catch {
    return { ok: false, error: { kind: "DekWrapFailed" } };
  }
}

/**
 * Unwraps a leased DEK with the workload's ephemeral key pair (single-shot
 * HPKE Open). Takes the full pair so the private key can stay non-extractable
 * (CRYPTO_SPEC §2). The workload must still match the unwrapped DEK against
 * the chain-published commitment (§5.2) before using it (§9.1 の検証義務 3)。
 */
export async function unwrapLeaseDek(input: {
  readonly workloadKeyPair: EncryptionKeyPair;
  readonly wrapped: WrappedDek;
  readonly context: LeaseWrapContext;
}): Promise<CryptoResult<Uint8Array>> {
  const invalidField = contextInvalidField(input.context);
  if (invalidField !== null) {
    return invalidInput(invalidField);
  }
  try {
    const dek = await hpkeSuite().Open(
      input.workloadKeyPair,
      input.wrapped.enc,
      input.wrapped.ciphertext,
      { info: buildLeaseWrapInfo(input.context) },
    );
    return { ok: true, value: dek };
  } catch {
    return { ok: false, error: { kind: "DekUnwrapFailed" } };
  }
}
