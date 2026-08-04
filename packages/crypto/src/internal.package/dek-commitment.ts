// CRYPTO_SPEC §5.2: エポック DEK のコミットメント。
//   dek_commitment_hex = lower_hex(SHA-256(LP("<suite>/dek-commit",
//                                             project_id, environment_id, epoch, dek_hex)))
// suite の束縛はドメイン文字列が担う(§5.1 と同型)。座標(project / environment /
// epoch)を原像に含めることで、同一 DEK の別文脈への流用もコミットメント不一致に
// なり、コミットメント値同士の比較から文脈間の DEK 一致が漏れることもない。
// dek_hex は DEK 32 バイトの hex 小文字文字列(§6.2 grant_server の先例と同じ
// binary_encoding 規約)。テストベクター: test-vectors/dek-commitment.json
//
// これは新しいプリミティブではない: SHA-256 + §2.1 LP のみで構成され、§3 の鍵
// フィンガープリントと同じ「公開ハッシュによる同定」の適用である。秘匿性は入力の
// エントロピーに依存するため、対象は一様ランダム 256-bit の DEK のみ(低エントロピー
// 値への流用は禁止 — §12)。
//
// 受信者は unwrap した DEK をこのコミットメントと照合するまで、その DEK を
// いかなる暗号操作(復号・暗号化)にも使用してはならない(§5.2 / §6.3)。

import { encodeHex } from "./bytes.ts";
import { encodeLengthPrefixed } from "./encoding.ts";
import type { CryptoError, CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";

const DEK_BYTES = 32;
const COMMITMENT_HEX_LENGTH = 32 * 2;

/**
 * Coordinates a DEK commitment is bound to (CRYPTO_SPEC §5.2). The suite is
 * embedded via the domain string, so a commitment never transplants across
 * suites; the coordinates keep commitments of the same DEK apart per context.
 */
export interface DekCommitmentContext {
  readonly suite: string;
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
}

function invalidInput(field: string): { readonly ok: false; readonly error: CryptoError } {
  return { ok: false, error: { kind: "InvalidInput", field } };
}

function contextInvalidField(context: DekCommitmentContext): string | null {
  if (context.suite.length === 0) {
    return "context suite";
  }
  if (!Number.isSafeInteger(context.epoch) || context.epoch < 1) {
    return "context epoch";
  }
  return null;
}

/**
 * Builds the canonical commitment preimage (CRYPTO_SPEC §5.2). The DEK is
 * carried as its lowercase-hex form — `encodeHex` is the only producer here,
 * so an uppercase variant can never enter the preimage. Callers must validate
 * the context first (compute / verify below do); this builder assumes valid
 * input.
 */
export function buildDekCommitmentBytes(context: DekCommitmentContext, dek: Uint8Array): Uint8Array {
  return encodeLengthPrefixed([
    `${context.suite}/dek-commit`,
    context.projectId,
    context.environmentId,
    context.epoch,
    encodeHex(dek),
  ]);
}

/**
 * Computes the §5.2 commitment of an epoch DEK as lowercase hex — the value
 * published on the chain by `create_environment` / `rotate_epoch` (§6.2).
 */
export async function computeDekCommitment(input: {
  readonly context: DekCommitmentContext;
  readonly dek: Uint8Array;
}): Promise<CryptoResult<string>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  if (input.dek.length !== DEK_BYTES) {
    return invalidInput("dek");
  }
  return { ok: true, value: encodeHex(await sha256(buildDekCommitmentBytes(input.context, input.dek))) };
}

/**
 * Matches an unwrapped DEK against the chain-published commitment for its
 * (environment, epoch) coordinates (CRYPTO_SPEC §5.2 / §6.3). Until this
 * succeeds the DEK must not be used for any cryptographic operation; a
 * mismatch marks the wrap as poisoned (repair path — AUTH_SPEC §12-6).
 */
export async function verifyDekCommitment(input: {
  readonly context: DekCommitmentContext;
  readonly dek: Uint8Array;
  readonly expectedCommitmentHex: string;
}): Promise<CryptoResult<void>> {
  // 期待値はチェーン由来の正規形(hex 小文字 64 文字)のみ受け付ける。大文字を
  // 許すと「照合に使う正規形」が複数生まれ、実装間で判定が割れる
  if (
    input.expectedCommitmentHex.length !== COMMITMENT_HEX_LENGTH ||
    !/^[0-9a-f]+$/.test(input.expectedCommitmentHex)
  ) {
    return invalidInput("expectedCommitmentHex");
  }
  const computed = await computeDekCommitment({ context: input.context, dek: input.dek });
  if (!computed.ok) {
    return computed;
  }
  return computed.value === input.expectedCommitmentHex
    ? { ok: true, value: undefined }
    : { ok: false, error: { kind: "DekCommitmentMismatch" } };
}
