// 境界 checkpoint の構築・署名(AUTH_SPEC §12-4 / CRYPTO_SPEC §6.3 —
// 2026-08-27 セッション 33 = 所有者承認済み案 2-G′)。
//
// 環境作成・ローテーション複合は、H+1(create / rotate)の直後 seq(H+2)に
// 当該環境 1 タプルのみをカバーする `checkpoint` エントリを必須で同梱する。
// タプルは同梱マニフェストの (epoch, manifestVersion, signed_bytes ハッシュ) と、
// 検証済みビュー由来の values_digest(作成 = 変数空集合、rotate = 再暗号化の
// ために実読した現在値 — 追加の読み取りは発生しない。session-32 §5-1)を束縛する。
// 監査ヘッドは公証しない(空文字列 — 申告の取得〔§16-2〕と standalone 受理は M2)。
//
// CAS リトライではエントリ・ステートメント・マニフェストとともに本エントリも
// 再署名する(prev = H+1 エントリのハッシュが変わるため)。

import type { ChainEntry, ChainMember, EnvValuesDigestEntry } from "@maruhi/crypto";
import {
  computeChainEntryHash,
  computeEnvValuesDigest,
  signChainEntry,
  SUITE_ID,
} from "@maruhi/crypto";
import { Effect } from "effect";

import { cliError, type CliError } from "./errors.ts";

/**
 * H+1 の複合エントリに続く境界 checkpoint(H+2)を署名する。values は検証済み
 * ビューの値レベルの最新形(active 変数のみ — §6.2 の values_digest 定義)。
 */
export function signBoundaryCheckpoint(input: {
  /** 直前に署名した複合エントリ(create / rotate — seq / prev のアンカー)。 */
  readonly compositeEntry: ChainEntry;
  readonly environmentId: string;
  /** 複合が確立するエポック(作成 = 1、rotate = new_epoch)。 */
  readonly epoch: number;
  /** 同梱マニフェストの版と signed_bytes ハッシュ(束縛対象 — §4.3 (2))。 */
  readonly manifestVersion: number;
  readonly manifestSigHashHex: string;
  readonly values: readonly EnvValuesDigestEntry[];
  readonly member: ChainMember;
  readonly signingKey: CryptoKey;
}): Effect.Effect<ChainEntry & { readonly op: "checkpoint" }, CliError> {
  return Effect.gen(function* () {
    const digest = yield* Effect.tryPromise({
      try: () => computeEnvValuesDigest(SUITE_ID, input.values),
      catch: () => cliError("Failed to compute the checkpoint values digest"),
    });
    if (!digest.ok) {
      return yield* Effect.fail(cliError("Failed to compute the checkpoint values digest"));
    }
    const prevHashHex = yield* Effect.tryPromise({
      try: () => computeChainEntryHash(input.compositeEntry),
      catch: () => cliError("Failed to sign the boundary checkpoint entry"),
    });
    const signed = yield* Effect.tryPromise({
      try: () =>
        signChainEntry({
          entry: {
            suite: SUITE_ID,
            seq: input.compositeEntry.seq + 1,
            prevHashHex,
            op: "checkpoint",
            actor: {
              userId: input.member.userId,
              keyFingerprintHex: input.member.keyFingerprintHex,
            },
            payload: {
              environments: [
                {
                  environmentId: input.environmentId,
                  epoch: input.epoch,
                  manifestVersion: input.manifestVersion,
                  manifestSigHashHex: input.manifestSigHashHex,
                  valuesDigestHex: digest.value,
                },
              ],
              auditHeadHashHex: "",
            },
            timestampMs: Date.now(),
          },
          signingKey: input.signingKey,
        }),
      catch: () => cliError("Failed to sign the boundary checkpoint entry"),
    });
    if (!signed.ok || signed.value.op !== "checkpoint") {
      return yield* Effect.fail(cliError("Failed to sign the boundary checkpoint entry"));
    }
    return signed.value;
  });
}
