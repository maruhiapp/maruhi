// 鍵フィンガープリントを受けるフラグの形式検証(server grant / revoke、
// invite accept、member add で共用)。
//
// ADR-0016 第 2 段階の移行で cli.ts(gunshi 側)から切り出した。第 2 段階の
// 完了により、利用者は全員 effect/unstable/cli 側(effect-cli.ts)になった。
// 文言は ADR-0017 に従い英語。

import { Effect } from "effect";

import { type CliError, usageError } from "./errors.ts";

/**
 * 鍵 FP を受けるフラグの形式検証(hex 小文字 32 文字 = 16 バイト)。
 * エラーは**打たれたフラグ名**で報告する(grant の --expect-fingerprint /
 * revoke の --fingerprint / invite・member の FP フラグで共用 — 存在しない
 * フラグ名を指して混乱させない)。`hint` は FP の出所の案内(鍵種別ごと)。
 */
export function parseFingerprintFlag(
  flagName: string,
  value: string | undefined,
  hint = "a server key fingerprint is 32 lowercase hex characters — serverKeyFingerprintHex in /auth/config",
): Effect.Effect<string | null, CliError> {
  if (value === undefined) {
    return Effect.succeed(null);
  }
  if (!/^[0-9a-f]{32}$/.test(value)) {
    return Effect.fail(usageError(`${flagName} is malformed (${hint})`));
  }
  return Effect.succeed(value);
}

/** ユーザー鍵 FP フラグ(CRYPTO_SPEC §3)— 共用パーサに出所の案内だけを差す。 */
export function parseUserFingerprintFlag(
  flagName: string,
  value: string | undefined,
): Effect.Effect<string | null, CliError> {
  return parseFingerprintFlag(
    flagName,
    value,
    "a user key fingerprint is 32 lowercase hex characters — the key fingerprint shown by maruhi key show",
  );
}
