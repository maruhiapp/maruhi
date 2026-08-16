// OS キーチェーン境界(Effect サービス)と保存レコードの形。
//
// CLI が永続化してよい秘密は maruhi API トークンと master 秘密鍵のみで、
// どちらもこの境界(OS キーチェーン)を通す(CLAUDE.md ディスクレス不変条件)。
// 平文ファイルへのフォールバックは実装しない — キーチェーン不在環境では
// 保存せず、型付きエラーで案内する。
//
// 本番実装は Bun.secrets(live.ts。macOS Keychain / Linux libsecret /
// Windows Credential Manager)。テストはインメモリ実装(test/support)。
//
// 保存レコードの秘密フィールドは `Redacted` で包む(ログ・エラーへの漏出を
// 型で止める)。**ただし `JSON.stringify` は伏字を保存する** — `Redacted` の
// `toJSON()` は "<redacted>" を返すため、レコードをそのまま stringify すると
// 型エラーにならないまま伏字がキーチェーンへ書かれる(トークンなら次回認証
// 失敗、master 鍵なら復号不能)。永続化は必ずこのファイルの
// {@link serializeStoredToken} / {@link serializeStoredMasterKey} を通し、
// 直列化の直前で明示的に剥がす。

import { Context, type Effect, Redacted } from "effect";

import type { CliError } from "./errors.ts";

/** OS keychain boundary. Names are scoped by {@link tokenEntryName} / {@link masterKeyEntryName}. */
export interface KeychainShape {
  readonly get: (name: string) => Effect.Effect<string | null, CliError>;
  readonly set: (name: string, value: string) => Effect.Effect<void, CliError>;
  readonly remove: (name: string) => Effect.Effect<void, CliError>;
}

export class Keychain extends Context.Service<Keychain, KeychainShape>()("cli/Keychain") {}

/** Keychain service name shared by every maruhi entry. */
export const KEYCHAIN_SERVICE = "maruhi";

/** Keychain entry name for the maruhi API token of one server. */
export function tokenEntryName(origin: string): string {
  return `token::${origin}`;
}

/** Keychain entry name for the master keypair of one (server, user). */
export function masterKeyEntryName(origin: string, userId: string): string {
  return `master::${origin}::${userId}`;
}

/** The maruhi API token record stored in the keychain (AUTH_SPEC §4-5). */
export interface StoredToken {
  readonly token: Redacted.Redacted<string>;
  readonly userId: string;
  readonly tokenId: string;
}

/**
 * The master keypair record stored in the keychain (CRYPTO_SPEC §3).
 *
 * 秘密側(`encSkHex` / `sigSkSeedHex`)だけを包む。公開鍵とスイートは
 * 署名文脈・FP 計算・招待受諾のペイロードで広く使う非機密なので素のまま。
 */
export interface StoredMasterKey {
  readonly suite: string;
  readonly encPubHex: string;
  readonly encSkHex: Redacted.Redacted<string>;
  readonly sigPubHex: string;
  readonly sigSkSeedHex: Redacted.Redacted<string>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

// `Redacted.toString()` / `toJSON()` の出力そのもの(ラベル付きも含む)。
const REDACTED_PLACEHOLDER = /^<redacted(?::[^>]*)?>$/;

/**
 * 読み出し境界での伏字保存の検出。
 *
 * 冒頭の注記のとおり、直列化で剥がし忘れると "<redacted>" が保存される。
 * これは**型では止まらない**唯一の経路なので、読み側でも 1 度だけ見る:
 * 検出しないと、トークンなら「401 = 失効したので再ログインを」、master 鍵なら
 * 「鍵素材を読み込めません」という**原因を取り違えた診断**に化け、真因
 * (保存側のバグ)へ辿り着けない。生値がこの形になることはない
 * (トークンは `maruhi_pat_` / `maruhi_inv_` 接頭辞、鍵素材は hex)。
 */
function isRedactedPlaceholder(value: string): boolean {
  return REDACTED_PLACEHOLDER.test(value);
}

/** Parses a stored token record; null when the shape is corrupt. */
export function parseStoredToken(json: string): StoredToken | null {
  try {
    const value: unknown = JSON.parse(json);
    if (
      isRecord(value) &&
      nonEmptyString(value["token"]) &&
      !isRedactedPlaceholder(value["token"]) &&
      nonEmptyString(value["userId"]) &&
      nonEmptyString(value["tokenId"])
    ) {
      return {
        token: Redacted.make(value["token"], { label: "maruhi-token" }),
        userId: value["userId"],
        tokenId: value["tokenId"],
      };
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Serializes a token record for the keychain, unwrapping the token.
 *
 * 剥がす理由: キーチェーンへ書くのは生値でなければならない。`JSON.stringify`
 * に {@link StoredToken} をそのまま渡すと `Redacted.toJSON()` が働いて
 * "<redacted>" が保存され、次回のログインまで気づけない(型は通る)。
 * 保存経路をこの 1 関数に集約し、剥がす箇所を数えられる状態に保つ。
 */
export function serializeStoredToken(record: StoredToken): string {
  return JSON.stringify({
    token: Redacted.value(record.token),
    userId: record.userId,
    tokenId: record.tokenId,
  });
}

/** Parses a stored master-key record; null when the shape is corrupt. */
export function parseStoredMasterKey(json: string): StoredMasterKey | null {
  try {
    const value: unknown = JSON.parse(json);
    if (
      isRecord(value) &&
      nonEmptyString(value["suite"]) &&
      nonEmptyString(value["encPubHex"]) &&
      nonEmptyString(value["encSkHex"]) &&
      !isRedactedPlaceholder(value["encSkHex"]) &&
      nonEmptyString(value["sigPubHex"]) &&
      nonEmptyString(value["sigSkSeedHex"]) &&
      !isRedactedPlaceholder(value["sigSkSeedHex"])
    ) {
      return {
        suite: value["suite"],
        encPubHex: value["encPubHex"],
        encSkHex: Redacted.make(value["encSkHex"], { label: "master-enc-sk" }),
        sigPubHex: value["sigPubHex"],
        sigSkSeedHex: Redacted.make(value["sigSkSeedHex"], { label: "master-sig-seed" }),
      };
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Serializes a master-key record, unwrapping the private halves.
 *
 * 剥がす理由: {@link serializeStoredToken} と同じ — キーチェーンとリカバリー
 * ブロブへ書くのは生値でなければならない。`JSON.stringify` に
 * {@link StoredMasterKey} をそのまま渡すと秘密側が "<redacted>" になり、
 * **鍵を復元できないレコードが保存される**(型は通り、復号が要るまで
 * 気づけない)。保存・ラップの全経路をこの 1 関数へ集約する。
 */
export function serializeStoredMasterKey(record: StoredMasterKey): string {
  return JSON.stringify({
    suite: record.suite,
    encPubHex: record.encPubHex,
    encSkHex: Redacted.value(record.encSkHex),
    sigPubHex: record.sigPubHex,
    sigSkSeedHex: Redacted.value(record.sigSkSeedHex),
  });
}
