// 認証セッション(maruhi トークン)と master 鍵の解決。
//
// トークンの解決順: 環境変数 MARUHI_TOKEN(キーチェーン不在環境・CI 用の
// 読み取り専用経路。userId は /auth/me で解決)→ OS キーチェーン。
// master 秘密鍵はキーチェーンのみ(環境変数経路は設けない — 鍵素材を
// プロセス環境に置く経路を v1 では作らない。session-11.md 申し送り)。

import type { EncryptionKeyPair, SigningKeyPair } from "@maruhi/crypto";
import {
  computeUserKeyFingerprint,
  decodeHex,
  encodeHex,
  importEncryptionKeyPair,
  importSigningKeyPair,
  SUITE_ID,
} from "@maruhi/crypto";
import { Effect, Redacted } from "effect";
import type { HttpClient } from "effect/unstable/http";

import { makeApiClient } from "./api.ts";
import type { CliConfig } from "./config.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { CliIo } from "./io.ts";
import {
  hasRedactedPlaceholder,
  Keychain,
  masterKeyEntryName,
  parseStoredMasterKey,
  parseStoredToken,
  redactedPlaceholderMasterKeyMessage,
  redactedPlaceholderTokenMessage,
  type StoredMasterKey,
  tokenEntryName,
} from "./keychain.ts";

/** A resolved authenticated session against one server. */
export interface CliSession {
  /** Normalized server origin (keychain scoping key and API base URL). */
  readonly origin: string;
  readonly token: Redacted.Redacted<string>;
  readonly userId: string;
}

/**
 * The master keypair loaded from the keychain, imported and ready to use.
 *
 * `encKeyPair` / `sigKeyPair` は `Redacted` で包まない: どちらも
 * `extractable: false` でインポートした CryptoKey であり、値を取り出す口が
 * WebCrypto の側に無い(既に不透明)。包む対象は hex を持つ `record` のほう。
 */
export interface MasterKeys {
  readonly record: StoredMasterKey;
  readonly encKeyPair: EncryptionKeyPair;
  readonly sigKeyPair: SigningKeyPair;
  readonly fingerprintHex: string;
}

const LOOPBACK_HOSTNAMES = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

/**
 * Validates and normalizes a base URL: https anywhere, http only on loopback
 * (tokens / GitHub tokens travel in cleartext otherwise; wrangler dev and
 * device-flow test servers on localhost still pass). `label` names the URL in
 * error messages.
 */
export function normalizeHttpOrigin(
  raw: string,
  label: string,
  /**
   * 値の出所。コマンドライン以外(config・環境変数)なら「打ち間違い」では
   * ないので、usage エラー(2)にせず直し先を示す。
   */
  source: { readonly fix: string } | "flag" = "flag",
): Effect.Effect<string, CliError> {
  const reject = (message: string): Effect.Effect<never, CliError> =>
    Effect.fail(
      source === "flag"
        ? usageError(message)
        : cliError(`${message} — ${source.fix} を直してください`),
    );
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    // URL そのものは返さない(認証情報が埋まった URL を書かれる形もある)
    return reject(`${label}を解釈できません(https:// で始まる URL)`);
  }
  // どの分岐でも URL は返さない(`http://user:token@host/x?token=…` の形で
  // 認証情報が書かれうる)。書き方の誤りなので終了コードも 2 で揃える
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    return reject(`${label}は http(s) で指定してください`);
  }
  if (url.protocol === "http:" && !LOOPBACK_HOSTNAMES.has(url.hostname)) {
    return reject(`${label}の http: は loopback のみ許可されます(平文送信になるため)`);
  }
  return Effect.succeed(url.origin);
}

/**
 * Resolves the server base URL: --server flag → config. Fails with guidance.
 */
export function resolveServerOrigin(
  flag: string | undefined,
  config: CliConfig,
): Effect.Effect<string, CliError> {
  const raw = flag ?? config.server;
  if (raw === undefined) {
    return Effect.fail(
      cliError(
        "サーバー URL が未設定です。--server <url> を指定するか、`maruhi config set server <url>` で設定してください",
      ),
    );
  }
  return normalizeHttpOrigin(
    raw,
    "サーバー URL",
    flag === undefined ? { fix: "config の server" } : "flag",
  );
}

const noSessionError = cliError(
  "ログインしていません。`maruhi login` を実行してください(キーチェーン不在環境では MARUHI_TOKEN 環境変数でトークンを渡せます)",
);

/**
 * Resolves the authenticated session for `origin`. The MARUHI_TOKEN env path
 * resolves the user id via `GET /auth/me` (the keychain record carries it).
 */
export function resolveSession(
  origin: string,
): Effect.Effect<CliSession, CliError, Keychain | CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    // env は素の string で入ってくる唯一の起点。ここで包み、以降は
    // CliSession.token(Redacted)としてしか流れないようにする
    const rawEnvToken = io.envVar("MARUHI_TOKEN");
    if (rawEnvToken !== undefined && rawEnvToken.length > 0) {
      const envToken = Redacted.make(rawEnvToken, { label: "maruhi-token" });
      // MARUHI_TOKEN は接続先 origin に束縛する: これを要求しないと --server /
      // 設定で解決した任意の origin へ Bearer トークンを送ってしまう
      // (誘導された攻撃者オリジンへのトークン漏えい)。対象 origin を
      // MARUHI_TOKEN_ORIGIN で明示させ、解決 origin と一致するときのみ送る
      const declaredOrigin = io.envVar("MARUHI_TOKEN_ORIGIN");
      if (declaredOrigin === undefined || declaredOrigin.length === 0) {
        return yield* Effect.fail(
          cliError(
            "MARUHI_TOKEN を使うには MARUHI_TOKEN_ORIGIN で対象サーバー origin を指定してください(トークンを意図しない別オリジンへ送らないため)",
          ),
        );
      }
      // 環境変数もコマンドラインではない(直し先を示す)
      const expectedOrigin = yield* normalizeHttpOrigin(declaredOrigin, "MARUHI_TOKEN_ORIGIN", {
        fix: "MARUHI_TOKEN_ORIGIN 環境変数",
      });
      if (expectedOrigin !== origin) {
        return yield* Effect.fail(
          cliError(
            `MARUHI_TOKEN_ORIGIN(${expectedOrigin})が接続先(${origin})と一致しません。トークンをこのオリジンへ送信しません`,
          ),
        );
      }
      const client = yield* makeApiClient({ baseUrl: origin, token: envToken });
      const me = yield* client.auth
        .me({})
        .pipe(
          Effect.mapError(() =>
            cliError(
              "MARUHI_TOKEN での認証に失敗しました(失効・スコープ・接続先を確認してください)",
            ),
          ),
        );
      return {
        origin,
        token: envToken,
        userId: me.userId,
      } satisfies CliSession;
    }
    const keychain = yield* Keychain;
    const stored = yield* keychain.get(tokenEntryName(origin));
    if (stored === null) {
      return yield* Effect.fail(noSessionError);
    }
    const record = parseStoredToken(stored);
    if (record === null) {
      // 伏字保存は「壊れたレコード」と区別する: 再ログインは同じ直列化を
      // 通るので同じ伏字を書き直すだけで、案内どおりに操作しても直らない
      return yield* Effect.fail(
        hasRedactedPlaceholder(stored)
          ? cliError(redactedPlaceholderTokenMessage)
          : cliError(
              "キーチェーンのトークンレコードが壊れています。`maruhi login` で再ログインしてください",
            ),
      );
    }
    return {
      origin,
      token: record.token,
      userId: record.userId,
    } satisfies CliSession;
  });
}

/**
 * Fails when a master key is already stored for (origin, userId); returns the
 * keychain entry name otherwise. keygen / recover 共通の上書き防止ガード
 * (鍵を失うと復号可能性を失うため、上書きは常に拒否する)。
 */
export function ensureNoStoredMasterKey(
  session: CliSession,
  refusal: string,
): Effect.Effect<string, CliError, Keychain> {
  return Effect.gen(function* () {
    const keychain = yield* Keychain;
    const entryName = masterKeyEntryName(session.origin, session.userId);
    const existing = yield* keychain.get(entryName);
    if (existing !== null) {
      return yield* Effect.fail(cliError(refusal));
    }
    return entryName;
  });
}

/** Loads and imports the master keypair for (origin, userId) from the keychain. */
export function loadMasterKeys(session: CliSession): Effect.Effect<MasterKeys, CliError, Keychain> {
  return Effect.gen(function* () {
    const keychain = yield* Keychain;
    const entryName = masterKeyEntryName(session.origin, session.userId);
    const stored = yield* keychain.get(entryName);
    if (stored === null) {
      return yield* Effect.fail(
        cliError("master 鍵がありません。`maruhi key generate` で生成してください"),
      );
    }
    const record = parseStoredMasterKey(stored);
    if (record === null) {
      return yield* Effect.fail(
        hasRedactedPlaceholder(stored)
          ? cliError(redactedPlaceholderMasterKeyMessage(entryName))
          : cliError("キーチェーンの master 鍵レコードが壊れています"),
      );
    }
    return yield* importMasterKeys(record);
  });
}

const corruptKeyError = cliError(
  "キーチェーンの master 鍵レコードが壊れています(鍵素材を読み込めません)",
);

/**
 * Imports a stored master-key record into usable (non-extractable) key
 * objects. keygen は保存前の自己検証にも使う(壊れたレコードを書かない)。
 */
export function importMasterKeys(record: StoredMasterKey): Effect.Effect<MasterKeys, CliError> {
  return Effect.gen(function* () {
    if (record.suite !== SUITE_ID) {
      // 将来スイートの鍵レコードを v1 として黙って解釈しない
      return yield* Effect.fail(cliError(`master 鍵レコードのスイートが未知です(${record.suite})`));
    }
    const encPub = decodeHex(record.encPubHex);
    // 剥がす理由: 鍵素材のインポート(hex → bytes → 非抽出 CryptoKey)。
    // 産物の encKeyPair / sigKeyPair は extractable: false なので、ここを
    // 通った後の鍵は既に不透明(Redacted の対象外 — MasterKeys の注記参照)
    const encSk = decodeHex(Redacted.value(record.encSkHex));
    const sigPub = decodeHex(record.sigPubHex);
    const sigSeed = decodeHex(Redacted.value(record.sigSkSeedHex));
    if (encPub === null || encSk === null || sigPub === null || sigSeed === null) {
      return yield* Effect.fail(corruptKeyError);
    }
    // WebCrypto の reject(壊れた鍵素材のインポート例外)も corruptKeyError に写す
    const encKeyPair = yield* Effect.tryPromise({
      try: () => importEncryptionKeyPair({ publicKey: encPub, privateKey: encSk }),
      catch: () => corruptKeyError,
    });
    const sigKeyPair = yield* Effect.tryPromise({
      try: () => importSigningKeyPair({ publicKey: sigPub, privateSeed: sigSeed }),
      catch: () => corruptKeyError,
    });
    const fingerprint = yield* Effect.tryPromise({
      try: () => computeUserKeyFingerprint(encPub, sigPub),
      catch: () => corruptKeyError,
    });
    if (!encKeyPair.ok || !sigKeyPair.ok || !fingerprint.ok) {
      return yield* Effect.fail(corruptKeyError);
    }
    return {
      record,
      encKeyPair: encKeyPair.value,
      sigKeyPair: sigKeyPair.value,
      fingerprintHex: encodeHex(fingerprint.value),
    } satisfies MasterKeys;
  });
}
