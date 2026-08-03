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
import { Effect } from "effect";
import type { HttpClient } from "effect/unstable/http";

import { makeApiClient } from "./api.ts";
import type { CliConfig } from "./config.ts";
import { cliError, type CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import {
  Keychain,
  masterKeyEntryName,
  parseStoredMasterKey,
  parseStoredToken,
  type StoredMasterKey,
  tokenEntryName,
} from "./keychain.ts";

/** A resolved authenticated session against one server. */
export interface CliSession {
  /** Normalized server origin (keychain scoping key and API base URL). */
  readonly origin: string;
  readonly token: string;
  readonly tokenSource: "env" | "keychain";
  readonly userId: string;
}

/** The master keypair loaded from the keychain, imported and ready to use. */
export interface MasterKeys {
  readonly record: StoredMasterKey;
  readonly encKeyPair: EncryptionKeyPair;
  readonly sigKeyPair: SigningKeyPair;
  readonly fingerprintHex: string;
}

const LOOPBACK_HOSTNAMES = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

/**
 * Resolves the server base URL: --server flag → config. Fails with guidance.
 * `http:` は loopback のみ許可する(トークン・GitHub トークンが平文で
 * 経路上に出るため。wrangler dev のローカル開発は通る)。
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
  try {
    const url = new URL(raw);
    if (url.protocol === "http:" && !LOOPBACK_HOSTNAMES.has(url.hostname)) {
      return Effect.fail(
        cliError(`http: は loopback のみ許可されます(トークンが平文送信されるため): ${raw}`),
      );
    }
    if (url.protocol !== "https:" && url.protocol !== "http:") {
      return Effect.fail(cliError(`サーバー URL は http(s) で指定してください: ${raw}`));
    }
    return Effect.succeed(url.origin);
  } catch {
    return Effect.fail(cliError(`サーバー URL を解釈できません: ${raw}`));
  }
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
    const envToken = io.envVar("MARUHI_TOKEN");
    if (envToken !== undefined && envToken.length > 0) {
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
        tokenSource: "env",
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
      return yield* Effect.fail(
        cliError(
          "キーチェーンのトークンレコードが壊れています。`maruhi login` で再ログインしてください",
        ),
      );
    }
    return {
      origin,
      token: record.token,
      tokenSource: "keychain",
      userId: record.userId,
    } satisfies CliSession;
  });
}

/** Loads and imports the master keypair for (origin, userId) from the keychain. */
export function loadMasterKeys(session: CliSession): Effect.Effect<MasterKeys, CliError, Keychain> {
  return Effect.gen(function* () {
    const keychain = yield* Keychain;
    const stored = yield* keychain.get(masterKeyEntryName(session.origin, session.userId));
    if (stored === null) {
      return yield* Effect.fail(
        cliError("master 鍵がありません。`maruhi key generate` で生成してください"),
      );
    }
    const record = parseStoredMasterKey(stored);
    if (record === null) {
      return yield* Effect.fail(cliError("キーチェーンの master 鍵レコードが壊れています"));
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
    const encSk = decodeHex(record.encSkHex);
    const sigPub = decodeHex(record.sigPubHex);
    const sigSeed = decodeHex(record.sigSkSeedHex);
    if (encPub === null || encSk === null || sigPub === null || sigSeed === null) {
      return yield* Effect.fail(corruptKeyError);
    }
    const encKeyPair = yield* Effect.promise(() =>
      importEncryptionKeyPair({ publicKey: encPub, privateKey: encSk }),
    );
    const sigKeyPair = yield* Effect.promise(() =>
      importSigningKeyPair({ publicKey: sigPub, privateSeed: sigSeed }),
    );
    const fingerprint = yield* Effect.promise(() => computeUserKeyFingerprint(encPub, sigPub));
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
