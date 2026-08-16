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
  classifyUnreadableMasterKey,
  corruptMasterKeyMessage,
  declaredSuiteOf,
  foreignSuiteMasterKeyMessage,
  hasRedactedPlaceholder,
  Keychain,
  masterKeyEntryName,
  parseStoredMasterKey,
  parseStoredToken,
  REDACTED_PLACEHOLDER_TEXT,
  redactedPlaceholderEnvTokenMessage,
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
 * MARUHI_TOKEN 経路のセッション解決(キーチェーン不在環境・CI 用)。
 *
 * 環境変数は平文の string が入ってくる唯一の起点なので、入口で包み、以降は
 * {@link CliSession} の Redacted としてしか流れないようにする。
 */
function sessionFromEnvToken(input: {
  readonly origin: string;
  readonly rawToken: string;
  readonly declaredOrigin: string | undefined;
}): Effect.Effect<CliSession, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    // 伏字そのものが入っていたら、通信する前に理由を名指しする。`Redacted` を
    // 導入した以上、出力で見た "<redacted:maruhi-token>" をトークンだと思って
    // 環境変数へ貼る経路は現実的で、そのまま送ると 401 になり
    // 「失効・スコープ・接続先を確認してください」という**別の原因**の案内へ
    // 送られてしまう(キーチェーン側と同じ値に同じ診断を出す)
    // 前後の空白を落としてから見る: 貼り付けで改行や空白が混じるのはごく普通で、
    // 完全一致だけだとこのガードの目的(貼り間違いを名指しする)が空白ひとつで
    // 破れる。送るのは従来どおり生値のまま(本物のトークンの扱いは変えない)
    // 前後の空白は落として扱う。貼り付けで改行や空白が混じるのはごく普通で、
    // 判定だけを trim して送信は生値のままにすると (a) 伏字の検出と送る値が
    // 食い違い、(b) 空白つきの本物のトークンの成否がヘッダー正規化の実装依存に
    // なる。両方を同じ値にすれば、どちらの疑いも残らない
    const rawToken = input.rawToken.trim();
    if (REDACTED_PLACEHOLDER_TEXT.test(rawToken)) {
      return yield* Effect.fail(cliError(redactedPlaceholderEnvTokenMessage));
    }
    const envToken = Redacted.make(rawToken, { label: "maruhi-token" });
    // MARUHI_TOKEN は接続先 origin に束縛する: これを要求しないと --server /
    // 設定で解決した任意の origin へ Bearer トークンを送ってしまう
    // (誘導された攻撃者オリジンへのトークン漏えい)。対象 origin を
    // MARUHI_TOKEN_ORIGIN で明示させ、解決 origin と一致するときのみ送る
    if (input.declaredOrigin === undefined || input.declaredOrigin.length === 0) {
      return yield* Effect.fail(
        cliError(
          "MARUHI_TOKEN を使うには MARUHI_TOKEN_ORIGIN で対象サーバー origin を指定してください(トークンを意図しない別オリジンへ送らないため)",
        ),
      );
    }
    // 環境変数もコマンドラインではない(直し先を示す)
    const expectedOrigin = yield* normalizeHttpOrigin(input.declaredOrigin, "MARUHI_TOKEN_ORIGIN", {
      fix: "MARUHI_TOKEN_ORIGIN 環境変数",
    });
    if (expectedOrigin !== input.origin) {
      return yield* Effect.fail(
        cliError(
          `MARUHI_TOKEN_ORIGIN(${expectedOrigin})が接続先(${input.origin})と一致しません。トークンをこのオリジンへ送信しません`,
        ),
      );
    }
    const client = yield* makeApiClient({ baseUrl: input.origin, token: envToken });
    const me = yield* client.auth
      .me({})
      .pipe(
        Effect.mapError(() =>
          cliError("MARUHI_TOKEN での認証に失敗しました(失効・スコープ・接続先を確認してください)"),
        ),
      );
    return { origin: input.origin, token: envToken, userId: me.userId } satisfies CliSession;
  });
}

/**
 * Resolves the authenticated session for `origin`. The MARUHI_TOKEN env path
 * resolves the user id via `GET /auth/me` (the keychain record carries it).
 */
export function resolveSession(
  origin: string,
): Effect.Effect<CliSession, CliError, Keychain | CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const rawEnvToken = io.envVar("MARUHI_TOKEN");
    if (rawEnvToken !== undefined && rawEnvToken.length > 0) {
      return yield* sessionFromEnvToken({
        origin,
        rawToken: rawEnvToken,
        declaredOrigin: io.envVar("MARUHI_TOKEN_ORIGIN"),
      });
    }
    const keychain = yield* Keychain;
    const stored = yield* keychain.get(tokenEntryName(origin));
    if (stored === null) {
      return yield* Effect.fail(noSessionError);
    }
    const record = parseStoredToken(stored);
    if (record === null) {
      // 伏字保存は「壊れたレコード」と区別する: 原因(maruhi の不具合)も、
      // 復旧手順(旧ビルドが書いたものなら再ログインで上書きされる)も、
      // 汎用の「壊れています」では伝わらない
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
 * 既存レコードに対する拒否文言の選択。
 *
 * 伏字・破損・正常で原因も出口も違う: 伏字と破損は「手で消す」出口を示す必要が
 * あり、正常な鍵だけが本来の上書き拒否({@link ensureNoStoredMasterKey} の
 * 呼び出し側が渡す文言)に当たる。
 */
function refusalFor(existing: string, entryName: string, refusal: string): string {
  if (hasRedactedPlaceholder(existing)) {
    return redactedPlaceholderMasterKeyMessage(entryName);
  }
  return parseStoredMasterKey(existing) === null
    ? unreadableMasterKeyMessage(existing, entryName)
    : refusal;
}

/**
 * 読めないレコードの文言。**削除を勧めるのは破損と判定できたときだけ**
 * (将来版が書いたレコードを消させない — keychain.ts の分類を参照)。
 */
function unreadableMasterKeyMessage(stored: string, entryName: string): string {
  if (classifyUnreadableMasterKey(stored) === "foreign-suite") {
    return foreignSuiteMasterKeyMessage(declaredSuiteOf(stored) ?? "不明");
  }
  return corruptMasterKeyMessage(entryName);
}

/**
 * Fails when a master key is already stored for (origin, userId); returns the
 * keychain entry name otherwise. keygen / recover 共通の上書き防止ガード
 * (鍵を失うと復号可能性を失うため、上書きは常に拒否する)。
 *
 * 伏字レコードはここでも区別する: このガードは読み出し境界の中で**最初に**
 * 当たる場所であり(`key generate` / `key recover` の両方がここで止まる)、
 * 「鍵は既に存在します」と言ってしまうと、実際には使えない鍵を「ある」と
 * 報告したうえで、真の診断(消すべきエントリ名)は別コマンドまで出てこない。
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
      // 「既にある」と言ってよいのは**読めるレコードが実在するとき**だけ。
      // 読めない記録に対して拒否文言(使える鍵がある)を返すと、事実に反する
      // うえ出口も示さないまま generate / recover / show の全部が塞がる
      return yield* Effect.fail(cliError(refusalFor(existing, entryName, refusal)));
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
          : cliError(unreadableMasterKeyMessage(stored, entryName)),
      );
    }
    // 記録は解釈できたが鍵素材として読み込めない場合も同じ行き止まり
    // (上書き防止ガードが全コマンドを拒否する)なので、同じ出口を案内する。
    // **その 1 種類だけ**を写す: 未知スイートは別の原因(将来版で書かれた鍵)で
    // あり、消せば新しい maruhi でも失うため削除を勧めてはいけない。
    // importMasterKeys 自身は保存前の自己検証にも使われる — そちらは残存
    // エントリが無く削除の案内が的外れになるため、写像はここで行う
    return yield* importMasterKeys(record).pipe(
      Effect.mapError((error) =>
        error === corruptKeyError ? cliError(corruptMasterKeyMessage(entryName)) : error,
      ),
    );
  });
}

/**
 * 鍵素材そのものを読み込めない({@link importMasterKeys} の失敗)。
 *
 * 呼び出し側が「どの成果物が壊れているか」で文言を差し替えられるよう公開する
 * — 同じ失敗でも、キーチェーンのレコード由来かリカバリーブロブ由来かで
 * 指すべき対象と復旧手順が変わる。
 */
export const corruptKeyError = cliError(
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
