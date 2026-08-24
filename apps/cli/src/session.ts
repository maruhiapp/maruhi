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
  exportEncryptionPrivateKey,
  exportEncryptionPublicKey,
  exportSigningPrivateSeed,
  exportSigningPublicKey,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  importEncryptionKeyPair,
  importSigningKeyPair,
  SUITE_ID,
} from "@maruhi/crypto";
import { Data, Effect, Redacted } from "effect";
import type { HttpClient } from "effect/unstable/http";

import { makeApiClient } from "./api.ts";
import type { CliConfig } from "./config.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { CliIo } from "./io.ts";
import {
  classifyUnreadableMasterKey,
  corruptMasterKeyMessage,
  declaredSuiteOf,
  foreignMasterKeyMessage,
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

/**
 * loopback ホスト名か: localhost / ::1(URL の括弧付き表記含む)/ 127.0.0.0/8 の
 * IPv4 リテラル(DNS 名・別記法は不可)。「http を許してよいのはどこか」の
 * 判定は CLI 内でこの 1 関数に集約する(サーバー origin — 下の
 * normalizeHttpOrigin — と OIDC 発行 URL — oidc-github.ts — で規則が割れると、
 * 片方だけ直した将来の変更が他方を黙って取り残す — レビューループ 10)。
 */
export function isLoopbackHostname(hostname: string): boolean {
  if (hostname === "localhost" || hostname === "::1" || hostname === "[::1]") {
    return true;
  }
  const match = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(hostname);
  return match !== null && match.slice(1).every((octet) => Number(octet) <= 255);
}

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
      source === "flag" ? usageError(message) : cliError(`${message} — fix ${source.fix}`),
    );
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    // URL そのものは返さない(認証情報が埋まった URL を書かれる形もある)
    return reject(`Cannot parse ${label} (use a URL starting with https://)`);
  }
  // どの分岐でも URL は返さない(`http://user:token@host/x?token=…` の形で
  // 認証情報が書かれうる)。書き方の誤りなので終了コードも 2 で揃える
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    return reject(`${label} must be http(s)`);
  }
  if (url.protocol === "http:" && !isLoopbackHostname(url.hostname)) {
    return reject(
      `http: for ${label} is only allowed on loopback (it would otherwise transmit in cleartext)`,
    );
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
        "No server URL is configured. Pass --server <url> or set it with `maruhi config set server <url>`",
      ),
    );
  }
  return normalizeHttpOrigin(
    raw,
    "the server URL",
    flag === undefined ? { fix: "server in your config" } : "flag",
  );
}

const noSessionError = cliError(
  "Not logged in. Run `maruhi login` (in environments without a keychain, pass a token via the MARUHI_TOKEN env var)",
);

/**
 * MARUHI_TOKEN 経路のセッション解決(キーチェーン不在環境・CI 用)。
 *
 * 環境変数は平文の string が入ってくる唯一の起点なので、入口で包み、以降は
 * {@link CliSession} の Redacted としてしか流れないようにする。
 */
function sessionFromEnvToken(input: {
  /** 前後の空白を落とした値(呼び出し側で trim 済み — 判定と送信で同じ値を使う)。 */
  readonly token: string;
  readonly origin: string;
  readonly declaredOrigin: string | undefined;
}): Effect.Effect<CliSession, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    // 伏字そのものが入っていたら、通信する前に理由を名指しする。`Redacted` を
    // 導入した以上、出力で見た "<redacted:maruhi-token>" をトークンだと思って
    // 環境変数へ貼る経路は現実的で、そのまま送ると 401 になり
    // 「失効・スコープ・接続先を確認してください」という**別の原因**の案内へ
    // 送られてしまう(キーチェーン側と同じ値に同じ診断を出す)
    if (REDACTED_PLACEHOLDER_TEXT.test(input.token)) {
      return yield* Effect.fail(cliError(redactedPlaceholderEnvTokenMessage));
    }
    const envToken = Redacted.make(input.token, { label: "maruhi-token" });
    // MARUHI_TOKEN は接続先 origin に束縛する: これを要求しないと --server /
    // 設定で解決した任意の origin へ Bearer トークンを送ってしまう
    // (誘導された攻撃者オリジンへのトークン漏えい)。対象 origin を
    // MARUHI_TOKEN_ORIGIN で明示させ、解決 origin と一致するときのみ送る
    if (input.declaredOrigin === undefined || input.declaredOrigin.length === 0) {
      return yield* Effect.fail(
        cliError(
          "Using MARUHI_TOKEN requires MARUHI_TOKEN_ORIGIN to name the target server origin (so the token is never sent to an unintended origin)",
        ),
      );
    }
    // 環境変数もコマンドラインではない(直し先を示す)
    const expectedOrigin = yield* normalizeHttpOrigin(input.declaredOrigin, "MARUHI_TOKEN_ORIGIN", {
      fix: "the MARUHI_TOKEN_ORIGIN env var",
    });
    if (expectedOrigin !== input.origin) {
      return yield* Effect.fail(
        cliError(
          `MARUHI_TOKEN_ORIGIN (${expectedOrigin}) does not match the connection target (${input.origin}). The token will not be sent to this origin`,
        ),
      );
    }
    const client = yield* makeApiClient({ baseUrl: input.origin, token: envToken });
    const me = yield* client.auth
      .me({})
      .pipe(
        Effect.mapError(() =>
          cliError(
            "Authentication with MARUHI_TOKEN failed (check revocation, scope, and the target server)",
          ),
        ),
      );
    return { origin: input.origin, token: envToken, userId: me.userId } satisfies CliSession;
  });
}

/**
 * MARUHI_TOKEN がこの origin に効くか。
 *
 * logout の案内({@link resolveSession} の次の一手)がセッション解決と食い違わない
 * ようにするための判定で、規則(trim / 伏字の検出 / origin 束縛)をここに
 * 一本化する。`active` 以外はいずれも**キーチェーンへ落ちずに失敗する**状態で、
 * 「引き続き認証されます」と言ってはいけない。原因ごとに直し方が違うので
 * (足す・直す・消す)、ひとまとめにせず区別して返す。
 */
export type EnvTokenStatus =
  | { readonly kind: "unset" }
  | { readonly kind: "active" }
  | { readonly kind: "placeholder" }
  | { readonly kind: "originMissing" }
  /** 形が使えない。**理由は正規化側の文言をそのまま運ぶ** — 「URL として
   * 解釈できない」と「http: が loopback でない」を自前で言い分けると、
   * 次のコマンドが出す拒否理由と食い違う */
  | { readonly kind: "originInvalid"; readonly reason: string }
  | { readonly kind: "originMismatch" };

export function envTokenStatus(origin: string): Effect.Effect<EnvTokenStatus, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const token = io.envVar("MARUHI_TOKEN")?.trim();
    if (token === undefined || token.length === 0) {
      return { kind: "unset" };
    }
    // 伏字そのものを貼った状態(sessionFromEnvToken が名指しで拒否する)
    if (REDACTED_PLACEHOLDER_TEXT.test(token)) {
      return { kind: "placeholder" };
    }
    const declared = io.envVar("MARUHI_TOKEN_ORIGIN");
    if (declared === undefined || declared.length === 0) {
      return { kind: "originMissing" };
    }
    // 形が使えないのと、形は正しいが別 origin を指しているのは直し方が違う。
    // 前者の理由は**正規化側の文言をそのまま運ぶ**(自前で言い換えると、
    // 次のコマンドが出す拒否理由と食い違う)
    const normalized = yield* normalizeHttpOrigin(declared, "MARUHI_TOKEN_ORIGIN", {
      fix: "the MARUHI_TOKEN_ORIGIN env var",
    }).pipe(
      Effect.map((value) => ({ ok: true, value }) as const),
      Effect.catch((error) => Effect.succeed({ ok: false, reason: error.message } as const)),
    );
    if (!normalized.ok) {
      return { kind: "originInvalid", reason: normalized.reason };
    }
    return normalized.value === origin ? { kind: "active" } : { kind: "originMismatch" };
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
    // 前後の空白はここで一度だけ落とす。貼り付けで改行や空白が混じるのはごく
    // 普通で、判定と送信で違う値を使うと (a) 伏字の検出と送る値が食い違い、
    // (b) 空白つきの値の成否がヘッダー正規化の実装依存になる。空白だけの
    // MARUHI_TOKEN は未設定と同じ扱い — 空トークンで往復させない
    const envToken = io.envVar("MARUHI_TOKEN")?.trim();
    if (envToken !== undefined && envToken.length > 0) {
      return yield* sessionFromEnvToken({
        origin,
        token: envToken,
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
          : cliError("The keychain token record is corrupt. Log in again with `maruhi login`"),
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
 * 「レコードが壊れている」と言い切る前の環境確認。
 *
 * {@link importMasterKeys} の失敗は**鍵素材が壊れている場合と、この環境の
 * WebCrypto が必要なアルゴリズム(Ed25519 / HPKE)を持たない場合の両方**で
 * 起きる(crypto 側は例外を一様に失敗へ畳む)。区別せず「消してください」と
 * 案内すると、無事な鍵を消させて復号可能性を永久に失わせる。
 *
 * そこで**同じ操作を新しい鍵で試す**: 使い捨ての鍵で生成 → 書き出し →
 * 読み込みまで通らないなら、原因は保存された鍵ではなく環境。
 *
 * **生成だけを試すのでは足りない**: ここで守りたい失敗は import 側
 * (`importKey` / HPKE の DeserializePrivateKey)で起きる。生成できても
 * 読み込みができない環境では「生成は通る = 環境は正常」と誤判定し、無事な鍵に
 * 削除を勧めてしまう。{@link importMasterKeys} が踏むのと同じ順序で確かめる。
 * 判定は失敗経路でだけ走るので、通常の実行に費用はかからない。
 */
export function cryptoBackendUsable(): Effect.Effect<boolean> {
  return Effect.tryPromise({
    try: probeCryptoRoundTrip,
    catch: () => null,
  }).pipe(Effect.catch(() => Effect.succeed(false)));
}

/** 使い捨ての鍵で生成 → 書き出し → 読み込みを一巡する(鍵素材は外に出さない)。 */
async function probeCryptoRoundTrip(): Promise<boolean> {
  const enc = await generateEncryptionKeyPair({ extractable: true });
  const sig = await generateSigningKeyPair({ extractable: true });
  const encSk = await exportEncryptionPrivateKey(enc.privateKey);
  const sigSeed = await exportSigningPrivateSeed(sig.privateKey);
  if (!encSk.ok || !sigSeed.ok) {
    return false;
  }
  const encPub = await exportEncryptionPublicKey(enc.publicKey);
  const sigPub = await exportSigningPublicKey(sig.publicKey);
  const encPair = await importEncryptionKeyPair({ publicKey: encPub, privateKey: encSk.value });
  const sigPair = await importSigningKeyPair({ publicKey: sigPub, privateSeed: sigSeed.value });
  const fingerprint = await computeUserKeyFingerprint(encPub, sigPub);
  return encPair.ok && sigPair.ok && fingerprint.ok;
}

/**
 * 環境側が原因のときの共通部分(原因と、どの経路でも同じ次の一手)。
 *
 * **「何が無事か」は経路ごとに違う**ので、そこは共有しない: 保存済みの鍵を
 * 指せるのはキーチェーン経路だけで、recover(まだ保存していない)や
 * generate(これから作る)で「保存されている鍵を消さないでください」と言うと、
 * 存在しない物を指した診断になる。
 */
export const unsupportedCryptoCause =
  "This environment's WebCrypto does not support the algorithms the master key needs (Ed25519 / HPKE), so the key cannot be loaded" as const;

/** 環境側が原因のときの次の一手(どの経路でも同じ)。 */
export const retryOnSupportedRuntime = "Re-run on a supported runtime (a newer Bun / OS)" as const;

/** キーチェーンの鍵を読み込めないときの環境起因の文言(**消させない**のが要点)。 */
export const unsupportedCryptoMessage =
  `${unsupportedCryptoCause}. The stored key is most likely intact — do not delete it. ${retryOnSupportedRuntime}` as const;

/**
 * 破損と判定されたときの文言。**環境が原因でないことを確かめてから**決める。
 *
 * 別形式(未知スイート)は破損ではないので、この関数には来ない — 分岐は
 * 呼び出し側の {@link Effect.catchTag} が型で見分ける。
 */
function corruptOrEnvironmentMessage(entryName: string): Effect.Effect<string> {
  return Effect.map(cryptoBackendUsable(), (usable) =>
    usable ? corruptMasterKeyMessage(entryName) : unsupportedCryptoMessage,
  );
}

/**
 * 既存レコードに対する拒否文言の選択。
 *
 * 「既に存在します」と言ってよいのは**実際に使える鍵があるとき**だけ。形だけ
 * 整っていて鍵素材が読めないレコードにこれを返すと、事実に反するうえ出口も
 * 示さないまま generate / recover / show の全部が塞がる。判定は保存形の検査で
 * 止めず、実際にインポートまで試して決める(コマンド 1 回に 1 度だけ)。
 */
function refusalFor(
  existing: string,
  entryName: string,
  refusal: string,
): Effect.Effect<string, never> {
  if (hasRedactedPlaceholder(existing)) {
    return Effect.succeed(redactedPlaceholderMasterKeyMessage(entryName));
  }
  const record = parseStoredMasterKey(existing);
  if (record === null) {
    return Effect.succeed(unreadableMasterKeyMessage(existing, entryName));
  }
  return importMasterKeys(record).pipe(
    // インポートできた = 本当に使える鍵。ここだけが本来の上書き拒否
    Effect.as(refusal),
    // 読めない理由(破損 / 別形式 / 環境)で出口が違う。タグで分けるので、
    // 失敗の種類が増えれば型検査がここを指す
    Effect.catchTag("MasterKeyUnknownSuite", (error) =>
      Effect.succeed(foreignMasterKeyMessage(error.suite, entryName)),
    ),
    Effect.catchTag("MasterKeyCorrupt", () => corruptOrEnvironmentMessage(entryName)),
  );
}

/**
 * 読めないレコードの文言。**削除を勧めるのは破損と判定できたときだけ**
 * (将来版が書いたレコードを消させない — keychain.ts の分類を参照)。
 */
function unreadableMasterKeyMessage(stored: string, entryName: string): string {
  return classifyUnreadableMasterKey(stored) === "foreign"
    ? foreignMasterKeyMessage(declaredSuiteOf(stored), entryName)
    : corruptMasterKeyMessage(entryName);
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
      return yield* Effect.fail(cliError(yield* refusalFor(existing, entryName, refusal)));
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
      return yield* Effect.fail(cliError("No master key. Generate one with `maruhi key generate`"));
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
    // 原因で分ける理由は refusalFor と同じ: 破損なら消して作り直せるが、未知
    // スイート(将来版が書いた鍵)は消せば新しい maruhi でも失う。同じ状態に
    // 対して二つのコマンドが違う案内を出さないよう、写像もそちらへ合わせる。
    // importMasterKeys 自身は保存前の自己検証にも使われる — そちらは残存
    // エントリが無く削除の案内が的外れになるため、写像はここで行う
    return yield* importMasterKeys(record).pipe(
      Effect.catchTag("MasterKeyUnknownSuite", (error) =>
        Effect.fail(cliError(foreignMasterKeyMessage(error.suite, entryName))),
      ),
      Effect.catchTag("MasterKeyCorrupt", () =>
        Effect.flatMap(corruptOrEnvironmentMessage(entryName), (message) =>
          Effect.fail(cliError(message)),
        ),
      ),
    );
  });
}

/**
 * 鍵素材そのものを読み込めない({@link importMasterKeys} の失敗)。
 *
 * 呼び出し側が「どの成果物が壊れているか」で文言を差し替えられるよう、
 * **型で**区別する — 同じ失敗でも、キーチェーンのレコード由来かリカバリー
 * ブロブ由来かで指すべき対象と復旧手順が変わる。
 *
 * 値の同一性比較(`error === corruptKeyError`)ではなくタグにしてあるのは、
 * この分岐の取り違えが「消してよい / 消してはいけない」を反転させ、鍵の
 * 恒久喪失に直結するため。網羅性を型検査に見てもらう。
 */
// 内訳(hex を解釈できない / WebCrypto が読めない)は持たない: 呼び出し側は
// どちらでも同じ出口へ案内するので、読まれない payload を運ばない
class MasterKeyCorrupt extends Data.TaggedError("MasterKeyCorrupt")<Record<never, never>> {}

/** レコードが現行版の知らないスイートを名乗っている(破損ではない)。 */
class MasterKeyUnknownSuite extends Data.TaggedError("MasterKeyUnknownSuite")<{
  readonly suite: string;
}> {}

/**
 * {@link importMasterKeys} の失敗。文言は呼び出し側が経路に合わせて決める。
 *
 * クラス自体は公開しない: 呼び出し側は `Effect.catchTag` のタグ名で分けるので
 * 構築子を要らず、公開すると「どこでも作れる失敗」になる(生成元は 1 つに保つ)。
 */
export type MasterKeyImportError = MasterKeyCorrupt | MasterKeyUnknownSuite;

/**
 * Imports a stored master-key record into usable (non-extractable) key
 * objects. keygen は保存前の自己検証にも使う(壊れたレコードを書かない)。
 */
export function importMasterKeys(
  record: StoredMasterKey,
): Effect.Effect<MasterKeys, MasterKeyImportError> {
  return Effect.gen(function* () {
    if (record.suite !== SUITE_ID) {
      // 将来スイートの鍵レコードを v1 として黙って解釈しない
      return yield* Effect.fail(new MasterKeyUnknownSuite({ suite: record.suite }));
    }
    const encPub = decodeHex(record.encPubHex);
    // 剥がす理由: 鍵素材のインポート(hex → bytes → 非抽出 CryptoKey)。
    // 産物の encKeyPair / sigKeyPair は extractable: false なので、ここを
    // 通った後の鍵は既に不透明(Redacted の対象外 — MasterKeys の注記参照)
    const encSk = decodeHex(Redacted.value(record.encSkHex));
    const sigPub = decodeHex(record.sigPubHex);
    const sigSeed = decodeHex(Redacted.value(record.sigSkSeedHex));
    if (encPub === null || encSk === null || sigPub === null || sigSeed === null) {
      return yield* Effect.fail(new MasterKeyCorrupt());
    }
    // WebCrypto の reject(壊れた鍵素材のインポート例外)も破損として扱う
    const encKeyPair = yield* Effect.tryPromise({
      try: () => importEncryptionKeyPair({ publicKey: encPub, privateKey: encSk }),
      catch: () => new MasterKeyCorrupt(),
    });
    const sigKeyPair = yield* Effect.tryPromise({
      try: () => importSigningKeyPair({ publicKey: sigPub, privateSeed: sigSeed }),
      catch: () => new MasterKeyCorrupt(),
    });
    const fingerprint = yield* Effect.tryPromise({
      try: () => computeUserKeyFingerprint(encPub, sigPub),
      catch: () => new MasterKeyCorrupt(),
    });
    if (!encKeyPair.ok || !sigKeyPair.ok || !fingerprint.ok) {
      return yield* Effect.fail(new MasterKeyCorrupt());
    }
    return {
      record,
      encKeyPair: encKeyPair.value,
      sigKeyPair: sigKeyPair.value,
      fingerprintHex: encodeHex(fingerprint.value),
    } satisfies MasterKeys;
  });
}
