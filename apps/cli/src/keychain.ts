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

import { SUITE_ID } from "@maruhi/crypto";
import { Context, type Effect, Redacted } from "effect";

import { escapeText } from "./display.ts";
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
 * 保存レコード以外(環境変数など)で伏字そのものを受け取っていないか見るための
 * 公開版。値の出所は違っても、混入した文字列は同じなので判定を共有する。
 */
export const REDACTED_PLACEHOLDER_TEXT: RegExp = REDACTED_PLACEHOLDER;

function isRedactedPlaceholder(value: string): boolean {
  return REDACTED_PLACEHOLDER.test(value);
}

/**
 * 保存済みレコードに伏字が書かれているか(読み出し境界での検出)。
 *
 * 冒頭の注記のとおり、直列化で剥がし忘れると "<redacted>" が保存される。
 * これは**型では止まらない**唯一の経路なので、読み側でも見る。
 *
 * 検出結果を**呼び出し側が区別できる形**で出すのが要点: 汎用の「レコードが
 * 壊れています」に混ぜると、原因(maruhi 側の不具合)も、レコード種別ごとに
 * 違う復旧手順も伝わらない。復旧可否は**どのビルドが書いたか**で変わる:
 * 旧ビルドが書いたレコードを修正版で読んだのなら上書きで直り、現行版に
 * 不具合が残っていれば書き直しても再発する。どちらも起こりうるので、
 * 文言は両方を示す。
 *
 * 生値がこの形になることはない(トークンは `maruhi_pat_` / `maruhi_inv_`
 * 接頭辞、鍵素材は hex)ため、誤検出しない。
 */
export function hasRedactedPlaceholder(json: string): boolean {
  try {
    const value: unknown = JSON.parse(json);
    if (!isRecord(value)) {
      return false;
    }
    return ["token", "encSkHex", "sigSkSeedHex"].some((name) => {
      const field = value[name];
      return typeof field === "string" && isRedactedPlaceholder(field);
    });
  } catch {
    return false;
  }
}

/**
 * 伏字混入の原因説明(復旧手順は種別ごとに呼び出し側が足す)。
 *
 * 壊れている成果物を引数で受けるのは、経路によって**別の物**が壊れているため:
 * キーチェーンのレコードの場合と、サーバー登録済みのリカバリーブロブの場合が
 * ある。前者の文面を後者で使うと、存在しないキーチェーンのレコードを指して
 * 調査を誤らせる。
 */
export function placeholderCause(artifact: string): string {
  return `${artifact}に伏字(<redacted>)が入っています。これは maruhi の不具合(秘密を取り出し忘れた状態で書き出されたもの)です`;
}

const keychainPlaceholderCause = placeholderCause("キーチェーンのレコード");

/**
 * トークンレコードに伏字が保存されていたときの文言。
 *
 * 復旧手段は**レコードの種類で違う**ので分けている。トークンは `maruhi login`
 * が無条件に上書きするため、旧ビルドが書いたレコードなら再ログインで直る
 * (直らないと書き切ると、唯一の 1 コマンド復旧から利用者を遠ざけてしまう)。
 * ただし現行版に不具合が残っていれば同じ伏字を書き直すだけなので、再発したら
 * それが判断材料になることまで書く。
 */
export const redactedPlaceholderTokenMessage =
  `${keychainPlaceholderCause}。旧バージョンが書いたレコードであれば \`maruhi login\` で正しく上書きされます。再ログインしても再発する場合は現行版の不具合なので、報告してください` as const;

/**
 * MARUHI_TOKEN に伏字そのものが入っていたときの文言。
 *
 * こちらは maruhi の不具合ではなく**貼り間違い**が原因: 出力に現れた伏字を
 * トークンだと思って環境変数へ入れた形。直し方も違う(再ログインでも鍵の
 * 削除でもなく、本物のトークンを入れ直す)ので、文面を分ける。
 */
export const redactedPlaceholderEnvTokenMessage =
  "MARUHI_TOKEN の値が伏字(<redacted>)そのものです。これは maruhi が伏せた表示をトークンとして貼り付けた状態で、認証には使えません。`maruhi login` で発行したトークンの生値を設定してください" as const;

/**
 * エントリ名の表示(エスケープ + 「エスケープしてある」旨の注記)。
 *
 * 注記を落とすと、印字可能 ASCII 以外を含む user_id では**表示された名前が
 * 実在しない**ため、唯一の復旧手順(手で消す)が実行できない。名前を出す
 * 場所が増えたので、注記ごと一箇所に閉じ込める。
 */
function quotedEntryName(entryName: string): string {
  return `"${escapeText(entryName)}"(名前は印字可能 ASCII 以外を \\u{16 進} — 4 桁以上、補助面はより長い — 、バックスラッシュと引用符を \\\\ / \\" の形にエスケープして表示しています。実際のエントリ名はエスケープを戻したものです)`;
}

/**
 * 「手で消してから、こう進む」の共通部分(伏字・破損のどちらでも同じ出口)。
 *
 * 削除後の手順を**両方**示すのが要点: どちらが使えるかは利用者の状況で決まる。
 * リカバリーコードがあれば `key recover` が元の鍵を戻して復号可能性を保てるが、
 * 無ければ `key generate` で作り直すしかない(その場合は既存の値を復号できず、
 * 自分宛ラップの再配布が要る)。`key recover` だけを案内すると、コードを持たない
 * 利用者は実行できない案内へ送られる。
 */
function manualDeletionGuidance(entryName: string): string {
  // entryName は user_id(サーバー配布の自由文字列)を含む。端末へ出す前に
  // 無害化するが、**潰さずエスケープする**: この名前は「消してください」と
  // 案内する操作対象そのものであり、置換文字に潰すと実在しない名前を案内して
  // 唯一の復旧手順が実行不能になる。
  //
  // ただしエスケープ後の文字列は原文そのものではない(印字可能 ASCII 以外を
  // 含む user_id では表記が変わる)。**エスケープしてある旨を文面に明記する** —
  // 書かないと、利用者は表示どおりの名前を探して見つけられない。
  return `master 鍵は上書き防止のため \`maruhi key generate\` / \`maruhi key recover\` では直せません。OS キーチェーンからサービス "${KEYCHAIN_SERVICE}" のエントリ ${quotedEntryName(entryName)} を手で削除してください。削除後、リカバリーコードがあれば \`maruhi key recover\` で元の鍵を復元できます(既存の値を復号し続けられます)。無い場合は \`maruhi key generate\` で新しい鍵を作れますが、既存プロジェクトの値は復号できなくなるため、管理者に自分宛ラップの再配布(\`maruhi member add\` の再実行)を依頼してください。`;
}

/**
 * 読めないレコードの分類。
 *
 * **削除を勧めてよいかの判定**であり、ここを誤ると鍵を恒久的に失わせる:
 * 将来版の maruhi が別の形で書いたレコードは現行の {@link parseStoredMasterKey}
 * を通らない(形が変われば必須フィールドの検査で落ちる)が、それは破損では
 * なく**その版では正しい鍵**である。区別せずに「消してください」と案内すると、
 * リカバリーコードが無い利用者は復元できなくなる。
 *
 * 判定は**削除を勧めない側へ倒す**: 「JSON ですらない」「JSON オブジェクトで
 * すらない」「現行スイートを名乗っているのに読めない」ときだけ破損とみなし、
 * それ以外(スイートが違う・無い・入れ子になっている等)は別形式扱いにする。
 * 将来の形がスイートをどこに置くかは今の実装からは分からないので、特定の
 * フィールド名に賭けない。逆に、レコードがオブジェクトであることは形式に
 * 依らない最低限の前提なので、そこまでは破損と言い切ってよい(言い切らないと
 * 更新しても直らない案内で行き止まりにする)。
 */
export function classifyUnreadableMasterKey(json: string): "corrupt" | "foreign" {
  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch {
    // JSON ですらない = どの版の maruhi も書かない形。消して安全
    return "corrupt";
  }
  // JSON のスカラー(null・数値・文字列・真偽値)= どの版の maruhi も鍵
  // レコードとして書かない形。ここを「別形式かもしれない」に倒すと、消して
  // よいはずの記録に「消さずに更新してください」と案内することになり、更新
  // しても永久に直らないまま generate / recover / show の全部を塞いでしまう
  // (逃げ道が無い)。配列は object 側 = 残す側に残す — 将来版が鍵を複数
  // 持つ入れ物として使う形は考えられる
  if (!isRecord(value)) {
    return "corrupt";
  }
  // 現行スイートを名乗っているのに読めない = 本当に壊れている
  if (value["suite"] === SUITE_ID) {
    return "corrupt";
  }
  // それ以外(スイートが違う・無い・入れ子になっている等)は**別形式かも
  // しれない**。単一のフィールド名に賭けて「消してよい」と判定しない —
  // 誤れば鍵の恒久喪失で、取り違えの代償が両側で釣り合わない
  return "foreign";
}

/**
 * 現行版では読めない(将来版が書いた可能性がある)レコードの文言。
 *
 * **既定では削除を勧めない**。消すと、その版へ上げれば使えたはずの鍵を失う。
 *
 * ただし「残してください」だけで終えると、実際には壊れているレコード(形は
 * オブジェクトだがスイートを失った等)に当たった利用者が、更新しても直らない
 * まま `key generate` / `key recover` / `key show` の全部を塞がれる。そこで
 * 逃げ道は残すが、**リカバリーコードを条件にしない**: 新しい版がこのレコードを
 * 書いたなら、サーバーのリカバリーブロブも同じ形式で書かれている見込みが高く、
 * `key recover` も同じ理由で失敗する(消した後に気づくと恒久喪失)。条件では
 * なく**可逆性**で安全にする — 消す前に値を控えれば、戻せる。
 */
export function foreignMasterKeyMessage(suite: string | null, entryName: string): string {
  const named = suite === null ? "" : `(${escapeText(suite)})`;
  return `キーチェーンの master 鍵レコードをこのバージョンでは読み取れません${named}。より新しい maruhi が書いた可能性があるため、このレコードは残してください(消すと復元できなくなります)。maruhi を最新版へ更新してから再実行してください。更新しても直らない場合のみ、OS キーチェーンからサービス "${KEYCHAIN_SERVICE}" のエントリ ${quotedEntryName(entryName)} の**値を控えてから**削除すれば、\`maruhi key generate\` / \`maruhi key recover\` を試せます(控えがあれば元へ戻せます。控えずに消さないでください — リカバリーコードがあっても、登録済みのブロブが同じ新しい形式なら復元できません)。併せて不具合として報告してください`;
}

/** レコードから宣言スイートだけを取り出す(読めなければ null)。 */
export function declaredSuiteOf(json: string): string | null {
  try {
    const value: unknown = JSON.parse(json);
    return isRecord(value) && nonEmptyString(value["suite"]) ? value["suite"] : null;
  } catch {
    return null;
  }
}

/**
 * master 鍵レコードが壊れていて読めないときの文言(伏字以外の破損)。
 *
 * 伏字の場合と同じく**行き止まりにしない**のが要点: 上書き防止ガードは
 * レコードの存在だけを見るので、読めない記録が残っている限り
 * `key generate` / `key recover` / `key show` の全部が拒否され、CLI からは
 * 何もできなくなる。原因は違っても出口(手で消す)は同じなので、消すべき
 * エントリ名と、その後に取れる手を示す。
 */
export function corruptMasterKeyMessage(entryName: string): string {
  return `キーチェーンの master 鍵レコードを読み取れません(記録が壊れています)。${manualDeletionGuidance(entryName)}`;
}

/**
 * master 鍵レコードに伏字が保存されていたときの文言。
 *
 * こちらはコマンドだけでは直らない: 上書き防止ガード({@link masterKeyEntryName}
 * のエントリが存在する時点で `key generate` / `key recover` は拒否される —
 * 鍵を失うと復号可能性を失うため)に阻まれる。OS キーチェーンからエントリを
 * 手で消す以外に道が無いので、消すべきエントリ名まで書く。
 *
 * 削除後の手順を**両方**示すのが要点: どちらが使えるかは利用者の状況で決まる。
 * リカバリーコードがあれば `key recover` が元の鍵を戻して復号可能性を保てるが、
 * 無ければ `key generate` で作り直すしかない(その場合は既存の値を復号できず、
 * 自分宛ラップの再配布が要る)。`key recover` だけを案内すると、コードを持たない
 * 利用者は「別デバイスで再登録してください」という実行できない案内へ送られる。
 */
export function redactedPlaceholderMasterKeyMessage(entryName: string): string {
  // entryName は user_id(サーバー配布の自由文字列)を含む。端末へ出す前に
  // 無害化するが、**潰さずエスケープする**: この名前は「消してください」と
  // 案内する操作対象そのものであり、置換文字に潰すと実在しない名前を案内して
  // 唯一の復旧手順が実行不能になる。
  //
  // ただしエスケープ後の文字列は原文そのものではない(制御文字・`\`・`"` を
  // 含む user_id では表記が変わる)。**エスケープしてある旨を文面に明記する** —
  // 書かないと、利用者は表示どおりの名前を探して見つけられない。
  return `${keychainPlaceholderCause}。${manualDeletionGuidance(entryName)}併せて不具合として報告してください`;
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
