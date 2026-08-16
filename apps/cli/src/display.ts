// 端末出力のサニタイズと表示整形。
//
// 変数の表示名・user_id 等はサーバー配布の非認証メタデータ(自由文字列)で、
// 改行・ANSI エスケープを含められる。生のまま端末へ流すと偽行・誘導文の
// 混入(端末インジェクション)になるため、制御文字を可視の代替文字に置換
// してから表示する。値(--show)は対象外: 値はメンバーが E2EE で書いた
// データでサーバーには偽造できず、改変すれば復号失敗に落ちる。

import { Effect, Redacted, type Stdio } from "effect";

import { ensureValueDisplayAllowed } from "./agent-gate.ts";
import { cliError, type CliError } from "./errors.ts";
import { CliIo } from "./io.ts";

// Unicode カテゴリ Cc = C0 制御(NUL〜US)+ DEL + C1 制御(ANSI CSI を含む)
const CONTROL_CHARS = /\p{Cc}/gu;
// escapeText が素通しする範囲 = 印字可能 ASCII(U+0020〜U+007E)から
// バックスラッシュと引用符を除いたもの。それ以外は一律に逃がす。
// バックスラッシュは可逆性(逃がした表記と元から同じ見た目の文字列が衝突しない)、
// 引用符は引用符で囲んだ表示を閉じられないことに要る
const ESCAPABLE = /[^\u0020-\u007E]|["\\]/gu;

/** Replaces control characters (C0 / C1 / DEL) for safe terminal display. */
export function displayText(value: string): string {
  return value.replace(CONTROL_CHARS, "\uFFFD");
}

/**
 * Escapes everything outside printable ASCII (plus `\` and `"`) as `\u{XXXX}`,
 * so the rendered text is exactly reconstructible.
 *
 * {@link displayText} は置換文字に潰すため、**利用者が元の文字列を復元できない**。
 * 「この名前のエントリを消してください」のように文字列そのものを操作対象として
 * 案内する場面では潰してはいけない(消せない名前を案内することになる)ので、
 * 端末へ流しても危険のない形にエスケープしたうえで原文を保つ。
 *
 * **許可制(allow-list)にしている理由**: 危険な文字を列挙して逃がす形では
 * 閉じない。制御文字・書式文字・孤立サロゲート・行区切りと足していっても、
 * 最後に同形異字(Latin `a` U+0061 と Cyrillic `а` U+0430 など)が残り、これは
 * **見た目が同一なので文字クラスでは区別できない**。「表示された名前 = 実際の
 * 名前」を本当に成り立たせるには、安全と分かっている範囲だけを素通しし、
 * 残りを一律に逃がすしかない。非 ASCII の user_id は冗長な表記になるが、
 * この関数の目的は可読性ではなく**操作対象としての一致**なので、そちらを取る。
 */
export function escapeText(value: string): string {
  return value.replace(ESCAPABLE, (char) =>
    char === "\\" || char === '"'
      ? `\\${char}`
      : `\\u{${(char.codePointAt(0) ?? 0xff_fd).toString(16).padStart(4, "0")}}`,
  );
}

// 値の表示(pull --show)用: 端末インジェクションの媒介(ESC・BEL・C1・
// CR 等)は中和しつつ、正当なシークレット(複数行 PEM 鍵など)を壊さないよう
// タブ(\t)と改行(\n)だけは残す。値は共同編集者(正当な書き手)が保存する
// ため、悪意ある値による他メンバーの端末改ざんを防ぐ(サーバー偽造とは別脅威)
const VALUE_CONTROL_CHARS = /[^\P{Cc}\t\n]/gu;

/** Neutralizes injection-capable control chars in a secret value, keeping \t and \n. */
function displayValue(value: string): string {
  return value.replace(VALUE_CONTROL_CHARS, "\uFFFD");
}

// ---------------------------------------------------------------------------
// コマンド出力の整形ヘルパ(旧 cli.ts から移動)
// ---------------------------------------------------------------------------

/** pull 一覧行の対象(pull.ts の DecryptedVariable の表示部分)。 */
export interface DisplayableVariable {
  readonly name: string;
  readonly version: number;
  readonly epoch: number;
  readonly value: Redacted.Redacted<Uint8Array>;
}

/**
 * pull のメタデータ一覧 1 行。
 *
 * 剥がす理由: **バイト長だけ**を読む(値は行に載せない)。この行は --show の
 * 有無に関わらず出るため値表示ゲートの手前にあり、ここで値そのものを出力に
 * 混ぜてはならない。
 */
export function formatPulledLine(variable: DisplayableVariable): string {
  const byteLength = Redacted.value(variable.value).byteLength;
  return `${displayText(variable.name)}\tversion=${variable.version}\tepoch=${variable.epoch}\t(${byteLength} bytes)`;
}

/** 検証中に収集した SHOULD 警告(非 NFC 名の配布等 — §12-1)を表示する。 */
export function logWarnings(warnings: readonly string[]): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    for (const warning of warnings) {
      yield* io.logError(`警告: ${warning}`);
    }
  });
}

const strictValueDecoder = new TextDecoder("utf-8", { fatal: true });

/**
 * 値バイト列 → テキストの唯一のデコード方針(fatal)。不正 UTF-8 は null
 * (呼び出し側が変数名付きの明示エラーにする)。
 *
 * 方針の選定: run(環境変数注入)は fatal 必須であり、表示側だけ置換文字で
 * 通すと「--show では表示できるのに run では失敗する」非対称と、置換文字で
 * 静かに壊れた値のコピー事故を生む。両経路とも fatal に統一する(pull --show の
 * 不正 UTF-8 値は置換表示からハードエラーへの挙動変更)。
 */
export function decodeValueText(value: Uint8Array): string | null {
  try {
    return strictValueDecoder.decode(value);
  } catch {
    // fatal デコーダの例外は「不正 UTF-8」の判定値として扱う(値は運ばない)
    return null;
  }
}

/** 値の端末表示(pull --show)。表示可否は agent-gate.ts が拒否する。 */
export function showValues(
  variables: readonly DisplayableVariable[],
): Effect.Effect<void, CliError, CliIo | Stdio.Stdio> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    // コマンド入口(復号前)の検査が本線。復号後のこの検査は、showValues を
    // 直接呼ぶ将来の経路が入口検査を欠いても表示に至らせない防衛線。
    // **両方**を新しい gate(TTY 一次境界)に揃える — 片方を deny-list の
    // まま残すと、防衛線側だけ未知のエージェントに素通りされる
    yield* ensureValueDisplayAllowed;
    // 全値のデコードを出力より前に完了させる(all-or-nothing)。1 値でも不正
    // UTF-8 なら何も表示せず失敗し、部分出力(前半の値だけ画面に残る)を作らない
    const lines: string[] = [];
    for (const variable of variables) {
      // 剥がす理由: 値の表示がこのコマンドの機能そのもの。**必ず上の
      // ensureValueDisplayAllowed(TTY 一次境界 + エージェント二次層)を
      // 通った後**で剥がす — ゲートより前に剥がすと、拒否される環境でも
      // 平文がメモリ上の文字列として組み上がってしまう
      const text = decodeValueText(Redacted.value(variable.value));
      if (text === null) {
        return yield* Effect.fail(
          cliError(
            `変数 ${displayText(variable.name)} の値は UTF-8 として不正のため表示できません(バイナリ値は --show の対象外です)`,
          ),
        );
      }
      lines.push(`${displayText(variable.name)}=${displayValue(text)}`);
    }
    for (const line of lines) {
      yield* io.log(line);
    }
  });
}
