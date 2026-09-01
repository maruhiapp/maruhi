// `.env` / `.env.example` 形式の最小パーサ(`maruhi schema import` の入力層 —
// 設計文書 §1-3 の (1))。
//
// **クライアント側でのみ読む**。値は読み取り直後に Redacted で包み、以降は
// 型推論(値の**形**の観察 — CRYPTO_SPEC §4.2 の閉集合)と「実値らしさ」の
// 判定にのみ使う。値・値の断片を端末・ログ・エラーへ出さない(ゼロ知識維持 —
// 値そのものは観察のみで送信しない。送信は利用者が変数ごとに明示選択した
// activation の値 push だけで、それは push.ts の既存暗号境界を通る)。
//
// 対応する構文は意図的に最小(新規依存を追加しない — CLAUDE.md):
//   - `KEY=VALUE`(最初の `=` で分割)
//   - `export KEY=VALUE`(接頭辞を剥がす)
//   - `#` 始まりのコメント行(**直前の連続コメント** → description 候補。
//     空行・非コメント行で候補はリセットする)
//   - 値の両端の一致する引用符('…' / "…")は 1 対だけ剥がす(エスケープ・
//     変数展開・複数行値は解釈しない — 解釈の複雑化は値の誤読 = 誤った型推論に
//     しかならず、宣言はどのみち利用者が対話で承認・編集する)
//
// 受理できない行は**行番号と理由だけ**を持って skipped に落とす(行の内容は
// 運ばない — 壊れた行は値そのものでありうる)。

import type { MetaVarType } from "@maruhi/crypto";
import { Redacted } from "effect";

/**
 * import が候補にする変数名の形式: POSIX 環境変数名(先頭が英字か `_`、以降は
 * 英数字と `_`)。`.env` の名前は子プロセスの環境変数名になる前提であり、
 * サーバーの表示名受理(AUTH_SPEC §12-1 — NFC・256 文字)より狭い集合を要求
 * する。ASCII のみなので NFC 正規形であることは自明に満たす。
 */
const ENV_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** 名前の長さ上限(AUTH_SPEC §12-8 の表示名 256 文字と同じ値)。 */
const MAX_NAME_LENGTH = 256;

/** 1 行がスキップされた理由(内容は運ばない — 表示は理由と行番号のみ)。 */
export type EnvFileSkipReason = "not-an-assignment" | "invalid-name" | "duplicate-name";

/** スキップされた行(行番号は 1 始まり)。 */
export interface EnvFileSkippedLine {
  readonly line: number;
  readonly reason: EnvFileSkipReason;
  /**
   * 名前だけは表示してよい場合に持つ(duplicate-name — 有効な名前の重複)。
   * invalid-name / not-an-assignment の行内容は値でありうるため運ばない。
   */
  readonly name?: string;
}

/** 解釈できた 1 変数(値は Redacted — 観察以外に使わない)。 */
export interface EnvFileEntry {
  /** NFC 正規化済みの変数名(ASCII のみなので正規化は恒等)。 */
  readonly name: string;
  /** 行番号(1 始まり — 承認プロンプトの文脈表示用)。 */
  readonly line: number;
  /** 値(読み取り直後に Redacted — 剥がすのは observeValue の観察のみ)。 */
  readonly value: Redacted.Redacted<string>;
  /** 直前の連続コメントから組んだ description 候補("" = 候補なし)。 */
  readonly descriptionCandidate: string;
}

/** parseEnvFile の結果。 */
export interface ParsedEnvFile {
  readonly entries: readonly EnvFileEntry[];
  readonly skipped: readonly EnvFileSkippedLine[];
}

/** 値の両端の一致する引用符 1 対を剥がす(エスケープは解釈しない)。 */
function unquote(raw: string): string {
  if (raw.length >= 2) {
    const first = raw[0];
    if ((first === '"' || first === "'") && raw.endsWith(first)) {
      return raw.slice(1, -1);
    }
  }
  return raw;
}

/**
 * Parses `.env` / `.env.example` text into schema candidates (設計文書 §1-3).
 * Values are wrapped in `Redacted` immediately; malformed lines carry only
 * their line number and a reason (the content may be a value).
 */
export function parseEnvFile(content: string): ParsedEnvFile {
  const entries: EnvFileEntry[] = [];
  const skipped: EnvFileSkippedLine[] = [];
  const seen = new Set<string>();
  /** 直前の連続コメント行(次の代入行の description 候補)。 */
  let comments: string[] = [];
  const lines = content.split(/\r?\n/);
  for (const [index, rawLine] of lines.entries()) {
    const lineNumber = index + 1;
    const line = rawLine.trim();
    if (line === "") {
      // 空行はコメントブロックの区切り(離れたコメントを候補にしない)
      comments = [];
      continue;
    }
    if (line.startsWith("#")) {
      comments.push(line.replace(/^#+\s?/, ""));
      continue;
    }
    const assignment = line.startsWith("export ") ? line.slice("export ".length).trim() : line;
    const separator = assignment.indexOf("=");
    if (separator < 0) {
      skipped.push({ line: lineNumber, reason: "not-an-assignment" });
      comments = [];
      continue;
    }
    const name = assignment.slice(0, separator).trim().normalize("NFC");
    if (!ENV_NAME_PATTERN.test(name) || name.length > MAX_NAME_LENGTH) {
      skipped.push({ line: lineNumber, reason: "invalid-name" });
      comments = [];
      continue;
    }
    if (seen.has(name)) {
      // 同名の後勝ち・先勝ちを黙って選ばない — 重複は理由つきでスキップし、
      // 最初の出現だけを候補にする(名前は有効なので表示してよい)
      skipped.push({ line: lineNumber, reason: "duplicate-name", name });
      comments = [];
      continue;
    }
    seen.add(name);
    entries.push({
      name,
      line: lineNumber,
      // 値はここで包む — 以降は observeValue の観察でしか剥がさない
      value: Redacted.make(unquote(assignment.slice(separator + 1).trim()), {
        label: "env-file-value",
      }),
      descriptionCandidate: comments.join(" ").trim(),
    });
    comments = [];
  }
  return { entries, skipped };
}

/* -------------------------------------------------------------------------- */
/* 値の観察(型推論・実値らしさ — 値そのものは外へ出さない)                    */
/* -------------------------------------------------------------------------- */

// number の形は run.ts の advisory 型検証と同じ判定(10 進表記のみ — "0x1f" /
// "Infinity" を number に数えない)。判定器を共有しないのは import 側が
// Redacted の観察境界の中で完結するため(文字列の正規表現 1 本を重複と数えない)
const NUMBER_TEXT = /^-?(?:\d+)(?:\.\d+)?(?:[eE][+-]?\d+)?$/;

// プレースホルダらしさ: `.env.example` の慣用形。実値でないと判断した値は
// activation の提案自体を出さない(送信の既定は常に「しない」であり、これは
// 提案 UX の絞り込みにすぎない — 誤判定の帰結は「提案が出ない / 出る」のみ)
const PLACEHOLDER_PATTERNS = [
  /^<[^>]*>$/,
  /^\$\{[^}]*\}$/,
  /^(changeme|change-me|change_me|todo|tbd|placeholder|dummy|sample|xxx+|\.{3})$/i,
  /^your[-_]/i,
];

/** 値の観察結果(値そのものを運ばない — 型候補と実値らしさのみ)。 */
export interface ObservedValue {
  /** 型推論(値の形の観察 — 自信がなければ "" 未指定)。 */
  readonly varType: MetaVarType;
  /** 実値らしいか(空・プレースホルダ慣用形は false)。 */
  readonly looksReal: boolean;
}

/**
 * Observes one value's **shape** for type inference (CRYPTO_SPEC §4.2 closed
 * set) and placeholder-ness. The value itself never leaves this function —
 * only the inferred type and a boolean.
 */
export function observeValue(value: Redacted.Redacted<string>): ObservedValue {
  // 剥がす理由: 形の観察(型推論・実値らしさ)。産物は閉集合の型名と真偽値
  // だけで、値・値の断片はこの関数の外へ出ない
  const text = Redacted.value(value).trim();
  if (text === "") {
    return { varType: "", looksReal: false };
  }
  const looksReal = !PLACEHOLDER_PATTERNS.some((pattern) => pattern.test(text));
  if (text === "true" || text === "false") {
    return { varType: "boolean", looksReal };
  }
  if (NUMBER_TEXT.test(text)) {
    return { varType: "number", looksReal };
  }
  if (/^https?:\/\/\S+$/.test(text) && URL.canParse(text)) {
    return { varType: "url", looksReal };
  }
  // どの形にも確信が持てない値は "" 未指定(任意の値は string でありうるため、
  // string の推論は情報を足さない — 利用者が承認時に編集できる)
  return { varType: "", looksReal };
}
