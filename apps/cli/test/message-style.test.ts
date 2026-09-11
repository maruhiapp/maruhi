// ユーザーに見える文言の規約を機械検査にする(DP5 追補 E — 用語集を「守る」から
// 「壊れたら落ちる」へ)。対象は apps/cli/src の cliError / usageError /
// evidenceError / io.log / io.logError / logNote / logWarning に直接渡された
// 文字列リテラル(テンプレートリテラルを含む)。
//
// 加えて、SCREAMING_SNAKE_CASE の定数へ代入された文字列リテラル(名前付き
// 定数に切り出された文面 — `cliError(AUDIT_HEAD_NOT_READY_EXHAUSTED)` の形)も
// 同じ規約に掛ける。整形関数の中で組み立てる文面までは追わない(割り切り)。
//
// 規約(裁定録 E):
//   1. 末尾ピリオド無し(複文は文中のピリオドで区切り、最後には付けない)
//   2. コマンド名(`maruhi <command>`)は常にバッククォートで囲む
//   3. Markdown の強調(`**`)を端末に出さない

import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { COMMAND_SPECS, ROOT_SPEC_KEY } from "../src/effect-cli.ts";

const SRC_DIR = join(import.meta.dirname, "..", "src");

// トップレベルのコマンド名は宣言(COMMAND_SPECS)から導く — 手書きの写しを持つと、
// コマンドを足したときに規約 (2) がその名前を黙って見逃す
const COMMANDS = Object.keys(COMMAND_SPECS)
  .filter((key) => key !== ROOT_SPEC_KEY && !key.includes(" "))
  .join("|");

/** 文言を運ぶ呼び出しの直後の文字列リテラル(エスケープ付きの引用符を跨がない)。 */
const MESSAGE_CALL =
  /(cliError|usageError|evidenceError|io\.log|io\.logError|logNote|logWarning)\(\s*(["`])((?:\\.|(?!\2).)*)\2/gs;

/** 名前付き定数(SCREAMING_SNAKE_CASE)へ代入された文字列リテラル。 */
const MESSAGE_CONST =
  /(?:const|let)\s+([A-Z][A-Z0-9_]*)\s*(?::[^=]+)?=\s*(["`])((?:\\.|(?!\2).)*)\2/gs;

/**
 * ファイルへ書く本文(スナップショットのヘッダー・エクスポートのコメント行)は
 * 端末の 1 行ではなく文書なので、文末のピリオドは正当 — 名前の接尾辞で除く。
 */
const FILE_CONTENT_SUFFIX = /_(?:HEADER|COMMENT)$/;

interface Hit {
  readonly file: string;
  readonly line: number;
  readonly text: string;
  readonly kind: "call" | "const";
}

async function collectMessages(): Promise<Hit[]> {
  const hits: Hit[] = [];
  for (const name of (await readdir(SRC_DIR)).filter((entry) => entry.endsWith(".ts")).toSorted()) {
    const source = await readFile(join(SRC_DIR, name), "utf8");
    for (const match of source.matchAll(MESSAGE_CALL)) {
      const text = match[3] ?? "";
      const line = source.slice(0, match.index).split("\n").length;
      hits.push({ file: name, line, text, kind: "call" });
    }
    for (const match of source.matchAll(MESSAGE_CONST)) {
      if (FILE_CONTENT_SUFFIX.test(match[1] ?? "")) {
        continue;
      }
      const text = match[3] ?? "";
      const line = source.slice(0, match.index).split("\n").length;
      hits.push({ file: name, line, text, kind: "const" });
    }
  }
  return hits;
}

const label = (hit: Hit) => `${hit.file}:${hit.line}: ${hit.text.slice(0, 80)}`;

describe("ユーザーに見える文言の規約(apps/cli/src)", () => {
  it("十分な数の文言を拾っている(検査が空回りしていない)", async () => {
    const hits = await collectMessages();
    expect(hits.filter((hit) => hit.kind === "call").length).toBeGreaterThan(300);
    expect(hits.filter((hit) => hit.kind === "const").length).toBeGreaterThan(20);
  });

  it("1. 末尾にピリオドを付けない", async () => {
    const offenders = (await collectMessages()).filter((hit) => {
      const trimmed = hit.text.trimEnd();
      return trimmed.endsWith(".") && !trimmed.endsWith("...");
    });
    expect(offenders.map(label)).toEqual([]);
  });

  it("2. コマンド名はバッククォートで囲む", async () => {
    // 直前が バッククォート・英数字・`/` `-` `.`・エスケープの `\\` のどれでもない
    // `maruhi <command>` = 素のまま prose に置かれたコマンド名
    const bare = new RegExp(String.raw`(?<![\`\w/\-.\\])maruhi (?:${COMMANDS})\b`);
    const offenders = (await collectMessages()).filter((hit) => bare.test(hit.text));
    expect(offenders.map(label)).toEqual([]);
  });

  it("3. Markdown の強調を端末に出さない", async () => {
    const offenders = (await collectMessages()).filter((hit) => hit.text.includes("**"));
    expect(offenders.map(label)).toEqual([]);
  });
});
