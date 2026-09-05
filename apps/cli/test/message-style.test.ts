// ユーザーに見える文言の規約を機械検査にする(DP5 追補 E — 用語集を「守る」から
// 「壊れたら落ちる」へ)。対象は apps/cli/src の cliError / usageError /
// evidenceError / io.log / io.logError / logNote / logWarning に直接渡された
// 文字列リテラル(テンプレートリテラルを含む)。
//
// 規約(裁定録 E):
//   1. 末尾ピリオド無し(複文は文中のピリオドで区切り、最後には付けない)
//   2. コマンド名(`maruhi <command>`)は常にバッククォートで囲む
//   3. Markdown の強調(`**`)を端末に出さない

import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const SRC_DIR = join(import.meta.dirname, "..", "src");

const COMMANDS =
  "login|logout|pull|run|push|env|server|invite|member|key|project|ci|rotation|audit|config|schema|var";

/** 文言を運ぶ呼び出しの直後の文字列リテラル(エスケープ付きの引用符を跨がない)。 */
const MESSAGE_CALL =
  /(cliError|usageError|evidenceError|io\.log|io\.logError|logNote|logWarning)\(\s*(["`])((?:\\.|(?!\2).)*)\2/gs;

interface Hit {
  readonly file: string;
  readonly line: number;
  readonly text: string;
}

async function collectMessages(): Promise<Hit[]> {
  const hits: Hit[] = [];
  for (const name of (await readdir(SRC_DIR)).filter((entry) => entry.endsWith(".ts")).toSorted()) {
    const source = await readFile(join(SRC_DIR, name), "utf8");
    for (const match of source.matchAll(MESSAGE_CALL)) {
      const text = match[3] ?? "";
      const line = source.slice(0, match.index).split("\n").length;
      hits.push({ file: name, line, text });
    }
  }
  return hits;
}

const label = (hit: Hit) => `${hit.file}:${hit.line}: ${hit.text.slice(0, 80)}`;

describe("ユーザーに見える文言の規約(apps/cli/src)", () => {
  it("十分な数の文言を拾っている(検査が空回りしていない)", async () => {
    expect((await collectMessages()).length).toBeGreaterThan(300);
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
