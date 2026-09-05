// `--help` の整合(DP5 裁定 F): 全コマンド段 + bare `maruhi` + `maruhi --help` の
// 出力を golden ファイル(test/golden/help.txt)で固定する。
//
// - 文言を変えたら `UPDATE_GOLDEN=1 bunx vitest run --project cli test/help.test.ts`
//   で更新し、差分をレビューで読む(usage 行と実際のフラグ・説明文の食い違いを
//   目で確かめる場所をここ 1 つにする)
// - 併せて機械検査: 説明文は動詞始まりの 1 行(仕様の § 参照を含まない —
//   利用者はスペックを読めない)、ヘルプは stderr、色は付かない(テスト環境)

import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { COMMAND_SPECS, ROOT_SPEC_KEY } from "../src/effect-cli.ts";
import { makeTestEnv } from "./support/env.ts";

const GOLDEN_PATH = join(import.meta.dirname, "golden", "help.txt");
const ESC = "\u001B";

/** 1 段ぶんのヘルプ(stderr)を採取する。 */
async function helpOf(argv: readonly string[]): Promise<string> {
  const env = await makeTestEnv();
  const code = await runCli(argv, env.layer);
  expect(code, argv.join(" ")).toBe(0);
  // ヘルプは stdout を汚さない(ADR-0016 決定 9)
  expect(env.logs, argv.join(" ")).toEqual([]);
  return env.errors.join("\n");
}

async function renderAll(): Promise<string> {
  const keys = Object.keys(COMMAND_SPECS).filter((key) => key !== ROOT_SPEC_KEY);
  const sections: string[] = [];
  sections.push(`$ maruhi\n${await helpOf([])}`);
  sections.push(`$ maruhi --help\n${await helpOf(["--help"])}`);
  for (const key of keys) {
    const argv = [...key.split(" "), "--help"];
    sections.push(`$ maruhi ${key} --help\n${await helpOf(argv)}`);
  }
  return `${sections.join("\n\n")}\n`;
}

describe("--help の整合(golden)", () => {
  it("全コマンドの --help は golden と一致する(更新は UPDATE_GOLDEN=1)", async () => {
    const rendered = await renderAll();
    if (process.env["UPDATE_GOLDEN"] === "1") {
      await writeFile(GOLDEN_PATH, rendered);
    }
    const golden = await readFile(GOLDEN_PATH, "utf8");
    expect(rendered).toBe(golden);
  });

  it("説明文は動詞始まりの 1 行で、仕様の § 参照と ANSI を含まない", async () => {
    const rendered = await renderAll();
    expect(rendered).not.toContain(ESC);
    expect(rendered).not.toContain("§");
    // DESCRIPTION の直後の行 = 説明文。大文字の動詞で始まる(sentence case)
    const lines = rendered.split("\n");
    const descriptions = lines.flatMap((line, index) =>
      line === "DESCRIPTION" ? [lines[index + 1] ?? ""] : [],
    );
    expect(descriptions.length).toBeGreaterThan(40);
    for (const description of descriptions) {
      expect(description, description).toMatch(/^ {2}[A-Z][a-z]+(-[a-z]+)? /);
    }
  });
});
