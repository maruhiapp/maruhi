// `--help` consistency (DP5 ruling F): pin the output of every command
// level + bare `maruhi` + `maruhi --help` against the golden file
// (test/golden/help.txt).
//
// - When the wording changes, regenerate with `UPDATE_GOLDEN=1 bunx vitest
//   run --project cli test/help.test.ts` and read the diff in review (this is
//   the single place where usage lines vs. actual flags/descriptions are
//   checked by eye)
// - Plus a mechanical check: descriptions are one verb-led line (no § spec
//   references — users can't read the spec), help goes to stderr, and no
//   color (test environment)

import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { COMMAND_SPECS, ROOT_SPEC_KEY } from "../src/effect-cli.ts";
import { makeTestEnv } from "./support/env.ts";

const GOLDEN_PATH = join(import.meta.dirname, "golden", "help.txt");
const ESC = "\u001B";

/** Captures one command level's help (stderr). */
async function helpOf(argv: readonly string[]): Promise<string> {
  const env = await makeTestEnv();
  const code = await runCli(argv, env.layer);
  expect(code, argv.join(" ")).toBe(0);
  // Help does not pollute stdout (ADR-0016 decision 9)
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

describe("--help consistency (golden)", () => {
  it("every command's --help matches the golden (regenerate with UPDATE_GOLDEN=1)", async () => {
    const rendered = await renderAll();
    if (process.env["UPDATE_GOLDEN"] === "1") {
      await writeFile(GOLDEN_PATH, rendered);
    }
    const golden = await readFile(GOLDEN_PATH, "utf8");
    expect(rendered).toBe(golden);
  });

  it("color follows CliIo's judgement: headings are bold when enabled, no ANSI when disabled (pipe, NO_COLOR)", async () => {
    const colored = await makeTestEnv();
    colored.setColor(true);
    expect(await runCli(["pull", "--help"], colored.layer)).toBe(0);
    const withColor = colored.errors.join("\n");
    expect(withColor).toContain(`${ESC}[1mDESCRIPTION${ESC}[0m`);
    expect(colored.logs).toEqual([]);
    const plain = await makeTestEnv();
    expect(await runCli(["pull", "--help"], plain.layer)).toBe(0);
    expect(plain.errors.join("\n")).not.toContain(ESC);
  });

  it("descriptions are one verb-led line and contain no spec § references", async () => {
    const rendered = await renderAll();
    expect(rendered).not.toContain("§");
    // The line right after DESCRIPTION = the description. It starts with a
    // capitalized verb (sentence case)
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
