import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vite-plus/test";

import { COMMAND_SPECS, ROOT_SPEC_KEY } from "../src/commands/index.ts";

const SRC_DIR = join(import.meta.dirname, "..", "src");

const COMMANDS = Object.keys(COMMAND_SPECS)
  .filter((key) => key !== ROOT_SPEC_KEY && !key.includes(" "))
  .join("|");

const MESSAGE_CALL =
  /(cliError|usageError|evidenceError|io\.log|io\.logError|logNote|logWarning)\(\s*(["`])((?:\\.|(?!\2).)*)\2/gs;

const MESSAGE_CONST =
  /(?:const|let)\s+([A-Z][A-Z0-9_]*)\s*(?::[^=]+)?=\s*(["`])((?:\\.|(?!\2).)*)\2/gs;

const FILE_CONTENT_SUFFIX = /_(?:HEADER|COMMENT)$/;

interface Hit {
  readonly file: string;
  readonly line: number;
  readonly text: string;
  readonly kind: "call" | "const";
}

async function srcFiles(): Promise<readonly string[]> {
  return (await readdir(SRC_DIR, { recursive: true }))
    .filter((entry) => entry.endsWith(".ts"))
    .map((name) => name.replaceAll("\\", "/"))
    .toSorted();
}

async function collectMessages(): Promise<Hit[]> {
  const hits: Hit[] = [];
  for (const name of await srcFiles()) {
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

describe("user-visible wording conventions (apps/cli/src)", () => {
  it("collects a sufficient number of messages (the check isn't idling)", async () => {
    expect((await srcFiles()).length).toBeGreaterThan(125);
    const hits = await collectMessages();
    expect(hits.filter((hit) => hit.kind === "call").length).toBeGreaterThan(995);
    expect(hits.filter((hit) => hit.kind === "const").length).toBeGreaterThan(59);
  });

  it("1. no trailing period", async () => {
    const offenders = (await collectMessages()).filter((hit) => {
      const trimmed = hit.text.trimEnd();
      return trimmed.endsWith(".") && !trimmed.endsWith("...");
    });
    expect(offenders.map(label)).toEqual([]);
  });

  it("2. command names are wrapped in backquotes", async () => {
    const bare = new RegExp(String.raw`(?<![\`\w/\-.\\])maruhi (?:${COMMANDS})\b`);
    const offenders = (await collectMessages()).filter((hit) => bare.test(hit.text));
    expect(offenders.map(label)).toEqual([]);
  });

  it("3. no Markdown emphasis is emitted to the terminal", async () => {
    const offenders = (await collectMessages()).filter((hit) => hit.text.includes("**"));
    expect(offenders.map(label)).toEqual([]);
  });
});
