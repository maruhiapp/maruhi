// Turns the user-visible wording conventions into a mechanical check (DP5
// supplement E — from "keeping" the glossary to "failing when it's
// broken"). In scope: string literals (including template literals) passed
// directly to cliError / usageError / evidenceError / io.log / io.logError
// / logNote / logWarning in apps/cli/src.
//
// Additionally, string literals assigned to SCREAMING_SNAKE_CASE constants
// (wording factored out into a named constant — the
// `cliError(AUDIT_HEAD_NOT_READY_EXHAUSTED)` shape) are subject to the same
// conventions. Wording assembled inside formatting functions is not
// followed (a deliberate cutoff).
//
// Conventions (ruling record E):
//   1. No trailing period (compound sentences separate with an in-text
//      period but end without one)
//   2. Command names (`maruhi <command>`) are always wrapped in backquotes
//   3. Markdown emphasis (`**`) is never shown on the terminal

import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { COMMAND_SPECS, ROOT_SPEC_KEY } from "../src/effect-cli.ts";

const SRC_DIR = join(import.meta.dirname, "..", "src");

// Top-level command names are derived from the declaration
// (COMMAND_SPECS) — a handwritten copy would let convention (2) silently
// miss a name when a command is added
const COMMANDS = Object.keys(COMMAND_SPECS)
  .filter((key) => key !== ROOT_SPEC_KEY && !key.includes(" "))
  .join("|");

/** The string literal right after a wording-carrying call (does not span escaped quotes). */
const MESSAGE_CALL =
  /(cliError|usageError|evidenceError|io\.log|io\.logError|logNote|logWarning)\(\s*(["`])((?:\\.|(?!\2).)*)\2/gs;

/** A string literal assigned to a named constant (SCREAMING_SNAKE_CASE). */
const MESSAGE_CONST =
  /(?:const|let)\s+([A-Z][A-Z0-9_]*)\s*(?::[^=]+)?=\s*(["`])((?:\\.|(?!\2).)*)\2/gs;

/**
 * A body written to a file (a snapshot's header, an export's comment line)
 * is a document rather than a terminal line, so a sentence-final period is
 * legitimate — excluded via a name suffix.
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

describe("user-visible wording conventions (apps/cli/src)", () => {
  it("collects a sufficient number of messages (the check isn't idling)", async () => {
    const hits = await collectMessages();
    expect(hits.filter((hit) => hit.kind === "call").length).toBeGreaterThan(300);
    expect(hits.filter((hit) => hit.kind === "const").length).toBeGreaterThan(20);
  });

  it("1. no trailing period", async () => {
    const offenders = (await collectMessages()).filter((hit) => {
      const trimmed = hit.text.trimEnd();
      return trimmed.endsWith(".") && !trimmed.endsWith("...");
    });
    expect(offenders.map(label)).toEqual([]);
  });

  it("2. command names are wrapped in backquotes", async () => {
    // `maruhi <command>` not preceded by a backquote, alphanumeric,
    // `/` `-` `.`, or the escape `\\` = a bare command name placed in
    // prose
    const bare = new RegExp(String.raw`(?<![\`\w/\-.\\])maruhi (?:${COMMANDS})\b`);
    const offenders = (await collectMessages()).filter((hit) => bare.test(hit.text));
    expect(offenders.map(label)).toEqual([]);
  });

  it("3. no Markdown emphasis is emitted to the terminal", async () => {
    const offenders = (await collectMessages()).filter((hit) => hit.text.includes("**"));
    expect(offenders.map(label)).toEqual([]);
  });
});
