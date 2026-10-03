// COMMAND_SPECS is the single declaration the dispatch diagnostics
// (cli.ts's positionalTokens lexer), the --help walk (help.test.ts), and
// the wording checks (message-style.test.ts) all read. Two drift detectors:
//
// - The golden pins the table itself, key order included
//   (JSON.stringify serializes insertion order, so a reordered entry is a
//   diff). Regenerate with `UPDATE_GOLDEN=1 bunx vitest run --project cli
//   test/command-specs.test.ts` and read the diff in review
// - The tree walk compares the table against the Command structure
//   makeRootCommand actually builds (the public `name` / `subcommands`
//   fields): a command with no spec entry, or a spec entry for no command,
//   fails as a mismatch — never as a snapshot to regenerate

import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { COMMAND_SPECS, makeRootCommand, ROOT_SPEC_KEY } from "../src/commands/index.ts";

const GOLDEN_PATH = join(import.meta.dirname, "golden", "command-specs.json");

/** The public fields of a `Command` node the walk reads (effect/cli's generics are irrelevant to a name comparison). */
interface CommandNode {
  readonly name: string;
  readonly subcommands: ReadonlyArray<{
    readonly commands: ReadonlyArray<CommandNode>;
  }>;
}

/** Every command path under the root ("env rotate", "key seal passkey", ...). */
function commandPaths(root: CommandNode): readonly string[] {
  const paths: string[] = [];
  const walk = (command: CommandNode, prefix: string): void => {
    const path = prefix === "" ? command.name : `${prefix} ${command.name}`;
    paths.push(path);
    for (const group of command.subcommands) {
      for (const subcommand of group.commands) {
        walk(subcommand, path);
      }
    }
  };
  for (const group of root.subcommands) {
    for (const subcommand of group.commands) {
      walk(subcommand, "");
    }
  }
  return paths;
}

describe("COMMAND_SPECS", () => {
  it("matches the golden snapshot (regenerate with UPDATE_GOLDEN=1)", async () => {
    const rendered = `${JSON.stringify(COMMAND_SPECS, null, 2)}\n`;
    if (process.env["UPDATE_GOLDEN"] === "1") {
      await writeFile(GOLDEN_PATH, rendered);
    }
    const golden = await readFile(GOLDEN_PATH, "utf8");
    expect(rendered).toBe(golden);
  });

  it("covers exactly the commands the tree declares (a miss in either direction is a bug)", () => {
    const root = makeRootCommand(() => {}) as unknown as CommandNode;
    const expected = Object.keys(COMMAND_SPECS).filter((key) => key !== ROOT_SPEC_KEY);
    expect(commandPaths(root).toSorted()).toEqual(expected.toSorted());
  });
});
