// COMMAND_SPECS is the single declaration the dispatch diagnostics
// (cli.ts's positionalTokens lexer), the --help walk (help.test.ts), and
// the wording checks (message-style.test.ts) all read. Three drift detectors:
//
// - The golden pins the table itself, key order included
//   (JSON.stringify serializes insertion order, so a reordered entry is a
//   diff). Regenerate with `UPDATE_GOLDEN=1 bunx vitest run --project cli
//   test/command-specs.test.ts` and read the diff in review
// - The tree walk compares the table against the Command structure
//   makeRootCommand actually builds (the public `name` / `subcommands`
//   fields): a command with no spec entry, or a spec entry for no command,
//   fails as a mismatch — never as a snapshot to regenerate
// - The name check compares each entry's flags and positionals with the
//   ones the command's --help lists, in order: the diagnostics print a
//   spec's names as typed (`--<name>`, `<name>`), so a config key that is
//   not its parameter's typed name would name one that does not exist

import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import type { CommandSpec } from "../src/cli-formatter.ts";
import { runCli } from "../src/cli.ts";
import { COMMAND_SPECS, makeRootCommand, ROOT_SPEC_KEY } from "../src/commands/index.ts";
import { makeTestEnv } from "./support/env.ts";

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

/** The names a --help section lists, in order (`--server` under FLAGS; `path` for `path...` under ARGUMENTS). */
function helpNames(help: string, heading: string): readonly string[] {
  const lines = help.split("\n");
  const start = lines.indexOf(heading);
  if (start === -1) {
    return [];
  }
  const names: string[] = [];
  for (const line of lines.slice(start + 1)) {
    const name = /^ {2}(\S+?)(?:\.\.\.)?(?:,| |$)/.exec(line)?.[1];
    if (name === undefined) {
      break;
    }
    names.push(name);
  }
  return names;
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

  it("names each parameter as it is typed: an entry lists what its command's --help lists, in order", async () => {
    const declared: Record<string, Pick<CommandSpec, "flags" | "positionals">> = {};
    const listed: typeof declared = {};
    for (const [key, spec] of Object.entries(COMMAND_SPECS)) {
      const argv = key === ROOT_SPEC_KEY ? ["--help"] : [...key.split(" "), "--help"];
      const env = await makeTestEnv();
      expect(await runCli(argv, env.layer), key).toBe(0);
      const help = env.errors.join("\n");
      declared[key] = { flags: spec.flags, positionals: spec.positionals };
      listed[key] = {
        flags: helpNames(help, "FLAGS").map((flag) => flag.slice("--".length)),
        positionals: helpNames(help, "ARGUMENTS"),
      };
    }
    expect(declared).toEqual(listed);
  });
});
