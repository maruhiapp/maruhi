import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vite-plus/test";

import type { CommandSpec } from "../src/cli-formatter.ts";
import { runCli } from "../src/cli.ts";
import { COMMAND_SPECS, makeRootCommand, ROOT_SPEC_KEY } from "../src/commands/index.ts";
import { makeTestEnv } from "./support/env.ts";

const GOLDEN_PATH = join(import.meta.dirname, "golden", "command-specs.json");

interface CommandNode {
  readonly name: string;
  readonly subcommands: ReadonlyArray<{
    readonly commands: ReadonlyArray<CommandNode>;
  }>;
}

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
