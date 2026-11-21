import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";

import { afterAll, describe, expect, it } from "vite-plus/test";

const CLI_ROOT = join(import.meta.dirname, "..");
const SRC_DIR = realpathSync(join(CLI_ROOT, "src"));
const TRACE_PRELOAD = join(import.meta.dirname, "support", "import-trace.ts");

const LAZY_ONLY = ["context.ts", "api.ts", "session.ts", "chain-sync.ts"];

const scratch = mkdtempSync(join(tmpdir(), "maruhi-startup-loads-"));
afterAll(() => {
  rmSync(scratch, { recursive: true, force: true });
});
let runCount = 0;

interface TracedRun {
  readonly status: number | null;
  readonly stderr: string;
  readonly loaded: ReadonlyMap<string, string | null>;
}

function sourcePath(file: string): string | null {
  const path = relative(SRC_DIR, file);
  return path.startsWith("..") ? null : path.split(sep).join("/");
}

function tracedRun(args: readonly string[]): TracedRun {
  runCount += 1;
  const trace = join(scratch, `${runCount}.trace`);
  const result = spawnSync("bun", ["--preload", TRACE_PRELOAD, "src/bin.ts", ...args], {
    cwd: CLI_ROOT,
    encoding: "utf8",
    env: {
      ...process.env,
      IMPORT_TRACE: trace,
      MARUHI_CONFIG_DIR: mkdtempSync(join(scratch, "config-")),
    },
    timeout: 20_000,
  });
  const loaded = new Map<string, string | null>([["bin.ts", null]]);
  const lines = existsSync(trace) ? readFileSync(trace, "utf8").split("\n") : [];
  for (const line of lines) {
    const [importer = "", specifier = ""] = line.split("\t");
    const from = sourcePath(importer);
    const file = specifier.startsWith(".")
      ? sourcePath(resolve(dirname(importer), specifier))
      : null;
    if (from !== null && file !== null && !loaded.has(file)) {
      loaded.set(file, from);
    }
  }
  return { status: result.status, stderr: result.stderr, loaded };
}

function heavyLoads(run: TracedRun): readonly string[] {
  return LAZY_ONLY.filter((file) => run.loaded.has(file)).map((file) => {
    const chain = [file];
    for (
      let from = run.loaded.get(file);
      from !== undefined && from !== null && !chain.includes(from);
      from = run.loaded.get(from)
    ) {
      chain.unshift(from);
    }
    return chain.join(" -> ");
  });
}

describe("the CLI's startup loads (bin.ts run from source, P-6)", () => {
  it("names modules that exist", () => {
    for (const file of LAZY_ONLY) {
      expect(existsSync(join(SRC_DIR, file)), file).toBe(true);
    }
  });

  it.each([
    { args: "--version", status: 0 },
    { args: "--help", status: 0 },
    { args: "env --help", status: 0 },
    { args: "pull --no-such-flag", status: 2 },
  ])("maruhi $args loads none of them", ({ args, status }) => {
    const run = tracedRun(args.split(" "));
    expect(run.status, run.stderr).toBe(status);
    expect(run.loaded.has("commands/index.ts")).toBe(true);
    expect(run.loaded.has("commands/lazy.ts")).toBe(true);
    expect(heavyLoads(run)).toEqual([]);
  });

  it("sees a handler's load (the trace follows dynamic imports)", () => {
    const run = tracedRun(["env", "list"]);
    expect(run.stderr).toContain("No project specified");
    expect(run.loaded.get("context.ts")).toBe("commands/lazy.ts");
  });
});
