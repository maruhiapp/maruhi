import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vite-plus/test";

const siteRoot = join(import.meta.dirname, "..", "..");
const page = readFileSync(join(siteRoot, "src", "content", "docs", "deploy-targets.mdx"), "utf8");
const shimBin = join(import.meta.dirname, "shims", "bin");

function shellBlocks(markdown: string): string[] {
  return [...markdown.matchAll(/```sh\n([\s\S]*?)```/g)].map((m) => m[1] ?? "");
}

const allBlocks = shellBlocks(page);
const RECIPE_PREFIX = "maruhi run --env production -- ";
const blocks = allBlocks.filter((b) => b.startsWith(RECIPE_PREFIX));
const workersRecipe = blocks.find((b) => b.includes("wrangler secret bulk"));
const vercelRecipe = blocks.find((b) => b.includes("vercel env add"));
const githubRecipe = blocks.find((b) => b.includes("gh secret set"));

const values = {
  DATABASE_URL: 'postgres://user:p@ss"word\\x#frag=1 ?a=b&c=d\n-- second line --',
  STRIPE_SECRET_KEY: "-sk_test_starts_with_a_dash",
} as const;

const githubValues = {
  NPM_TOKEN: values.DATABASE_URL,
  CODECOV_TOKEN: values.STRIPE_SECRET_KEY,
} as const;

interface MaruhiCall {
  readonly tool: "maruhi";
  readonly flags: Record<string, string>;
  readonly command: string[];
}
interface VendorCall {
  readonly tool: "wrangler" | "vercel" | "gh";
  readonly argv: string[];
  readonly stdin: string;
}
type Call = MaruhiCall | VendorCall;

function hasCommand(shell: string): boolean {
  return spawnSync("sh", ["-c", `command -v ${shell}`], { stdio: "ignore" }).status === 0;
}

const shells = ["sh", "bash", "zsh", "dash"].filter(hasCommand);
const hasJq = hasCommand("jq");
const inheritedPath = process.env["PATH"] ?? "";
const inheritedHome = process.env["HOME"];

let workDir: string | undefined;
afterEach(() => {
  if (workDir !== undefined) rmSync(workDir, { recursive: true, force: true });
  workDir = undefined;
});

function runRecipe(
  shell: string,
  recipe: string,
  injected: Readonly<Record<string, string>>,
  options: { readonly xtrace?: boolean } = {},
): { calls: Call[]; status: number | null; stderr: string } {
  workDir = mkdtempSync(join(tmpdir(), "maruhi-recipes-"));
  const log = join(workDir, "calls.jsonl");
  const valuesFile = join(workDir, "values.json");
  writeFileSync(log, "");
  writeFileSync(valuesFile, JSON.stringify(injected));
  const env: Record<string, string> = {
    PATH: `${shimBin}:${inheritedPath}`,
    HOME: inheritedHome ?? workDir,
    RECIPE_TEST_LOG: log,
    RECIPE_TEST_VALUES: valuesFile,
  };
  const args = ["-c", recipe];
  if (options.xtrace === true) {
    args.unshift("-x");
    env["RECIPE_TEST_XTRACE"] = "1";
  }
  const result = spawnSync(shell, args, { cwd: workDir, env, encoding: "utf8" });
  const calls = readFileSync(log, "utf8")
    .split("\n")
    .filter((line) => line !== "")
    .map((line) => JSON.parse(line) as Call);
  return { calls, status: result.status, stderr: result.stderr };
}

function vendorCalls(calls: Call[]): VendorCall[] {
  return calls.filter((c): c is VendorCall => c.tool !== "maruhi");
}

function maruhiCall(calls: Call[]): MaruhiCall {
  const call = calls.find((c): c is MaruhiCall => c.tool === "maruhi");
  expect(call).toBeDefined();
  return call as MaruhiCall;
}

function argvOf(call: Call): string[] {
  return call.tool === "maruhi" ? [...Object.values(call.flags), ...call.command] : call.argv;
}

const valueFragments = Object.values(values).flatMap((v) => [v, ...v.split("\n")]);

function expectValuesOffCommandLines(calls: Call[]): void {
  const commandLines = calls.flatMap(argvOf).join("\n");
  for (const fragment of valueFragments) {
    expect(commandLines).not.toContain(fragment);
  }
}

function expectValuesOffTrace(stderr: string): void {
  expect(stderr).toMatch(/^\+/m);
  for (const word of ["maruhi", "run", "--env", "production"]) {
    expect(stderr).toContain(word);
  }
  for (const fragment of valueFragments) {
    expect(stderr).not.toContain(fragment);
  }
}

describe("deploy-targets.mdx recipes (extracted from the page)", () => {
  it("has exactly one recipe per target, each starting with `maruhi run --env`", () => {
    expect(blocks).toHaveLength(3);
    expect(workersRecipe).toBeDefined();
    expect(vercelRecipe).toBeDefined();
    expect(githubRecipe).toBeDefined();
    expect(allBlocks.some((b) => b.includes("maruhi sync apply"))).toBe(true);
    for (const block of allBlocks) {
      expect(block).not.toMatch(
        /--value|--env-file|--body|\.env\b|npx|bunx|>(?!\s*\/dev\/null|&)|tee\b/,
      );
    }
  });

  it("runs under a POSIX shell available here", () => {
    expect(shells).toContain("sh");
  });

  it("has jq in CI, so the Workers recipe is never skipped there", () => {
    if (process.env["CI"] === undefined) return;
    expect(hasJq, "install jq on the CI runner: the Workers recipe check needs it").toBe(true);
  });

  it("has every shell the page names in CI (bash, zsh, dash), so none is silently skipped there", () => {
    if (process.env["CI"] === undefined) return;
    expect(shells, "install bash, zsh, and dash on the CI runner").toEqual([
      "sh",
      "bash",
      "zsh",
      "dash",
    ]);
  });

  describe.each(shells)("under %s", (shell) => {
    it.skipIf(!hasJq)(
      "Cloudflare Workers: one JSON object on wrangler's stdin, values off argv",
      () => {
        const { calls, status } = runRecipe(shell, workersRecipe ?? "", values);
        expect(status).toBe(0);
        const maruhi = maruhiCall(calls);
        expect(maruhi.flags).toEqual({ "--env": "production" });
        expect(maruhi.command[0]).toBe("jq");
        const [wrangler, ...rest] = vendorCalls(calls);
        expect(rest).toEqual([]);
        expect(wrangler).toMatchObject({ tool: "wrangler", argv: ["secret", "bulk"] });
        expect(JSON.parse(wrangler?.stdin ?? "")).toEqual(values);
        expectValuesOffCommandLines(calls);
      },
    );

    it.skipIf(!hasJq)(
      "Cloudflare Workers: a name without a value sends nothing (never a null = delete)",
      () => {
        const { calls, stderr } = runRecipe(shell, workersRecipe ?? "", {
          DATABASE_URL: values.DATABASE_URL,
        });
        expect(stderr).toContain("STRIPE_SECRET_KEY has no value");
        expect(vendorCalls(calls)).toEqual([
          { tool: "wrangler", argv: ["secret", "bulk"], stdin: "" },
        ]);
        expectValuesOffCommandLines(calls);
      },
    );

    it("Vercel: one call per name, the value on stdin with one trailing newline, values off argv", () => {
      const { calls, status } = runRecipe(shell, vercelRecipe ?? "", values);
      expect(status).toBe(0);
      const maruhi = maruhiCall(calls);
      expect(maruhi.flags).toEqual({ "--env": "production" });
      expect(maruhi.command[0]).toBe("sh");
      expect(vendorCalls(calls)).toEqual(
        Object.entries(values).map(([name, value]) => ({
          tool: "vercel",
          argv: ["env", "add", name, "production", "--force"],
          stdin: `${value}\n`,
        })),
      );
      expectValuesOffCommandLines(calls);
    });

    it.skipIf(!hasJq)("Cloudflare Workers: `set -x` never echoes a value", () => {
      const { status, stderr } = runRecipe(shell, workersRecipe ?? "", values, { xtrace: true });
      expect(status).toBe(0);
      expectValuesOffTrace(stderr);
    });

    it("Vercel: `set -x` never echoes a value (outer shell and the inner `sh -c`)", () => {
      const { calls, status, stderr } = runRecipe(shell, vercelRecipe ?? "", values, {
        xtrace: true,
      });
      expect(status).toBe(0);
      expect(vendorCalls(calls)).toHaveLength(2);
      expect(stderr).toContain("printenv");
      expect(stderr).toContain("STRIPE_SECRET_KEY");
      expectValuesOffTrace(stderr);
    });

    it("Vercel: a name without a value stops before anything is copied", () => {
      const { calls, status, stderr } = runRecipe(shell, vercelRecipe ?? "", {
        DATABASE_URL: values.DATABASE_URL,
      });
      expect(status).toBe(1);
      expect(stderr).toContain("STRIPE_SECRET_KEY has no value");
      expect(vendorCalls(calls)).toEqual([]);
    });

    it("GitHub Actions: one `gh secret set` per name, the value on stdin with one trailing newline, values off argv (no --body / -f)", () => {
      const { calls, status } = runRecipe(shell, githubRecipe ?? "", githubValues);
      expect(status).toBe(0);
      const maruhi = maruhiCall(calls);
      expect(maruhi.flags).toEqual({ "--env": "production" });
      expect(maruhi.command[0]).toBe("sh");
      expect(vendorCalls(calls)).toEqual(
        Object.entries(githubValues).map(([name, value]) => ({
          tool: "gh",
          argv: ["secret", "set", name],
          stdin: `${value}\n`,
        })),
      );
      expectValuesOffCommandLines(calls);
    });

    it("GitHub Actions: `set -x` never echoes a value (outer shell and the inner `sh -c`)", () => {
      const { calls, status, stderr } = runRecipe(shell, githubRecipe ?? "", githubValues, {
        xtrace: true,
      });
      expect(status).toBe(0);
      expect(vendorCalls(calls)).toHaveLength(2);
      expect(stderr).toContain("printenv");
      expect(stderr).toContain("CODECOV_TOKEN");
      expectValuesOffTrace(stderr);
    });

    it("GitHub Actions: a name without a value stops before anything is copied", () => {
      const { calls, status, stderr } = runRecipe(shell, githubRecipe ?? "", {
        NPM_TOKEN: githubValues.NPM_TOKEN,
      });
      expect(status).toBe(1);
      expect(stderr).toContain("CODECOV_TOKEN has no value");
      expect(vendorCalls(calls)).toEqual([]);
    });
  });
});
