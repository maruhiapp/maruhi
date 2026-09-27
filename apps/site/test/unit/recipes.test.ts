// Executes the recipes of docs/deploy-targets.mdx (the ruling H of
// docs/notes/integration-options.md §3) **verbatim as cut from the page
// body**, so that — like DP5's golden — "the written wording" and "the
// checked target" coincide and doc drift is prevented structurally. What
// is pinned:
//   1. no plaintext value ever appears on an external command's argv or in
//      a `set -x` trace (`ps` / shell history — ruling C)
//   2. values reach only the vendor CLI's stdin (wrangler = one JSON
//      object; vercel / gh = value + newline per variable)
//   3. a name without a value fails sending nothing (wrangler's JSON null
//      must never create a delete)
//   4. written in POSIX sh (same result under whichever of dash / bash /
//      zsh is installed)
// The vendor CLIs and maruhi are fake commands in shims/ (they only record
// argv and stdin). End-to-end verification against real accounts is the
// owner's human task. Environments without jq skip it (CI's ubuntu has it).
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

const siteRoot = join(import.meta.dirname, "..", "..");
const page = readFileSync(join(siteRoot, "docs", "deploy-targets.mdx"), "utf8");
const shimBin = join(import.meta.dirname, "shims", "bin");

/** The ```sh blocks of the page, in document order. */
function shellBlocks(markdown: string): string[] {
  return [...markdown.matchAll(/```sh\n([\s\S]*?)```/g)].map((m) => m[1] ?? "");
}

const allBlocks = shellBlocks(page);
// A recipe is a block starting with `maruhi run --env production -- `
// (the `maruhi sync` usage ```sh blocks are on the same page, so select by
// shape, not document order)
const RECIPE_PREFIX = "maruhi run --env production -- ";
const blocks = allBlocks.filter((b) => b.startsWith(RECIPE_PREFIX));
const workersRecipe = blocks.find((b) => b.includes("wrangler secret bulk"));
const vercelRecipe = blocks.find((b) => b.includes("vercel env add"));
const githubRecipe = blocks.find((b) => b.includes("gh secret set"));

/** Values with every character class the recipes must carry intact (and one that starts with `-`). */
const values = {
  DATABASE_URL: 'postgres://user:p@ss"word\\x#frag=1 ?a=b&c=d\n-- second line --',
  STRIPE_SECRET_KEY: "-sk_test_starts_with_a_dash",
} as const;

/** The GitHub recipe names other variables on the page; same character classes. */
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

/** Runs one recipe under `shell` with the shims on PATH; returns the recorded calls and the exit status. */
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
  // xtrace: start the outer shell with -x and tell the fake maruhi to
  // make the recipe's inner `sh -c` run with -x too
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

/** No argv of any recorded command contains an injected value (nor a line of a multi-line one). */
function expectValuesOffCommandLines(calls: Call[]): void {
  const commandLines = calls.flatMap(argvOf).join("\n");
  for (const fragment of valueFragments) {
    expect(commandLines).not.toContain(fragment);
  }
}

/**
 * The xtrace output (`set -x`) of a recipe run never shows an injected value. The trace prefix is
 * `PS4`, whose default differs per shell (`+ ` in bash / dash, `+zsh:1> ` in zsh), so the proof that
 * tracing happened is a line starting with `+` that shows the outer `maruhi run` command.
 */
function expectValuesOffTrace(stderr: string): void {
  // The two sides of the pipeline (maruhi run … | wrangler …) are separate
  // processes, and dash writes the trace word by word, so under load the
  // words of both sides interleave arbitrarily on the same stderr
  // (observed: `+ maruhi+  run --env production …` /
  // `  maruhiwrangler run --env secret production bulk`). Do not depend on
  // word order — the evidence that "a trace came out" is a line starting
  // with `+` plus each word of the outer command appearing
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
    // The `maruhi sync` usage blocks (env create / plan / apply) live on
    // the same page
    expect(allBlocks.some((b) => b.includes("maruhi sync apply"))).toBe(true);
    for (const block of allBlocks) {
      // Never write the shapes that put a value on argv, place it on disk
      // (redirects to anywhere but /dev/null and fds), or go fetch it
      // (invariant — applies to the recipes and the sync examples alike)
      expect(block).not.toMatch(
        /--value|--env-file|--body|\.env\b|npx|bunx|>(?!\s*\/dev\/null|&)|tee\b/,
      );
    }
  });

  it("runs under a POSIX shell available here", () => {
    expect(shells).toContain("sh");
  });

  it("has jq in CI, so the Workers recipe is never skipped there", () => {
    // Locally without jq the two Workers cases are skipped, but CI must
    // not silently degrade
    if (process.env["CI"] === undefined) return;
    expect(hasJq, "install jq on the CI runner: the Workers recipe check needs it").toBe(true);
  });

  it("has every shell the page names in CI (bash, zsh, dash), so none is silently skipped there", () => {
    // The page promises "bash, zsh, and dash run them unchanged". Locally
    // only the installed ones run; in CI (ci.yml installs zsh) the presence
    // of all four shells is asserted
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
        // maruhi run's only child is jq. wrangler runs outside maruhi run
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
      // Evidence the inner sh also ran with -x (the per-name printenv
      // appears in the trace). The two sides of `printenv "$name" |
      // vercel …` are separate processes whose words may interleave, so do
      // not depend on word order (same reason as expectValuesOffTrace
      // above)
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
