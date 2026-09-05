// docs/deploy-targets.mdx のレシピ(SY1 — docs/notes/integration-options.md §3「SY1 実装時の裁定録」裁定 H)を
// **ページの本文からそのまま切り出して実行**し、次を固定する(DP5 の golden と同じく「書いた文言」と
// 「検査対象」を一致させ、docs の漂流を構造で防ぐ):
//   1. 平文の値は外部コマンドの argv に一切現れず、`set -x` のトレースにも出ない(`ps` / シェル履歴 — 裁定 C)
//   2. 値はベンダー CLI の stdin だけに届く(wrangler = JSON オブジェクト 1 つ、vercel = 変数ごとに値 + 改行)
//   3. 名前に値が無いときは何も送らずに失敗する(wrangler の JSON null = 削除を決して作らない)
//   4. POSIX sh で書かれている(dash / bash / zsh のうち導入済みのもので同じ結果)
// ベンダー CLI と maruhi は shims/ の偽コマンド(argv と stdin を記録するだけ)。実アカウントでの通し確認は
// 所有者の人間タスク。jq が無い環境ではスキップする(CI の ubuntu には入っている)。
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

const blocks = shellBlocks(page);
const workersRecipe = blocks.find((b) => b.includes("wrangler secret bulk"));
const vercelRecipe = blocks.find((b) => b.includes("vercel env add"));

/** Values with every character class the recipes must carry intact (and one that starts with `-`). */
const values = {
  DATABASE_URL: 'postgres://user:p@ss"word\\x#frag=1 ?a=b&c=d\n-- second line --',
  STRIPE_SECRET_KEY: "-sk_test_starts_with_a_dash",
} as const;

interface MaruhiCall {
  readonly tool: "maruhi";
  readonly flags: Record<string, string>;
  readonly command: string[];
}
interface VendorCall {
  readonly tool: "wrangler" | "vercel";
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
  // xtrace: 外側のシェルを -x で起動し、偽 maruhi にはレシピ内の `sh -c` も -x にするよう伝える
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
  expect(stderr).toMatch(/^\+.*\bmaruhi run --env production\b/m);
  for (const fragment of valueFragments) {
    expect(stderr).not.toContain(fragment);
  }
}

describe("deploy-targets.mdx recipes (extracted from the page)", () => {
  it("has exactly one recipe per target, each starting with `maruhi run --env`", () => {
    expect(blocks).toHaveLength(2);
    expect(workersRecipe).toBeDefined();
    expect(vercelRecipe).toBeDefined();
    for (const block of blocks) {
      expect(block.startsWith("maruhi run --env production -- ")).toBe(true);
      // 値を argv に載せるフラグ・ディスクに置く形(/dev/null と fd 以外へのリダイレクト)・取得しに行く形を
      // 書かない(不変条件)
      expect(block).not.toMatch(
        /--value|--env-file|--body|\.env\b|npx|bunx|>(?!\s*\/dev\/null|&)|tee\b/,
      );
    }
  });

  it("runs under a POSIX shell available here", () => {
    expect(shells).toContain("sh");
  });

  it("has jq in CI, so the Workers recipe is never skipped there", () => {
    // 手元で jq が無いときは Workers の 2 態をスキップするが、CI では静かな劣化にしない(pullfrog 指摘)
    if (process.env["CI"] === undefined) return;
    expect(hasJq, "install jq on the CI runner: the Workers recipe check needs it").toBe(true);
  });

  it("has every shell the page names in CI (bash, zsh, dash), so none is silently skipped there", () => {
    // ページは「bash, zsh, and dash run them unchanged」と約束している。手元では導入済みのものだけを回し、
    // CI(ci.yml が zsh を入れる)では 4 シェルすべての存在を断言する(pullfrog 指摘)
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
        // maruhi run の子は jq だけ。wrangler は maruhi run の外で走る
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
      // 内側の sh も -x で走った証拠(名前ごとの printenv がトレースに出る)
      expect(stderr).toContain("printenv STRIPE_SECRET_KEY");
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
  });
});
