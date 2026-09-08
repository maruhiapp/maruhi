// docs/github-actions.mdx の workflow テンプレート(SY3 — docs/notes/integration-options.md §3「SY3 実装時の
// 裁定録」裁定 H)を**ページの本文からそのまま切り出して**検査する(recipes.test.ts と同じ規律: 「書いた文言」と
// 「検査対象」を一致させ、docs の漂流を構造で防ぐ)。YAML の解釈は Bun 1.4.0 同梱の `Bun.YAML`(リポジトリが
// `.bun-version` で要求する実行環境。依存追加なし)を子プロセスで呼ぶ — vitest は Node で走るため。固定するのは:
//   1. 起動先の契約(`workflow_dispatch` + `target` 入力)が deploy-targets.mdx の断片と一致する(第 3 段の契約)
//   2. maruhi を実行する job は `permissions: id-token: write` + `contents: read` だけ(他の write なし)
//   3. 導入は setup-maruhi をタグで固定(`@<tag>` + `version: <tag>`)、他の action は 40 hex の commit SHA、
//      checkout は `persist-credentials: false`、`npx` / `curl` で取りに行かない
//   4. 平文は CI の中だけ: `secrets.` を参照しない、maruhi を実行する step は `$GITHUB_ENV` / `$GITHUB_OUTPUT` /
//      `echo "$…"` / `set -x` / `printenv` / `--value` を持たず、`run:` に `${{ }}` を直接展開しない(env 経由)
//   5. `maruhi ci sync` は `--yes` / `--server` / `--project` / `--anchor .maruhi/anchor.json` を持つ
//   6. 標準形 ②: `schedule` を持ち、`sync` job は Environment = ターゲット名・ターゲット単位の concurrency
//      (cancel-in-progress: false)・fail-fast: false・空リストのガード。`targets` job のスクリプトは実際に
//      sh で走らせる(dispatch の実在 / 不在ターゲット・schedule の一覧)
//   7. 標準形 ①: Environment `production`、`ci sync` が deploy の前、deploy は `maruhi ci run … -- <wrangler>`
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

const siteRoot = join(import.meta.dirname, "..", "..");
const page = readFileSync(join(siteRoot, "docs", "github-actions.mdx"), "utf8");
const deployTargetsPage = readFileSync(join(siteRoot, "docs", "deploy-targets.mdx"), "utf8");

/** The ```yaml blocks of a page, in document order. */
function yamlBlocks(markdown: string): string[] {
  return [...markdown.matchAll(/```yaml\n([\s\S]*?)```/g)].map((m) => m[1] ?? "");
}

/** Parses YAML with Bun's built-in parser (a subprocess: vitest runs on Node). */
function parseYaml(text: string): unknown {
  const result = spawnSync(
    "bun",
    ["-e", "process.stdout.write(JSON.stringify(Bun.YAML.parse(await Bun.stdin.text())))"],
    { input: text, encoding: "utf8" },
  );
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout) as unknown;
}

type Record_ = Record<string, unknown>;
interface Step {
  readonly name?: string;
  readonly id?: string;
  readonly uses?: string;
  readonly with?: Record_;
  readonly run?: string;
  readonly env?: Record_;
}
interface Job {
  readonly permissions?: Record_;
  readonly environment?: unknown;
  readonly concurrency?: Record_;
  readonly strategy?: Record_;
  readonly needs?: unknown;
  readonly if?: unknown;
  readonly steps: Step[];
}
interface Workflow {
  readonly name: string;
  readonly on: Record_;
  readonly permissions?: unknown;
  readonly env?: Record_;
  readonly concurrency?: Record_;
  readonly jobs: Record<string, Job>;
}

const sources = yamlBlocks(page);
const workflows = sources.map((source) => ({ source, workflow: parseYaml(source) as Workflow }));
const byName = (name: string) => {
  const found = workflows.find((w) => w.workflow.name === name);
  expect(found, `workflow "${name}" is on the page`).toBeDefined();
  return found as (typeof workflows)[number];
};

const runsMaruhi = (step: Step) => /\bmaruhi ci\b/.test(step.run ?? "");

const jobsRunningMaruhi = (workflow: Workflow) =>
  Object.entries(workflow.jobs).filter(([, job]) => job.steps.some(runsMaruhi));

const SHA_PINNED = /^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/;
const SETUP_MARUHI = "maruhiapp/maruhi/actions/setup-maruhi@<tag>";

const stepsOf = (workflow: Workflow) => Object.values(workflow.jobs).flatMap((job) => job.steps);

/** setup-maruhi = `@<tag>` + `version: <tag>`; every other action = a 40-hex commit; checkout keeps no token. */
function expectPinned(step: Step): void {
  if (step.uses === SETUP_MARUHI) {
    expect(step.with).toEqual({ version: "<tag>" });
  } else {
    expect(step.uses).toMatch(SHA_PINNED);
  }
  if (step.uses?.startsWith("actions/checkout@")) {
    expect(step.with).toEqual({ "persist-credentials": false });
  }
}

const withoutComments = (yaml: string) =>
  yaml
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("#"))
    .join("\n");

/**
 * A step that runs maruhi writes nothing to the runner's files and echoes nothing; its env holds
 * only the target name (the values go to maruhi's child process or request body, nowhere else).
 */
function expectMaruhiStepKeepsValues(step: Step): void {
  expect(step.run).not.toMatch(
    /GITHUB_OUTPUT|GITHUB_ENV|\becho\b|set -x|printenv|--value|>(?!\s*\/dev\/null)|tee\b/,
  );
  for (const value of Object.values(step.env ?? {})) {
    expect(String(value)).toMatch(/^\$\{\{ (inputs|matrix)\.\w+ \}\}$/);
  }
}

function hasCommand(name: string): boolean {
  return spawnSync("sh", ["-c", `command -v ${name}`], { stdio: "ignore" }).status === 0;
}
const hasJq = hasCommand("jq");

let workDir: string | undefined;
afterEach(() => {
  if (workDir !== undefined) rmSync(workDir, { recursive: true, force: true });
  workDir = undefined;
});

describe("github-actions.mdx workflow templates (extracted from the page)", () => {
  it("has the three workflows: test (ci run), deploy (shape 1), maruhi sync (shape 2)", () => {
    expect(workflows.map((w) => w.workflow.name)).toEqual(["test", "deploy", "maruhi sync"]);
  });

  it("keeps the dispatch contract of deploy-targets.mdx (workflow_dispatch + a required target input)", () => {
    const contracts = yamlBlocks(deployTargetsPage);
    expect(contracts).toHaveLength(1);
    const contract = parseYaml(contracts[0] ?? "") as { on: Record_ };
    const dispatch = (byName("maruhi sync").workflow.on as { workflow_dispatch: Record_ })
      .workflow_dispatch;
    const contractDispatch = (contract.on as { workflow_dispatch: Record_ }).workflow_dispatch;
    const inputOf = (d: Record_) => (d["inputs"] as Record<string, Record_>)["target"];
    expect(inputOf(dispatch)).toMatchObject(inputOf(contractDispatch) ?? {});
    expect(inputOf(dispatch)).toMatchObject({ required: true, type: "string" });
  });

  describe.each(workflows.map((w) => [w.workflow.name, w] as const))(
    "%s",
    (_name, { source, workflow }) => {
      it("grants nothing by default and only id-token: write + contents: read to jobs that run maruhi", () => {
        expect(workflow.permissions).toEqual({});
        const running = jobsRunningMaruhi(workflow);
        expect(running.length).toBeGreaterThan(0);
        for (const [, job] of running) {
          expect(job.permissions).toEqual({ "id-token": "write", contents: "read" });
        }
        for (const job of Object.values(workflow.jobs)) {
          const writes = Object.entries(job.permissions ?? {}).filter(([, v]) => v === "write");
          expect(writes).toEqual(
            [["id-token", "write"]].filter(() => running.some(([, j]) => j === job)),
          );
        }
      });

      it("installs maruhi with setup-maruhi pinned to a tag, pins every other action to a commit SHA, and fetches nothing else", () => {
        const uses = stepsOf(workflow).filter((s) => s.uses !== undefined);
        expect(uses.some((s) => s.uses === SETUP_MARUHI)).toBe(true);
        for (const step of uses) expectPinned(step);
        expect(source).not.toMatch(/npx|bunx|curl|wget|\| *sh\b/);
        // action の ref とバージョンは同じプレースホルダ(README と同じ約束: 置き換え箇所は 1 種類)。
        // コメント行(置き換えの案内)は数えない
        expect(withoutComments(source).match(/<tag>/g)?.length).toBe(2);
      });

      it("keeps the values inside the job: no GitHub secrets, no expression in run:, no echo / GITHUB_ENV / xtrace around maruhi", () => {
        expect(source).not.toMatch(/secrets\./);
        expect(source).not.toMatch(/GITHUB_ENV/);
        // 式は env 経由でだけシェルへ渡す(GitHub のスクリプトインジェクション対策)
        for (const step of stepsOf(workflow)) expect(step.run ?? "").not.toMatch(/\$\{\{/);
        for (const step of stepsOf(workflow).filter(runsMaruhi)) expectMaruhiStepKeepsValues(step);
      });

      it("passes every maruhi ci command its coordinates and the anchor as flags", () => {
        const runs = Object.values(workflow.jobs)
          .flatMap((job) => job.steps)
          .map((s) => s.run ?? "")
          .filter((run) => /\bmaruhi ci\b/.test(run));
        for (const run of runs) {
          expect(run).toMatch(/--server "\$MARUHI_SERVER"/);
          expect(run).toMatch(/--project "\$MARUHI_PROJECT"/);
          expect(run).toMatch(/--anchor \.maruhi\/anchor\.json/);
          if (/\bmaruhi ci sync\b/.test(run)) {
            expect(run).toMatch(/\bmaruhi ci sync (\w+|"\$TARGET") --yes\b/);
          }
          if (/\bmaruhi ci run\b/.test(run)) {
            expect(run).toMatch(/--env \w+/);
            expect(run).toMatch(/ -- \S/);
          }
        }
        expect(workflow.env).toMatchObject({
          MARUHI_SERVER: "https://my.maruhi.app",
          MARUHI_PROJECT: expect.stringMatching(/^[0-9a-f]{64}$/),
        });
      });
    },
  );

  describe("shape 1: re-apply on every deploy (deploy)", () => {
    const { workflow } = byName("deploy");
    const deploy = workflow.jobs["deploy"] as Job;

    it("runs on push to main, one deploy at a time, in the production Environment", () => {
      expect(workflow.on).toEqual({ push: { branches: ["main"] } });
      expect(workflow.concurrency).toEqual({
        group: "deploy-production",
        "cancel-in-progress": false,
      });
      expect(Object.keys(workflow.jobs)).toEqual(["deploy"]);
      expect(deploy.environment).toBe("production");
    });

    it("syncs the target before the deploy, and deploys through maruhi ci run with the vendor CLI from the project", () => {
      const runs = deploy.steps.map((s) => s.run ?? "");
      const syncIndex = runs.findIndex((r) => r.includes("maruhi ci sync worker --yes"));
      const deployIndex = runs.findIndex((r) => r.includes("maruhi ci run"));
      expect(syncIndex).toBeGreaterThan(0);
      expect(deployIndex).toBeGreaterThan(syncIndex);
      expect(runs[deployIndex]).toMatch(/--env tokens/);
      expect(runs[deployIndex]).toMatch(/ -- \.\/node_modules\/\.bin\/wrangler deploy$/);
      // ベンダー CLI はプロジェクトの依存として入れる(取りに行かない)
      expect(runs.slice(0, syncIndex).some((r) => /^npm ci$/.test(r.trim()))).toBe(true);
    });
  });

  describe("shape 2: sync on demand and on a schedule (maruhi sync)", () => {
    const { workflow } = byName("maruhi sync");
    const targets = workflow.jobs["targets"] as Job;
    const sync = workflow.jobs["sync"] as Job;

    it("is dispatched with a target and scheduled with a cron, and lists the scheduled targets in one place", () => {
      expect(Object.keys(workflow.on)).toEqual(["workflow_dispatch", "schedule"]);
      const schedule = workflow.on["schedule"] as { cron: string }[];
      expect(schedule).toHaveLength(1);
      expect(schedule[0]?.cron.split(" ")).toHaveLength(5);
      expect(workflow.env?.["SCHEDULED_TARGETS"]).toBe("web");
      expect(Object.keys(workflow.jobs)).toEqual(["targets", "sync"]);
    });

    it("runs one target per matrix leg, in the Environment named after it, one run per target at a time", () => {
      expect(sync.needs).toBe("targets");
      // 独自の `if` は暗黙の success() を置き換えうるので明示する(targets の失敗で sync を始めない — Bugbot 指摘)
      expect(sync.if).toBe("success() && needs.targets.outputs.list != '[]'");
      expect(sync.strategy).toEqual({
        "fail-fast": false,
        matrix: { target: "${{ fromJson(needs.targets.outputs.list) }}" },
      });
      expect(sync.environment).toBe("${{ matrix.target }}");
      expect(sync.concurrency).toEqual({
        group: "maruhi-sync-${{ matrix.target }}",
        "cancel-in-progress": false,
      });
      const step = sync.steps.find((s) => /\bmaruhi ci sync\b/.test(s.run ?? ""));
      expect(step?.env).toEqual({ TARGET: "${{ matrix.target }}" });
      expect(step?.run).toMatch(/maruhi ci sync "\$TARGET" --yes/);
    });

    it("has jq in CI, so the targets job check is never skipped there", () => {
      if (process.env["CI"] === undefined) return;
      expect(hasJq, "install jq on the CI runner").toBe(true);
    });

    describe.skipIf(!hasJq)("the targets job's script, run under sh with a sample config", () => {
      const listStep = targets.steps.find((s) => s.id === "list") as Step;

      it("reads the dispatched target through env, and needs nothing but contents: read", () => {
        expect(listStep.env).toEqual({ TARGET: "${{ inputs.target }}" });
        expect(targets.permissions).toEqual({ contents: "read" });
      });

      function runTargets(env: Record<string, string>): {
        status: number | null;
        stderr: string;
        output: string;
      } {
        workDir = mkdtempSync(join(tmpdir(), "maruhi-workflows-"));
        const output = join(workDir, "output");
        writeFileSync(output, "");
        writeFileSync(
          join(workDir, "maruhi.sync.json"),
          JSON.stringify({ version: 1, targets: { web: {}, preview: {} } }),
        );
        const result = spawnSync("sh", ["-e", "-c", listStep.run ?? ""], {
          cwd: workDir,
          env: { PATH: process.env["PATH"] ?? "", GITHUB_OUTPUT: output, ...env },
          encoding: "utf8",
        });
        return {
          status: result.status,
          stderr: result.stderr,
          output: readFileSync(output, "utf8"),
        };
      }

      it("dispatch: a target that exists becomes a one-element list", () => {
        const { status, output } = runTargets({ TARGET: "web", SCHEDULED_TARGETS: "web preview" });
        expect(status).toBe(0);
        expect(output).toBe('list=["web"]\n');
      });

      it("dispatch: a target the config does not have stops the run before any Environment is created", () => {
        const { status, stderr, output } = runTargets({ TARGET: "wep", SCHEDULED_TARGETS: "web" });
        expect(status).toBe(1);
        expect(stderr).toContain("maruhi.sync.json has no target named wep");
        expect(output).toBe("");
      });

      it("schedule: the listed targets, in order, ignoring extra spaces; an empty list when none is listed", () => {
        expect(runTargets({ TARGET: "", SCHEDULED_TARGETS: "web  preview " }).output).toBe(
          'list=["web","preview"]\n',
        );
        expect(runTargets({ TARGET: "", SCHEDULED_TARGETS: "" }).output).toBe("list=[]\n");
      });
    });
  });
});
