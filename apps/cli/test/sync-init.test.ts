// `maruhi sync init`(SY2 第 2 段 — 裁定 F)のテスト: フラグから設定 JSON を
// 組んで stdout に出し、生成物が厳格なパーサ(sync-config.ts)をそのまま通る
// (往復)。ネットワークにもファイルにも触れない。

import { describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { parseSyncConfig } from "../src/sync-config.ts";
import { makeTestEnv } from "./support/env.ts";

async function init(...args: string[]) {
  const env = await makeTestEnv();
  const code = await runCli(["sync", "init", ...args], env.layer);
  return { code, env, stdout: env.logs.join("\n"), stderr: env.errors.join("\n") };
}

describe("maruhi sync init", () => {
  it("exec の Vercel ターゲット: JSON を stdout に出し、パーサをそのまま通る", async () => {
    const result = await init(
      "web",
      "--preset",
      "vercel",
      "--env",
      "production",
      "--receipts",
      "sync-receipts",
      "--variables",
      "DATABASE_URL, STRIPE_SECRET_KEY",
      "--option",
      "environment=production",
      "--option",
      "sensitive=false",
    );
    expect(result.code).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      version: 1,
      receipts: { environment: "sync-receipts" },
      targets: {
        web: {
          preset: "vercel",
          environment: "production",
          variables: ["DATABASE_URL", "STRIPE_SECRET_KEY"],
          options: { environment: "production", sensitive: false },
        },
      },
    });
    const parsed = parseSyncConfig(result.stdout, "/repo");
    expect(typeof parsed).not.toBe("string");
    // 明示リストなので "all" の案内は出ない。project の案内は出る
    expect(result.stderr).not.toContain("copies every variable");
    expect(result.stderr).toContain('Note: add "project": "<project ID>"');
    // 出力は 2 スペースの整形 JSON(コミットしやすい形)
    expect(result.stdout.startsWith('{\n  "version": 1,')).toBe(true);
  });

  it("http の Workers ターゲット: driver / token / options を組み、案内を stderr に出す", async () => {
    const result = await init(
      "worker",
      "--preset",
      "cloudflare-workers",
      "--driver",
      "http",
      "--env",
      "production",
      "--receipts",
      "sync-receipts",
      "--exclude",
      "NEXT_PUBLIC_SITE_URL",
      "--token-env",
      "tokens",
      "--token-name",
      "CF_API_TOKEN",
      "--option",
      "accountId=acc1",
      "--option",
      "name=my-worker",
      "--project",
      "a".repeat(64),
    );
    expect(result.code).toBe(0);
    const config = JSON.parse(result.stdout) as Record<string, unknown>;
    expect(config).toEqual({
      version: 1,
      project: "a".repeat(64),
      receipts: { environment: "sync-receipts" },
      targets: {
        worker: {
          preset: "cloudflare-workers",
          driver: "http",
          environment: "production",
          variables: "all",
          exclude: ["NEXT_PUBLIC_SITE_URL"],
          token: { environment: "tokens", name: "CF_API_TOKEN" },
          options: { accountId: "acc1", name: "my-worker" },
        },
      },
    });
    expect(typeof parseSyncConfig(result.stdout, "/repo")).not.toBe("string");
    expect(result.stderr).toContain(
      'Note: the target copies every variable of the environment ("all")',
    );
    expect(result.stderr).toContain(
      "Note: the http driver reads the vendor's token from the maruhi variable",
    );
    expect(result.stderr).not.toContain('add "project"');
  });

  it("必須フラグの欠落・プリセットの誤り・パーサが拒む組み合わせは書き方の誤り(2)で、何も出さない", async () => {
    const missing = await init("web", "--preset", "vercel", "--env", "production");
    expect(missing.code).toBe(2);
    expect(missing.stdout).toBe("");
    expect(missing.stderr).toContain("sync init requires --receipts");
    const preset = await init("web", "--preset", "netlify", "--env", "p", "--receipts", "r");
    expect(preset.code).toBe(2);
    expect(preset.stderr).toContain("--preset must be one of cloudflare-workers, vercel");
    const option = await init(
      "web",
      "--preset",
      "vercel",
      "--env",
      "p",
      "--receipts",
      "r",
      "--option",
      "bogus=1",
    );
    expect(option.code).toBe(2);
    expect(option.stderr).toContain(
      "--option names an unknown key (accepted keys for this preset and driver: environment, gitBranch, project, scope, sensitive)",
    );
    const invalid = await init("web", "--preset", "vercel", "--env", "p", "--receipts", "r");
    expect(invalid.code).toBe(2);
    expect(invalid.stderr).toContain(
      "The config would be invalid: targets.web.options.environment is required for the vercel preset with the exec driver",
    );
    expect(invalid.stdout).toBe("");
    const receipts = await init(
      "web",
      "--preset",
      "vercel",
      "--env",
      "p",
      "--receipts",
      "p",
      "--option",
      "environment=preview",
    );
    expect(receipts.code).toBe(2);
    expect(receipts.stderr).toContain("targets.web.environment is the receipts environment");
    const http = await init(
      "worker",
      "--preset",
      "cloudflare-workers",
      "--driver",
      "http",
      "--env",
      "p",
      "--receipts",
      "r",
      "--option",
      "accountId=a",
      "--option",
      "name=w",
    );
    expect(http.code).toBe(2);
    expect(http.stderr).toContain("targets.worker.token is required for the http driver");
  });
  it("--on-push workflow --workflow: onPush と workflow.file を組み、project が無ければ書き方の誤り", async () => {
    const result = await init(
      "web",
      "--preset",
      "vercel",
      "--env",
      "production",
      "--receipts",
      "sync-receipts",
      "--project",
      "a".repeat(64),
      "--option",
      "environment=production",
      "--on-push",
      "workflow",
      "--workflow",
      "maruhi-sync.yml",
    );
    expect(result.code).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({
      project: "a".repeat(64),
      targets: {
        web: { onPush: "workflow", workflow: { file: "maruhi-sync.yml" } },
      },
    });
    expect(typeof parseSyncConfig(result.stdout, "/repo")).not.toBe("string");
    expect(result.stderr).toContain(
      'Note: the workflow must have a workflow_dispatch trigger with a "target" input',
    );

    const noProject = await init(
      "web",
      "--preset",
      "vercel",
      "--env",
      "production",
      "--receipts",
      "sync-receipts",
      "--option",
      "environment=preview",
      "--on-push",
      "apply",
    );
    expect(noProject.code).toBe(2);
    expect(noProject.stderr).toContain(
      'The config would be invalid: targets.web.onPush needs the top-level "project"',
    );
    expect(noProject.stdout).toBe("");

    // production に apply は組めない(パーサが拒む)
    const production = await init(
      "web",
      "--preset",
      "vercel",
      "--env",
      "production",
      "--receipts",
      "sync-receipts",
      "--project",
      "a".repeat(64),
      "--option",
      "environment=production",
      "--on-push",
      "apply",
    );
    expect(production.code).toBe(2);
    expect(production.stderr).toContain('onPush cannot be "apply" for a production target');
  });
});
