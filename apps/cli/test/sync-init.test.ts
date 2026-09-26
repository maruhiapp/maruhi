// Tests for `maruhi sync init` (SY2 phase 2 — ruling F): assembles the
// config JSON from the flags onto stdout, and the product passes the
// strict parser (sync-config.ts) as-is (round-trip). Touches neither the
// network nor files.

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
  it("exec Vercel target: emits JSON on stdout and it passes the parser as-is", async () => {
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
    // It's an explicit list, so no "all" guidance; the project guidance
    // does appear
    expect(result.stderr).not.toContain("copies every variable");
    expect(result.stderr).toContain('Note: add "project": "<project ID>"');
    // The output is 2-space-formatted JSON (a committable shape)
    expect(result.stdout.startsWith('{\n  "version": 1,')).toBe(true);
  });

  it("http Workers target: assembles driver / token / options and emits guidance on stderr", async () => {
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

  it("a missing required flag, a wrong preset, or a combination the parser rejects is a usage error (2) and emits nothing", async () => {
    const missing = await init("web", "--preset", "vercel", "--env", "production");
    expect(missing.code).toBe(2);
    expect(missing.stdout).toBe("");
    expect(missing.stderr).toContain("sync init requires --receipts");
    const preset = await init("web", "--preset", "railway", "--env", "p", "--receipts", "r");
    expect(preset.code).toBe(2);
    expect(preset.stderr).toContain(
      "--preset must be one of cloudflare-workers, vercel, netlify, github-actions",
    );
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
  it("netlify: --driver omitted assembles http (the only driver) explicitly, and --driver exec is a usage error with a reason", async () => {
    const result = await init(
      "site",
      "--preset",
      "netlify",
      "--env",
      "production",
      "--receipts",
      "sync-receipts",
      "--token-env",
      "tokens",
      "--token-name",
      "NETLIFY_TOKEN",
      "--option",
      "accountId=my-team",
      "--option",
      "siteId=0f1e2d3c",
      "--option",
      "context=production",
    );
    expect(result.code).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      version: 1,
      receipts: { environment: "sync-receipts" },
      targets: {
        site: {
          preset: "netlify",
          driver: "http",
          environment: "production",
          variables: "all",
          token: { environment: "tokens", name: "NETLIFY_TOKEN" },
          options: { accountId: "my-team", siteId: "0f1e2d3c", context: "production" },
        },
      },
    });
    expect(typeof parseSyncConfig(result.stdout, "/repo")).not.toBe("string");
    expect(result.stderr).toContain(
      "Note: the http driver reads the vendor's token from the maruhi variable",
    );
    const exec = await init(
      "site",
      "--preset",
      "netlify",
      "--driver",
      "exec",
      "--env",
      "production",
      "--receipts",
      "sync-receipts",
    );
    expect(exec.code).toBe(2);
    expect(exec.stdout).toBe("");
    expect(exec.stderr).toContain(
      "--driver exec: the netlify preset has no exec driver: the Netlify CLI takes the value as a command-line argument (visible in ps), so maruhi only talks to the Netlify API; use --driver http",
    );
    const missing = await init(
      "site",
      "--preset",
      "netlify",
      "--env",
      "production",
      "--receipts",
      "sync-receipts",
      "--token-env",
      "tokens",
      "--token-name",
      "NETLIFY_TOKEN",
      "--option",
      "accountId=my-team",
      "--option",
      "siteId=0f1e2d3c",
      "--option",
      "context=branch",
    );
    expect(missing.code).toBe(2);
    expect(missing.stderr).toContain(
      "The config would be invalid: targets.site.options.branch is required when context is branch",
    );
  });

  it("github-actions: exec only (driver emitted when omitted), options are repo / environment / app, and --driver http is a usage error with a reason", async () => {
    const result = await init(
      "dependabot",
      "--preset",
      "github-actions",
      "--env",
      "ci",
      "--receipts",
      "sync-receipts",
      "--variables",
      "NPM_TOKEN",
      "--option",
      "repo=acme/app",
      "--option",
      "app=dependabot",
    );
    expect(result.code).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      version: 1,
      receipts: { environment: "sync-receipts" },
      targets: {
        dependabot: {
          preset: "github-actions",
          environment: "ci",
          variables: ["NPM_TOKEN"],
          options: { repo: "acme/app", app: "dependabot" },
        },
      },
    });
    expect(typeof parseSyncConfig(result.stdout, "/repo")).not.toBe("string");
    expect(result.stderr).not.toContain("http driver");
    expect(result.stderr).toContain(
      "Note: the github-actions preset runs the gh CLI, which must be installed and signed in (`gh auth login`, or GH_TOKEN in the environment) with write access to the repository's secrets",
    );
    const http = await init(
      "actions",
      "--preset",
      "github-actions",
      "--driver",
      "http",
      "--env",
      "ci",
      "--receipts",
      "sync-receipts",
    );
    expect(http.code).toBe(2);
    expect(http.stdout).toBe("");
    expect(http.stderr).toContain(
      "--driver http: the github-actions preset has no http driver: the GitHub API takes the value sealed to the repository's public key with libsodium, which maruhi does not implement, so maruhi only drives the gh CLI; use --driver exec",
    );
    const inconsistent = await init(
      "actions",
      "--preset",
      "github-actions",
      "--env",
      "ci",
      "--receipts",
      "sync-receipts",
      "--option",
      "environment=production",
      "--option",
      "app=codespaces",
    );
    expect(inconsistent.code).toBe(2);
    expect(inconsistent.stderr).toContain(
      "The config would be invalid: targets.actions.options.app: environment secrets exist for GitHub Actions only",
    );
  });

  it("--on-push workflow --workflow: assembles onPush and workflow.file, and is a usage error without a project", async () => {
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

    // apply can't be assembled for production (the parser rejects it)
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
