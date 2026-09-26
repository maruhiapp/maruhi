// Unit tests for `maruhi sync`'s parts: repository-config validation
// (sync-config.ts), the declarative presets and invocation assembly
// (sync-exec.ts — no values on argv, the stdin format, splitting every
// 100 entries, how deletions are expressed), the value constraints,
// scrubbing vendor output, the plan diff (sync-plan.ts), and the receipt
// codec (sync-receipt.ts).

import { Effect, Exit, Redacted } from "effect";
import { describe, expect, it } from "vitest";

import { parseSyncConfig, type SyncTarget, type TargetDriver } from "../src/sync-config.ts";
import {
  buildInvocations,
  checkValueConstraints,
  EXEC_PRESETS,
  scrubVendorOutput,
  type SyncWrite,
} from "../src/sync-exec.ts";
import { computePlan } from "../src/sync-plan.ts";
import { decodeReceipt, encodeReceipt, receiptVariableName } from "../src/sync-receipt.ts";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function write(name: string, value: string): SyncWrite {
  return { name, value: Redacted.make(encoder.encode(value), { label: "variable-value" }) };
}

function baseConfig(target: Record<string, unknown>): string {
  return JSON.stringify({
    version: 1,
    receipts: { environment: "sync-receipts" },
    targets: { t: target },
  });
}

function vercelTarget(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    preset: "vercel",
    environment: "prod",
    variables: ["A"],
    options: { environment: "production" },
    ...overrides,
  };
}

function githubTarget(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    preset: "github-actions",
    environment: "prod",
    variables: ["A"],
    ...overrides,
  };
}

/** A config carrying `project` (onPush requires it). */
function withProject(target: Record<string, unknown>): string {
  return JSON.stringify({
    version: 1,
    project: "a".repeat(64),
    receipts: { environment: "sync-receipts" },
    targets: { t: target },
  });
}

function parsed(target: Record<string, unknown>): SyncTarget {
  const config = parseSyncConfig(baseConfig(target), "/repo");
  if (typeof config === "string") {
    throw new Error(config);
  }
  return config.targets.get("t") as SyncTarget;
}

/** The exec driver's side (cwd / command). An http one would violate the test's premise. */
function execOf(target: SyncTarget): Extract<TargetDriver, { kind: "exec" }> {
  if (target.driver.kind !== "exec") {
    throw new Error("expected the exec driver");
  }
  return target.driver;
}

describe("parseSyncConfig", () => {
  it("Vercel's production counts as production by default and preview doesn't; an explicit setting wins", () => {
    expect(parsed(vercelTarget()).production).toBe(true);
    expect(parsed(vercelTarget({ options: { environment: "preview" } })).production).toBe(false);
    expect(parsed(vercelTarget({ production: false })).production).toBe(false);
    expect(
      parsed(vercelTarget({ options: { environment: "development" }, production: true }))
        .production,
    ).toBe(true);
  });

  it("Workers without a named environment counts as production; cwd / command are relative-to-config and overridable", () => {
    const top = parsed({ preset: "cloudflare-workers", environment: "prod", variables: "all" });
    expect(top.production).toBe(true);
    expect(execOf(top).cwd).toBe("/repo");
    expect(execOf(top).command).toBe("wrangler");
    expect(execOf(top).namedCommand).toBe(false);
    const named = parsed({
      preset: "cloudflare-workers",
      environment: "prod",
      variables: "all",
      cwd: "apps/worker",
      command: "node_modules/.bin/wrangler",
      options: { environment: "staging" },
    });
    expect(named.production).toBe(false);
    expect(execOf(named).cwd).toBe("/repo/apps/worker");
    expect(execOf(named).command).toBe("node_modules/.bin/wrangler");
    expect(execOf(named).namedCommand).toBe(true);
    // Even spelled identically to the default, writing it in config
    // counts as 'naming it specifically'
    const spelled = parsed({
      preset: "vercel",
      environment: "prod",
      variables: "all",
      command: "vercel",
      options: { environment: "preview" },
    });
    expect(execOf(spelled).command).toBe("vercel");
    expect(execOf(spelled).namedCommand).toBe(true);
  });

  it.each([
    ["not json", "not valid JSON"],
    ["[]", "the top level must be an object"],
    [JSON.stringify({ version: 2 }), "unsupported config version"],
    [JSON.stringify({ version: 1, extra: 1 }), "unknown top-level keys (extra)"],
    [JSON.stringify({ version: 1, project: "nope" }), "project must be the project ID"],
    [JSON.stringify({ version: 1 }), "receipts must be an object"],
    [
      JSON.stringify({ version: 1, receipts: { environment: "bad id!" } }),
      "receipts.environment must be a maruhi environment ID",
    ],
    [
      JSON.stringify({ version: 1, receipts: { environment: "r" }, targets: {} }),
      "targets must be an object with at least one target",
    ],
    [
      baseConfig({ preset: "railway" }),
      "targets.t.preset must be one of cloudflare-workers, vercel, netlify, github-actions",
    ],
    [baseConfig({ preset: "__proto__" }), "targets.t.preset must be one of"],
    [
      baseConfig(vercelTarget({ environment: "no spaces" })),
      "targets.t.environment must be a maruhi environment ID",
    ],
    [
      baseConfig(vercelTarget({ variables: [] })),
      'targets.t.variables must be a non-empty array of variable names, or "all"',
    ],
    [baseConfig(vercelTarget({ variables: ["A", "A"] })), "lists the same name more than once"],
    [
      baseConfig(vercelTarget({ exclude: ["B"] })),
      'targets.t.exclude applies only when variables is "all"',
    ],
    [baseConfig(vercelTarget({ bogus: 1 })), "targets.t has unknown keys (bogus)"],
    [
      baseConfig(vercelTarget({ options: {} })),
      "targets.t.options.environment is required for the vercel preset with the exec driver (one of production, preview, development)",
    ],
    [
      baseConfig(vercelTarget({ options: { environment: "prod" } })),
      "targets.t.options.environment must be one of production, preview, development",
    ],
    [
      baseConfig(vercelTarget({ options: { environment: "production", sensitive: "no" } })),
      "targets.t.options.sensitive must be true or false",
    ],
    [
      baseConfig(vercelTarget({ options: { environment: "production", value: "x" } })),
      "targets.t.options has unknown keys (value)",
    ],
    [
      baseConfig(vercelTarget({ environment: "sync-receipts" })),
      "targets.t.environment is the receipts environment",
    ],
    [
      baseConfig(githubTarget({ driver: "http" })),
      'targets.t.driver: the github-actions preset has no http driver: the GitHub API takes the value sealed to the repository\'s public key with libsodium, which maruhi does not implement, so maruhi only drives the gh CLI; use "exec"',
    ],
    [
      baseConfig(githubTarget({ options: { repo: "acme" } })),
      "targets.t.options.repo must be OWNER/REPO (or HOST/OWNER/REPO)",
    ],
    [
      baseConfig(githubTarget({ options: { repo: "--body" } })),
      "targets.t.options.repo must be OWNER/REPO (or HOST/OWNER/REPO)",
    ],
    [
      baseConfig(githubTarget({ options: { repo: "-x/y" } })),
      "targets.t.options.repo must be OWNER/REPO (or HOST/OWNER/REPO)",
    ],
    [
      baseConfig(githubTarget({ options: { repo: "-host/x/y" } })),
      "targets.t.options.repo must be OWNER/REPO (or HOST/OWNER/REPO)",
    ],
    [
      baseConfig(githubTarget({ options: { environment: "-r" } })),
      "targets.t.options.environment must be a GitHub Environment name (not starting with -)",
    ],
    [
      baseConfig(githubTarget({ options: { app: "actions,dependabot" } })),
      "targets.t.options.app must be one of actions, agents, codespaces, dependabot",
    ],
    [
      baseConfig(githubTarget({ options: { environment: "production", app: "dependabot" } })),
      'targets.t.options.app: environment secrets exist for GitHub Actions only, so app must be "actions" (or left out) when environment is set',
    ],
    [
      baseConfig(githubTarget({ token: { environment: "tokens", name: "GH_TOKEN" } })),
      "targets.t.token applies only to the http driver",
    ],
  ])("rejects: %s", (content, reason) => {
    const result = parseSyncConfig(content, "/repo");
    expect(typeof result).toBe("string");
    expect(result).toContain(reason);
  });

  it("GitHub Actions: exec only (driver omitted = exec); repository secrets and Environment production count as production, other Environments don't", () => {
    const repository = parsed(githubTarget());
    expect(repository.driver.kind).toBe("exec");
    expect(execOf(repository).command).toBe("gh");
    expect(execOf(repository).cwd).toBe("/repo");
    expect(repository.production).toBe(true);
    expect(repository.options).toEqual({});
    expect(parsed(githubTarget({ options: { environment: "production" } })).production).toBe(true);
    // GitHub Environment names are case-insensitive
    expect(parsed(githubTarget({ options: { environment: "Production" } })).production).toBe(true);
    expect(parsed(githubTarget({ options: { environment: "PRODUCTION" } })).production).toBe(true);
    expect(parsed(githubTarget({ options: { environment: "staging" } })).production).toBe(false);
    // Dependabot secrets are repository-wide = production
    // (overridable explicitly)
    expect(parsed(githubTarget({ options: { app: "dependabot" } })).production).toBe(true);
    expect(
      parsed(githubTarget({ options: { app: "dependabot" }, production: false })).production,
    ).toBe(false);
    // Environment secrets omit app or say actions
    const full = parsed(
      githubTarget({
        options: { repo: "acme/app", environment: "staging", app: "actions" },
        cwd: "infra",
        command: "tools/gh",
      }),
    );
    expect(full.options).toEqual({ repo: "acme/app", environment: "staging", app: "actions" });
    expect(execOf(full).cwd).toBe("/repo/infra");
    expect(execOf(full).command).toBe("tools/gh");
    expect(execOf(full).namedCommand).toBe(true);
    expect(parsed(githubTarget({ options: { repo: "ghe.example.com/acme/app" } })).options).toEqual(
      {
        repo: "ghe.example.com/acme/app",
      },
    );
  });

  it("onPush: apply is for non-production targets only; workflow carries file / ref / command (cwd = the config's location) and needs a project", () => {
    const apply = parseSyncConfig(
      withProject(vercelTarget({ options: { environment: "preview" }, onPush: "apply" })),
      "/repo",
    );
    if (typeof apply === "string") throw new Error(apply);
    expect(apply.targets.get("t")?.onPush).toEqual({ kind: "apply" });
    const workflow = parseSyncConfig(
      withProject(
        vercelTarget({
          onPush: "workflow",
          workflow: { file: "maruhi-sync.yml", ref: "main", command: "tools/gh" },
        }),
      ),
      "/repo",
    );
    if (typeof workflow === "string") throw new Error(workflow);
    // Even on production (Vercel's production environment), a CI
    // trigger is allowed
    expect(workflow.targets.get("t")?.production).toBe(true);
    expect(workflow.targets.get("t")?.onPush).toEqual({
      kind: "workflow",
      file: "maruhi-sync.yml",
      ref: "main",
      command: "tools/gh",
      namedCommand: true,
      cwd: "/repo",
    });
    const defaults = parseSyncConfig(
      withProject(vercelTarget({ onPush: "workflow", workflow: { file: "sync.yml" } })),
      "/repo",
    );
    if (typeof defaults === "string") throw new Error(defaults);
    expect(defaults.targets.get("t")?.onPush).toMatchObject({
      ref: undefined,
      command: "gh",
      namedCommand: false,
    });
    // Omitted = manual only
    expect(parsed(vercelTarget()).onPush).toBeNull();
  });

  it.each([
    [
      vercelTarget({ onPush: "apply" }),
      'targets.t.onPush cannot be "apply" for a production target',
    ],
    [vercelTarget({ onPush: "always" }), 'targets.t.onPush must be "apply"'],
    [
      vercelTarget({ onPush: "workflow" }),
      'targets.t.workflow is required when onPush is "workflow"',
    ],
    [
      vercelTarget({
        options: { environment: "preview" },
        onPush: "apply",
        workflow: { file: "x.yml" },
      }),
      'targets.t.workflow applies only when onPush is "workflow"',
    ],
    [
      vercelTarget({ workflow: { file: "x.yml" } }),
      'targets.t.workflow applies only when onPush is "workflow"',
    ],
    [
      vercelTarget({ onPush: "workflow", workflow: { file: "x.yml", bogus: 1 } }),
      "targets.t.workflow has unknown keys (bogus)",
    ],
    [
      vercelTarget({ onPush: "workflow", workflow: { file: "" } }),
      "targets.t.workflow.file must be the workflow's file name",
    ],
    [
      vercelTarget({ onPush: "workflow", workflow: { file: "--ref" } }),
      "targets.t.workflow.file must be the workflow's file name",
    ],
    [
      vercelTarget({ onPush: "workflow", workflow: { file: "x.yml", ref: "-r" } }),
      "targets.t.workflow.ref must be a branch or tag name",
    ],
    [
      vercelTarget({ onPush: "workflow", workflow: "x.yml" }),
      "targets.t.workflow must be an object",
    ],
  ])("rejects onPush: %o", (target, reason) => {
    const result = parseSyncConfig(withProject(target), "/repo");
    expect(typeof result).toBe("string");
    expect(result).toContain(reason);
  });

  it("onPush needs the top-level project (so a config at the default path is never used to push a different project)", () => {
    const result = parseSyncConfig(
      baseConfig(vercelTarget({ onPush: "workflow", workflow: { file: "x.yml" } })),
      "/repo",
    );
    expect(result).toContain('targets.t.onPush needs the top-level "project"');
  });

  it("target names use the same alphabet as environment IDs (they become part of receipt variable names)", () => {
    const bad = parseSyncConfig(
      JSON.stringify({
        version: 1,
        receipts: { environment: "r" },
        targets: { "bad name": vercelTarget() },
      }),
      "/repo",
    );
    expect(bad).toContain("target names must start with an alphanumeric character");
  });
});

describe("buildInvocations (the declarative presets)", () => {
  it("Vercel: one process per name, values as stdin verbatim, options on argv, deletion via env rm", () => {
    const target = parsed(
      vercelTarget({
        options: {
          environment: "preview",
          gitBranch: "feature/x",
          project: "my-app",
          scope: "team",
          sensitive: false,
        },
      }),
    );
    const invocations = buildInvocations({
      preset: execOf(target).spec,
      command: execOf(target).command,
      cwd: execOf(target).cwd,
      options: target.options,
      writes: [write("A", "value-a"), write("B", "line1\nline2\n")],
      deletes: ["OLD"],
    });
    expect(invocations.map((invocation) => invocation.command)).toEqual([
      [
        "vercel",
        "env",
        "add",
        "A",
        "preview",
        "--git-branch",
        "feature/x",
        "--project",
        "my-app",
        "--scope",
        "team",
        "--no-sensitive",
        "--force",
        "--non-interactive",
      ],
      [
        "vercel",
        "env",
        "add",
        "B",
        "preview",
        "--git-branch",
        "feature/x",
        "--project",
        "my-app",
        "--scope",
        "team",
        "--no-sensitive",
        "--force",
        "--non-interactive",
      ],
      [
        "vercel",
        "env",
        "rm",
        "OLD",
        "preview",
        "--git-branch",
        "feature/x",
        "--project",
        "my-app",
        "--scope",
        "team",
        "--yes",
        "--non-interactive",
      ],
    ]);
    expect(
      invocations.map((invocation) => decoder.decode(Redacted.value(invocation.stdin))),
    ).toEqual(["value-a", "line1\nline2\n", ""]);
    expect(invocations.map((invocation) => invocation.kind)).toEqual(["write", "write", "delete"]);
    for (const invocation of invocations) {
      expect(invocation.extraEnv).toEqual({ VERCEL_TELEMETRY_DISABLED: "1" });
      expect(invocation.cwd).toBe("/repo");
      expect(invocation.command.join(" ")).not.toContain("value-a");
    }
  });

  it("Workers: writes and deletions (null) coexist in one JSON, split every 100 entries", () => {
    const target = parsed({
      preset: "cloudflare-workers",
      environment: "prod",
      variables: "all",
      options: { name: "w", environment: "staging", config: "wrangler.jsonc" },
    });
    const writes = Array.from({ length: 150 }, (_, index) => write(`V${index}`, `value ${index}`));
    const invocations = buildInvocations({
      preset: execOf(target).spec,
      command: "npx-free/wrangler",
      cwd: "/repo",
      options: target.options,
      writes,
      deletes: ["GONE"],
    });
    expect(invocations).toHaveLength(2);
    for (const invocation of invocations) {
      expect(invocation.command).toEqual([
        "npx-free/wrangler",
        "secret",
        "bulk",
        "--name",
        "w",
        "--env",
        "staging",
        "--config",
        "wrangler.jsonc",
      ]);
      expect(invocation.kind).toBe("write");
    }
    const first = JSON.parse(
      decoder.decode(Redacted.value((invocations[0] as (typeof invocations)[number]).stdin)),
    ) as Record<string, unknown>;
    const second = JSON.parse(
      decoder.decode(Redacted.value((invocations[1] as (typeof invocations)[number]).stdin)),
    ) as Record<string, unknown>;
    expect(Object.keys(first)).toHaveLength(100);
    expect(Object.keys(second)).toHaveLength(51);
    expect(first["V0"]).toBe("value 0");
    expect(second["GONE"]).toBeNull();
    expect(invocations[1]?.names).toContain("GONE");
  });

  it("GitHub Actions: one `gh secret set` process per name, values as stdin verbatim, -R / --env / --app on argv, deletion via `gh secret delete`, gh telemetry off", () => {
    const target = parsed(
      githubTarget({
        options: { repo: "acme/app", environment: "staging", app: "actions" },
      }),
    );
    const invocations = buildInvocations({
      preset: execOf(target).spec,
      command: execOf(target).command,
      cwd: execOf(target).cwd,
      options: target.options,
      writes: [write("API_KEY", "value-a"), write("PEM", "line1\nline2")],
      deletes: ["OLD"],
    });
    expect(invocations.map((invocation) => invocation.command)).toEqual([
      [
        "gh",
        "secret",
        "set",
        "API_KEY",
        "--repo",
        "acme/app",
        "--env",
        "staging",
        "--app",
        "actions",
      ],
      ["gh", "secret", "set", "PEM", "--repo", "acme/app", "--env", "staging", "--app", "actions"],
      [
        "gh",
        "secret",
        "delete",
        "OLD",
        "--repo",
        "acme/app",
        "--env",
        "staging",
        "--app",
        "actions",
      ],
    ]);
    expect(
      invocations.map((invocation) => decoder.decode(Redacted.value(invocation.stdin))),
    ).toEqual(["value-a", "line1\nline2", ""]);
    for (const invocation of invocations) {
      expect(invocation.extraEnv).toEqual({
        GH_TELEMETRY: "false",
        DO_NOT_TRACK: "1",
        GH_NO_UPDATE_NOTIFIER: "1",
        GH_PROMPT_DISABLED: "1",
      });
      expect(invocation.command.join(" ")).not.toContain("value-a");
      expect(invocation.command).not.toContain("--body");
      expect(invocation.command).not.toContain("--env-file");
    }
    // No options = repository secrets (gh resolves the repo from cwd's
    // git remote)
    const bare = buildInvocations({
      preset: execOf(parsed(githubTarget())).spec,
      command: "gh",
      cwd: "/repo",
      options: {},
      writes: [write("API_KEY", "v")],
      deletes: [],
    });
    expect(bare.map((invocation) => invocation.command)).toEqual([
      ["gh", "secret", "set", "API_KEY"],
    ]);
  });

  it("a non-UTF-8 value is dropped rather than silently written empty (the defense line premised on prepareWork rejecting it first)", () => {
    const target = parsed({ preset: "cloudflare-workers", environment: "prod", variables: "all" });
    expect(() =>
      buildInvocations({
        preset: execOf(target).spec,
        command: execOf(target).command,
        cwd: execOf(target).cwd,
        options: target.options,
        writes: [
          {
            name: "A",
            value: Redacted.make(new Uint8Array([0xff, 0xfe]), { label: "variable-value" }),
          },
        ],
        deletes: [],
      }),
    ).toThrow("not valid UTF-8");
  });

  it("no value token exists in the argument templates (banned by type — verifies by scanning the declarations)", () => {
    for (const preset of Object.values(EXEC_PRESETS)) {
      const templates = [
        ...preset.writeArgs,
        ...(preset.delete === "json-null" ? [] : preset.delete.args),
      ];
      for (const template of templates) {
        if (typeof template === "string") {
          expect(template).not.toMatch(/value|body/i);
        } else {
          expect(["name", "option", "switch"]).toContain(template.kind);
        }
      }
    }
  });
});

describe("checkValueConstraints", () => {
  const vercel = { constraints: EXEC_PRESETS.vercel.constraints, label: "the vercel CLI" };
  const workers = {
    constraints: EXEC_PRESETS["cloudflare-workers"].constraints,
    label: "the wrangler CLI",
  };

  it("Vercel: rejects empty, over-16-KiB, and single-line-with-trailing-newline values, and the wording names only the variable", () => {
    const secret = "s3cr3t-value";
    expect(checkValueConstraints(vercel, "A", encoder.encode(""))?.message).toContain(
      "Variable A is empty",
    );
    const large = checkValueConstraints(vercel, "A", new Uint8Array(16 * 1024 + 1));
    expect(large?.message).toContain("16385 bytes, above the 16384-byte limit");
    expect(checkValueConstraints(vercel, "A", new Uint8Array(16 * 1024))).toBeNull();
    const newline = checkValueConstraints(vercel, "A", encoder.encode(`${secret}\n`));
    expect(newline?.message).toContain("single line ending with a newline");
    expect(newline?.message).not.toContain(secret);
    expect(checkValueConstraints(vercel, "A", encoder.encode(`${secret}\r\n`))).not.toBeNull();
    // Multi-line values keep their trailing newline (the Vercel CLI
    // doesn't drop it), so they pass
    expect(checkValueConstraints(vercel, "A", encoder.encode("a\nb\n"))).toBeNull();
    expect(checkValueConstraints(vercel, "A", encoder.encode(secret))).toBeNull();
  });

  it("Workers: no constraints (empty and newlines ride the JSON as-is)", () => {
    expect(checkValueConstraints(workers, "A", encoder.encode(""))).toBeNull();
    expect(checkValueConstraints(workers, "A", encoder.encode("x\n"))).toBeNull();
    expect(checkValueConstraints(workers, "A", new Uint8Array(70_000))).toBeNull();
    expect(checkValueConstraints(workers, "lower-case:name", encoder.encode("x"))).toBeNull();
  });

  it("GitHub Actions: trailing newlines are rejected on single- and multi-line values and CRs too (gh's TrimRight); names can't start uppercase/with a digit/contain GITHUB_; empty and large values pass", () => {
    const gh = {
      constraints: EXEC_PRESETS["github-actions"].constraints,
      label: "the gh CLI",
    };
    const secret = "s3cr3t-value";
    for (const value of [
      `${secret}\n`,
      `${secret}\r\n`,
      `${secret}\r`,
      "a\nb\n",
      "a\nb\n\n",
      "\n",
    ]) {
      const refused = checkValueConstraints(gh, "A", encoder.encode(value));
      expect(refused?.message).toContain(
        "Variable A ends with a newline, which the gh CLI strips from stdin",
      );
      expect(refused?.message).not.toContain(secret);
    }
    expect(checkValueConstraints(gh, "A", encoder.encode("a\nb"))).toBeNull();
    expect(checkValueConstraints(gh, "A", encoder.encode(secret))).toBeNull();
    // Empty stdin is sent by gh as an empty body (not rejected); the
    // ceiling is the API's business (no trimming)
    expect(checkValueConstraints(gh, "A", encoder.encode(""))).toBeNull();
    expect(checkValueConstraints(gh, "A", new Uint8Array(70_000))).toBeNull();
    // Names: GitHub stores them uppercase = two names differing by case
    // would fold into one secret, so uppercase only
    for (const name of [
      "api_key",
      "ApiKey",
      "1KEY",
      "GITHUB_TOKEN",
      "github_x",
      "A-B",
      "A.B",
      "A B",
    ]) {
      const refused = checkValueConstraints(gh, name, encoder.encode("v"));
      expect(refused?.message).toContain(
        `Variable ${name} has a name the gh CLI cannot store as is`,
      );
      expect(refused?.message).toContain("GitHub stores secret names in uppercase");
    }
    for (const name of ["API_KEY", "_KEY", "KEY2", "GITHUBX", "GIT_HUB_TOKEN"]) {
      expect(checkValueConstraints(gh, name, encoder.encode("v"))).toBeNull();
    }
  });
});

describe("scrubVendorOutput", () => {
  it("scrubs values in their JSON-escaped form too (wrangler's body echo)", () => {
    const values = [write("A", 'quo"te\\back\nnext'), write("B", "plain")];
    const echoed = `Error: body was ${JSON.stringify({ A: 'quo"te\\back\nnext', B: "plain" })}`;
    const scrubbed = scrubVendorOutput(echoed, values).join("\n");
    expect(scrubbed).not.toContain("quo");
    expect(scrubbed).not.toContain("back");
    expect(scrubbed).not.toContain("next");
    expect(scrubbed).not.toContain("plain");
    expect(scrubbed).toContain('{"A":"[redacted]","B":"[redacted]"}');
  });

  it("scrubs before truncating output over the cap (doesn't leave the second half of a value that straddled the cut)", () => {
    // If you truncated to the last 64K chars before scrubbing, the second
    // half of a straddling value wouldn't match any fragment and would be
    // displayed as-is. Size it so the cut lands at the value's 20th char
    const value = "S".repeat(40);
    const values = [write("A", value)];
    const tail = "\nError: request failed";
    const filler = "f".repeat(64 * 1024 + 20 - value.length - tail.length);
    const scrubbed = scrubVendorOutput(`${value}${filler}${tail}`, values);
    expect(scrubbed).toHaveLength(2);
    expect(scrubbed.join("\n")).not.toContain("SSSSSSSSSS");
    expect(scrubbed[0]?.length).toBeLessThan(64 * 1024);
    expect(scrubbed[1]).toBe("Error: request failed");
  });

  it("scrubs values and each line of multi-line values, neutralizes control characters, and keeps only the last 20 lines", () => {
    const values = [write("A", "top-secret"), write("B", "first line\nsecond line")];
    const lines = Array.from({ length: 30 }, (_, index) => `line ${index}`);
    const output = [
      ...lines,
      "wrote top-secret ok[31m",
      "saw second line and first line\nfirst line",
    ].join("\n");
    const scrubbed = scrubVendorOutput(output, values);
    expect(scrubbed).toHaveLength(20);
    expect(scrubbed.join("\n")).not.toContain("top-secret");
    expect(scrubbed.join("\n")).not.toContain("second line");
    expect(scrubbed.join("\n")).not.toContain("");
    expect(scrubbed[scrubbed.length - 3]).toBe("wrote [redacted] ok�[31m");
    expect(scrubbed[scrubbed.length - 2]).toBe("saw [redacted] and [redacted]");
    expect(scrubbed[scrubbed.length - 1]).toBe("[redacted]");
  });
});

describe("computePlan", () => {
  const target = parsed(vercelTarget({ variables: ["A", "B", "C"] }));

  function plan(input: {
    readonly source: readonly {
      name: string;
      version: number;
      byteLength?: number;
      required?: boolean;
    }[];
    readonly receipt: Record<string, number> | null;
    readonly declared?: readonly { name: string; required: boolean }[];
    readonly targetOverride?: SyncTarget;
  }) {
    return Effect.runSync(
      computePlan({
        target: input.targetOverride ?? target,
        source: input.source.map((entry) => ({
          name: entry.name,
          version: entry.version,
          byteLength: entry.byteLength ?? 10,
          required: entry.required ?? false,
        })),
        declared: (input.declared ?? []).map((entry) => ({
          variableId: `id-${entry.name}`,
          name: entry.name,
          required: entry.required,
          varType: "",
        })),
        receipt:
          input.receipt === null
            ? null
            : {
                version: 1,
                target: "t",
                preset: "vercel",
                syncedAt: "2026-09-06T00:00:00.000Z",
                variables: input.receipt,
              },
      }),
    );
  }

  it("emits add / update / unchanged / delete in name order", () => {
    const result = plan({
      source: [
        { name: "C", version: 1 },
        { name: "A", version: 3 },
        { name: "B", version: 2 },
      ],
      receipt: { A: 2, B: 2, Z: 9 },
    });
    expect(result.entries).toEqual([
      { action: "update", name: "A", version: 3, previousVersion: 2 },
      { action: "unchanged", name: "B", version: 2 },
      { action: "add", name: "C", version: 1 },
      { action: "delete", name: "Z", previousVersion: 9 },
    ]);
  });

  it("a declared-only variable has nothing to carry, and if required it becomes material to stop", () => {
    const result = plan({
      source: [
        { name: "A", version: 1 },
        { name: "B", version: 1 },
      ],
      receipt: null,
      declared: [{ name: "C", required: true }],
    });
    expect(result.entries.map((entry) => entry.name)).toEqual(["A", "B"]);
    expect(result.declaredRequired.map((entry) => entry.name)).toEqual(["C"]);
  });

  it("counts required actives missing from the selection, and a name on the receipt but out of the selection is a delete", () => {
    const narrow = parsed(vercelTarget({ variables: ["A"] }));
    const result = plan({
      targetOverride: narrow,
      source: [
        { name: "A", version: 1 },
        { name: "B", version: 1, required: true },
      ],
      receipt: { A: 1, B: 1 },
    });
    expect(result.requiredNotSelected).toEqual(["B"]);
    expect(result.entries).toEqual([
      { action: "unchanged", name: "A", version: 1 },
      { action: "delete", name: "B", previousVersion: 1 },
    ]);
  });

  it("all + exclude: excluded names aren't carried, names gone from maruhi are deletes, and `__proto__` is an ordinary name", () => {
    const all = parsed({
      preset: "cloudflare-workers",
      environment: "prod",
      variables: "all",
      exclude: ["PUBLIC"],
    });
    const result = plan({
      targetOverride: all,
      source: [
        { name: "PUBLIC", version: 1 },
        { name: "__proto__", version: 2 },
      ],
      // An object literal's `__proto__:` becomes the prototype
      // designation, so build it from JSON
      receipt: JSON.parse('{"REMOVED":1,"__proto__":1}') as Record<string, number>,
    });
    expect(result.entries).toEqual([
      { action: "delete", name: "REMOVED", previousVersion: 1 },
      { action: "update", name: "__proto__", version: 2, previousVersion: 1 },
    ]);
  });

  it("name rules (gh = uppercase only) become blocked in the plan, while a receipt-only name stays a delete regardless of rules", () => {
    const gh = parsed(githubTarget({ variables: "all" }));
    const result = plan({
      targetOverride: gh,
      source: [
        { name: "API_KEY", version: 2 },
        { name: "apiKey", version: 1 },
      ],
      // A leftover receipt name violating today's rules still passes,
      // since a delete carries no value
      receipt: { API_KEY: 2, oldName: 1 },
    });
    expect(result.entries).toEqual([
      { action: "unchanged", name: "API_KEY", version: 2 },
      {
        action: "blocked",
        name: "apiKey",
        version: 1,
        reason:
          "a name the gh CLI cannot store as is: GitHub stores secret names in uppercase and accepts only uppercase letters, digits, and _, not starting with a digit or with GITHUB_",
      },
      { action: "delete", name: "oldName", previousVersion: 1 },
    ]);
  });

  it("a name missing from the explicit list fails (and names only the value's name)", () => {
    const exit = Effect.runSyncExit(
      computePlan({
        target,
        source: [{ name: "A", version: 1, byteLength: 1, required: false }],
        declared: [],
        receipt: null,
      }),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(JSON.stringify(exit)).toContain("do not exist in environment prod: B, C");
  });
});

describe("receipt codec", () => {
  it("round-trips and encodes deterministically in name order", () => {
    const encoded = encodeReceipt({
      version: 1,
      target: "web",
      preset: "vercel",
      syncedAt: "2026-09-06T00:00:00.000Z",
      variables: { B: 2, A: 1 },
    });
    expect(decoder.decode(encoded)).toBe(
      '{"version":1,"target":"web","preset":"vercel","syncedAt":"2026-09-06T00:00:00.000Z","variables":{"A":1,"B":2}}',
    );
    const decoded = decodeReceipt(decoder.decode(encoded), "web");
    expect(decoded).toMatchObject({ target: "web", variables: { A: 1, B: 2 } });
    expect(receiptVariableName("web")).toBe("sync-receipt:web");
  });

  it.each([
    ["nope", "not valid JSON"],
    ["[]", "the top level must be an object"],
    ['{"version":2}', "unsupported receipt version"],
    ['{"version":1,"target":"other"}', "the receipt names a different target"],
    ['{"version":1,"target":"web","preset":"x"}', "unknown preset"],
    ['{"version":1,"target":"web","preset":"vercel","syncedAt":1}', "syncedAt must be a string"],
    [
      '{"version":1,"target":"web","preset":"vercel","syncedAt":"t","variables":[]}',
      "variables must be an object",
    ],
    [
      '{"version":1,"target":"web","preset":"vercel","syncedAt":"t","variables":{"A":0}}',
      "positive integer versions",
    ],
  ])("rejects: %s", (text, reason) => {
    expect(decodeReceipt(text, "web")).toContain(reason);
  });
});
