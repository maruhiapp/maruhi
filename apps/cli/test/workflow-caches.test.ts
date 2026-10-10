// Pins "a privileged workflow restores no Actions cache" mechanically, so a
// later edit cannot bring one back unnoticed.
//
// An Actions cache entry in the default branch's scope is writable by code
// in any run there (a push to main and its dependencies, the Pullfrog
// agent's workflow_dispatch) — GITHUB_TOKEN permissions do not limit cache
// writes — and tag-triggered release runs read that scope. An executable
// restored from it would run with the release run's artifact-overwrite token
// or ops-backup's Cloudflare token. What is pinned:
//   1. every workflow is classified, and the unprivileged ones hold no secret
//      and no write permission (a new privileged workflow cannot slip in as
//      unprivileged)
//   2. privileged workflows use only allowlisted actions (default-deny: an
//      action with an implicit cache — setup-go, setup-python's `cache`,
//      setup-node v5's package-manager cache — fails here first), no cache
//      input, and no cross-run artifact download
//   3. ci.yml, which release.yml runs as its gate, gates each cache step on
//      `skip-caches`, and release.yml passes `skip-caches: true`
//   4. Bun comes only from .github/actions/install-bun, whose pinned version
//      is `.bun-version`, and release.yml's publish-npm (the OIDC publish)
//      runs only a pinned Node.js; both check the pinned SHA-256 before
//      unpacking, and unpack before first running anything
// YAML is parsed by `Bun.YAML` in a subprocess (vitest runs on Node), the
// same way as apps/site/test/unit/workflows.test.ts.

import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const repoRoot = fileURLToPath(new URL("../../../", import.meta.url));
const read = (path: string): string => readFileSync(join(repoRoot, path), "utf8");

function parseYaml(text: string): unknown {
  const result = spawnSync(
    "bun",
    ["-e", "process.stdout.write(JSON.stringify(Bun.YAML.parse(await Bun.stdin.text())))"],
    { input: text, encoding: "utf8", timeout: 10_000 },
  );
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout) as unknown;
}

interface Step {
  readonly name?: string;
  readonly uses?: string;
  readonly with?: Readonly<Record<string, unknown>>;
  readonly env?: Readonly<Record<string, unknown>>;
  readonly if?: string;
  readonly run?: string;
}
interface Job {
  readonly uses?: string;
  readonly with?: Readonly<Record<string, unknown>>;
  readonly permissions?: unknown;
  readonly steps?: readonly Step[];
}
interface Workflow {
  readonly on: Readonly<Record<string, unknown>>;
  readonly permissions?: unknown;
  readonly jobs: Readonly<Record<string, Job>>;
}

const WORKFLOWS_DIR = ".github/workflows";
const loadWorkflow = (file: string) => {
  const source = read(`${WORKFLOWS_DIR}/${file}`);
  return { source, workflow: parseYaml(source) as Workflow };
};

/** Hold a secret, a write permission, or produce what gets published. */
const PRIVILEGED = ["ops-backup.yml", "pullfrog.yml", "release.yml"];
/** Read-only runs with no secret. ci.yml is also release.yml's gate (see 3). */
const UNPRIVILEGED = ["ci.yml", "english-pr.yml", "installer.yml"];

const INSTALL_BUN = "./.github/actions/install-bun";

/** Actions with no cache feature at all: any commit, pinned by its 40-hex SHA. */
const NO_CACHE_ACTIONS = [
  "actions/checkout",
  "actions/upload-artifact",
  "actions/download-artifact",
];
/**
 * Actions that could grow a cache (pullfrog's agent runtime), allowed at the reviewed commit only,
 * so a bump re-checks them here. actions/setup-node is deliberately absent: v5+ turns a
 * package-manager cache on by default, and it downloads Node unverified on a tool-cache miss.
 */
const REVIEWED_ACTIONS = ["pullfrog/pullfrog@0657d542f2e34565c6254d5c84581313e631cd90"];
const CACHE_ACTIONS = /^actions\/cache(\/restore|\/save)?@/;

/** Why a `uses:` step could restore an Actions cache, or undefined when it cannot. */
function cacheRisk(step: Step): string | undefined {
  const uses = step.uses ?? "";
  const allowed =
    uses === INSTALL_BUN ||
    REVIEWED_ACTIONS.includes(uses) ||
    NO_CACHE_ACTIONS.some((action) => new RegExp(`^${action}@[0-9a-f]{40}$`).test(uses));
  if (!allowed) return `${uses} is not an allowlisted, SHA-pinned action`;
  const cacheInputs = Object.keys(step.with ?? {}).filter((key) => key.includes("cache"));
  return cacheInputs.length > 0 ? `${uses} sets ${cacheInputs.join(", ")}` : undefined;
}

/**
 * A pinned install script checks the digest, then unpacks, then runs the unpacked binary — in that
 * order, so nothing downloaded runs unverified.
 */
function expectVerifiedBeforeRun(run: string, unpack: string, firstRun: string): void {
  const verify = run.indexOf("sha256sum --check --strict");
  expect(verify, "checks the SHA-256").toBeGreaterThan(-1);
  expect(run.indexOf(unpack), `${unpack} after the check`).toBeGreaterThan(verify);
  expect(run.indexOf(firstRun), `${firstRun} after ${unpack}`).toBeGreaterThan(run.indexOf(unpack));
}

const stepsOf = (workflow: Workflow): Step[] =>
  Object.values(workflow.jobs).flatMap((job) => [...(job.steps ?? [])]);

/** Every `permissions:` value granting write, at the workflow or a job level. */
function writeGrants(workflow: Workflow): string[] {
  const grants: string[] = [];
  const collect = (permissions: unknown, where: string) => {
    if (typeof permissions === "string") {
      if (permissions !== "read-all") grants.push(`${where}: ${permissions}`);
      return;
    }
    for (const [scope, level] of Object.entries((permissions ?? {}) as Record<string, unknown>)) {
      if (level === "write") grants.push(`${where}: ${scope}`);
    }
  };
  collect(workflow.permissions, "workflow");
  for (const [name, job] of Object.entries(workflow.jobs)) collect(job.permissions, name);
  return grants;
}

describe("Actions caches stay out of privileged workflows", () => {
  it("classifies every workflow, and the unprivileged ones hold no secret and no write permission", () => {
    const files = readdirSync(join(repoRoot, WORKFLOWS_DIR)).filter((f) => /\.ya?ml$/.test(f));
    expect(files.toSorted()).toEqual([...PRIVILEGED, ...UNPRIVILEGED].toSorted());
    for (const file of UNPRIVILEGED) {
      const { source, workflow } = loadWorkflow(file);
      expect(source, `${file} references a secret`).not.toMatch(/secrets\./);
      expect(writeGrants(workflow), `${file} grants write`).toEqual([]);
      // A workflow without an explicit permissions block gets the repository default
      expect(workflow.permissions, `${file} states its permissions`).toBeDefined();
    }
  });

  describe.each(PRIVILEGED)("%s", (file) => {
    const { workflow } = loadWorkflow(file);

    it("uses only actions that restore no Actions cache", () => {
      const risks = stepsOf(workflow)
        .filter((step) => step.uses !== undefined)
        .map(cacheRisk);
      expect(risks.filter((risk) => risk !== undefined)).toEqual([]);
    });

    it("downloads artifacts from its own run only", () => {
      const downloads = stepsOf(workflow).filter((s) =>
        s.uses?.startsWith("actions/download-artifact@"),
      );
      for (const step of downloads) {
        expect(Object.keys(step.with ?? {})).not.toContain("run-id");
        expect(Object.keys(step.with ?? {})).not.toContain("github-token");
      }
    });

    it("calls no reusable workflow except ci.yml with skip-caches: true", () => {
      for (const job of Object.values(workflow.jobs)) {
        if (job.uses === undefined) continue;
        expect(job.uses).toBe("./.github/workflows/ci.yml");
        expect(job.with).toEqual({ "skip-caches": true });
      }
    });
  });

  describe("ci.yml (also release.yml's gate)", () => {
    const { workflow } = loadWorkflow("ci.yml");

    it("declares skip-caches as a boolean input defaulting to false", () => {
      const call = workflow.on["workflow_call"] as { inputs: Record<string, unknown> };
      expect(call.inputs["skip-caches"]).toEqual({ type: "boolean", default: false });
    });

    it("gates every cache step on skip-caches and uses no other action with a cache", () => {
      const cacheSteps = stepsOf(workflow).filter((s) => CACHE_ACTIONS.test(s.uses ?? ""));
      expect(cacheSteps.length).toBeGreaterThan(0);
      // The gate is the whole condition or its first conjunct (no top-level `||`)
      for (const step of cacheSteps) {
        expect(step.if, step.name).toMatch(/^\$\{\{ !inputs\.skip-caches( && [^|]+)? \}\}$/);
      }
      const risks = stepsOf(workflow)
        .filter((step) => step.uses !== undefined && !CACHE_ACTIONS.test(step.uses))
        .map(cacheRisk);
      expect(risks.filter((risk) => risk !== undefined)).toEqual([]);
    });
  });

  describe("Bun comes only from the pinned install-bun action", () => {
    const action = parseYaml(read(".github/actions/install-bun/action.yml")) as {
      runs: { using: string; steps: Step[] };
    };

    it("is the only Bun installer in any workflow", () => {
      for (const file of [...PRIVILEGED, ...UNPRIVILEGED]) {
        const { source } = loadWorkflow(file);
        expect(source, file).not.toMatch(/setup-bun@|bun\.sh\/install/);
      }
    });

    it("runs shell steps only and pins the version .bun-version names, with a SHA-256", () => {
      expect(action.runs.using).toBe("composite");
      expect(action.runs.steps.map((s) => s.uses)).toEqual([undefined]);
      const env = action.runs.steps[0]?.env ?? {};
      expect(env["BUN_VERSION"]).toBe(read(".bun-version").trim());
      expect(env["BUN_LINUX_X64_ZIP_SHA256"]).toMatch(/^[0-9a-f]{64}$/);
      expectVerifiedBeforeRun(action.runs.steps[0]?.run ?? "", "unzip ", '"${bin_dir}/bun"');
    });
  });

  describe("release.yml publish-npm runs only a pinned Node.js", () => {
    const steps = loadWorkflow("release.yml").workflow.jobs["publish-npm"]?.steps ?? [];
    const install = steps.findIndex((s) => s.name === "Install Node.js (pinned SHA-256, no cache)");
    const step = steps[install];

    it("pins an exact version and its SHA-256, and checks it before unpacking and running", () => {
      expect(step?.env?.["NODE_VERSION"]).toMatch(/^\d+\.\d+\.\d+$/);
      expect(step?.env?.["NODE_LINUX_X64_TARGZ_SHA256"]).toMatch(/^[0-9a-f]{64}$/);
      const run = step?.run ?? "";
      expect(run).toContain(
        "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.gz",
      );
      expectVerifiedBeforeRun(run, "tar -xzf ", '"${node_dir}/bin/node"');
    });

    it("installs Node before any step runs node or npm", () => {
      const firstUse = steps.findIndex(
        (s, i) => i !== install && /\b(node|npm)\b/.test(s.run ?? ""),
      );
      expect(install).toBeGreaterThan(-1);
      expect(firstUse).toBeGreaterThan(install);
    });
  });
});
