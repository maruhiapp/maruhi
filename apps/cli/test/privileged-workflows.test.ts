// Pins the privileged workflows' supply-chain invariants mechanically, so a
// later edit cannot undo one unnoticed. The rule behind them: an executable
// that runs in a privileged run comes either from the commit being run or
// from a fetch verified against a digest pinned in that commit, and a
// release publishes only what its build job produced.
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
//      input, no cross-run artifact download, and no job or service
//      container
//   3. ci.yml, which release.yml runs as its gate, gates each cache step on
//      `skip-caches`, and release.yml passes `skip-caches: true`
//   4. Bun comes only from .github/actions/install-bun, whose pinned version
//      is `.bun-version`, and release.yml's publish-npm (the OIDC publish)
//      runs only a pinned Node.js; both check the pinned SHA-256 before
//      unpacking, and unpack before first running anything
//   5. the Bun runtime embedded in each release binary is a release zip
//      pinned in apps/cli/scripts/bun-runtimes.ts at that same version (the
//      linux-x64 pin is install-bun's), and the build cannot fall back to an
//      unpinned download
//   6. release.yml's build job digests each artifact into its job outputs,
//      and every job that can publish (a write permission or the OIDC token)
//      checks each artifact it downloads against that digest before anything
//      else, then publishes from the checked directory only
//   7. the OIDC publish (publish-npm) is the only job in an environment, and
//      a job with no condition fails the run before publish-github unless
//      that environment requires a reviewer and admits exactly the release
//      tag pattern (GitHub creates a missing environment unprotected)
// YAML is parsed by `Bun.YAML` in a subprocess (vitest runs on Node), the
// same way as apps/site/test/unit/workflows.test.ts.

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { BUN_RUNTIME_VERSION, BUN_RUNTIMES, downloadVerified } from "../scripts/bun-runtimes.ts";
import { TARGETS } from "../scripts/shared.ts";

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
  readonly id?: string;
  readonly name?: string;
  readonly uses?: string;
  readonly "working-directory"?: string;
  readonly with?: Readonly<Record<string, unknown>>;
  readonly env?: Readonly<Record<string, unknown>>;
  readonly if?: string;
  readonly run?: string;
}
interface Job {
  readonly uses?: string;
  readonly needs?: string | readonly string[];
  readonly outputs?: Readonly<Record<string, string>>;
  readonly if?: string;
  readonly environment?: string | { readonly name: string };
  readonly container?: unknown;
  readonly services?: unknown;
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

    it("runs no job in a container and starts no service container", () => {
      // An image pulled by tag is another unverified executable; none is needed today
      const images = Object.entries(workflow.jobs).filter(
        ([, job]) => job.container !== undefined || job.services !== undefined,
      );
      expect(images.map(([name]) => name)).toEqual([]);
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

  describe("Bun comes only from pinned release zips", () => {
    // The install-bun action runs scripts/install-bun.sh, which holds the CI pin; both are
    // pinned in dev-setup.test.ts
    const installScript = read("scripts/install-bun.sh");
    const scriptPin = (name: string) =>
      new RegExp(`^${name}="([^"]*)"$`, "m").exec(installScript)?.[1];

    it("is the only Bun installer in any workflow", () => {
      for (const file of [...PRIVILEGED, ...UNPRIVILEGED]) {
        const { source } = loadWorkflow(file);
        expect(source, file).not.toMatch(/setup-bun@|bun\.sh\/install/);
      }
    });

    it("pins the runtime embedded in every release target, at the same version and zip", () => {
      expect(BUN_RUNTIME_VERSION).toBe(read(".bun-version").trim());
      expect(Object.keys(BUN_RUNTIMES).toSorted()).toEqual(
        TARGETS.map((t) => t.bunTarget).toSorted(),
      );
      for (const runtime of Object.values(BUN_RUNTIMES)) {
        expect(runtime.sha256).toMatch(/^[0-9a-f]{64}$/);
        expect(runtime.member).toMatch(/^bun-[a-z0-9-]+\/bun(\.exe)?$/);
        expect(runtime.zip).toBe(`${runtime.member.split("/")[0]}.zip`);
      }
      // One zip, two pins: the CI Bun and the linux-x64 runtime must not drift apart
      expect(scriptPin("BUN_VERSION")).toBe(BUN_RUNTIME_VERSION);
      expect(BUN_RUNTIMES["bun-linux-x64"].sha256).toBe(scriptPin("BUN_LINUX_X64_ZIP_SHA256"));
    });

    it("compiles every target with a pinned runtime and no fallback download", () => {
      const script = read("apps/cli/scripts/build-binaries.ts");
      expect(script).toContain("`--compile-executable-path=${executable}`");
      expect(script).toContain("downloadVerified(runtimeUrl(runtime), runtime.sha256)");
      // A flag bun ignored would fetch the runtime from npm; this env makes that fail
      expect(script).toContain("HTTPS_PROXY: unreachable,");
      expect(script).toContain('BUN_INSTALL_CACHE_DIR: join(runtimesDir, "install-cache"),');
      expect(script).toMatch(/run\(\s*"bun",\s*\[[^\]]*\],\s*cliRoot,\s*compileEnv,\s*\)/);
      expect(script.match(/"--compile"/g)).toHaveLength(1);
    });

    it("downloadVerified returns only bytes matching the pin", async () => {
      const url = "https://runtime.invalid/bun.zip";
      const pin = createHash("sha256").update("runtime").digest("hex");
      const serve = (body: string, status = 200) =>
        (async () => new Response(body, { status })) as unknown as typeof fetch;
      const bytes = await downloadVerified(url, pin, serve("runtime"));
      expect(new TextDecoder().decode(bytes)).toBe("runtime");
      await expect(downloadVerified(url, pin, serve("evil"))).rejects.toThrow(
        /does not match the pinned/,
      );
      await expect(downloadVerified(url, pin, serve("runtime", 404))).rejects.toThrow(/HTTP 404/);
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

    it("installs Node before any step runs node, npm, npx or corepack", () => {
      const firstUse = steps.findIndex(
        (s, i) => i !== install && /\b(node|npm|npx|corepack)\b/.test(s.run ?? ""),
      );
      expect(install).toBeGreaterThan(-1);
      expect(firstUse).toBeGreaterThan(install);
    });
  });
});

describe("release.yml publishes only what its build job produced", () => {
  const { workflow } = loadWorkflow("release.yml");
  const jobs = Object.entries(workflow.jobs);
  const build = workflow.jobs["build"];
  const buildSteps = build?.steps ?? [];
  /** The one digest function, byte-identical in build and in every publishing job. */
  const DIGEST =
    "digest() { (cd \"$1\" && find . ! -type d -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum --) | sha256sum | cut -d ' ' -f 1; }";
  /** Defines the digest function exactly once, as DIGEST. */
  const expectDigestFunction = (run: string, where: string) => {
    expect(run, where).toContain(DIGEST);
    expect(run.split("digest()"), where).toHaveLength(2);
  };
  const isDownload = (step: Step) => step.uses?.startsWith("actions/download-artifact@") === true;
  const needsOf = (job: Job) => (typeof job.needs === "string" ? [job.needs] : (job.needs ?? []));
  /** Jobs that can publish: any write permission or the OIDC token. */
  const publishers = jobs.filter(([, { permissions }]) =>
    typeof permissions === "string"
      ? permissions === "write-all"
      : Object.values((permissions ?? {}) as Record<string, unknown>).includes("write"),
  );

  it("digests each uploaded artifact after it is built and before it is uploaded", () => {
    const digests = buildSteps.findIndex((s) => s.id === "digests");
    const run = buildSteps[digests]?.run ?? "";
    expectDigestFunction(run, "build");
    const lastBuild = buildSteps.findLastIndex((s) => /\bbuild:(binaries|npm)\b/.test(s.run ?? ""));
    expect(digests).toBeGreaterThan(lastBuild);
    expect(lastBuild).toBeGreaterThan(-1);
    const uploads = buildSteps.filter((s) => s.uses?.startsWith("actions/upload-artifact@"));
    expect(uploads.map((s) => s.with?.["name"]).toSorted()).toEqual(["binaries", "npm-package"]);
    for (const upload of uploads) {
      expect(buildSteps.indexOf(upload)).toBeGreaterThan(digests);
      const name = String(upload.with?.["name"]);
      const path = String(upload.with?.["path"]).replace(/\/$/, "");
      const variable = name.replaceAll("-", "_");
      expect(run).toContain(`${variable}=$(digest ${path})`);
      expect(run).toContain(`echo "${name}=\${${variable}}" >> "$GITHUB_OUTPUT"`);
      expect(build?.outputs?.[`${name}-digest`]).toBe(`\${{ steps.digests.outputs.${name} }}`);
    }
  });

  /** The step right after `download` checks that artifact against the build job's digest. */
  function expectVerified(steps: readonly Step[], download: Step, job: string): void {
    const verify = steps[steps.indexOf(download) + 1];
    const artifact = String(download.with?.["name"]);
    expect(verify?.["working-directory"], job).toBe(download.with?.["path"]);
    expect(verify?.env?.["EXPECTED_DIGEST"], job).toBe(
      `\${{ needs.build.outputs.${artifact}-digest }}`,
    );
    const run = verify?.run ?? "";
    expectDigestFunction(run, job);
    expect(run, job).toContain("actual=$(digest .)");
    expect(run, job).toContain(
      'if ! [[ "${EXPECTED_DIGEST}" =~ ^[0-9a-f]{64}$ ]] || [ "${actual}" != "${EXPECTED_DIGEST}" ]; then',
    );
  }

  it("verifies every artifact a publishing job downloads, right after the download", () => {
    expect(publishers.map(([name]) => name).toSorted()).toEqual(["publish-github", "publish-npm"]);
    for (const [name, job] of publishers) {
      const steps = job.steps ?? [];
      const downloads = steps.filter(isDownload);
      expect(downloads.length, name).toBeGreaterThan(0);
      expect(needsOf(job), name).toContain("build");
      for (const download of downloads) expectVerified(steps, download, name);
    }
  });

  it("publishes from the verified directories only", () => {
    const steps = (job: string) => workflow.jobs[job]?.steps ?? [];
    const release = steps("publish-github").filter((s) => s.run?.includes("gh release create"));
    expect(release.map((s) => s["working-directory"])).toEqual(["binaries"]);
    const publish = steps("publish-npm").filter((s) => /\bnpm publish\b/.test(s.run ?? ""));
    expect(publish.length).toBeGreaterThan(0);
    for (const step of publish) expect(step.run).toMatch(/npm publish \.\/dist-npm /);
  });
});

describe("release.yml publishes to npm only after a reviewer approves", () => {
  const { workflow } = loadWorkflow("release.yml");
  const check = workflow.jobs["npm-environment"];
  const step = check?.steps?.[0];
  const environmentOf = (job: Job | undefined) =>
    typeof job?.environment === "string" ? job.environment : job?.environment?.name;

  it("runs the OIDC publish in the checked environment, and nothing else in any environment", () => {
    const withEnvironment = Object.entries(workflow.jobs).filter(([, job]) => job.environment);
    expect(withEnvironment.map(([name]) => name)).toEqual(["publish-npm"]);
    const oidc = Object.entries(workflow.jobs).filter(
      ([, job]) =>
        (job.permissions as Record<string, unknown> | undefined)?.["id-token"] === "write",
    );
    expect(oidc.map(([name]) => name)).toEqual(["publish-npm"]);
    expect(environmentOf(workflow.jobs["publish-npm"])).toBe(step?.env?.["ENVIRONMENT"]);
  });

  it("checks that environment before anything irreversible, on dry runs too", () => {
    expect(check?.if).toBeUndefined();
    expect(check?.permissions).toEqual({ actions: "read" });
    expect(check?.steps?.map((s) => s.uses)).toEqual([undefined]);
    // publish-npm runs after publish-github, so the check gates both
    expect(workflow.jobs["publish-github"]?.needs).toContain("npm-environment");
    expect(workflow.jobs["publish-npm"]?.needs).toContain("publish-github");
  });

  it("requires a reviewer and exactly the release tag pattern, failing closed", () => {
    const push = workflow.on["push"] as { tags: readonly string[] };
    expect(push.tags).toEqual([step?.env?.["TAG_PATTERN"]]);
    const run = step?.run ?? "";
    expect(run).toContain("set -euo pipefail");
    expect(run).toContain('if ! config=$(gh api "${api}"); then');
    expect(run).toContain(
      `reviewers=$(jq '[.protection_rules[] | select(.type == "required_reviewers") | .reviewers[]] | length' <<< "\${config}")`,
    );
    expect(run).toContain('if [ "${reviewers}" -lt 1 ]; then');
    expect(run).toContain(
      `if [ "$(jq '.deployment_branch_policy.custom_branch_policies' <<< "\${config}")" != "true" ]; then`,
    );
    expect(run).toContain('if [ "${policies}" != "tag ${TAG_PATTERN}" ]; then');
    expect(run.match(/\bexit 1\b/g)).toHaveLength(4);
  });
});
