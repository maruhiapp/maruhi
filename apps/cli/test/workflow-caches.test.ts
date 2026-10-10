// Pins "no workflow restores an Actions cache" mechanically, so a later edit
// cannot bring one back unnoticed.
//
// An Actions cache entry in the default branch's scope is writable by code
// in any run there (a push to main and its dependencies, the Pullfrog
// agent's workflow_dispatch) — GITHUB_TOKEN permissions do not limit cache
// writes — and PR, push and tag-triggered release runs all read that scope.
// actions/cache restores by untarring the entry with absolute paths allowed
// (`tar -P`) and no member filter, so whatever its key and path, one entry
// can rewrite the checkout, node_modules, build output or $HOME before they
// run: falsified gate results on PR / push runs, and the release run's
// artifact-overwrite token or ops-backup's Cloudflare token on privileged
// ones. Checking the file a step meant to restore does not help. What is
// pinned:
//   1. every workflow is classified, and the unprivileged ones hold no secret
//      and no write permission (a new privileged workflow cannot slip in as
//      unprivileged)
//   2. every workflow uses only allowlisted, SHA-pinned or local actions and
//      no reusable workflow but ci.yml (called with no inputs)
//      (default-deny: actions/cache, and any action with an implicit cache —
//      setup-go, setup-python's `cache`, setup-node v5's package-manager
//      cache — fails here first) with no cache input, and the local actions
//      run shell steps only
//   3. privileged workflows download artifacts from their own run only, and
//      run no job or service container
//   4. Bun comes only from .github/actions/install-bun, whose pinned version
//      is `.bun-version`, and release.yml's publish-npm (the OIDC publish)
//      runs only a pinned Node.js; both check the pinned SHA-256 before
//      unpacking, and unpack before first running anything
//   5. ci.yml's browser is the Chrome Headless Shell version the pinned
//      Playwright expects (bun.lock resolves one Playwright), downloaded and
//      checked against a pinned SHA-256 before it is unpacked. Any other
//      Playwright browser download fails: ci.yml points PLAYWRIGHT_DOWNLOAD_HOST
//      at an unresolvable host and nothing else sets a PLAYWRIGHT_ variable,
//      and no workflow, local action or package.json script (`pre`/`post`
//      hooks included) runs `playwright install` in any spelling
// YAML is parsed by `Bun.YAML` in a subprocess (vitest runs on Node), the
// same way as apps/site/test/unit/workflows.test.ts.

import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
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
  readonly env?: Readonly<Record<string, unknown>>;
  readonly container?: unknown;
  readonly services?: unknown;
  readonly with?: Readonly<Record<string, unknown>>;
  readonly permissions?: unknown;
  readonly steps?: readonly Step[];
}
interface Workflow {
  readonly on: Readonly<Record<string, unknown>>;
  readonly env?: Readonly<Record<string, unknown>>;
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
/** Read-only runs with no secret. ci.yml is also release.yml's gate. */
const UNPRIVILEGED = ["ci.yml", "english-pr.yml", "installer.yml"];

const INSTALL_BUN = "./.github/actions/install-bun";
/** Actions in this repository, allowed when they run shell steps only (checked below). */
const LOCAL_ACTIONS = [INSTALL_BUN, "./actions/setup-maruhi"];
const loadLocalAction = (uses: string) =>
  parseYaml(read(`${uses.slice(2)}/action.yml`)) as { runs: { using: string; steps: Step[] } };

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

/** Why a `uses:` step could restore an Actions cache, or undefined when it cannot. */
function cacheRisk(step: Step): string | undefined {
  const uses = step.uses ?? "";
  const allowed =
    LOCAL_ACTIONS.includes(uses) ||
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

describe("No workflow restores an Actions cache", () => {
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

  it.each([...PRIVILEGED, ...UNPRIVILEGED])(
    "%s uses only actions that restore no Actions cache",
    (file) => {
      const risks = stepsOf(loadWorkflow(file).workflow)
        .filter((step) => step.uses !== undefined)
        .map(cacheRisk);
      expect(risks.filter((risk) => risk !== undefined)).toEqual([]);
    },
  );

  it.each([...PRIVILEGED, ...UNPRIVILEGED])(
    "%s calls no reusable workflow except ci.yml, with no inputs",
    (file) => {
      // A reusable workflow elsewhere would bring its own steps, caches included
      for (const job of Object.values(loadWorkflow(file).workflow.jobs)) {
        if (job.uses === undefined) continue;
        expect(job.uses).toBe("./.github/workflows/ci.yml");
        expect(job.with).toBeUndefined();
      }
    },
  );

  it.each(LOCAL_ACTIONS)("%s runs shell steps only", (uses) => {
    const action = loadLocalAction(uses);
    expect(action.runs.using).toBe("composite");
    expect(action.runs.steps.filter((s) => s.uses !== undefined)).toEqual([]);
  });

  describe.each(PRIVILEGED)("%s", (file) => {
    const { workflow } = loadWorkflow(file);

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
  });

  describe("Bun comes only from the pinned install-bun action", () => {
    const action = loadLocalAction(INSTALL_BUN);

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

    it("installs Node before any step runs node, npm, npx or corepack", () => {
      const firstUse = steps.findIndex(
        (s, i) => i !== install && /\b(node|npm|npx|corepack)\b/.test(s.run ?? ""),
      );
      expect(install).toBeGreaterThan(-1);
      expect(firstUse).toBeGreaterThan(install);
    });
  });

  describe("ci.yml runs only the pinned, verified Chrome Headless Shell", () => {
    const steps = loadWorkflow("ci.yml").workflow.jobs["check"]?.steps ?? [];
    const install = steps.findIndex(
      (s) => s.name === "Install Chrome Headless Shell (pinned SHA-256, no cache)",
    );
    const step = steps[install];
    const run = step?.run ?? "";
    const webPin = (
      JSON.parse(read("apps/web/package.json")) as { devDependencies: Record<string, string> }
    ).devDependencies["playwright"];

    it("pins the headless-shell version the pinned Playwright expects, with a SHA-256", () => {
      const sitePin = (
        JSON.parse(read("apps/site/package.json")) as { devDependencies: Record<string, string> }
      ).devDependencies["playwright"];
      // Steps 9 / 9b / 11 share the one browser
      expect(sitePin, "apps/site and apps/web pin the same playwright").toBe(webPin);
      const fromWeb = createRequire(join(repoRoot, "apps/web/package.json"));
      const corePackage = createRequire(fromWeb.resolve("playwright/package.json")).resolve(
        "playwright-core/package.json",
      );
      const core = JSON.parse(readFileSync(corePackage, "utf8")) as { version: string };
      expect(core.version).toBe(webPin);
      const { browsers } = JSON.parse(
        readFileSync(join(dirname(corePackage), "browsers.json"), "utf8"),
      ) as { browsers: { name: string; browserVersion?: string }[] };
      const expected = browsers.find((b) => b.name === "chromium-headless-shell")?.browserVersion;
      expect(expected).toMatch(/^\d+\.\d+\.\d+\.\d+$/);
      expect(
        step?.env?.["CHROME_HEADLESS_SHELL_VERSION"],
        `playwright ${core.version} expects headless shell ${expected}: update the version and SHA-256 together (procedure at the install step)`,
      ).toBe(expected);
      expect(step?.env?.["CHROME_HEADLESS_SHELL_LINUX64_ZIP_SHA256"]).toMatch(/^[0-9a-f]{64}$/);
    });

    it("resolves one Playwright everywhere, so @vitest/browser-playwright drives the same one", () => {
      const lock = read("bun.lock");
      for (const name of ["playwright", "playwright-core"]) {
        const versions = new Set(
          [...lock.matchAll(new RegExp(`"${name}@([^"]+)"`, "g"))].map((m) => m[1]),
        );
        expect([...versions], name).toEqual([webPin]);
      }
    });

    it("downloads the archive and checks it against the pin before unpacking it", () => {
      expect(install).toBeGreaterThan(-1);
      expect(run).toContain(
        "https://storage.googleapis.com/chrome-for-testing-public/${CHROME_HEADLESS_SHELL_VERSION}/linux64/chrome-headless-shell-linux64.zip",
      );
      expectVerifiedBeforeRun(run, "unzip ", "PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=");
      // Unconditional, at the top level of the script, and exits on its own (not through `set -e`)
      const lines = run.split("\n");
      const check = lines.indexOf(
        'if ! echo "${CHROME_HEADLESS_SHELL_LINUX64_ZIP_SHA256}  ${zip}" | sha256sum --check --strict; then',
      );
      expect(check).toBeGreaterThan(-1);
      expect(lines.slice(check + 1, check + 3)).toEqual(["  exit 1", "fi"]);
      // No enclosing block (if / case / loop / group / subshell) opened before it
      let depth = 0;
      for (const line of lines.slice(0, check)) {
        if (/^\s*(if|case|for|while|until)\b|[{(]\s*$/.test(line)) depth += 1;
        if (/^\s*(fi|esac|done|\}|\))(\s|;|$)/.test(line)) depth -= 1;
      }
      expect(depth, "the check is not nested in a block").toBe(0);
    });

    it("sends every other Playwright browser download to an unresolvable host", () => {
      // playwright-core 1.64 replaces all its mirrors (Chrome for Testing's included) with this
      // host, so `playwright install` fails before unpacking, whoever runs it and however
      const { workflow } = loadWorkflow("ci.yml");
      expect(workflow.env?.["PLAYWRIGHT_DOWNLOAD_HOST"]).toBe(
        "https://playwright-download.invalid",
      );
      // ... and nothing overrides it (a PLAYWRIGHT_<browser>_DOWNLOAD_HOST would win over it)
      const playwrightKeys = (env: Readonly<Record<string, unknown>> | undefined) =>
        Object.keys(env ?? {}).filter((key) => key.startsWith("PLAYWRIGHT_"));
      for (const file of [...PRIVILEGED, ...UNPRIVILEGED]) {
        const flow = loadWorkflow(file).workflow;
        expect(playwrightKeys(flow.env), file).toEqual(
          file === "ci.yml" ? ["PLAYWRIGHT_DOWNLOAD_HOST"] : [],
        );
        for (const [name, job] of Object.entries(flow.jobs)) {
          expect(playwrightKeys(job.env), `${file} ${name}`).toEqual([]);
          for (const s of job.steps ?? []) {
            expect(playwrightKeys(s.env), `${file} ${s.name ?? s.uses}`).toEqual([]);
            // Only the install step writes one, the verified executable path, through GITHUB_ENV
            if (file !== "ci.yml" || s.name !== step?.name)
              expect(s.run ?? "", `${file} ${s.name}`).not.toMatch(/PLAYWRIGHT_/);
          }
        }
      }
      expect(run.match(/PLAYWRIGHT_\w+/g)).toEqual(["PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"]);
    });

    it("installs the browser before every browser step", () => {
      const browserSteps = steps.flatMap((s, i) =>
        /\be2e\b|test:browser/.test(s.run ?? "") ? [i] : [],
      );
      expect(browserSteps.length).toBeGreaterThan(0);
      for (const i of browserSteps) expect(i, steps[i]?.name).toBeGreaterThan(install);
    });

    it("has no workflow, local action or package.json script run playwright install", () => {
      const installs = (commands: readonly string[]) =>
        commands.filter((c) => /playwright(-core)?(@\S+)?\s+install|cli\.js\s+install/.test(c));
      for (const file of [...PRIVILEGED, ...UNPRIVILEGED]) {
        const runs = stepsOf(loadWorkflow(file).workflow).map((s) => s.run ?? "");
        expect(installs(runs), file).toEqual([]);
      }
      for (const uses of LOCAL_ACTIONS) {
        expect(installs(loadLocalAction(uses).runs.steps.map((s) => s.run ?? "")), uses).toEqual(
          [],
        );
      }
      // bun runs `pre<name>` / `post<name>` around every script, so every script counts
      const manifests = spawnSync("git", ["ls-files", "--", "*package.json"], {
        cwd: repoRoot,
        encoding: "utf8",
      })
        .stdout.split("\n")
        .filter((f) => f !== "");
      expect(manifests).toContain("apps/web/package.json");
      for (const manifest of manifests) {
        const { scripts = {} } = JSON.parse(read(manifest)) as { scripts?: Record<string, string> };
        expect(installs(Object.values(scripts)), manifest).toEqual([]);
      }
    });
  });
});
