// Pins the workflows' supply-chain invariants mechanically, so a later edit
// cannot undo one unnoticed. The rule behind them: an executable that runs in
// a workflow comes either from the commit being run or from a fetch verified
// against a digest pinned in that commit, no run reads a store another run
// can write, and a release publishes only what its build job produced.
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
//      no reusable workflow but ci.yml (called with no inputs) — default-deny:
//      actions/cache, and any action with an implicit cache (setup-go,
//      setup-python's `cache`, setup-node v5's package-manager cache), fails
//      here first — with no cache input, and the local actions run shell
//      steps only
//   3. privileged workflows download artifacts from their own run only, and
//      run no job or service container
//   4. Bun comes only from .github/actions/install-bun, whose pinned version
//      is `.bun-version`, and release.yml's publish-npm (the OIDC publish)
//      runs only a pinned Node.js; both check the pinned SHA-256 before
//      unpacking, and unpack before first running anything
//   5. the Bun runtime embedded in each release binary is a release zip
//      pinned in apps/cli/scripts/bun-runtimes.ts at that same version (the
//      linux-x64 pin is install-bun's), and the build cannot fall back to an
//      unpinned download
//   6. release.yml's build job digests each artifact into its job outputs,
//      publish-github checks both artifacts against them before creating the
//      Release, and publish-npm checks the npm package again before anything
//      else, each publishing from the checked directory only
//   7. both publish jobs, and only they, run in the `release` environment,
//      and an unconditional job fails the run before either of them unless
//      that environment requires a reviewer and admits exactly the release
//      tag pattern (GitHub creates a missing environment unprotected)
//   8. the publish path cannot be skipped or soft-fail: the publish jobs'
//      `if:`, step sequences, and every check and publish command are pinned
//      byte for byte, with no `if:`, continue-on-error or custom shell on
//      their steps, no `defaults` or extra `env` (BASH_ENV, GH_HOST) above
//      them, smoke's soft-fail limited to the keychain probe, and artifacts
//      kept as long as a re-run can wait for its approval
//   9. ci.yml's browser is the Chrome Headless Shell version the pinned
//      Playwright expects (bun.lock resolves one Playwright), downloaded and
//      checked against a pinned SHA-256 before it is unpacked. Any other
//      Playwright browser download fails: ci.yml points PLAYWRIGHT_DOWNLOAD_HOST
//      at an unresolvable host and nothing else sets a PLAYWRIGHT_ variable,
//      and no workflow, local action or package.json script (`pre`/`post`
//      hooks included) runs `playwright install` in any spelling
// YAML is parsed by `Bun.YAML` in a subprocess (vitest runs on Node), the
// same way as apps/site/test/unit/workflows.test.ts.

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
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
  readonly "continue-on-error"?: unknown;
  readonly shell?: string;
  readonly run?: string;
}
interface Job {
  readonly uses?: string;
  readonly needs?: string | readonly string[];
  readonly outputs?: Readonly<Record<string, string>>;
  readonly if?: string;
  readonly "continue-on-error"?: unknown;
  readonly environment?: string | { readonly name: string };
  readonly defaults?: unknown;
  readonly env?: Readonly<Record<string, unknown>>;
  readonly container?: unknown;
  readonly services?: unknown;
  readonly with?: Readonly<Record<string, unknown>>;
  readonly permissions?: unknown;
  readonly steps?: readonly Step[];
}
interface Workflow {
  readonly on: Readonly<Record<string, unknown>>;
  readonly permissions?: unknown;
  readonly defaults?: unknown;
  readonly env?: Readonly<Record<string, unknown>>;
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

/** Every PLAYWRIGHT_ variable a workflow sets in an env block or names in a step's script. */
function playwrightSettings(file: string): string[] {
  const { env, jobs } = loadWorkflow(file).workflow;
  const keys = (block: Readonly<Record<string, unknown>> | undefined, where: string) =>
    Object.keys(block ?? {})
      .filter((key) => key.startsWith("PLAYWRIGHT_"))
      .map((key) => `${file} ${where}: ${key}`);
  return [
    ...keys(env, "env"),
    ...Object.entries(jobs).flatMap(([name, job]) => [
      ...keys(job.env, `${name} env`),
      ...(job.steps ?? []).flatMap((step) => {
        const where = `${name} ${step.name ?? step.uses}`;
        const named = step.run?.match(/PLAYWRIGHT_\w+/g) ?? [];
        return [
          ...keys(step.env, `${where} env`),
          ...named.map((key) => `${file} ${where} run: ${key}`),
        ];
      }),
    ]),
  ];
}

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

describe("No workflow restores an Actions cache or runs an unpinned download", () => {
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
      // ... and nothing overrides it (a PLAYWRIGHT_<browser>_DOWNLOAD_HOST would win over it): the
      // only other PLAYWRIGHT_ variable is the verified executable path the install step exports
      expect([...PRIVILEGED, ...UNPRIVILEGED].flatMap(playwrightSettings)).toEqual([
        "ci.yml env: PLAYWRIGHT_DOWNLOAD_HOST",
        `ci.yml check ${step?.name} run: PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH`,
      ]);
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

/** The one digest function: every non-directory entry's path and SHA-256, C-sorted. */
const DIGEST =
  "digest() { (cd \"$1\" && find . ! -type d -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum --) | sha256sum | cut -d ' ' -f 1; }";

/** The build job's digest step, byte for byte. */
const DIGEST_RUN = [
  "set -euo pipefail",
  DIGEST,
  "binaries=$(digest apps/cli/dist)",
  "npm_package=$(digest apps/cli/dist-npm)",
  'echo "binaries=${binaries}" >> "$GITHUB_OUTPUT"',
  'echo "npm-package=${npm_package}" >> "$GITHUB_OUTPUT"',
  "",
].join("\n");

/** Every publish job's check of a downloaded artifact, byte for byte. */
const VERIFY_RUN = [
  "set -euo pipefail",
  DIGEST,
  "actual=$(digest .)",
  'if ! [[ "${EXPECTED_DIGEST}" =~ ^[0-9a-f]{64}$ ]] || [ "${actual}" != "${EXPECTED_DIGEST}" ]; then',
  '  echo "::error::the downloaded artifact (digest ${actual}) is not the one the build job produced (${EXPECTED_DIGEST:-no digest})"',
  "  exit 1",
  "fi",
  "",
].join("\n");

/** The Release upload: exactly the five archives and checksums.txt. */
const RELEASE_RUN = [
  "FLAGS=(--generate-notes --verify-tag)",
  'if [ "${PRERELEASE}" = "true" ]; then',
  "  FLAGS+=(--prerelease)",
  "fi",
  'gh release create "${GITHUB_REF_NAME}" \\',
  '  --repo "${GITHUB_REPOSITORY}" \\',
  '  "${FLAGS[@]}" \\',
  "  maruhi-*.tar.gz checksums.txt",
  "",
].join("\n");

/** release-environment's fail-closed read of the environment's protection. */
const ENVIRONMENT_CHECK_RUN = [
  "set -euo pipefail",
  'api="repos/${GITHUB_REPOSITORY}/environments/${ENVIRONMENT}"',
  'if ! config=$(gh api "${api}"); then',
  '  echo "::error::cannot read the ${ENVIRONMENT} environment; create it as docs/RELEASING.md describes"',
  "  exit 1",
  "fi",
  'reviewers=$(jq \'[.protection_rules[] | select(.type == "required_reviewers") | .reviewers[]] | length\' <<< "${config}")',
  'if [ "${reviewers}" -lt 1 ]; then',
  '  echo "::error::the ${ENVIRONMENT} environment has no required reviewer (docs/RELEASING.md)"',
  "  exit 1",
  "fi",
  'if [ "$(jq \'.deployment_branch_policy.custom_branch_policies\' <<< "${config}")" != "true" ]; then',
  '  echo "::error::the ${ENVIRONMENT} environment must admit selected tags only (docs/RELEASING.md)"',
  "  exit 1",
  "fi",
  'policies=$(gh api --paginate "${api}/deployment-branch-policies" --jq \'.branch_policies[] | "\\(.type) \\(.name)"\')',
  'if [ "${policies}" != "tag ${TAG_PATTERN}" ]; then',
  "  echo \"::error::the ${ENVIRONMENT} environment must admit exactly the tag pattern ${TAG_PATTERN} (got: ${policies//$'\\n'/, })\"",
  "  exit 1",
  "fi",
  'echo "${ENVIRONMENT}: ${reviewers} required reviewer(s), tags ${TAG_PATTERN} only"',
  "",
].join("\n");

/** publish-npm's dry run, lifecycle scripts off. */
const DRY_RUN_RUN = [
  "set +e",
  'OUT=$(npm publish ./dist-npm --dry-run --ignore-scripts --tag "${DIST_TAG}" 2>&1)',
  "CODE=$?",
  "set -e",
  'echo "${OUT}"',
  'if [ "${CODE}" != "0" ]; then',
  '  echo "::error::npm publish --dry-run itself failed (exit ${CODE})"',
  "  exit 1",
  "fi",
  'if echo "${OUT}" | grep -q "auto-corrected"; then',
  '  echo "::error::npm auto-corrected the manifest at publish time (bin etc. may be stripped; check the npm pkg fix diff)"',
  "  exit 1",
  "fi",
  "",
].join("\n");

const PUBLISH_IF = "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')";
const RELEASE_TAGS = "v[0-9]*";
const RELEASE_ENVIRONMENT = "release";

/** No condition and no continue-on-error: a failure here stops what depends on it. */
function expectUnconditional(item: Step | Job | undefined, where: string): void {
  expect(item, where).toBeDefined();
  expect(item?.if, `${where} has an if:`).toBeUndefined();
  expect(item?.["continue-on-error"], `${where} has continue-on-error`).toBeUndefined();
  // A custom shell (`shell: "true {0}"`) would skip the script and still pass
  expect((item as Step | undefined)?.shell, `${where} sets a shell`).toBeUndefined();
}

const needsOf = (job: Job | undefined) =>
  typeof job?.needs === "string" ? [job.needs] : [...(job?.needs ?? [])];
const environmentOf = (job: Job | undefined) =>
  typeof job?.environment === "string" ? job.environment : job?.environment?.name;
/** Jobs that can publish: any write permission or the OIDC token. */
const canPublish = ({ permissions }: Job) =>
  typeof permissions === "string"
    ? permissions === "write-all"
    : Object.values((permissions ?? {}) as Record<string, unknown>).includes("write");
const stepKey = (step: Step) => step.name ?? step.uses?.replace(/@.*/, "");

describe("release.yml publishes only what its build job produced", () => {
  const { workflow } = loadWorkflow("release.yml");
  const build = workflow.jobs["build"];
  const buildSteps = build?.steps ?? [];
  const github = workflow.jobs["publish-github"]?.steps ?? [];
  const npm = workflow.jobs["publish-npm"]?.steps ?? [];

  /** `steps[at]` downloads `artifact` into `path`, and the next step checks it there. */
  function expectVerifiedDownload(
    steps: readonly Step[],
    at: number,
    artifact: string,
    path: string,
  ) {
    const [download, verify] = [steps[at], steps[at + 1]];
    expect(download?.uses).toMatch(/^actions\/download-artifact@/);
    expect(download?.with).toEqual({ name: artifact, path });
    expect(verify?.name).toBe("Verify the artifact is the build job's");
    expect(verify?.["working-directory"]).toBe(path);
    expect(verify?.env).toEqual({
      EXPECTED_DIGEST: `\${{ needs.build.outputs.${artifact}-digest }}`,
    });
    expect(verify?.run).toBe(VERIFY_RUN);
  }

  it("digests each uploaded artifact after it is built and before it is uploaded", () => {
    const digests = buildSteps.findIndex((s) => s.id === "digests");
    expect(buildSteps[digests]?.run).toBe(DIGEST_RUN);
    expectUnconditional(buildSteps[digests], "the digest step");
    const lastBuild = buildSteps.findLastIndex((s) => /\bbuild:(binaries|npm)\b/.test(s.run ?? ""));
    expect(lastBuild).toBeGreaterThan(-1);
    expect(digests).toBe(lastBuild + 1);
    const uploads = buildSteps.slice(digests + 1);
    expect(
      uploads.map((s) => [s.uses?.replace(/@.*/, ""), s.with?.["name"], s.with?.["path"]]),
    ).toEqual([
      ["actions/upload-artifact", "binaries", "apps/cli/dist/"],
      ["actions/upload-artifact", "npm-package", "apps/cli/dist-npm/"],
    ]);
    expect(build?.outputs).toMatchObject({
      "binaries-digest": "${{ steps.digests.outputs.binaries }}",
      "npm-package-digest": "${{ steps.digests.outputs.npm-package }}",
    });
  });

  it("checks both artifacts in publish-github, then releases exactly the checked files", () => {
    expect(github.map(stepKey)).toEqual([
      "actions/download-artifact",
      "Verify the artifact is the build job's",
      "actions/download-artifact",
      "Verify the artifact is the build job's",
      "Verify checksums",
      "Create GitHub Release",
    ]);
    expectVerifiedDownload(github, 0, "binaries", "binaries");
    expectVerifiedDownload(github, 2, "npm-package", "npm-package");
    expect(github[4]?.["working-directory"]).toBe("binaries");
    expect(github[4]?.run).toBe("sha256sum -c checksums.txt");
    expect(github[5]?.["working-directory"]).toBe("binaries");
    expect(github[5]?.run).toBe(RELEASE_RUN);
  });

  it("checks the npm package in publish-npm, and only pinned steps touch it afterwards", () => {
    expect(npm.map(stepKey)).toEqual([
      "actions/download-artifact",
      "Verify the artifact is the build job's",
      "Install Node.js (pinned SHA-256, no cache)",
      "Ensure npm >= 11.5.1",
      "Restore executable bit (lost in artifact roundtrip)",
      "Reject npm-side manifest auto-correction (dry-run)",
      "Publish to npm (provenance)",
    ]);
    expectVerifiedDownload(npm, 0, "npm-package", "dist-npm");
    expect(npm.slice(2, 4).filter((s) => /dist-npm/.test(JSON.stringify(s)))).toEqual([]);
    expect(npm[4]?.run).toBe("chmod +x ./dist-npm/bin.js");
    expect(npm[5]?.run).toBe(DRY_RUN_RUN);
    expect(npm[6]?.run).toBe(
      'npm publish ./dist-npm --ignore-scripts --provenance --tag "${DIST_TAG}"',
    );
  });

  it("lets no step or gating job of the publish path be skipped or soft-fail", () => {
    for (const name of ["publish-github", "publish-npm"]) {
      const job = workflow.jobs[name];
      expect(job?.if, name).toBe(PUBLISH_IF);
      expect(job?.["continue-on-error"], name).toBeUndefined();
      for (const step of job?.steps ?? []) expectUnconditional(step, `${name}: ${stepKey(step)}`);
    }
    expect(needsOf(workflow.jobs["publish-github"]).toSorted()).toEqual([
      "build",
      "release-environment",
      "smoke",
      "verify",
      "version-check",
    ]);
    expect(needsOf(workflow.jobs["publish-npm"])).toContain("publish-github");
    for (const name of ["version-check", "build", "smoke", "release-environment"]) {
      expect(workflow.jobs[name]?.["continue-on-error"], name).toBeUndefined();
    }
  });

  it("lets nothing reshape the shell those steps run in", () => {
    // defaults.run.shell or BASH_ENV (sourced before every bash step) at any level would run
    // before or instead of the pinned scripts, and GH_HOST would point the environment check
    // at another server
    expect(workflow.defaults).toBeUndefined();
    expect(workflow.env).toEqual({
      DO_NOT_TRACK: "1",
      WRANGLER_SEND_METRICS: "false",
      CF_SEND_TELEMETRY: "false",
    });
    for (const name of ["build", "release-environment", "publish-github", "publish-npm"]) {
      expect(workflow.jobs[name]?.defaults, name).toBeUndefined();
      expect(workflow.jobs[name]?.env, name).toBeUndefined();
    }
    expect(buildSteps.find((s) => s.id === "digests")?.env).toBeUndefined();
    const dist = { DIST_TAG: expect.stringMatching(/^\$\{\{ .* \}\}$/) };
    expect(github.slice(4).map((s) => s.env)).toEqual([
      undefined,
      {
        GH_TOKEN: "${{ github.token }}",
        PRERELEASE: "${{ needs.version-check.outputs.prerelease }}",
      },
    ]);
    expect(npm.slice(2).map((s) => Object.keys(s.env ?? {}))).toEqual([
      ["NODE_VERSION", "NODE_LINUX_X64_TARGZ_SHA256"],
      [],
      [],
      ["DIST_TAG"],
      ["DIST_TAG"],
    ]);
    expect(npm[5]?.env).toEqual(dist);
    expect(npm[6]?.env).toEqual(dist);
  });

  it("smokes every target with only the keychain probe allowed to soft-fail", () => {
    const smoke = workflow.jobs["smoke"]?.steps ?? [];
    expect(smoke.map(stepKey)).toEqual([
      "actions/download-artifact",
      "Launch check (--version / --help)",
      "Keychain probe (typed failure expected)",
    ]);
    expect(smoke.map((s) => s["continue-on-error"])).toEqual([undefined, undefined, true]);
    expect(smoke.map((s) => s.if)).toEqual([undefined, undefined, undefined]);
  });

  it("keeps the artifacts as long as a re-run can still wait for its approval", () => {
    // A re-run may start 30 days after the run and then wait 30 days for an approval
    const uploads = buildSteps.filter((s) => s.uses?.startsWith("actions/upload-artifact@"));
    expect(uploads.map((s) => s.with?.["retention-days"])).toEqual([60, 60]);
  });
});

describe("release.yml publishes nothing before a reviewer approves", () => {
  const { workflow } = loadWorkflow("release.yml");
  const jobs = Object.entries(workflow.jobs);
  const check = workflow.jobs["release-environment"];

  it("runs every job that can publish, and only those, in the release environment", () => {
    const publishers = jobs.filter(([, job]) => canPublish(job)).map(([name]) => name);
    expect(publishers.toSorted()).toEqual(["publish-github", "publish-npm"]);
    const gated = jobs.filter(([, job]) => job.environment !== undefined);
    expect(gated.map(([name]) => name).toSorted()).toEqual(publishers.toSorted());
    for (const name of publishers)
      expect(environmentOf(workflow.jobs[name])).toBe(RELEASE_ENVIRONMENT);
    const oidc = jobs.filter(
      ([, job]) =>
        (job.permissions as Record<string, unknown> | undefined)?.["id-token"] === "write",
    );
    expect(oidc.map(([name]) => name)).toEqual(["publish-npm"]);
  });

  it("checks that environment's protection, failing closed, before either publish job", () => {
    expectUnconditional(check, "release-environment");
    expect(check?.permissions).toEqual({ actions: "read" });
    expect(check?.steps).toHaveLength(1);
    const step = check?.steps?.[0];
    expectUnconditional(step, "the environment check");
    expect(step?.uses).toBeUndefined();
    expect(step?.env).toEqual({
      GH_TOKEN: "${{ github.token }}",
      ENVIRONMENT: RELEASE_ENVIRONMENT,
      TAG_PATTERN: RELEASE_TAGS,
    });
    expect(step?.run).toBe(ENVIRONMENT_CHECK_RUN);
  });

  it("triggers on exactly the tag pattern the environment admits", () => {
    expect((workflow.on["push"] as { tags: readonly string[] }).tags).toEqual([RELEASE_TAGS]);
  });
});
