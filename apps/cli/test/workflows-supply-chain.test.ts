import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vite-plus/test";

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
  readonly background?: boolean;
  readonly parallel?: readonly Step[];
  readonly wait?: string | readonly string[];
  readonly "wait-all"?: unknown;
  readonly cancel?: string;
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
  readonly "timeout-minutes"?: unknown;
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

const PRIVILEGED = ["ops-backup.yml", "pullfrog.yml", "release.yml"];
const UNPRIVILEGED = ["ci.yml", "english-pr.yml", "installer.yml"];

const INSTALL_BUN = "./.github/actions/install-bun";
const LOCAL_ACTIONS = [INSTALL_BUN, "./actions/setup-maruhi"];
const loadLocalAction = (uses: string) =>
  parseYaml(read(`${uses.slice(2)}/action.yml`)) as { runs: { using: string; steps: Step[] } };

const NO_CACHE_ACTIONS = [
  "actions/checkout",
  "actions/upload-artifact",
  "actions/download-artifact",
];
const REVIEWED_ACTIONS = ["pullfrog/pullfrog@0657d542f2e34565c6254d5c84581313e631cd90"];

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

function expectVerifiedBeforeRun(run: string, unpack: string, firstRun: string): void {
  const verify = run.indexOf("sha256sum --check --strict");
  expect(verify, "checks the SHA-256").toBeGreaterThan(-1);
  expect(run.indexOf(unpack), `${unpack} after the check`).toBeGreaterThan(verify);
  expect(run.indexOf(firstRun), `${firstRun} after ${unpack}`).toBeGreaterThan(run.indexOf(unpack));
}

const flattenStep = (step: Step): readonly Step[] => step.parallel ?? [step];

const stepsOf = (workflow: Workflow): Step[] =>
  Object.values(workflow.jobs).flatMap((job) => (job.steps ?? []).flatMap(flattenStep));

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
      ...(job.steps ?? []).flatMap(flattenStep).flatMap((step) => {
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
      expect(scriptPin("BUN_VERSION")).toBe(BUN_RUNTIME_VERSION);
      expect(BUN_RUNTIMES["bun-linux-x64"].sha256).toBe(scriptPin("BUN_LINUX_X64_ZIP_SHA256"));
    });

    it("compiles every target with a pinned runtime and no fallback download", () => {
      const script = read("apps/cli/scripts/build-binaries.ts");
      expect(script).toContain("`--compile-executable-path=${executable}`");
      expect(script).toContain("downloadVerified(runtimeUrl(runtime), runtime.sha256)");
      expect(script).toContain("HTTPS_PROXY: unreachable,");
      expect(script).toContain('BUN_INSTALL_CACHE_DIR: join(runtimesDir, "install-cache"),');
      expect(script).toMatch(/run\(\s*"bun",\s*\[[^\]]*\],\s*cliRoot,\s*compileEnv,\s*\)/);
      expect(script.match(/"--compile"/g)).toHaveLength(1);
    });

    it("compiles every binary in strict mode, without the working directory's .env files and bunfig.toml, proven by a probe on the host's target", () => {
      const script = read("apps/cli/scripts/build-binaries.ts");
      expect(script).toContain(
        'const COMPILE_EXEC_ARGV = "--disallow-code-generation-from-strings=strict";',
      );
      expect(script).toContain("`--compile-exec-argv=${COMPILE_EXEC_ARGV}`");
      expect(script).toContain('"--no-compile-autoload-dotenv",');
      expect(script).toContain('"--no-compile-autoload-bunfig",');
      expect(script).toContain("compile(target, executable, probeEntry, probe);");
      expect(script).toContain(
        'compile(target, executable, "src/bin.ts", join(workDir, target.bin));',
      );
      expect(script).toContain(
        'await writeFile(join(probeDir, ".env"), "MARUHI_STRICT_PROBE_DOTENV=read\\n");',
      );
      expect(script).toContain(
        "if (process.env.MARUHI_STRICT_PROBE_DOTENV !== undefined) process.exit(1);",
      );
      expect(script).toContain(
        `await writeFile(join(probeDir, "bunfig.toml"), 'preload = ["./preload.ts"]\\n');`,
      );
      expect(script).toContain(
        'await writeFile(join(probeDir, "preload.ts"), "process.exit(1);\\n");',
      );
      expect(script).toContain(
        '([name]) => !name.toUpperCase().startsWith("BUN_") && name !== "MARUHI_STRICT_PROBE_DOTENV",',
      );
      expect(script).toContain("run(probe, [], probeDir, probeEnv);");
      expect(script).toContain("if (error instanceof EvalError) process.exit(0);");
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
    const steps = loadWorkflow("ci.yml").workflow.jobs["e2e"]?.steps ?? [];
    const install = steps.findIndex(
      (s) => s.name === "Install Chrome Headless Shell (pinned SHA-256, no cache)",
    );
    const step = steps[install];
    const script = read("scripts/install-headless-shell.sh");
    const scriptPin = (name: string) => new RegExp(`^${name}="([^"]*)"$`, "m").exec(script)?.[1];
    const webPin = (
      JSON.parse(read("apps/web/package.json")) as { devDependencies: Record<string, string> }
    ).devDependencies["playwright"];

    it("pins the headless-shell version the pinned Playwright expects, with a SHA-256", () => {
      const sitePin = (
        JSON.parse(read("apps/site/package.json")) as { devDependencies: Record<string, string> }
      ).devDependencies["playwright"];
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
        scriptPin("CHROME_HEADLESS_SHELL_VERSION"),
        `playwright ${core.version} expects headless shell ${expected}: update the version and SHA-256 in scripts/install-headless-shell.sh together (procedure in the script)`,
      ).toBe(expected);
      expect(scriptPin("CHROME_HEADLESS_SHELL_LINUX64_ZIP_SHA256")).toMatch(/^[0-9a-f]{64}$/);
    });

    it("installs only through the script, which holds the one pin, and exports what it printed", () => {
      expect(install).toBeGreaterThan(-1);
      expect(step?.run).toBe(
        [
          "set -euo pipefail",
          'if ! executable="$(bash scripts/install-headless-shell.sh)"; then',
          "  exit 1",
          "fi",
          'echo "PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=${executable}" >> "${GITHUB_ENV}"',
          "",
        ].join("\n"),
      );
      expect(Object.keys(step ?? {}).toSorted()).toEqual([
        "background",
        "id",
        "name",
        "run",
        "timeout-minutes",
      ]);
      expect(step?.id).toBe("headless-shell");
      expect(step?.background).toBe(true);
      expect(read(`${WORKFLOWS_DIR}/ci.yml`)).not.toMatch(/[0-9a-f]{64}|CHROME_HEADLESS_SHELL_/);
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
      expect(script).toContain(
        "https://storage.googleapis.com/chrome-for-testing-public/${CHROME_HEADLESS_SHELL_VERSION}/linux64/${tree}.zip",
      );
      expect(script).toContain("--proto '=https' --proto-redir '=https'");
      expectVerifiedBeforeRun(
        script,
        "unzip ",
        'echo "${install_root}/${tree}/chrome-headless-shell"',
      );
      const lines = script.split("\n");
      const check = lines.indexOf(
        'if ! echo "${CHROME_HEADLESS_SHELL_LINUX64_ZIP_SHA256}  ${zip}" | sha256sum --check --strict >&2; then',
      );
      expect(check).toBeGreaterThan(-1);
      expect(lines.slice(check + 1, check + 3)).toEqual([
        '  die "${tree}.zip does not match the pinned SHA-256; nothing was installed"',
        "fi",
      ]);
      expect(script).toMatch(/^die\(\) \{\n(?:  .*\n)*  exit 1\n\}$/m);
      let depth = 0;
      for (const line of lines.slice(0, check)) {
        if (/^\s*(if|case|for|while|until)\b|[{(]\s*$/.test(line)) depth += 1;
        if (/^\s*(fi|esac|done|\}|\))(\s|;|$)/.test(line)) depth -= 1;
      }
      expect(depth, "the check is not nested in a block").toBe(0);
    });

    it("sends every other Playwright browser download to an unresolvable host", () => {
      const { workflow } = loadWorkflow("ci.yml");
      expect(workflow.env?.["PLAYWRIGHT_DOWNLOAD_HOST"]).toBe(
        "https://playwright-download.invalid",
      );
      expect([...PRIVILEGED, ...UNPRIVILEGED].flatMap(playwrightSettings)).toEqual([
        "ci.yml env: PLAYWRIGHT_DOWNLOAD_HOST",
        `ci.yml e2e ${step?.name} run: PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH`,
      ]);
    });

    it("gates every browser step behind a wait on the background install", () => {
      const waitForInstall = steps.findIndex((s) => {
        const waits = typeof s.wait === "string" ? [s.wait] : (s.wait ?? []);
        return waits.includes(step?.id ?? "");
      });
      expect(waitForInstall, "a wait step names the install's id").toBeGreaterThan(install);
      const { jobs } = loadWorkflow("ci.yml").workflow;
      let browserSteps = 0;
      for (const [name, job] of Object.entries(jobs)) {
        const indices = (job.steps ?? []).flatMap((s, i) =>
          flattenStep(s).flatMap((m) => (/\be2e\b|test:browser/.test(m.run ?? "") ? [i] : [])),
        );
        browserSteps += indices.length;
        for (const i of indices) {
          expect(name, "browser steps live in the install step's job").toBe("e2e");
          expect(i, job.steps?.[i]?.name ?? name).toBeGreaterThan(waitForInstall);
        }
      }
      expect(browserSteps).toBeGreaterThan(0);
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

const DIGEST =
  "digest() { (cd \"$1\" && find . ! -type d -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum --) | sha256sum | cut -d ' ' -f 1; }";

const DIGEST_RUN = [
  "set -euo pipefail",
  DIGEST,
  "binaries=$(digest apps/cli/dist)",
  "npm_package=$(digest apps/cli/dist-npm)",
  'echo "binaries=${binaries}" >> "$GITHUB_OUTPUT"',
  'echo "npm-package=${npm_package}" >> "$GITHUB_OUTPUT"',
  "",
].join("\n");

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
const RESOLVE_RUN = [
  "VERSION=$(node -p \"require('./apps/cli/package.json').version\")",
  "SEMVER_RE='^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?$'",
  'if ! [[ "${VERSION}" =~ ${SEMVER_RE} ]]; then',
  '  echo "::error::apps/cli/package.json version is not SemVer: ${VERSION}"',
  "  exit 1",
  "fi",
  'if [ "${EVENT_NAME}" = "push" ] && [ "v${VERSION}" != "${GITHUB_REF_NAME}" ]; then',
  '  echo "::error::tag ${GITHUB_REF_NAME} does not match apps/cli/package.json version ${VERSION} (docs/RELEASING.md)"',
  "  exit 1",
  "fi",
  'if [ "${EVENT_NAME}" = "push" ]; then',
  "  if ! git merge-base --is-ancestor HEAD origin/main; then",
  '    echo "::error::tag ${GITHUB_REF_NAME} does not point at a commit on main (docs/RELEASING.md)"',
  "    exit 1",
  "  fi",
  "fi",
  'case "${VERSION}" in',
  "  *-*) PRERELEASE=true ;;",
  "  *) PRERELEASE=false ;;",
  "esac",
  'if [ "${EVENT_NAME}" = "push" ] && [ "${PRERELEASE}" = "false" ]; then',
  '  echo "::error::stable tag ${GITHUB_REF_NAME}: enable the release approval gate first (docs/RELEASING.md, \\"Before the first public release\\")"',
  "  exit 1",
  "fi",
  'echo "version=${VERSION}" >> "$GITHUB_OUTPUT"',
  'echo "prerelease=${PRERELEASE}" >> "$GITHUB_OUTPUT"',
  "",
].join("\n");

function expectUnconditional(item: Step | Job | undefined, where: string): void {
  expect(item, where).toBeDefined();
  expect(item?.if, `${where} has an if:`).toBeUndefined();
  expect(item?.["continue-on-error"], `${where} has continue-on-error`).toBeUndefined();
  expect((item as Step | undefined)?.shell, `${where} sets a shell`).toBeUndefined();
}

const needsOf = (job: Job | undefined) =>
  typeof job?.needs === "string" ? [job.needs] : [...(job?.needs ?? [])];
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
      "smoke",
      "verify",
      "version-check",
    ]);
    expect(needsOf(workflow.jobs["publish-npm"])).toContain("publish-github");
    for (const name of ["version-check", "build", "smoke"]) {
      expect(workflow.jobs[name]?.["continue-on-error"], name).toBeUndefined();
    }
  });

  it("lets nothing reshape the shell those steps run in", () => {
    expect(workflow.defaults).toBeUndefined();
    expect(workflow.env).toEqual({
      DO_NOT_TRACK: "1",
      WRANGLER_SEND_METRICS: "false",
      CF_SEND_TELEMETRY: "false",
    });
    for (const name of ["version-check", "build", "publish-github", "publish-npm"]) {
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

  it("keeps the artifacts as long as a re-run can still wait for an approval", () => {
    const uploads = buildSteps.filter((s) => s.uses?.startsWith("actions/upload-artifact@"));
    expect(uploads.map((s) => s.with?.["retention-days"])).toEqual([60, 60]);
  });
});

describe("release.yml ships no stable release until the approval gate is enabled", () => {
  const { workflow } = loadWorkflow("release.yml");
  const jobs = Object.entries(workflow.jobs);
  const versionCheck = workflow.jobs["version-check"];
  const resolve = versionCheck?.steps?.find((s) => s.id === "resolve");

  it("keeps apps/cli's version a prerelease", () => {
    const { version } = JSON.parse(read("apps/cli/package.json")) as { version: string };
    expect(version, "a stable version needs the release approval gate first").toMatch(
      /^\d+\.\d+\.\d+-/,
    );
  });

  it("refuses a stable tag in version-check, which every other job waits for", () => {
    expectUnconditional(versionCheck, "version-check");
    expectUnconditional(resolve, "version-check's resolve step");
    expect(resolve?.env).toEqual({ EVENT_NAME: "${{ github.event_name }}" });
    expect(resolve?.run).toBe(RESOLVE_RUN);
    for (const name of ["build", "publish-github", "publish-npm"]) {
      expect(needsOf(workflow.jobs[name]), name).toContain("version-check");
    }
  });

  it("runs no job in an environment, and only the two publish jobs can publish", () => {
    expect(jobs.filter(([, job]) => job.environment !== undefined).map(([name]) => name)).toEqual(
      [],
    );
    const publishers = jobs.filter(([, job]) => canPublish(job)).map(([name]) => name);
    expect(publishers.toSorted()).toEqual(["publish-github", "publish-npm"]);
    const oidc = jobs.filter(
      ([, job]) =>
        (job.permissions as Record<string, unknown> | undefined)?.["id-token"] === "write",
    );
    expect(oidc.map(([name]) => name)).toEqual(["publish-npm"]);
  });

  it("triggers on exactly the release tag pattern", () => {
    expect((workflow.on["push"] as { tags: readonly string[] }).tags).toEqual([RELEASE_TAGS]);
  });
});

const MAX_JOB_TIMEOUT_MINUTES = 120;

describe("Every job that runs on a runner is time-bounded", () => {
  it.each([...PRIVILEGED, ...UNPRIVILEGED])(
    "%s bounds every job that runs on a runner with timeout-minutes",
    (file) => {
      const unbounded = Object.entries(loadWorkflow(file).workflow.jobs)
        .filter(([, job]) => job.uses === undefined)
        .filter(([, job]) => {
          const minutes = job["timeout-minutes"];
          return !(
            typeof minutes === "number" &&
            Number.isInteger(minutes) &&
            minutes > 0 &&
            minutes <= MAX_JOB_TIMEOUT_MINUTES
          );
        })
        .map(([name]) => name);
      expect(unbounded).toEqual([]);
    },
  );
});
