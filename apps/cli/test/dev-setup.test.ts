// Pins "Bun and pnpm reach a machine only through a fetch checked against a
// digest pinned in this repository", for every setup path: CI
// (.github/actions/install-bun), the Claude Code on the web SessionStart hook
// (.claude/hooks/session-start.sh) and the Cursor Cloud startup script all
// install Bun through scripts/install-bun.sh, and the hook gets pnpm only
// through corepack's check of the sha512 in .deepsec/package.json.
//
// The script and the hook are run here, offline, against stubs: the script
// against a curl serving a real zip whose `bun` would leave a marker if it ever
// ran, the hook against stub bun / corepack / pnpm / fetchers that log every
// call.

import { spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

const repoRoot = fileURLToPath(new URL("../../../", import.meta.url));
const read = (path: string): string => readFileSync(join(repoRoot, path), "utf8");
const pinned = read(".bun-version").trim();

const scratchDirs: string[] = [];
afterEach(() => {
  for (const dir of scratchDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});
function scratch(): string {
  const dir = mkdtempSync(join(tmpdir(), "dev-setup-"));
  scratchDirs.push(dir);
  return dir;
}

function writeExecutable(path: string, lines: readonly string[]): void {
  writeFileSync(path, [...lines, ""].join("\n"));
  chmodSync(path, 0o755);
}

/** Where a system tool lives, so a stubbed PATH can still reach it. */
function systemTool(name: string): string {
  const found = spawnSync("sh", ["-c", `command -v ${name}`], { encoding: "utf8" });
  expect(found.status, `${name} is needed by this test`).toBe(0);
  return found.stdout.trim();
}

function crc32(data: Buffer): number {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = crc & 1 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1;
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/** A stored (uncompressed) zip whose entries keep the given Unix modes. */
function zipOf(entries: ReadonlyArray<{ name: string; mode: number; data: string }>): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name);
    const data = Buffer.from(entry.data);
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(10, 4);
    local.writeUInt16LE(0x21, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE((3 << 8) | 20, 4);
    central.writeUInt16LE(10, 6);
    central.writeUInt16LE(0x21, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE((entry.mode << 16) >>> 0, 38);
    central.writeUInt32LE(offset, 42);
    locals.push(local, name, data);
    centrals.push(central, name);
    offset += local.length + name.length + data.length;
  }
  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

describe("scripts/install-bun.sh", () => {
  const script = read("scripts/install-bun.sh");
  const assigned = (name: string) => new RegExp(`^${name}="([^"]*)"$`, "m").exec(script)?.[1];

  it("pins the version .bun-version names, with a SHA-256 per build, from the official release", () => {
    expect(assigned("BUN_VERSION")).toBe(pinned);
    expect(assigned("BUN_LINUX_X64_ZIP_SHA256")).toMatch(/^[0-9a-f]{64}$/);
    expect(assigned("BUN_LINUX_X64_BASELINE_ZIP_SHA256")).toMatch(/^[0-9a-f]{64}$/);
    expect(script).toContain(
      "https://github.com/oven-sh/bun/releases/download/bun-v${BUN_VERSION}/bun-${target}.zip",
    );
  });

  it("checks the digest, then unpacks, then runs the unpacked binary", () => {
    const verify = script.indexOf("sha256sum --check --strict");
    const unpack = script.indexOf("unzip ");
    const firstRun = script.indexOf('"${bin_dir}/bun" --revision');
    expect(verify).toBeGreaterThan(-1);
    expect(unpack).toBeGreaterThan(verify);
    expect(firstRun).toBeGreaterThan(unpack);
  });
});

describe(".github/actions/install-bun", () => {
  const action = read(".github/actions/install-bun/action.yml");

  it("is one shell step that runs the script with --require-avx2, holding no pin of its own", () => {
    expect(action).toContain('using: "composite"');
    expect(action).not.toMatch(/^\s*(-\s+)?uses:/m);
    expect(action.match(/^\s*run: \|$/gm)).toHaveLength(1);
    // The whole line, so nothing (`|| true`, another flag) can ride along
    expect(action).toMatch(
      /^ {8}bash "\$\{GITHUB_WORKSPACE\}\/scripts\/install-bun\.sh" --require-avx2$/m,
    );
    expect(action).not.toMatch(/[0-9a-f]{64}/);
  });
});

describe.runIf(process.platform === "linux" && process.arch === "x64")(
  "scripts/install-bun.sh fails closed",
  () => {
    interface Run {
      readonly bunVersion?: string;
      readonly avx2?: boolean;
      readonly args?: readonly string[];
      readonly env?: Readonly<Record<string, string>>;
    }

    /**
     * Runs a copy of the script in a scratch repository. curl serves a real zip holding both
     * builds' `bun`, which creates a marker if it is ever executed; grep answers the AVX2 probe.
     */
    function run({ bunVersion = pinned, avx2 = true, args = [], env = {} }: Run) {
      const root = scratch();
      const [repo, home, bin] = ["repo", "home", "bin"].map((dir) => join(root, dir)) as [
        string,
        string,
        string,
      ];
      for (const dir of [join(repo, "scripts"), home, bin]) mkdirSync(dir, { recursive: true });
      copyFileSync(join(repoRoot, "scripts/install-bun.sh"), join(repo, "scripts/install-bun.sh"));
      writeFileSync(join(repo, ".bun-version"), `${bunVersion}\n`);
      const marker = join(root, "bun-ran");
      const fakeBun = `#!/bin/sh\n: > '${marker}'\necho 0.0.0\n`;
      const zip = join(root, "served.zip");
      writeFileSync(
        zip,
        zipOf(
          ["bun-linux-x64", "bun-linux-x64-baseline"].map((dir) => ({
            name: `${dir}/bun`,
            mode: 0o100755,
            data: fakeBun,
          })),
        ),
      );
      const curlLog = join(root, "curl.log");
      writeExecutable(join(bin, "curl"), [
        "#!/bin/sh",
        `echo "$*" >> '${curlLog}'`,
        `while [ $# -gt 0 ]; do [ "$1" = --output ] && cp '${zip}' "$2"; shift; done`,
      ]);
      writeExecutable(join(bin, "grep"), [
        "#!/bin/sh",
        `case "$*" in *avx2*/proc/cpuinfo*) exit ${avx2 ? 0 : 1} ;; esac`,
        `exec '${systemTool("grep")}' "$@"`,
      ]);
      const result = spawnSync("bash", [join(repo, "scripts/install-bun.sh"), ...args], {
        encoding: "utf8",
        timeout: 30_000,
        env: {
          ...process.env,
          GITHUB_ACTIONS: "",
          ...env,
          HOME: home,
          PATH: `${bin}:${process.env["PATH"] ?? ""}`,
        },
      });
      return {
        result,
        curlCalls: existsSync(curlLog) ? readFileSync(curlLog, "utf8") : "",
        bunRan: existsSync(marker),
        installed: existsSync(join(home, ".bun")),
      };
    }
    const release = `https://github.com/oven-sh/bun/releases/download/bun-v${pinned}`;

    it("refuses a zip that does not match the pinned SHA-256: nothing installed, nothing run", () => {
      const { result, curlCalls, bunRan, installed } = run({});
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("does not match the pinned SHA-256");
      expect(curlCalls).toContain(`${release}/bun-linux-x64.zip`);
      expect(bunRan).toBe(false);
      expect(installed).toBe(false);
    });

    it("takes the baseline build on a CPU without AVX2, checked the same way", () => {
      const { result, curlCalls, bunRan, installed } = run({ avx2: false });
      expect(result.status).toBe(1);
      expect(curlCalls).toContain(`${release}/bun-linux-x64-baseline.zip`);
      expect(bunRan).toBe(false);
      expect(installed).toBe(false);
    });

    it("with --require-avx2 (CI), refuses a CPU without AVX2 before downloading", () => {
      const { result, curlCalls, installed } = run({ avx2: false, args: ["--require-avx2"] });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("--require-avx2 refuses the baseline build");
      expect(curlCalls).toBe("");
      expect(installed).toBe(false);
    });

    it("with --require-avx2 on an AVX2 CPU, fetches the non-baseline build", () => {
      const { curlCalls } = run({ args: ["--require-avx2"] });
      expect(curlCalls).toContain(`${release}/bun-linux-x64.zip`);
      expect(curlCalls).not.toContain("baseline");
    });

    it("refuses a .bun-version it does not pin, and an unknown argument, before downloading", () => {
      for (const options of [{ bunVersion: "0.0.1" }, { args: ["--baseline"] }]) {
        const { result, curlCalls, installed } = run(options);
        expect(result.status).toBe(1);
        expect(result.stderr).toMatch(/\.bun-version is 0\.0\.1 but|unknown argument: --baseline/);
        expect(curlCalls).toBe("");
        expect(installed).toBe(false);
      }
    });

    it("annotates its failures on GitHub Actions", () => {
      const { result } = run({ env: { GITHUB_ACTIONS: "true" } });
      expect(result.stderr).toMatch(/^::error::install-bun: bun-linux-x64\.zip does not match/m);
    });
  },
);

describe("SessionStart hook (.claude/hooks/session-start.sh)", () => {
  const ENV_PATH_LINE = 'export PATH="$HOME/.bun/bin:$PATH"';

  interface Hook {
    /** The version ~/.bun/bin/bun reports, or undefined when it is not installed. */
    readonly bun?: string | undefined;
    readonly installBunExit?: number;
    readonly bunInstallExit?: number;
    /** corepack's exit status, or undefined when it is not on PATH. */
    readonly corepack?: number;
    readonly pnpm?: boolean;
  }

  /**
   * Runs the real hook against a scratch project, on a PATH holding only logging stubs (bun,
   * corepack, pnpm, and the fetchers it must never call) plus the few tools it needs. A call
   * to a tool outside that PATH (an absolute path, or a command after `||` that fails as not
   * found) is not seen: an accepted limit of the stub approach.
   */
  function runHook({ bun, installBunExit = 0, bunInstallExit = 0, corepack, pnpm = false }: Hook) {
    const root = scratch();
    const [project, home, stubs, tools] = ["project", "home", "stubs", "tools"].map((dir) =>
      join(root, dir),
    ) as [string, string, string, string];
    const bunBin = join(home, ".bun/bin");
    for (const dir of [join(project, "scripts"), join(project, ".deepsec"), stubs, tools]) {
      mkdirSync(dir, { recursive: true });
    }
    writeFileSync(join(project, ".bun-version"), `${pinned}\n`);
    writeFileSync(join(project, ".deepsec/package.json"), "{}\n");
    const log = join(root, "calls.log");
    const envFile = join(root, "claude-env");
    writeFileSync(envFile, "");
    const stub = (path: string, name: string, behavior: readonly string[] = []) =>
      writeExecutable(path, [
        "#!/bin/sh",
        `echo "${name} $* @\${PWD##*/}" >> '${log}'`,
        ...behavior,
      ]);
    const bunStub = join(root, "bun-stub");
    stub(bunStub, "bun", [
      `[ "$1" = --version ] && echo ${bun ?? pinned}`,
      `[ "$1" = install ] && exit ${bunInstallExit}`,
      "exit 0",
    ]);
    const installBun = () => {
      mkdirSync(bunBin, { recursive: true });
      copyFileSync(bunStub, join(bunBin, "bun"));
      chmodSync(join(bunBin, "bun"), 0o755);
    };
    if (bun !== undefined) installBun();
    stub(join(project, "scripts/install-bun.sh"), "install-bun.sh", [
      `[ ${installBunExit} -eq 0 ] || exit ${installBunExit}`,
      `mkdir -p '${bunBin}' && cp '${bunStub}' '${bunBin}/bun'`,
    ]);
    for (const fetcher of ["curl", "wget", "npm", "npx", "node", "bunx", "git"]) {
      stub(join(stubs, fetcher), fetcher, ["exit 0"]);
    }
    if (corepack !== undefined) stub(join(stubs, "corepack"), "corepack", [`exit ${corepack}`]);
    if (pnpm) stub(join(stubs, "pnpm"), "pnpm", ["exit 0"]);
    for (const tool of ["bash", "cat", "mkdir", "cp"])
      symlinkSync(systemTool(tool), join(tools, tool));

    const result = spawnSync(
      systemTool("bash"),
      [join(repoRoot, ".claude/hooks/session-start.sh")],
      {
        encoding: "utf8",
        timeout: 30_000,
        env: {
          CLAUDE_CODE_REMOTE: "true",
          CLAUDE_PROJECT_DIR: project,
          CLAUDE_ENV_FILE: envFile,
          HOME: home,
          PATH: `${stubs}:${tools}`,
        },
      },
    );
    const calls = existsSync(log) ? readFileSync(log, "utf8").trim().split("\n") : [];
    return { result, calls, env: readFileSync(envFile, "utf8") };
  }

  const project = "@project";
  const corepackInstall = "corepack pnpm install --frozen-lockfile @.deepsec";

  it("with the pinned Bun present, runs bun install and corepack pnpm, and puts Bun on PATH", () => {
    const { result, calls, env } = runHook({ bun: pinned, corepack: 0 });
    expect(result.status, result.stderr).toBe(0);
    expect(calls).toEqual([`bun --version ${project}`, `bun install ${project}`, corepackInstall]);
    expect(env).toContain(ENV_PATH_LINE);
  });

  it("installs Bun only through scripts/install-bun.sh, when it is missing or another version", () => {
    for (const bun of [undefined, "1.0.0"]) {
      const { result, calls } = runHook({ bun, corepack: 0 });
      expect(result.status, result.stderr).toBe(0);
      expect(calls.filter((call) => !call.startsWith("bun --version"))).toEqual([
        `install-bun.sh  ${project}`,
        `bun install ${project}`,
        corepackInstall,
      ]);
    }
  });

  it("stops when scripts/install-bun.sh fails, before bun install and the session PATH", () => {
    // An older bun stays on disk, so carrying on would still find a `bun` to run
    const { result, calls, env } = runHook({ bun: "1.0.0", installBunExit: 1, corepack: 0 });
    expect(result.status).not.toBe(0);
    expect(calls).toEqual([`bun --version ${project}`, `install-bun.sh  ${project}`]);
    expect(env).toBe("");
  });

  it("keeps Bun on the session PATH when bun install fails", () => {
    const { result, calls, env } = runHook({ bun: pinned, bunInstallExit: 1, corepack: 0 });
    expect(result.status).not.toBe(0);
    expect(calls).toEqual([`bun --version ${project}`, `bun install ${project}`]);
    expect(env).toContain(ENV_PATH_LINE);
  });

  it("does not fall back to pnpm when corepack fails, and the hook still succeeds", () => {
    const { result, calls, env } = runHook({ bun: pinned, corepack: 1, pnpm: true });
    expect(result.status).toBe(0);
    expect(calls).toEqual([`bun --version ${project}`, `bun install ${project}`, corepackInstall]);
    expect(result.stderr).toContain("cd .deepsec && corepack pnpm install --frozen-lockfile");
    expect(env).toContain(ENV_PATH_LINE);
  });

  it("without corepack, runs a preinstalled pnpm with its version switch off", () => {
    const { result, calls } = runHook({ bun: pinned, pnpm: true });
    expect(result.status).toBe(0);
    expect(calls.at(-1)).toBe(
      "pnpm install --frozen-lockfile --config.manage-package-manager-versions=false @.deepsec",
    );
  });

  it("with neither corepack nor pnpm, fetches no pnpm and reports the skipped install", () => {
    const { result, calls } = runHook({ bun: pinned });
    expect(result.status).toBe(0);
    expect(calls).toEqual([`bun --version ${project}`, `bun install ${project}`]);
    expect(result.stderr).toContain(".deepsec install failed");
  });
});

describe(".deepsec pnpm pin", () => {
  it("pins pnpm with the sha512 corepack checks", () => {
    const manifest = JSON.parse(read(".deepsec/package.json")) as { packageManager?: string };
    expect(manifest.packageManager).toMatch(/^pnpm@\d+\.\d+\.\d+\+sha512\.[0-9a-f]{128}$/);
  });

  it("turns off pnpm's unverified switch to the packageManager version", () => {
    expect(read(".deepsec/pnpm-workspace.yaml")).toMatch(/^managePackageManagerVersions: false$/m);
  });
});
