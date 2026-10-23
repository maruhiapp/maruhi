// Builds the 5 compiled release binaries and checksums.txt into dist/.
// Both the release workflow (.github/workflows/release.yml) and local
// verification call this, keeping the target list, archive format, and
// checksum format defined in one place.
//
// Output (apps/cli/dist/):
//   maruhi-<target>.tar.gz × 5 (one binary each; the `mh` alias is not bundled —
//   the installer creates the link. ADR-0015)
//   checksums.txt (`sha256sum -c` compatible: "<64-hex><space><space><filename>")
//
// The Bun runtime inside each binary is the official release zip verified
// against the SHA-256 pinned in bun-runtimes.ts, for every target including
// the host one.

import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, extname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { BUN_RUNTIME_VERSION, BUN_RUNTIMES, downloadVerified, runtimeUrl } from "./bun-runtimes.ts";
import { run, TARGETS } from "./shared.ts";

const cliRoot = fileURLToPath(new URL("..", import.meta.url));
const distDir = join(cliRoot, "dist");

// The running bun bundles the code that goes next to the pinned runtime
if (process.versions.bun !== BUN_RUNTIME_VERSION) {
  throw new Error(
    `running bun ${process.versions.bun}, but bun-runtimes.ts pins the ${BUN_RUNTIME_VERSION} runtimes`,
  );
}

// The strict-mode probe below runs on this host, so the host has to be a
// release target. Checked before dist/ is cleared or anything is downloaded
const hostTarget = `bun-${process.platform === "win32" ? "windows" : process.platform}-${process.arch}`;
if (!TARGETS.some((target) => target.bunTarget === hostTarget)) {
  throw new Error(
    `${hostTarget} is not a release target, so the strict-mode probe cannot run here`,
  );
}

await rm(distDir, { recursive: true, force: true });
await mkdir(distDir, { recursive: true });

const runtimesDir = await mkdtemp(join(tmpdir(), "maruhi-bun-runtimes-"));
// bun silently ignores an unknown flag, so a renamed --compile-executable-path
// would fall back to fetching the runtime from npm. An empty install cache
// and an unreachable proxy turn that fallback into a failed build
const unreachable = "http://127.0.0.1:9";
const compileEnv = {
  ...process.env,
  BUN_INSTALL_CACHE_DIR: join(runtimesDir, "install-cache"),
  HTTPS_PROXY: unreachable,
  https_proxy: unreachable,
  HTTP_PROXY: unreachable,
  http_proxy: unreachable,
  NO_PROXY: "",
  no_proxy: "",
};

// Each binary runs only the code compiled into it: eval(), new Function(),
// node:vm, import() of JavaScript from a data: URL, and JavaScript or
// TypeScript files on disk, including a --preload in BUN_OPTIONS, throw
// EvalError (JSON, TOML and YAML files still load). BUN_OPTIONS can raise
// this level but not lower it. The exception is BUN_BE_BUN=1 in the process
// environment, which makes any Bun executable act as the bun CLI, without
// this flag
const COMPILE_EXEC_ARGV = "--disallow-code-generation-from-strings=strict";

// The one `bun build --compile` call, so the probe below is compiled exactly
// like the release binaries. By default a compiled executable reads the
// bunfig.toml of the directory it runs in, and a strict one exits with
// EvalError when that file has a preload, so --no-compile-autoload-bunfig
// turns the reading off
const compile = (
  target: (typeof TARGETS)[number],
  executable: string,
  entry: string,
  outfile: string,
): void => {
  run(
    "bun",
    [
      "build",
      "--compile",
      `--target=${target.bunTarget}`,
      `--compile-executable-path=${executable}`,
      `--compile-exec-argv=${COMPILE_EXEC_ARGV}`,
      "--no-compile-autoload-bunfig",
      entry,
      "--outfile",
      outfile,
    ],
    cliRoot,
    compileEnv,
  );
};

// bun also ignores a misspelled flag, which would ship binaries that still
// run code from strings or read the working directory's bunfig.toml. So
// before the host's own target is built, a probe compiled for it runs in a
// directory whose bunfig.toml preloads a file that exits 1. The probe exits 0
// only when that file is not read and new Function throws
const STRICT_PROBE = `try {
  new Function("");
} catch (error) {
  if (error instanceof EvalError) process.exit(0);
}
process.exit(1);
`;
// The probe runs without this environment's BUN_* variables: BUN_OPTIONS
// could switch strict mode on by itself, and BUN_BE_BUN would run the bun CLI
// instead of the probe (its help exits 0)
const probeEnv = Object.fromEntries(
  Object.entries(process.env).filter(([name]) => !name.toUpperCase().startsWith("BUN_")),
);

const checksumLines: string[] = [];
try {
  for (const target of TARGETS) {
    const runtime = BUN_RUNTIMES[target.bunTarget];
    const zipPath = join(runtimesDir, runtime.zip);
    await writeFile(zipPath, await downloadVerified(runtimeUrl(runtime), runtime.sha256));
    const runtimeDir = join(runtimesDir, target.name);
    run("unzip", ["-q", "-j", zipPath, runtime.member, "-d", runtimeDir], cliRoot);
    const executable = join(runtimeDir, basename(runtime.member));

    if (target.bunTarget === hostTarget) {
      const probeDir = join(runtimesDir, "strict-probe");
      await mkdir(probeDir);
      await writeFile(join(probeDir, "bunfig.toml"), 'preload = ["./preload.ts"]\n');
      await writeFile(join(probeDir, "preload.ts"), "process.exit(1);\n");
      const probeEntry = join(probeDir, "probe.ts");
      const probe = join(probeDir, `probe${extname(target.bin)}`);
      await writeFile(probeEntry, STRICT_PROBE);
      compile(target, executable, probeEntry, probe);
      try {
        run(probe, [], probeDir, probeEnv);
      } catch (error) {
        throw new Error(
          `the strict-mode probe failed on ${target.name} (it exits 1 when new Function runs or its directory's bunfig.toml is read)`,
          { cause: error },
        );
      }
    }

    const workDir = join(distDir, target.name);
    await mkdir(workDir, { recursive: true });
    compile(target, executable, "src/bin.ts", join(workDir, target.bin));

    const archiveName = `maruhi-${target.name}.tar.gz`;
    // Windows uses tar.gz too (the stock tar on Windows 10+ can extract it).
    // If a distribution path that needs zip appears (scoop etc.), revisit the
    // whole release workflow
    run("tar", ["-czf", join(distDir, archiveName), "-C", workDir, target.bin], cliRoot);
    await rm(workDir, { recursive: true, force: true });

    const archive = await readFile(join(distDir, archiveName));
    const hex = createHash("sha256").update(archive).digest("hex");
    checksumLines.push(`${hex}  ${archiveName}`);
    console.log(`${archiveName}: ${(archive.byteLength / 1024 / 1024).toFixed(1)} MB`);
  }
} finally {
  await rm(runtimesDir, { recursive: true, force: true });
}

await writeFile(join(distDir, "checksums.txt"), `${checksumLines.join("\n")}\n`);
console.log(`checksums.txt: ${checksumLines.length} entries (sha256sum -c compatible)`);
