import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, extname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { BUN_RUNTIME_VERSION, BUN_RUNTIMES, downloadVerified, runtimeUrl } from "./bun-runtimes.ts";
import { run, TARGETS } from "./shared.ts";

const cliRoot = fileURLToPath(new URL("..", import.meta.url));
const distDir = join(cliRoot, "dist");

if (process.versions.bun !== BUN_RUNTIME_VERSION) {
  throw new Error(
    `running bun ${process.versions.bun}, but bun-runtimes.ts pins the ${BUN_RUNTIME_VERSION} runtimes`,
  );
}

const hostTarget = `bun-${process.platform === "win32" ? "windows" : process.platform}-${process.arch}`;
if (!TARGETS.some((target) => target.bunTarget === hostTarget)) {
  throw new Error(
    `${hostTarget} is not a release target, so the strict-mode probe cannot run here`,
  );
}

await rm(distDir, { recursive: true, force: true });
await mkdir(distDir, { recursive: true });

const runtimesDir = await mkdtemp(join(tmpdir(), "maruhi-bun-runtimes-"));
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

const COMPILE_EXEC_ARGV = "--disallow-code-generation-from-strings=strict";

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
      "--no-compile-autoload-dotenv",
      "--no-compile-autoload-bunfig",
      entry,
      "--outfile",
      outfile,
    ],
    cliRoot,
    compileEnv,
  );
};

const STRICT_PROBE = `if (process.env.MARUHI_STRICT_PROBE_DOTENV !== undefined) process.exit(1);
try {
  new Function("");
} catch (error) {
  if (error instanceof EvalError) process.exit(0);
}
process.exit(1);
`;
const probeEnv = Object.fromEntries(
  Object.entries(process.env).filter(
    ([name]) => !name.toUpperCase().startsWith("BUN_") && name !== "MARUHI_STRICT_PROBE_DOTENV",
  ),
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
      await writeFile(join(probeDir, ".env"), "MARUHI_STRICT_PROBE_DOTENV=read\n");
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
          `the strict-mode probe failed on ${target.name} (it exits 1 when new Function runs, or when its directory's .env or bunfig.toml is read)`,
          { cause: error },
        );
      }
    }

    const workDir = join(distDir, target.name);
    await mkdir(workDir, { recursive: true });
    compile(target, executable, "src/bin.ts", join(workDir, target.bin));

    const archiveName = `maruhi-${target.name}.tar.gz`;
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
