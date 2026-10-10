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
import { basename, join } from "node:path";
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

const checksumLines: string[] = [];
try {
  for (const target of TARGETS) {
    const runtime = BUN_RUNTIMES[target.bunTarget];
    const zipPath = join(runtimesDir, runtime.zip);
    await writeFile(zipPath, await downloadVerified(runtimeUrl(runtime), runtime.sha256));
    const runtimeDir = join(runtimesDir, target.name);
    run("unzip", ["-q", "-j", zipPath, runtime.member, "-d", runtimeDir], cliRoot);
    const executable = join(runtimeDir, basename(runtime.member));

    const workDir = join(distDir, target.name);
    await mkdir(workDir, { recursive: true });
    run(
      "bun",
      [
        "build",
        "--compile",
        `--target=${target.bunTarget}`,
        `--compile-executable-path=${executable}`,
        "src/bin.ts",
        "--outfile",
        join(workDir, target.bin),
      ],
      cliRoot,
      compileEnv,
    );

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
