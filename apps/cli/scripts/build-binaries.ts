// Builds the 5 compiled release binaries and checksums.txt into dist/.
// Both the release workflow (.github/workflows/release.yml) and local
// verification call this, keeping the target list, archive format, and
// checksum format defined in one place.
//
// Output (apps/cli/dist/):
//   maruhi-<target>.tar.gz × 5 (one binary each; the `mh` alias is not bundled —
//   the installer creates the link. ADR-0015)
//   checksums.txt (`sha256sum -c` compatible: "<64-hex><space><space><filename>")

import { createHash } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { run, TARGETS } from "./shared.ts";

const cliRoot = fileURLToPath(new URL("..", import.meta.url));
const distDir = join(cliRoot, "dist");

await rm(distDir, { recursive: true, force: true });
await mkdir(distDir, { recursive: true });

const checksumLines: string[] = [];
for (const target of TARGETS) {
  const workDir = join(distDir, target.name);
  await mkdir(workDir, { recursive: true });
  run(
    "bun",
    [
      "build",
      "--compile",
      `--target=${target.bunTarget}`,
      "src/bin.ts",
      "--outfile",
      join(workDir, target.bin),
    ],
    cliRoot,
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

await writeFile(join(distDir, "checksums.txt"), `${checksumLines.join("\n")}\n`);
console.log(`checksums.txt: ${checksumLines.length} entries (sha256sum -c compatible)`);
