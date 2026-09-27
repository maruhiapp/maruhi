// Generates the formula to copy to the Homebrew tap (maruhiapp/homebrew-maruhi).
//
//   bun apps/cli/scripts/generate-formula.ts --version v0.1.0
//   bun apps/cli/scripts/generate-formula.ts --checksums apps/cli/dist/checksums.txt
//
// By default fetches checksums.txt from the GitHub Release and writes
// packaging/homebrew/maruhi.rb (a generated artifact, not committed to the
// repo — see maruhi.example.rb in the same directory for the shape). The
// procedure is "Updating the Homebrew tap" in docs/RELEASING.md.
//
// Why tap updates are not an automatic PR from the release workflow (in the
// ADR-0015 line): it would mean adding cross-repo write credentials to a
// release path that already holds contents: write + id-token: write. Not worth
// it at this release cadence.

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import { isPrerelease, normalizeVersion, parseChecksums, renderFormula } from "./formula.ts";

const repoRoot = fileURLToPath(new URL("../../..", import.meta.url));

const { values } = parseArgs({
  args: process.argv.slice(2),
  strict: true,
  options: {
    // Defaults to apps/cli/package.json (single source of truth for the
    // version. ADR-0015 ruling 4)
    version: { type: "string" },
    // Defaults to fetching checksums.txt from the Release
    checksums: { type: "string" },
    out: { type: "string", default: resolve(repoRoot, "packaging/homebrew/maruhi.rb") },
    "allow-prerelease": { type: "boolean", default: false },
  },
});

async function packageVersion(): Promise<string> {
  const manifest = await readFile(resolve(repoRoot, "apps/cli/package.json"), "utf8");
  const { version } = JSON.parse(manifest) as { version: string };
  return version;
}

async function loadChecksums(source: string | undefined, tag: string): Promise<string> {
  if (source !== undefined) {
    return await readFile(resolve(process.cwd(), source), "utf8");
  }
  const url = `https://github.com/maruhiapp/maruhi/releases/download/${tag}/checksums.txt`;
  console.error(`fetching checksums.txt: ${url}`);
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(
      `could not fetch checksums.txt (${response.status}). Check that the release exists or pass --checksums <path>: ${url}`,
    );
  }
  return await response.text();
}

const { version, tag } = normalizeVersion(values.version ?? (await packageVersion()));

if (isPrerelease(version) && !values["allow-prerelease"]) {
  throw new Error(
    `${tag} is a prerelease. The brew tap only carries stable releases (docs/RELEASING.md). Pass --allow-prerelease if intentional`,
  );
}

const out = resolve(process.cwd(), values.out);
const formula = renderFormula(version, parseChecksums(await loadChecksums(values.checksums, tag)));
await mkdir(dirname(out), { recursive: true });
await writeFile(out, formula);
console.error(`wrote ${out} (${tag})`);
console.error("to the tap: cp <this output> <homebrew-maruhi>/Formula/maruhi.rb");
