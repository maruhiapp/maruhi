// Assembles the npm distribution staging (unscoped `maruhi`; default:
// apps/cli/dist-npm/). The policy is ADR-0015: ship a single bundled JS that
// assumes Bun. Workspace dependencies (@maruhi/core etc., unpublished) and the
// effect beta are folded into the bundle so they don't leak into users'
// dependency graphs. The publish itself is done by the release workflow via
// the npm CLI (provenance — bun publish is unsupported, oven-sh/bun#15601).
//
// Argument: output directory (default dist-npm; tests pass a temp dir)

import { chmod, cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { run, SEMVER_PATTERN } from "./shared.ts";

const cliRoot = fileURLToPath(new URL("..", import.meta.url));
const outDirArg = process.argv[2] ?? "dist-npm";
const outDir = isAbsolute(outDirArg) ? outDirArg : resolve(cliRoot, outDirArg);

const workspaceManifest = JSON.parse(await readFile(join(cliRoot, "package.json"), "utf8")) as {
  version: string;
};
const version = workspaceManifest.version;
// Preconditions for tag matching (release.yml) and npm's version format. Stop
// a broken version before it gets as far as publish
if (!SEMVER_PATTERN.test(version)) {
  throw new Error(`apps/cli/package.json version is not SemVer: ${version}`);
}

const bunVersion = (await readFile(join(cliRoot, "../../.bun-version"), "utf8")).trim();

await rm(outDir, { recursive: true, force: true });
await mkdir(outDir, { recursive: true });

run("bun", ["build", "--target=bun", "src/bin.ts", "--outfile", join(outDir, "bin.js")], cliRoot);

const bundle = await readFile(join(outDir, "bin.js"), "utf8");
// The shebang (#!/usr/bin/env bun) is essential for bin execution; check it so
// a regression where bun build drops it gets noticed
if (!bundle.startsWith("#!/usr/bin/env bun\n")) {
  throw new Error("bundle does not start with the bun shebang (bin execution would break)");
}

await writeFile(
  join(outDir, "package.json"),
  `${JSON.stringify(
    {
      name: "maruhi",
      version,
      description:
        "Diskless, end-to-end encrypted secrets manager CLI. Requires the Bun runtime (https://bun.sh).",
      license: "MIT",
      type: "module",
      // No `./` prefix: npm 11's publish-time normalization judges `./bin.js`
      // invalid and silently deletes the whole bin entry (observed in
      // v0.1.0-rc.1 — nearly shipped a package with zero commands)
      bin: { maruhi: "bin.js", mh: "bin.js" },
      engines: { bun: `>=${bunVersion}` },
      repository: {
        type: "git",
        url: "git+https://github.com/maruhiapp/maruhi.git",
        directory: "apps/cli",
      },
      homepage: "https://github.com/maruhiapp/maruhi",
      bugs: "https://github.com/maruhiapp/maruhi/issues",
      keywords: ["secrets", "e2ee", "cli", "dotenv", "cloudflare"],
    },
    null,
    2,
  )}\n`,
);

await cp(join(cliRoot, "LICENSE"), join(outDir, "LICENSE"));
await writeFile(
  join(outDir, "README.md"),
  `# maruhi ㊙

Diskless, end-to-end encrypted secrets manager CLI.

This package requires the [Bun](https://bun.sh) runtime (>= ${bunVersion}): the CLI
stores credentials in the OS keychain via Bun APIs and never writes plaintext
secrets to disk. Running it under Node.js prints an error and exits.

Standalone binaries (no Bun required) are available on
[GitHub Releases](https://github.com/maruhiapp/maruhi/releases).

Documentation: https://github.com/maruhiapp/maruhi
`,
);
await chmod(join(outDir, "bin.js"), 0o755);

console.log(`npm staging complete: ${outDir} (maruhi@${version}, engines.bun >=${bunVersion})`);
