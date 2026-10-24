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
// bun build starts the bundle with src/bin.ts's shebang and a `// @bun`
// pragma line. The launcher below replaces exactly those two lines, so a
// regression where bun build drops or changes them stops here
const BUILD_HEADER = "#!/usr/bin/env bun\n// @bun\n";
if (!bundle.startsWith(BUILD_HEADER)) {
  throw new Error("bundle does not start with the shebang and pragma lines the launcher replaces");
}
// bin.js starts as a shell script that runs the same file under Bun with
// --no-env-file, --env-file=/dev/null and --config=/dev/null, so Bun reads no
// .env file and no bunfig.toml from the working directory: a .env there could
// hand the CLI variables such as NODE_TLS_REJECT_UNAUTHORIZED or
// MARUHI_AGENT_SOCK, and a bunfig.toml preload would run its code inside the
// CLI. Bun before 1.3.3 ignores --no-env-file, as bun does any flag it does
// not know, and npm and bun install the package there despite engines.bun, so
// --env-file=/dev/null, an empty file Bun loads in place of the .env files,
// keeps them out there too. The shell runs the second line: `//` is a
// directory, so that command fails (its error goes to /dev/null, and `|| :`
// carries a shell with errexit on to the exec). To Bun the same line is the
// `// @bun` pragma, so Bun runs the bundle as built instead of transpiling it
// again into its runtime transpiler cache. A `#!/usr/bin/env -S bun ...`
// shebang would need an env with -S, which BusyBox (Alpine) does not have.
// npm and bun build their Windows launchers from the first line, and no first
// line turns bunfig.toml off there (Bun on Windows cannot read
// --config=/dev/null), so the package is for Linux and macOS (`os` below)
const LAUNCHER = `#!/bin/sh\n// @bun 2>/dev/null || :; exec bun --no-env-file --env-file=/dev/null --config=/dev/null "$0" "$@"\n`;
await writeFile(join(outDir, "bin.js"), `${LAUNCHER}${bundle.slice(BUILD_HEADER.length)}`);

await writeFile(
  join(outDir, "package.json"),
  `${JSON.stringify(
    {
      name: "maruhi",
      version,
      description:
        "Diskless, end-to-end encrypted secrets manager CLI. Requires the Bun runtime (https://bun.sh) on Linux or macOS.",
      license: "MIT",
      type: "module",
      // No `./` prefix: npm 11's publish-time normalization judges `./bin.js`
      // invalid and silently deletes the whole bin entry (observed in
      // v0.1.0-rc.1 — nearly shipped a package with zero commands)
      bin: { maruhi: "bin.js", mh: "bin.js" },
      // The launcher at the top of bin.js is for Linux and macOS. npm refuses
      // to install the package anywhere else
      os: ["darwin", "linux"],
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

This package requires the [Bun](https://bun.sh) runtime (>= ${bunVersion}) on Linux or
macOS: the CLI stores credentials in the OS keychain via Bun APIs and never writes
plaintext secrets to disk. Running it under Node.js prints an error and exits. The
\`maruhi\` command runs Bun without the working directory's \`.env\` files and
\`bunfig.toml\`.

Standalone binaries (no Bun required, and the way to run maruhi on Windows) are
available on [GitHub Releases](https://github.com/maruhiapp/maruhi/releases).

Documentation: https://github.com/maruhiapp/maruhi
`,
);
await chmod(join(outDir, "bin.js"), 0o755);

console.log(`npm staging complete: ${outDir} (maruhi@${version}, engines.bun >=${bunVersion})`);
