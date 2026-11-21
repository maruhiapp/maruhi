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
if (!SEMVER_PATTERN.test(version)) {
  throw new Error(`apps/cli/package.json version is not SemVer: ${version}`);
}

const bunVersion = (await readFile(join(cliRoot, "../../.bun-version"), "utf8")).trim();

await rm(outDir, { recursive: true, force: true });
await mkdir(outDir, { recursive: true });

run("bun", ["build", "--target=bun", "src/bin.ts", "--outfile", join(outDir, "bin.js")], cliRoot);

const bundle = await readFile(join(outDir, "bin.js"), "utf8");
const BUILD_HEADER = "#!/usr/bin/env bun\n// @bun\n";
if (!bundle.startsWith(BUILD_HEADER)) {
  throw new Error("bundle does not start with the shebang and pragma lines the launcher replaces");
}
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
      bin: { maruhi: "bin.js", mh: "bin.js" },
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
