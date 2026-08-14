// npm 配布物(unscoped `maruhi`)のステージングを組み立てる(既定: apps/cli/dist-npm/)。
// 方針は ADR-0015: Bun 前提の単一バンドル JS を配る。workspace 依存
// (@maruhi/core など未 publish)と effect beta はバンドルへ畳み、利用者の
// 依存グラフに伝播させない。publish 自体は release workflow が npm CLI で行う
// (provenance。bun publish は未対応 — oven-sh/bun#15601)。
//
// 引数: 出力ディレクトリ(省略時 dist-npm。テストが一時ディレクトリを渡す)

import { spawnSync } from "node:child_process";
import { chmod, cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const cliRoot = fileURLToPath(new URL("..", import.meta.url));
const outDirArg = process.argv[2] ?? "dist-npm";
const outDir = isAbsolute(outDirArg) ? outDirArg : resolve(cliRoot, outDirArg);

const workspaceManifest = JSON.parse(await readFile(join(cliRoot, "package.json"), "utf8")) as {
  version: string;
  description?: string;
};
const version = workspaceManifest.version;
// タグ照合(release.yml)と npm の版形式の前提。壊れた版を publish 直前より
// 手前で止める
if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?$/.test(version)) {
  throw new Error(`apps/cli/package.json の version が SemVer ではない: ${version}`);
}

const bunVersion = (await readFile(join(cliRoot, "../../.bun-version"), "utf8")).trim();

await rm(outDir, { recursive: true, force: true });
await mkdir(outDir, { recursive: true });

const build = spawnSync(
  "bun",
  ["build", "--target=bun", "src/bin.ts", "--outfile", join(outDir, "bin.js")],
  { cwd: cliRoot, stdio: "inherit" },
);
if (build.error !== undefined || build.status !== 0) {
  throw new Error(`bun build に失敗: ${build.error?.message ?? `exit ${build.status}`}`);
}

const bundle = await readFile(join(outDir, "bin.js"), "utf8");
// shebang(#!/usr/bin/env bun)は bin 実行の要。bun build が落とす退行に気づけるよう検査する
if (!bundle.startsWith("#!/usr/bin/env bun\n")) {
  throw new Error("バンドル先頭に bun の shebang がない(bin 実行が壊れる)");
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
      bin: { maruhi: "./bin.js", mh: "./bin.js" },
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

console.log(`npm ステージング完成: ${outDir}(maruhi@${version}, engines.bun >=${bunVersion})`);
