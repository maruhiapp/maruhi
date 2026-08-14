// リリース用のコンパイル済みバイナリ 5 対象と checksums.txt を dist/ に作る。
// release workflow(.github/workflows/release.yml)とローカル検証の両方がこれを
// 呼ぶことで、対象一覧・アーカイブ形式・チェックサム形式の定義を 1 か所に保つ。
//
// 出力(apps/cli/dist/):
//   maruhi-<target>.tar.gz × 5(中身はバイナリ 1 本。`mh` エイリアスは同梱しない —
//   インストーラ側でリンクを張る。ADR-0015)
//   checksums.txt(`sha256sum -c` 互換: "<hex 64 桁><space><space><ファイル名>")

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const TARGETS = [
  { bunTarget: "bun-linux-x64", name: "linux-x64", bin: "maruhi" },
  { bunTarget: "bun-linux-arm64", name: "linux-arm64", bin: "maruhi" },
  { bunTarget: "bun-darwin-x64", name: "darwin-x64", bin: "maruhi" },
  { bunTarget: "bun-darwin-arm64", name: "darwin-arm64", bin: "maruhi" },
  { bunTarget: "bun-windows-x64", name: "windows-x64", bin: "maruhi.exe" },
] as const;

const cliRoot = fileURLToPath(new URL("..", import.meta.url));
const distDir = join(cliRoot, "dist");

function run(command: string, args: readonly string[], cwd: string): void {
  const result = spawnSync(command, [...args], { cwd, stdio: "inherit" });
  if (result.error !== undefined) {
    throw new Error(`${command} の起動に失敗: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} が exit ${result.status ?? "signal"} で失敗`);
  }
}

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
  // Windows も tar.gz で統一する(Windows 10+ の標準 tar が展開できる)。
  // zip が要る配布経路(scoop 等)が出たら release workflow ごと見直す
  run("tar", ["-czf", join(distDir, archiveName), "-C", workDir, target.bin], cliRoot);
  await rm(workDir, { recursive: true, force: true });

  const archive = await readFile(join(distDir, archiveName));
  const hex = createHash("sha256").update(archive).digest("hex");
  checksumLines.push(`${hex}  ${archiveName}`);
  console.log(`${archiveName}: ${(archive.byteLength / 1024 / 1024).toFixed(1)} MB`);
}

await writeFile(join(distDir, "checksums.txt"), `${checksumLines.join("\n")}\n`);
console.log(`checksums.txt: ${checksumLines.length} 件(sha256sum -c 互換)`);
