// Homebrew tap(maruhiapp/homebrew-maruhi)へコピーする formula を生成する。
//
//   bun apps/cli/scripts/generate-formula.ts --version v0.1.0
//   bun apps/cli/scripts/generate-formula.ts --checksums apps/cli/dist/checksums.txt
//
// 既定では GitHub Release の checksums.txt を取得して packaging/homebrew/maruhi.rb を
// 書く(生成物なのでリポジトリにはコミットしない — 形の例は同ディレクトリの
// maruhi.example.rb)。手順は docs/RELEASING.md の「Homebrew tap の更新」。
//
// tap への反映を release workflow からの自動 PR にしない理由(ADR-0015 の系):
// cross-repo の書き込み資格情報を、contents: write + id-token: write を持つ
// リリース経路へ足すことになる。リリース頻度に対して割に合わない。

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
    // 省略時は apps/cli/package.json(版の単一の出所。ADR-0015 裁定 4)
    version: { type: "string" },
    // 省略時は Release の checksums.txt を取得する
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
  console.error(`checksums.txt を取得: ${url}`);
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(
      `checksums.txt を取得できません(${response.status})。リリース済みか確認するか --checksums <path> を渡してください: ${url}`,
    );
  }
  return await response.text();
}

const { version, tag } = normalizeVersion(values.version ?? (await packageVersion()));

if (isPrerelease(version) && !values["allow-prerelease"]) {
  throw new Error(
    `${tag} はプレリリースです。brew tap には安定版だけを載せます(docs/RELEASING.md)。意図的なら --allow-prerelease を付けてください`,
  );
}

const out = resolve(process.cwd(), values.out);
const formula = renderFormula(version, parseChecksums(await loadChecksums(values.checksums, tag)));
await mkdir(dirname(out), { recursive: true });
await writeFile(out, formula);
console.error(`${out} を生成しました(${tag})`);
console.error("tap へ: cp <この出力> <homebrew-maruhi>/Formula/maruhi.rb");
