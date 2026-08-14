// Homebrew formula(tap: maruhiapp/homebrew-maruhi)の組み立て。
//
// 入力は Release の checksums.txt(build-binaries.ts が作る sha256sum -c 互換)と
// 版だけ。対象一覧は shared.ts の TARGETS が単一の出所で、対象の追加・改名は
// ここへ自動で波及する(未知の形は握り潰さず throw する — 静かに 1 プラット
// フォーム落ちた formula を publish する方が、生成に失敗するより悪い)。
//
// CLI 入口は generate-formula.ts、golden は packaging/homebrew/maruhi.example.rb
// (apps/cli/test/installer.test.ts が一致を固定する)。

import { SEMVER_PATTERN, TARGETS } from "./shared.ts";

const REPO = "maruhiapp/maruhi";

/** checksums.txt の 1 行: hex 64 桁 + スペース 2 個 + ファイル名。 */
const CHECKSUM_LINE = /^([0-9a-f]{64}) {2}(\S+)$/;

/** brew の on_macos / on_linux × on_arm / on_intel のどこに載る対象か。 */
interface Slot {
  readonly os: "macos" | "linux";
  readonly cpu: "arm" | "intel";
}

interface Download {
  readonly url: string;
  readonly sha256: string;
}

/**
 * Parses a `sha256sum -c` compatible checksums file into filename → hex digest.
 *
 * Rejects malformed and duplicated lines: a formula built from a half-understood
 * checksums file would ship a wrong digest, which brew reports as a download
 * failure far from the cause.
 */
export function parseChecksums(text: string): ReadonlyMap<string, string> {
  const entries = new Map<string, string>();
  for (const [index, line] of text.split("\n").entries()) {
    if (line === "") continue;
    const matched = CHECKSUM_LINE.exec(line);
    const hex = matched?.[1];
    const name = matched?.[2];
    if (hex === undefined || name === undefined) {
      throw new Error(`checksums.txt の ${index + 1} 行目が sha256sum 形式ではありません: ${line}`);
    }
    if (entries.has(name)) {
      throw new Error(`checksums.txt に ${name} の行が重複しています`);
    }
    entries.set(name, hex);
  }
  if (entries.size === 0) {
    throw new Error("checksums.txt が空です");
  }
  return entries;
}

/** 版(v 有無どちらでも可)を検査して `{ version, tag }` に正規化する。 */
export function normalizeVersion(input: string): {
  readonly version: string;
  readonly tag: string;
} {
  const version = input.startsWith("v") ? input.slice(1) : input;
  if (!SEMVER_PATTERN.test(version)) {
    throw new Error(`版が SemVer ではありません: ${input}`);
  }
  return { version, tag: `v${version}` };
}

/** True for `-rc.N` style prereleases (brew tap は安定版だけを載せる)。 */
export function isPrerelease(version: string): boolean {
  return version.includes("-");
}

function slotOf(targetName: string): Slot {
  const [platform, arch] = targetName.split("-");
  const os = platform === "darwin" ? "macos" : platform === "linux" ? "linux" : undefined;
  const cpu = arch === "arm64" ? "arm" : arch === "x64" ? "intel" : undefined;
  if (os === undefined || cpu === undefined) {
    throw new Error(
      `対象 ${targetName} を brew の on_<os> / on_<cpu> ブロックへ対応付けられません(scripts/formula.ts を更新してください)`,
    );
  }
  return { os, cpu };
}

/**
 * Maps every non-Windows target to its brew slot, failing when the release is
 * missing an archive: a formula silently short one platform is worse than none.
 */
function collectDownloads(
  tag: string,
  checksums: ReadonlyMap<string, string>,
): ReadonlyMap<string, Download> {
  const downloads = new Map<string, Download>();
  const missing: string[] = [];
  for (const target of TARGETS) {
    if (target.name.startsWith("windows")) continue;
    const archive = `maruhi-${target.name}.tar.gz`;
    const sha256 = checksums.get(archive);
    if (sha256 === undefined) {
      missing.push(archive);
      continue;
    }
    const { os, cpu } = slotOf(target.name);
    downloads.set(`${os}/${cpu}`, {
      url: `https://github.com/${REPO}/releases/download/${tag}/${archive}`,
      sha256,
    });
  }
  if (missing.length > 0) {
    throw new Error(`checksums.txt に次のアーカイブがありません: ${missing.join(", ")}`);
  }
  return downloads;
}

function renderPlatform(os: Slot["os"], downloads: ReadonlyMap<string, Download>): string {
  const lines: string[] = [`  on_${os} do`];
  for (const cpu of ["arm", "intel"] as const) {
    const download = downloads.get(`${os}/${cpu}`);
    if (download === undefined) {
      throw new Error(`対象表(shared.ts TARGETS)に ${os}/${cpu} の対象がありません`);
    }
    lines.push(
      `    on_${cpu} do`,
      `      url "${download.url}"`,
      `      sha256 "${download.sha256}"`,
      `    end`,
    );
  }
  lines.push("  end");
  return lines.join("\n");
}

/**
 * Renders the tap formula for the given version from a parsed checksums map.
 *
 * Windows targets are skipped (brew has no Windows); every other target must be
 * present in the checksums file.
 */
export function renderFormula(input: string, checksums: ReadonlyMap<string, string>): string {
  const { version, tag } = normalizeVersion(input);
  const downloads = collectDownloads(tag, checksums);

  return `# 生成物 — 手で編集しない。
# apps/cli/scripts/generate-formula.ts が Release の checksums.txt から作る
# (${REPO})。更新手順は docs/RELEASING.md の「Homebrew tap の更新」。
class Maruhi < Formula
  desc "Diskless, end-to-end encrypted secrets manager on Cloudflare"
  homepage "https://github.com/${REPO}"
  version "${version}"
  license "MIT"

${renderPlatform("macos", downloads)}

${renderPlatform("linux", downloads)}

  def install
    bin.install "maruhi"
    # アーカイブにはバイナリ 1 本しか入っていない。\`mh\` はインストーラ側で
    # 張る(ADR-0015 裁定 6/7)
    bin.install_symlink "maruhi" => "mh"
  end

  test do
    assert_equal version.to_s, shell_output("#{bin}/maruhi --version").strip
  end
end
`;
}
