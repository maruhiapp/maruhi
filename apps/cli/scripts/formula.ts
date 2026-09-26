// Assembling the Homebrew formula (tap: maruhiapp/homebrew-maruhi).
//
// Inputs are the Release's checksums.txt (the sha256sum -c compatible file
// build-binaries.ts makes) and the version only. shared.ts's TARGETS is the
// single source of truth for the target list, so added/renamed targets ripple
// here automatically (unknown shapes are thrown, not swallowed — silently
// publishing a formula one platform short is worse than failing to generate).
//
// The CLI entry point is generate-formula.ts; the golden is
// packaging/homebrew/maruhi.example.rb (apps/cli/test/installer.test.ts pins
// the match).

import { SEMVER_PATTERN, TARGETS } from "./shared.ts";

const REPO = "maruhiapp/maruhi";

/** One line of checksums.txt: 64-hex + two spaces + filename. */
const CHECKSUM_LINE = /^([0-9a-f]{64}) {2}(\S+)$/;

/** Which of brew's on_macos / on_linux × on_arm / on_intel slots a target lands in. */
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
      throw new Error(`line ${index + 1} of checksums.txt is not in sha256sum format: ${line}`);
    }
    if (entries.has(name)) {
      throw new Error(`checksums.txt has a duplicate line for ${name}`);
    }
    entries.set(name, hex);
  }
  if (entries.size === 0) {
    throw new Error("checksums.txt is empty");
  }
  return entries;
}

/** Checks a version (with or without leading v) and normalizes it to `{ version, tag }`. */
export function normalizeVersion(input: string): {
  readonly version: string;
  readonly tag: string;
} {
  const version = input.startsWith("v") ? input.slice(1) : input;
  if (!SEMVER_PATTERN.test(version)) {
    throw new Error(`version is not SemVer: ${input}`);
  }
  return { version, tag: `v${version}` };
}

/** True for `-rc.N` style prereleases (the brew tap only carries stable releases). */
export function isPrerelease(version: string): boolean {
  return version.includes("-");
}

function slotOf(targetName: string): Slot {
  const [platform, arch] = targetName.split("-");
  const os = platform === "darwin" ? "macos" : platform === "linux" ? "linux" : undefined;
  const cpu = arch === "arm64" ? "arm" : arch === "x64" ? "intel" : undefined;
  if (os === undefined || cpu === undefined) {
    throw new Error(
      `cannot map target ${targetName} to a brew on_<os> / on_<cpu> block (update scripts/formula.ts)`,
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
    throw new Error(`checksums.txt is missing these archives: ${missing.join(", ")}`);
  }
  return downloads;
}

function renderPlatform(os: Slot["os"], downloads: ReadonlyMap<string, Download>): string {
  const lines: string[] = [`  on_${os} do`];
  for (const cpu of ["arm", "intel"] as const) {
    const download = downloads.get(`${os}/${cpu}`);
    if (download === undefined) {
      throw new Error(`the target table (shared.ts TARGETS) has no ${os}/${cpu} target`);
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

  // english-exempt: generated text must byte-match the golden fixture
  // packaging/homebrew/maruhi.example.rb, owned by another shard — these lines
  // stay in Japanese until that fixture is translated.
  const header = [
    "# 生成物 — 手で編集しない。", // english-exempt: byte-matches packaging/homebrew/maruhi.example.rb
    "# apps/cli/scripts/generate-formula.ts が Release の checksums.txt から作る", // english-exempt: byte-matches packaging/homebrew/maruhi.example.rb
    `# (${REPO})。更新手順は docs/RELEASING.md の「Homebrew tap の更新」。`, // english-exempt: byte-matches packaging/homebrew/maruhi.example.rb
  ].join("\n");
  const installComment = [
    "    # アーカイブにはバイナリ 1 本しか入っていない。`mh` はインストーラ側で", // english-exempt: byte-matches packaging/homebrew/maruhi.example.rb
    "    # 張る(ADR-0015 裁定 6/7)", // english-exempt: byte-matches packaging/homebrew/maruhi.example.rb
  ].join("\n");

  return `${header}
class Maruhi < Formula
  desc "Diskless, end-to-end encrypted secrets manager on Cloudflare"
  homepage "https://github.com/${REPO}"
  version "${version}"
  license "MIT"

${renderPlatform("macos", downloads)}

${renderPlatform("linux", downloads)}

  def install
    bin.install "maruhi"
${installComment}
    bin.install_symlink "maruhi" => "mh"
  end

  test do
    assert_equal version.to_s, shell_output("#{bin}/maruhi --version").strip
  end
end
`;
}
