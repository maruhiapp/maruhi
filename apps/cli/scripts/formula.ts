import { SEMVER_PATTERN, TARGETS } from "./shared.ts";

const REPO = "maruhiapp/maruhi";

const CHECKSUM_LINE = /^([0-9a-f]{64}) {2}(\S+)$/;

interface Slot {
  readonly os: "macos" | "linux";
  readonly cpu: "arm" | "intel";
}

interface Download {
  readonly url: string;
  readonly sha256: string;
}

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

export function renderFormula(input: string, checksums: ReadonlyMap<string, string>): string {
  const { version, tag } = normalizeVersion(input);
  const downloads = collectDownloads(tag, checksums);

  return `# Generated file — do not edit by hand.
# Built by apps/cli/scripts/generate-formula.ts from the Release's checksums.txt
# (${REPO}). Update procedure: docs/RELEASING.md, "Updating the Homebrew tap".
class Maruhi < Formula
  desc "Diskless, end-to-end encrypted secrets manager on Cloudflare"
  homepage "https://github.com/${REPO}"
  version "${version}"
  license "MIT"

${renderPlatform("macos", downloads)}

${renderPlatform("linux", downloads)}

  def install
    bin.install "maruhi"
    bin.install_symlink "maruhi" => "mh"
  end

  test do
    assert_equal version.to_s, shell_output("#{bin}/maruhi --version").strip
  end
end
`;
}
