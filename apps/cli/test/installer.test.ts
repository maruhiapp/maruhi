// Pins the install script (packaging/install.sh) and the Homebrew formula
// to the target table and the naming conventions.
//
// Real-install verification is done by packaging/install-test.sh (4 real
// OSes × .github/workflows/installer.yml). What this file holds down is the
// three "copies of the table" that can drift silently before ever reaching
// there — shared.ts's TARGETS, build-binaries.ts's archive naming, and the
// formula's platform mapping.

import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  isPrerelease,
  normalizeVersion,
  parseChecksums,
  renderFormula,
} from "../scripts/formula.ts";
import { TARGETS } from "../scripts/shared.ts";

const read = (path: string): string =>
  readFileSync(new URL(`../../../${path}`, import.meta.url), "utf8");

const installScript = read("packaging/install.sh");
const buildScript = read("apps/cli/scripts/build-binaries.ts");
const exampleChecksums = read("packaging/homebrew/example-checksums.txt");
const exampleFormula = read("packaging/homebrew/maruhi.example.rb");

const unixTargets = TARGETS.filter((target) => !target.name.startsWith("windows"));

describe("install script (packaging/install.sh)", () => {
  it("the supported set matches TARGETS (minus windows)", () => {
    const declared = /^SUPPORTED_TARGETS="([^"]+)"$/m.exec(installScript)?.[1];
    expect(declared, "could not read install.sh's SUPPORTED_TARGETS").toBeDefined();
    expect(declared?.split(" ")).toEqual(unixTargets.map((target) => target.name));
  });

  it("the archive naming convention matches build-binaries.ts", () => {
    // If the producer (build-binaries.ts) and the fetcher (install.sh)
    // disagree on the naming, it first surfaces as a 404 in the real-OS
    // tests. Pin both assembly lines
    expect(buildScript).toContain("`maruhi-${target.name}.tar.gz`");
    expect(installScript).toContain('ARCHIVE="maruhi-${TARGET}.tar.gz"');
  });

  it("windows is not an install-script target (directed to the manual steps in the README)", () => {
    expect(installScript).not.toMatch(/TARGET="windows/);
    expect(installScript).toContain("Windows is not supported by this script");
  });

  it("`mh` is installed as a relative symlink to maruhi (ADR-0015 ruling 7)", () => {
    expect(installScript).toContain("ln -s maruhi");
  });
});

describe("Homebrew formula generation", () => {
  const checksums = parseChecksums(exampleChecksums);

  it("reproduces packaging/homebrew/maruhi.example.rb from the example checksums", () => {
    expect(renderFormula("1.2.3", checksums)).toBe(exampleFormula);
  });

  it("carries the url / sha256 of the 4 unix targets and not windows", () => {
    const formula = renderFormula("1.2.3", checksums);
    for (const target of unixTargets) {
      expect(formula).toContain(`maruhi-${target.name}.tar.gz`);
    }
    expect(formula).not.toContain("windows");
    expect(formula.match(/^ {6}sha256 "[0-9a-f]{64}"$/gm)).toHaveLength(unixTargets.length);
  });

  it("includes the `mh` symlink and a `test do` asserting --version agreement", () => {
    const formula = renderFormula("1.2.3", checksums);
    expect(formula).toContain('bin.install_symlink "maruhi" => "mh"');
    expect(formula).toContain(
      'assert_equal version.to_s, shell_output("#{bin}/maruhi --version").strip',
    );
    expect(formula).toContain('license "MIT"');
  });

  it("does not generate when a target's archive is missing from checksums.txt", () => {
    const partial = new Map(checksums);
    partial.delete("maruhi-darwin-arm64.tar.gz");
    expect(() => renderFormula("1.2.3", partial)).toThrow("maruhi-darwin-arm64.tar.gz");
  });

  it("rejects a broken checksums.txt", () => {
    expect(() => parseChecksums("not-a-checksum-line\n")).toThrow("sha256sum format");
    expect(() => parseChecksums(`${exampleChecksums}${exampleChecksums}`)).toThrow("duplicate");
    expect(() => parseChecksums("")).toThrow("empty");
  });

  it("normalizes versions and detects pre-releases", () => {
    expect(normalizeVersion("v0.1.0")).toEqual({ version: "0.1.0", tag: "v0.1.0" });
    expect(normalizeVersion("0.1.0")).toEqual({ version: "0.1.0", tag: "v0.1.0" });
    expect(() => normalizeVersion("01.2.3")).toThrow("SemVer");
    expect(isPrerelease("0.1.0-rc.1")).toBe(true);
    expect(isPrerelease("0.1.0")).toBe(false);
  });
});
