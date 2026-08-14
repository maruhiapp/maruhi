// install script(packaging/install.sh)と Homebrew formula の、対象表・命名規約に
// 対する追従を固定する。
//
// 実インストールの検証は packaging/install-test.sh(実 OS 4 種 ×
// .github/workflows/installer.yml)が行う。ここで押さえるのは、そこへ届く前に
// 静かにズレうる「表の複製」— shared.ts の TARGETS、build-binaries.ts の
// アーカイブ命名、formula のプラットフォーム対応付け — の 3 点。

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

describe("install script(packaging/install.sh)", () => {
  it("対応対象が TARGETS(windows を除く)と一致する", () => {
    const declared = /^SUPPORTED_TARGETS="([^"]+)"$/m.exec(installScript)?.[1];
    expect(declared, "install.sh の SUPPORTED_TARGETS を読めない").toBeDefined();
    expect(declared?.split(" ")).toEqual(unixTargets.map((target) => target.name));
  });

  it("アーカイブ名の規約が build-binaries.ts と揃っている", () => {
    // 生成側(build-binaries.ts)と取得側(install.sh)で命名がズレると、
    // 実 OS テストで初めて 404 として現れる。両方の組み立て行を固定する
    expect(buildScript).toContain("`maruhi-${target.name}.tar.gz`");
    expect(installScript).toContain('ARCHIVE="maruhi-${TARGET}.tar.gz"');
  });

  it("windows は install script の対象にしない(README の手動手順へ誘導する)", () => {
    expect(installScript).not.toMatch(/TARGET="windows/);
    expect(installScript).toContain("Windows はこの script の対象外です");
  });

  it("`mh` は maruhi への相対 symlink として張る(ADR-0015 裁定 7)", () => {
    expect(installScript).toContain("ln -s maruhi");
  });
});

describe("Homebrew formula の生成", () => {
  const checksums = parseChecksums(exampleChecksums);

  it("例の checksums から packaging/homebrew/maruhi.example.rb を再現する", () => {
    expect(renderFormula("1.2.3", checksums)).toBe(exampleFormula);
  });

  it("unix 4 対象の url / sha256 を載せ、windows は載せない", () => {
    const formula = renderFormula("1.2.3", checksums);
    for (const target of unixTargets) {
      expect(formula).toContain(`maruhi-${target.name}.tar.gz`);
    }
    expect(formula).not.toContain("windows");
    expect(formula.match(/^ {6}sha256 "[0-9a-f]{64}"$/gm)).toHaveLength(unixTargets.length);
  });

  it("`mh` の symlink と --version 一致の test do を含む", () => {
    const formula = renderFormula("1.2.3", checksums);
    expect(formula).toContain('bin.install_symlink "maruhi" => "mh"');
    expect(formula).toContain(
      'assert_equal version.to_s, shell_output("#{bin}/maruhi --version").strip',
    );
    expect(formula).toContain('license "MIT"');
  });

  it("対象のアーカイブが checksums.txt に無ければ生成しない", () => {
    const partial = new Map(checksums);
    partial.delete("maruhi-darwin-arm64.tar.gz");
    expect(() => renderFormula("1.2.3", partial)).toThrow("maruhi-darwin-arm64.tar.gz");
  });

  it("壊れた checksums.txt を受け取らない", () => {
    expect(() => parseChecksums("not-a-checksum-line\n")).toThrow("sha256sum 形式");
    expect(() => parseChecksums(`${exampleChecksums}${exampleChecksums}`)).toThrow("重複");
    expect(() => parseChecksums("")).toThrow("空です");
  });

  it("版を正規化し、プレリリースを見分ける", () => {
    expect(normalizeVersion("v0.1.0")).toEqual({ version: "0.1.0", tag: "v0.1.0" });
    expect(normalizeVersion("0.1.0")).toEqual({ version: "0.1.0", tag: "v0.1.0" });
    expect(() => normalizeVersion("01.2.3")).toThrow("SemVer");
    expect(isPrerelease("0.1.0-rc.1")).toBe(true);
    expect(isPrerelease("0.1.0")).toBe(false);
  });
});
