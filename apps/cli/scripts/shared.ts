// build-binaries.ts / build-npm.ts / print-smoke-matrix.ts で共有する部品。

import { spawnSync } from "node:child_process";

/**
 * リリース対象の単一の出所。バイナリ生成(build-binaries.ts)と release.yml の
 * smoke matrix(print-smoke-matrix.ts → fromJSON)の両方がここから導出される。
 * 対象を足すと実 OS スモークが自動で付いてくる — 表を複製して smoke 側だけ漏れ、
 * クロスコンパイルしか通っていない成果物が公開される形を構造的に塞ぐ。
 *
 * runner はスモークに使う GitHub ホスト runner のラベル。darwin-x64 は Intel mac
 * の最終世代 macos-15-intel(2027-08 retire。その際ここを見直す)。
 */
export const TARGETS = [
  { bunTarget: "bun-linux-x64", name: "linux-x64", bin: "maruhi", runner: "ubuntu-latest" },
  { bunTarget: "bun-linux-arm64", name: "linux-arm64", bin: "maruhi", runner: "ubuntu-24.04-arm" },
  { bunTarget: "bun-darwin-x64", name: "darwin-x64", bin: "maruhi", runner: "macos-15-intel" },
  { bunTarget: "bun-darwin-arm64", name: "darwin-arm64", bin: "maruhi", runner: "macos-latest" },
  {
    bunTarget: "bun-windows-x64",
    name: "windows-x64",
    bin: "maruhi.exe",
    runner: "windows-latest",
  },
] as const;

/**
 * Canonical SemVer(build metadata なし。タグに `+` は使わない運用)。
 * `\d+` ベースの緩い形だと `01.2.3` を通し、GitHub Release 作成後の npm publish
 * で初めて弾かれて Release と npm が食い違う。npm と同じ判定をゲートの先頭
 * (release.yml の version-check にも同型の ERE がある)から掛ける。
 */
export const SEMVER_PATTERN =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?$/;

/** 子プロセスを同期実行し、起動失敗・シグナル死・非 0 終了を区別して失敗させる。 */
export function run(command: string, args: readonly string[], cwd: string): void {
  const result = spawnSync(command, [...args], { cwd, stdio: "inherit" });
  if (result.error !== undefined) {
    throw new Error(`${command} の起動に失敗: ${result.error.message}`);
  }
  if (result.signal !== null) {
    throw new Error(`${command} ${args.join(" ")} がシグナル ${result.signal} で死んだ`);
  }
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} が exit ${result.status} で失敗`);
  }
}
