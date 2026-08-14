// build-binaries.ts / build-npm.ts で共有する部品。

import { spawnSync } from "node:child_process";

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
