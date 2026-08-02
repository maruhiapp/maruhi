// 全チェックの集約。vitest(node / workerd / browser)と Bun 直接実行の共通入口。
// 各層の実装が進むごとにここへチェックを追加する。

import { encodingChecks } from "./checks/encoding.ts";
import { keysChecks } from "./checks/keys.ts";
import type { CheckResult } from "./checks/support.ts";

export async function runAllChecks(): Promise<CheckResult[]> {
  // 各層のチェックは共有の固定ベクターを読むだけで相互に独立だが、
  // WebCrypto 呼び出しの並行実行で失敗箇所が紛れないよう直列に実行する
  const groups: CheckResult[][] = [];
  groups.push(await encodingChecks());
  groups.push(await keysChecks());
  return groups.flat();
}
