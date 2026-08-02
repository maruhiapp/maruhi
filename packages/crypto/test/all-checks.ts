// 全チェックの集約。vitest(node / workerd / browser)と Bun 直接実行の共通入口。
// 各層の実装が進むごとにここへチェックを追加する。

import { chainNegativeChecks } from "./checks/chain-negative.ts";
import { chainChecks } from "./checks/chain.ts";
import { dekWrapChecks } from "./checks/dek-wrap.ts";
import { encodingChecks } from "./checks/encoding.ts";
import { keysChecks } from "./checks/keys.ts";
import { recoveryChecks } from "./checks/recovery.ts";
import { rfc9180Checks } from "./checks/rfc9180.ts";
import type { CheckResult } from "./checks/support.ts";
import { variableChecks } from "./checks/variable.ts";

export async function runAllChecks(): Promise<CheckResult[]> {
  // 各層のチェックは共有の固定ベクターを読むだけで相互に独立だが、
  // WebCrypto 呼び出しの並行実行で失敗箇所が紛れないよう直列に実行する
  const groups: CheckResult[][] = [];
  groups.push(await encodingChecks());
  groups.push(await keysChecks());
  groups.push(await variableChecks());
  groups.push(await dekWrapChecks());
  groups.push(await rfc9180Checks());
  groups.push(await chainChecks());
  groups.push(await chainNegativeChecks());
  groups.push(await recoveryChecks());
  return groups.flat();
}
