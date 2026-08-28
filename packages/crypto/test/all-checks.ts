// 全チェックの集約。vitest(node / workerd / browser)と Bun 直接実行の共通入口。
// 各層の実装が進むごとにここへチェックを追加する。

import { auditHeadChecks } from "./checks/audit-head.ts";
import { chainHistoryChecks } from "./checks/chain-history.ts";
import { chainNegativeChecks } from "./checks/chain-negative.ts";
import { chainChecks } from "./checks/chain.ts";
import { checkpointChecks } from "./checks/checkpoint.ts";
import { dekCommitmentChecks } from "./checks/dek-commitment.ts";
import { dekWrapSignatureChecks } from "./checks/dek-wrap-signature.ts";
import { dekWrapChecks } from "./checks/dek-wrap.ts";
import { encodingChecks } from "./checks/encoding.ts";
import { envManifestChecks } from "./checks/env-manifest.ts";
import { fingerprintWordsChecks } from "./checks/fingerprint-words.ts";
import { inviteAcceptSignatureChecks } from "./checks/invite-accept-signature.ts";
import { keysChecks } from "./checks/keys.ts";
import { leaseWrapChecks } from "./checks/lease-wrap.ts";
import { metadataSignatureChecks } from "./checks/metadata-signature.ts";
import { recoveryChecks } from "./checks/recovery.ts";
import { rfc9180Checks } from "./checks/rfc9180.ts";
import type { CheckResult } from "./checks/support.ts";
import { valueSignatureChecks } from "./checks/value-signature.ts";
import { variableChecks } from "./checks/variable.ts";

export async function runAllChecks(): Promise<CheckResult[]> {
  // 各層のチェックは共有の固定ベクターを読むだけで相互に独立だが、
  // WebCrypto 呼び出しの並行実行で失敗箇所が紛れないよう直列に実行する
  const groups: CheckResult[][] = [];
  groups.push(await encodingChecks());
  groups.push(await keysChecks());
  groups.push(await fingerprintWordsChecks());
  groups.push(await variableChecks());
  groups.push(await dekWrapChecks());
  groups.push(await dekWrapSignatureChecks());
  groups.push(await inviteAcceptSignatureChecks());
  groups.push(await dekCommitmentChecks());
  groups.push(await leaseWrapChecks());
  groups.push(await rfc9180Checks());
  groups.push(await chainChecks());
  groups.push(await chainNegativeChecks());
  groups.push(await chainHistoryChecks());
  groups.push(await checkpointChecks());
  groups.push(await valueSignatureChecks());
  groups.push(await metadataSignatureChecks());
  groups.push(await envManifestChecks());
  groups.push(await auditHeadChecks());
  groups.push(await recoveryChecks());
  return groups.flat();
}
