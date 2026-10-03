// Aggregation of all checks. Shared entry point for vitest (node / workerd / browser)
// and direct Bun execution. Add checks here as each layer's implementation progresses.

import { auditHeadChecks } from "./checks/audit-head.ts";
import { chainHistoryChecks } from "./checks/chain-history.ts";
import { chainNegativeChecks } from "./checks/chain-negative.ts";
import { chainChecks } from "./checks/chain.ts";
import { checkpointDigestChecks } from "./checks/checkpoint-digest.ts";
import { checkpointChecks } from "./checks/checkpoint.ts";
import { dekCommitmentChecks } from "./checks/dek-commitment.ts";
import { dekWrapSignatureChecks } from "./checks/dek-wrap-signature.ts";
import { dekWrapChecks } from "./checks/dek-wrap.ts";
import { encodingChecks } from "./checks/encoding.ts";
import { envManifestChecks } from "./checks/env-manifest.ts";
import { fingerprintWordsChecks } from "./checks/fingerprint-words.ts";
import { headAttestationChecks } from "./checks/head-attestation.ts";
import { inviteAcceptSignatureChecks } from "./checks/invite-accept-signature.ts";
import { inviteLinkChecks } from "./checks/invite-link.ts";
import { keysChecks } from "./checks/keys.ts";
import { leaseWrapChecks } from "./checks/lease-wrap.ts";
import { masterKeyWrapChecks } from "./checks/master-key-wrap.ts";
import { metadataSignatureChecks } from "./checks/metadata-signature.ts";
import { recoveryChecks } from "./checks/recovery.ts";
import { rfc9180Checks } from "./checks/rfc9180.ts";
import { sealedValueChecks } from "./checks/sealed-value.ts";
import type { CheckResult } from "./checks/support.ts";
import { valueSignatureChecks } from "./checks/value-signature.ts";
import { variableChecks } from "./checks/variable.ts";
import { vectorInventoryChecks } from "./checks/vector-inventory.ts";

// Lower bound on the total check count (effectiveness of the tests): detects check
// groups silently dropping out (removed from all-checks, early-returned, etc.) as an
// explicit failure rather than a shrinking population. Adding checks never fails this
// (lower bound only). A change that deliberately reduces checks lowers this value in
// the same change
const MIN_TOTAL_CHECKS = 1699;

export async function runAllChecks(): Promise<CheckResult[]> {
  // Each layer's checks are mutually independent — they only read shared fixed
  // vectors — but are run serially so that concurrent WebCrypto calls do not
  // obscure which one failed
  const groups: CheckResult[][] = [];
  groups.push(vectorInventoryChecks());
  groups.push(await encodingChecks());
  groups.push(await keysChecks());
  groups.push(await fingerprintWordsChecks());
  groups.push(await variableChecks());
  groups.push(await dekWrapChecks());
  groups.push(await dekWrapSignatureChecks());
  groups.push(await inviteAcceptSignatureChecks());
  groups.push(await inviteLinkChecks());
  groups.push(await dekCommitmentChecks());
  groups.push(await leaseWrapChecks());
  groups.push(await sealedValueChecks());
  groups.push(await rfc9180Checks());
  groups.push(await chainChecks());
  groups.push(await chainNegativeChecks());
  groups.push(await chainHistoryChecks());
  groups.push(await checkpointChecks());
  groups.push(await checkpointDigestChecks());
  groups.push(await valueSignatureChecks());
  groups.push(await metadataSignatureChecks());
  groups.push(await envManifestChecks());
  groups.push(await headAttestationChecks());
  groups.push(await auditHeadChecks());
  groups.push(await recoveryChecks());
  groups.push(await masterKeyWrapChecks());
  const results = groups.flat();
  results.push({
    name: `meta: total check count is at least ${MIN_TOTAL_CHECKS}`,
    ok: results.length >= MIN_TOTAL_CHECKS,
    detail: `actual ${results.length}`,
  });
  return results;
}
