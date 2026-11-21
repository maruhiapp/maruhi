import { auditHeadChecks } from "./checks/audit-head.ts";
import { chainHistoryChecks } from "./checks/chain-history.ts";
import { chainNegativeChecks } from "./checks/chain-negative.ts";
import { chainOpCoverageChecks } from "./checks/chain-op-coverage.ts";
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
import { recipientSetsChecks } from "./checks/recipient-sets.ts";
import { recoveryChecks } from "./checks/recovery.ts";
import { rfc9180Checks } from "./checks/rfc9180.ts";
import { sealedValueChecks } from "./checks/sealed-value.ts";
import type { CheckResult } from "./checks/support.ts";
import { valueSignatureChecks } from "./checks/value-signature.ts";
import { variableChecks } from "./checks/variable.ts";
import { vectorInventoryChecks } from "./checks/vector-inventory.ts";

const MIN_TOTAL_CHECKS = 2870;
const MAX_FLOOR_SLACK = 0.05;

export async function runAllChecks(): Promise<CheckResult[]> {
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
  groups.push(await chainOpCoverageChecks());
  groups.push(await checkpointChecks());
  groups.push(await checkpointDigestChecks());
  groups.push(recipientSetsChecks());
  groups.push(await valueSignatureChecks());
  groups.push(await metadataSignatureChecks());
  groups.push(await envManifestChecks());
  groups.push(await headAttestationChecks());
  groups.push(await auditHeadChecks());
  groups.push(await recoveryChecks());
  groups.push(await masterKeyWrapChecks());
  const results = groups.flat();
  const total = results.length;
  results.push(
    {
      name: `meta: total check count is at least ${MIN_TOTAL_CHECKS}`,
      ok: total >= MIN_TOTAL_CHECKS,
      detail: `actual ${total}`,
    },
    {
      name: `meta: MIN_TOTAL_CHECKS is within ${MAX_FLOOR_SLACK * 100}% of the total check count`,
      ok: total <= Math.floor(MIN_TOTAL_CHECKS * (1 + MAX_FLOOR_SLACK)),
      detail: `actual ${total} — raise MIN_TOTAL_CHECKS to ${total}`,
    },
  );
  return results;
}
