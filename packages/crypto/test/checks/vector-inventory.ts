// ベクター棚卸し(inventory)チェック: 各ベクター JSON の「存在すべきケース名」を
// テスト側に固定する。既存のチェックは JSON に存在するベクターを列挙して回す形の
// ため、ベクターの誤削除・rename・重複がそのまま黙って通過する(検査対象が減った
// ことを誰も検出できない)。ここで名前集合をテストコードに複製して固定し、
// JSON 側の欠落・増減を fail-closed に検出する(PR #116 観点 7 — テストの実効性)。
//
// 運用規約: ベクターを追加・改名したらこのリストも同じ変更で更新する(意図的な
// 摩擦)。JSON 側にメタ情報(件数宣言など)を足す形は採らない — 宣言ごと改変
// されると検出できないため、固定はテスト側にのみ置く(session-15 レビュー③の
// 「宣言はハードコードとの一致を検査する」と同じ裁定)。名前の照合は順序
// 非依存(ソート後の完全一致)— 並べ替えは無害だが、削除・改名・重複は落とす。

import auditHeadVectors from "../../test-vectors/audit-head.json" with { type: "json" };
import chainEntries from "../../test-vectors/chain-entries.json" with { type: "json" };
import checkpointDigest from "../../test-vectors/checkpoint-digest.json" with { type: "json" };
import dekCommitment from "../../test-vectors/dek-commitment.json" with { type: "json" };
import dekWrapSignature from "../../test-vectors/dek-wrap-signature.json" with { type: "json" };
import dekWrap from "../../test-vectors/dek-wrap.json" with { type: "json" };
import encoding from "../../test-vectors/encoding.json" with { type: "json" };
import envManifest from "../../test-vectors/env-manifest.json" with { type: "json" };
import headAttestation from "../../test-vectors/head-attestation.json" with { type: "json" };
import rfc9180Vectors from "../../test-vectors/hpke/rfc9180-base-x25519-hkdfsha256-aes256gcm.json" with { type: "json" };
import inviteAccept from "../../test-vectors/invite-accept-signature.json" with { type: "json" };
import leaseWrap from "../../test-vectors/lease-wrap.json" with { type: "json" };
import metaVectors from "../../test-vectors/metadata-signature.json" with { type: "json" };
import recoveryWrap from "../../test-vectors/recovery-wrap.json" with { type: "json" };
import valueSignature from "../../test-vectors/value-signature.json" with { type: "json" };
import variableEncryption from "../../test-vectors/variable-encryption.json" with { type: "json" };
import { type CheckResult, Checks } from "./support.ts";

interface NamedEntry {
  readonly name: string;
}

interface NamedCollection {
  readonly label: string;
  readonly actual: readonly NamedEntry[];
  readonly expected: readonly string[];
}

// 名前付きコレクションの固定リスト(2026-08-31 時点の全ベクター)。
// S1(レイアウト v2)で追加されたベクターを含む。
const NAMED_COLLECTIONS: readonly NamedCollection[] = [
  {
    label: "chain-entries.valid_appends",
    actual: chainEntries.valid_appends,
    expected: [
      "readd-removed-member-same-key",
      "reuse-removed-member-key-new-user",
      "create-environment-fresh-id",
      "rotate-freshly-created-environment",
      "regrant-lease-policy-revised",
      "standalone-checkpoint-all-environments",
      "checkpoint-empty-environments",
    ],
  },
  {
    label: "chain-entries.negative",
    actual: chainEntries.negative,
    expected: [
      "tampered-payload-role",
      "field-order-swap",
      "wrong-signer",
      "prev-hash-mismatch",
      "grant-server-scope-reorder",
      "grant-server-scope-flat-concat",
      "grant-server-lease-policy-reorder",
      "grant-server-lease-claims-reorder",
      "grant-server-lease-policy-flat-concat",
      "grant-server-lease-policy-dropped",
      "change-role-tampered-new-role",
      "revoke-server-tampered-fp",
      "create-env-tampered-commitment",
      "rotate-tampered-commitment",
      "authz-admin-grant-server",
      "authz-reader-rotate-epoch",
      "authz-nonmember-actor",
      "authz-remove-last-owner",
      "authz-demote-last-owner",
      "authz-admin-adds-admin",
      "authz-grant-scope-narrowed",
      "authz-grant-scope-narrowed-policy-revised",
      "authz-grant-role-precedes-scope-narrowed",
      "authz-grant-duplicate-server-key",
      "authz-grant-role-precedes-duplicate-server-key",
      "authz-grant-lease-policy-too-many",
      "authz-grant-lease-claims-too-many",
      "grant-lease-policy-too-many-precedes-role",
      "authz-grant-narrowed-precedes-duplicate-key",
      "authz-grant-duplicate-key-on-regrant",
      "authz-create-env-duplicate",
      "authz-rotate-unknown-environment",
      "authz-rotate-unknown-precedes-epoch",
      "authz-create-env-reader",
      "authz-create-env-role-precedes-duplicate",
      "authz-rotate-role-precedes-unknown",
      "authz-epoch-rollback",
      "authz-epoch-duplicate",
      "authz-epoch-jump",
      "authz-epoch-first-jump",
      "create-env-commitment-uppercase-hex",
      "create-env-commitment-bad-length",
      "rotate-commitment-uppercase-hex",
      "create-env-commitment-format-precedes-role",
      "authz-field-too-long",
      "authz-scope-too-many",
      "authz-add-member-duplicate-key",
      "authz-add-member-duplicate-enc-key",
      "authz-add-member-duplicate-sig-key",
      "authz-add-member-duplicate-owner-key",
      "authz-add-member-role-precedes-duplicate-key",
      "authz-add-member-duplicate-user-precedes-key",
      "authz-actor-key-mismatch",
      "authz-checkpoint-reader-role",
      "authz-checkpoint-audit-role-insufficient",
      "authz-checkpoint-role-precedes-audit-role",
      "authz-checkpoint-unknown-environment",
      "authz-checkpoint-epoch-rollback",
      "authz-checkpoint-epoch-ahead",
      "authz-checkpoint-audit-role-precedes-unknown",
      "authz-checkpoint-unknown-precedes-epoch",
      "authz-checkpoint-regression",
      "authz-checkpoint-epoch-precedes-regression",
      "checkpoint-manifest-hash-uppercase-hex",
      "checkpoint-values-digest-bad-length",
      "checkpoint-audit-head-bad-length",
      "checkpoint-duplicate-environment",
      "checkpoint-manifest-version-zero",
      "checkpoint-format-precedes-role",
      "checkpoint-tampered-environments",
      "checkpoint-environments-flat-concat",
    ],
  },
  {
    label: "chain-entries.values_digests",
    actual: chainEntries.values_digests,
    expected: ["empty-set", "single-entry", "byte-ascending-order", "surrogate-boundary-order"],
  },
  {
    label: "checkpoint-digest.cases",
    actual: checkpointDigest.cases,
    expected: ["declared-excluded", "all-declared-empty"],
  },
  {
    label: "dek-commitment.vectors",
    actual: dekCommitment.vectors,
    expected: ["basic", "epoch-1-create"],
  },
  {
    label: "dek-commitment.negative",
    actual: dekCommitment.negative,
    expected: [
      "dek-mismatch",
      "transplant-project",
      "transplant-environment",
      "transplant-epoch",
      "wrong-domain",
      "uppercase-hex",
    ],
  },
  {
    label: "dek-wrap-signature.vectors",
    actual: dekWrapSignature.vectors,
    expected: ["basic", "server-basic"],
  },
  {
    label: "dek-wrap-signature.negative",
    actual: dekWrapSignature.negative,
    expected: [
      "tampered-signature",
      "tampered-ciphertext",
      "tampered-enc",
      "transplant-project",
      "transplant-environment",
      "transplant-epoch",
      "transplant-recipient",
      "recipient-key-mismatch",
      "wrong-signer-key",
      "transplant-signer",
      "suite-mismatch",
      "server-transplant-recipient-class",
      "server-transplant-fp",
      "server-recipient-key-mismatch",
    ],
  },
  {
    label: "dek-wrap.vectors",
    actual: dekWrap.vectors,
    expected: ["basic", "server-basic"],
  },
  {
    label: "dek-wrap.negative",
    actual: dekWrap.negative,
    expected: [
      "info-epoch-mismatch",
      "info-recipient-mismatch",
      "info-environment-mismatch",
      "enc-tampered",
      "server-info-member-user-id",
      "server-info-fp-mismatch",
      "member-info-server-fp",
    ],
  },
  {
    label: "encoding.cases",
    actual: encoding.cases,
    expected: [
      "ambiguity-ab-c",
      "ambiguity-a-bc",
      "empty-field",
      "empty-list",
      "utf8-multibyte",
      "number-decimal",
      "aad-shape-example",
    ],
  },
  {
    label: "env-manifest.digests",
    actual: envManifest.digests,
    expected: [
      "empty-set",
      "single-entry",
      "tombstone-entry",
      "byte-ascending-order",
      "surrogate-boundary-order",
      "declared-entry",
    ],
  },
  {
    label: "env-manifest.vectors",
    actual: envManifest.vectors,
    expected: [
      "manifest-v1-create",
      "manifest-rotate",
      "manifest-removed-issuer",
      "manifest-var-create",
      "manifest-var-rename",
      "manifest-var-delete",
    ],
  },
  {
    label: "env-manifest.manifest_fork.branches",
    actual: envManifest.manifest_fork.branches,
    expected: ["manifest-fork-a", "manifest-fork-b"],
  },
  {
    label: "env-manifest.negative",
    actual: envManifest.negative,
    expected: [
      "tampered-signature",
      "tampered-digest",
      "transplant-project",
      "transplant-environment",
      "transplant-issuer",
      "wrong-issuer-key",
      "chain-head-swap",
      "chain-head-seq-mismatch",
      "suite-mismatch",
      "head-not-in-chain",
      "head-beyond-local-seq",
      "issuer-removed-at-head",
      "issuer-role-insufficient",
      "key-from-other-tenure",
      "issuer-unknown-in-history",
      "environment-not-created-at-head",
      "epoch-not-current-at-head",
      "epoch-regression",
      "v1-nonempty-prev",
      "v2-empty-prev",
      "prev-hash-mismatch",
      "digest-variable-omitted",
      "digest-tombstone-omitted",
      "digest-order-swap",
      "env-meta-mismatch",
      "composite-head-without-checkpoint-create",
      "composite-head-without-checkpoint-rotate",
      "checkpoint-binding-mismatch",
      "checkpoint-equivocation",
      "checkpoint-regressed",
    ],
  },
  {
    label: "head-attestation.vectors",
    actual: headAttestation.vectors,
    expected: ["basic", "reader-attestation", "removed-attester-in-tenure"],
  },
  {
    label: "head-attestation.negative",
    actual: headAttestation.negative,
    expected: [
      "tampered-signature",
      "transplant-project",
      "transplant-attester",
      "wrong-attester-key",
      "head-seq-mismatch",
      "suite-mismatch",
      "head-not-in-chain",
      "head-beyond-local-seq",
      "attester-removed-at-head",
    ],
  },
  {
    label: "invite-accept-signature.vectors",
    actual: inviteAccept.vectors,
    expected: ["basic"],
  },
  {
    label: "invite-accept-signature.negative",
    actual: inviteAccept.negative,
    expected: [
      "tampered-signature",
      "transplant-token",
      "transplant-project",
      "transplant-invitee",
      "enc-key-mismatch",
      "sig-key-mismatch",
      "wrong-signer-key",
      "suite-mismatch",
    ],
  },
  {
    label: "lease-wrap.vectors",
    actual: leaseWrap.vectors,
    expected: ["basic", "prior-epoch"],
  },
  {
    label: "lease-wrap.negative",
    actual: leaseWrap.negative,
    expected: [
      "info-project-mismatch",
      "info-environment-mismatch",
      "info-epoch-mismatch",
      "info-claims-digest-mismatch",
      "info-dek-wrap-domain",
    ],
  },
  {
    label: "metadata-signature.vectors",
    actual: metaVectors.vectors,
    expected: [
      "var-create",
      "var-rename",
      "var-delete",
      "var-nfc-name",
      "env-create-meta",
      "env-rename",
      "env-delete-admin",
      "removed-author-in-tenure",
      "var-meta-head-before-env-create",
      "var-v2-create-typed",
      "var-v2-create-untyped",
      "var-v2-declared-create",
      "var-v2-activation",
      "var-v2-delete-keeps-schema",
    ],
  },
  {
    label: "metadata-signature.rename_fork.branches",
    actual: metaVectors.rename_fork.branches,
    expected: ["rename-fork-a", "rename-fork-b"],
  },
  {
    label: "metadata-signature.name_swap.statements",
    actual: metaVectors.name_swap.statements,
    expected: ["name-swap-var-a", "name-swap-var-b"],
  },
  {
    label: "metadata-signature.name_swap.swapped",
    actual: metaVectors.name_swap.swapped,
    expected: ["name-swap-a-to-b", "name-swap-b-to-a"],
  },
  {
    label: "metadata-signature.negative",
    actual: metaVectors.negative,
    expected: [
      "tampered-signature",
      "tampered-status",
      "transplant-project",
      "transplant-environment",
      "transplant-variable",
      "transplant-meta-version",
      "transplant-signer",
      "wrong-signer-key",
      "chain-head-swap",
      "chain-head-seq-mismatch",
      "tampered-prev-hash",
      "suite-mismatch",
      "nfc-variant",
      "env-transplant-environment",
      "cross-kind-transplant",
      "head-not-in-chain",
      "head-beyond-local-seq",
      "author-removed-at-head",
      "author-role-insufficient",
      "env-delete-role-insufficient",
      "key-from-other-tenure",
      "author-unknown-in-history",
      "v1-nonempty-prev",
      "v2-empty-prev",
      "prev-hash-mismatch",
      "revive-after-delete",
      "layout-confusion-v2-as-v1",
      "layout-confusion-v1-as-v2",
      "tampered-var-type",
      "tampered-required",
      "tampered-description",
      "v2-suite-mismatch",
      "declared-after-active",
      "declared-after-delete",
      "layout-regression-rename",
      "v1-declared-status",
      "v2-empty-required",
    ],
  },
  {
    label: "recovery-wrap.vectors",
    actual: recoveryWrap.vectors,
    expected: ["basic"],
  },
  {
    label: "recovery-wrap.negative",
    actual: recoveryWrap.negative,
    expected: ["aad-user-mismatch", "ciphertext-bit-flip", "wrong-salt"],
  },
  {
    label: "value-signature.vectors",
    actual: valueSignature.vectors,
    expected: [
      "v1-basic",
      "v2-chained",
      "create-head-inclusive",
      "removed-writer-in-tenure",
      "env-dev-v1",
      "rotate-head-reencryption",
    ],
  },
  {
    label: "value-signature.fork_same_version.branches",
    actual: valueSignature.fork_same_version.branches,
    expected: ["fork-branch-a", "fork-branch-b"],
  },
  {
    label: "value-signature.negative",
    actual: valueSignature.negative,
    expected: [
      "tampered-signature",
      "tampered-ciphertext",
      "tampered-nonce",
      "transplant-project",
      "transplant-environment",
      "transplant-epoch",
      "transplant-variable",
      "transplant-version",
      "transplant-signer",
      "wrong-signer-key",
      "chain-head-swap",
      "chain-head-seq-mismatch",
      "tampered-prev-hash",
      "suite-mismatch",
      "head-not-in-chain",
      "head-beyond-local-seq",
      "writer-role-insufficient",
      "writer-removed-at-head",
      "epoch-not-current-at-head",
      "head-before-environment-create",
      "key-from-other-tenure",
      "writer-unknown-in-history",
      "v1-nonempty-prev",
      "v2-empty-prev",
      "prev-hash-mismatch",
      "epoch-regression-across-versions",
    ],
  },
  {
    label: "variable-encryption.vectors",
    actual: variableEncryption.vectors,
    expected: ["basic"],
  },
  {
    label: "variable-encryption.negative",
    actual: variableEncryption.negative,
    expected: [
      "aad-environment-mismatch",
      "aad-epoch-mismatch",
      "ciphertext-bit-flip",
      "nonce-mismatch",
    ],
  },
];

// 名前を持たないが検査対象数として意味を持つコレクション(件数で固定)と、
// オブジェクトのキー集合で列挙されるコレクション(キー集合で固定)
const COUNTED_COLLECTIONS: readonly { label: string; actual: number; expected: number }[] = [
  { label: "chain-entries.entries", actual: chainEntries.entries.length, expected: 12 },
  {
    label: "chain-entries.expected_head_states",
    actual: chainEntries.expected_head_states.length,
    expected: 3,
  },
  { label: "audit-head.chain", actual: auditHeadVectors.chain.length, expected: 4 },
  { label: "hpke.rfc9180 vector groups", actual: rfc9180Vectors.length, expected: 1 },
];

const KEYED_COLLECTIONS: readonly {
  label: string;
  actual: readonly string[];
  expected: readonly string[];
}[] = [
  {
    label: "chain-entries.extended_chains",
    actual: Object.keys(chainEntries.extended_chains),
    expected: [
      "server-key-member-sock",
      "checkpoint-baseline",
      "checkpoint-boundary-create",
      "checkpoint-boundary-rotate",
      "checkpoint-boundary-equivocation",
    ],
  },
  {
    label: "chain-entries.keys",
    actual: Object.keys(chainEntries.keys),
    expected: ["user-owner-0001", "user-member-0002", "user-admin-0003"],
  },
  {
    label: "env-manifest.statements",
    actual: Object.keys(envManifest.statements),
    expected: [
      "api_key_v1",
      "api_key_v2_rename",
      "api_key_v3_delete",
      "env_meta_v1",
      "legacy_v1",
      "note",
    ],
  },
];

/** ソート後の完全一致(順序非依存)。不一致時は差分を detail に載せる。 */
function namesMatch(
  c: Checks,
  label: string,
  actual: readonly string[],
  expected: readonly string[],
): void {
  const a = actual.toSorted();
  const e = expected.toSorted();
  const ok = a.length === e.length && a.every((name, i) => name === e[i]);
  if (ok) {
    c.push(`vector inventory: ${label}`, true);
    return;
  }
  const actualSet = new Set(a);
  const expectedSet = new Set(e);
  const missing = e.filter((name) => !actualSet.has(name));
  const extra = a.filter((name) => !expectedSet.has(name));
  c.push(
    `vector inventory: ${label}`,
    false,
    `missing=[${missing.join(", ")}] extra=[${extra.join(", ")}] (dupes count toward both totals: actual ${a.length} vs expected ${e.length})`,
  );
}

export function vectorInventoryChecks(): CheckResult[] {
  const c = new Checks();
  for (const collection of NAMED_COLLECTIONS) {
    namesMatch(
      c,
      collection.label,
      collection.actual.map((entry) => entry.name),
      collection.expected,
    );
  }
  for (const counted of COUNTED_COLLECTIONS) {
    c.push(
      `vector inventory: ${counted.label} count`,
      counted.actual === counted.expected,
      counted.actual === counted.expected
        ? undefined
        : `actual ${counted.actual} vs expected ${counted.expected}`,
    );
  }
  for (const keyed of KEYED_COLLECTIONS) {
    namesMatch(c, keyed.label, keyed.actual, keyed.expected);
  }
  return c.results;
}
