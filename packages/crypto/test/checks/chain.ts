// CRYPTO_SPEC §6 のチェック(positive): 正規化バイト列・決定論的署名・
// ハッシュ連鎖・チェーン検証と状態導出(expected_head_states)。

import {
  canonicalChainEntryBytes,
  canonicalChainPayloadBytes,
  canonicalChainSignedBytes,
  type ChainState,
  computeChainEntryHash,
  importSigningKeyPair,
  signChainEntry,
  verifyChain,
} from "../../src/index.ts";
import {
  membersMatchVector,
  pendingMatchesVector,
  policyMatchesVector,
  serverGrantsMatchVector,
  toTypedEntry,
  typedEntries,
  vectorEntries,
  vectorExtendedChains,
  vectorHeadStates,
  vectorKeyFor,
  vectorValidAppends,
} from "./chain-vector.ts";
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

async function canonicalizationChecks(c: Checks): Promise<void> {
  // 正規 24 エントリに加えて valid_appends / extended_chains の追記エントリも
  // 同水準で正規化を固定する(checkpoint op は正規チェーンに現れないため、
  // 追記エントリのバイト一致が checkpoint 正規化の唯一の直接固定点になる)
  const labeled: readonly (readonly [string, (typeof vectorEntries)[number]])[] = [
    ...vectorEntries.map((vector) => [`chain seq ${vector.seq}`, vector] as const),
    ...vectorValidAppends.map(
      (append) => [`chain valid append ${append.name}`, append.entry] as const,
    ),
    ...Object.entries(vectorExtendedChains).flatMap(([name, extended]) =>
      extended.entries.map(
        (vector) => [`chain extended ${name} seq ${vector.seq}`, vector] as const,
      ),
    ),
  ];
  for (const [label, vector] of labeled) {
    const entry = toTypedEntry(vector);
    c.push(
      `${label}: payload bytes`,
      toHex(canonicalChainPayloadBytes(entry)) === vector.payload_bytes_hex,
    );
    c.push(
      `${label}: signed bytes`,
      toHex(canonicalChainSignedBytes(entry)) === vector.signed_bytes_hex,
    );
    c.push(
      `${label}: entry bytes`,
      toHex(canonicalChainEntryBytes(entry)) === vector.entry_bytes_hex,
    );
    c.push(`${label}: entry hash`, (await computeChainEntryHash(entry)) === vector.entry_hash_hex);
  }
}

async function deterministicSigningChecks(c: Checks): Promise<void> {
  // WebCrypto Ed25519 は RFC 8032 の決定論的署名なので、ベクターの seed で
  // 署名し直すと signature_hex が完全一致するはず(正規化 + 署名の同時固定)。
  // 派生チェーンの端末鍵エントリ(device-ops — 署名者は (user_id, FP) で選ぶ)も同水準で固定する
  const labeled: readonly (readonly [string, (typeof vectorEntries)[number]])[] = [
    ...vectorEntries.map((vector) => [`chain seq ${vector.seq}`, vector] as const),
    ...Object.entries(vectorExtendedChains).flatMap(([name, extended]) =>
      extended.entries.map(
        (vector) => [`chain extended ${name} seq ${vector.seq}`, vector] as const,
      ),
    ),
  ];
  for (const [label, vector] of labeled) {
    const keys = vectorKeyFor(vector.actor.user_id, vector.actor.key_fingerprint_hex);
    if (keys === undefined) {
      c.push(`${label}: deterministic re-sign`, false, "actor keys missing");
      continue;
    }
    const pair = await importSigningKeyPair({
      publicKey: fromHex(keys.sig_pub_hex),
      privateSeed: fromHex(keys.sig_sk_seed_hex),
    });
    if (!pair.ok) {
      c.push(`${label}: deterministic re-sign`, false, "key import failed");
      continue;
    }
    const { signatureHex: _ignored, ...unsigned } = toTypedEntry(vector);
    const signed = await signChainEntry({ entry: unsigned, signingKey: pair.value.privateKey });
    c.push(
      `${label}: deterministic re-sign matches vector`,
      signed.ok && signed.value.signatureHex === vector.signature_hex,
    );
  }
}

function environmentMatches(
  state: ChainState,
  environmentId: string,
  expected: (typeof vectorHeadStates)[number]["environments"][string],
): boolean {
  const actual = state.environments.get(environmentId);
  if (actual === undefined) {
    return false;
  }
  const seqsMatch =
    actual.epochStartSeqs.size === Object.keys(expected.epoch_start_seqs).length &&
    Object.entries(expected.epoch_start_seqs).every(
      ([epoch, seq]) => actual.epochStartSeqs.get(Number(epoch)) === seq,
    );
  const commitmentsMatch =
    actual.dekCommitments.size === Object.keys(expected.dek_commitments).length &&
    Object.entries(expected.dek_commitments).every(
      ([epoch, commitment]) => actual.dekCommitments.get(Number(epoch)) === commitment,
    );
  return (
    actual.currentEpoch === Number(expected.current_epoch) &&
    actual.createdAtSeq === expected.created_at_seq &&
    seqsMatch &&
    commitmentsMatch
  );
}

function stateMatches(state: ChainState, expectedIndex: number): boolean {
  const expected = vectorHeadStates[expectedIndex];
  if (expected === undefined) {
    return false;
  }
  // メンバー集合は role + scope(§6.2 — 2026-09-14 ES)
  const membersMatch = membersMatchVector(state.members, expected.members);
  // lease_policy(§6.2)も導出状態の一部(順序込みで一致 — as-signed 順)
  const grantsMatch = serverGrantsMatchVector(state.serverGrants, expected.server_grants);
  // 環境集合はチェーン導出(§6.2): 期待に無い環境が導出されてもならない
  // (「未観測なら初期値 1」の既定値は存在しない)
  const environmentsMatch =
    state.environments.size === Object.keys(expected.environments).length &&
    Object.entries(expected.environments).every(([environmentId, environment]) =>
      environmentMatches(state, environmentId, environment),
    );
  // 四眼(§6.2 — PF1): 方針(null = オフ)と pending 提案も導出状態の一部
  const approvalMatch =
    policyMatchesVector(state.approvalPolicy, expected.approval_policy) &&
    pendingMatchesVector(state.pendingProposals, expected.pending_proposals);
  return membersMatch && grantsMatch && environmentsMatch && approvalMatch;
}

async function verificationChecks(c: Checks): Promise<void> {
  // 正規チェーン全エントリ(24)の検証 + ヘッド情報
  const full = await verifyChain(typedEntries);
  const lastVector = vectorEntries[vectorEntries.length - 1];
  c.push(
    "chain: full verification",
    full.ok &&
      full.value.headSeq === typedEntries.length &&
      full.value.headHashHex === lastVector?.entry_hash_hex,
  );

  // expected_head_states の各時点(プレフィックス検証 = 差分同期の基礎)
  for (const [index, expected] of vectorHeadStates.entries()) {
    const prefix = typedEntries.slice(0, expected.after_seq);
    const result = await verifyChain(prefix);
    c.push(
      `chain: derived state after seq ${expected.after_seq}`,
      result.ok && stateMatches(result.value, index),
    );
  }
}

export async function chainChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  await canonicalizationChecks(c);
  await deterministicSigningChecks(c);
  await verificationChecks(c);
  return c.results;
}
