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
  serverGrantsMatchVector,
  toTypedEntry,
  typedEntries,
  vectorEntries,
  vectorHeadStates,
  vectorKeys,
} from "./chain-vector.ts";
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

async function canonicalizationChecks(c: Checks): Promise<void> {
  for (const vector of vectorEntries) {
    const entry = toTypedEntry(vector);
    c.push(
      `chain seq ${vector.seq}: payload bytes`,
      toHex(canonicalChainPayloadBytes(entry)) === vector.payload_bytes_hex,
    );
    c.push(
      `chain seq ${vector.seq}: signed bytes`,
      toHex(canonicalChainSignedBytes(entry)) === vector.signed_bytes_hex,
    );
    c.push(
      `chain seq ${vector.seq}: entry bytes`,
      toHex(canonicalChainEntryBytes(entry)) === vector.entry_bytes_hex,
    );
    c.push(
      `chain seq ${vector.seq}: entry hash`,
      (await computeChainEntryHash(entry)) === vector.entry_hash_hex,
    );
  }
}

async function deterministicSigningChecks(c: Checks): Promise<void> {
  // WebCrypto Ed25519 は RFC 8032 の決定論的署名なので、ベクターの seed で
  // 署名し直すと signature_hex が完全一致するはず(正規化 + 署名の同時固定)
  for (const vector of vectorEntries) {
    const keys = vectorKeys[vector.actor.user_id];
    if (keys === undefined) {
      c.push(`chain seq ${vector.seq}: deterministic re-sign`, false, "actor keys missing");
      continue;
    }
    const pair = await importSigningKeyPair({
      publicKey: fromHex(keys.sig_pub_hex),
      privateSeed: fromHex(keys.sig_sk_seed_hex),
    });
    if (!pair.ok) {
      c.push(`chain seq ${vector.seq}: deterministic re-sign`, false, "key import failed");
      continue;
    }
    const { signatureHex: _ignored, ...unsigned } = toTypedEntry(vector);
    const signed = await signChainEntry({ entry: unsigned, signingKey: pair.value.privateKey });
    c.push(
      `chain seq ${vector.seq}: deterministic re-sign matches vector`,
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
  const membersMatch =
    state.members.size === Object.keys(expected.members).length &&
    Object.entries(expected.members).every(
      ([userId, role]) => state.members.get(userId)?.role === role,
    );
  // lease_policy(§6.2)も導出状態の一部(順序込みで一致 — as-signed 順)
  const grantsMatch = serverGrantsMatchVector(state.serverGrants, expected.server_grants);
  // 環境集合はチェーン導出(§6.2): 期待に無い環境が導出されてもならない
  // (「未観測なら初期値 1」の廃止 — 2026-08-03)
  const environmentsMatch =
    state.environments.size === Object.keys(expected.environments).length &&
    Object.entries(expected.environments).every(([environmentId, environment]) =>
      environmentMatches(state, environmentId, environment),
    );
  return membersMatch && grantsMatch && environmentsMatch;
}

async function verificationChecks(c: Checks): Promise<void> {
  // 正規チェーン全エントリ(12)の検証 + ヘッド情報
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
