// Checks for CRYPTO_SPEC §6 (positive): canonical byte strings, deterministic
// signatures, hash chaining, chain verification, and state derivation
// (expected_head_states).

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
  // In addition to the canonical 24 entries, the appended entries of
  // valid_appends / extended_chains pin canonicalization to the same level
  // (the checkpoint op never appears in the canonical chain, so byte-equality
  // of an appended entry is the only direct pin of checkpoint canonicalization)
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
  // WebCrypto Ed25519 is the RFC 8032 deterministic signature, so re-signing
  // with the vector's seed must match signature_hex exactly (pins
  // canonicalization + signing together). The device key entries of the derived
  // chains (device-ops — the signer is chosen by (user_id, FP)) are pinned to
  // the same level
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
    // The canonical chain deletes no environment (§6.2 — 2026-10-07)
    actual.deletedAtSeq === null &&
    seqsMatch &&
    commitmentsMatch
  );
}

function stateMatches(state: ChainState, expectedIndex: number): boolean {
  const expected = vectorHeadStates[expectedIndex];
  if (expected === undefined) {
    return false;
  }
  // The member set is role + scope (§6.2 — 2026-09-14 ES)
  const membersMatch = membersMatchVector(state.members, expected.members);
  // lease_policy (§6.2) is also part of the derived state (matches including order — as-signed order)
  const grantsMatch = serverGrantsMatchVector(state.serverGrants, expected.server_grants);
  // The environment set is chain-derived (§6.2): no environment absent from
  // the expectation may be derived (there is no default of "initial value 1 if
  // unobserved")
  const environmentsMatch =
    state.environments.size === Object.keys(expected.environments).length &&
    Object.entries(expected.environments).every(([environmentId, environment]) =>
      environmentMatches(state, environmentId, environment),
    );
  // Four-eyes (§6.2 — PF1): the policy (null = off) and pending proposals are also part of the derived state
  const approvalMatch =
    policyMatchesVector(state.approvalPolicy, expected.approval_policy) &&
    pendingMatchesVector(state.pendingProposals, expected.pending_proposals);
  return membersMatch && grantsMatch && environmentsMatch && approvalMatch;
}

async function verificationChecks(c: Checks): Promise<void> {
  // Verification of all entries (24) of the canonical chain + head info
  const full = await verifyChain(typedEntries);
  const lastVector = vectorEntries[vectorEntries.length - 1];
  c.push(
    "chain: full verification",
    full.ok &&
      full.value.headSeq === typedEntries.length &&
      full.value.headHashHex === lastVector?.entry_hash_hex,
  );

  // Each point of expected_head_states (prefix verification = the basis of incremental sync)
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
