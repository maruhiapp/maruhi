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
import { testEnvironmentId } from "../support/fixture.ts";
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
  const actual = state.environments.get(testEnvironmentId(environmentId));
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
  const membersMatch = membersMatchVector(state.members, expected.members);
  const grantsMatch = serverGrantsMatchVector(state.serverGrants, expected.server_grants);
  const environmentsMatch =
    state.environments.size === Object.keys(expected.environments).length &&
    Object.entries(expected.environments).every(([environmentId, environment]) =>
      environmentMatches(state, environmentId, environment),
    );
  const approvalMatch =
    policyMatchesVector(state.approvalPolicy, expected.approval_policy) &&
    pendingMatchesVector(state.pendingProposals, expected.pending_proposals);
  return membersMatch && grantsMatch && environmentsMatch && approvalMatch;
}

async function verificationChecks(c: Checks): Promise<void> {
  const full = await verifyChain(typedEntries);
  const lastVector = vectorEntries[vectorEntries.length - 1];
  c.push(
    "chain: full verification",
    full.ok &&
      full.value.headSeq === typedEntries.length &&
      full.value.headHashHex === lastVector?.entry_hash_hex,
  );

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
