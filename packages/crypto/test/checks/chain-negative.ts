// Checks for CRYPTO_SPEC §6 (negatives + boundary positives): tampering,
// transplanting, reordering (must_fail), authorization vectors (valid
// signatures rejected by the §6.2 rules), framing and semantic verification
// failures, and the permissive-side boundaries of the consensus rules
// (valid_appends).

import {
  canonicalChainSignedBytes,
  type ChainEntry,
  type ChainState,
  computeChainEntryHash,
  type CryptoResult,
  type EnvironmentChainState,
  importSigningKeyPair,
  signChainEntry,
  type UnsignedChainEntry,
  verifyChain,
} from "../../src/index.ts";
import { testUserId } from "../support/fixture.ts";
import {
  membersMatchVector,
  pendingMatchesVector,
  policyMatchesVector,
  toTypedEntry,
  typedEntries,
  serverGrantsMatchVector,
  type VectorCheckpointState,
  type VectorMemberState,
  vectorEntries,
  vectorEnvironmentDeks,
  vectorExtendedChains,
  vectorKeys,
  vectorNegatives,
  vectorValidAppends,
} from "./chain-vector.ts";
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

function failsWith(result: CryptoResult<ChainState>, seq: number, reason: string): boolean {
  return (
    !result.ok &&
    result.error.kind === "ChainInvalid" &&
    result.error.seq === seq &&
    result.error.reason === reason
  );
}

function entryAt(seq: number): ChainEntry {
  const entry = typedEntries[seq - 1];
  if (entry === undefined) {
    throw new Error(`chain vector entry seq ${seq} missing`);
  }
  return entry;
}

function negativeByName(name: string) {
  return vectorNegatives.find((n) => n.name === name);
}

/** Vector-fixed keys (missing = fixture corruption → throw. Same convention as entryAt). */
function keysOf(userId: string) {
  const keys = vectorKeys[userId];
  if (keys === undefined) {
    throw new Error(`chain vector keys for ${userId} missing`);
  }
  return keys;
}

interface TamperVariant {
  readonly name: string;
  readonly entry: ChainEntry;
  readonly expect: string;
  /** The base entry's derived chain (an extended_chains key; unset = the canonical chain). */
  readonly chain?: string;
}

/** The vector entry of the expected op (mismatch = fixture corruption → throw). */
function entryOfOp<K extends ChainEntry["op"]>(seq: number, op: K): ChainEntry & { op: K } {
  const entry = entryAt(seq);
  if (entry.op !== op) {
    throw new Error(`chain vector seq ${seq}: expected ${op}, got ${entry.op}`);
  }
  return entry as ChainEntry & { op: K };
}

/** The expected-op entry of a derived chain (mismatch/missing = fixture corruption → throw). */
function extendedEntryOfOp<K extends ChainEntry["op"]>(
  chainName: string,
  seq: number,
  op: K,
): ChainEntry & { op: K } {
  const raw = vectorExtendedChains[chainName]?.entries.find((entry) => entry.seq === seq);
  if (raw === undefined) {
    throw new Error(`chain vector extended entry ${chainName}#${seq} missing`);
  }
  const entry = toTypedEntry(raw);
  if (entry.op !== op) {
    throw new Error(`chain vector ${chainName}#${seq}: expected ${op}, got ${entry.op}`);
  }
  return entry as ChainEntry & { op: K };
}

/** Prefix of a derived chain up to just before seq (base + derived entries below seq). */
function extendedPrefix(chainName: string, seq: number): readonly ChainEntry[] {
  const extended = vectorExtendedChains[chainName];
  if (extended === undefined) {
    throw new Error(`chain vector extended chain ${chainName} missing`);
  }
  return [
    ...typedEntries.slice(0, extended.base_seq),
    ...extended.entries.filter((entry) => entry.seq < seq).map((entry) => toTypedEntry(entry)),
  ];
}

/** The vector's (environment, epoch) commitment (missing = fixture corruption → throw). */
function vectorCommitmentOf(environmentId: string, epoch: number): string {
  const commitment = vectorEnvironmentDeks[environmentId]?.[String(epoch)]?.dek_commitment_hex;
  if (commitment === undefined) {
    throw new Error(`chain vector environment_deks missing ${environmentId}#${epoch}`);
  }
  return commitment;
}

/** Typed variants with tampered payloads; the canonical bytes should match the vector negatives */
function payloadTamperVariants(): readonly TamperVariant[] {
  const e2 = entryOfOp(2, "add_member");
  const eChange = entryOfOp(7, "change_role");
  const eGrant = entryOfOp(9, "grant_server");
  const eRotate = entryOfOp(10, "rotate_epoch");
  const eCreate = entryOfOp(11, "create_environment");
  const eRevoke = entryOfOp(12, "revoke_server");
  const flipped = fromHex(eRevoke.payload.serverKeyFingerprintHex);
  flipped[0] = (flipped[0] ?? 0) ^ 0x01;
  const freshCommitment = vectorCommitmentOf("env-fresh-0004", 1);
  const prodCommitment = vectorCommitmentOf("env-prod-0001", 2);
  return [
    ...legacyPayloadTamperVariants(
      e2,
      eChange,
      eGrant,
      eRotate,
      eCreate,
      eRevoke,
      flipped,
      freshCommitment,
      prodCommitment,
    ),
    ...scopeAndApprovalTamperVariants(),
    ...deviceTamperVariants(),
  ];
}

/** The unregistered dummy enc public key that add-device-tampered-enc-pub substitutes (matches the vector payload). */
const FRESH_DEVICE_ENC_PUB_HEX = "1349ac6a06c18c9fb1cc6f15b1907ca645b45fe524716d690bb29f354dffa76e";

/** Payload-tampered variants for DK (device keys — 2026-09-19) (based on seq 25 / 27 / 35 / 37 of the derived chain device-ops). */
function deviceTamperVariants(): readonly TamperVariant[] {
  const chain = "device-ops";
  const eReserve = extendedEntryOfOp(chain, 25, "add_device");
  const eCiBox = extendedEntryOfOp(chain, 27, "add_device");
  const eRevokeSelf = extendedEntryOfOp(chain, 35, "revoke_device");
  const eRevokeOther = extendedEntryOfOp(chain, 37, "revoke_device");
  return [
    // cap (role_cap / scope) is signed — guards against relabeling the cap
    {
      name: "add-device-tampered-role-cap",
      entry: { ...eCiBox, payload: { ...eCiBox.payload, roleCap: "owner" } },
      expect: "bad-signature",
      chain,
    },
    {
      name: "add-device-scope-relabel-all",
      entry: {
        ...eCiBox,
        payload: { ...eCiBox.payload, scopeKind: "all", scopeEnvironmentIds: [] },
      },
      expect: "bad-signature",
      chain,
    },
    // The order of a device scope's nested LP is also signed (same shape as
    // add_member's scope)
    {
      name: "add-device-scope-reorder",
      entry: {
        ...eCiBox,
        payload: {
          ...eCiBox.payload,
          scopeEnvironmentIds: eCiBox.payload.scopeEnvironmentIds.toReversed(),
        },
      },
      expect: "bad-signature",
      chain,
    },
    // The registered key is signed (guards against a server swapping the
    // key)
    {
      name: "add-device-tampered-enc-pub",
      entry: { ...eReserve, payload: { ...eReserve.payload, encPubHex: FRESH_DEVICE_ENC_PUB_HEX } },
      expect: "bad-signature",
      chain,
    },
    // The order of the revocation FP list is also signed (generators SHOULD
    // emit ascending; verification is set-based)
    {
      name: "revoke-device-fp-reorder",
      entry: {
        ...eRevokeSelf,
        payload: {
          ...eRevokeSelf.payload,
          deviceFingerprintsHex: eRevokeSelf.payload.deviceFingerprintsHex.toReversed(),
        },
      },
      expect: "bad-signature",
      chain,
    },
    {
      name: "revoke-device-tampered-target",
      entry: {
        ...eRevokeOther,
        payload: { ...eRevokeOther.payload, targetUserId: testUserId("user-owner-0015") },
      },
      expect: "bad-signature",
      chain,
    },
  ];
}

/** Payload-tampered variants for ES (scope) / PF1 (four-eyes) (2026-09-14 — based on canonical seq 13-22). */
function scopeAndApprovalTamperVariants(): readonly TamperVariant[] {
  const eDevMember = entryOfOp(13, "add_member");
  const eDevAdmin = entryOfOp(14, "add_member");
  const eWiden = entryOfOp(17, "change_role");
  const ePolicy = entryOfOp(20, "set_approval_policy");
  const ePropose = entryOfOp(21, "propose");
  const eApprove = entryOfOp(22, "approve");
  const inner = ePropose.payload.inner;
  if (inner.op !== "change_role") {
    throw new Error("chain vector seq 21: inner op must be change_role");
  }
  const flippedHash = fromHex(eApprove.payload.proposalHashHex);
  flippedHash[0] = (flippedHash[0] ?? 0) ^ 0x01;
  return [
    // The order of scope_environments is also signed (nested LP — same
    // shape as grant_server's scope)
    {
      name: "add-member-scope-reorder",
      entry: {
        ...eDevAdmin,
        payload: {
          ...eDevAdmin.payload,
          scopeEnvironmentIds: eDevAdmin.payload.scopeEnvironmentIds.toReversed(),
        },
      },
      expect: "bad-signature",
    },
    // Relabeling scope_kind (listed{dev} → all) relabels the granted range
    // = signature failure
    {
      name: "add-member-scope-relabel-all",
      entry: {
        ...eDevMember,
        payload: { ...eDevMember.payload, scopeKind: "all", scopeEnvironmentIds: [] },
      },
      expect: "bad-signature",
    },
    {
      name: "change-role-tampered-scope",
      entry: { ...eWiden, payload: { ...eWiden.payload, scopeEnvironmentIds: ["env-dev-0002"] } },
      expect: "bad-signature",
    },
    // The order of ops is also signed (generators SHOULD emit ascending;
    // verification is set-based)
    {
      name: "policy-ops-reorder",
      entry: { ...ePolicy, payload: { ...ePolicy.payload, ops: ePolicy.payload.ops.toReversed() } },
      expect: "bad-signature",
    },
    {
      name: "policy-tampered-required",
      entry: { ...ePolicy, payload: { ...ePolicy.payload, requiredApprovals: 3 } },
      expect: "bad-signature",
    },
    // The inner payload (inner_payload_lp_hex) and the expiry are signed
    {
      name: "propose-tampered-inner-payload",
      entry: {
        ...ePropose,
        payload: {
          ...ePropose.payload,
          inner: { op: "change_role", payload: { ...inner.payload, newRole: "member" } },
        },
      },
      expect: "bad-signature",
    },
    {
      name: "propose-tampered-expires",
      entry: {
        ...ePropose,
        payload: { ...ePropose.payload, expiresAtMs: ePropose.payload.expiresAtMs + 1 },
      },
      expect: "bad-signature",
    },
    {
      name: "approve-tampered-hash",
      entry: { ...eApprove, payload: { proposalHashHex: toHex(flippedHash) } },
      expect: "bad-signature",
    },
  ];
}

function legacyPayloadTamperVariants(
  e2: ChainEntry & { op: "add_member" },
  eChange: ChainEntry & { op: "change_role" },
  eGrant: ChainEntry & { op: "grant_server" },
  eRotate: ChainEntry & { op: "rotate_epoch" },
  eCreate: ChainEntry & { op: "create_environment" },
  eRevoke: ChainEntry & { op: "revoke_server" },
  flipped: Uint8Array,
  freshCommitment: string,
  prodCommitment: string,
): readonly TamperVariant[] {
  return [
    {
      name: "tampered-payload-role",
      entry: { ...e2, payload: { ...e2.payload, role: "admin" } },
      expect: "bad-signature",
    },
    {
      name: "grant-server-scope-reorder",
      entry: {
        ...eGrant,
        payload: {
          ...eGrant.payload,
          scopeEnvironmentIds: eGrant.payload.scopeEnvironmentIds.toReversed(),
        },
      },
      expect: "bad-signature",
    },
    // The order of lease_policy (both elements and constraints) is also
    // signed (§6.2)
    {
      name: "grant-server-lease-policy-reorder",
      entry: {
        ...eGrant,
        payload: { ...eGrant.payload, leasePolicy: eGrant.payload.leasePolicy.toReversed() },
      },
      expect: "bad-signature",
    },
    {
      name: "grant-server-lease-claims-reorder",
      entry: {
        ...eGrant,
        payload: {
          ...eGrant.payload,
          leasePolicy: eGrant.payload.leasePolicy.map((element, index) =>
            index === 0
              ? { ...element, claimConstraints: element.claimConstraints.toReversed() }
              : element,
          ),
        },
      },
      expect: "bad-signature",
    },
    {
      name: "change-role-tampered-new-role",
      entry: { ...eChange, payload: { ...eChange.payload, newRole: "owner" } },
      expect: "bad-signature",
    },
    {
      name: "revoke-server-tampered-fp",
      entry: { ...eRevoke, payload: { serverKeyFingerprintHex: toHex(flipped) } },
      expect: "bad-signature",
    },
    // dek_commitment_hex is also signed (§5.2): substitution fails
    // verification
    {
      name: "create-env-tampered-commitment",
      entry: { ...eCreate, payload: { ...eCreate.payload, dekCommitmentHex: freshCommitment } },
      expect: "bad-signature",
    },
    {
      name: "rotate-tampered-commitment",
      entry: { ...eRotate, payload: { ...eRotate.payload, dekCommitmentHex: prodCommitment } },
      expect: "bad-signature",
    },
  ];
}

/** Variants with the signature / prev_hash substituted (payload untouched) */
function headerTamperVariants(): readonly TamperVariant[] {
  const e3 = entryAt(3);
  return [
    {
      name: "wrong-signer",
      entry: { ...e3, signatureHex: negativeByName("wrong-signer")?.signature_hex ?? "" },
      expect: "bad-signature",
    },
    {
      name: "prev-hash-mismatch",
      entry: {
        ...e3,
        prevHashHex: negativeByName("prev-hash-mismatch")?.claimed_prev_hash_hex ?? "",
      },
      expect: "bad-prev-hash",
    },
  ];
}

/**
 * Coverage guard for kind-less (crypto-verification) negatives: when vector
 * regeneration adds new negatives, pins that every name belongs to the
 * covered set so that the name-hardcoded checks (payloadTamperVariants etc.)
 * do not silently drop the newcomers.
 */
function tamperCoverageCheck(c: Checks, covered: ReadonlySet<string>): void {
  // The kind vocabulary has only two values: undefined (crypto-verification
  // — the coverage target of this function) and "authorization" (the
  // authorization sweeps of crypto / server cover every one). A third kind
  // would quietly escape both sieves, so pin the vocabulary itself
  const unknownKinds = vectorNegatives
    .filter((negative) => negative.kind !== undefined && negative.kind !== "authorization")
    .map((negative) => negative.name);
  c.push(
    "chain negative: kind vocabulary is fixed",
    unknownKinds.length === 0,
    unknownKinds.length === 0 ? undefined : `unknown kind: ${unknownKinds.join(", ")}`,
  );
  const uncovered = vectorNegatives
    .filter((negative) => negative.kind === undefined)
    .map((negative) => negative.name)
    .filter((name) => !covered.has(name));
  c.push(
    "chain negative: every non-authorization vector is covered",
    uncovered.length === 0,
    uncovered.length === 0 ? undefined : `uncovered: ${uncovered.join(", ")}`,
  );
}

async function tamperedChecks(c: Checks): Promise<void> {
  const payloadVariants = payloadTamperVariants();
  const headerVariants = headerTamperVariants();
  tamperCoverageCheck(
    c,
    new Set([
      ...payloadVariants.map((variant) => variant.name),
      ...headerVariants.map((variant) => variant.name),
      // The 12 covered by bytesLevelChecks (byte strings this implementation
      // cannot produce)
      ...BYTES_LEVEL_NEGATIVES,
      // The 1 covered by checkpointTamperChecks (based on a derived-chain
      // entry)
      "checkpoint-tampered-environments",
    ]),
  );
  for (const variant of [...payloadVariants, ...headerVariants]) {
    const vector = negativeByName(variant.name);
    if (vector === undefined) {
      c.push(`chain negative: ${variant.name}`, false, "vector missing");
      continue;
    }
    // For payload tampering, also confirm the post-tamper canonical byte
    // string matches the vector
    const canonicalMatches =
      vector.signed_bytes_hex === undefined ||
      variant.name === "wrong-signer" ||
      toHex(canonicalChainSignedBytes(variant.entry)) === vector.signed_bytes_hex;
    const prefix =
      variant.chain === undefined
        ? typedEntries.slice(0, variant.entry.seq - 1)
        : extendedPrefix(variant.chain, variant.entry.seq);
    const result = await verifyChain([...prefix, variant.entry]);
    c.push(
      `chain negative: ${variant.name}`,
      canonicalMatches && failsWith(result, variant.entry.seq, variant.expect),
    );
  }
}

/** Base entry of a bytes-level negative (chain-tagged ones are pulled from the derived chain). */
function bytesLevelBaseEntry(chainName: string | undefined, baseSeq: number): ChainEntry {
  if (chainName === undefined) {
    return entryAt(baseSeq);
  }
  const extended = vectorExtendedChains[chainName];
  const raw = extended?.entries.find((entry) => entry.seq === baseSeq);
  if (raw === undefined) {
    throw new Error(`chain vector extended entry ${chainName}#${baseSeq} missing`);
  }
  return toTypedEntry(raw);
}

// Byte strings that break canonicalization order / nested LP (this
// implementation cannot produce them):
// lease-policy-flat-concat flattens a 3-level nest; lease-policy-dropped is
// the old 3-field form (pins that the 4-field form is canonical — §6.2);
// checkpoint-environments-flat-concat flattens the environment tuples'
// nested LP (§6.2).
// 2026-09-14 ES / PF1: *-scope-dropped are old forms lacking the 2 scope
// fields (pins that the new form is canonical — no compatibility
// acceptance); *-flat-concat flatten the scope / ops nested LP;
// propose-inner-payload-flat splices the inner payload into the outer LP.
// 2026-09-19 DK: add-device-scope-flat-concat / revoke-device-fp-flat-concat
// flatten the device-scope / revocation-FP-list nested LP (based on the
// derived chain device-ops)
const BYTES_LEVEL_NEGATIVES: readonly string[] = [
  "field-order-swap",
  "grant-server-scope-flat-concat",
  "grant-server-lease-policy-flat-concat",
  "grant-server-lease-policy-dropped",
  "checkpoint-environments-flat-concat",
  "add-member-scope-dropped",
  "change-role-scope-dropped",
  "add-member-scope-flat-concat",
  "policy-ops-flat-concat",
  "propose-inner-payload-flat",
  "add-device-scope-flat-concat",
  "revoke-device-fp-flat-concat",
];

async function bytesLevelChecks(c: Checks): Promise<void> {
  // Confirm the broken byte string differs from the canonical bytes and
  // that the original signature does not verify either
  for (const name of BYTES_LEVEL_NEGATIVES) {
    const vector = negativeByName(name);
    if (
      vector?.signed_bytes_hex === undefined ||
      vector.signature_hex === undefined ||
      vector.verify_key_hex === undefined ||
      vector.base_seq === undefined
    ) {
      c.push(`chain negative: ${name}`, false, "vector missing");
      continue;
    }
    const base = bytesLevelBaseEntry(vector.chain, vector.base_seq);
    const canonicalDiffers = toHex(canonicalChainSignedBytes(base)) !== vector.signed_bytes_hex;
    const key = await crypto.subtle.importKey(
      "raw",
      fromHex(vector.verify_key_hex) as BufferSource,
      "Ed25519",
      false,
      ["verify"],
    );
    const signatureRejected = !(await crypto.subtle.verify(
      "Ed25519",
      key,
      fromHex(vector.signature_hex) as BufferSource,
      fromHex(vector.signed_bytes_hex) as BufferSource,
    ));
    c.push(`chain negative: ${name}`, canonicalDiffers && signatureRejected);
  }
}

/**
 * checkpoint payload-tamper negative: based on seq 13 of the derived chain
 * (checkpoint-baseline), pins that the canonical bytes of a typed variant
 * with the environment tuple's manifest_version rewritten match the vector
 * and that the original signature gives bad-signature (the derived-chain
 * counterpart of payloadTamperVariants — the canonical 12 entries contain
 * no checkpoint op, so the base is pulled via the vector's chain field).
 */
async function checkpointTamperChecks(c: Checks): Promise<void> {
  const name = "checkpoint-tampered-environments";
  const vector = negativeByName(name);
  const extended = vectorExtendedChains["checkpoint-baseline"];
  const rawBase = extended?.entries.find((entry) => entry.seq === vector?.base_seq);
  if (vector?.payload === undefined || extended === undefined || rawBase === undefined) {
    c.push(`chain negative: ${name}`, false, "vector missing");
    return;
  }
  const tampered = toTypedEntry({ ...rawBase, payload: vector.payload });
  const canonicalMatches =
    vector.signed_bytes_hex !== undefined &&
    toHex(canonicalChainSignedBytes(tampered)) === vector.signed_bytes_hex;
  const result = await verifyChain([...typedEntries.slice(0, extended.base_seq), tampered]);
  c.push(
    `chain negative: ${name}`,
    canonicalMatches && failsWith(result, tampered.seq, "bad-signature"),
  );
}

/** Prerequisite chain of an authorization negative: the canonical prefix or an extended_chains derived chain. */
function authzPrefix(chainName: string | undefined, seq: number): readonly ChainEntry[] {
  if (chainName === undefined) {
    return typedEntries.slice(0, seq - 1);
  }
  const extended = vectorExtendedChains[chainName];
  if (extended === undefined) {
    throw new Error(`chain vector extended chain ${chainName} missing`);
  }
  return [
    ...typedEntries.slice(0, extended.base_seq),
    ...extended.entries.map((entry) => toTypedEntry(entry)),
  ];
}

async function authorizationChecks(c: Checks): Promise<void> {
  // kind = "authorization": signature and chaining are valid; must be
  // rejected only by the §6.2 authorization rules
  for (const vector of vectorNegatives) {
    if (vector.kind !== "authorization" || vector.entry === undefined) {
      continue;
    }
    const entry = toTypedEntry(vector.entry);
    const prefix = authzPrefix(vector.chain, entry.seq);
    const result = await verifyChain([...prefix, entry]);
    c.push(
      `chain authz: ${vector.name}`,
      failsWith(result, entry.seq, vector.expected_reason ?? ""),
    );
  }
}

async function extendedChainChecks(c: Checks): Promise<void> {
  // extended_chains: the derived chain itself is accepted (the permissive
  // boundary). server-key-member-sock pins the §6.2 line that "add_member's
  // key-uniqueness index covers only current members' keys; active-grant
  // server keys are out of scope". checkpoint-baseline pins a legitimate
  // re-notarization at the same manifest_version (the equality side of
  // non-regression) and the "latest checkpoint per environment" derivation
  // (expected_checkpoints). The four-eyes family (proposal-* / stale-* /
  // proposer-* / policy-*) pins the derived state of the policy, pending
  // proposals, and vote re-tallying (votes of departed voters are not
  // counted — principle 2)
  for (const [name, extended] of Object.entries(vectorExtendedChains)) {
    const chain = [
      ...typedEntries.slice(0, extended.base_seq),
      ...extended.entries.map((entry) => toTypedEntry(entry)),
    ];
    const result = await verifyChain(chain);
    c.push(
      `chain extended: ${name} verifies`,
      result.ok &&
        membersMatch(result.value, extended.expected_members) &&
        checkpointsMatch(result.value, extended.expected_checkpoints) &&
        policyMatchesVector(result.value.approvalPolicy, extended.expected_policy) &&
        pendingMatchesVector(result.value.pendingProposals, extended.expected_pending),
    );
  }
}

async function framingChecks(c: Checks): Promise<void> {
  const e1 = entryAt(1);
  c.push("chain framing: empty chain", failsWith(await verifyChain([]), 0, "empty-chain"));
  c.push(
    "chain framing: bad suite",
    failsWith(await verifyChain([{ ...e1, suite: "maruhi/v0" }]), 1, "bad-suite"),
  );
  c.push("chain framing: seq gap", failsWith(await verifyChain([e1, entryAt(3)]), 2, "bad-seq"));
  const secondGenesis: ChainEntry = { ...e1, seq: 2, prevHashHex: "0".repeat(64) };
  c.push(
    "chain framing: genesis only at seq 1",
    failsWith(await verifyChain([e1, secondGenesis]), 2, "bad-genesis"),
  );
  c.push(
    "chain framing: non-genesis head",
    failsWith(await verifyChain([{ ...entryAt(2), seq: 1 }]), 1, "bad-genesis"),
  );
}

async function signAs(userId: string, entry: UnsignedChainEntry): Promise<ChainEntry | undefined> {
  const keys = vectorKeys[userId];
  if (keys === undefined) {
    return undefined;
  }
  const pair = await importSigningKeyPair({
    publicKey: fromHex(keys.sig_pub_hex),
    privateSeed: fromHex(keys.sig_sk_seed_hex),
  });
  if (!pair.ok) {
    return undefined;
  }
  const signed = await signChainEntry({ entry, signingKey: pair.value.privateKey });
  return signed.ok ? signed.value : undefined;
}

/** seq of an append entry following the canonical chain end (seq 24). */
const NEXT_SEQ = typedEntries.length + 1;

function nextEntryBase(): Omit<UnsignedChainEntry, "op" | "payload"> {
  const head = entryAt(typedEntries.length);
  const owner = vectorKeys["user-owner-0001"];
  if (owner === undefined) {
    throw new Error("owner keys missing");
  }
  return {
    suite: "maruhi/v1",
    seq: NEXT_SEQ,
    // prev is the vector's final-entry hash (already pinned by the
    // chain.ts positives)
    prevHashHex: "",
    actor: { userId: testUserId("user-owner-0001"), keyFingerprintHex: owner.key_fingerprint_hex },
    timestampMs: head.timestampMs + 1000,
  };
}

/** A formally valid commitment for entries appended inside the test (the content is the §5.2 comparison target; chain verification checks form only). */
const DUMMY_COMMITMENT_HEX = "ab".repeat(32);

type SemanticBase = Omit<UnsignedChainEntry, "op" | "payload">;

function semanticCases(
  base: SemanticBase,
): readonly { name: string; entry: UnsignedChainEntry; expect: string }[] {
  const memberKeys = keysOf("user-member-0002");
  const ownerKeys = keysOf("user-owner-0001");
  return [
    {
      name: "grant_server with mismatched fingerprint",
      entry: {
        ...base,
        op: "grant_server",
        payload: {
          serverEncPubHex: memberKeys.enc_pub_hex,
          serverKeyFingerprintHex: memberKeys.key_fingerprint_hex,
          scopeEnvironmentIds: ["env-prod-0001"],
          leasePolicy: [],
        },
      },
      expect: "invalid-payload",
    },
    {
      name: "add_member duplicate",
      entry: {
        ...base,
        op: "add_member",
        payload: {
          targetUserId: testUserId("user-admin-0003"),
          encPubHex: memberKeys.enc_pub_hex,
          sigPubHex: memberKeys.sig_pub_hex,
          role: "reader",
          scopeKind: "all",
          scopeEnvironmentIds: [],
        },
      },
      expect: "duplicate-member",
    },
    {
      // Pin the check order (§6.2): when both the target user_id and the
      // key are duplicates, the user_id duplicate (duplicate-member) is
      // judged before the key duplicate (duplicate-member-key) (reusing the
      // owner's full key set still reports duplicate-member)
      name: "add_member duplicate user id wins over duplicate key",
      entry: {
        ...base,
        op: "add_member",
        payload: {
          targetUserId: testUserId("user-admin-0003"),
          encPubHex: ownerKeys.enc_pub_hex,
          sigPubHex: ownerKeys.sig_pub_hex,
          role: "reader",
          scopeKind: "all",
          scopeEnvironmentIds: [],
        },
      },
      expect: "duplicate-member",
    },
    {
      name: "remove_member unknown target",
      entry: {
        ...base,
        op: "remove_member",
        payload: { targetUserId: testUserId("user-ghost-9999") },
      },
      expect: "unknown-target",
    },
    {
      name: "revoke_server without active grant",
      entry: {
        ...base,
        op: "revoke_server",
        payload: { serverKeyFingerprintHex: "00112233445566778899aabbccddeeff" },
      },
      expect: "unknown-server-grant",
    },
  ];
}

async function appendRotation(
  base: SemanticBase,
  environmentId: string,
  newEpoch: number,
): Promise<ChainState | undefined> {
  const rotate = await signAs("user-admin-0003", {
    ...base,
    actor: {
      userId: testUserId("user-admin-0003"),
      keyFingerprintHex: vectorKeys["user-admin-0003"]?.key_fingerprint_hex ?? "",
    },
    op: "rotate_epoch",
    payload: {
      environmentId,
      newEpoch,
      reason: "scheduled",
      dekCommitmentHex: DUMMY_COMMITMENT_HEX,
    },
  });
  if (rotate === undefined) {
    return undefined;
  }
  const result = await verifyChain([...typedEntries, rotate]);
  return result.ok ? result.value : undefined;
}

/** Whether the derived member set matches the expectation (user_id → role + scope). */
function membersMatch(
  state: ChainState,
  expected: Readonly<Record<string, VectorMemberState>>,
): boolean {
  return membersMatchVector(state.members, expected);
}

/**
 * Whether the derived latest-checkpoint set matches the expectation (§6.2
 * derived state — vectors without expected_checkpoints pass as out of
 * scope).
 */
function checkpointsMatch(
  state: ChainState,
  expected: Readonly<Record<string, VectorCheckpointState>> | undefined,
): boolean {
  if (expected === undefined) {
    return true;
  }
  return (
    state.checkpoints.size === Object.keys(expected).length &&
    Object.entries(expected).every(([environmentId, checkpoint]) => {
      const actual = state.checkpoints.get(environmentId);
      return (
        actual !== undefined &&
        actual.seq === checkpoint.seq &&
        actual.epoch === Number(checkpoint.epoch) &&
        actual.manifestVersion === Number(checkpoint.manifest_version) &&
        actual.manifestSigHashHex === checkpoint.manifest_sig_hash_hex &&
        actual.valuesDigestHex === checkpoint.values_digest_hex
      );
    })
  );
}

/** Whether the derived environment set matches the expectation (environment_id → current epoch). */
function environmentsMatch(state: ChainState, expected: Readonly<Record<string, string>>): boolean {
  return (
    state.environments.size === Object.keys(expected).length &&
    Object.entries(expected).every(
      ([environmentId, epoch]) =>
        state.environments.get(environmentId)?.currentEpoch === Number(epoch),
    )
  );
}

/** Whether the derived active-grant set matches the expectation (including scope + lease_policy). */
function serverGrantsMatch(
  state: ChainState,
  expected: Parameters<typeof serverGrantsMatchVector>[1],
): boolean {
  return serverGrantsMatchVector(state.serverGrants, expected);
}

/** One valid_appends entry: appended onto the attach-point head, pin acceptance and the derived state (all axes). */
async function validAppendVectorCheck(
  c: Checks,
  append: (typeof vectorValidAppends)[number],
): Promise<void> {
  const entry = toTypedEntry(append.entry);
  // The attach point is right after the canonical entry (or derived-chain
  // head) that the entry's seq points to (seq 25 = the terminal head, seq 10
  // = a re-grant append onto the seq-9 head — regrant-lease-policy-revised,
  // seq 20 = an append onto the pre-policy head 19)
  const result = await verifyChain([...authzPrefix(append.chain, entry.seq), entry]);
  c.push(
    `chain valid append: ${append.name}`,
    result.ok &&
      membersMatch(result.value, append.expected_members) &&
      environmentsMatch(result.value, append.expected_environments) &&
      serverGrantsMatch(result.value, append.expected_server_grants) &&
      checkpointsMatch(result.value, append.expected_checkpoints) &&
      policyMatchesVector(result.value.approvalPolicy, append.expected_policy) &&
      pendingMatchesVector(result.value.pendingProposals, append.expected_pending),
  );
}

async function validAppendVectorChecks(c: Checks, base: SemanticBase): Promise<void> {
  // Pin the permissive-side boundaries of the consensus rules with the
  // vectors (valid_appends):
  // (1) Member key uniqueness is prohibited only within "the current member
  //     set" (§6.2) — a verifier that wrongly implements "no duplication
  //     across all history" fails here
  // (2) Environment lifecycle (§6.2) — create_environment of an unused ID
  //     and the first rotate (new_epoch 2) onto an already-created
  //     environment (epoch 1) are accepted
  // (3) ES / PF1 (2026-09-14) — in-scope add / remove / change / rotate /
  //     checkpoint by listed-scope admin / member, direct append of an op
  //     not targeted by the policy, acceptance of propose / withdraw, and
  //     direct appends after the policy is narrowed or off (chain = append
  //     onto the derived head of extended_chains)
  for (const append of vectorValidAppends) {
    await validAppendVectorCheck(c, append);
  }
  await duplicateKeyAfterReaddCheck(c, base);
}

/**
 * Index re-formation: once re-add returns a key to the current member set,
 * adding a different user_id with the same key is duplicate-member-key
 * again (closes both directions — index removal on remove and
 * re-registration on add).
 */
async function duplicateKeyAfterReaddCheck(c: Checks, base: SemanticBase): Promise<void> {
  const readd = vectorValidAppends.find((a) => a.name === "readd-removed-member-same-key");
  if (readd === undefined) {
    c.push("chain semantic: duplicate key rejected again after re-add", false, "vector missing");
    return;
  }
  // The re-add vector is an append (seq 13) onto the canonical seq-12 head,
  // so continue right after it
  const readdEntry = toTypedEntry(readd.entry);
  const memberKeys = keysOf("user-member-0002");
  const duplicated = await signAs("user-owner-0001", {
    ...base,
    seq: readdEntry.seq + 1,
    prevHashHex: await computeChainEntryHash(readdEntry),
    timestampMs: readdEntry.timestampMs + 1000,
    op: "add_member",
    payload: {
      targetUserId: testUserId("user-clone-0004"),
      encPubHex: memberKeys.enc_pub_hex,
      sigPubHex: memberKeys.sig_pub_hex,
      role: "member",
      scopeKind: "all",
      scopeEnvironmentIds: [],
    },
  });
  const result =
    duplicated === undefined
      ? undefined
      : await verifyChain([...typedEntries.slice(0, readdEntry.seq - 1), readdEntry, duplicated]);
  c.push(
    "chain semantic: duplicate key rejected again after re-add",
    result !== undefined && failsWith(result, readdEntry.seq + 1, "duplicate-member-key"),
  );
}

/** Whether the derived environment state matches the expectation (current epoch, created seq, epoch-start seqs). */
function environmentStateIs(
  environment: EnvironmentChainState | undefined,
  expected: {
    readonly currentEpoch: number;
    readonly createdAtSeq?: number;
    readonly epochStartSeqs: Readonly<Record<number, number>>;
  },
): boolean {
  if (environment === undefined || environment.currentEpoch !== expected.currentEpoch) {
    return false;
  }
  if (expected.createdAtSeq !== undefined && environment.createdAtSeq !== expected.createdAtSeq) {
    return false;
  }
  return Object.entries(expected.epochStartSeqs).every(
    ([epoch, seq]) => environment.epochStartSeqs.get(Number(epoch)) === seq,
  );
}

async function validAppendCheck(c: Checks, base: SemanticBase): Promise<void> {
  // A correct append (rotate_epoch by admin; current epoch 2 → 3) verifies
  // and the state (current epoch, epoch-start seq, commitment) updates
  const extended = await appendRotation(base, "env-prod-0001", 3);
  const prod = extended?.environments.get("env-prod-0001");
  c.push(
    "chain semantic: valid append by admin verifies",
    extended?.headSeq === NEXT_SEQ &&
      environmentStateIs(prod, { currentEpoch: 3, epochStartSeqs: { 3: NEXT_SEQ } }) &&
      prod?.dekCommitments.get(3) === DUMMY_COMMITMENT_HEX,
  );

  // A create_environment → rotate_epoch two-entry chain: the epoch-start
  // seqs of a freshly created environment are derived (1 = the create's seq,
  // 2 = the rotate's seq)
  const create = await signAs("user-owner-0001", {
    ...base,
    op: "create_environment",
    payload: { environmentId: "env-chained-0006", dekCommitmentHex: DUMMY_COMMITMENT_HEX },
  });
  if (create === undefined) {
    c.push("chain semantic: create then rotate chain", false, "signing failed");
    return;
  }
  const rotate = await signAs("user-admin-0003", {
    ...base,
    seq: NEXT_SEQ + 1,
    prevHashHex: await computeChainEntryHash(create),
    actor: {
      userId: testUserId("user-admin-0003"),
      keyFingerprintHex: keysOf("user-admin-0003").key_fingerprint_hex,
    },
    op: "rotate_epoch",
    payload: {
      environmentId: "env-chained-0006",
      newEpoch: 2,
      reason: "scheduled",
      dekCommitmentHex: DUMMY_COMMITMENT_HEX,
    },
  });
  const result =
    rotate === undefined ? undefined : await verifyChain([...typedEntries, create, rotate]);
  const chained =
    result?.ok === true ? result.value.environments.get("env-chained-0006") : undefined;
  c.push(
    "chain semantic: create then rotate chain",
    environmentStateIs(chained, {
      currentEpoch: 2,
      createdAtSeq: NEXT_SEQ,
      epochStartSeqs: { 1: NEXT_SEQ, 2: NEXT_SEQ + 1 },
    }),
  );
}

/**
 * A malicious/corrupt entry whose runtime types diverge from the TS types
 * (as in server-distributed JSON) becomes invalid-payload, not an exception
 */
async function malformedInputChecks(c: Checks): Promise<void> {
  const full = await verifyChain(typedEntries);
  if (!full.ok) {
    c.push("chain malformed: setup", false, "full chain must verify");
    return;
  }
  const eGrant = entryAt(9);
  if (eGrant.op !== "grant_server") {
    c.push("chain malformed: setup", false, "seq 9 must be grant_server");
    return;
  }
  // signatureHex is a shape-valid 64-byte dummy: a shorter value would
  // short-circuit every case at the signature-length shape check, so the
  // cases would stop testing their intended fields
  const base = {
    ...nextEntryBase(),
    prevHashHex: full.value.headHashHex,
    signatureHex: "00".repeat(64),
  };
  const cases: readonly { name: string; entry: unknown }[] = [
    {
      name: "grant_server scope is not an array",
      entry: {
        ...base,
        op: "grant_server",
        payload: { ...eGrant.payload, scopeEnvironmentIds: "env-prod-0001" },
      },
    },
    {
      name: "grant_server scope contains non-string",
      entry: {
        ...base,
        op: "grant_server",
        payload: { ...eGrant.payload, scopeEnvironmentIds: [42] },
      },
    },
    {
      name: "rotate_epoch reason is not a string",
      entry: {
        ...base,
        op: "rotate_epoch",
        payload: {
          environmentId: "env-prod-0001",
          newEpoch: 3,
          reason: {},
          dekCommitmentHex: DUMMY_COMMITMENT_HEX,
        },
      },
    },
    {
      name: "rotate_epoch commitment is not a string",
      entry: {
        ...base,
        op: "rotate_epoch",
        payload: {
          environmentId: "env-prod-0001",
          newEpoch: 3,
          reason: "scheduled",
          dekCommitmentHex: 42,
        },
      },
    },
    {
      name: "create_environment commitment missing",
      entry: {
        ...base,
        op: "create_environment",
        payload: { environmentId: "env-shapeless-0007" },
      },
    },
    {
      name: "actor missing",
      entry: { ...base, actor: undefined, op: "remove_member", payload: { targetUserId: "x" } },
    },
    {
      name: "payload missing",
      entry: { ...base, op: "remove_member", payload: undefined },
    },
    {
      name: "add_member target is not a string",
      entry: {
        ...base,
        op: "add_member",
        payload: { ...entryAt(2).payload, targetUserId: 123 },
      },
    },
    {
      name: "signature missing",
      entry: {
        ...base,
        signatureHex: undefined,
        op: "remove_member",
        payload: { targetUserId: "x" },
      },
    },
    {
      name: "signature is null",
      entry: {
        ...base,
        signatureHex: null,
        op: "remove_member",
        payload: { targetUserId: "x" },
      },
    },
    {
      name: "signature hex oversized",
      entry: {
        ...base,
        signatureHex: "ab".repeat(500_000),
        op: "remove_member",
        payload: { targetUserId: "x" },
      },
    },
    {
      name: "actor fingerprint hex oversized",
      entry: {
        ...base,
        actor: { userId: testUserId("user-owner-0001"), keyFingerprintHex: "ab".repeat(500_000) },
        op: "remove_member",
        payload: { targetUserId: "x" },
      },
    },
    // checkpoint payload (§6.2): runtime-type divergence also lands on
    // invalid-payload
    {
      name: "checkpoint environments is not an array",
      entry: {
        ...base,
        op: "checkpoint",
        payload: { environments: "env-prod-0001", auditHeadHashHex: "" },
      },
    },
    {
      name: "checkpoint environment entry is null",
      entry: {
        ...base,
        op: "checkpoint",
        payload: { environments: [null], auditHeadHashHex: "" },
      },
    },
    {
      name: "checkpoint epoch is a string",
      entry: {
        ...base,
        op: "checkpoint",
        payload: {
          environments: [
            {
              environmentId: "env-prod-0001",
              epoch: "2",
              manifestVersion: 2,
              manifestSigHashHex: "ab".repeat(32),
              valuesDigestHex: "cd".repeat(32),
            },
          ],
          auditHeadHashHex: "",
        },
      },
    },
    {
      name: "checkpoint audit head missing",
      entry: {
        ...base,
        op: "checkpoint",
        payload: { environments: [] },
      },
    },
    {
      name: "checkpoint values digest missing",
      entry: {
        ...base,
        op: "checkpoint",
        payload: {
          environments: [
            {
              environmentId: "env-prod-0001",
              epoch: 2,
              manifestVersion: 2,
              manifestSigHashHex: "ab".repeat(32),
            },
          ],
          auditHeadHashHex: "",
        },
      },
    },
    // Payload shapes for scope (§6.2 — 2026-09-14 ES) / four-eyes (PF1):
    // runtime-type divergence also lands on invalid-payload (recursion into
    // nested payloads does not throw either)
    {
      name: "add_member scope kind is not a string",
      entry: {
        ...base,
        op: "add_member",
        payload: { ...entryAt(2).payload, scopeKind: 1 },
      },
    },
    {
      name: "add_member scope environments is not an array",
      entry: {
        ...base,
        op: "add_member",
        payload: {
          ...entryAt(2).payload,
          scopeKind: "listed",
          scopeEnvironmentIds: "env-dev-0002",
        },
      },
    },
    {
      name: "change_role scope missing",
      entry: {
        ...base,
        op: "change_role",
        payload: { targetUserId: testUserId("user-admin-0003"), newRole: "member" },
      },
    },
    {
      name: "set_approval_policy ops is not an array",
      entry: {
        ...base,
        op: "set_approval_policy",
        payload: { ops: "grant_server", requiredApprovals: 2 },
      },
    },
    {
      name: "set_approval_policy required is a string",
      entry: {
        ...base,
        op: "set_approval_policy",
        payload: { ops: ["grant_server"], requiredApprovals: "2" },
      },
    },
    {
      name: "propose inner is null",
      entry: { ...base, op: "propose", payload: { inner: null, expiresAtMs: 0 } },
    },
    {
      name: "propose inner op is a prototype property name",
      entry: {
        ...base,
        op: "propose",
        payload: { inner: { op: "__proto__", payload: {} }, expiresAtMs: 0 },
      },
    },
    {
      name: "propose inner payload missing",
      entry: {
        ...base,
        op: "propose",
        payload: { inner: { op: "remove_member" }, expiresAtMs: 0 },
      },
    },
    {
      name: "propose expires is a string",
      entry: {
        ...base,
        op: "propose",
        payload: {
          inner: { op: "remove_member", payload: { targetUserId: testUserId("user-admin-0003") } },
          expiresAtMs: "0",
        },
      },
    },
    {
      name: "approve hash is a number",
      entry: { ...base, op: "approve", payload: { proposalHashHex: 42 } },
    },
    {
      name: "withdraw payload missing",
      entry: { ...base, op: "withdraw", payload: undefined },
    },
    // Payload shapes for device keys (§6.2 — 2026-09-19 DK): runtime-type
    // divergence also lands on invalid-payload
    {
      name: "add_device role cap is a number",
      entry: {
        ...base,
        op: "add_device",
        payload: {
          encPubHex: "ab".repeat(32),
          sigPubHex: "cd".repeat(32),
          roleCap: 3,
          scopeKind: "all",
          scopeEnvironmentIds: [],
        },
      },
    },
    {
      name: "add_device scope environments is not an array",
      entry: {
        ...base,
        op: "add_device",
        payload: {
          encPubHex: "ab".repeat(32),
          sigPubHex: "cd".repeat(32),
          roleCap: "member",
          scopeKind: "listed",
          scopeEnvironmentIds: "env-dev-0002",
        },
      },
    },
    {
      name: "revoke_device fingerprints is not an array",
      entry: {
        ...base,
        op: "revoke_device",
        payload: {
          targetUserId: testUserId("user-owner-0001"),
          deviceFingerprintsHex: "ab".repeat(16),
        },
      },
    },
    {
      name: "revoke_device fingerprint element is a number",
      entry: {
        ...base,
        op: "revoke_device",
        payload: { targetUserId: testUserId("user-owner-0001"), deviceFingerprintsHex: [42] },
      },
    },
    // Unknown op: if the PAYLOAD_SHAPES table lookup is called without
    // confirming membership, verification aborts with a TypeError. Pin the
    // public verifier's contract here: "invalid input returns
    // invalid-payload and never throws" (defense-in-depth)
    {
      name: "unknown op",
      entry: { ...base, op: "self_destruct", payload: {} },
    },
    {
      name: "op is a prototype property name",
      entry: { ...base, op: "toString", payload: {} },
    },
    {
      name: "op is __proto__",
      entry: { ...base, op: "__proto__", payload: {} },
    },
    { name: "op missing", entry: { ...base, op: undefined, payload: {} } },
    { name: "entry slot is null", entry: null },
    { name: "entry slot is a string", entry: "not-an-entry" },
  ];
  for (const item of cases) {
    // Verify it returns an invalid-payload CryptoResult without throwing
    try {
      const result = await verifyChain([...typedEntries, item.entry as ChainEntry]);
      c.push(`chain malformed: ${item.name}`, failsWith(result, NEXT_SEQ, "invalid-payload"));
    } catch (error) {
      c.push(`chain malformed: ${item.name}`, false, `threw: ${String(error)}`);
    }
  }
}

async function regrantWideningCheck(c: Checks): Promise<void> {
  // A scope-widening re-grant (old ⊆ new) is accepted and the scope is
  // updated. The narrowing rejection (grant-scope-narrowed) is pinned by
  // the vector authz-grant-scope-narrowed
  const check = "chain semantic: re-grant widening accepted";
  const eGrant = entryAt(9);
  const owner = vectorKeys["user-owner-0001"];
  if (eGrant.op !== "grant_server" || owner === undefined) {
    c.push(check, false, "setup failed");
    return;
  }
  const widened = await signAs("user-owner-0001", {
    suite: "maruhi/v1",
    seq: 10,
    prevHashHex: vectorEntries[8]?.entry_hash_hex ?? "",
    actor: { userId: testUserId("user-owner-0001"), keyFingerprintHex: owner.key_fingerprint_hex },
    timestampMs: eGrant.timestampMs + 500,
    op: "grant_server",
    payload: {
      ...eGrant.payload,
      scopeEnvironmentIds: [...eGrant.payload.scopeEnvironmentIds, "env-stage-0003"],
    },
  });
  if (widened === undefined) {
    c.push(check, false, "signing failed");
    return;
  }
  const result = await verifyChain([...typedEntries.slice(0, 9), widened]);
  if (!result.ok) {
    c.push(check, false, "widened re-grant must verify");
    return;
  }
  const grant = result.value.serverGrants.get(eGrant.payload.serverKeyFingerprintHex);
  c.push(
    check,
    grant !== undefined &&
      grant.scopeEnvironmentIds.length === 3 &&
      // Independence of the two-layer rule: even a re-grant touching only
      // the scope replaces lease_policy with the new payload's value (here
      // the same 2 elements as before)
      grant.leasePolicy.length === eGrant.payload.leasePolicy.length,
  );
}

/** Boundary of the field size limit (§6.1): exactly 1024 bytes is accepted; judged by byte count */
async function fieldSizeBoundaryChecks(c: Checks): Promise<void> {
  const full = await verifyChain(typedEntries);
  if (!full.ok) {
    c.push("chain field-size: setup", false, "full chain must verify");
    return;
  }
  const base = { ...nextEntryBase(), prevHashHex: full.value.headHashHex };
  const adminActor = {
    userId: testUserId("user-admin-0003"),
    keyFingerprintHex: vectorKeys["user-admin-0003"]?.key_fingerprint_hex ?? "",
  };

  // A reason of exactly 1024 bytes (ASCII) → accepted
  const atLimit = await signAs("user-admin-0003", {
    ...base,
    actor: adminActor,
    op: "rotate_epoch",
    payload: {
      environmentId: "env-prod-0001",
      newEpoch: 3,
      reason: "y".repeat(1024),
      dekCommitmentHex: DUMMY_COMMITMENT_HEX,
    },
  });
  const accepted =
    atLimit === undefined ? undefined : await verifyChain([...typedEntries, atLimit]);
  c.push("chain field-size: 1024-byte reason accepted", accepted !== undefined && accepted.ok);

  // ㊙ (3 bytes) x 342 = 1026 bytes: 342 ≤ 1024 code units, but the UTF-8
  // byte count exceeds → rejected (pins that the limit is byte-based)
  const multibyte = await signAs("user-admin-0003", {
    ...base,
    actor: adminActor,
    op: "rotate_epoch",
    payload: {
      environmentId: "env-prod-0001",
      newEpoch: 3,
      reason: "㊙".repeat(342),
      dekCommitmentHex: DUMMY_COMMITMENT_HEX,
    },
  });
  const rejected =
    multibyte === undefined ? undefined : await verifyChain([...typedEntries, multibyte]);
  c.push(
    "chain field-size: multibyte over-limit reason rejected",
    rejected !== undefined && failsWith(rejected, NEXT_SEQ, "invalid-payload"),
  );
}

/** The canonical head before policy establishment (seq 20) — the last point where a four-eyes target op can be appended directly. */
const PRE_POLICY_HEAD_SEQ = 19;

/** Build correctly-signed but semantically invalid entries (failure cases outside the vectors) with the owner key and check them */
async function semanticChecks(c: Checks): Promise<void> {
  const full = await verifyChain(typedEntries);
  if (!full.ok) {
    c.push("chain semantic: setup", false, "full chain must verify");
    return;
  }
  const base = { ...nextEntryBase(), prevHashHex: full.value.headHashHex };
  // grant_server / remove_member become policy targets at seq 20
  // (approval-required precedes, right after role — pinned by the vectors),
  // so op-specific reasons are checked by appending onto the pre-policy
  // head 19
  const prePolicy = typedEntries.slice(0, PRE_POLICY_HEAD_SEQ);
  const prePolicyHead = prePolicy[prePolicy.length - 1];
  const prePolicyBase = {
    ...base,
    seq: PRE_POLICY_HEAD_SEQ + 1,
    prevHashHex: await computeChainEntryHash(prePolicyHead as ChainEntry),
    timestampMs: (prePolicyHead?.timestampMs ?? 0) + 1000,
  };
  for (const item of semanticCases(prePolicyBase)) {
    const signed = await signAs("user-owner-0001", item.entry);
    if (signed === undefined) {
      c.push(`chain semantic: ${item.name}`, false, "signing failed");
      continue;
    }
    const result = await verifyChain([...prePolicy, signed]);
    c.push(`chain semantic: ${item.name}`, failsWith(result, PRE_POLICY_HEAD_SEQ + 1, item.expect));
  }
  await validAppendCheck(c, base);
  await validAppendVectorChecks(c, base);
}

export async function chainNegativeChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  await tamperedChecks(c);
  await bytesLevelChecks(c);
  await checkpointTamperChecks(c);
  await authorizationChecks(c);
  await extendedChainChecks(c);
  await framingChecks(c);
  await semanticChecks(c);
  await regrantWideningCheck(c);
  await malformedInputChecks(c);
  await fieldSizeBoundaryChecks(c);
  return c.results;
}
