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
import type { EnvironmentId, UserId } from "../../src/index.ts";
import { testEnvironmentId, testKeyFingerprintHex, testUserId } from "../support/fixture.ts";
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
  readonly chain?: string;
}

function entryOfOp<K extends ChainEntry["op"]>(seq: number, op: K): ChainEntry & { op: K } {
  const entry = entryAt(seq);
  if (entry.op !== op) {
    throw new Error(`chain vector seq ${seq}: expected ${op}, got ${entry.op}`);
  }
  return entry as ChainEntry & { op: K };
}

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

function vectorCommitmentOf(environmentId: string, epoch: number): string {
  const commitment = vectorEnvironmentDeks[environmentId]?.[String(epoch)]?.dek_commitment_hex;
  if (commitment === undefined) {
    throw new Error(`chain vector environment_deks missing ${environmentId}#${epoch}`);
  }
  return commitment;
}

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
    ...deletionTamperVariants(),
  ];
}

function deletionTamperVariants(): readonly TamperVariant[] {
  const chain = "environment-deleted";
  const eDelete = extendedEntryOfOp(chain, 20, "delete_environment");
  return [
    {
      name: "delete-env-tampered-environment-id",
      entry: { ...eDelete, payload: { environmentId: testEnvironmentId("env-dev-0002") } },
      expect: "bad-signature",
      chain,
    },
  ];
}

const FRESH_DEVICE_ENC_PUB_HEX = "1349ac6a06c18c9fb1cc6f15b1907ca645b45fe524716d690bb29f354dffa76e";

function deviceTamperVariants(): readonly TamperVariant[] {
  const chain = "device-ops";
  const eReserve = extendedEntryOfOp(chain, 25, "add_device");
  const eCiBox = extendedEntryOfOp(chain, 27, "add_device");
  const eRevokeSelf = extendedEntryOfOp(chain, 35, "revoke_device");
  const eRevokeOther = extendedEntryOfOp(chain, 37, "revoke_device");
  return [
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
    {
      name: "add-device-tampered-enc-pub",
      entry: { ...eReserve, payload: { ...eReserve.payload, encPubHex: FRESH_DEVICE_ENC_PUB_HEX } },
      expect: "bad-signature",
      chain,
    },
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
      entry: {
        ...eWiden,
        payload: {
          ...eWiden.payload,
          scopeEnvironmentIds: ["env-dev-0002"].map((id) => testEnvironmentId(id)),
        },
      },
      expect: "bad-signature",
    },
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
      entry: {
        ...eRevoke,
        payload: { serverKeyFingerprintHex: testKeyFingerprintHex(toHex(flipped)) },
      },
      expect: "bad-signature",
    },
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

function tamperCoverageCheck(c: Checks, covered: ReadonlySet<string>): void {
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
      ...BYTES_LEVEL_NEGATIVES,
      "checkpoint-tampered-environments",
    ]),
  );
  for (const variant of [...payloadVariants, ...headerVariants]) {
    const vector = negativeByName(variant.name);
    if (vector === undefined) {
      c.push(`chain negative: ${variant.name}`, false, "vector missing");
      continue;
    }
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
  "delete-env-op-confusion",
  "delete-env-suite-mismatch",
];

async function bytesLevelChecks(c: Checks): Promise<void> {
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
  for (const [name, extended] of Object.entries(vectorExtendedChains)) {
    const chain = [
      ...typedEntries.slice(0, extended.base_seq),
      ...extended.entries.map((entry) => toTypedEntry(entry)),
    ];
    const result = await verifyChain(chain);
    c.push(
      `chain extended: ${name} verifies`,
      result.ok && extendedStateMatches(result.value, extended),
    );
  }
}

async function namedServerKeysCheck(c: Checks): Promise<void> {
  const grant = entryOfOp(9, "grant_server").payload;
  const approvedGrant =
    vectorExtendedChains["server-key-grant-approved"]?.expected_server_grants?.[0];
  if (approvedGrant === undefined) {
    c.push("chain semantic: named server keys", false, "vector missing");
    return;
  }
  const seq9Key = `${grant.serverEncPubHex}:${grant.serverKeyFingerprintHex}`;
  const approvedKey = `${approvedGrant.server_enc_pub_hex}:${approvedGrant.server_key_fingerprint_hex}`;
  const cases: readonly (readonly [string, readonly ChainEntry[], readonly string[]])[] = [
    ["a revoked grant's key stays named", typedEntries, [seq9Key]],
    [
      "a pending grant proposal names none",
      extendedPrefix("server-key-grant-pending", 27),
      [seq9Key],
    ],
    [
      "an approve names its grant's key",
      extendedPrefix("server-key-grant-approved", 28),
      [seq9Key, approvedKey].toSorted(),
    ],
  ];
  for (const [name, entries, expected] of cases) {
    const result = await verifyChain(entries);
    const named = result.ok
      ? [...result.value.namedServerKeys].map(([enc, fingerprint]) => `${enc}:${fingerprint}`)
      : [];
    c.push(
      `chain semantic: named server keys — ${name}`,
      result.ok && named.toSorted().join(",") === expected.join(","),
    );
  }
}

function extendedStateMatches(
  state: ChainState,
  extended: (typeof vectorExtendedChains)[string],
): boolean {
  return [
    membersMatch(state, extended.expected_members),
    checkpointsMatch(state, extended.expected_checkpoints),
    policyMatchesVector(state.approvalPolicy, extended.expected_policy),
    pendingMatchesVector(state.pendingProposals, extended.expected_pending),
    optionalMatch(extended.expected_environments, (expected) => environmentsMatch(state, expected)),
    deletedEnvironmentsMatch(state, extended.expected_deleted_environments),
    optionalMatch(extended.expected_server_grants, (expected) =>
      serverGrantsMatch(state, expected),
    ),
  ].every(Boolean);
}

function optionalMatch<T>(expected: T | undefined, match: (expected: T) => boolean): boolean {
  return expected === undefined || match(expected);
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
    prevHashHex: "",
    actor: { userId: testUserId("user-owner-0001"), keyFingerprintHex: owner.key_fingerprint_hex },
    timestampMs: head.timestampMs + 1000,
  };
}

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
          scopeEnvironmentIds: ["env-prod-0001"].map((id) => testEnvironmentId(id)),
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
        payload: {
          serverKeyFingerprintHex: testKeyFingerprintHex("00112233445566778899aabbccddeeff"),
        },
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
      keyFingerprintHex:
        vectorKeys["user-admin-0003"]?.key_fingerprint_hex ?? testKeyFingerprintHex(""),
    },
    op: "rotate_epoch",
    payload: {
      environmentId: testEnvironmentId(environmentId),
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

function membersMatch(
  state: ChainState,
  expected: Readonly<Record<string, VectorMemberState>>,
): boolean {
  return membersMatchVector(state.members, expected);
}

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
      const actual = state.checkpoints.get(testEnvironmentId(environmentId));
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

function environmentsMatch(state: ChainState, expected: Readonly<Record<string, string>>): boolean {
  return (
    state.environments.size === Object.keys(expected).length &&
    Object.entries(expected).every(
      ([environmentId, epoch]) =>
        state.environments.get(testEnvironmentId(environmentId))?.currentEpoch === Number(epoch),
    )
  );
}

function deletedEnvironmentsMatch(
  state: ChainState,
  expected: Readonly<Record<string, number>> | undefined,
): boolean {
  const deleted = [...state.environments].filter(
    ([, environment]) => environment.deletedAtSeq !== null,
  );
  const wanted = Object.entries(expected ?? {});
  return (
    deleted.length === wanted.length &&
    wanted.every(
      ([environmentId, seq]) =>
        state.environments.get(testEnvironmentId(environmentId))?.deletedAtSeq === seq,
    )
  );
}

function serverGrantsMatch(
  state: ChainState,
  expected: Parameters<typeof serverGrantsMatchVector>[1],
): boolean {
  return serverGrantsMatchVector(state.serverGrants, expected);
}

async function validAppendVectorCheck(
  c: Checks,
  append: (typeof vectorValidAppends)[number],
): Promise<void> {
  const entry = toTypedEntry(append.entry);
  const result = await verifyChain([...authzPrefix(append.chain, entry.seq), entry]);
  c.push(
    `chain valid append: ${append.name}`,
    result.ok &&
      membersMatch(result.value, append.expected_members) &&
      environmentsMatch(result.value, append.expected_environments) &&
      deletedEnvironmentsMatch(result.value, append.expected_deleted_environments) &&
      serverGrantsMatch(result.value, append.expected_server_grants) &&
      checkpointsMatch(result.value, append.expected_checkpoints) &&
      policyMatchesVector(result.value.approvalPolicy, append.expected_policy) &&
      pendingMatchesVector(result.value.pendingProposals, append.expected_pending),
  );
}

async function validAppendVectorChecks(c: Checks, base: SemanticBase): Promise<void> {
  for (const append of vectorValidAppends) {
    await validAppendVectorCheck(c, append);
  }
  await duplicateKeyAfterReaddCheck(c, base);
}

async function duplicateKeyAfterReaddCheck(c: Checks, base: SemanticBase): Promise<void> {
  const readd = vectorValidAppends.find((a) => a.name === "readd-removed-member-same-key");
  if (readd === undefined) {
    c.push("chain semantic: duplicate key rejected again after re-add", false, "vector missing");
    return;
  }
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
  const extended = await appendRotation(base, "env-prod-0001", 3);
  const prod = extended?.environments.get(testEnvironmentId("env-prod-0001"));
  c.push(
    "chain semantic: valid append by admin verifies",
    extended?.headSeq === NEXT_SEQ &&
      environmentStateIs(prod, { currentEpoch: 3, epochStartSeqs: { 3: NEXT_SEQ } }) &&
      prod?.dekCommitments.get(3) === DUMMY_COMMITMENT_HEX,
  );

  const create = await signAs("user-owner-0001", {
    ...base,
    op: "create_environment",
    payload: {
      environmentId: testEnvironmentId("env-chained-0006"),
      dekCommitmentHex: DUMMY_COMMITMENT_HEX,
    },
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
      environmentId: testEnvironmentId("env-chained-0006"),
      newEpoch: 2,
      reason: "scheduled",
      dekCommitmentHex: DUMMY_COMMITMENT_HEX,
    },
  });
  const result =
    rotate === undefined ? undefined : await verifyChain([...typedEntries, create, rotate]);
  const chained =
    result?.ok === true
      ? result.value.environments.get(testEnvironmentId("env-chained-0006"))
      : undefined;
  c.push(
    "chain semantic: create then rotate chain",
    environmentStateIs(chained, {
      currentEpoch: 2,
      createdAtSeq: NEXT_SEQ,
      epochStartSeqs: { 1: NEXT_SEQ, 2: NEXT_SEQ + 1 },
    }),
  );
}

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
        payload: { ...eGrant.payload, scopeEnvironmentIds: [42 as unknown as EnvironmentId] },
      },
    },
    {
      name: "rotate_epoch reason is not a string",
      entry: {
        ...base,
        op: "rotate_epoch",
        payload: {
          environmentId: testEnvironmentId("env-prod-0001"),
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
          environmentId: testEnvironmentId("env-prod-0001"),
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
      entry: {
        ...base,
        actor: undefined,
        op: "remove_member",
        payload: { targetUserId: testUserId("x") },
      },
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
        payload: { ...entryAt(2).payload, targetUserId: 123 as unknown as UserId },
      },
    },
    {
      name: "signature missing",
      entry: {
        ...base,
        signatureHex: undefined,
        op: "remove_member",
        payload: { targetUserId: testUserId("x") },
      },
    },
    {
      name: "signature is null",
      entry: {
        ...base,
        signatureHex: null,
        op: "remove_member",
        payload: { targetUserId: testUserId("x") },
      },
    },
    {
      name: "signature hex oversized",
      entry: {
        ...base,
        signatureHex: "ab".repeat(500_000),
        op: "remove_member",
        payload: { targetUserId: testUserId("x") },
      },
    },
    {
      name: "actor fingerprint hex oversized",
      entry: {
        ...base,
        actor: { userId: testUserId("user-owner-0001"), keyFingerprintHex: "ab".repeat(500_000) },
        op: "remove_member",
        payload: { targetUserId: testUserId("x") },
      },
    },
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
              environmentId: testEnvironmentId("env-prod-0001"),
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
              environmentId: testEnvironmentId("env-prod-0001"),
              epoch: 2,
              manifestVersion: 2,
              manifestSigHashHex: "ab".repeat(32),
            },
          ],
          auditHeadHashHex: "",
        },
      },
    },
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
    try {
      const result = await verifyChain([...typedEntries, item.entry as ChainEntry]);
      c.push(`chain malformed: ${item.name}`, failsWith(result, NEXT_SEQ, "invalid-payload"));
    } catch (error) {
      c.push(`chain malformed: ${item.name}`, false, `threw: ${String(error)}`);
    }
  }
}

async function regrantWideningCheck(c: Checks): Promise<void> {
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
      scopeEnvironmentIds: [...eGrant.payload.scopeEnvironmentIds, "env-stage-0003"].map((id) =>
        testEnvironmentId(id),
      ),
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
      grant.leasePolicy.length === eGrant.payload.leasePolicy.length,
  );
}

async function fieldSizeBoundaryChecks(c: Checks): Promise<void> {
  const full = await verifyChain(typedEntries);
  if (!full.ok) {
    c.push("chain field-size: setup", false, "full chain must verify");
    return;
  }
  const base = { ...nextEntryBase(), prevHashHex: full.value.headHashHex };
  const adminActor = {
    userId: testUserId("user-admin-0003"),
    keyFingerprintHex:
      vectorKeys["user-admin-0003"]?.key_fingerprint_hex ?? testKeyFingerprintHex(""),
  };

  const atLimit = await signAs("user-admin-0003", {
    ...base,
    actor: adminActor,
    op: "rotate_epoch",
    payload: {
      environmentId: testEnvironmentId("env-prod-0001"),
      newEpoch: 3,
      reason: "y".repeat(1024),
      dekCommitmentHex: DUMMY_COMMITMENT_HEX,
    },
  });
  const accepted =
    atLimit === undefined ? undefined : await verifyChain([...typedEntries, atLimit]);
  c.push("chain field-size: 1024-byte reason accepted", accepted !== undefined && accepted.ok);

  const multibyte = await signAs("user-admin-0003", {
    ...base,
    actor: adminActor,
    op: "rotate_epoch",
    payload: {
      environmentId: testEnvironmentId("env-prod-0001"),
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

const PRE_POLICY_HEAD_SEQ = 19;

async function semanticChecks(c: Checks): Promise<void> {
  const full = await verifyChain(typedEntries);
  if (!full.ok) {
    c.push("chain semantic: setup", false, "full chain must verify");
    return;
  }
  const base = { ...nextEntryBase(), prevHashHex: full.value.headHashHex };
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
  await namedServerKeysCheck(c);
  await framingChecks(c);
  await semanticChecks(c);
  await regrantWideningCheck(c);
  await malformedInputChecks(c);
  await fieldSizeBoundaryChecks(c);
  return c.results;
}
