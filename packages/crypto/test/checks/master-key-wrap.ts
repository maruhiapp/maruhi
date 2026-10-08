// Checks for CRYPTO_SPEC §8 (0.9-draft / KL3 — the master key wrap ledger).
// Vectors: test-vectors/master-key-wrap.json. Same layout as dek-wrap /
// lease-wrap: fixed vectors (generated via hpke-js ekm derandomize) are
// verified in the Open direction, and the Seal direction is covered by a
// roundtrip. For AES-GCM / HKDF, a successful vector decryption pins the
// derivation. recovery-wrap.json (the recovery-code path) is unchanged and
// still lives in checks/recovery.ts.

import {
  buildGuardianWrapInfo,
  buildHandoffWrapInfo,
  buildMasterWrapAad,
  computeHandoffRequestId,
  decodeHandoffCode,
  derivePasskeyKek,
  encodeHandoffCode,
  type EncryptionKeyPair,
  encodeLengthPrefixed,
  exportEncryptionPublicKey,
  generateEncryptionKeyPair,
  generateMasterWrapKek,
  type GuardianMode,
  type GuardianWrapContext,
  type HandoffWrapContext,
  importEncryptionKeyPair,
  joinGuardianShares,
  type MasterWrapContext,
  openGuardianShare,
  openHandoffValue,
  sealGuardianShare,
  sealHandoffValue,
  splitGuardianKek,
  unwrapMasterBlob,
  wrapMasterBlob,
} from "../../src/index.ts";
import masterWrapVectors from "../../test-vectors/master-key-wrap.json" with { type: "json" };
import recoveryVectors from "../../test-vectors/recovery-wrap.json" with { type: "json" };
import { testUserId } from "../support/fixture.ts";
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

const doc = masterWrapVectors;
const userId = testUserId(doc.user_id);
const blobHex = doc.master_secret_blob_hex;

interface AeadVector {
  readonly kek_hex: string;
  readonly nonce_hex: string;
  readonly ciphertext_hex: string;
}

interface GuardianShareVector {
  readonly share_index: number;
  readonly guardian_user_id: string;
  readonly share_hex: string;
  readonly info_hex: string;
  readonly enc_hex: string;
  readonly ciphertext_hex: string;
}

interface GuardianGroupVector extends AeadVector {
  readonly name: string;
  readonly group_id: string;
  readonly mode: GuardianMode;
  readonly aad_hex: string;
  readonly shares: readonly GuardianShareVector[];
}

interface HandoffVector {
  readonly name: string;
  readonly source: string;
  readonly share_index: number;
  readonly approver_user_id: string;
  readonly request_id_hex: string;
  readonly value_hex: string;
  readonly info_hex: string;
  readonly enc_hex: string;
  readonly ciphertext_hex: string;
}

interface NegativeVector {
  readonly decrypt_aad_hex?: string;
  readonly decrypt_kek_hex?: string;
  readonly other_prf_out_hex?: string;
  readonly open_info_hex?: string;
  readonly open_enc_hex?: string;
  readonly code_symbols?: string;
}

function vectorNamed<T>(name: string): T {
  const vector = doc.vectors.find((v) => v.name === name);
  if (vector === undefined) {
    throw new Error(`master-key-wrap.json: ${name} vector missing`);
  }
  return vector as unknown as T;
}

function negativeNamed(name: string): NegativeVector {
  const vector = doc.negative.find((n) => n.name === name);
  if (vector === undefined) {
    throw new Error(`master-key-wrap.json: negative ${name} missing`);
  }
  return vector as unknown as NegativeVector;
}

const passkey = vectorNamed<
  AeadVector & { readonly wrap_id: string; readonly prf_out_hex: string; readonly aad_hex: string }
>("passkey-prf-basic");
const any2 = vectorNamed<GuardianGroupVector>("guardian-any-2");
const all3 = vectorNamed<GuardianGroupVector>("guardian-all-3");
const handoffShare = vectorNamed<HandoffVector>("handoff-guardian-share");

const passkeyContext: MasterWrapContext = { userId, kind: "passkey-prf", wrapRef: passkey.wrap_id };
const groupContext = (g: GuardianGroupVector): MasterWrapContext => ({
  userId,
  kind: "guardian",
  wrapRef: g.group_id,
  mode: g.mode,
});
const shareContext = (g: GuardianGroupVector, s: GuardianShareVector): GuardianWrapContext => ({
  userId,
  groupId: g.group_id,
  mode: g.mode,
  shareIndex: s.share_index,
  guardianUserId: testUserId(s.guardian_user_id),
});
const handoffContext = (h: HandoffVector): HandoffWrapContext => ({
  userId,
  requestId: h.request_id_hex,
  source: h.source,
  shareIndex: h.share_index,
  approverUserId: testUserId(h.approver_user_id),
});

async function importPair(pk: string, sk: string): Promise<EncryptionKeyPair> {
  const pair = await importEncryptionKeyPair({ publicKey: fromHex(pk), privateKey: fromHex(sk) });
  if (!pair.ok) {
    throw new Error("master-key-wrap.json: key import failed");
  }
  return pair.value;
}

async function guardianKeyPair(guardianUserId: string): Promise<EncryptionKeyPair> {
  const keys = (doc.guardian_keypairs as Record<string, { pk_hex: string; sk_hex: string }>)[
    guardianUserId
  ];
  if (keys === undefined) {
    throw new Error(`master-key-wrap.json: guardian ${guardianUserId} keypair missing`);
  }
  return importPair(keys.pk_hex, keys.sk_hex);
}

const unwrapVector = (v: AeadVector, context: MasterWrapContext, kek?: Uint8Array) =>
  unwrapMasterBlob({
    kek: kek ?? fromHex(v.kek_hex),
    wrapped: { nonce: fromHex(v.nonce_hex), ciphertext: fromHex(v.ciphertext_hex) },
    context,
  });

/** B and user_id are inherited from recovery-wrap.json (the ledger = the set of wraps of the same B). */
function provenanceChecks(c: Checks): void {
  const recovery = recoveryVectors.vectors[0];
  c.push(
    "master-wrap: B and user_id inherit recovery-wrap.json",
    recovery !== undefined &&
      recovery.user_id === userId &&
      recovery.master_secret_blob_hex === blobHex,
  );
}

async function passkeyChecks(c: Checks): Promise<void> {
  c.push(
    "master-wrap: passkey aad construction",
    toHex(buildMasterWrapAad(passkeyContext)) === passkey.aad_hex,
  );
  const kek = await derivePasskeyKek(fromHex(passkey.prf_out_hex));
  c.push("master-wrap: passkey KEK derivation", kek.ok && toHex(kek.value) === passkey.kek_hex);
  const blob = await unwrapVector(passkey, passkeyContext);
  c.push("master-wrap: passkey vector unwrap == B", blob.ok && toHex(blob.value) === blobHex);
  // A short PRF output is InvalidInput (never reaches HKDF)
  const short = await derivePasskeyKek(fromHex(passkey.prf_out_hex).slice(0, 16));
  c.push(
    "master-wrap: passkey short prf output rejected",
    !short.ok && short.error.kind === "InvalidInput",
  );
}

async function openVectorShares(g: GuardianGroupVector, c: Checks): Promise<Uint8Array[]> {
  const opened: Uint8Array[] = [];
  for (const s of g.shares) {
    c.push(
      `master-wrap: ${g.name} share ${s.share_index} info construction`,
      toHex(buildGuardianWrapInfo(shareContext(g, s))) === s.info_hex,
    );
    const share = await openGuardianShare({
      guardianKeyPair: await guardianKeyPair(s.guardian_user_id),
      wrapped: { enc: fromHex(s.enc_hex), ciphertext: fromHex(s.ciphertext_hex) },
      context: shareContext(g, s),
    });
    c.push(
      `master-wrap: ${g.name} share ${s.share_index} vector open == share`,
      share.ok && toHex(share.value) === s.share_hex,
    );
    if (share.ok) {
      opened.push(share.value);
    }
  }
  return opened;
}

async function guardianGroupChecks(c: Checks, g: GuardianGroupVector): Promise<void> {
  c.push(
    `master-wrap: ${g.name} aad construction`,
    toHex(buildMasterWrapAad(groupContext(g))) === g.aad_hex,
  );
  const blob = await unwrapVector(g, groupContext(g));
  c.push(`master-wrap: ${g.name} vector unwrap == B`, blob.ok && toHex(blob.value) === blobHex);
  const opened = await openVectorShares(g, c);
  // Assemble the KEK from the segments (any: 1 segment / all: XOR of all
  // segments)
  const joined = joinGuardianShares({
    mode: g.mode,
    shares: g.mode === "any" ? opened.slice(0, 1) : opened,
    expectedCount: g.shares.length,
  });
  c.push(
    `master-wrap: ${g.name} joined shares == KEK`,
    joined.ok && toHex(joined.value) === g.kek_hex,
  );
  c.push(
    `master-wrap: ${g.name} share layout`,
    g.mode === "any"
      ? opened.every((s) => toHex(s) === g.kek_hex)
      : new Set(opened.map(toHex)).size === g.shares.length,
  );
}

async function handoffIdChecks(c: Checks): Promise<void> {
  const pub = fromHex(doc.handoff.ephemeral_pub_hex);
  c.push(
    "master-wrap: handoff request_id LP",
    toHex(encodeLengthPrefixed([doc.handoff.request_id_domain, doc.handoff.ephemeral_pub_hex])) ===
      doc.handoff.request_id_lp_hex,
  );
  const requestId = await computeHandoffRequestId(pub);
  c.push(
    "master-wrap: handoff request_id",
    requestId.ok && requestId.value === doc.handoff.request_id_hex,
  );
  const otherId = await computeHandoffRequestId(fromHex(doc.handoff.other_ephemeral.pk_hex));
  c.push(
    "master-wrap: other ephemeral key has its own request_id",
    otherId.ok &&
      otherId.value === doc.handoff.other_ephemeral.request_id_hex &&
      otherId.value !== doc.handoff.request_id_hex,
  );
  const code = await encodeHandoffCode(pub);
  c.push("master-wrap: handoff code encoding", code.ok && code.value === doc.handoff.code.display);
  const decoded = await decodeHandoffCode(doc.handoff.code.display);
  c.push(
    "master-wrap: handoff code decoding",
    decoded.ok && toHex(decoded.value) === doc.handoff.ephemeral_pub_hex,
  );
  // Lowercase, whitespace, and hyphen-free input decodes to the same key
  // (leniency for transcription)
  const lenient = await decodeHandoffCode(
    ` ${doc.handoff.code.symbols.toLowerCase().replace(/(.{8})/g, "$1 ")} `,
  );
  c.push(
    "master-wrap: handoff code lenient input",
    lenient.ok && toHex(lenient.value) === doc.handoff.ephemeral_pub_hex,
  );
}

async function handoffOpenChecks(c: Checks, pair: EncryptionKeyPair): Promise<void> {
  // Only a guardian may approve (2026-09-19 DK — the old-device approval
  // handoff-device was removed from §8.4)
  for (const h of [handoffShare]) {
    c.push(
      `master-wrap: ${h.name} info construction`,
      toHex(buildHandoffWrapInfo(handoffContext(h))) === h.info_hex,
    );
    const value = await openHandoffValue({
      ephemeralKeyPair: pair,
      wrapped: { enc: fromHex(h.enc_hex), ciphertext: fromHex(h.ciphertext_hex) },
      context: handoffContext(h),
    });
    c.push(
      `master-wrap: ${h.name} vector open == value`,
      value.ok && toHex(value.value) === h.value_hex,
    );
  }
  // The guardian approval is a re-seal of segment 1 of guardian-all-3 (the
  // value is identical)
  c.push(
    "master-wrap: handoff-guardian-share re-seals share 1 of guardian-all-3",
    handoffShare.source === all3.group_id && handoffShare.value_hex === all3.shares[0]?.share_hex,
  );
}

/** AAD-substitution negative: the vector's decrypt_aad_hex matches the built AAD, and decryption fails. */
async function aadNegativeCheck(
  c: Checks,
  name: string,
  base: AeadVector,
  context: MasterWrapContext,
): Promise<void> {
  const n = negativeNamed(name);
  const aadMatches = n.decrypt_aad_hex === toHex(buildMasterWrapAad(context));
  const result = await unwrapVector(base, context);
  c.push(
    `master-wrap negative: ${name}`,
    aadMatches && !result.ok && result.error.kind === "DecryptFailed",
  );
}

async function aadNegativeChecks(c: Checks): Promise<void> {
  // Substitution on the kind axis alone (guardian → passkey-prf; same
  // wrap_ref, same mode — rebuilt on guardian-any-2 as base in 2026-09-20 DK
  // because device left the kind set)
  // (mode is a guardian-only field, so a passkey-prf context has no mode —
  // having one would be InvalidInput)
  await aadNegativeCheck(c, "aad-kind-mismatch", any2, {
    ...passkeyContext,
    wrapRef: any2.group_id,
  });
  await aadNegativeCheck(c, "aad-wrap-ref-mismatch", passkey, {
    ...passkeyContext,
    wrapRef: "01JMKWRAP0000000000000OTHER",
  });
  await aadNegativeCheck(c, "aad-user-mismatch", passkey, {
    ...passkeyContext,
    userId: testUserId("user-member-0002"),
  });
  await aadNegativeCheck(c, "aad-mode-all-as-any", all3, { ...groupContext(all3), mode: "any" });
  await aadNegativeCheck(c, "aad-mode-any-as-all", any2, { ...groupContext(any2), mode: "all" });
  // suite-mismatch: the implementation API cannot swap the domain string
  // (fixed by the type). Only check that the expected AAD bytes exist in the
  // vector; the decryption failure itself is pinned by verify_reference.mjs
  // (the independent implementation)
  c.push(
    "master-wrap negative: suite-mismatch",
    negativeNamed("suite-mismatch").decrypt_aad_hex !== undefined,
  );
}

/** hex of a successful Uint8Array result, or null (a helper to fold comparisons into one expression). */
function okHex(
  result: { readonly ok: boolean; readonly value?: Uint8Array } | null,
): string | null {
  return result?.ok === true && result.value !== undefined ? toHex(result.value) : null;
}

/** Decrypting with a "wrong KEK" that matches the vector's decrypt_kek_hex must yield DecryptFailed. */
async function expectWrongKek(
  c: Checks,
  name: string,
  base: AeadVector,
  context: MasterWrapContext,
  kek: Uint8Array | null,
): Promise<void> {
  const expected = negativeNamed(name).decrypt_kek_hex;
  if (kek === null || toHex(kek) !== expected) {
    c.push(`master-wrap negative: ${name}`, false, "derived KEK differs from the vector");
    return;
  }
  const result = await unwrapVector(base, context, kek);
  c.push(`master-wrap negative: ${name}`, !result.ok && result.error.kind === "DecryptFailed");
}

async function kekNegativeChecks(c: Checks): Promise<void> {
  // share-missing: the XOR of n−1 segments is not the KEK.
  // joinGuardianShares rejects an insufficient segment count as InvalidInput
  // first, and a KEK assembled with a faked segment count fails decryption
  const twoShares = all3.shares.slice(0, 2).map((s) => fromHex(s.share_hex));
  const tooFew = joinGuardianShares({ mode: "all", shares: twoShares, expectedCount: 3 });
  c.push(
    "master-wrap negative: share-missing rejected by join",
    !tooFew.ok && tooFew.error.kind === "InvalidInput",
  );
  const partial = joinGuardianShares({ mode: "all", shares: twoShares, expectedCount: 2 });
  await expectWrongKek(
    c,
    "share-missing",
    all3,
    groupContext(all3),
    partial.ok ? partial.value : null,
  );
  // prf-salt-mismatch: a PRF output under a different salt → a different KEK
  // → decryption fails
  const salt = negativeNamed("prf-salt-mismatch");
  const otherKek = await derivePasskeyKek(fromHex(salt.other_prf_out_hex ?? ""));
  await expectWrongKek(
    c,
    "prf-salt-mismatch",
    passkey,
    passkeyContext,
    otherKek.ok ? otherKek.value : null,
  );
}

async function guardianNegativeChecks(c: Checks): Promise<void> {
  const share1 = all3.shares[0];
  if (share1 === undefined) {
    c.push("master-wrap negative: guardian share 1", false, "share missing");
    return;
  }
  const base = shareContext(all3, share1);
  const pair = await guardianKeyPair(share1.guardian_user_id);
  const cases: readonly { readonly name: string; readonly context: GuardianWrapContext }[] = [
    { name: "guardian-transplant-share-index", context: { ...base, shareIndex: 2 } },
    {
      name: "guardian-transplant-guardian",
      context: { ...base, guardianUserId: testUserId("user-admin-0003") },
    },
    { name: "guardian-transplant-group", context: { ...base, groupId: any2.group_id } },
    { name: "guardian-mode-relabel", context: { ...base, mode: "any" } },
  ];
  for (const m of cases) {
    const infoMatches =
      negativeNamed(m.name).open_info_hex === toHex(buildGuardianWrapInfo(m.context));
    const result = await openGuardianShare({
      guardianKeyPair: pair,
      wrapped: { enc: fromHex(share1.enc_hex), ciphertext: fromHex(share1.ciphertext_hex) },
      context: m.context,
    });
    c.push(
      `master-wrap negative: ${m.name}`,
      infoMatches && !result.ok && result.error.kind === "DekUnwrapFailed",
    );
  }
}

async function handoffNegativeChecks(c: Checks, pair: EncryptionKeyPair): Promise<void> {
  const base = handoffContext(handoffShare);
  const cases: readonly { readonly name: string; readonly context: HandoffWrapContext }[] = [
    {
      name: "handoff-transplant-request-id",
      context: { ...base, requestId: doc.handoff.other_ephemeral.request_id_hex },
    },
    {
      name: "handoff-transplant-approver",
      context: { ...base, approverUserId: testUserId("user-admin-0003") },
    },
    // Relabeling the guardian segment's group (all-3 → any-2 — rebuilt from
    // the old → device shape in 2026-09-20 DK)
    { name: "handoff-transplant-source", context: { ...base, source: any2.group_id } },
    { name: "handoff-share-index-mismatch", context: { ...base, shareIndex: 2 } },
    { name: "handoff-request-id-other-key", context: base },
  ];
  for (const m of cases) {
    const n = negativeNamed(m.name);
    const infoMatches =
      n.open_info_hex === undefined || n.open_info_hex === toHex(buildHandoffWrapInfo(m.context));
    const result = await openHandoffValue({
      ephemeralKeyPair: pair,
      wrapped: {
        enc: fromHex(n.open_enc_hex ?? handoffShare.enc_hex),
        ciphertext: fromHex(handoffShare.ciphertext_hex),
      },
      context: m.context,
    });
    c.push(
      `master-wrap negative: ${m.name}`,
      infoMatches && !result.ok && result.error.kind === "DekUnwrapFailed",
    );
  }
}

async function codeNegativeChecks(c: Checks): Promise<void> {
  for (const name of [
    "handoff-code-checksum-mismatch",
    "handoff-code-bad-padding",
    "handoff-code-wrong-length",
  ]) {
    const decoded = await decodeHandoffCode(negativeNamed(name).code_symbols ?? "");
    c.push(
      `master-wrap negative: ${name}`,
      !decoded.ok &&
        decoded.error.kind === "InvalidInput" &&
        decoded.error.field === "handoff code",
    );
  }
  // Characters outside the alphabet (0 / 1 / 8 / 9) are rejected rather than
  // guessed-substituted
  const zeroForO = await decodeHandoffCode(doc.handoff.code.symbols.replace(/[A-Z]/, "0"));
  c.push("master-wrap negative: handoff code non-alphabet symbol", !zeroForO.ok);
}

async function invalidInputChecks(c: Checks): Promise<void> {
  const kek = generateMasterWrapKek();
  const blob = fromHex(blobHex);
  const wraps = await Promise.all([
    wrapMasterBlob({
      kek,
      masterSecretBlob: blob,
      context: { userId, kind: "guardian", wrapRef: "g" },
    }),
    wrapMasterBlob({
      kek,
      masterSecretBlob: blob,
      context: { userId, kind: "passkey-prf", wrapRef: "w", mode: "any" },
    }),
    wrapMasterBlob({ kek: kek.slice(0, 16), masterSecretBlob: blob, context: passkeyContext }),
  ]);
  c.push(
    "master-wrap invalid input: context mode / kek length",
    wraps.every((r) => !r.ok && r.error.kind === "InvalidInput"),
  );
  const bounds = [
    splitGuardianKek({ kek, mode: "all", count: 1 }),
    splitGuardianKek({ kek, mode: "any", count: 0 }),
    splitGuardianKek({ kek, mode: "any", count: 6 }),
    splitGuardianKek({ kek: kek.slice(0, 8), mode: "any", count: 2 }),
    joinGuardianShares({ mode: "any", shares: [kek, kek], expectedCount: 2 }),
    joinGuardianShares({ mode: "all", shares: [kek], expectedCount: 1 }),
    joinGuardianShares({ mode: "all", shares: [kek, kek.slice(0, 8)], expectedCount: 2 }),
  ];
  c.push(
    "master-wrap invalid input: split / join bounds",
    bounds.every((r) => !r.ok && r.error.kind === "InvalidInput"),
  );
  const pair = await generateEncryptionKeyPair();
  const contexts = await Promise.all([
    sealGuardianShare({
      guardianPublicKey: pair.publicKey,
      share: kek,
      context: {
        userId,
        groupId: "g",
        mode: "any",
        shareIndex: 0,
        guardianUserId: testUserId("u"),
      },
    }),
    sealHandoffValue({
      ephemeralPublicKey: pair.publicKey,
      value: kek,
      context: {
        userId,
        requestId: "r",
        source: "",
        shareIndex: 0,
        approverUserId: testUserId("u"),
      },
    }),
    sealHandoffValue({
      ephemeralPublicKey: pair.publicKey,
      value: kek,
      context: {
        userId,
        requestId: "r",
        source: "g",
        shareIndex: -1,
        approverUserId: testUserId("u"),
      },
    }),
  ]);
  c.push(
    "master-wrap invalid input: share / handoff context",
    contexts.every((r) => !r.ok && r.error.kind === "InvalidInput"),
  );
  const badPub = await encodeHandoffCode(new Uint8Array(31));
  const badId = await computeHandoffRequestId(new Uint8Array(33));
  c.push("master-wrap invalid input: ephemeral public key length", !badPub.ok && !badId.ok);
}

async function passkeyRoundtrip(c: Checks): Promise<void> {
  const blob = fromHex(blobHex);
  const kek = await derivePasskeyKek(crypto.getRandomValues(new Uint8Array(32)));
  const context: MasterWrapContext = {
    userId: testUserId("user-roundtrip"),
    kind: "passkey-prf",
    wrapRef: "w1",
  };
  if (!kek.ok) {
    c.push("master-wrap: passkey roundtrip", false, "kek derivation failed");
    return;
  }
  const wrapped = await wrapMasterBlob({ kek: kek.value, masterSecretBlob: blob, context });
  const unwrapped = wrapped.ok
    ? await unwrapMasterBlob({ kek: kek.value, wrapped: wrapped.value, context })
    : null;
  c.push(
    "master-wrap: passkey roundtrip",
    wrapped.ok &&
      wrapped.value.nonce.length === 12 &&
      unwrapped?.ok === true &&
      toHex(unwrapped.value) === toHex(blob),
  );
}

/** Seal one segment to a generated guardian key, then open with that key (a different key fails). Returns the opened segment. */
async function sealAndOpenShare(
  share: Uint8Array,
  context: GuardianWrapContext,
): Promise<Uint8Array | null> {
  const guardian = await generateEncryptionKeyPair();
  const sealed = await sealGuardianShare({ guardianPublicKey: guardian.publicKey, share, context });
  if (!sealed.ok) {
    return null;
  }
  const opened = await openGuardianShare({
    guardianKeyPair: guardian,
    wrapped: sealed.value,
    context,
  });
  const other = await generateEncryptionKeyPair();
  const wrongKey = await openGuardianShare({
    guardianKeyPair: other,
    wrapped: sealed.value,
    context,
  });
  return opened.ok && !wrongKey.ok ? opened.value : null;
}

/** Seal 3 segments to 3 generated guardian keys, then open and collect them (a failed segment drops out). */
async function recoverShares(
  mode: GuardianMode,
  shares: readonly Uint8Array[],
): Promise<Uint8Array[]> {
  const recovered: Uint8Array[] = [];
  for (const [i, share] of shares.entries()) {
    const opened = await sealAndOpenShare(share, {
      userId: testUserId("user-roundtrip"),
      groupId: `g-${mode}`,
      mode,
      shareIndex: i + 1,
      guardianUserId: testUserId(`guardian-${i + 1}`),
    });
    if (opened !== null) {
      recovered.push(opened);
    }
  }
  return recovered;
}

async function guardianRoundtrip(c: Checks, mode: GuardianMode): Promise<void> {
  const blob = fromHex(blobHex);
  const groupKek = generateMasterWrapKek();
  const context: MasterWrapContext = {
    userId: testUserId("user-roundtrip"),
    kind: "guardian",
    wrapRef: `g-${mode}`,
    mode,
  };
  const groupWrap = await wrapMasterBlob({ kek: groupKek, masterSecretBlob: blob, context });
  const shares = splitGuardianKek({ kek: groupKek, mode, count: 3 });
  if (!groupWrap.ok || !shares.ok) {
    c.push(`master-wrap: guardian ${mode} roundtrip`, false, "wrap / split failed");
    return;
  }
  const recovered = await recoverShares(mode, shares.value);
  const joined = joinGuardianShares({
    mode,
    shares: mode === "any" ? recovered.slice(1, 2) : recovered,
    expectedCount: 3,
  });
  const unwrapped = joined.ok
    ? await unwrapMasterBlob({ kek: joined.value, wrapped: groupWrap.value, context })
    : null;
  c.push(
    `master-wrap: guardian ${mode} roundtrip`,
    recovered.length === 3 && okHex(joined) === toHex(groupKek) && okHex(unwrapped) === blobHex,
  );
  if (mode === "all") {
    // Any 2 segments are independent of the KEK: the XOR of 2 segments does
    // not equal the KEK
    const pairJoin = joinGuardianShares({ mode, shares: recovered.slice(0, 2), expectedCount: 2 });
    c.push(
      "master-wrap: guardian all roundtrip partial shares != KEK",
      pairJoin.ok && toHex(pairJoin.value) !== toHex(groupKek),
    );
  }
}

/** ephemeral public key → code → decode → request_id. Returns null if the roundtrip does not hold. */
async function codeRoundtrip(pub: Uint8Array): Promise<string | null> {
  const code = await encodeHandoffCode(pub);
  const decoded = code.ok ? await decodeHandoffCode(code.value) : null;
  if (okHex(decoded) !== toHex(pub) || decoded?.ok !== true) {
    return null;
  }
  const requestId = await computeHandoffRequestId(decoded.value);
  return requestId.ok ? requestId.value : null;
}

async function handoffRoundtrip(c: Checks): Promise<void> {
  // generated ephemeral key → code → decode → request_id → seal / open
  const ephemeral = await generateEncryptionKeyPair();
  const pub = await exportEncryptionPublicKey(ephemeral.publicKey);
  const requestId = await codeRoundtrip(pub);
  const context: HandoffWrapContext = {
    userId: testUserId("user-roundtrip"),
    requestId: requestId ?? "",
    source: "01JMKGRP0000000000ROUNDTRIP",
    shareIndex: 0,
    approverUserId: testUserId("user-roundtrip"),
  };
  const kekH = generateMasterWrapKek();
  const sealed = await sealHandoffValue({
    ephemeralPublicKey: ephemeral.publicKey,
    value: kekH,
    context,
  });
  if (!sealed.ok) {
    c.push("master-wrap: handoff roundtrip", false, "seal failed");
    return;
  }
  const opened = await openHandoffValue({
    ephemeralKeyPair: ephemeral,
    wrapped: sealed.value,
    context,
  });
  c.push("master-wrap: handoff roundtrip", requestId !== null && okHex(opened) === toHex(kekH));
  // A different ephemeral key cannot open it (once the requester process
  // ends, the approval is worthless)
  const otherEphemeral = await generateEncryptionKeyPair();
  const wrongKey = await openHandoffValue({
    ephemeralKeyPair: otherEphemeral,
    wrapped: sealed.value,
    context,
  });
  c.push("master-wrap: handoff roundtrip other ephemeral key rejected", !wrongKey.ok);
}

export async function masterKeyWrapChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  provenanceChecks(c);
  await passkeyChecks(c);
  await guardianGroupChecks(c, any2);
  await guardianGroupChecks(c, all3);
  const pair = await importPair(doc.ephemeral_keypair.pk_hex, doc.ephemeral_keypair.sk_hex);
  await handoffIdChecks(c);
  await handoffOpenChecks(c, pair);
  await aadNegativeChecks(c);
  await kekNegativeChecks(c);
  await guardianNegativeChecks(c);
  await handoffNegativeChecks(c, pair);
  await codeNegativeChecks(c);
  await invalidInputChecks(c);
  await passkeyRoundtrip(c);
  await guardianRoundtrip(c, "any");
  await guardianRoundtrip(c, "all");
  await handoffRoundtrip(c);
  return c.results;
}
