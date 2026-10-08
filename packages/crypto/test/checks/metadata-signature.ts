// Checks for CRYPTO_SPEC §4.2 (signed statements of variable/environment
// metadata).
// Ed25519 is an RFC 8032 deterministic signature, so the signing direction is
// verified byte-for-byte against the vectors too.
// For the verification-rule kind (kind = "authorization"), pin that "the
// signature is valid but is rejected by the §6.3 history verification with
// expected_reason" via verifyDistributedMetaStatement against the history
// index built by verifyChainWithHistory.
//
// Metadata-specific pinning points (differences from value-signature):
// - var-meta-head-before-env-create is a **positive** (no epoch anchor — an
//   intentional asymmetry that does not check environment existence.
//   §14.3-5 / AUTH_SPEC §12-4)
// - rename_fork (a fork at the same metaVersion) and name_swap (a name
//   swap fails signature verification)
// - revive-after-delete (every successor of a deleted predecessor is
//   rejected)
// - v2-layout-unsupported (kind = unsupported-layout): the retired layout v2
//   is refused with UnsupportedMetaLayout before signature verification

import type {
  ChainHistoryIndex,
  CryptoResult,
  MetaInvalidReason,
  MetaStatementContext,
  MetaVariableSchema,
} from "../../src/index.ts";
import {
  buildMetaSignedBytes,
  computeMetaSignedBytesHash,
  generateSigningKeyPair,
  importSigningKeyPair,
  importSigningPublicKey,
  signMetaStatement,
  verifyDistributedMetaStatement,
  verifyMetaStatementSignature,
} from "../../src/index.ts";
import metaVectors from "../../test-vectors/metadata-signature.json" with { type: "json" };
import {
  testEnvironmentId,
  testProjectId,
  testUserId,
  testVariableId,
} from "../support/fixture.ts";
import { canonicalHistory, extendedVectorChainHistory } from "./chain-history.ts";
import { importVectorSigner, vectorKeys } from "./chain-vector.ts";
import { metaExtendedHistory } from "./meta-history.ts";
import {
  type CheckResult,
  Checks,
  expectRejectedReason,
  fromHex,
  reasonCoverageChecks,
  toHex,
} from "./support.ts";

interface VectorContext {
  readonly kind: string;
  readonly suite: string;
  readonly project_id: string;
  readonly environment_id: string;
  readonly variable_id?: string;
  readonly name: string;
  readonly status: string;
  readonly layout_version?: number;
  readonly var_type?: string;
  readonly required?: string;
  readonly description?: string;
  /** Layout v3 only (PF6 R9): "" or a decimal 1..3650. */
  readonly max_age_days?: string;
  readonly meta_version: number;
  readonly prev_meta_sig_hash_hex: string;
  readonly author_user_id: string;
  readonly chain_head_hash_hex: string;
  readonly chain_head_seq: number;
}

interface MetaVector {
  readonly name: string;
  /** Comparison chain (unset = canonical. device-ops = the device-key derived chain — 2026-09-19 DK). */
  readonly chain?: string;
  readonly context: VectorContext;
  readonly author_key_fingerprint_hex: string;
  readonly signed_bytes_hex: string;
  readonly signed_bytes_sha256_hex: string;
  readonly signature_hex: string;
  readonly prev_base?: string;
}

interface MetaNegative {
  readonly name: string;
  readonly kind?: string;
  readonly chain?: string;
  readonly context: VectorContext;
  readonly author_key_fingerprint_hex?: string;
  readonly verify_signed_bytes_hex?: string;
  readonly signed_bytes_hex?: string;
  readonly signature_hex: string;
  readonly verify_key_hex: string;
  readonly expected_reason?: string;
  readonly expected_error?: string;
  readonly predecessor?: {
    readonly base: string;
    readonly signed_bytes_sha256_hex: string;
    readonly status: string;
    readonly layout_version?: number;
  };
  readonly must_fail: boolean;
}

function contextOf(v: VectorContext): MetaStatementContext {
  return {
    suite: v.suite,
    projectId: testProjectId(v.project_id),
    environmentId: testEnvironmentId(v.environment_id),
    target:
      v.kind === "variable"
        ? { kind: "variable", variableId: testVariableId(v.variable_id ?? "") }
        : { kind: "environment" },
    name: v.name,
    status: v.status as MetaStatementContext["status"],
    layoutVersion: v.layout_version,
    schema: v.required === undefined ? undefined : schemaOf(v),
    metaVersion: v.meta_version,
    prevMetaSigHashHex: v.prev_meta_sig_hash_hex,
    authorUserId: testUserId(v.author_user_id),
    chainHeadHashHex: v.chain_head_hash_hex,
    chainHeadSeq: v.chain_head_seq,
  };
}

/**
 * The schema fields (var_type / required / description / max_age_days)
 * exist as one set (§4.2 — required represents presence on the vector
 * side). max_age_days rides only when the vector has the key: its absence
 * is the v3-missing-max-age shape negative (and the retired v2 encoding has
 * none), so the cast carries that wire shape into the implementation,
 * whose validation must refuse it.
 */
function schemaOf(v: VectorContext): MetaVariableSchema {
  const schema = {
    varType: (v.var_type ?? "") as MetaVariableSchema["varType"],
    required: v.required as MetaVariableSchema["required"],
    description: v.description ?? "",
    ...(v.max_age_days === undefined ? {} : { maxAgeDays: v.max_age_days }),
  };
  return schema as MetaVariableSchema;
}

/**
 * The builder's signed bytes as lowercase hex, or null when the builder
 * refuses the context's layout (never equal to any vector's hex).
 */
function signedBytesHexOf(context: MetaStatementContext): string | null {
  const built = buildMetaSignedBytes(context);
  return built.ok ? toHex(built.value) : null;
}

const positives: readonly MetaVector[] = metaVectors.vectors;

/** Comparison chains (name → verified history index). A vector with `chain` unset means canonical. */
type Histories = Readonly<Record<string, ChainHistoryIndex>>;

function historyFor(
  histories: Histories,
  chain: string | undefined,
): ChainHistoryIndex | undefined {
  return histories[chain ?? "canonical"];
}
const byName = new Map(positives.map((v) => [v.name, v]));

function predecessorOf(vector: MetaVector) {
  if (vector.prev_base === undefined) {
    return undefined;
  }
  const base = byName.get(vector.prev_base);
  return base === undefined
    ? undefined
    : {
        signedBytesHashHex: base.signed_bytes_sha256_hex,
        status: base.context.status as MetaStatementContext["status"],
        // Required on the MetaPredecessor side (fail-closed). A vector
        // omission = v1
        layoutVersion: base.context.layout_version ?? 1,
      };
}

/** Two checks: the signing direction (deterministic re-signing) and the low-level verification direction. */
async function signAndVerifyChecks(
  c: Checks,
  name: string,
  context: MetaStatementContext,
  signatureHex: string,
  authorKeyFingerprintHex: string,
): Promise<void> {
  // Sign with the author's device (user_id, FP) seed (2026-09-19 DK —
  // signers are per-device)
  const signer = await importVectorSigner(context.authorUserId, authorKeyFingerprintHex);
  if (signer === null) {
    c.push(`meta-sig ${name}: author keys`, false, "signer keys missing or failed to import");
    return;
  }
  const signed = await signMetaStatement({ context, signingKey: signer.privateKey });
  c.push(
    `meta-sig ${name}: deterministic re-sign matches vector`,
    signed.ok && signed.value === signatureHex,
  );
  const verified = await verifyMetaStatementSignature({
    context,
    signatureHex,
    authorPublicKey: signer.publicKey,
  });
  c.push(`meta-sig ${name}: raw signature verify`, verified.ok);
}

async function vectorChecks(c: Checks, histories: Histories): Promise<void> {
  for (const vector of positives) {
    const history = historyFor(histories, vector.chain);
    if (history === undefined) {
      c.push(`meta-sig ${vector.name}: history`, false, "history missing");
      continue;
    }
    const context = contextOf(vector.context);
    c.push(
      `meta-sig ${vector.name}: signed bytes construction`,
      signedBytesHexOf(context) === vector.signed_bytes_hex,
    );
    const hash = await computeMetaSignedBytesHash(context);
    c.push(
      `meta-sig ${vector.name}: signed bytes hash`,
      hash.ok && hash.value === vector.signed_bytes_sha256_hex,
    );
    // Deletion statements (status deleted, metaVersion > 1) must be
    // signable legitimately, so deletion vectors are also checked through
    // deterministic re-signing
    await signAndVerifyChecks(
      c,
      vector.name,
      context,
      vector.signature_hex,
      vector.author_key_fingerprint_hex,
    );

    // History-based composite verification (§6.3): predecessor included
    // when prev_base exists. var-meta-head-before-env-create (a pre-
    // environment-creation head) also passes through here = positive
    const distributed = await verifyDistributedMetaStatement({
      history,
      context,
      authorKeyFingerprintHex: vector.author_key_fingerprint_hex,
      signatureHex: vector.signature_hex,
      predecessor: predecessorOf(vector),
    });
    c.push(
      `meta-sig ${vector.name}: distributed verify`,
      distributed.ok && distributed.value.signedBytesHashHex === vector.signed_bytes_sha256_hex,
      distributed.ok ? undefined : JSON.stringify(distributed.error),
    );
  }
  deleteRetentionChecks(c);
}

/** Re-confirm the data of the deletion-statement retention convention (§4.2). */
function deleteRetentionChecks(c: Checks): void {
  // A deletion retains the last active name
  const del = byName.get("var-delete");
  const rename = byName.get("var-rename");
  c.push(
    "meta-sig var-delete: keeps last active name",
    del?.context.status === "deleted" && del.context.name === rename?.context.name,
  );
  deleteRetentionV3Checks(c);
}

/**
 * A v3 deletion fully retains the schema fields (max_age_days included) and
 * the layout from the previous statement under the same convention as name
 * (§4.2 layout v3).
 */
function deleteRetentionV3Checks(c: Checks): void {
  const deleted = byName.get("var-v3-delete-keeps-max-age")?.context;
  const created = byName.get("var-v3-create-expiring")?.context;
  const keptFields = ["name", "var_type", "required", "description", "max_age_days"] as const;
  c.push(
    "meta-sig var-v3-delete-keeps-max-age: keeps the schema fields and layout from predecessor",
    deleted?.status === "deleted" &&
      deleted.layout_version === 3 &&
      deleted.max_age_days === "90" &&
      keptFields.every((field) => deleted[field] === created?.[field]),
  );
}

async function forkChecks(c: Checks, history: ChainHistoryIndex): Promise<void> {
  const branches: readonly MetaVector[] = metaVectors.rename_fork.branches;
  const hashes: string[] = [];
  for (const branch of branches) {
    const result = await verifyDistributedMetaStatement({
      history,
      context: contextOf(branch.context),
      authorKeyFingerprintHex: branch.author_key_fingerprint_hex,
      signatureHex: branch.signature_hex,
      predecessor: predecessorOf(branch),
    });
    // Each branch passes all checks on its own (prevention is impossible —
    // the evidence-recording of §14.2-5)
    c.push(`meta-sig fork ${branch.name}: verifies individually`, result.ok);
    if (result.ok) {
      hashes.push(result.value.signedBytesHashHex);
    }
  }
  c.push(
    "meta-sig fork: same coordinate yields distinct hashes",
    hashes.length === 2 && hashes[0] !== hashes[1],
  );
}

async function nameSwapChecks(c: Checks, history: ChainHistoryIndex): Promise<void> {
  // Each of the 2 canonical statements verifies on its own (the name ↔ ID
  // binding is carried by the signature)
  for (const statement of metaVectors.name_swap.statements as readonly MetaVector[]) {
    const result = await verifyDistributedMetaStatement({
      history,
      context: contextOf(statement.context),
      authorKeyFingerprintHex: statement.author_key_fingerprint_hex,
      signatureHex: statement.signature_hex,
    });
    c.push(`meta-sig name-swap ${statement.name}: verifies individually`, result.ok);
  }
  // A byte string with only the name field swapped fails the original
  // signature's verification
  for (const swapped of metaVectors.name_swap.swapped as readonly MetaNegative[]) {
    const context = contextOf(swapped.context);
    const bytesMatch = signedBytesHexOf(context) === swapped.verify_signed_bytes_hex;
    const key = await importSigningPublicKey(fromHex(swapped.verify_key_hex));
    if (!key.ok) {
      c.push(`meta-sig name-swap: ${swapped.name}`, false, "verify key import failed");
      continue;
    }
    const result = await verifyMetaStatementSignature({
      context,
      signatureHex: swapped.signature_hex,
      authorPublicKey: key.value,
    });
    c.push(`meta-sig name-swap: ${swapped.name}`, bytesMatch && !result.ok);
  }
}

// Exhaustiveness pinning of the reason space (checked by support.ts's
// reasonCoverageChecks): the Record type enforces sync with the union
// **at compile time**, so "implemented a new rejection rule but neither
// the vectors nor the harness has a negative for it" is caught by type +
// test.
const META_REASON_COVERAGE: Record<MetaInvalidReason, true> = {
  "signature-invalid": true,
  "author-unknown": true,
  "chain-head-mismatch": true,
  "chain-head-future": true,
  "author-not-member-at-head": true,
  "author-key-mismatch-at-head": true,
  "author-role-insufficient-at-head": true,
  "author-environment-out-of-scope-at-head": true,
  "prev-shape-mismatch": true,
  "prev-hash-mismatch": true,
  "revived-after-delete": true,
  "declared-after-active": true,
  "layout-regression": true,
};

/** Verification-rule negative: the signature is valid but history verification rejects it with expected_reason. */
async function ruleNegativeCheck(
  c: Checks,
  negative: MetaNegative,
  histories: Histories,
  exercised: Set<MetaInvalidReason>,
): Promise<void> {
  const chainHistory = historyFor(histories, negative.chain);
  if (chainHistory === undefined) {
    c.push(`meta-sig rule negative: ${negative.name}`, false, `unknown chain ${negative.chain}`);
    return;
  }
  const result = await verifyDistributedMetaStatement({
    history: chainHistory,
    context: contextOf(negative.context),
    authorKeyFingerprintHex: negative.author_key_fingerprint_hex ?? "",
    signatureHex: negative.signature_hex,
    predecessor:
      negative.predecessor === undefined
        ? undefined
        : {
            signedBytesHashHex: negative.predecessor.signed_bytes_sha256_hex,
            status: negative.predecessor.status as MetaStatementContext["status"],
            layoutVersion: negative.predecessor.layout_version ?? 1,
          },
  });
  expectRejectedReason(
    c,
    `meta-sig rule negative: ${negative.name}`,
    !result.ok && result.error.kind === "MetaStatementInvalid" ? result.error.reason : undefined,
    negative.expected_reason,
    exercised,
    result.ok ? "verified unexpectedly" : JSON.stringify(result.error),
  );
}

/** Tamper/transplant negative: canonicalization reproduces the vector's verify-side byte string, and the original signature fails. */
async function tamperNegativeCheck(
  c: Checks,
  negative: MetaNegative,
  exercised: Set<MetaInvalidReason>,
): Promise<void> {
  const context = contextOf(negative.context);
  const bytesMatch = signedBytesHexOf(context) === negative.verify_signed_bytes_hex;
  const key = await importSigningPublicKey(fromHex(negative.verify_key_hex));
  if (!key.ok) {
    c.push(`meta-sig negative: ${negative.name}`, false, "verify key import failed");
    return;
  }
  const result = await verifyMetaStatementSignature({
    context,
    signatureHex: negative.signature_hex,
    authorPublicKey: key.value,
  });
  expectRejectedReason(
    c,
    `meta-sig negative: ${negative.name}`,
    bytesMatch && !result.ok && result.error.kind === "MetaStatementInvalid"
      ? result.error.reason
      : undefined,
    "signature-invalid",
    exercised,
  );
}

/**
 * Structural-violation negatives (kind = invalid-input): the signature is
 * valid over the given byte string (confirmed by the reference
 * implementation), but as a wire-form structural violation (v1 declared,
 * v3 empty required) it is rejected with InvalidInput before signature
 * verification is reached (§4.2 / ruling CS — the rejection is not by
 * cryptographic verification).
 */
async function invalidInputNegativeCheck(c: Checks, negative: MetaNegative): Promise<void> {
  const context = contextOf(negative.context);
  // The encoder is total over field values (it refuses only a layout it
  // cannot select — none of these vectors), so also pin that it reproduces
  // the vector's signed_bytes
  const bytesMatch = signedBytesHexOf(context) === negative.signed_bytes_hex;
  const key = await importSigningPublicKey(fromHex(negative.verify_key_hex));
  if (!key.ok) {
    c.push(`meta-sig invalid-input negative: ${negative.name}`, false, "key import failed");
    return;
  }
  const verified = await verifyMetaStatementSignature({
    context,
    signatureHex: negative.signature_hex,
    authorPublicKey: key.value,
  });
  const hash = await computeMetaSignedBytesHash(context);
  c.push(
    `meta-sig invalid-input negative: ${negative.name}`,
    bytesMatch &&
      !verified.ok &&
      verified.error.kind === negative.expected_error &&
      !hash.ok &&
      hash.error.kind === negative.expected_error,
    verified.ok ? "verified unexpectedly" : JSON.stringify(verified.error),
  );
}

function isUnsupportedLayout(result: CryptoResult<unknown>, layoutVersion: number): boolean {
  return (
    !result.ok &&
    result.error.kind === "UnsupportedMetaLayout" &&
    result.error.layoutVersion === layoutVersion
  );
}

/**
 * Retired-layout negatives (kind = unsupported-layout — §4.2 0.15-draft):
 * the statement is validly signed over the retired v2 encoding (confirmed by
 * the reference implementation), and every entry point — the signed-bytes
 * builder, signing, raw verification, hashing, and history verification
 * with the real author key — refuses it with the typed
 * UnsupportedMetaLayout. The history path would otherwise reach the
 * signature check (the author key exists), so the typed error proves the
 * rejection precedes signature verification; the builder's refusal proves
 * it never falls back to the v1 encoding.
 */
async function unsupportedLayoutNegativeCheck(
  c: Checks,
  negative: MetaNegative,
  histories: Histories,
): Promise<void> {
  const label = `meta-sig unsupported-layout negative: ${negative.name}`;
  const history = historyFor(histories, negative.chain);
  const key = await importSigningPublicKey(fromHex(negative.verify_key_hex));
  if (history === undefined || !key.ok) {
    c.push(label, false, "history or key missing");
    return;
  }
  const results = await unsupportedLayoutEntryPoints(negative, history, key.value);
  const layoutVersion = negative.context.layout_version;
  c.push(
    label,
    negative.expected_error === "UnsupportedMetaLayout" &&
      results.every((result) => isUnsupportedLayout(result, layoutVersion ?? 1)),
  );
}

/** The outcomes of building, signing, raw verification, hashing, and history verification of one negative. */
async function unsupportedLayoutEntryPoints(
  negative: MetaNegative,
  history: ChainHistoryIndex,
  authorPublicKey: CryptoKey,
): Promise<readonly CryptoResult<unknown>[]> {
  const context = contextOf(negative.context);
  const pair = await generateSigningKeyPair();
  return [
    buildMetaSignedBytes(context),
    await signMetaStatement({ context, signingKey: pair.privateKey }),
    await verifyMetaStatementSignature({
      context,
      signatureHex: negative.signature_hex,
      authorPublicKey,
    }),
    await computeMetaSignedBytesHash(context),
    await verifyDistributedMetaStatement({
      history,
      context,
      authorKeyFingerprintHex: negative.author_key_fingerprint_hex ?? "",
      signatureHex: negative.signature_hex,
    }),
  ];
}

async function negativeChecks(
  c: Checks,
  histories: Histories,
  exercised: Set<MetaInvalidReason>,
): Promise<void> {
  const seenKinds = new Set<string>();
  for (const negative of metaVectors.negative as readonly MetaNegative[]) {
    seenKinds.add(negative.kind ?? "signature");
    if (negative.kind === "authorization") {
      await ruleNegativeCheck(c, negative, histories, exercised);
    } else if (negative.kind === "invalid-input") {
      await invalidInputNegativeCheck(c, negative);
    } else if (negative.kind === "unsupported-layout") {
      await unsupportedLayoutNegativeCheck(c, negative, histories);
    } else {
      await tamperNegativeCheck(c, negative, exercised);
    }
  }
  // Pin the kind vocabulary (a third value would escape every sieve)
  c.push(
    "meta-sig negative: kind vocabulary is exhaustive",
    [...seenKinds].every(
      (kind) =>
        kind === "signature" ||
        kind === "authorization" ||
        kind === "invalid-input" ||
        kind === "unsupported-layout",
    ),
  );
}

async function invalidInputChecks(c: Checks): Promise<void> {
  const base = positives[0];
  if (base === undefined) {
    c.push("meta-sig invalid input: base vector", false);
    return;
  }
  const pair = await generateSigningKeyPair();
  const baseContext = contextOf(base.context);
  const badContexts: readonly { name: string; context: MetaStatementContext }[] = [
    { name: "bad meta version", context: { ...baseContext, metaVersion: 0 } },
    { name: "bad head seq", context: { ...baseContext, chainHeadSeq: 0 } },
    { name: "empty name", context: { ...baseContext, name: "" } },
    {
      name: "bad status",
      context: { ...baseContext, status: "archived" as MetaStatementContext["status"] },
    },
    { name: "short prev hash", context: { ...baseContext, prevMetaSigHashHex: "abcd" } },
    { name: "short head hash", context: { ...baseContext, chainHeadHashHex: "abcd" } },
    { name: "empty suite", context: { ...baseContext, suite: "" } },
    { name: "empty project id", context: { ...baseContext, projectId: testProjectId("") } },
    {
      name: "empty environment id",
      context: { ...baseContext, environmentId: testEnvironmentId("") },
    },
    { name: "empty author", context: { ...baseContext, authorUserId: testUserId("") } },
    {
      name: "empty variable id",
      context: { ...baseContext, target: { kind: "variable", variableId: testVariableId("") } },
    },
  ];
  for (const bad of badContexts) {
    const signed = await signMetaStatement({ context: bad.context, signingKey: pair.privateKey });
    const verified = await verifyMetaStatementSignature({
      context: bad.context,
      signatureHex: base.signature_hex,
      authorPublicKey: pair.publicKey,
    });
    c.push(
      `meta-sig invalid input: ${bad.name}`,
      !signed.ok &&
        signed.error.kind === "InvalidInput" &&
        !verified.ok &&
        verified.error.kind === "InvalidInput",
    );
  }
  // Checks only on the signing side (the verify side instead rejects
  // asymmetrically with a reason code — same shape as value-sign): a
  // non-empty prev on metaVersion 1, and status deleted on metaVersion 1
  // (creation is active — §4.2)
  const coupledPrev = await signMetaStatement({
    context: { ...baseContext, metaVersion: 1, prevMetaSigHashHex: "ab".repeat(32) },
    signingKey: pair.privateKey,
  });
  c.push(
    "meta-sig invalid input: sign rejects v1 with non-empty prev",
    !coupledPrev.ok && coupledPrev.error.kind === "InvalidInput",
  );
  const coupledStatus = await signMetaStatement({
    context: { ...baseContext, metaVersion: 1, prevMetaSigHashHex: "", status: "deleted" },
    signingKey: pair.privateKey,
  });
  c.push(
    "meta-sig invalid input: sign rejects deleted at metaVersion 1",
    !coupledStatus.ok && coupledStatus.error.kind === "InvalidInput",
  );
  const shortSignature = await verifyMetaStatementSignature({
    context: baseContext,
    signatureHex: "ab".repeat(63),
    authorPublicKey: pair.publicKey,
  });
  c.push(
    "meta-sig invalid input: short signature",
    !shortSignature.ok && shortSignature.error.kind === "InvalidInput",
  );
}

/**
 * Layout-dependent structural violations (§4.2 — the split of duties not
 * expressed as JSON vectors): schema fields on v1, missing schema fields
 * on v3, a var_type closed-set violation, v3 targeting environment meta.
 */
async function layoutInvalidInputChecks(c: Checks): Promise<void> {
  const base = positives[0];
  const v3Base = byName.get("var-v3-create-expiring");
  if (base === undefined || v3Base === undefined) {
    c.push("meta-sig invalid input: v3 base vector", false);
    return;
  }
  const pair = await generateSigningKeyPair();
  const baseContext = contextOf(base.context);
  const v3Context = contextOf(v3Base.context);
  const layoutBadContexts: readonly { name: string; context: MetaStatementContext }[] = [
    { name: "schema on layout 1", context: { ...baseContext, schema: v3Context.schema } },
    { name: "missing schema on layout 3", context: { ...v3Context, schema: undefined } },
    {
      name: "unknown var type",
      context: {
        ...v3Context,
        schema: {
          varType: "secret" as MetaVariableSchema["varType"],
          required: "true",
          description: "Rule fixture",
          maxAgeDays: "",
        },
      },
    },
    {
      name: "environment target on layout 3",
      context: { ...v3Context, target: { kind: "environment" } },
    },
  ];
  for (const bad of layoutBadContexts) {
    const signed = await signMetaStatement({ context: bad.context, signingKey: pair.privateKey });
    const verified = await verifyMetaStatementSignature({
      context: bad.context,
      signatureHex: v3Base.signature_hex,
      authorPublicKey: pair.publicKey,
    });
    c.push(
      `meta-sig invalid input: ${bad.name}`,
      !signed.ok &&
        signed.error.kind === "InvalidInput" &&
        !verified.ok &&
        verified.error.kind === "InvalidInput",
    );
  }
}

/**
 * Layout selection (§4.2 / ruling CR — a layout with no reference statement
 * is pinned on the harness side per the convention-21 split of duties; the
 * retired layout 2 is also pinned by the v2-layout-unsupported vector): an
 * unsupported layoutVersion is rejected with UnsupportedMetaLayout
 * **before signature verification** (an honest failure mode — not
 * collapsed into invalid signature or InvalidInput). An explicit
 * layoutVersion 1 is equivalent to omitted.
 */
async function layoutSelectionChecks(c: Checks, history: ChainHistoryIndex): Promise<void> {
  const base = byName.get("var-v3-create-expiring");
  if (base === undefined) {
    c.push("meta-sig layout selection: base vector", false);
    return;
  }
  // The supported set is {1, 3}: the retired 2 and the first future 4 are
  // both unsupported
  for (const layoutVersion of [2, 4]) {
    const unsupported: MetaStatementContext = { ...contextOf(base.context), layoutVersion };
    const pair = await generateSigningKeyPair();
    const signed = await signMetaStatement({ context: unsupported, signingKey: pair.privateKey });
    const verified = await verifyMetaStatementSignature({
      context: unsupported,
      signatureHex: base.signature_hex,
      authorPublicKey: pair.publicKey,
    });
    const hash = await computeMetaSignedBytesHash(unsupported);
    // Never even reaches signing-key resolution (author-unknown) =
    // rejection before signature verification; pin it by passing an FP
    // that does not exist in the history
    const distributed = await verifyDistributedMetaStatement({
      history,
      context: unsupported,
      authorKeyFingerprintHex: "00".repeat(16),
      signatureHex: base.signature_hex,
    });
    c.push(
      `meta-sig layout selection: builder rejects unsupported layout ${layoutVersion} (no v1 fallback)`,
      isUnsupportedLayout(buildMetaSignedBytes(unsupported), layoutVersion),
    );
    c.push(
      `meta-sig layout selection: sign rejects unsupported layout ${layoutVersion}`,
      isUnsupportedLayout(signed, layoutVersion),
    );
    c.push(
      `meta-sig layout selection: verify rejects unsupported layout ${layoutVersion}`,
      isUnsupportedLayout(verified, layoutVersion),
    );
    c.push(
      `meta-sig layout selection: hash rejects unsupported layout ${layoutVersion}`,
      isUnsupportedLayout(hash, layoutVersion),
    );
    c.push(
      `meta-sig layout selection: distributed verify rejects layout ${layoutVersion} before key resolution`,
      isUnsupportedLayout(distributed, layoutVersion),
    );
  }
  // Structural violations of layoutVersion (0 / non-integer) are
  // InvalidInput (a broken wire form, not version negotiation)
  for (const bad of [0, 1.5]) {
    const context: MetaStatementContext = { ...contextOf(base.context), layoutVersion: bad };
    const results: readonly CryptoResult<unknown>[] = [
      buildMetaSignedBytes(context),
      await computeMetaSignedBytesHash(context),
    ];
    c.push(
      `meta-sig layout selection: layoutVersion ${bad} is invalid input (builder and hash)`,
      results.every((result) => isInvalidInput(result, "context layoutVersion")),
    );
  }
  // An explicit layoutVersion 1 is equivalent to omitted (§4.2 — omitted
  // = 1)
  const v1 = byName.get("var-create");
  if (v1 === undefined) {
    c.push("meta-sig layout selection: v1 base vector", false);
    return;
  }
  c.push(
    "meta-sig layout selection: explicit layoutVersion 1 equals omitted",
    signedBytesHexOf({ ...contextOf(v1.context), layoutVersion: 1 }) === v1.signed_bytes_hex,
  );
}

function isInvalidInput(result: CryptoResult<unknown>, field: string): boolean {
  return !result.ok && result.error.kind === "InvalidInput" && result.error.field === field;
}

/**
 * The layout's field set (§4.2): layout 3 exists only for variable
 * statements and carries the schema fields; layout 1 carries none. A
 * context whose fields do not match its declared layout selects no layout,
 * so every entry point — the signed-bytes builder included — refuses it
 * with the same InvalidInput, and the builder never encodes it under the
 * other layout (a v3 environment statement or a schema-less v3 variable
 * statement used to fall back to the v1 encoding; a v1 statement with
 * schema fields used to drop them from the signed bytes). Rejection cases
 * have no reference expected value, so they are pinned here (convention
 * 21's split).
 */
async function layoutFieldSetChecks(c: Checks, history: ChainHistoryIndex): Promise<void> {
  const v3 = byName.get("var-v3-create-expiring");
  const env = positives.find((vector) => vector.context.kind === "environment");
  if (v3 === undefined || env === undefined) {
    c.push("meta-sig layout field set: base vectors", false);
    return;
  }
  const v3Context = contextOf(v3.context);
  const cases: readonly {
    readonly name: string;
    readonly context: MetaStatementContext;
    readonly field: string;
  }[] = [
    {
      name: "layout 3 on an environment statement",
      context: { ...contextOf(env.context), layoutVersion: 3, schema: v3Context.schema },
      field: "context layoutVersion",
    },
    {
      name: "layout 3 without schema fields",
      context: { ...v3Context, schema: undefined },
      field: "context schema",
    },
    {
      name: "layout 1 with schema fields",
      context: { ...v3Context, layoutVersion: 1 },
      field: "context schema",
    },
    {
      name: "omitted layout with schema fields",
      context: { ...v3Context, layoutVersion: undefined },
      field: "context schema",
    },
  ];
  const pair = await generateSigningKeyPair();
  for (const { name, context, field } of cases) {
    const results: readonly CryptoResult<unknown>[] = [
      buildMetaSignedBytes(context),
      await computeMetaSignedBytesHash(context),
      await signMetaStatement({ context, signingKey: pair.privateKey }),
      await verifyMetaStatementSignature({
        context,
        signatureHex: v3.signature_hex,
        authorPublicKey: pair.publicKey,
      }),
      await verifyDistributedMetaStatement({
        history,
        context,
        authorKeyFingerprintHex: "00".repeat(16),
        signatureHex: v3.signature_hex,
      }),
    ];
    c.push(
      `meta-sig layout field set: ${name} is refused by every entry point`,
      results.every((result) => isInvalidInput(result, field)),
    );
  }
  // Layout selection precedes field-value validation: a context that both
  // selects no layout and carries a bad coordinate reports the layout
  // (parse the layout, then validate and encode under it)
  const both: MetaStatementContext = {
    ...contextOf(env.context),
    layoutVersion: 3,
    schema: v3Context.schema,
    suite: "",
  };
  c.push(
    "meta-sig layout field set: the layout is judged before the coordinates",
    isInvalidInput(buildMetaSignedBytes(both), "context layoutVersion") &&
      isInvalidInput(await computeMetaSignedBytesHash(both), "context layoutVersion"),
  );
}

/**
 * Property check of domain separation (§4.2 — consideration 7):
 * signed_bytes of the same coordinate encoded as v1 / v3 must always
 * differ. The confusion vectors (both directions of layout-confusion)
 * illustrate on fixed inputs, but this is a generative direct check — an
 * implementation that drops the domain-separation string cannot fake it
 * unless a vector regeneration happens to coincide. Also pins that a
 * degenerate v3 with all schema fields empty still does not collide with
 * v1 (that the separation depends on the domain tag, not the LP
 * structure).
 */
function layoutDomainSeparationChecks(c: Checks): void {
  const v3 = byName.get("var-v3-create-expiring");
  if (v3 === undefined) {
    c.push("meta-sig domain separation: v3 base vector", false);
    return;
  }
  const v3Context = contextOf(v3.context);
  const v1Context: MetaStatementContext = {
    ...v3Context,
    layoutVersion: undefined,
    schema: undefined,
  };
  const v1Bytes = signedBytesHexOf(v1Context);
  const v3Bytes = signedBytesHexOf(v3Context);
  c.push(
    "meta-sig domain separation: same coordinates encode differently across layouts",
    v1Bytes !== null && v1Bytes !== v3Bytes && v3Bytes === v3.signed_bytes_hex,
  );
  // Degenerate case: even with all schema fields empty, the domain tag
  // prevents collision with v1 (the encoder is total over field values, so
  // it can build the byte string without the field-value checks)
  const degenerateBytes = signedBytesHexOf({
    ...v3Context,
    schema: {
      varType: "" as MetaVariableSchema["varType"],
      required: "" as MetaVariableSchema["required"],
      description: "",
      maxAgeDays: "",
    },
  });
  c.push(
    "meta-sig domain separation: degenerate empty-schema v3 never collides with v1",
    degenerateBytes !== null && degenerateBytes !== v1Bytes,
  );
}

/** Any successor of a deleted predecessor is rejected regardless of status (§4.2 — a tombstone is terminal). */
async function deletedPredecessorChecks(c: Checks, history: ChainHistoryIndex): Promise<void> {
  const deleted = byName.get("var-delete");
  const keys = vectorKeys["user-admin-0003"];
  if (deleted === undefined || keys === undefined) {
    c.push("meta-sig deleted predecessor: fixtures", false);
    return;
  }
  const pair = await importSigningKeyPair({
    publicKey: fromHex(keys.sig_pub_hex),
    privateSeed: fromHex(keys.sig_sk_seed_hex),
  });
  if (!pair.ok) {
    c.push("meta-sig deleted predecessor: key import", false);
    return;
  }
  // deleted → deleted (overwriting a deletion) is also rejected as
  // revived-after-delete
  const successor: MetaStatementContext = {
    ...contextOf(deleted.context),
    metaVersion: deleted.context.meta_version + 1,
    prevMetaSigHashHex: deleted.signed_bytes_sha256_hex,
  };
  const signature = await signMetaStatement({
    context: successor,
    signingKey: pair.value.privateKey,
  });
  if (!signature.ok) {
    c.push("meta-sig deleted predecessor: sign", false);
    return;
  }
  const result = await verifyDistributedMetaStatement({
    history,
    context: successor,
    authorKeyFingerprintHex: keys.key_fingerprint_hex,
    signatureHex: signature.value,
    predecessor: {
      signedBytesHashHex: deleted.signed_bytes_sha256_hex,
      status: "deleted",
      layoutVersion: 1,
    },
  });
  c.push(
    "meta-sig: any successor of a deleted predecessor is rejected",
    !result.ok &&
      result.error.kind === "MetaStatementInvalid" &&
      result.error.reason === "revived-after-delete",
  );
}

async function roundtripChecks(c: Checks): Promise<void> {
  const base = positives[0];
  if (base === undefined) {
    return;
  }
  const context = contextOf(base.context);
  const signer = await generateSigningKeyPair();
  const signed = await signMetaStatement({ context, signingKey: signer.privateKey });
  if (!signed.ok) {
    c.push("meta-sig: roundtrip", false, "sign failed");
    return;
  }
  const verified = await verifyMetaStatementSignature({
    context,
    signatureHex: signed.value,
    authorPublicKey: signer.publicKey,
  });
  c.push("meta-sig: roundtrip", verified.ok);

  const other = await generateSigningKeyPair();
  const wrongKey = await verifyMetaStatementSignature({
    context,
    signatureHex: signed.value,
    authorPublicKey: other.publicKey,
  });
  c.push("meta-sig: roundtrip wrong key rejected", !wrongKey.ok);

  const wrongContext = await verifyMetaStatementSignature({
    context: { ...context, name: `${context.name}-transplanted` },
    signatureHex: signed.value,
    authorPublicKey: signer.publicKey,
  });
  c.push("meta-sig: roundtrip wrong context rejected", !wrongContext.ok);
}

export async function metadataSignatureChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  const history = await canonicalHistory();
  const histories: Histories = {
    canonical: history,
    "tenure-extension": await metaExtendedHistory(),
    "device-ops": await extendedVectorChainHistory("device-ops"),
    "environment-deleted": await extendedVectorChainHistory("environment-deleted"),
  };
  const exercised = new Set<MetaInvalidReason>();
  await vectorChecks(c, histories);
  await forkChecks(c, history);
  await nameSwapChecks(c, history);
  await negativeChecks(c, histories, exercised);
  await invalidInputChecks(c);
  await layoutInvalidInputChecks(c);
  await layoutSelectionChecks(c, history);
  await layoutFieldSetChecks(c, history);
  layoutDomainSeparationChecks(c);
  await deletedPredecessorChecks(c, history);
  await roundtripChecks(c);
  reasonCoverageChecks(c, "meta-sig", META_REASON_COVERAGE, exercised);
  return c.results;
}
