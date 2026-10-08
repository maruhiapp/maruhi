// Checks for CRYPTO_SPEC §9.1 (the lease wrap of a workload lease).
// Same layout as dek-wrap: fixed vectors (generated via hpke-js ekm
// derandomize) are verified in the Open direction, and the Seal direction is
// covered by a roundtrip (panva cannot derandomize a one-shot Seal — the
// spike-c finding).

import {
  buildDekWrapInfo,
  buildLeaseClaimsBytes,
  buildLeaseWrapInfo,
  computeLeaseClaimsDigest,
  type EncryptionKeyPair,
  generateDek,
  generateEncryptionKeyPair,
  importEncryptionKeyPair,
  type LeaseClaims,
  type LeaseWrapContext,
  unwrapLeaseDek,
  wrapLeaseDek,
} from "../../src/index.ts";
import dekWrapVectors from "../../test-vectors/dek-wrap.json" with { type: "json" };
import leaseWrapVectors from "../../test-vectors/lease-wrap.json" with { type: "json" };
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

import { testEnvironmentId, testProjectId, testUserId } from "../support/fixture.ts";

function vectorNamed(name: string) {
  const vector = leaseWrapVectors.vectors.find((v) => v.name === name);
  if (vector === undefined) {
    throw new Error(`lease-wrap.json: ${name} vector missing`);
  }
  return vector;
}

const base = vectorNamed("basic");
const priorEpoch = vectorNamed("prior-epoch");

function claimsOf(subject: string): LeaseClaims {
  return {
    issuerUrl: leaseWrapVectors.claims.issuer_url,
    subject,
    audience: leaseWrapVectors.claims.audience,
  };
}

function contextOf(vector: {
  readonly project_id: string;
  readonly environment_id: string;
  readonly epoch: number;
}): LeaseWrapContext {
  return {
    projectId: testProjectId(vector.project_id),
    environmentId: testEnvironmentId(vector.environment_id),
    epoch: vector.epoch,
    claimsDigestHex: leaseWrapVectors.claims.claims_digest_hex,
  };
}

const baseContext = (): LeaseWrapContext => contextOf(base);

async function workloadKeyPair() {
  return importEncryptionKeyPair({
    publicKey: fromHex(leaseWrapVectors.workload_keypair.pkWm_hex),
    privateKey: fromHex(leaseWrapVectors.workload_keypair.skWm_hex),
  });
}

/**
 * claims_digest (§9.1): the LP field order and SHA-256 must match the vector.
 * Also pinned here: two contexts sharing issuer / audience but differing in
 * subject produce different digests (the basis of the binding that prevents a
 * lease response from being reused by another job).
 */
async function claimsDigestChecks(c: Checks): Promise<void> {
  const primary = claimsOf(leaseWrapVectors.claims.subject);
  c.push(
    "lease-wrap: claims LP construction",
    toHex(buildLeaseClaimsBytes(primary)) === leaseWrapVectors.claims.lp_hex,
  );
  const digest = await computeLeaseClaimsDigest(primary);
  c.push(
    "lease-wrap: claims digest",
    digest.ok && digest.value === leaseWrapVectors.claims.claims_digest_hex,
  );
  const other = await computeLeaseClaimsDigest(claimsOf(leaseWrapVectors.claims.other_subject));
  c.push(
    "lease-wrap: claims digest of other subject",
    other.ok &&
      other.value === leaseWrapVectors.claims.other_claims_digest_hex &&
      other.value !== leaseWrapVectors.claims.claims_digest_hex,
  );
  // Empty fields are InvalidInput (allowing empty could collapse different
  // contexts into the same digest)
  const empty = await Promise.all([
    computeLeaseClaimsDigest({ ...primary, issuerUrl: "" }),
    computeLeaseClaimsDigest({ ...primary, subject: "" }),
    computeLeaseClaimsDigest({ ...primary, audience: "" }),
  ]);
  c.push(
    "lease-wrap: empty claim fields rejected",
    empty.every((result) => !result.ok && result.error.kind === "InvalidInput"),
  );
}

async function vectorOpenChecks(c: Checks, pair: EncryptionKeyPair): Promise<void> {
  for (const vector of [base, priorEpoch]) {
    const context = contextOf(vector);
    c.push(
      `lease-wrap: ${vector.name} info construction`,
      toHex(buildLeaseWrapInfo(context)) === vector.info_hex,
    );
    const dek = await unwrapLeaseDek({
      workloadKeyPair: pair,
      wrapped: { enc: fromHex(vector.enc_hex), ciphertext: fromHex(vector.ciphertext_hex) },
      context,
    });
    c.push(
      `lease-wrap: ${vector.name} vector open == DEK`,
      dek.ok && toHex(dek.value) === vector.dek_hex,
    );
  }
  // Coordinates and DEK are inherited from dek-wrap.json's server-basic
  // (§9.1: the server only opens its own wrap and re-wraps it — it creates
  // neither values nor DEKs)
  const serverWrap = dekWrapVectors.vectors.find((v) => v.name === "server-basic");
  c.push(
    "lease-wrap: basic re-wraps the server-addressed DEK",
    serverWrap !== undefined &&
      serverWrap.dek_hex === base.dek_hex &&
      serverWrap.project_id === base.project_id &&
      serverWrap.environment_id === base.environment_id &&
      serverWrap.epoch === base.epoch,
  );
  // The DEK is independent per epoch (a single response carries multiple
  // epochs — AUTH_SPEC §14-2)
  c.push("lease-wrap: prior epoch uses its own DEK", priorEpoch.dek_hex !== base.dek_hex);
}

/** info-substitution negative: the vector's open_info_hex matches the built info, and Open fails. */
async function infoNegativeCheck(
  c: Checks,
  input: {
    readonly name: string;
    readonly infoHex: string;
    readonly context?: LeaseWrapContext;
    readonly pair: EncryptionKeyPair;
  },
): Promise<void> {
  const vector = leaseWrapVectors.negative.find((n) => n.name === input.name);
  const infoMatches = vector?.open_info_hex === input.infoHex;
  // A negative whose context cannot be built (domain substitution) only gets
  // the info match checked: the implementation's LeaseWrapContext cannot swap
  // the domain — this asserts "the domain is fixed by the type", and the Open
  // failure itself is pinned by verify_reference.mjs (the independent
  // implementation)
  if (input.context === undefined) {
    c.push(`lease-wrap negative: ${input.name}`, infoMatches);
    return;
  }
  const result = await unwrapLeaseDek({
    workloadKeyPair: input.pair,
    wrapped: { enc: fromHex(base.enc_hex), ciphertext: fromHex(base.ciphertext_hex) },
    context: input.context,
  });
  c.push(
    `lease-wrap negative: ${input.name}`,
    infoMatches && !result.ok && result.error.kind === "DekUnwrapFailed",
  );
}

async function negativeChecks(c: Checks, pair: EncryptionKeyPair): Promise<void> {
  const contexts: readonly { readonly name: string; readonly context: LeaseWrapContext }[] = [
    { name: "info-project-mismatch", context: { ...baseContext(), projectId: testProjectId("proj-0002") } },
    {
      name: "info-environment-mismatch",
      context: { ...baseContext(), environmentId: testEnvironmentId("env-dev-0002") },
    },
    { name: "info-epoch-mismatch", context: { ...baseContext(), epoch: base.epoch + 1 } },
    {
      // Reuse in another workload context (same issuer / audience, different
      // subject)
      name: "info-claims-digest-mismatch",
      context: {
        ...baseContext(),
        claimsDigestHex: leaseWrapVectors.claims.other_claims_digest_hex,
      },
    },
  ];
  for (const m of contexts) {
    await infoNegativeCheck(c, {
      name: m.name,
      infoHex: toHex(buildLeaseWrapInfo(m.context)),
      context: m.context,
      pair,
    });
  }
  // Domain separation from the §5 persistent wrap. Since the implementation
  // API cannot swap the domain, this is pinned by checking that the byte
  // string built by the dek-wrap-side info builder matches the vector
  await infoNegativeCheck(c, {
    name: "info-dek-wrap-domain",
    infoHex: toHex(
      buildDekWrapInfo({
        projectId: testProjectId(base.project_id),
        environmentId: testEnvironmentId(base.environment_id),
        epoch: base.epoch,
        // The "only the domain differs" shape with claims_digest placed in
        // dek-wrap's recipient slot
        recipientUserId: testUserId(leaseWrapVectors.claims.claims_digest_hex),
      }),
    ),
    pair,
  });
}

async function invalidContextChecks(c: Checks): Promise<void> {
  const workload = await generateEncryptionKeyPair();
  const dek = generateDek();
  // A malformed epoch is InvalidInput, not a throw
  const badEpoch = await wrapLeaseDek({
    workloadPublicKey: workload.publicKey,
    dek,
    context: { ...baseContext(), epoch: -1 },
  });
  // claims_digest accepts only 64-char lowercase hex: rules out passing raw
  // claims by mistake and implementation drift where "the same digest
  // produces different info" via uppercase hex
  const rawClaims = await wrapLeaseDek({
    workloadPublicKey: workload.publicKey,
    dek,
    context: { ...baseContext(), claimsDigestHex: leaseWrapVectors.claims.subject },
  });
  const upperDigest = await unwrapLeaseDek({
    workloadKeyPair: workload,
    wrapped: { enc: fromHex(base.enc_hex), ciphertext: fromHex(base.ciphertext_hex) },
    context: {
      ...baseContext(),
      claimsDigestHex: leaseWrapVectors.claims.claims_digest_hex.toUpperCase(),
    },
  });
  c.push(
    "lease-wrap invalid context: rejected as InvalidInput",
    [badEpoch, rawClaims, upperDigest].every(
      (result) => !result.ok && result.error.kind === "InvalidInput",
    ),
  );
  // DEK length check (anything other than 32 bytes never reaches Seal)
  const shortDek = await wrapLeaseDek({
    workloadPublicKey: workload.publicKey,
    dek: dek.slice(0, 16),
    context: baseContext(),
  });
  c.push(
    "lease-wrap invalid input: dek length",
    !shortDek.ok && shortDek.error.kind === "InvalidInput",
  );
}

async function roundtripChecks(c: Checks): Promise<void> {
  // Seal direction: self-roundtrip (the workload key is generated and
  // non-extractable)
  const workload = await generateEncryptionKeyPair();
  const dek = generateDek();
  const wrapped = await wrapLeaseDek({
    workloadPublicKey: workload.publicKey,
    dek,
    context: baseContext(),
  });
  if (!wrapped.ok) {
    c.push("lease-wrap: roundtrip", false, "wrap failed");
    return;
  }
  const unwrapped = await unwrapLeaseDek({
    workloadKeyPair: workload,
    wrapped: wrapped.value,
    context: baseContext(),
  });
  c.push("lease-wrap: roundtrip", unwrapped.ok && toHex(unwrapped.value) === toHex(dek));

  // Open fails with a different workload context (different claims_digest) =
  // a lease response cannot be reused
  const otherDigest = await computeLeaseClaimsDigest(
    claimsOf(leaseWrapVectors.claims.other_subject),
  );
  const wrongClaims = await unwrapLeaseDek({
    workloadKeyPair: workload,
    wrapped: wrapped.value,
    context: {
      ...baseContext(),
      claimsDigestHex: otherDigest.ok ? otherDigest.value : baseContext().claimsDigestHex,
    },
  });
  c.push("lease-wrap: roundtrip other workload context rejected", !wrongClaims.ok);

  // Open fails with a different ephemeral key (once the key disappears at job
  // end, the response is worthless)
  const otherWorkload = await generateEncryptionKeyPair();
  const wrongKey = await unwrapLeaseDek({
    workloadKeyPair: otherWorkload,
    wrapped: wrapped.value,
    context: baseContext(),
  });
  c.push("lease-wrap: roundtrip other workload key rejected", !wrongKey.ok);
}

export async function leaseWrapChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  await claimsDigestChecks(c);
  const pair = await workloadKeyPair();
  if (!pair.ok) {
    c.push("lease-wrap: workload key import", false, "import failed");
    return c.results;
  }
  await vectorOpenChecks(c, pair.value);
  await negativeChecks(c, pair.value);
  await invalidContextChecks(c);
  await roundtripChecks(c);
  return c.results;
}
