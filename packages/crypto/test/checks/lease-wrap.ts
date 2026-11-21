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
import { testEnvironmentId, testProjectId, testUserId } from "../support/fixture.ts";
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

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
  const serverWrap = dekWrapVectors.vectors.find((v) => v.name === "server-basic");
  c.push(
    "lease-wrap: basic re-wraps the server-addressed DEK",
    serverWrap !== undefined &&
      serverWrap.dek_hex === base.dek_hex &&
      serverWrap.project_id === base.project_id &&
      serverWrap.environment_id === base.environment_id &&
      serverWrap.epoch === base.epoch,
  );
  c.push("lease-wrap: prior epoch uses its own DEK", priorEpoch.dek_hex !== base.dek_hex);
}

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
    {
      name: "info-project-mismatch",
      context: { ...baseContext(), projectId: testProjectId("proj-0002") },
    },
    {
      name: "info-environment-mismatch",
      context: { ...baseContext(), environmentId: testEnvironmentId("env-dev-0002") },
    },
    { name: "info-epoch-mismatch", context: { ...baseContext(), epoch: base.epoch + 1 } },
    {
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
  await infoNegativeCheck(c, {
    name: "info-dek-wrap-domain",
    infoHex: toHex(
      buildDekWrapInfo({
        projectId: testProjectId(base.project_id),
        environmentId: testEnvironmentId(base.environment_id),
        epoch: base.epoch,
        recipientUserId: testUserId(leaseWrapVectors.claims.claims_digest_hex),
      }),
    ),
    pair,
  });
}

async function invalidContextChecks(c: Checks): Promise<void> {
  const workload = await generateEncryptionKeyPair();
  const dek = generateDek();
  const badEpoch = await wrapLeaseDek({
    workloadPublicKey: workload.publicKey,
    dek,
    context: { ...baseContext(), epoch: -1 },
  });
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
