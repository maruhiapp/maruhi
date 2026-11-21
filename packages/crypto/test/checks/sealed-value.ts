import {
  buildSealedValueInfo,
  encodeLengthPrefixed,
  type EncryptionKeyPair,
  generateEncryptionKeyPair,
  importEncryptionKeyPair,
  isProposalId,
  MAX_SEALED_VALUE_BYTES,
  openProposedValue,
  type SealedValueContext,
  sealProposedValue,
} from "../../src/index.ts";
import dekWrapVectors from "../../test-vectors/dek-wrap.json" with { type: "json" };
import sealedValueVectors from "../../test-vectors/sealed-value.json" with { type: "json" };
import {
  testEnvironmentId,
  testProjectId,
  testUserId,
  testVariableId,
} from "../support/fixture.ts";
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

function vectorNamed(name: string) {
  const vector = sealedValueVectors.vectors.find((v) => v.name === name);
  if (vector === undefined) {
    throw new Error(`sealed-value.json: ${name} vector missing`);
  }
  return vector;
}

const base = vectorNamed("basic");
const companion = vectorNamed("companion");

function contextOf(vector: typeof base): SealedValueContext {
  return {
    projectId: testProjectId(vector.project_id),
    environmentId: testEnvironmentId(vector.environment_id),
    proposalId: vector.proposal_id,
    variableId: testVariableId(vector.variable_id),
    baseVersion: vector.base_version,
    recipientUserId: testUserId(vector.recipient_user_id),
  };
}

const baseContext = (): SealedValueContext => contextOf(base);

async function recipientKeyPair() {
  return importEncryptionKeyPair({
    publicKey: fromHex(dekWrapVectors.recipient_keypair.pkRm_hex),
    privateKey: fromHex(dekWrapVectors.recipient_keypair.skRm_hex),
  });
}

async function vectorOpenChecks(c: Checks, pair: EncryptionKeyPair): Promise<void> {
  for (const vector of [base, companion]) {
    const context = contextOf(vector);
    c.push(
      `sealed-value: ${vector.name} info construction`,
      toHex(buildSealedValueInfo(context)) === vector.info_hex,
    );
    const opened = await openProposedValue({
      recipientKeyPair: pair,
      sealed: { enc: fromHex(vector.enc_hex), ciphertext: fromHex(vector.ciphertext_hex) },
      context,
    });
    c.push(
      `sealed-value: ${vector.name} vector open == plaintext`,
      opened.ok && toHex(opened.value) === vector.plaintext_hex,
    );
  }
  const dekBasic = dekWrapVectors.vectors.find((v) => v.name === "basic");
  c.push(
    "sealed-value: recipient and coordinates match dek-wrap.json basic",
    dekBasic !== undefined &&
      dekBasic.project_id === base.project_id &&
      dekBasic.environment_id === base.environment_id &&
      dekBasic.recipient_user_id === base.recipient_user_id,
  );
  c.push(
    "sealed-value: companion shares the proposal id under its own variable id",
    companion.proposal_id === base.proposal_id &&
      companion.variable_id !== base.variable_id &&
      companion.enc_hex !== base.enc_hex,
  );
  c.push("sealed-value: proposal id form", isProposalId(sealedValueVectors.proposal.proposal_id));
}

async function negativeCheck(
  c: Checks,
  input: {
    readonly name: string;
    readonly context: SealedValueContext | null;
    readonly infoHex: string;
    readonly pair: EncryptionKeyPair;
  },
): Promise<void> {
  const vector = sealedValueVectors.negative.find((n) => n.name === input.name);
  const infoMatches = vector?.open_info_hex === input.infoHex;
  if (input.context === null) {
    c.push(`sealed-value negative: ${input.name}`, infoMatches);
    return;
  }
  const result = await openProposedValue({
    recipientKeyPair: input.pair,
    sealed: { enc: fromHex(base.enc_hex), ciphertext: fromHex(base.ciphertext_hex) },
    context: input.context,
  });
  c.push(
    `sealed-value negative: ${input.name}`,
    infoMatches && !result.ok && result.error.kind === "DekUnwrapFailed",
  );
}

async function negativeChecks(c: Checks, pair: EncryptionKeyPair): Promise<void> {
  const contexts: readonly { readonly name: string; readonly context: SealedValueContext }[] = [
    {
      name: "info-project-mismatch",
      context: { ...baseContext(), projectId: testProjectId("proj-0002") },
    },
    {
      name: "info-environment-mismatch",
      context: { ...baseContext(), environmentId: testEnvironmentId("env-dev-0002") },
    },
    {
      name: "info-proposal-mismatch",
      context: { ...baseContext(), proposalId: sealedValueVectors.proposal.other_proposal_id },
    },
    {
      name: "info-variable-mismatch",
      context: { ...baseContext(), variableId: testVariableId(companion.variable_id) },
    },
    {
      name: "info-base-version-mismatch",
      context: { ...baseContext(), baseVersion: base.base_version + 1 },
    },
    {
      name: "info-recipient-mismatch",
      context: { ...baseContext(), recipientUserId: testUserId("user-recipient-0003") },
    },
  ];
  for (const m of contexts) {
    await negativeCheck(c, {
      name: m.name,
      context: m.context,
      infoHex: toHex(buildSealedValueInfo(m.context)),
      pair,
    });
  }
  const dekDomain = sealedValueVectors.negative.find((n) => n.name === "info-dek-wrap-domain");
  c.push(
    "sealed-value negative: info-dek-wrap-domain",
    dekDomain?.open_info_hex ===
      toHex(
        encodeLengthPrefixed([
          "maruhi/v1/dek-wrap",
          base.project_id,
          base.environment_id,
          base.proposal_id,
          base.variable_id,
          base.base_version,
          base.recipient_user_id,
        ]),
      ) && dekDomain.open_info_hex !== base.info_hex,
  );
  const tampered = sealedValueVectors.negative.find((n) => n.name === "ciphertext-tampered");
  const tamperedResult =
    tampered?.ciphertext_hex === undefined
      ? null
      : await openProposedValue({
          recipientKeyPair: pair,
          sealed: { enc: fromHex(base.enc_hex), ciphertext: fromHex(tampered.ciphertext_hex) },
          context: baseContext(),
        });
  c.push(
    "sealed-value negative: ciphertext-tampered",
    tamperedResult !== null &&
      !tamperedResult.ok &&
      tamperedResult.error.kind === "DekUnwrapFailed",
  );
}

async function invalidContextChecks(c: Checks): Promise<void> {
  const recipient = await generateEncryptionKeyPair();
  const value = new TextEncoder().encode("dummy-credential");
  const upperId = await sealProposedValue({
    recipientPublicKey: recipient.publicKey,
    value,
    context: { ...baseContext(), proposalId: base.proposal_id.toUpperCase() },
  });
  const shortId = await openProposedValue({
    recipientKeyPair: recipient,
    sealed: { enc: fromHex(base.enc_hex), ciphertext: fromHex(base.ciphertext_hex) },
    context: { ...baseContext(), proposalId: "abc" },
  });
  const emptyVariable = await sealProposedValue({
    recipientPublicKey: recipient.publicKey,
    value,
    context: { ...baseContext(), variableId: testVariableId("") },
  });
  const zeroVersion = await sealProposedValue({
    recipientPublicKey: recipient.publicKey,
    value,
    context: { ...baseContext(), baseVersion: 0 },
  });
  c.push(
    "sealed-value invalid context: rejected as InvalidInput",
    [upperId, shortId, emptyVariable, zeroVersion].every(
      (result) => !result.ok && result.error.kind === "InvalidInput",
    ),
  );
  const empty = await sealProposedValue({
    recipientPublicKey: recipient.publicKey,
    value: new Uint8Array(0),
    context: baseContext(),
  });
  const oversized = await sealProposedValue({
    recipientPublicKey: recipient.publicKey,
    value: new Uint8Array(MAX_SEALED_VALUE_BYTES + 1),
    context: baseContext(),
  });
  c.push(
    "sealed-value invalid input: value length",
    [empty, oversized].every((result) => !result.ok && result.error.kind === "InvalidInput"),
  );
}

async function roundtripChecks(c: Checks): Promise<void> {
  const recipient = await generateEncryptionKeyPair();
  const value = new TextEncoder().encode("postgres://app_b:fresh-dummy@db.example/shop");
  const sealed = await sealProposedValue({
    recipientPublicKey: recipient.publicKey,
    value,
    context: baseContext(),
  });
  if (!sealed.ok) {
    c.push("sealed-value: roundtrip", false, "seal failed");
    return;
  }
  const opened = await openProposedValue({
    recipientKeyPair: recipient,
    sealed: sealed.value,
    context: baseContext(),
  });
  c.push("sealed-value: roundtrip", opened.ok && toHex(opened.value) === toHex(value));
  const otherDevice = await generateEncryptionKeyPair();
  const crosswise = await openProposedValue({
    recipientKeyPair: otherDevice,
    sealed: sealed.value,
    context: baseContext(),
  });
  c.push(
    "sealed-value: another device key cannot open",
    !crosswise.ok && crosswise.error.kind === "DekUnwrapFailed",
  );
  const largest = new Uint8Array(MAX_SEALED_VALUE_BYTES).fill(0x41);
  const sealedLargest = await sealProposedValue({
    recipientPublicKey: recipient.publicKey,
    value: largest,
    context: baseContext(),
  });
  const openedLargest = sealedLargest.ok
    ? await openProposedValue({
        recipientKeyPair: recipient,
        sealed: sealedLargest.value,
        context: baseContext(),
      })
    : null;
  c.push(
    "sealed-value: largest value roundtrip",
    openedLargest !== null && openedLargest.ok && openedLargest.value.length === largest.length,
  );
}

export async function sealedValueChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  const imported = await recipientKeyPair();
  if (!imported.ok) {
    c.push("sealed-value: recipient key import", false, imported.error.kind);
    return c.results;
  }
  const pair = imported.value;
  await vectorOpenChecks(c, pair);
  await negativeChecks(c, pair);
  await invalidContextChecks(c);
  await roundtripChecks(c);
  return c.results;
}
