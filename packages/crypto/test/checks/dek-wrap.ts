import {
  buildDekWrapInfo,
  computeServerKeyFingerprint,
  type DekWrapContext,
  type EncryptionKeyPair,
  generateDek,
  generateEncryptionKeyPair,
  importEncryptionKeyPair,
  unwrapDek,
  wrapDek,
} from "../../src/index.ts";
import dekWrapVectors from "../../test-vectors/dek-wrap.json" with { type: "json" };
import { testEnvironmentId, testProjectId, testUserId } from "../support/fixture.ts";
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

function fixtureString(value: string | undefined, name: string): string {
  if (value === undefined) {
    throw new Error(`dek-wrap.json: ${name} missing`);
  }
  return value;
}

const baseVector = dekWrapVectors.vectors.find((v) => v.name === "basic");
if (baseVector === undefined) {
  throw new Error("dek-wrap.json: basic vector missing");
}
const base = baseVector;
const baseRecipientUserId = fixtureString(base.recipient_user_id, "basic recipient_user_id");

const serverVectorFound = dekWrapVectors.vectors.find((v) => v.name === "server-basic");
if (serverVectorFound === undefined) {
  throw new Error("dek-wrap.json: server-basic vector missing");
}
const serverVector = serverVectorFound;
const serverFingerprintHex = fixtureString(
  serverVector.server_key_fingerprint_hex,
  "server-basic server_key_fingerprint_hex",
);

function baseContext(): DekWrapContext {
  return {
    projectId: testProjectId(base.project_id),
    environmentId: testEnvironmentId(base.environment_id),
    epoch: base.epoch,
    recipientUserId: testUserId(baseRecipientUserId),
  };
}

function serverContext(): DekWrapContext {
  return {
    projectId: testProjectId(serverVector.project_id),
    environmentId: testEnvironmentId(serverVector.environment_id),
    epoch: serverVector.epoch,
    recipientUserId: testUserId(serverFingerprintHex),
  };
}

async function recipientKeyPair() {
  return importEncryptionKeyPair({
    publicKey: fromHex(dekWrapVectors.recipient_keypair.pkRm_hex),
    privateKey: fromHex(dekWrapVectors.recipient_keypair.skRm_hex),
  });
}

async function serverKeyPair() {
  return importEncryptionKeyPair({
    publicKey: fromHex(dekWrapVectors.server_keypair.pkSm_hex),
    privateKey: fromHex(dekWrapVectors.server_keypair.skSm_hex),
  });
}

async function vectorOpenChecks(c: Checks): Promise<void> {
  c.push("dek-wrap: info construction", toHex(buildDekWrapInfo(baseContext())) === base.info_hex);

  const pair = await recipientKeyPair();
  if (!pair.ok) {
    c.push("dek-wrap: vector open", false, "recipient key import failed");
    return;
  }
  const dek = await unwrapDek({
    recipientKeyPair: pair.value,
    wrapped: { enc: fromHex(base.enc_hex), ciphertext: fromHex(base.ciphertext_hex) },
    context: baseContext(),
  });
  c.push("dek-wrap: vector open == DEK", dek.ok && toHex(dek.value) === base.dek_hex);
}

async function infoNegativeCheck(
  c: Checks,
  input: {
    readonly name: string;
    readonly context: DekWrapContext;
    readonly keyPair: EncryptionKeyPair;
    readonly encHex: string;
    readonly ciphertextHex: string;
  },
): Promise<void> {
  const vector = dekWrapVectors.negative.find((n) => n.name === input.name);
  const infoMatches = vector?.open_info_hex === toHex(buildDekWrapInfo(input.context));
  const result = await unwrapDek({
    recipientKeyPair: input.keyPair,
    wrapped: { enc: fromHex(input.encHex), ciphertext: fromHex(input.ciphertextHex) },
    context: input.context,
  });
  c.push(
    `dek-wrap negative: ${input.name}`,
    infoMatches && !result.ok && result.error.kind === "DekUnwrapFailed",
  );
}

async function serverVectorChecks(c: Checks): Promise<void> {
  const fp = await computeServerKeyFingerprint(fromHex(dekWrapVectors.server_keypair.pkSm_hex));
  c.push(
    "dek-wrap: server key fingerprint matches vector",
    fp.ok && toHex(fp.value) === dekWrapVectors.server_keypair.server_key_fingerprint_hex,
  );
  c.push(
    "dek-wrap: server info construction",
    toHex(buildDekWrapInfo(serverContext())) === serverVector.info_hex,
  );

  const pair = await serverKeyPair();
  if (!pair.ok) {
    c.push("dek-wrap: server vector open", false, "server key import failed");
    return;
  }
  const dek = await unwrapDek({
    recipientKeyPair: pair.value,
    wrapped: {
      enc: fromHex(serverVector.enc_hex),
      ciphertext: fromHex(serverVector.ciphertext_hex),
    },
    context: serverContext(),
  });
  c.push(
    "dek-wrap: server vector open == DEK",
    dek.ok && toHex(dek.value) === serverVector.dek_hex,
  );
  c.push("dek-wrap: server vector wraps the same DEK", serverVector.dek_hex === base.dek_hex);

  const serverWrapped = {
    encHex: serverVector.enc_hex,
    ciphertextHex: serverVector.ciphertext_hex,
  };
  await infoNegativeCheck(c, {
    name: "server-info-member-user-id",
    context: { ...serverContext(), recipientUserId: testUserId(baseRecipientUserId) },
    keyPair: pair.value,
    ...serverWrapped,
  });
  await infoNegativeCheck(c, {
    name: "server-info-fp-mismatch",
    context: { ...serverContext(), recipientUserId: testUserId(wrongServerFingerprintHex()) },
    keyPair: pair.value,
    ...serverWrapped,
  });

  const memberPair = await recipientKeyPair();
  if (!memberPair.ok) {
    c.push("dek-wrap negative: member-info-server-fp", false, "recipient key import failed");
    return;
  }
  await infoNegativeCheck(c, {
    name: "member-info-server-fp",
    context: { ...baseContext(), recipientUserId: testUserId(serverFingerprintHex) },
    keyPair: memberPair.value,
    encHex: base.enc_hex,
    ciphertextHex: base.ciphertext_hex,
  });
}

function wrongServerFingerprintHex(): string {
  const fp = fromHex(dekWrapVectors.server_keypair.server_key_fingerprint_hex);
  const flipped = fp.slice();
  flipped[0] = (flipped[0] ?? 0) ^ 0x01;
  return toHex(flipped);
}

async function negativeChecks(c: Checks): Promise<void> {
  const pair = await recipientKeyPair();
  if (!pair.ok) {
    c.push("dek-wrap: negatives", false, "recipient key import failed");
    return;
  }

  const contexts: readonly { name: string; context: DekWrapContext }[] = [
    { name: "info-epoch-mismatch", context: { ...baseContext(), epoch: 4 } },
    {
      name: "info-recipient-mismatch",
      context: { ...baseContext(), recipientUserId: testUserId("user-owner-0001") },
    },
    {
      name: "info-environment-mismatch",
      context: { ...baseContext(), environmentId: testEnvironmentId("env-dev-0002") },
    },
  ];
  for (const m of contexts) {
    await infoNegativeCheck(c, {
      name: m.name,
      context: m.context,
      keyPair: pair.value,
      encHex: base.enc_hex,
      ciphertextHex: base.ciphertext_hex,
    });
  }

  const encTampered = dekWrapVectors.negative.find((n) => n.name === "enc-tampered");
  if (encTampered?.enc_hex === undefined) {
    c.push("dek-wrap negative: enc-tampered", false, "vector missing");
  } else {
    const result = await unwrapDek({
      recipientKeyPair: pair.value,
      wrapped: {
        enc: fromHex(encTampered.enc_hex),
        ciphertext: fromHex(base.ciphertext_hex),
      },
      context: baseContext(),
    });
    c.push("dek-wrap negative: enc-tampered", !result.ok);
  }
}

async function invalidContextChecks(c: Checks): Promise<void> {
  const recipient = await generateEncryptionKeyPair();
  try {
    const wrapped = await wrapDek({
      recipientPublicKey: recipient.publicKey,
      dek: generateDek(),
      context: { ...baseContext(), epoch: -1 },
    });
    const unwrapped = await unwrapDek({
      recipientKeyPair: recipient,
      wrapped: { enc: fromHex(base.enc_hex), ciphertext: fromHex(base.ciphertext_hex) },
      context: { ...baseContext(), epoch: Number.NaN },
    });
    c.push(
      "dek-wrap invalid context: bad epoch",
      !wrapped.ok &&
        wrapped.error.kind === "InvalidInput" &&
        !unwrapped.ok &&
        unwrapped.error.kind === "InvalidInput",
    );
  } catch (error) {
    c.push("dek-wrap invalid context: bad epoch", false, `threw: ${String(error)}`);
  }
}

async function roundtripChecks(c: Checks): Promise<void> {
  const recipient = await generateEncryptionKeyPair();
  const dek = generateDek();
  const wrapped = await wrapDek({
    recipientPublicKey: recipient.publicKey,
    dek,
    context: baseContext(),
  });
  if (!wrapped.ok) {
    c.push("dek-wrap: roundtrip", false, "wrap failed");
    return;
  }
  const unwrapped = await unwrapDek({
    recipientKeyPair: recipient,
    wrapped: wrapped.value,
    context: baseContext(),
  });
  c.push("dek-wrap: roundtrip", unwrapped.ok && toHex(unwrapped.value) === toHex(dek));

  const wrongContext = await unwrapDek({
    recipientKeyPair: recipient,
    wrapped: wrapped.value,
    context: { ...baseContext(), projectId: testProjectId("proj-other") },
  });
  c.push("dek-wrap: roundtrip wrong context rejected", !wrongContext.ok);

  const otherRecipient = await generateEncryptionKeyPair();
  const wrongKey = await unwrapDek({
    recipientKeyPair: otherRecipient,
    wrapped: wrapped.value,
    context: baseContext(),
  });
  c.push("dek-wrap: roundtrip wrong recipient rejected", !wrongKey.ok);
}

export async function dekWrapChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  await vectorOpenChecks(c);
  await serverVectorChecks(c);
  await negativeChecks(c);
  await invalidContextChecks(c);
  await roundtripChecks(c);
  return c.results;
}
