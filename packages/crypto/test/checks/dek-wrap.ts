// Checks for CRYPTO_SPEC §5 (DEK wrap).
// Because panva hpke cannot derandomize a single-shot Seal (spike-c finding),
// the fixed vectors (generated via hpke-js ekm derandomize) are verified in the
// Open direction, and the Seal direction is covered by round-trip. The official
// RFC 9180 vectors are in rfc9180.ts.

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
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

/** Required fixture string (verifying read of a field made optional by the JSON union type). */
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

// Recipient class server (§9): the recipient position of info holds the server key FP
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
    projectId: base.project_id,
    environmentId: base.environment_id,
    epoch: base.epoch,
    recipientUserId: baseRecipientUserId,
  };
}

function serverContext(): DekWrapContext {
  return {
    projectId: serverVector.project_id,
    environmentId: serverVector.environment_id,
    epoch: serverVector.epoch,
    // §9: the recipient_user_id position uses the server key FP (lowercase hex)
    recipientUserId: serverFingerprintHex,
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

  // Open of the fixed vector (the KeyPair is imported non-extractable)
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

/**
 * A single info-swap negative: the vector's open_info_hex matches the info
 * construction, and Open under that context becomes DekUnwrapFailed (shared by
 * negativeChecks / the server cases).
 */
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
  // Recipient class server (§9): the implementation recomputes
  // FP = SHA-256(server_enc_pub)[:16], and a construction that puts the FP in
  // the recipient position of info matches the vector
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
  // The same epoch DEK as basic (one DEK × multiple recipient classes — the §7 complete wrap set shape)
  c.push("dek-wrap: server vector wraps the same DEK", serverVector.dek_hex === base.dek_hex);

  // Transplant negatives across recipient classes (build the server-addressed info with a member user_id / a different FP)
  const serverWrapped = {
    encHex: serverVector.enc_hex,
    ciphertextHex: serverVector.ciphertext_hex,
  };
  await infoNegativeCheck(c, {
    name: "server-info-member-user-id",
    context: { ...serverContext(), recipientUserId: baseRecipientUserId },
    keyPair: pair.value,
    ...serverWrapped,
  });
  await infoNegativeCheck(c, {
    name: "server-info-fp-mismatch",
    context: { ...serverContext(), recipientUserId: wrongServerFingerprintHex() },
    keyPair: pair.value,
    ...serverWrapped,
  });

  // The reverse-direction transplant (a server FP in the recipient position of a member-addressed wrap) also fails Open
  const memberPair = await recipientKeyPair();
  if (!memberPair.ok) {
    c.push("dek-wrap negative: member-info-server-fp", false, "recipient key import failed");
    return;
  }
  await infoNegativeCheck(c, {
    name: "member-info-server-fp",
    context: { ...baseContext(), recipientUserId: serverFingerprintHex },
    keyPair: memberPair.value,
    encHex: base.enc_hex,
    ciphertextHex: base.ciphertext_hex,
  });
}

/** The "different server key FP" of the server-info-fp-mismatch vector (first byte flipped). */
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

  // The info-family negatives are reproduced as context swaps; also confirm
  // the info construction matches the vector's open_info_hex
  const contexts: readonly { name: string; context: DekWrapContext }[] = [
    { name: "info-epoch-mismatch", context: { ...baseContext(), epoch: 4 } },
    {
      name: "info-recipient-mismatch",
      context: { ...baseContext(), recipientUserId: "user-owner-0001" },
    },
    {
      name: "info-environment-mismatch",
      context: { ...baseContext(), environmentId: "env-dev-0002" },
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

  // Tampering with enc (the encapsulated public key)
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
  // A non-(non-negative safe integer) epoch returns InvalidInput rather than throwing
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
  // Seal direction: self round-trip (the recipient is a generated, non-extractable key)
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

  // Swapping the context fails Open
  const wrongContext = await unwrapDek({
    recipientKeyPair: recipient,
    wrapped: wrapped.value,
    context: { ...baseContext(), projectId: "proj-other" },
  });
  c.push("dek-wrap: roundtrip wrong context rejected", !wrongContext.ok);

  // A different recipient key fails Open
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
