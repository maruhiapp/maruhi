import {
  buildInviteAcceptSignedBytes,
  deriveInviteLinkKeyPair,
  generateSigningKeyPair,
  importSigningKeyPair,
  type InviteAcceptSignatureContext,
  signInviteAccept,
  signInviteLink,
  verifyInviteAcceptSignature,
  verifyInviteLinkSignature,
} from "../../src/index.ts";
import vectors from "../../test-vectors/invite-accept-signature.json" with { type: "json" };
import { testProjectId, testUserId } from "../support/fixture.ts";
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

const baseVector = vectors.vectors[0];
if (baseVector === undefined) {
  throw new Error("invite-accept-signature.json: basic vector missing");
}
const base = baseVector;

interface VectorContext {
  readonly suite: string;
  readonly project_id: string;
  readonly link_pub_hex: string;
  readonly invitee_user_id: string;
  readonly invitee_enc_pub_hex: string;
  readonly invitee_sig_pub_hex: string;
}

function contextOf(v: VectorContext): InviteAcceptSignatureContext {
  return {
    suite: v.suite,
    projectId: testProjectId(v.project_id),
    linkPubHex: v.link_pub_hex,
    inviteeUserId: testUserId(v.invitee_user_id),
    inviteeEncPubHex: v.invitee_enc_pub_hex,
    inviteeSigPubHex: v.invitee_sig_pub_hex,
  };
}

async function vectorChecks(c: Checks): Promise<void> {
  const invitee = await importSigningKeyPair({
    publicKey: fromHex(vectors.invitee.sig_pub_hex),
    privateSeed: fromHex(vectors.invitee.sig_sk_seed_hex),
  });
  const link = await deriveInviteLinkKeyPair(fromHex(vectors.link_key.seed_hex));
  if (!invitee.ok || !link.ok) {
    c.push("invite-accept-sig: vector keys", false, "key import failed");
    return;
  }
  c.push(
    "invite-accept-sig: link key derived from seed",
    toHex(link.value.publicKeyRaw) === vectors.link_key.pub_hex &&
      base.link_pub_hex === vectors.link_key.pub_hex,
  );
  for (const vector of vectors.vectors) {
    const context = contextOf(vector);
    const builtHex = toHex(buildInviteAcceptSignedBytes(context));
    const signed = await signInviteAccept({ context, signingKey: invitee.value.privateKey });
    const linkSigned = await signInviteLink({ context, linkPrivateKey: link.value.privateKey });
    const verified = await verifyInviteAcceptSignature({
      context,
      signatureHex: vector.signature_hex,
    });
    const linkVerified = await verifyInviteLinkSignature({
      context,
      linkSignatureHex: vector.link_signature_hex,
    });
    c.push(
      `invite-accept-sig: ${vector.name} signed bytes construction`,
      builtHex === vector.signed_bytes_hex,
    );
    c.push(
      `invite-accept-sig: ${vector.name} sign == signature`,
      signed.ok && signed.value === vector.signature_hex,
    );
    c.push(
      `invite-accept-sig: ${vector.name} link sign == link signature`,
      linkSigned.ok && linkSigned.value === vector.link_signature_hex,
    );
    c.push(`invite-accept-sig: ${vector.name} verify`, verified.ok);
    c.push(`invite-accept-sig: ${vector.name} verify link`, linkVerified.ok);
  }
}

async function negativeChecks(c: Checks): Promise<void> {
  await acceptNegativeChecks(c);
  await linkNegativeChecks(c);
}

async function acceptNegativeChecks(c: Checks): Promise<void> {
  for (const negative of vectors.negative) {
    const context = contextOf(negative.context);
    const result = await verifyInviteAcceptSignature({
      context,
      signatureHex: negative.signature_hex,
    });
    const bytesHex = toHex(buildInviteAcceptSignedBytes(context));
    const bytesExpectation =
      negative.name === "legacy-domain"
        ? bytesHex !== negative.verify_signed_bytes_hex
        : bytesHex === negative.verify_signed_bytes_hex;
    c.push(
      `invite-accept-sig negative: ${negative.name}`,
      bytesExpectation &&
        negative.verify_key_hex === negative.context.invitee_sig_pub_hex &&
        isKind(result, "InviteAcceptSignatureInvalid"),
    );
  }
}

async function linkNegativeChecks(c: Checks): Promise<void> {
  for (const negative of vectors.link_negative) {
    const context = contextOf(negative.context);
    const result = await verifyInviteLinkSignature({
      context,
      linkSignatureHex: negative.signature_hex,
    });
    c.push(
      `invite-link-sig negative: ${negative.name}`,
      toHex(buildInviteAcceptSignedBytes(context)) === negative.verify_signed_bytes_hex &&
        negative.verify_key_hex === negative.context.link_pub_hex &&
        isKind(result, "InviteLinkSignatureInvalid"),
    );
  }
}

function isKind(result: { ok: boolean; error?: { kind: string } }, kind: string): boolean {
  return !result.ok && result.error?.kind === kind;
}

function badAcceptContexts(): readonly { name: string; context: InviteAcceptSignatureContext }[] {
  return [
    {
      name: "uppercase link pub",
      context: { ...contextOf(base), linkPubHex: base.link_pub_hex.toUpperCase() },
    },
    { name: "short link pub", context: { ...contextOf(base), linkPubHex: "ab" } },
    { name: "short enc pub", context: { ...contextOf(base), inviteeEncPubHex: "ab" } },
    { name: "short sig pub", context: { ...contextOf(base), inviteeSigPubHex: "ab" } },
    { name: "empty suite", context: { ...contextOf(base), suite: "" } },
    { name: "empty invitee", context: { ...contextOf(base), inviteeUserId: testUserId("") } },
  ];
}

async function allInvalidInput(
  context: InviteAcceptSignatureContext,
  signingKey: CryptoKey,
): Promise<boolean> {
  const results = await Promise.all([
    signInviteAccept({ context, signingKey }),
    signInviteLink({ context, linkPrivateKey: signingKey }),
    verifyInviteAcceptSignature({ context, signatureHex: base.signature_hex }),
    verifyInviteLinkSignature({ context, linkSignatureHex: base.link_signature_hex }),
  ]);
  return results.every((result) => isKind(result, "InvalidInput"));
}

async function invalidInputChecks(c: Checks): Promise<void> {
  const pair = await generateSigningKeyPair();
  for (const bad of badAcceptContexts()) {
    c.push(
      `invite-accept-sig invalid input: ${bad.name}`,
      await allInvalidInput(bad.context, pair.privateKey),
    );
  }
  const shortSignature = await verifyInviteAcceptSignature({
    context: contextOf(base),
    signatureHex: "ab".repeat(63),
  });
  const shortLinkSignature = await verifyInviteLinkSignature({
    context: contextOf(base),
    linkSignatureHex: "ab".repeat(63),
  });
  c.push(
    "invite-accept-sig invalid input: short signature",
    isKind(shortSignature, "InvalidInput") && isKind(shortLinkSignature, "InvalidInput"),
  );
}

async function roundtripChecks(c: Checks): Promise<void> {
  const invitee = await generateSigningKeyPair();
  const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", invitee.publicKey));
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  const link = await deriveInviteLinkKeyPair(seed);
  if (!link.ok) {
    c.push("invite-accept-sig: roundtrip", false, "link key derivation failed");
    return;
  }
  const context: InviteAcceptSignatureContext = {
    ...contextOf(base),
    inviteeSigPubHex: toHex(rawPub),
    linkPubHex: toHex(link.value.publicKeyRaw),
  };
  const signed = await signInviteAccept({ context, signingKey: invitee.privateKey });
  const linkSigned = await signInviteLink({ context, linkPrivateKey: link.value.privateKey });
  if (!signed.ok || !linkSigned.ok) {
    c.push("invite-accept-sig: roundtrip", false, "sign failed");
    return;
  }
  const verified = await verifyInviteAcceptSignature({ context, signatureHex: signed.value });
  const linkVerified = await verifyInviteLinkSignature({
    context,
    linkSignatureHex: linkSigned.value,
  });
  c.push("invite-accept-sig: roundtrip", verified.ok && linkVerified.ok);

  const other = await generateSigningKeyPair();
  const otherPub = new Uint8Array(await crypto.subtle.exportKey("raw", other.publicKey));
  const declaredOther = await verifyInviteAcceptSignature({
    context: { ...context, inviteeSigPubHex: toHex(otherPub) },
    signatureHex: signed.value,
  });
  c.push("invite-accept-sig: roundtrip declared-key swap rejected", !declaredOther.ok);

  const otherSeed = new Uint8Array(32);
  crypto.getRandomValues(otherSeed);
  const otherLink = await deriveInviteLinkKeyPair(otherSeed);
  const forged = otherLink.ok
    ? await signInviteLink({ context, linkPrivateKey: otherLink.value.privateKey })
    : otherLink;
  const forgedVerified = forged.ok
    ? await verifyInviteLinkSignature({ context, linkSignatureHex: forged.value })
    : forged;
  c.push("invite-accept-sig: roundtrip forged link signature rejected", !forgedVerified.ok);

  const wrongContext = await verifyInviteAcceptSignature({
    context: { ...context, projectId: testProjectId("proj-other") },
    signatureHex: signed.value,
  });
  const wrongLinkContext = await verifyInviteLinkSignature({
    context: { ...context, projectId: testProjectId("proj-other") },
    linkSignatureHex: linkSigned.value,
  });
  c.push(
    "invite-accept-sig: roundtrip wrong context rejected",
    !wrongContext.ok && !wrongLinkContext.ok,
  );
}

export async function inviteAcceptSignatureChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  await vectorChecks(c);
  await negativeChecks(c);
  await invalidInputChecks(c);
  await roundtripChecks(c);
  return c.results;
}
