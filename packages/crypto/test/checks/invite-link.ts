// Checks for CRYPTO_SPEC §6.5 (IV — link key derivation, issue signature, and
// the OpenSSH public key line).
// The issue signature is Ed25519-deterministic, so the sign direction is also
// verified to match the vector exactly.
// The negatives pin that "the implementation's canonicalization reproduces the
// vector's verify_signed_bytes_hex, and on top of that the original signature
// fails verification". OpenSSH parsing decodes third-party data (GitHub
// responses), so the acceptance boundary (type, key length, in-blob type,
// extra bytes, base64) is pinned with vectors.

import {
  buildInviteIssueSignedBytes,
  deriveInviteLinkKeyPair,
  encodeOpenSshEd25519PublicKey,
  generateInviteLinkSeed,
  generateSigningKeyPair,
  importSigningKeyPair,
  importSigningPublicKey,
  INVITE_LINK_SEED_BYTES,
  type InviteIssueContext,
  parseOpenSshEd25519PublicKey,
  type ScopeKind,
  signInviteIssue,
  verifyInviteIssueSignature,
} from "../../src/index.ts";
import chainVectors from "../../test-vectors/chain-entries.json" with { type: "json" };
import vectors from "../../test-vectors/invite-link.json" with { type: "json" };
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

const baseVector = vectors.issue.vectors[0];
if (baseVector === undefined) {
  throw new Error("invite-link.json: basic issue vector missing");
}
const base = baseVector;

interface VectorContext {
  readonly suite: string;
  readonly invite_id: string;
  readonly project_id: string;
  readonly link_pub_hex: string;
  readonly head_hash_hex: string;
  readonly head_seq: number;
  readonly role: string;
  readonly inviter_user_id: string;
  readonly inviter_enc_pub_hex: string;
  readonly inviter_sig_pub_hex: string;
  readonly scope_kind: string;
  readonly scope_environments: readonly string[];
}

function contextOf(v: VectorContext): InviteIssueContext {
  return {
    suite: v.suite,
    inviteId: v.invite_id,
    projectId: v.project_id,
    linkPubHex: v.link_pub_hex,
    headHashHex: v.head_hash_hex,
    headSeq: v.head_seq,
    role: v.role,
    inviterUserId: v.inviter_user_id,
    inviterEncPubHex: v.inviter_enc_pub_hex,
    inviterSigPubHex: v.inviter_sig_pub_hex,
    // scope (2026-09-14 ES — the last 2 fields of the §6.5 issue text)
    scopeKind: v.scope_kind as ScopeKind,
    scopeEnvironmentIds: v.scope_environments,
  };
}

async function linkKeyChecks(c: Checks): Promise<void> {
  for (const [label, key] of [
    ["link_key", vectors.link_key],
    ["other_link_key", vectors.other_link_key],
  ] as const) {
    const derived = await deriveInviteLinkKeyPair(fromHex(key.seed_hex));
    c.push(
      `invite-link: ${label} derived from seed`,
      derived.ok && toHex(derived.value.publicKeyRaw) === key.pub_hex,
    );
    // The derived public key object also matches raw (consistency of the two imports)
    if (derived.ok) {
      const exported = new Uint8Array(
        await crypto.subtle.exportKey("raw", derived.value.publicKey),
      );
      c.push(`invite-link: ${label} public CryptoKey matches raw`, toHex(exported) === key.pub_hex);
    }
  }
  const generated = generateInviteLinkSeed();
  c.push(
    "invite-link: generated seed length",
    generated.length === INVITE_LINK_SEED_BYTES && generated.some((b) => b !== 0),
  );
  const short = await deriveInviteLinkKeyPair(new Uint8Array(31));
  c.push("invite-link: short seed rejected", !short.ok && short.error.kind === "InvalidInput");
}

async function issueVectorChecks(c: Checks): Promise<void> {
  const ownerKeys = chainVectors.keys["user-owner-0001"];
  const inviter = await importSigningKeyPair({
    publicKey: fromHex(ownerKeys.sig_pub_hex),
    privateSeed: fromHex(ownerKeys.sig_sk_seed_hex),
  });
  if (!inviter.ok) {
    c.push("invite-issue-sig: vector keys", false, "inviter key import failed");
    return;
  }
  const head = chainVectors.entries[chainVectors.entries.length - 1];
  c.push(
    "invite-issue-sig: inviter and head come from the canonical chain",
    base.inviter_sig_pub_hex === ownerKeys.sig_pub_hex &&
      base.inviter_enc_pub_hex === ownerKeys.enc_pub_hex &&
      head !== undefined &&
      base.head_hash_hex === head.entry_hash_hex &&
      base.head_seq === head.seq,
  );
  await issuePositiveChecks(c, inviter.value.privateKey);
  await issueNegativeChecks(c);
}

async function issuePositiveChecks(c: Checks, signingKey: CryptoKey): Promise<void> {
  for (const vector of vectors.issue.vectors) {
    const context = contextOf(vector);
    const signed = await signInviteIssue({ context, signingKey });
    const verified = await verifyInviteIssueSignature({
      context,
      signatureHex: vector.signature_hex,
    });
    c.push(
      `invite-issue-sig: ${vector.name} signed bytes construction`,
      toHex(buildInviteIssueSignedBytes(context)) === vector.signed_bytes_hex,
    );
    c.push(
      `invite-issue-sig: ${vector.name} sign == signature`,
      signed.ok && signed.value === vector.signature_hex,
    );
    c.push(`invite-issue-sig: ${vector.name} verify`, verified.ok);
  }
}

interface IssueNegative {
  readonly name: string;
  /** "encoding" = a byte string this implementation would never produce (legacy form, flattened). Unspecified = tampering / transplant. */
  readonly kind?: string;
  readonly context: VectorContext;
  readonly signature_hex: string;
  readonly verify_key_hex: string;
  readonly verify_signed_bytes_hex: string;
}

async function issueNegativeChecks(c: Checks): Promise<void> {
  const seenKinds = new Set<string>();
  for (const negative of vectors.issue.negative as readonly IssueNegative[]) {
    seenKinds.add(negative.kind ?? "signature");
    if (negative.kind === "encoding") {
      await issueEncodingNegativeCheck(c, negative);
      continue;
    }
    const context = contextOf(negative.context);
    const result = await verifyInviteIssueSignature({
      context,
      signatureHex: negative.signature_hex,
    });
    c.push(
      `invite-issue-sig negative: ${negative.name}`,
      toHex(buildInviteIssueSignedBytes(context)) === negative.verify_signed_bytes_hex &&
        negative.verify_key_hex === negative.context.inviter_sig_pub_hex &&
        !result.ok &&
        result.error.kind === "InviteIssueSignatureInvalid",
    );
  }
  c.push(
    "invite-issue-sig negative: kind vocabulary is exhaustive",
    [...seenKinds].every((kind) => kind === "signature" || kind === "encoding"),
  );
}

/**
 * Encoding-family negatives (the legacy 10-field form lacking scope, the flat
 * scope concatenation): pin that canonicalization **does not produce** the
 * vector's byte string, and that the canonical issue signature fails
 * verification on top of that byte string (README convention 27 — there is no
 * compat-acceptance path; isomorphic to chain-entries' flat-concat)
 */
async function issueEncodingNegativeCheck(c: Checks, negative: IssueNegative): Promise<void> {
  const context = contextOf(negative.context);
  const differs = toHex(buildInviteIssueSignedBytes(context)) !== negative.verify_signed_bytes_hex;
  const key = await importSigningPublicKey(fromHex(negative.verify_key_hex));
  if (!key.ok) {
    c.push(`invite-issue-sig negative: ${negative.name}`, false, "verify key import failed");
    return;
  }
  const verified = await crypto.subtle.verify(
    "Ed25519",
    key.value,
    fromHex(negative.signature_hex) as BufferSource,
    fromHex(negative.verify_signed_bytes_hex) as BufferSource,
  );
  c.push(
    `invite-issue-sig negative: ${negative.name}`,
    differs && negative.verify_key_hex === negative.context.inviter_sig_pub_hex && !verified,
  );
}

async function issueInvalidInputChecks(c: Checks): Promise<void> {
  const pair = await generateSigningKeyPair();
  const badContexts: readonly { name: string; context: InviteIssueContext }[] = [
    { name: "empty suite", context: { ...contextOf(base), suite: "" } },
    { name: "empty invite id", context: { ...contextOf(base), inviteId: "" } },
    { name: "empty role", context: { ...contextOf(base), role: "" } },
    { name: "empty inviter", context: { ...contextOf(base), inviterUserId: "" } },
    {
      name: "uppercase link pub",
      context: { ...contextOf(base), linkPubHex: base.link_pub_hex.toUpperCase() },
    },
    { name: "short head hash", context: { ...contextOf(base), headHashHex: "ab" } },
    { name: "zero head seq", context: { ...contextOf(base), headSeq: 0 } },
    { name: "fractional head seq", context: { ...contextOf(base), headSeq: 1.5 } },
    {
      name: "unsafe head seq",
      context: { ...contextOf(base), headSeq: Number.MAX_SAFE_INTEGER + 1 },
    },
    { name: "short inviter enc pub", context: { ...contextOf(base), inviterEncPubHex: "ab" } },
    { name: "short inviter sig pub", context: { ...contextOf(base), inviterSigPubHex: "ab" } },
    // The structural rules of scope (same as §6.2 — all ⇒ empty list, no duplicates, closed-set kind, non-empty id)
    {
      name: "all scope with environments",
      context: { ...contextOf(base), scopeKind: "all", scopeEnvironmentIds: ["env-dev-0002"] },
    },
    {
      name: "duplicate scope environment",
      context: {
        ...contextOf(base),
        scopeKind: "listed",
        scopeEnvironmentIds: ["env-dev-0002", "env-dev-0002"],
      },
    },
    {
      name: "empty scope environment id",
      context: { ...contextOf(base), scopeKind: "listed", scopeEnvironmentIds: [""] },
    },
    {
      name: "unknown scope kind",
      context: { ...contextOf(base), scopeKind: "some" as ScopeKind, scopeEnvironmentIds: [] },
    },
    // The id bound (1024 bytes in §6.1 — symmetric to add_member on the chain side)
    {
      name: "oversized scope environment id",
      context: {
        ...contextOf(base),
        scopeKind: "listed",
        scopeEnvironmentIds: ["e".repeat(1025)],
      },
    },
  ];
  for (const bad of badContexts) {
    const signed = await signInviteIssue({ context: bad.context, signingKey: pair.privateKey });
    const verified = await verifyInviteIssueSignature({
      context: bad.context,
      signatureHex: base.signature_hex,
    });
    c.push(
      `invite-issue-sig invalid input: ${bad.name}`,
      !signed.ok &&
        signed.error.kind === "InvalidInput" &&
        !verified.ok &&
        verified.error.kind === "InvalidInput",
    );
  }
  const shortSignature = await verifyInviteIssueSignature({
    context: contextOf(base),
    signatureHex: "ab".repeat(63),
  });
  c.push(
    "invite-issue-sig invalid input: short signature",
    !shortSignature.ok && shortSignature.error.kind === "InvalidInput",
  );
}

async function issueRoundtripChecks(c: Checks): Promise<void> {
  const inviter = await generateSigningKeyPair();
  const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", inviter.publicKey));
  const context: InviteIssueContext = { ...contextOf(base), inviterSigPubHex: toHex(rawPub) };
  const signed = await signInviteIssue({ context, signingKey: inviter.privateKey });
  if (!signed.ok) {
    c.push("invite-issue-sig: roundtrip", false, "sign failed");
    return;
  }
  const verified = await verifyInviteIssueSignature({ context, signatureHex: signed.value });
  c.push("invite-issue-sig: roundtrip", verified.ok);
  // Transplanting to a different invite id fails verification (the server cannot transplant the issue text to another row)
  const transplanted = await verifyInviteIssueSignature({
    context: { ...context, inviteId: "invite-other" },
    signatureHex: signed.value,
  });
  c.push("invite-issue-sig: roundtrip transplanted invite id rejected", !transplanted.ok);
  // The ghost-adder shape: even setting the declared key to the inviter's public key, a signature by another key does not pass
  const ghost = await generateSigningKeyPair();
  const ghostSigned = await signInviteIssue({ context, signingKey: ghost.privateKey });
  const ghostVerified = ghostSigned.ok
    ? await verifyInviteIssueSignature({ context, signatureHex: ghostSigned.value })
    : ghostSigned;
  c.push("invite-issue-sig: roundtrip ghost signer rejected", !ghostVerified.ok);
}

function opensshChecks(c: Checks): void {
  opensshVectorChecks(c);
  opensshRoundtripChecks(c);
  // Parse rejections (convention 21: pinned in the implementation harness — shapes not present in the vector negatives)
  for (const [name, input] of rejectedOpenSshInputs()) {
    const rejectedParse = parseOpenSshEd25519PublicKey(input as string);
    c.push(
      `openssh: parse rejects ${name}`,
      !rejectedParse.ok && rejectedParse.error.kind === "InvalidInput",
    );
  }
}

function opensshVectorChecks(c: Checks): void {
  for (const vector of vectors.openssh.encode) {
    const encoded = encodeOpenSshEd25519PublicKey(fromHex(vector.public_key_hex));
    c.push(`openssh: encode ${vector.name}`, encoded.ok && encoded.value === vector.expected_line);
  }
  for (const vector of vectors.openssh.parse) {
    const parsed = parseOpenSshEd25519PublicKey(vector.line);
    c.push(
      `openssh: parse ${vector.name}`,
      parsed.ok && toHex(parsed.value) === vector.expected_public_key_hex,
    );
  }
  for (const negative of vectors.openssh.parse_negative) {
    const parsed = parseOpenSshEd25519PublicKey(negative.line);
    c.push(
      `openssh: parse negative ${negative.name}`,
      !parsed.ok && parsed.error.kind === "InvalidInput",
    );
  }
}

function opensshRoundtripChecks(c: Checks): void {
  // The encode → parse round-trip (generated key), and encode rejection of a wrong key length
  const raw = new Uint8Array(32);
  crypto.getRandomValues(raw);
  const encoded = encodeOpenSshEd25519PublicKey(raw);
  const parsed = encoded.ok ? parseOpenSshEd25519PublicKey(encoded.value) : encoded;
  c.push("openssh: roundtrip", parsed.ok && toHex(parsed.value) === toHex(raw));
  const shortKey = encodeOpenSshEd25519PublicKey(new Uint8Array(31));
  c.push("openssh: encode short key rejected", !shortKey.ok);
}

/** Rejected inputs built from the vector's positive case (type mismatch, length, alphabet, whitespace). */
function rejectedOpenSshInputs(): readonly (readonly [string, unknown])[] {
  const good = vectors.openssh.parse[0];
  if (good === undefined) {
    throw new Error("openssh parse vector missing");
  }
  const [type = "", text = ""] = good.line.split(" ");
  const line = `${type} ${text}`;
  const blob = base64ToBytes(text);
  const withBlob = (bytes: Uint8Array) => `${type} ${bytesToBase64(bytes)}`;
  // A 33-byte key (the inner length prefix is also set to 33)
  const longKey = new Uint8Array(blob.length + 1);
  longKey.set(blob);
  longKey[4 + 11 + 3] = 33;
  // Only the inner type length prefix set to 10, keeping the total length
  const badInnerLength = new Uint8Array(blob);
  badInnerLength[3] = 10;
  return [
    ["non-string input (null)", null],
    ["non-string input (number)", 42],
    ["33-byte key", withBlob(longKey)],
    ["inner type length mismatch with same total length", withBlob(badInnerLength)],
    // base64url-only characters (- _) are outside the standard alphabet (length is kept)
    ["base64url alphabet", `${type} -_${text.slice(2)}`],
    ["whitespace inside the base64", `${type} ${text.slice(0, 10)} ${text.slice(10)}`],
    ["leading space", ` ${line}`],
    ["tab separator", line.replace(" ", "\t")],
    ["newline inside the line", `${type}\n${text}`],
    ["oversize base64 (rejected before decoding)", `${type} ${"A".repeat(4 * 1024 * 1024)}`],
  ];
}

function base64ToBytes(text: string): Uint8Array {
  return Uint8Array.from(atob(text), (ch) => ch.charCodeAt(0));
}

function bytesToBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

export async function inviteLinkChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  await linkKeyChecks(c);
  await issueVectorChecks(c);
  await issueInvalidInputChecks(c);
  await issueRoundtripChecks(c);
  opensshChecks(c);
  return c.results;
}
