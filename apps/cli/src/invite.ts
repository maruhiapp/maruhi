// `maruhi invite create|accept|list|revoke` (AUTH_SPEC §15 / CRYPTO_SPEC
// §6.5 — the 2026-09-13 IV revision).
//
// - create: assign the invite id → generate the link key (seed → Ed25519)
//   → sign the issuance with one's own chain sig key → issue (the
//   issuance to the server; the secret is never sent) → assemble the
//   §15-3 link (seed + issuance + signature; the anchor = the verified
//   head at issuance) → save the issuance pin (link_pub / role /
//   addressee login — an extra cross-check at member add)
// - accept: interpret the link → verify the issue signature (mechanical;
//   failure = no acceptance) → mutual confirmation of the inviter FP
//   (§6.5, invitee side — the mechanical check against the chain happens
//   on the first sync after add_member = context.ts) → key generation
//   [when absent, guarded] → joint acceptance signature (one's own sig
//   key + the link key) → accept → pinning the anchor (§6.3 (a) — only
//   after the acceptance is established)
// - list: verify the issuance (with the chain-derived inviter key) +
//   independent §6.5 verification of the acceptance block (acceptance
//   signature + link signature) + FP-word display + issuance-pin
//   cross-check
// - revoke: revocation
//
// The link key's seed exists only on the wire (the link) and in display —
// never persisted (the issuance pin holds only the public key). The
// server never receives the seed.

import { cryptoEffect } from "@maruhi/core";
import {
  computeUserKeyFingerprint,
  decodeHex,
  deriveInviteLinkKeyPair,
  encodeHex,
  type InviteAcceptSignatureContext,
  type MemberScope,
  type ScopeKind,
  SUITE_ID,
  verifyInviteAcceptSignature,
  verifyInviteIssueSignature,
  verifyInviteLinkSignature,
} from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { VerifiedProject } from "./chain-sync.ts";
import { devicesOf } from "./device-key.ts";
import { displayText, formatUtcMinutes } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import type { InviteLinkData, InviteRole } from "./invite-link.ts";
import { CliIo } from "./io.ts";
import { type InvitePins, issuedPinOf } from "./pins.ts";
import { describeScope, sameScope } from "./scope.ts";

/** The issuance (a listing response row — §15-1. An old row has null). */
export interface InviteIssuance {
  readonly linkPubHex: string;
  readonly headHashHex: string;
  readonly headSeq: number;
  readonly issueSignatureHex: string;
}

/** An invite's acceptance block (a listing response row — §15-1). */
export interface InviteAcceptance {
  readonly inviteeUserId: string;
  readonly inviteeEncPubHex: string;
  readonly inviteeSigPubHex: string;
  readonly signatureHex: string;
  readonly linkSignatureHex: string;
  readonly acceptedAtMs: number;
}

/** One row of the listing response (same shape as api-schema's InvitationSummary). */
export interface InvitationRow {
  readonly id: string;
  readonly projectId: string;
  readonly role: InviteRole;
  /** The scope to grant (2026-09-14 ES — part of the issuance; add_member signs this scope). */
  readonly scopeKind: ScopeKind;
  readonly scopeEnvironmentIds: readonly string[];
  readonly status: "pending" | "accepted" | "completed" | "revoked";
  readonly inviterUserId: string;
  readonly issuance: InviteIssuance;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
  readonly acceptance: InviteAcceptance | null;
}

/** Fetching the invite list (the shared prologue of invite list / member add). */
export function listInvitations(
  client: MaruhiClient,
  projectId: string,
): Effect.Effect<readonly InvitationRow[], CliError> {
  return client.invites.list({ params: { projectId } }).pipe(
    Effect.mapError(toCliError),
    Effect.map((response) => response.invitations),
  );
}

/** The issuance verification result (the reason is mapped to wording). */
export type IssuanceVerdict =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: "inviter-not-member" | "signature" };

/**
 * Verifying the issuance (CRYPTO_SPEC §6.5): the row's issuance + issue
 * signature are verified under **the inviter's current key derived from
 * the chain**. When the inviter is oneself this checks "is this a row I
 * issued" under one's own key (independent of the issuance pin —
 * supplement 21, ruling A ⑦), and a different admin running `member add`
 * detects a swapped row by the same check.
 */
export function verifyIssuance(input: {
  readonly verified: VerifiedProject;
  readonly row: InvitationRow;
}): Effect.Effect<IssuanceVerdict, CliError> {
  return Effect.gen(function* () {
    const { issuance } = input.row;
    const inviter = input.verified.state.members.get(input.row.inviterUserId);
    if (inviter === undefined) {
      return { ok: false, reason: "inviter-not-member" } as const;
    }
    // The issue signature's verification key = **any of the inviter's
    // current devices** (DK K4-16 — the issuance names a device's key
    // pair, so iterate all valid devices; if any verifies it is genuine.
    // A row issued by a revoked device does not pass = the inviter
    // reissues)
    for (const inviterDevice of devicesOf(inviter)) {
      // Any crypto failure means "this device's key does not verify the
      // row" — the same folding the pre-bridge `!ok` check made (the
      // verification's producible kinds are these three); anything the
      // union adds later is an invariant break and dies
      const verified = yield* cryptoEffect(() =>
        verifyInviteIssueSignature({
          context: {
            suite: SUITE_ID,
            inviteId: input.row.id,
            projectId: input.verified.projectId,
            linkPubHex: issuance.linkPubHex,
            headHashHex: issuance.headHashHex,
            headSeq: issuance.headSeq,
            role: input.row.role,
            inviterUserId: inviter.userId,
            inviterEncPubHex: inviterDevice.encPubHex,
            inviterSigPubHex: inviterDevice.sigPubHex,
            scopeKind: input.row.scopeKind,
            scopeEnvironmentIds: input.row.scopeEnvironmentIds,
          },
          signatureHex: issuance.issueSignatureHex,
        }),
      ).pipe(
        Effect.map(() => true as const),
        Effect.catchTags({
          CryptoInvalidInput: () => Effect.succeed(false as const),
          CryptoKeyImport: () => Effect.succeed(false as const),
          CryptoInviteIssueSignature: () => Effect.succeed(false as const),
        }),
        Effect.orDie,
      );
      if (verified) {
        return { ok: true } as const;
      }
    }
    return { ok: false, reason: "signature" } as const;
  });
}

/** The wording for an issuance verification failure (shared by list / member add). */
export function issuanceFailureText(
  reason: Exclude<IssuanceVerdict, { ok: true }>["reason"],
): string {
  switch (reason) {
    case "inviter-not-member":
      return "names an inviter who is not a current member of this project, so its issue signature cannot be checked — revoke it and issue a new one";
    case "signature":
      return "has an issue signature that does not verify under the inviter's chain key (CRYPTO_SPEC §6.5). The row may have been swapped or tampered with — do not use it; revoke the invite";
  }
}

/**
 * The acceptance block's independent §6.5 verification: **reconstruct**
 * signed_bytes oneself from the listing's material + the verified
 * context's projectId, and verify the acceptance signature (the declared
 * key) and the link signature (the issuance's link public key) (never
 * trusting the server's declared verification result).
 */
export function verifyAcceptanceBlock(input: {
  readonly projectId: string;
  readonly issuance: InviteIssuance;
  readonly acceptance: InviteAcceptance;
}): Effect.Effect<
  | { readonly ok: true; readonly fingerprintHex: string }
  | { readonly ok: false; readonly which: "accept" | "link" | "keys" },
  CliError
> {
  return Effect.gen(function* () {
    const context: InviteAcceptSignatureContext = {
      suite: SUITE_ID,
      projectId: input.projectId,
      linkPubHex: input.issuance.linkPubHex,
      inviteeUserId: input.acceptance.inviteeUserId,
      inviteeEncPubHex: input.acceptance.inviteeEncPubHex,
      inviteeSigPubHex: input.acceptance.inviteeSigPubHex,
    };
    // A crypto failure folds to the block's rejection kind (the same
    // folding the pre-bridge `!ok` checks made); a kind the verifiers
    // cannot produce is an invariant break and dies
    const linkVerified = yield* cryptoEffect(() =>
      verifyInviteLinkSignature({
        context,
        linkSignatureHex: input.acceptance.linkSignatureHex,
      }),
    ).pipe(
      Effect.map(() => true as const),
      Effect.catchTags({
        CryptoInvalidInput: () => Effect.succeed(false as const),
        CryptoKeyImport: () => Effect.succeed(false as const),
        CryptoInviteLinkSignature: () => Effect.succeed(false as const),
      }),
      Effect.orDie,
    );
    if (!linkVerified) {
      return { ok: false, which: "link" } as const;
    }
    const verified = yield* cryptoEffect(() =>
      verifyInviteAcceptSignature({ context, signatureHex: input.acceptance.signatureHex }),
    ).pipe(
      Effect.map(() => true as const),
      Effect.catchTags({
        CryptoInvalidInput: () => Effect.succeed(false as const),
        CryptoKeyImport: () => Effect.succeed(false as const),
        CryptoInviteAcceptSignature: () => Effect.succeed(false as const),
      }),
      Effect.orDie,
    );
    if (!verified) {
      return { ok: false, which: "accept" } as const;
    }
    const enc = decodeHex(input.acceptance.inviteeEncPubHex);
    const sig = decodeHex(input.acceptance.inviteeSigPubHex);
    if (enc === null || sig === null) {
      return { ok: false, which: "keys" } as const;
    }
    const fingerprint = yield* cryptoEffect(() => computeUserKeyFingerprint(enc, sig)).pipe(
      Effect.catchTag("CryptoInvalidInput", () => Effect.succeed(null)),
      Effect.orDie,
    );
    if (fingerprint === null) {
      return { ok: false, which: "keys" } as const;
    }
    return { ok: true, fingerprintHex: encodeHex(fingerprint) } as const;
  });
}

/** The wording for an acceptance-block verification failure (shared by list / member add). */
export function acceptanceFailureText(which: "accept" | "link" | "keys"): string {
  switch (which) {
    case "link":
      return "the link signature failed verification (CRYPTO_SPEC §6.5) — the acceptance was not made with the link you issued (the server or someone in between may have substituted the key)";
    case "accept":
      return "the acceptance signature failed verification (CRYPTO_SPEC §6.5)";
    case "keys":
      return "the acceptance keys are malformed";
  }
}

/** The post-issuance guidance (the link to stdout, explanations to stderr). */
export function reportIssued(input: {
  readonly link: Redacted.Redacted<string>;
  readonly inviteId: string;
  readonly role: InviteRole;
  readonly scope: MemberScope;
  readonly expiresAtMs: number;
  readonly expectedGithubLogin: string | null;
}): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    // Reason for unwrapping: displaying the link is this command's very
    // function. Displayability was already decided by the TTY + agent
    // gate at the head of inviteCreateOp, and the unwrap happens behind
    // it
    yield* io.log(Redacted.value(input.link));
    yield* io.logError(
      `Issued an invite (id=${displayText(input.inviteId)}, role=${input.role}, scope=${describeScope(input.scope)}, expires=${formatDateTimeUtc(input.expiresAtMs)})`,
    );
    yield* io.logError(
      "This link is shown only once (the server holds only the link's public key and cannot rebuild it). Hand it to the invitee over a person-to-person channel",
    );
    yield* io.logError(
      input.expectedGithubLogin === null
        ? "After they accept: run `maruhi member add`. The acceptance is checked against the link you issued; confirm the acceptor's FP words with them out of band (e.g. a call) unless it can be verified through their GitHub signing keys"
        : `After they accept: run \`maruhi member add\`. The acceptance is checked against the link you issued and against github.com/${input.expectedGithubLogin}'s signing keys — no call is needed when both pass`,
    );
  });
}

// createdAtMs / expiresAtMs are the server's declared, unbounded numbers
// (B4): display them via the total shared formatter so a value outside
// the Date range cannot become a defect (RangeError) (never let invite
// create / list end in an untyped crash)
export const formatDateTimeUtc = formatUtcMinutes;

/** Deriving the link key (seed → key pair + public key hex). */
export function resolveLinkKey(link: InviteLinkData) {
  return Effect.gen(function* () {
    // Reason for unwrapping: key derivation needs the byte string itself.
    // The seed is consumed here; from here on only the CryptoKey
    // (non-extractable) and the public key flow
    const seed = decodeHex(Redacted.value(link.linkSeedHex));
    if (seed === null) {
      return yield* Effect.fail(cliError("The link's key seed (k=) is malformed"));
    }
    const derived = yield* cryptoEffect(() => deriveInviteLinkKeyPair(seed)).pipe(
      Effect.mapError(() => cliError("Failed to derive the invite link key")),
    );
    return { keyPair: derived, linkPubHex: encodeHex(derived.publicKeyRaw) };
  });
}

/**
 * The issuance-pin cross-check (§6.5's inviter-side extra material —
 * SHOULD): a server-claimed row disagreeing with the issuance-time
 * link_pub / role / scope is a sign of a swapped row or a false role /
 * scope claim. With no pin (issued on another device) only the issue
 * signature's verification pins the row.
 */
export function pinMismatchOf(
  pins: InvitePins | null,
  row: InvitationRow,
): "missing" | "mismatch" | "match" {
  const pin = issuedPinOf(pins, row.id);
  if (pin === undefined) {
    return "missing";
  }
  return pin.linkPubHex !== row.issuance?.linkPubHex ||
    pin.role !== row.role ||
    !sameScope(pin, row)
    ? "mismatch"
    : "match";
}
