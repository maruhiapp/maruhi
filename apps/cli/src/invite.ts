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

import {
  ForbiddenError,
  InviteConflictError,
  InviteGoneError,
  InviteNotFoundError,
  InvitePendingLimitError,
  InviteRateLimitedError,
  InviteSignatureInvalidError,
} from "@maruhi/api-schema";
import { ulid } from "@maruhi/core";
import {
  type ChainMember,
  computeUserKeyFingerprint,
  decodeHex,
  deriveInviteLinkKeyPair,
  effectivePermissionOf,
  encodeHex,
  generateInviteLinkSeed,
  type InviteAcceptSignatureContext,
  type MemberScope,
  type ScopeKind,
  type ScopePayloadFields,
  scopePayloadFieldsOf,
  signInviteAccept,
  signInviteIssue,
  signInviteLink,
  SUITE_ID,
  verifyInviteAcceptSignature,
  verifyInviteIssueSignature,
  verifyInviteLinkSignature,
} from "@maruhi/crypto";
import { Effect, Redacted, Stdio } from "effect";
import type { HttpClient } from "effect/unstable/http";

import { ensureSensitiveTerminalAllowed } from "./agent-gate.ts";
import type { MaruhiClient } from "./api.ts";
import type { IdentityBacking } from "./config.ts";
import type { CliServices } from "./context.ts";
import { ROLE_RANK } from "./dek-wrap.ts";
import { devicesOf, ownDeviceByKeys } from "./device-key.ts";
import { displayText, formatUtcMinutes } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { confirmByLastWord, fingerprintWords, formatWordList } from "./fp-words.ts";
import { checkSigningKeyBacking, describeBackingFallback } from "./github-signing-keys.ts";
import { buildInviteLink, type InviteLinkData, type InviteRole } from "./invite-link.ts";
import { CliIo, type CliIoShape } from "./io.ts";
import { offerGithubRegistration } from "./key-publish.ts";
import { Keychain, masterKeyEntryName } from "./keychain.ts";
import {
  confirmKnownFingerprint,
  consultFingerprintBook,
  type FingerprintBook,
  usableBookHit,
} from "./known-fingerprints.ts";
import { logNote, logWarning } from "./notice.ts";
import { type InvitePins, issuedPinOf, PinStore } from "./pins.ts";
import { describeScope, requireScopeEnvironmentsExist, sameScope, scopeContains } from "./scope.ts";
import { type CliSession, loadMasterKeys, type MasterKeys } from "./session.ts";
import type { VerifiedProject } from "./sync.ts";

/** The warning for a failed anchor pin (a SHOULD-level degradation — the acceptance itself is already established). */
const warnUnpinned = (detail: string) =>
  logWarning(
    `could not pin the invite link anchor (${detail}). The machine check on first sync (CRYPTO_SPEC §6.3 (a)) will not run — be sure to perform the ceremony with the inviter (out-of-band FP word comparison)`,
  );

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
      const verified = yield* Effect.tryPromise({
        try: () =>
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
        catch: () => cliError("Failed to verify the issue signature (crypto error)"),
      });
      if (verified.ok) {
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
    const linkVerified = yield* Effect.tryPromise({
      try: () =>
        verifyInviteLinkSignature({
          context,
          linkSignatureHex: input.acceptance.linkSignatureHex,
        }),
      catch: () => cliError("Failed to verify the link signature (crypto error)"),
    });
    if (!linkVerified.ok) {
      return { ok: false, which: "link" } as const;
    }
    const verified = yield* Effect.tryPromise({
      try: () =>
        verifyInviteAcceptSignature({ context, signatureHex: input.acceptance.signatureHex }),
      catch: () => cliError("Failed to verify the acceptance signature (crypto error)"),
    });
    if (!verified.ok) {
      return { ok: false, which: "accept" } as const;
    }
    const enc = decodeHex(input.acceptance.inviteeEncPubHex);
    const sig = decodeHex(input.acceptance.inviteeSigPubHex);
    if (enc === null || sig === null) {
      return { ok: false, which: "keys" } as const;
    }
    const fingerprint = yield* Effect.tryPromise({
      try: () => computeUserKeyFingerprint(enc, sig),
      catch: () => cliError("Failed to compute the acceptance key's fingerprint (crypto error)"),
    });
    if (!fingerprint.ok) {
      return { ok: false, which: "keys" } as const;
    }
    return { ok: true, fingerprintHex: encodeHex(fingerprint.value) } as const;
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

// ---------------------------------------------------------------------------
// invite create
// ---------------------------------------------------------------------------

export interface InviteCreateSummary {
  readonly id: string;
  /** The issued link (contains the link key's seed — never unwrapped except for display). */
  readonly link: Redacted.Redacted<string>;
  readonly role: InviteRole;
  readonly expiresAtMs: number;
}

function ensureInviteLinkDisplayAllowed(
  io: CliIoShape,
): Effect.Effect<void, CliError, Stdio.Stdio> {
  return ensureSensitiveTerminalAllowed({
    agent: io.agentProfile(),
    stderrIsTerminal: io.stderrIsTerminal(),
    agentError:
      "An AI agent environment was detected, so the invite was not issued (the invite link's secret would persist in execution logs and transcripts). Run `maruhi invite create` on a human interactive terminal",
    terminalError:
      "Invite-link display is only allowed on an interactive terminal (stdin, stdout, and stderr must all be terminals; pipes, redirects, CI, and AI agents are refused)",
  });
}

/** The wording for an issuance acceptance error (translates a reason code into an operational procedure). */
function issueErrorToCliError(error: unknown): CliError {
  if (error instanceof InvitePendingLimitError) {
    return cliError(
      `Pending invites have reached the limit (${error.limit}). Revoke unneeded invites with \`maruhi invite revoke\`, then issue again`,
    );
  }
  if (error instanceof InviteRateLimitedError) {
    return cliError(
      `Invite issuance hit the rate limit. Retry in about ${error.retryAfterSeconds} seconds`,
    );
  }
  if (error instanceof InviteConflictError) {
    // id / link key are random, so a collision effectively never happens — if it does, re-running draws a fresh one
    return cliError(
      "The server already has an invite with the same id or link key (an astronomically unlikely collision). Re-run `maruhi invite create` to draw a new one",
    );
  }
  return toCliError(error);
}

/**
 * Issuing an invite + issue signature + link assembly + saving the
 * issuance pin. Issuance authorization is enforced by the server, but the
 * role rules (the same level as §6.2: issuing requires admin or above,
 * role=admin requires owner) are dropped locally before communicating
 * (for clear wording).
 */
/**
 * Pre-issuance checks (before communicating): the inviter's role rules
 * (the same level as §6.2: issuing requires admin or above, role=admin
 * requires owner) and that the local master key matches one's own key on
 * the chain (otherwise the issuance fails the invitee's and one's own
 * later verification). Returns oneself on the chain (the issuance's
 * inviter key).
 */
function ensureCanIssue(input: {
  readonly verified: VerifiedProject;
  readonly sessionUserId: string;
  readonly role: InviteRole;
  readonly scope: MemberScope;
  readonly masterKeys: MasterKeys;
}): Effect.Effect<ChainMember, CliError> {
  return Effect.gen(function* () {
    const inviter = input.verified.state.members.get(input.sessionUserId);
    if (inviter === undefined) {
      return yield* Effect.fail(
        cliError("Only admins and above can issue invites (AUTH_SPEC §15-2)"),
      );
    }
    // The local key must be one of the inviter's device keys (2026-09-19
    // DK — the signer is per device). Only once the device is resolved is
    // the effective permission defined (person ∩ device cap — §6.2), so
    // the permission check runs afterwards (issuing from a cap-narrowed
    // device would create a trap on both sides of the ceremony where the
    // post-acceptance add_member falls to consensus — do not issue)
    const device = ownDeviceByKeys(
      inviter,
      input.masterKeys.record.encPubHex,
      input.masterKeys.record.sigPubHex,
    );
    if (device === undefined) {
      return yield* Effect.fail(
        cliError(
          "This machine's key is not one of your registered devices on this project's chain, so an issue signature made here would not verify. Issue the invite from a device that is registered here (`maruhi device list` shows them) or have an owner re-add you",
        ),
      );
    }
    const permission = effectivePermissionOf(inviter, device);
    if (ROLE_RANK[permission.role] < ROLE_RANK.admin) {
      return yield* Effect.fail(
        cliError("Only admins and above can issue invites (AUTH_SPEC §15-2)"),
      );
    }
    if (input.role === "admin" && permission.role !== "owner") {
      return yield* Effect.fail(
        cliError(
          "Only an owner can issue a role=admin invite (same level as the add_member permission table in CRYPTO_SPEC §6.2)",
        ),
      );
    }
    // scope (2026-09-15 ES K4 — design record K4-G): check before
    // communicating that every `--env` id exists on the chain
    // (`unknown-environment`) and that the effective scope contains the
    // invite's scope (`scope-not-contained` — principle 1: the
    // environment set whose permission add_member changes = the new
    // scope). The server does not check (AUTH_SPEC §15-2), but even if it
    // passed, the post-acceptance add_member would fall to a consensus
    // rule = a trap sending the invitee through the ceremony for nothing,
    // so do not issue (no escape hatch is kept — ask an all-scope admin /
    // owner instead)
    yield* requireScopeEnvironmentsExist(input.verified, input.scope);
    if (!scopeContains(permission.scope, input.scope)) {
      return yield* Effect.fail(
        cliError(
          `Your environment scope (${describeScope(permission.scope)}) does not contain the invite's scope (${describeScope(input.scope)}), so the add_member after acceptance would be rejected (CRYPTO_SPEC §6.2 scope-not-contained). Invite only environments in your own scope, or ask an owner / all-scope admin to issue this invite`,
        ),
      );
    }
    return inviter;
  });
}

/** The issuance's material (id, seed, link public key) and the issue signature. */
interface SignedIssuance {
  readonly inviteId: string;
  readonly seed: Uint8Array;
  readonly linkPubHex: string;
  readonly issueSignatureHex: string;
}

/** Assign the id → generate the seed → derive the link key → issue signature (CRYPTO_SPEC §6.5). */
function signIssuance(input: {
  readonly verified: VerifiedProject;
  readonly inviter: ChainMember;
  /** The inviter's signing device (its keys — the local master-key record — go into the issuance). */
  readonly inviterKeys: { readonly encPubHex: string; readonly sigPubHex: string };
  readonly role: InviteRole;
  readonly scope: ScopePayloadFields;
  readonly signingKey: MasterKeys["sigKeyPair"]["privateKey"];
}): Effect.Effect<SignedIssuance, CliError> {
  return Effect.gen(function* () {
    const inviteId = ulid();
    const seed = generateInviteLinkSeed();
    const linkKey = yield* Effect.tryPromise({
      try: () => deriveInviteLinkKeyPair(seed),
      catch: () => cliError("Failed to derive the invite link key (crypto error)"),
    });
    if (!linkKey.ok) {
      return yield* Effect.fail(cliError("Failed to derive the invite link key"));
    }
    const linkPubHex = encodeHex(linkKey.value.publicKeyRaw);
    const signed = yield* Effect.tryPromise({
      try: () =>
        signInviteIssue({
          context: {
            suite: SUITE_ID,
            inviteId,
            projectId: input.verified.projectId,
            linkPubHex,
            headHashHex: input.verified.state.headHashHex,
            headSeq: input.verified.state.headSeq,
            role: input.role,
            inviterUserId: input.inviter.userId,
            inviterEncPubHex: input.inviterKeys.encPubHex,
            inviterSigPubHex: input.inviterKeys.sigPubHex,
            scopeKind: input.scope.scopeKind,
            scopeEnvironmentIds: input.scope.scopeEnvironmentIds,
          },
          signingKey: input.signingKey,
        }),
      catch: () => cliError("Failed to create the issue signature (crypto error)"),
    });
    if (!signed.ok) {
      return yield* Effect.fail(cliError("Failed to create the issue signature"));
    }
    return { inviteId, seed, linkPubHex, issueSignatureHex: signed.value };
  });
}

/** The post-issuance guidance (the link to stdout, explanations to stderr). */
function reportIssued(input: {
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

/**
 * Issuing an invite + issue signature + link assembly + saving the
 * issuance pin. Issuance authorization is enforced by the server, but
 * role rules are dropped locally before communicating (for clear
 * wording).
 */
export function inviteCreateOp(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly origin: string;
  readonly role: InviteRole;
  /** The scope to grant (`--env` repetition → listed, omitted = all — AUTH_SPEC §15-3 / design record ruling K). */
  readonly scope: MemberScope;
  readonly sessionUserId: string;
  readonly masterKeys: MasterKeys;
  /** The addressee's GitHub login (`--github` — the backing source's check target. Kept only on the issuance pin). */
  readonly expectedGithubLogin: string | null;
  /** One's own GitHub login (the link's `il=` — material for the invitee-side backing check). */
  readonly inviterLogin: string | null;
}): Effect.Effect<InviteCreateSummary, CliError, CliIo | PinStore | Stdio.Stdio> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const pinStore = yield* PinStore;
    // An invite link's seed is displayed as the link (that is the
    // function), but under an AI agent environment display = persisting
    // into the transcript, a path leaking to a third party (the agent
    // platform, logs) before it is handed over a person-to-person
    // channel. Since a seed cannot be re-displayed, "issue without
    // displaying" is not an option — issuance itself is refused
    yield* ensureInviteLinkDisplayAllowed(io);
    const inviter = yield* ensureCanIssue(input);
    // The same scope goes onto all four places: the issuance, the issue
    // body, the link, and the issuance pin (2026-09-15 ES K4 — `--env`
    // repetition = listed, omitted = all. Generated ascending with no
    // duplicates — scope.ts)
    const scope: ScopePayloadFields = scopePayloadFieldsOf(input.scope);
    // The issuing device = the local key (ensureCanIssue already checked it is one of the inviter's device keys)
    const inviterKeys = {
      encPubHex: input.masterKeys.record.encPubHex,
      sigPubHex: input.masterKeys.record.sigPubHex,
    };
    const signed = yield* signIssuance({
      verified: input.verified,
      inviter,
      inviterKeys,
      role: input.role,
      scope,
      signingKey: input.masterKeys.sigKeyPair.privateKey,
    });
    const headHashHex = input.verified.state.headHashHex;
    const headSeq = input.verified.state.headSeq;
    const issued = yield* input.client.invites
      .issue({
        params: { projectId: input.verified.projectId },
        payload: {
          id: signed.inviteId,
          role: input.role,
          scopeKind: scope.scopeKind,
          scopeEnvironmentIds: scope.scopeEnvironmentIds,
          linkPubHex: signed.linkPubHex,
          headHashHex,
          headSeq,
          issueSignatureHex: signed.issueSignatureHex,
        },
      })
      .pipe(Effect.mapError(issueErrorToCliError));
    const link = buildInviteLink({
      origin: input.origin,
      link: {
        inviteId: signed.inviteId,
        linkSeedHex: Redacted.make(encodeHex(signed.seed), { label: "invite-link-seed" }),
        projectId: input.verified.projectId,
        headHashHex,
        headSeq,
        inviterUserId: inviter.userId,
        inviterEncPubHex: inviterKeys.encPubHex,
        inviterSigPubHex: inviterKeys.sigPubHex,
        role: input.role,
        scopeKind: scope.scopeKind,
        scopeEnvironmentIds: scope.scopeEnvironmentIds,
        inviterLogin: input.inviterLogin,
        issueSignatureHex: signed.issueSignatureHex,
      },
    });
    // The issuance pin (SHOULD): extra material cross-checked at member
    // add against the server's claimed row (link_pub / role) + retaining
    // the addressee login (pins.ts). The seed is not saved. A save
    // failure does not fail an already-established issuance (the link can
    // be shown only once)
    yield* pinStore
      .saveIssuedPin(input.verified.projectId, signed.inviteId, {
        linkPubHex: signed.linkPubHex,
        role: input.role,
        scopeKind: scope.scopeKind,
        scopeEnvironmentIds: scope.scopeEnvironmentIds,
        expiresAtMs: issued.expiresAtMs,
        expectedGithubLogin: input.expectedGithubLogin,
      })
      .pipe(
        Effect.catch((error) =>
          logWarning(
            `could not save the issuance pin (${error.message}). member add still verifies your issue signature on the server's row; only the extra pin cross-check and the addressee login are lost`,
          ),
        ),
      );
    yield* reportIssued({
      link,
      inviteId: signed.inviteId,
      role: input.role,
      scope: input.scope,
      expiresAtMs: issued.expiresAtMs,
      expectedGithubLogin: input.expectedGithubLogin,
    });
    return { id: signed.inviteId, link, role: input.role, expiresAtMs: issued.expiresAtMs };
  });
}

// createdAtMs / expiresAtMs are the server's declared, unbounded numbers
// (B4): display them via the total shared formatter so a value outside
// the Date range cannot become a defect (RangeError) (never let invite
// create / list end in an untyped crash)
const formatDateTimeUtc = formatUtcMinutes;

// ---------------------------------------------------------------------------
// invite accept
// ---------------------------------------------------------------------------

export interface InviteAcceptSummary {
  readonly projectId: string;
  readonly role: InviteRole;
}

/** The inviter FP (derived from `ie` ‖ `is` per §3). */
function inviterFingerprintOf(link: InviteLinkData): Effect.Effect<string, CliError> {
  return Effect.gen(function* () {
    const enc = decodeHex(link.inviterEncPubHex);
    const sig = decodeHex(link.inviterSigPubHex);
    if (enc === null || sig === null) {
      return yield* Effect.fail(cliError("The link's inviter keys (ie= / is=) are malformed"));
    }
    const fingerprint = yield* Effect.tryPromise({
      try: () => computeUserKeyFingerprint(enc, sig),
      catch: () => cliError("Failed to compute the inviter's key fingerprint (crypto error)"),
    });
    if (!fingerprint.ok) {
      return yield* Effect.fail(cliError("The link's inviter keys (ie= / is=) are malformed"));
    }
    return encodeHex(fingerprint.value);
  });
}

/** Deriving the link key (seed → key pair + public key hex). */
function resolveLinkKey(link: InviteLinkData) {
  return Effect.gen(function* () {
    // Reason for unwrapping: key derivation needs the byte string itself.
    // The seed is consumed here; from here on only the CryptoKey
    // (non-extractable) and the public key flow
    const seed = decodeHex(Redacted.value(link.linkSeedHex));
    if (seed === null) {
      return yield* Effect.fail(cliError("The link's key seed (k=) is malformed"));
    }
    const derived = yield* Effect.tryPromise({
      try: () => deriveInviteLinkKeyPair(seed),
      catch: () => cliError("Failed to derive the invite link key (crypto error)"),
    });
    if (!derived.ok) {
      return yield* Effect.fail(cliError("Failed to derive the invite link key"));
    }
    return { keyPair: derived.value, linkPubHex: encodeHex(derived.value.publicKeyRaw) };
  });
}

/**
 * Verifying the issue signature (CRYPTO_SPEC §6.5 — the invitee-side
 * first check). Failure = do not accept (never overridden by the
 * out-of-band check): either tampering on the link's path or a third
 * party's link ghost-added with the inviter's public key. link_pub uses
 * the value derived from the seed (the link is not carried).
 */
function verifyLinkIssuanceWith(
  link: InviteLinkData,
  linkPubHex: string,
): Effect.Effect<void, CliError> {
  return Effect.gen(function* () {
    const verified = yield* Effect.tryPromise({
      try: () =>
        verifyInviteIssueSignature({
          context: {
            suite: SUITE_ID,
            inviteId: link.inviteId,
            projectId: link.projectId,
            linkPubHex,
            headHashHex: link.headHashHex,
            headSeq: link.headSeq,
            role: link.role,
            inviterUserId: link.inviterUserId,
            inviterEncPubHex: link.inviterEncPubHex,
            inviterSigPubHex: link.inviterSigPubHex,
            scopeKind: link.scopeKind,
            scopeEnvironmentIds: link.scopeEnvironmentIds,
          },
          signatureHex: link.issueSignatureHex,
        }),
      catch: () => cliError("Failed to verify the link's issue signature (crypto error)"),
    });
    if (!verified.ok) {
      return yield* Effect.fail(
        cliError(
          "The invite link's issue signature does not verify under the inviter key it names (CRYPTO_SPEC §6.5). The link was altered in transit, or it was not issued by the holder of that key — do not accept it; ask the inviter to reissue over a trusted channel",
        ),
      );
    }
  });
}

/**
 * The invitee-side mutual confirmation (§6.5): display the inviter key's
 * FP words from the link and require an explicit confirmation of the
 * out-of-band check. A mechanical check against the chain is
 * **impossible** at acceptance time (a non-member's chain GET is a flat
 * 404 — AUTH_SPEC §11-2), so it happens at the first sync after
 * add_member (context.ts's anchor check).
 *
 * - `--inviter-fingerprint <hex>`: mechanically compares the inviter FP
 *   noted out of band against the link's key (non-interactive explicit
 *   confirmation + second-path detection of link tampering)
 * - Interactive: shows the 12 words and requires re-typing the last word
 *   (the same ceremony as server-grant)
 * - An agent environment refuses to perform the flagless ceremony on
 *   one's behalf (even on a ledger hit)
 * - The verified-fingerprint ledger (KF — known-fingerprints.ts): when an
 *   inviter (origin × user_id) previously confirmed out of band matches
 *   the fingerprint, re-running the 12-word out-of-band read-out is
 *   waived. **The explicit confirmation of the acceptance itself (typing
 *   yes) is still required on a hit**. The ledger is usable only when
 *   stdin / stdout are interactive terminals (ADR-0016 decision 7's
 *   first boundary)
 */
function confirmInviterFingerprint(input: {
  readonly origin: string;
  readonly link: InviteLinkData;
  readonly inviterFingerprintHex: string;
  readonly expectInviterFingerprintHex: string | null;
}): Effect.Effect<void, CliError, CliIo | FingerprintBook | Stdio.Stdio> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const words = yield* fingerprintWords(
      input.inviterFingerprintHex,
      "The link's inviter fingerprint is malformed",
    );
    const book = yield* consultFingerprintBook({
      origin: input.origin,
      userId: input.link.inviterUserId,
      fingerprintHex: input.inviterFingerprintHex,
    });
    // A ledger hit is usable only on the path of interactive terminals +
    // no flag + non-agent (the decision is usableBookHit). In that case
    // the two instruction lines for the read-out check are dropped
    const hit = yield* usableBookHit({
      book,
      flagProvided: input.expectInviterFingerprintHex !== null,
      isAgent: io.agentProfile().isAgent,
    });
    const lines = [
      "Inviter's key fingerprint (from ie= / is= in the link — mutual confirmation, CRYPTO_SPEC §6.5):",
      `  inviter: ${displayText(input.link.inviterUserId)}`,
      `  hex:  ${input.inviterFingerprintHex}`,
      "  word: " + formatWordList(words),
      ...(hit !== null
        ? []
        : [
            "Check that this word list matches the 12 words the inviter reads to you out of band (e.g. over a call).",
            "If they do not match, the link has been swapped (luring you into an attacker's project = reverse phishing) — abort the acceptance.",
          ]),
    ];
    for (const line of lines) {
      yield* io.log(line);
    }
    if (input.expectInviterFingerprintHex !== null) {
      if (input.expectInviterFingerprintHex !== input.inviterFingerprintHex) {
        return yield* Effect.fail(
          cliError(
            "--inviter-fingerprint does not match the inviter fingerprint derived from the link (ie= / is=). The link may have been tampered with — the acceptance was aborted (ask the inviter to reissue)",
          ),
        );
      }
      yield* io.log(
        "--inviter-fingerprint matches (continuing; the out-of-band record counts as checked)",
      );
      yield* book.record;
      return;
    }
    yield* book.warnIfChanged;
    // Do not let the ceremony be performed by an AI agent environment
    // (the same posture as server-grant. A ledger hit is not grounds for
    // acting on one's behalf either — only an explicit flag is the
    // non-interactive path)
    if (io.agentProfile().isAgent) {
      return yield* Effect.fail(
        cliError(
          "Refused to run the inviter-fingerprint confirmation ceremony: an AI agent environment was detected. Run this yourself in a terminal, or pass the inviter fingerprint noted out of band via --inviter-fingerprint",
        ),
      );
    }
    if (hit !== null) {
      return yield* confirmKnownFingerprint({
        entry: hit,
        filePath: book.filePath,
        prompt: `Type yes to accept this invite attributed to ${displayText(input.link.inviterUserId)} for project ${displayText(input.link.projectId)}`,
        cancelText: "The acceptance was cancelled.",
      });
    }
    yield* confirmByLastWord({
      words,
      promptText:
        "Once you have checked against the inviter's out-of-band read-out (e.g. a call), type the last of the 12 words shown above",
      mismatchText: "That does not match. Type the last word of the list shown above",
      exhaustedText:
        "Inviter fingerprint confirmation failed (the re-typed word does not match). The acceptance was not performed — re-run once you can check with the inviter",
    });
    yield* book.record;
  });
}

/**
 * Preparing the master key (§15-3's "key generation [when absent]" — B1b
 * ruling A′'s 3 guards): (1) never generated under an agent environment,
 * (2) recovery already registered = an existing key on another device →
 * steer to `key recover` (prevents the accident of overwriting the old
 * key's recovery registration), (3) explicit interactive confirmation →
 * run the existing keyGenerateOp (generation → recovery-code ceremony)
 * as-is. If interrupted after generating, a re-run detects the existing
 * key and resumes at acceptance (idempotent restart).
 */
function ensureMasterKeysForAccept(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly keyGenerate: Effect.Effect<void, CliError, CliServices>;
}): Effect.Effect<
  { readonly keys: MasterKeys; readonly generated: boolean },
  CliError,
  CliServices
> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const keychain = yield* Keychain;
    const stored = yield* keychain.get(
      masterKeyEntryName(input.session.origin, input.session.userId),
    );
    if (stored !== null) {
      return { keys: yield* loadMasterKeys(input.session), generated: false };
    }
    if (io.agentProfile().isAgent) {
      return yield* Effect.fail(
        cliError(
          "No device key is present. Key generation is not performed in AI agent environments (issuing and storing the recovery code needs a human interactive terminal). Accept on a human terminal, or give this machine a key first — `maruhi device add` (approved from a device you have) or, if no device is left, `maruhi key recover` — and re-run",
        ),
      );
    }
    const status = yield* input.client.auth.recoveryStatus({}).pipe(Effect.mapError(toCliError));
    if (status.registered) {
      return yield* Effect.fail(
        cliError(
          "This machine has no device key, but your account already has a recovery ledger (a key was generated on another device). Creating a new key would start a second identity — add this machine as a device instead (`maruhi device add` here, `maruhi device approve` on a device you have), or `maruhi key recover` if no device of yours is left, then re-run (only if every device and every way to open the ledger are lost, rebuild with `maruhi key generate --new-identity`)",
        ),
      );
    }
    yield* io.log(
      "This machine has no device key. A new key (= a new cryptographic identity) will be generated before proceeding to accept",
    );
    yield* io.log(
      "If you already use maruhi on another device, stop here: add this machine as a device instead (`maruhi device add` here, then `maruhi device approve` on the other device) and re-run",
    );
    const answer = yield* io.promptLine({
      prompt: "Type yes to generate a new key: ",
    });
    if (answer.trim().toLowerCase() !== "yes") {
      return yield* Effect.fail(
        cliError(
          "Key generation was cancelled (the acceptance was not performed). Re-run when ready",
        ),
      );
    }
    yield* input.keyGenerate;
    return { keys: yield* loadMasterKeys(input.session), generated: true };
  });
}

/**
 * The invitee-side sufficiency form 4 (CRYPTO_SPEC §6.5 — IV2): when the
 * backing source confirms "the inviter's sig key (`is`) is a signing key
 * of the login (`il`) the link names", the 12-word read-out is unneeded
 * and **the invitee's declaration that they "were expecting an invite
 * from that login"** satisfies it (non-interactive: a `--from` match /
 * interactive: a yes naming the login). A check that is **impossible**
 * (backing `none`, no `il`, unregistered, unfetchable) is false = fall
 * back to sufficiency forms 1–3 (confirmInviterFingerprint). Only a
 * `--from` / `il` mismatch is **refused** (the shape of a valid link for
 * someone else, swapped in along the path).
 */
function confirmInviterViaBacking(input: {
  readonly link: InviteLinkData;
  readonly identityBacking: IdentityBacking;
  readonly expectedFromLogin: string | null;
}): Effect.Effect<boolean, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const { link } = input;
    if (input.identityBacking === "none") {
      if (input.expectedFromLogin !== null) {
        yield* logNote(
          "identityBacking is none, so --from cannot be checked against github.com — falling back to the inviter fingerprint confirmation",
        );
      }
      return false;
    }
    if (link.inviterLogin === null) {
      if (input.expectedFromLogin !== null) {
        yield* logNote(
          "the link does not name the inviter's GitHub login (il=), so --from cannot be checked — falling back to the inviter fingerprint confirmation",
        );
      }
      return false;
    }
    if (
      input.expectedFromLogin !== null &&
      input.expectedFromLogin.toLowerCase() !== link.inviterLogin.toLowerCase()
    ) {
      return yield* Effect.fail(
        cliError(
          `The link names github.com/${link.inviterLogin} as the inviter, but --from expects ${input.expectedFromLogin}. The link may have been swapped for another project's valid link — the acceptance was aborted (check with the person who sent it)`,
        ),
      );
    }
    const verdict = yield* checkSigningKeyBacking({
      login: link.inviterLogin,
      sigPubHex: link.inviterSigPubHex,
    });
    if (verdict.kind !== "match") {
      yield* logNote(
        `${describeBackingFallback(link.inviterLogin, verdict)} — falling back to the inviter fingerprint confirmation`,
      );
      return false;
    }
    yield* io.log(
      `Inviter key verified: the link's inviter signing key (is=) is registered as a signing key on github.com/${link.inviterLogin} (CRYPTO_SPEC §6.5)`,
    );
    if (input.expectedFromLogin !== null) {
      yield* io.log(
        "--from matches the link's inviter login (continuing without the 12-word call)",
      );
      return true;
    }
    return yield* confirmExpectedInviter(link, link.inviterLogin);
  });
}

/**
 * Sufficiency form 4's "was expecting it" declaration (interactive): a
 * yes naming the login. Non-interactive only the flag (`--from`) is the
 * path — an agent environment is refused, a non-terminal falls back to
 * the ceremony.
 */
function confirmExpectedInviter(
  link: InviteLinkData,
  inviterLogin: string,
): Effect.Effect<boolean, CliError, CliIo | Stdio.Stdio> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    if (io.agentProfile().isAgent) {
      return yield* Effect.fail(
        cliError(
          `Refused to confirm the invite on your behalf: an AI agent environment was detected. Re-run with --from ${inviterLogin} if you expect this invite from that GitHub account, or accept on a human terminal`,
        ),
      );
    }
    const stdio = yield* Stdio.Stdio;
    if (!(yield* stdio.stdinIsTerminal) || !(yield* stdio.stdoutIsTerminal)) {
      yield* logNote(
        `stdin or stdout is not an interactive terminal — pass --from ${inviterLogin} to accept non-interactively; falling back to the inviter fingerprint confirmation`,
      );
      return false;
    }
    const answer = yield* io.promptLine({
      prompt: `Type yes to accept this invite from github.com/${inviterLogin} (project ${displayText(link.projectId)}, role ${link.role}, scope ${describeScope(link)}): `,
    });
    if (answer.trim().toLowerCase() !== "yes") {
      return yield* Effect.fail(
        cliError(
          "The acceptance was cancelled. If you did not expect an invite from that GitHub account, tell the person who sent you the link",
        ),
      );
    }
    return true;
  });
}

export function inviteAcceptOp(input: {
  readonly client: MaruhiClient;
  readonly session: CliSession;
  readonly link: InviteLinkData;
  readonly expectInviterFingerprintHex: string | null;
  /** `--from <login>` (the non-interactive declaration of sufficiency form 4 via the backing source). */
  readonly expectedFromLogin: string | null;
  readonly identityBacking: IdentityBacking;
  /** keyGenerateOp itself (generation → recovery ceremony) (wired by cli.ts). */
  readonly keyGenerate: Effect.Effect<void, CliError, CliServices>;
}): Effect.Effect<InviteAcceptSummary, CliError, CliServices> {
  return Effect.gen(function* () {
    const { link } = input;
    // §15-3's order: verify the issue signature (mechanical) → mutual
    // confirmation (sufficiency form 4 → 1–3) → key generation [when
    // absent] → joint signature → accept → pin the anchor (only after
    // the acceptance is established)
    const linkKey = yield* resolveLinkKey(link);
    yield* verifyLinkIssuanceWith(link, linkKey.linkPubHex);
    const inviterFingerprintHex = yield* inviterFingerprintOf(link);
    const backed = yield* confirmInviterViaBacking({
      link,
      identityBacking: input.identityBacking,
      expectedFromLogin: input.expectedFromLogin,
    });
    if (!backed) {
      yield* confirmInviterFingerprint({
        origin: input.session.origin,
        link,
        inviterFingerprintHex,
        expectInviterFingerprintHex: input.expectInviterFingerprintHex,
      });
    }

    const { keys: masterKeys, generated } = yield* ensureMasterKeysForAccept({
      session: input.session,
      client: input.client,
      keyGenerate: input.keyGenerate,
    });

    const context: InviteAcceptSignatureContext = {
      suite: SUITE_ID,
      projectId: link.projectId,
      linkPubHex: linkKey.linkPubHex,
      inviteeUserId: input.session.userId,
      inviteeEncPubHex: masterKeys.record.encPubHex,
      inviteeSigPubHex: masterKeys.record.sigPubHex,
    };
    const signature = yield* Effect.tryPromise({
      try: () => signInviteAccept({ context, signingKey: masterKeys.sigKeyPair.privateKey }),
      catch: () => cliError("Failed to create the acceptance signature (crypto error)"),
    });
    const linkSignature = yield* Effect.tryPromise({
      try: () => signInviteLink({ context, linkPrivateKey: linkKey.keyPair.privateKey }),
      catch: () => cliError("Failed to create the link signature (crypto error)"),
    });
    if (!signature.ok || !linkSignature.ok) {
      return yield* Effect.fail(cliError("Failed to create the acceptance signatures"));
    }

    const accepted = yield* input.client.invites
      .accept({
        payload: {
          linkPubHex: linkKey.linkPubHex,
          encPubHex: masterKeys.record.encPubHex,
          sigPubHex: masterKeys.record.sigPubHex,
          acceptSignatureHex: signature.value,
          linkSignatureHex: linkSignature.value,
        },
      })
      .pipe(Effect.mapError(acceptErrorToCliError));

    // Reconciling the link (issue-signed) with the server's response: a
    // p / r mismatch is a response that should not have passed signature
    // verification = the server contradicting itself or a swapped row →
    // refuse
    if (accepted.projectId !== link.projectId) {
      return yield* Effect.fail(
        cliError(
          "The acceptance response's project ID does not match what the acceptance signature was bound to (the server's response contradicts itself). Do not trust this acceptance",
        ),
      );
    }
    if (accepted.role !== link.role) {
      return yield* Effect.fail(
        cliError(
          `The role declared in the signed link (${link.role}) does not match the role the server reports (${accepted.role}). The server's row contradicts the inviter's issue signature — do not trust this acceptance; ask the inviter to check \`maruhi invite list\``,
        ),
      );
    }
    // scope (2026-09-14 ES) is also covered by the issue signature: a
    // response scope disagreeing with the signed link is likewise the
    // server contradicting itself → refuse (AUTH_SPEC §15-3)
    if (!sameScope(accepted, link)) {
      return yield* Effect.fail(
        cliError(
          `The scope declared in the signed link (${describeScope(link)}) does not match the scope the server reports (${describeScope(accepted)}). The server's row contradicts the inviter's issue signature — do not trust this acceptance; ask the inviter to check \`maruhi invite list\``,
        ),
      );
    }

    // The anchor pin comes after the acceptance is established (+ reconciled) (see pinAnchorAfterAccept)
    const anchored = yield* pinAnchorAfterAccept(link, inviterFingerprintHex);

    yield* reportAcceptOutcome({
      accepted,
      fingerprintHex: masterKeys.fingerprintHex,
      anchored,
      identityBacking: input.identityBacking,
    });
    // The registration path (supplement 21, ruling G ⑥ (b)): when a key
    // was born inside this acceptance, offer GitHub registration here so
    // the inviter can add them ceremony-free
    if (generated && input.identityBacking !== "none") {
      yield* offerGithubRegistration({ session: input.session });
    }
    return { projectId: accepted.projectId, role: accepted.role };
  });
}

/**
 * Pinning the anchor after the acceptance is established (§6.3 (a)).
 * **An existing anchor already machine-checked (verifiedAtSeq ≠ null) is
 * never overwritten**: the chain is append-only so a verified anchor's
 * containment check keeps holding forever (old but harmless, detection
 * power equal), there is no gain in replacing it, and leaving no
 * overwrite path at all narrows the attack surface (a verified track
 * record wins over a re-invite's fresh anchor). An unchecked anchor is
 * replaced by the latest acceptance (the last legitimate acceptance
 * wins).
 *
 * Return = whether a valid anchor exists (saved successfully or the
 * verified one kept).
 */
function pinAnchorAfterAccept(
  link: InviteLinkData,
  inviterFingerprintHex: string,
): Effect.Effect<boolean, CliError, CliIo | PinStore> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const pinStore = yield* PinStore;
    // By the time we get here the acceptance is established server-side.
    // The pin is SHOULD-level local defense, so a pinning failure does
    // not fail the acceptance — the link is already consumed and
    // "re-running" can only become 410 (accepted). A corrupt file is left
    // un-overwritten (pins.ts's merge discipline) while warning to make
    // the degradation explicit
    const loaded = yield* pinStore
      .load(link.projectId)
      .pipe(
        Effect.catch((error) =>
          Effect.succeed({ pins: null, state: "error", detail: error.message } as const),
        ),
      );
    if (loaded.state === "error") {
      yield* warnUnpinned(loaded.detail);
      return false;
    }
    if (loaded.state === "corrupt") {
      yield* warnUnpinned(
        "the existing pin file is corrupt — inspect it, and delete it if the change was not intentional",
      );
      return false;
    }
    const existing = loaded.pins?.anchor ?? null;
    if (existing !== null && existing.verifiedAtSeq !== null) {
      yield* io.log(
        "This project already has a machine-verified invite link anchor — keeping the existing anchor (verified anchors are never overwritten)",
      );
      return true;
    }
    if (existing !== null) {
      // Replacing an unchecked anchor also happens on a legitimate
      // re-invite, but with zero trace a substitution by a fake link (a
      // DoS path) would be unauditable — surface it in one line
      yield* io.log(
        "Replacing the unverified existing anchor with this acceptance's link anchor (the latest legitimate acceptance wins)",
      );
    }
    return yield* pinStore
      .saveAnchor(link.projectId, {
        headSeq: link.headSeq,
        headHashHex: link.headHashHex,
        inviterUserId: link.inviterUserId,
        inviterKeyFingerprintHex: inviterFingerprintHex,
        inviterSigPubHex: link.inviterSigPubHex,
        verifiedAtSeq: null,
      })
      .pipe(
        Effect.map(() => true),
        Effect.catch((error) => warnUnpinned(error.message).pipe(Effect.map(() => false))),
      );
  });
}

/** The display after the acceptance is established (one's own FP words = the read-out material for the inviter + the next-step guidance). */
function reportAcceptOutcome(input: {
  readonly accepted: InviteAcceptSummary;
  readonly fingerprintHex: string;
  readonly anchored: boolean;
  readonly identityBacking: IdentityBacking;
}): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* io.log(
      `Accepted the invite (project=${input.accepted.projectId}, role=${input.accepted.role})`,
    );
    const ownWords = yield* fingerprintWords(
      input.fingerprintHex,
      "The key fingerprint is malformed",
    );
    yield* io.log("Your key fingerprint (the inviter checks this at member add):");
    yield* io.log(`  hex:  ${input.fingerprintHex}`);
    yield* io.log("  word: " + formatWordList(ownWords));
    // The completion display (supplement 21, ruling G ⑥ (a)): when a
    // backing source exists, "register" is the primary path and the
    // 12-word read-out is its fallback
    yield* io.log(
      input.identityBacking === "none"
        ? "Your acceptance is bound to the invite link. Read these 12 words to the inviter out of band (e.g. over a call) (§6.5 mutual confirmation. To show them again later, run `maruhi key show`)"
        : "Your acceptance is bound to the invite link. Register this key on GitHub as a signing key with `maruhi key publish` so the inviter can add you without a call; otherwise read these 12 words to them out of band (e.g. over a call) (§6.5 mutual confirmation. To show them again later, run `maruhi key show`)",
    );
    yield* io.log(
      input.anchored
        ? "Your membership becomes final once the inviter completes member add. On the first sync after joining, the link anchor (genesis, head, inviter key) is machine-checked automatically"
        : "Your membership becomes final once the inviter completes member add (no anchor was pinned, so the first-sync machine check will not run — the out-of-band ceremony is the only defense)",
    );
  });
}

/** Translating 410's reason code into an operational procedure. */
function goneErrorToCliError(error: InviteGoneError): CliError {
  switch (error.reason) {
    case "accepted":
    case "completed":
      return cliError(
        "This invite has already been accepted. If that acceptance was not yours, the link may have been intercepted — contact the inviter and ask them to revoke this invite (`maruhi invite revoke`) and reissue (single use surfaces collisions — CRYPTO_SPEC §6.5)",
      );
    case "revoked":
      return cliError("This invite has been revoked. Ask the inviter to reissue");
    case "expired":
      return cliError("This invite has expired. Ask the inviter to reissue");
    default:
      return cliError("This invite is not usable. Ask the inviter to reissue");
  }
}

/** The acceptance-error wording map (translates reason codes into operational procedures). */
function acceptErrorToCliError(error: unknown): CliError {
  if (error instanceof InviteNotFoundError) {
    return cliError(
      "The server does not know this invite link's key. Check that the link (including everything after #) was copied completely, or ask the inviter whether it was issued against this server",
    );
  }
  if (error instanceof InviteGoneError) {
    return goneErrorToCliError(error);
  }
  if (error instanceof InviteSignatureInvalidError) {
    return error.which === "link"
      ? cliError(
          "The link signature was rejected by server verification. The link's key (k=) does not match the invite the server holds — the link is broken or was tampered with; ask the inviter to reissue",
        )
      : cliError(
          "The acceptance signature was rejected by server verification. The link's p (project ID) was tampered with, or the link is broken — ask the inviter to reissue the link",
        );
  }
  if (error instanceof ForbiddenError) {
    return cliError(
      "These credentials cannot accept the invite. Acceptance needs an all-project-scope (*) × admin token (AUTH_SPEC §15-2 — scope-limited tokens and web sessions are not allowed). Sign in again with `maruhi login`",
    );
  }
  return toCliError(error);
}

// ---------------------------------------------------------------------------
// invite list / revoke
// ---------------------------------------------------------------------------

export interface InviteListSummary {
  readonly rows: number;
  /** The count of signature-verification failures and issuance-pin mismatches (exit 1 when > 0). */
  readonly integrityFailures: number;
}

/** The displayed status (pending past its expiry shows as expired — derived from the stored state). */
function displayStatus(row: InvitationRow, nowMs: number): string {
  return row.status === "pending" && row.expiresAtMs <= nowMs ? "expired" : row.status;
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

/** Verifying and displaying one listing row (returns the integrity-failure count). */
function listRowChecks(input: {
  readonly verified: VerifiedProject;
  readonly pins: InvitePins | null;
  readonly row: InvitationRow;
  readonly nowMs: number;
}): Effect.Effect<number, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const { row } = input;
    let failures = 0;
    yield* io.log(
      `${displayText(row.id)}\t${displayStatus(row, input.nowMs)}\trole=${row.role}\tscope=${describeScope(row)}\tissued=${formatDateTimeUtc(row.createdAtMs)}\texpires=${formatDateTimeUtc(row.expiresAtMs)}`,
    );
    const issuance = yield* verifyIssuance({ verified: input.verified, row });
    if (!issuance.ok) {
      failures += 1;
      yield* logWarning(`invite ${displayText(row.id)} ${issuanceFailureText(issuance.reason)}`);
      return failures;
    }
    yield* io.log("  issuance: signature verified against the inviter's chain key");
    const pin = pinMismatchOf(input.pins, row);
    if (pin === "mismatch") {
      failures += 1;
      yield* logWarning(
        `the server's claim for invite ${displayText(row.id)} (link key / role) does not match the local record from issuance. The row may have been swapped or the role tampered with — do not run member add with this invite`,
      );
    }
    // Do not give "checked and passed" and "no check material" the same
    // look (S12 — on a row missing §6.5's extra material, only the issue
    // signature pins it)
    if (pin === "missing") {
      yield* io.log(
        "  issuance pin: none on this machine (this invite may have been issued on another device) — the link key / role / scope cross-check was not performed",
      );
    }
    if (row.acceptance !== null) {
      const verified = yield* verifyAcceptanceBlock({
        projectId: input.verified.projectId,
        issuance: row.issuance,
        acceptance: row.acceptance,
      });
      if (!verified.ok) {
        failures += 1;
        yield* logWarning(
          `for invite ${displayText(row.id)}, ${acceptanceFailureText(verified.which)}. This acceptance block cannot be trusted — do not run member add; revoke the invite`,
        );
        return failures;
      }
      const words = yield* fingerprintWords(
        verified.fingerprintHex,
        "The acceptance key's fingerprint is malformed",
      );
      yield* io.log(
        `  accepted: ${displayText(row.acceptance.inviteeUserId)} (acceptance and link signatures verified)`,
      );
      yield* io.log(`  fp:   ${verified.fingerprintHex}`);
      yield* io.log("  word: " + formatWordList(words));
    }
    return failures;
  });
}

export function inviteListOp(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly pins: InvitePins | null;
  readonly nowMs: number;
}): Effect.Effect<InviteListSummary, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const listed = yield* listInvitations(input.client, input.verified.projectId);
    const rows = [...listed].toSorted((a, b) => a.createdAtMs - b.createdAtMs);
    let integrityFailures = 0;
    if (rows.length === 0) {
      yield* io.log("No invites");
      return { rows: 0, integrityFailures };
    }
    for (const row of rows) {
      integrityFailures += yield* listRowChecks({
        verified: input.verified,
        pins: input.pins,
        row,
        nowMs: input.nowMs,
      });
    }
    return { rows: rows.length, integrityFailures };
  });
}

export function inviteRevokeOp(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly inviteId: string;
}): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* input.client.invites
      .revoke({ params: { projectId: input.verified.projectId, id: input.inviteId } })
      .pipe(
        Effect.mapError((error) => {
          if (error instanceof InviteNotFoundError) {
            return cliError("Invite not found (check the id with `maruhi invite list`)");
          }
          if (error instanceof InviteGoneError) {
            return error.reason === "completed"
              ? cliError(
                  "This invite has completed through add_member. To undo the membership, run `maruhi member remove` (it rotates every environment — CRYPTO_SPEC §7)",
                )
              : cliError("This invite is already revoked");
          }
          return toCliError(error);
        }),
      );
    yield* io.log("Revoked the invite");
  });
}
