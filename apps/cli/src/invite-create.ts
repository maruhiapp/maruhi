// `maruhi invite create`: the pre-issuance role / scope checks -> the issue
// signature -> link assembly -> the issuance pin -> the one-time link
// display (the group's overview lives in invite.ts).

import {
  InviteConflictError,
  InvitePendingLimitError,
  InviteRateLimitedError,
} from "@maruhi/api-schema";
import { ulid } from "@maruhi/core";
import {
  type ChainMember,
  deriveInviteLinkKeyPair,
  effectivePermissionOf,
  encodeHex,
  generateInviteLinkSeed,
  type MemberScope,
  type ScopePayloadFields,
  scopePayloadFieldsOf,
  signInviteIssue,
  SUITE_ID,
} from "@maruhi/crypto";
import { Effect, Redacted, Stdio } from "effect";

import { ensureSensitiveTerminalAllowed } from "./agent-gate.ts";
import type { MaruhiClient } from "./api.ts";
import type { VerifiedProject } from "./chain-sync.ts";
import { ROLE_RANK } from "./dek-wrap.ts";
import { ownDeviceByKeys } from "./device-key.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { buildInviteLink, type InviteRole } from "./invite-link.ts";
import { reportIssued } from "./invite.ts";
import { CliIo, type CliIoShape } from "./io.ts";
import { logWarning } from "./notice.ts";
import { PinStore } from "./pins.ts";
import { describeScope, requireScopeEnvironmentsExist, scopeContains } from "./scope.ts";
import type { MasterKeys } from "./session.ts";

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
