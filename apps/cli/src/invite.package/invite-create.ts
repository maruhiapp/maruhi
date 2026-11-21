import {
  InviteConflictError,
  InvitePendingLimitError,
  InviteRateLimitedError,
} from "@maruhi/api-schema";
import type { UserId } from "@maruhi/core";
import { cryptoEffect, ulid } from "@maruhi/core";
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
import { SecureRandom } from "effect/crypto";

import { ensureSensitiveTerminalAllowed } from "../agent-gate.ts";
import type { MaruhiClient } from "../api.ts";
import type { VerifiedProject } from "../chain-sync.ts";
import { ROLE_RANK } from "../dek-wrap.ts";
import { ownDeviceByKeys } from "../device-key.ts";
import { cliError, type CliError } from "../errors.ts";
import { toCliError } from "../failure.ts";
import { buildInviteLink, type InviteRole } from "../invite-link.ts";
import { CliIo, type CliIoShape } from "../io.ts";
import { logWarning } from "../notice.ts";
import { PinStore } from "../pins.ts";
import { describeScope, requireScopeEnvironmentsExist, scopeContains } from "../scope.ts";
import type { MasterKeys } from "../session.ts";
import { reportIssued } from "./invite.ts";

interface InviteCreateSummary {
  readonly id: string;
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
    return cliError(
      "The server already has an invite with the same id or link key (an astronomically unlikely collision). Re-run `maruhi invite create` to draw a new one",
    );
  }
  return toCliError(error);
}

const ensureCanIssue = Effect.fn("invite-create.ensureCanIssue")(function* (input: {
  readonly verified: VerifiedProject;
  readonly sessionUserId: UserId;
  readonly role: InviteRole;
  readonly scope: MemberScope;
  readonly masterKeys: MasterKeys;
}): Effect.fn.Return<ChainMember, CliError> {
  const inviter = input.verified.state.members.get(input.sessionUserId);
  if (inviter === undefined) {
    return yield* Effect.fail(
      cliError("Only admins and above can issue invites (AUTH_SPEC §15-2)"),
    );
  }
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

interface SignedIssuance {
  readonly inviteId: string;
  readonly seed: Uint8Array;
  readonly linkPubHex: string;
  readonly issueSignatureHex: string;
}

const signIssuance = Effect.fn("invite-create.signIssuance")(function* (input: {
  readonly verified: VerifiedProject;
  readonly inviter: ChainMember;
  readonly inviterKeys: { readonly encPubHex: string; readonly sigPubHex: string };
  readonly role: InviteRole;
  readonly scope: ScopePayloadFields;
  readonly signingKey: MasterKeys["sigKeyPair"]["privateKey"];
}): Effect.fn.Return<SignedIssuance, CliError, SecureRandom.SecureRandom> {
  const inviteId = yield* ulid();
  const seed = generateInviteLinkSeed();
  const linkKey = yield* cryptoEffect(() => deriveInviteLinkKeyPair(seed)).pipe(
    Effect.mapError(() => cliError("Failed to derive the invite link key")),
  );
  const linkPubHex = encodeHex(linkKey.publicKeyRaw);
  const signed = yield* cryptoEffect(() =>
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
  ).pipe(Effect.mapError(() => cliError("Failed to create the issue signature")));
  return { inviteId, seed, linkPubHex, issueSignatureHex: signed };
});

export const inviteCreateOp = Effect.fn("invite-create.inviteCreateOp")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly origin: string;
  readonly role: InviteRole;
  readonly scope: MemberScope;
  readonly sessionUserId: UserId;
  readonly masterKeys: MasterKeys;
  readonly expectedGithubLogin: string | null;
  readonly inviterLogin: string | null;
}): Effect.fn.Return<
  InviteCreateSummary,
  CliError,
  CliIo | PinStore | Stdio.Stdio | SecureRandom.SecureRandom
> {
  const io = yield* CliIo;
  const pinStore = yield* PinStore;
  yield* ensureInviteLinkDisplayAllowed(io);
  const inviter = yield* ensureCanIssue(input);
  const scope: ScopePayloadFields = scopePayloadFieldsOf(input.scope);
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
