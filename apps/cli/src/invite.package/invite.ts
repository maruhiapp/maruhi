import {
  cryptoEffect,
  type UserId,
  type EnvironmentId,
  type ProjectId,
  type WrappedCryptoError,
} from "@maruhi/core";
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

import type { MaruhiClient } from "../api.ts";
import type { VerifiedProject } from "../chain-sync.ts";
import { devicesOf } from "../device-key.ts";
import { displayText, formatUtcMinutes } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import { toCliError } from "../failure.ts";
import type { InviteLinkData, InviteRole } from "../invite-link.ts";
import { CliIo } from "../io.ts";
import { type InvitePins, issuedPinOf } from "../pins.ts";
import { describeScope, sameScope } from "../scope.ts";

export interface InviteIssuance {
  readonly linkPubHex: string;
  readonly headHashHex: string;
  readonly headSeq: number;
  readonly issueSignatureHex: string;
}

export interface InviteAcceptance {
  readonly inviteeUserId: UserId;
  readonly inviteeEncPubHex: string;
  readonly inviteeSigPubHex: string;
  readonly signatureHex: string;
  readonly linkSignatureHex: string;
  readonly acceptedAtMs: number;
}

export interface InvitationRow {
  readonly id: string;
  readonly projectId: ProjectId;
  readonly role: InviteRole;
  readonly scopeKind: ScopeKind;
  readonly scopeEnvironmentIds: readonly EnvironmentId[];
  readonly status: "pending" | "accepted" | "completed" | "revoked";
  readonly inviterUserId: UserId;
  readonly issuance: InviteIssuance;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
  readonly acceptance: InviteAcceptance | null;
}

export function listInvitations(
  client: MaruhiClient,
  projectId: ProjectId,
): Effect.Effect<readonly InvitationRow[], CliError> {
  return client.invites.list({ params: { projectId } }).pipe(
    Effect.mapError(toCliError),
    Effect.map((response) => response.invitations),
  );
}

function signatureVerifies(
  signatureTag:
    | "CryptoInviteIssueSignature"
    | "CryptoInviteLinkSignature"
    | "CryptoInviteAcceptSignature",
  verification: Effect.Effect<unknown, WrappedCryptoError>,
): Effect.Effect<boolean> {
  return verification.pipe(
    Effect.as(true),
    Effect.catchTag(["CryptoInvalidInput", "CryptoKeyImport", signatureTag], () =>
      Effect.succeed(false),
    ),
    Effect.orDie,
  );
}

export type IssuanceVerdict =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: "inviter-not-member" | "signature" };

export const verifyIssuance = Effect.fn("invite.verifyIssuance")(function* (input: {
  readonly verified: VerifiedProject;
  readonly row: InvitationRow;
}): Effect.fn.Return<IssuanceVerdict, CliError> {
  const { issuance } = input.row;
  const inviter = input.verified.state.members.get(input.row.inviterUserId);
  if (inviter === undefined) {
    return { ok: false, reason: "inviter-not-member" } as const;
  }
  for (const inviterDevice of devicesOf(inviter)) {
    const verified = yield* signatureVerifies(
      "CryptoInviteIssueSignature",
      cryptoEffect(() =>
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
      ),
    );
    if (verified) {
      return { ok: true } as const;
    }
  }
  return { ok: false, reason: "signature" } as const;
});

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

export const verifyAcceptanceBlock = Effect.fn("invite.verifyAcceptanceBlock")(function* (input: {
  readonly projectId: ProjectId;
  readonly issuance: InviteIssuance;
  readonly acceptance: InviteAcceptance;
}): Effect.fn.Return<
  | { readonly ok: true; readonly fingerprintHex: string }
  | { readonly ok: false; readonly which: "accept" | "link" | "keys" },
  CliError
> {
  const context: InviteAcceptSignatureContext = {
    suite: SUITE_ID,
    projectId: input.projectId,
    linkPubHex: input.issuance.linkPubHex,
    inviteeUserId: input.acceptance.inviteeUserId,
    inviteeEncPubHex: input.acceptance.inviteeEncPubHex,
    inviteeSigPubHex: input.acceptance.inviteeSigPubHex,
  };
  const linkVerified = yield* signatureVerifies(
    "CryptoInviteLinkSignature",
    cryptoEffect(() =>
      verifyInviteLinkSignature({
        context,
        linkSignatureHex: input.acceptance.linkSignatureHex,
      }),
    ),
  );
  if (!linkVerified) {
    return { ok: false, which: "link" } as const;
  }
  const verified = yield* signatureVerifies(
    "CryptoInviteAcceptSignature",
    cryptoEffect(() =>
      verifyInviteAcceptSignature({ context, signatureHex: input.acceptance.signatureHex }),
    ),
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

export const reportIssued = Effect.fn("invite.reportIssued")(function* (input: {
  readonly link: Redacted.Redacted<string>;
  readonly inviteId: string;
  readonly role: InviteRole;
  readonly scope: MemberScope;
  readonly expiresAtMs: number;
  readonly expectedGithubLogin: string | null;
}): Effect.fn.Return<void, never, CliIo> {
  const io = yield* CliIo;
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

export const formatDateTimeUtc = formatUtcMinutes;

export const resolveLinkKey = Effect.fn("invite.resolveLinkKey")(function* (link: InviteLinkData) {
  const seed = decodeHex(Redacted.value(link.linkSeedHex));
  if (seed === null) {
    return yield* Effect.fail(cliError("The link's key seed (k=) is malformed"));
  }
  const derived = yield* cryptoEffect(() => deriveInviteLinkKeyPair(seed)).pipe(
    Effect.mapError(() => cliError("Failed to derive the invite link key")),
  );
  return { keyPair: derived, linkPubHex: encodeHex(derived.publicKeyRaw) };
});

export function pinMismatchOf(
  pins: InvitePins | null,
  row: InvitationRow,
): "missing" | "mismatch" | "match" {
  const pin = issuedPinOf(pins, row.id);
  if (pin === undefined) {
    return "missing";
  }
  return pin.linkPubHex !== row.issuance.linkPubHex || pin.role !== row.role || !sameScope(pin, row)
    ? "mismatch"
    : "match";
}
