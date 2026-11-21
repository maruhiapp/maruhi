import {
  ForbiddenError,
  InviteGoneError,
  InviteNotFoundError,
  InviteSignatureInvalidError,
} from "@maruhi/api-schema";
import { cryptoEffect, type ProjectId } from "@maruhi/core";
import {
  computeUserKeyFingerprint,
  decodeHex,
  encodeHex,
  type InviteAcceptSignatureContext,
  signInviteAccept,
  signInviteLink,
  SUITE_ID,
  verifyInviteIssueSignature,
} from "@maruhi/crypto";
import { Effect, Stdio } from "effect";
import type { HttpClient } from "effect/http";

import type { MaruhiClient } from "../api.ts";
import type { IdentityBacking } from "../config.ts";
import type { CliServices } from "../context.ts";
import { displayText } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import { toCliError } from "../failure.ts";
import { confirmByLastWord, fingerprintWords, formatWordList } from "../fp-words.ts";
import { checkSigningKeyBacking, describeBackingFallback } from "../github-signing-keys.ts";
import type { InviteLinkData, InviteRole } from "../invite-link.ts";
import { CliIo } from "../io.ts";
import { offerGithubRegistration } from "../key.package/index.ts";
import { Keychain, masterKeyEntryName } from "../keychain.ts";
import {
  confirmKnownFingerprint,
  consultFingerprintBook,
  type FingerprintBook,
  usableBookHit,
} from "../known-fingerprints.ts";
import { logNote, logWarning } from "../notice.ts";
import { PinStore } from "../pins.ts";
import { describeScope, sameScope } from "../scope.ts";
import { type CliSession, loadMasterKeys, type MasterKeys } from "../session.ts";
import { resolveLinkKey } from "./invite.ts";

interface InviteAcceptSummary {
  readonly projectId: ProjectId;
  readonly role: InviteRole;
}

const inviterFingerprintOf = Effect.fn("invite-accept.inviterFingerprintOf")(function* (
  link: InviteLinkData,
): Effect.fn.Return<string, CliError> {
  const enc = decodeHex(link.inviterEncPubHex);
  const sig = decodeHex(link.inviterSigPubHex);
  if (enc === null || sig === null) {
    return yield* Effect.fail(cliError("The link's inviter keys (ie= / is=) are malformed"));
  }
  const fingerprint = yield* cryptoEffect(() => computeUserKeyFingerprint(enc, sig)).pipe(
    Effect.mapError(() => cliError("The link's inviter keys (ie= / is=) are malformed")),
  );
  return encodeHex(fingerprint);
});

const verifyLinkIssuanceWith = Effect.fn("invite-accept.verifyLinkIssuanceWith")(function* (
  link: InviteLinkData,
  linkPubHex: string,
): Effect.fn.Return<void, CliError> {
  yield* cryptoEffect(() =>
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
  ).pipe(
    Effect.mapError(() =>
      cliError(
        "The invite link's issue signature does not verify under the inviter key it names (CRYPTO_SPEC §6.5). The link was altered in transit, or it was not issued by the holder of that key — do not accept it; ask the inviter to reissue over a trusted channel",
      ),
    ),
  );
});

const confirmInviterFingerprint = Effect.fn("invite-accept.confirmInviterFingerprint")(
  function* (input: {
    readonly origin: string;
    readonly link: InviteLinkData;
    readonly inviterFingerprintHex: string;
    readonly expectInviterFingerprintHex: string | null;
  }): Effect.fn.Return<void, CliError, CliIo | FingerprintBook | Stdio.Stdio> {
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
  },
);

const ensureMasterKeysForAccept = Effect.fn("invite-accept.ensureMasterKeysForAccept")(
  function* (input: {
    readonly session: CliSession;
    readonly client: MaruhiClient;
    readonly keyGenerate: Effect.Effect<void, CliError, CliServices>;
  }): Effect.fn.Return<
    { readonly keys: MasterKeys; readonly generated: boolean },
    CliError,
    CliServices
  > {
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
  },
);

const confirmInviterViaBacking = Effect.fn("invite-accept.confirmInviterViaBacking")(
  function* (input: {
    readonly link: InviteLinkData;
    readonly identityBacking: IdentityBacking;
    readonly expectedFromLogin: string | null;
  }): Effect.fn.Return<boolean, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient> {
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
  },
);

const confirmExpectedInviter = Effect.fn("invite-accept.confirmExpectedInviter")(function* (
  link: InviteLinkData,
  inviterLogin: string,
): Effect.fn.Return<boolean, CliError, CliIo | Stdio.Stdio> {
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

export const inviteAcceptOp = Effect.fn("invite-accept.inviteAcceptOp")(function* (input: {
  readonly client: MaruhiClient;
  readonly session: CliSession;
  readonly link: InviteLinkData;
  readonly expectInviterFingerprintHex: string | null;
  readonly expectedFromLogin: string | null;
  readonly identityBacking: IdentityBacking;
  readonly keyGenerate: Effect.Effect<void, CliError, CliServices>;
}): Effect.fn.Return<InviteAcceptSummary, CliError, CliServices> {
  const { link } = input;
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
  const signature = yield* cryptoEffect(() =>
    signInviteAccept({ context, signingKey: masterKeys.sigKeyPair.privateKey }),
  ).pipe(Effect.mapError(() => cliError("Failed to create the acceptance signatures")));
  const linkSignature = yield* cryptoEffect(() =>
    signInviteLink({ context, linkPrivateKey: linkKey.keyPair.privateKey }),
  ).pipe(Effect.mapError(() => cliError("Failed to create the acceptance signatures")));

  const accepted = yield* input.client.invites
    .accept({
      payload: {
        linkPubHex: linkKey.linkPubHex,
        encPubHex: masterKeys.record.encPubHex,
        sigPubHex: masterKeys.record.sigPubHex,
        acceptSignatureHex: signature,
        linkSignatureHex: linkSignature,
      },
    })
    .pipe(Effect.mapError(acceptErrorToCliError));

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
  if (!sameScope(accepted, link)) {
    return yield* Effect.fail(
      cliError(
        `The scope declared in the signed link (${describeScope(link)}) does not match the scope the server reports (${describeScope(accepted)}). The server's row contradicts the inviter's issue signature — do not trust this acceptance; ask the inviter to check \`maruhi invite list\``,
      ),
    );
  }

  const anchored = yield* pinAnchorAfterAccept(link, inviterFingerprintHex);

  yield* reportAcceptOutcome({
    accepted,
    fingerprintHex: masterKeys.fingerprintHex,
    anchored,
    identityBacking: input.identityBacking,
  });
  if (generated && input.identityBacking !== "none") {
    yield* offerGithubRegistration({ session: input.session });
  }
  return { projectId: accepted.projectId, role: accepted.role };
});

const warnUnpinned = (detail: string) =>
  logWarning(
    `could not pin the invite link anchor (${detail}). The machine check on first sync (CRYPTO_SPEC §6.3 (a)) will not run — be sure to perform the ceremony with the inviter (out-of-band FP word comparison)`,
  );

const pinAnchorAfterAccept = Effect.fn("invite-accept.pinAnchorAfterAccept")(function* (
  link: InviteLinkData,
  inviterFingerprintHex: string,
): Effect.fn.Return<boolean, CliError, CliIo | PinStore> {
  const io = yield* CliIo;
  const pinStore = yield* PinStore;
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

const reportAcceptOutcome = Effect.fn("invite-accept.reportAcceptOutcome")(function* (input: {
  readonly accepted: InviteAcceptSummary;
  readonly fingerprintHex: string;
  readonly anchored: boolean;
  readonly identityBacking: IdentityBacking;
}): Effect.fn.Return<void, CliError, CliIo> {
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
