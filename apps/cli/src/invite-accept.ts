// `maruhi invite accept`: link interpretation -> the issue-signature check
// -> the inviter confirmation (backing source -> fingerprint ceremony) ->
// key generation when absent -> the joint acceptance signature -> accept
// -> the anchor pin (the group's overview lives in invite.ts).

import {
  ForbiddenError,
  InviteGoneError,
  InviteNotFoundError,
  InviteSignatureInvalidError,
} from "@maruhi/api-schema";
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

import type { MaruhiClient } from "./api.ts";
import type { IdentityBacking } from "./config.ts";
import type { CliServices } from "./context.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { confirmByLastWord, fingerprintWords, formatWordList } from "./fp-words.ts";
import { checkSigningKeyBacking, describeBackingFallback } from "./github-signing-keys.ts";
import type { InviteLinkData, InviteRole } from "./invite-link.ts";
import { resolveLinkKey } from "./invite.ts";
import { CliIo } from "./io.ts";
import { offerGithubRegistration } from "./key-publish.ts";
import { Keychain, masterKeyEntryName } from "./keychain.ts";
import {
  confirmKnownFingerprint,
  consultFingerprintBook,
  type FingerprintBook,
  usableBookHit,
} from "./known-fingerprints.ts";
import { logNote, logWarning } from "./notice.ts";
import { PinStore } from "./pins.ts";
import { describeScope, sameScope } from "./scope.ts";
import { type CliSession, loadMasterKeys, type MasterKeys } from "./session.ts";

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

/** The warning for a failed anchor pin (a SHOULD-level degradation — the acceptance itself is already established). */
const warnUnpinned = (detail: string) =>
  logWarning(
    `could not pin the invite link anchor (${detail}). The machine check on first sync (CRYPTO_SPEC §6.3 (a)) will not run — be sure to perform the ceremony with the inviter (out-of-band FP word comparison)`,
  );

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
