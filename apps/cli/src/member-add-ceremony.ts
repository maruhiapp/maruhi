// `maruhi member add`'s invitee confirmation: choosing the accepted
// invitation row -> the FP-confirmation ceremony (interactive-terminal +
// non-agent gate — ADR-0016 decision 7) -> GitHub-signing-keys verification
// when possible (the group's overview lives in member.ts).

import type { Role } from "@maruhi/crypto";
import { Effect, Stdio } from "effect";
import type { HttpClient } from "effect/http";

import type { IdentityBacking } from "./config.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { confirmByLastWord, fingerprintWords, formatWordList } from "./fp-words.ts";
import { checkSigningKeyBacking, describeBackingFallback } from "./github-signing-keys.ts";
import type { InvitationRow, InviteAcceptance } from "./invite.ts";
import { CliIo } from "./io.ts";
import {
  confirmKnownFingerprint,
  consultFingerprintBook,
  type FingerprintBook,
  usableBookHit,
} from "./known-fingerprints.ts";
import { logNote } from "./notice.ts";
/** An accepted row (every row carries the issuance text). */
export type AddableRow = InvitationRow & { readonly acceptance: InviteAcceptance };

const withAcceptance = (
  row: InvitationRow,
): row is InvitationRow & { readonly acceptance: InviteAcceptance } => row.acceptance !== null;

/**
 * Choosing the accepted invite: a given id picks that row; without one,
 * auto-select only when exactly one accepted row exists (multiple or zero
 * requires an explicit choice).
 */
export function selectInvitation(
  rows: readonly InvitationRow[],
  inviteId: string | null,
): Effect.Effect<AddableRow, CliError> {
  if (inviteId !== null) {
    const row = rows.find((candidate) => candidate.id === inviteId);
    if (row === undefined) {
      return Effect.fail(
        cliError("The specified invite was not found (check the id with `maruhi invite list`)"),
      );
    }
    if (row.status === "revoked") {
      return Effect.fail(
        cliError(
          "The specified invite has been revoked (its acceptance block, if any, will not be used)",
        ),
      );
    }
    if (!withAcceptance(row)) {
      return Effect.fail(
        cliError(
          "The specified invite has not been accepted yet (check with `maruhi invite list` after acceptance)",
        ),
      );
    }
    return Effect.succeed(row);
  }
  const accepted = rows.filter(withAcceptance).filter((row) => row.status === "accepted");
  const first = accepted[0];
  if (first === undefined) {
    // completed rows are never auto-selected (ambiguous: every past
    // member's row stays completed forever). The resume of a backfill for
    // an already add_member'd invite takes the explicit-id path — that
    // route is shown here
    return Effect.fail(
      cliError(
        "There is no accepted invite. To resume the backfill of an invite that completed through add_member, look up the id with `maruhi invite list` and pass it explicitly: `maruhi member add <invite-id>`",
      ),
    );
  }
  if (accepted.length > 1) {
    return Effect.fail(
      cliError(
        `Multiple invites have been accepted (${accepted.map((row) => displayText(row.id)).join(", ")}). Specify which invite id to add`,
      ),
    );
  }
  return Effect.succeed(first);
}

/**
 * The inviter's mutual confirmation (§6.5 — mandatory UX): displays the
 * acceptance key's FP word list and the granted role, and requires an
 * explicit confirmation of the out-of-band match. The ceremony is not
 * skipped even on a re-run (a backfill-only interruption recovery) — same
 * discipline as server-grant (never skip verifying the key wraps are about
 * to be dealt to).
 *
 * The verified fingerprint book (KF — known-fingerprints.ts): when it
 * matches the fingerprint of a previously out-of-band-verified
 * counterpart (origin × user_id), the 12-word out-of-band recital is
 * waived. **The explicit confirmation (yes input) of the grant itself is
 * still required on a hit**, and in agent environments the book is never
 * used as an auto-pass (a flag stays required — the book records a past
 * verification and does not substitute a human's consent to this grant).
 * Furthermore **the book is usable only when stdin / stdout are an
 * interactive terminal** (the same allow-list as ADR-0016 decision 7's
 * primary boundary): the 12-word ceremony requires re-typing the last word
 * on each run so a blind pipe can't pass it, but a yes confirmation is not
 * like that, so on a pipe / CI / undetected agent the book is disabled and
 * the full ceremony returns (fail-closed). An explicit flag beats the
 * book; a mismatch warns and returns to the normal ceremony (not an
 * automatic failure — a legitimate key update is possible). A successful
 * ceremony / flag match is recorded into the book.
 */
export function confirmInviteeFingerprint(input: {
  readonly origin: string;
  readonly targetUserId: string;
  readonly role: Role;
  readonly fingerprintHex: string;
  readonly expectFingerprintHex: string | null;
}): Effect.Effect<void, CliError, CliIo | FingerprintBook | Stdio.Stdio> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const words = yield* fingerprintWords(
      input.fingerprintHex,
      "The acceptance key's fingerprint is malformed",
    );
    const book = yield* consultFingerprintBook({
      origin: input.origin,
      userId: input.targetUserId,
      fingerprintHex: input.fingerprintHex,
    });
    // A book hit is usable only on the interactive-terminal + no-flag +
    // non-agent path (judged by usableBookHit). In that case the 2 lines
    // instructing the recital comparison are dropped (never say "not
    // needed" right after instructing the call)
    const hit = yield* usableBookHit({
      book,
      flagProvided: input.expectFingerprintHex !== null,
      isAgent: io.agentProfile().isAgent,
    });
    const lines = [
      "Acceptor's key fingerprint (mutual confirmation — CRYPTO_SPEC §6.5):",
      `  invitee: ${displayText(input.targetUserId)}`,
      `  role:    ${input.role} (will be granted to this member)`,
      `  hex:  ${input.fingerprintHex}`,
      "  word: " + formatWordList(words),
      ...(hit !== null
        ? []
        : [
            "Check that this word list matches the 12 words the acceptor reads to you out of band (e.g. over a call).",
            "If they do not match, the acceptance has been hijacked (an attacker's key was injected) — abort add_member and revoke the invite.",
          ]),
    ];
    for (const line of lines) {
      yield* io.log(line);
    }
    if (input.expectFingerprintHex !== null) {
      if (input.expectFingerprintHex !== input.fingerprintHex) {
        return yield* Effect.fail(
          cliError(
            "--expect-fingerprint does not match the acceptance key's fingerprint. The acceptance may have been hijacked — add_member was aborted (revoke the invite and reissue)",
          ),
        );
      }
      yield* io.log(
        "--expect-fingerprint matches (continuing; the out-of-band record counts as checked)",
      );
      yield* book.record;
      return;
    }
    yield* book.warnIfChanged;
    if (io.agentProfile().isAgent) {
      return yield* Effect.fail(
        cliError(
          "Refused to run the acceptance-key confirmation ceremony: an AI agent environment was detected. Run this yourself in a terminal, or pass the acceptance key fingerprint noted out of band via --expect-fingerprint",
        ),
      );
    }
    if (hit !== null) {
      return yield* confirmKnownFingerprint({
        entry: hit,
        filePath: book.filePath,
        prompt: `Type yes to add ${displayText(input.targetUserId)} as ${input.role} with this previously verified key`,
        cancelText: "add_member was cancelled.",
      });
    }
    yield* confirmByLastWord({
      words,
      promptText:
        "Once you have checked against the acceptor's out-of-band read-out (e.g. a call), type the last of the 12 words shown above",
      mismatchText: "That does not match. Type the last word of the list shown above",
      exhaustedText:
        "Acceptance key fingerprint confirmation failed (the re-typed word does not match). add_member was not performed — re-run once you can check with the acceptor",
    });
    yield* book.record;
  });
}

/**
 * Resolving the destination login (adequacy form 4's (iii)): `--github` →
 * the issuance pin's destination. Absent = null = go to the ceremony. No
 * interactive input is provided (it would mix with the ceremony's re-input
 * prompt, and a typo becomes a query for "someone else's GitHub" — naming
 * is limited to issuance time or an explicit flag).
 */
function resolveAddresseeLogin(input: {
  readonly flagLogin: string | null;
  readonly pinLogin: string | null;
}): Effect.Effect<string | null, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    if (input.flagLogin !== null) {
      return input.flagLogin;
    }
    if (input.pinLogin !== null) {
      yield* io.log(
        `The invite was issued for github.com/${input.pinLogin} (recorded at issuance on this machine)`,
      );
      return input.pinLogin;
    }
    return null;
  });
}

/**
 * The two choices when unregistered (supplement 21 ruling D ④): when the
 * counterpart's GitHub carries no key, ask before entering the ceremony —
 * "ask them and re-run" or "ceremony right now". Only on an interactive
 * terminal + non-agent + no flag (non-interactive stays flag-only, as
 * before). yes = proceed to the ceremony.
 */
function askCeremonyOrWait(input: {
  readonly login: string;
  readonly flagProvided: boolean;
}): Effect.Effect<void, CliError, CliIo | Stdio.Stdio> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const stdio = yield* Stdio.Stdio;
    const interactive =
      !io.agentProfile().isAgent &&
      (yield* stdio.stdinIsTerminal) &&
      (yield* stdio.stdoutIsTerminal);
    if (!interactive || input.flagProvided) {
      return;
    }
    yield* io.log(
      `github.com/${input.login} has not registered this key as a signing key. Ask them to run \`maruhi key publish\` and re-run \`maruhi member add\` to add them without a call, or confirm the 12 words with them now`,
    );
    const answer = yield* io.promptLine({
      prompt:
        "Type yes to confirm the 12 words now; anything else to stop and wait for their registration: ",
    });
    if (answer.trim().toLowerCase() !== "yes") {
      return yield* Effect.fail(
        cliError(
          `add_member was not performed. Ask github.com/${input.login} to register their key with \`maruhi key publish\`, then re-run \`maruhi member add\``,
        ),
      );
    }
  });
}

/**
 * The inviter's adequacy form 4 (CRYPTO_SPEC §6.5 — IV2): in addition to
 * verifying the issuance text and both signatures (done by the caller),
 * when the backing source can confirm "the acceptance's sig key is the
 * named counterpart's key", it may proceed to add_member **without a
 * confirmation input** (the naming was the explicit act at issuance). If
 * `--expect-fingerprint` is also given, it is required on top of the
 * match, and a mismatch refuses. An impossible match (backing `none`, no
 * destination, unregistered, unfetchable) = false = falls back to adequacy
 * forms 1-3 (confirmInviteeFingerprint).
 */
export function confirmInviteeViaBacking(input: {
  readonly identityBacking: IdentityBacking;
  readonly flagLogin: string | null;
  readonly pinLogin: string | null;
  readonly sigPubHex: string;
  readonly fingerprintHex: string;
  readonly expectFingerprintHex: string | null;
}): Effect.Effect<boolean, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    if (input.identityBacking === "none") {
      if (input.flagLogin !== null) {
        yield* logNote(
          "identityBacking is none, so --github cannot be checked against github.com — falling back to the fingerprint confirmation",
        );
      }
      return false;
    }
    const login = yield* resolveAddresseeLogin({
      flagLogin: input.flagLogin,
      pinLogin: input.pinLogin,
    });
    if (login === null) {
      yield* logNote(
        "no GitHub login to check the acceptance key against (pass --github <login>, or name the invitee with `maruhi invite create --github`) — falling back to the fingerprint confirmation",
      );
      return false;
    }
    const verdict = yield* checkSigningKeyBacking({ login, sigPubHex: input.sigPubHex });
    if (verdict.kind === "not-registered") {
      yield* askCeremonyOrWait({ login, flagProvided: input.expectFingerprintHex !== null });
      yield* logNote(
        `${describeBackingFallback(login, verdict)} — falling back to the fingerprint confirmation`,
      );
      return false;
    }
    if (verdict.kind !== "match") {
      yield* logNote(
        `${describeBackingFallback(login, verdict)} — falling back to the fingerprint confirmation`,
      );
      return false;
    }
    if (
      input.expectFingerprintHex !== null &&
      input.expectFingerprintHex !== input.fingerprintHex
    ) {
      return yield* Effect.fail(
        cliError(
          "--expect-fingerprint does not match the acceptance key's fingerprint. The acceptance may have been hijacked — add_member was aborted (revoke the invite and reissue)",
        ),
      );
    }
    yield* io.log(
      `Acceptance key verified: it is registered as a signing key on github.com/${login}, and the acceptance is bound to the link you issued (CRYPTO_SPEC §6.5) — no 12-word call is needed`,
    );
    yield* io.log(`  fp:   ${input.fingerprintHex}`);
    return true;
  });
}
