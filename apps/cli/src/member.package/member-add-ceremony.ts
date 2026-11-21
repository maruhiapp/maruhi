import { type UserId } from "@maruhi/core";
import type { Role } from "@maruhi/crypto";
import { Effect, Stdio } from "effect";
import type { HttpClient } from "effect/http";

import type { IdentityBacking } from "../config.ts";
import { displayText } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import { confirmByLastWord, fingerprintWords, formatWordList } from "../fp-words.ts";
import { checkSigningKeyBacking, describeBackingFallback } from "../github-signing-keys.ts";
import type { InvitationRow, InviteAcceptance } from "../invite.package/index.ts";
import { CliIo } from "../io.ts";
import {
  confirmKnownFingerprint,
  consultFingerprintBook,
  type FingerprintBook,
  usableBookHit,
} from "../known-fingerprints.ts";
import { logNote } from "../notice.ts";

export type AddableRow = InvitationRow & { readonly acceptance: InviteAcceptance };

const withAcceptance = (
  row: InvitationRow,
): row is InvitationRow & { readonly acceptance: InviteAcceptance } => row.acceptance !== null;

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

export const confirmInviteeFingerprint = Effect.fn("member-add-ceremony.confirmInviteeFingerprint")(
  function* (input: {
    readonly origin: string;
    readonly targetUserId: UserId;
    readonly role: Role;
    readonly fingerprintHex: string;
    readonly expectFingerprintHex: string | null;
  }): Effect.fn.Return<void, CliError, CliIo | FingerprintBook | Stdio.Stdio> {
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
  },
);

const resolveAddresseeLogin = Effect.fn("member-add-ceremony.resolveAddresseeLogin")(
  function* (input: {
    readonly flagLogin: string | null;
    readonly pinLogin: string | null;
  }): Effect.fn.Return<string | null, never, CliIo> {
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
  },
);

const askCeremonyOrWait = Effect.fn("member-add-ceremony.askCeremonyOrWait")(function* (input: {
  readonly login: string;
  readonly flagProvided: boolean;
}): Effect.fn.Return<void, CliError, CliIo | Stdio.Stdio> {
  const io = yield* CliIo;
  const stdio = yield* Stdio.Stdio;
  const interactive =
    !io.agentProfile().isAgent && (yield* stdio.stdinIsTerminal) && (yield* stdio.stdoutIsTerminal);
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

export const confirmInviteeViaBacking = Effect.fn("member-add-ceremony.confirmInviteeViaBacking")(
  function* (input: {
    readonly identityBacking: IdentityBacking;
    readonly flagLogin: string | null;
    readonly pinLogin: string | null;
    readonly sigPubHex: string;
    readonly fingerprintHex: string;
    readonly expectFingerprintHex: string | null;
  }): Effect.fn.Return<boolean, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient> {
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
  },
);
