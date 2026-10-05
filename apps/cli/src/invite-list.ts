// `maruhi invite list` / `maruhi invite revoke`: the per-row issuance and
// acceptance verification with fingerprint-word display and the
// issuance-pin cross-check (the group's overview lives in invite.ts).

import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { VerifiedProject } from "./chain-sync.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { fingerprintWords, formatWordList } from "./fp-words.ts";
import {
  acceptanceFailureText,
  formatDateTimeUtc,
  type InvitationRow,
  issuanceFailureText,
  listInvitations,
  pinMismatchOf,
  verifyAcceptanceBlock,
  verifyIssuance,
} from "./invite.ts";
import { CliIo } from "./io.ts";
import { logWarning } from "./notice.ts";
import type { InvitePins } from "./pins.ts";
import { describeScope } from "./scope.ts";

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
        Effect.catchTags(
          {
            InviteNotFound: () =>
              Effect.fail(cliError("Invite not found (check the id with `maruhi invite list`)")),
            InviteGone: (error) =>
              Effect.fail(
                error.reason === "completed"
                  ? cliError(
                      "This invite has completed through add_member. To undo the membership, run `maruhi member remove` (it rotates every environment — CRYPTO_SPEC §7)",
                    )
                  : cliError("This invite is already revoked"),
              ),
          },
          (error) => Effect.fail(toCliError(error)),
        ),
      );
    yield* io.log("Revoked the invite");
  });
}
