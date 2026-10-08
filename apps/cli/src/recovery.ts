// Issuing / reissuing / opening a recovery code (CRYPTO_SPEC §8 /
// AUTH_SPEC §13).
//
// - The recovery code (256-bit) exists only in process memory and on
//   display — never written to disk, the keychain, or logs (safekeeping
//   the code is the user's responsibility)
// - The wrap target B = a JSON-serialized **reserve key** record
//   (2026-09-19 DK — previously: the master key) (the fixing point of
//   CRYPTO_SPEC §8's "the serialization format is fixed at CLI
//   implementation". The same shape as a device key). The opening side
//   passes it through importMasterKeys's self-verification, then uses it
//   **only for issuing a device key** (§8.1 — never stored. Recovery's
//   tail is key-recover.ts)
// - Since displaying / entering the code passes key material through the
//   terminal, it is allowed only on a human environment where stdin /
//   stdout / stderr are all TTYs (a known AI agent is refused by the
//   secondary layer too)
// - Save confirmation (ROADMAP's loss-prevention UX): complete only after
//   the user re-types the displayed code's last group. Server
//   registration finishes **before** the confirmation — build the state
//   where reissuing (`maruhi key recovery`) can redo it first, in case
//   the confirmation fails

import { cryptoEffect, type UserId } from "@maruhi/core";
import {
  decodeHex,
  encodeHex,
  generateRecoverySecret,
  SUITE_ID,
  unwrapMasterSecret,
  wrapMasterSecret,
} from "@maruhi/crypto";
import { Effect, Redacted, Stdio } from "effect";
import type { HttpClient } from "effect/http";

import { ensureSensitiveTerminalAllowed } from "./agent-gate.ts";
import type { MaruhiClient } from "./api.ts";
import { escapeText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo, type CliIoShape } from "./io.ts";
import {
  classifyUnreadableMasterKey,
  declaredSuiteOf,
  hasRedactedPlaceholder,
  parseStoredMasterKey,
  placeholderCause,
  serializeStoredMasterKey,
  type StoredMasterKey,
} from "./keychain.ts";
import { logNote } from "./notice.ts";
import { OwnDeviceStore } from "./own-devices.ts";
import { formatRecoveryCode, parseRecoveryCode } from "./recovery-code.ts";
import { generateReserveKeys, recordReserveLocally } from "./reserve.ts";
import {
  type CliSession,
  cryptoBackendUsable,
  type MasterKeyImportError,
  retryOnSupportedRuntime,
  unsupportedCryptoCause,
} from "./session.ts";

/** The retry count for save confirmation / code entry (forgiving typos. Exceeding it is an explicit error). */
const PROMPT_ATTEMPTS = 3;

const agentRefusalMessage =
  "Refused to issue a recovery code because an AI agent environment was detected (the code is key material; it may only be shown on a human interactive terminal)";

function ensureRecoveryCodeInteractionAllowed(
  io: CliIoShape,
  action: "issue" | "read",
): Effect.Effect<void, CliError, Stdio.Stdio> {
  return ensureSensitiveTerminalAllowed({
    agent: io.agentProfile(),
    stderrIsTerminal: io.stderrIsTerminal(),
    agentError:
      action === "issue"
        ? agentRefusalMessage
        : "Refused to read a recovery code because an AI agent environment was detected (the code is key material; run the recovery on a human interactive terminal)",
    terminalError: `Recovery-code ${action === "issue" ? "display" : "entry"} is only allowed on an interactive terminal (stdin, stdout, and stderr must all be terminals; pipes, redirects, CI, and AI agents are refused)`,
  });
}

/**
 * Issues (or reissues) the recovery code for the reserve key `record`:
 * generate → wrap → register → display → save confirmation. The shared
 * body of `maruhi key generate` (first sealing) / `maruhi key recovery`
 * (reissue / separation) / `maruhi key reserve rotate`. `record` is a
 * reserve key's record (reserve.ts) — there is no path to pass a device
 * key.
 */
export const issueRecoveryCodeOp = Effect.fn("recovery.issueRecoveryCodeOp")(function* (input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly record: StoredMasterKey;
}): Effect.fn.Return<void, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient> {
  const io = yield* CliIo;
  yield* ensureRecoveryCodeInteractionAllowed(io, "issue");

  // Replacing an existing registration (reissue) is announced beforehand (the previous code stops working with this operation)
  const status = yield* input.client.auth.recoveryStatus({}).pipe(Effect.mapError(toCliError));
  if (status.registered) {
    yield* io.logError(
      "Replacing the existing recovery registration (previous recovery codes become invalid)",
    );
  }

  const secret = Redacted.make(generateRecoverySecret(), { label: "recovery-secret" });
  // Never use JSON.stringify(record) — the secret side would be wrapped
  // still redacted, registering a recovery blob that "restores but the
  // key is unusable" (the same trap as keychain storage. keychain.ts's
  // note)
  const blob = new TextEncoder().encode(serializeStoredMasterKey(input.record));
  const wrapped = yield* cryptoEffect(() =>
    wrapMasterSecret({
      // Reason for unwrapping: the recovery wrap's key-derivation input (the crypto boundary)
      recoverySecret: Redacted.value(secret),
      userId: input.session.userId,
      masterSecretBlob: blob,
    }),
  ).pipe(Effect.mapError(() => cliError("Failed to create the recovery wrap")));
  yield* input.client.auth
    .recoveryPut({
      payload: {
        suite: SUITE_ID,
        nonceHex: encodeHex(wrapped.nonce),
        ciphertextHex: encodeHex(wrapped.ciphertext),
      },
    })
    .pipe(Effect.mapError(toCliError));

  // The code's display block goes wholly to stderr (the same channel as
  // the prompt). stdout may be redirected / piped: the code is key
  // material and must not get a path that lands in a plaintext file via
  // `maruhi key generate > log`. On stderr it appears on the same
  // screen as the confirmation prompt, so the confirmation ceremony
  // still works
  const code = formatRecoveryCode(secret);
  yield* io.logError("");
  yield* io.logError("Issued your recovery code. Store it somewhere safe now:");
  yield* io.logError("");
  // Reason for unwrapping: displaying the code is issuance's very
  // function (it is never shown again). Displayability was already
  // decided by the TTY + agent gate at the head of this function, and
  // the unwrap happens behind it. stderr itself was also confirmed to
  // be a TTY
  yield* io.logError(`    ${Redacted.value(code)}`);
  yield* io.logError("");
  yield* io.logError(
    "Recommended: print it or save it in a password manager. This code will never be shown again",
  );
  yield* io.logError(
    "With this code plus your account sign-in, you can restore your reserve key on a machine that has no device key and register that machine as a new device (`maruhi key recover`)",
  );
  yield* confirmCodeSaved(code);
  yield* io.logError("Save confirmation complete");
});

/** Confirm the save by re-typing the displayed code's last group (the loss-prevention UX). */
const confirmCodeSaved = Effect.fn("recovery.confirmCodeSaved")(function* (
  code: Redacted.Redacted<string>,
): Effect.fn.Return<void, CliError, CliIo> {
  const io = yield* CliIo;
  // Reason for unwrapping: the matching material for the last group.
  // The code is already displayed, and the substring taken here is
  // never output — used only for the comparison
  const groups = Redacted.value(code).split("-");
  const last = groups[groups.length - 1] ?? "";
  for (let attempt = 1; attempt <= PROMPT_ATTEMPTS; attempt += 1) {
    const answer = yield* io.promptLine({
      prompt: `To confirm you saved the code, enter its last group (group ${groups.length}, 4 characters): `,
    });
    if (answer.trim().toUpperCase() === last) {
      return;
    }
    yield* io.logError("It does not match. Check the code shown above");
  }
  return yield* Effect.fail(
    cliError(
      "Save confirmation failed. The recovery registration itself is complete — store the code shown above, or reissue it with `maruhi key recovery`",
    ),
  );
});

/**
 * Opens the recovery blob with a prompted recovery code and returns the reserve
 * key record (memory only — nothing is stored). Shared by `maruhi key
 * recover` (recovery's front half) and the opening for a ledger change
 * (ledger-open.ts — `key recovery` / `key seal passkey` / `guardian add`
 * / `key reserve rotate`). Recovery's tail (issuing the new device key →
 * `add_device` → discarding the reserve key) is key-recover.ts.
 */
export const unwrapRecoveryBlobWithCode = Effect.fn("recovery.unwrapRecoveryBlobWithCode")(
  function* (input: {
    readonly session: CliSession;
    readonly client: MaruhiClient;
  }): Effect.fn.Return<StoredMasterKey, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient> {
    const io = yield* CliIo;
    // A line symmetric to the issuing side: the code is key material, and
    // no path for typing it through an agent-mediated stdin is built
    // either (the input is readable from the agent's session layer).
    // Opening happens on a human interactive terminal
    yield* ensureRecoveryCodeInteractionAllowed(io, "read");

    const wrap = yield* input.client.auth.recoveryGet({}).pipe(
      Effect.catchTag("RecoveryWrapNotFound", () =>
        Effect.fail(
          cliError(
            "No recovery code is registered for your account. Run `maruhi key recovery` on a device that is registered, or restore with `maruhi key recover --passkey` / `--handoff`",
          ),
        ),
      ),
      Effect.catchTag("RecoveryRateLimited", (error) =>
        Effect.fail(
          cliError(
            `The recovery-blob fetch limit was reached. Retry after ${error.retryAfterSeconds} seconds`,
          ),
        ),
      ),
      Effect.mapError(toCliError),
    );
    const nonce = decodeHex(wrap.nonceHex);
    const ciphertext = decodeHex(wrap.ciphertextHex);
    if (nonce === null || ciphertext === null) {
      return yield* Effect.fail(cliError("The server response is malformed (cannot decode hex)"));
    }

    // Code entry → decryption retries locally (never consumes the fetch's rate-limit window)
    return yield* unwrapWithPromptedCode({
      nonce,
      ciphertext,
      userId: input.session.userId,
    });
  },
);

/** The re-registration procedure itself (identical for every cause). */
const reRegisterAction =
  "seal a new reserve key by running `maruhi key recovery --replace` on a device of yours that is registered (it does not open the ledger; the reserve keys recorded on that machine are revoked).";

/**
 * The common exit when the blob is unusable (this device cannot fix it).
 *
 * "This code cannot restore the key" is true **only for corruption /
 * redacted placeholder**. A blob of an unknown suite can still restore
 * with the same code after an update, so this wording must not be
 * attached (attaching it would make the user discard a working code).
 */
const reRegisterGuidance = `This code cannot restore the key — ${reRegisterAction}`;

/**
 * The mapping for when the opened blob cannot be loaded as key material
 * ({@link importMasterKeys}'s failure) (used by key-recover.ts /
 * ledger-open.ts). An unknown suite (a newer maruhi registered it on
 * another device) is not corruption. Distinguish the remaining two: if
 * the environment is incompatible, both blob and code are intact
 * (**never make the user discard them**); otherwise it is truly corrupt
 * (re-registration is needed).
 */
export function mapUnloadableRecoveryBlob<A, R>(
  effect: Effect.Effect<A, MasterKeyImportError, R>,
): Effect.Effect<A, CliError, R> {
  return effect.pipe(
    Effect.catchTag("MasterKeyUnknownSuite", (error) =>
      Effect.fail(cliError(foreignRecoveryBlobMessage(error.suite))),
    ),
    Effect.catchTag("MasterKeyCorrupt", () =>
      Effect.flatMap(cryptoBackendUsable(), (usable) =>
        Effect.fail(cliError(usable ? brokenRecoveryBlobMessage : unsupportedCryptoOnRecover)),
      ),
    ),
  );
}

/**
 * The wording for when the environment is incompatible (this route's
 * version).
 *
 * This route has passed through ensureNoStoredMasterKey, so this device
 * holds no key — "do not delete your stored key" points at nothing.
 * Instead it names **what is intact** (the code and the blob): without
 * it, the user might blame the code and discard their only means of
 * recovery.
 */
const unsupportedCryptoOnRecover =
  `${unsupportedCryptoCause}. The recovery code you entered and the registered blob are intact — do not discard them. ${retryOnSupportedRuntime}` as const;

/**
 * The wording for when the blob parses but its key material cannot be
 * loaded.
 *
 * **Never declare the cause "corrupt"**: this fork only receives blobs
 * whose shape matches the current version (= passed parse), so
 * "genuinely corrupt" and "written by a future version that changed only
 * the encoding, not the suite" are **indistinguishable by observation**
 * (suite is the crypto suite's identifier, not the storage format's
 * version — the same reason as keychain.ts's note). Declaring it and
 * attaching `reRegisterGuidance` ("this code cannot restore the key")
 * would **revoke a working code** when re-registering on another device.
 * Prompt an update first; keep re-registration as the step after.
 */
const brokenRecoveryBlobMessage =
  `Cannot load the key material in the registered recovery blob (the record is corrupt, or in a format this version does not know). First update maruhi to the latest version and re-run (the recovery code you just entered may still work — do not discard it). If updating does not fix it, ${reRegisterAction}` as const;

/**
 * The wording for when the blob was written under a suite the current
 * version does not know.
 *
 * Unlike a keychain record, **there is nothing to delete** (the blob
 * lives server-side and no key is stored on this device), so no deletion
 * warning is needed. The suite name is a free string from the blob, so
 * it is escaped before reaching the terminal.
 */
function foreignRecoveryBlobMessage(suite: string | null): string {
  const named = suite === null ? "" : ` (${escapeText(suite)})`;
  return `The registered recovery blob cannot be read by this version${named}. It may have been written by a newer maruhi — update maruhi to the latest version and re-run (the recovery code you just entered still works — do not discard it). If you cannot update, ${reRegisterAction}`;
}

/**
 * Interpreting the decrypted blob. Carved out so that **no string
 * holding plaintext key material (hex) leaves this function**: the
 * caller receives only the record and a boolean — physically out of
 * reach of error-message assembly (this route is the only place the
 * master secret key appears as a bare string).
 */
function readRecoveryBlob(bytes: Uint8Array): {
  readonly record: StoredMasterKey | null;
  readonly placeholder: boolean;
  /** The classification when uninterpretable (the same criteria as the keychain side). */
  readonly classification: "corrupt" | "foreign";
  /** The suite an uninterpretable blob claims (null when it claims none). */
  readonly declaredSuite: string | null;
} {
  const blob = new TextDecoder().decode(bytes);
  // The classification and suite extraction also happen **inside this
  // function**: both need the blob's raw string, so doing them outside
  // would leak a string holding plaintext key material to the caller
  return {
    record: parseStoredMasterKey(blob),
    placeholder: hasRedactedPlaceholder(blob),
    classification: classifyUnreadableMasterKey(blob),
    declaredSuite: declaredSuiteOf(blob),
  };
}

const unwrapWithPromptedCode = Effect.fn("recovery.unwrapWithPromptedCode")(function* (input: {
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly userId: UserId;
}): Effect.fn.Return<StoredMasterKey, CliError, CliIo> {
  const io = yield* CliIo;
  for (let attempt = 1; attempt <= PROMPT_ATTEMPTS; attempt += 1) {
    // The entered code is key material itself. **Wrap it at the
    // boundary** (left as a bare string, it could be loaded onto the
    // logError in the same block in one line, and never appear in the
    // inventory of unwrap points). It is unwrapped only just before
    // interpretation
    const answer = Redacted.make(
      yield* io.promptLine({
        prompt: "Enter your recovery code: ",
        secret: true,
      }),
      { label: "recovery-code" },
    );
    const secret = parseRecoveryCode(Redacted.value(answer));
    if (secret === null) {
      yield* io.logError(
        "The code is malformed (13 groups of 4 characters; hyphens, spaces, and letter case are ignored)",
      );
      continue;
    }
    // A crypto failure on the entered code (or a blob that does not
    // open under it) means the same thing to the user: warn and let
    // them re-enter — the wording is the failure itself, so the typed
    // error is re-wrapped then folded back into a logged retry
    const unwrapped = yield* cryptoEffect(() =>
      unwrapMasterSecret({
        // Reason for unwrapping: the recovery-blob decryption's key-derivation input (the crypto boundary)
        recoverySecret: Redacted.value(secret),
        userId: input.userId,
        wrapped: { nonce: input.nonce, ciphertext: input.ciphertext },
      }),
    ).pipe(
      Effect.mapError(() => cliError("Cannot decrypt. Check that the code is correct")),
      Effect.catchTag("CliError", (error) => Effect.as(io.logError(error.message), null)),
    );
    if (unwrapped === null) {
      continue;
    }
    const parsed = readRecoveryBlob(unwrapped);
    const record = parsed.record;
    if (record === null) {
      // Decryption succeeded yet the content is corrupt = the blob was
      // malformed at registration (not a code mistake, so no re-entry
      // is prompted). A redacted save is distinguished here too: the
      // blob is serializeStoredMasterKey's third sink and the same
      // forgotten unwrap can arrive. Moreover re-registering via
      // `maruhi key recovery` requires loading the master key (=
      // already restored), so it cannot run on a device that lost its
      // key — it does not even hold up as guidance
      return yield* Effect.fail(
        cliError(
          parsed.placeholder
            ? // What is corrupt is the **server-registered blob**, not a
              // keychain record (this route passed through
              // ensureNoStoredMasterKey, so no master key exists in the
              // keychain)
              `${placeholderCause("The registered recovery blob")}. ${reRegisterGuidance} Also report this as a maruhi bug`
            : // It may only be a different shape (a blob a future
              // version wrote). Use the same classification as the
              // keychain side, and for what cannot be declared corrupt,
              // guide toward an update first. Even on the corrupt side,
              // re-registration can only run **on another device that
              // still holds a key** (this device has none), so do not
              // drop that caveat
              parsed.classification === "foreign"
              ? foreignRecoveryBlobMessage(parsed.declaredSuite)
              : `Cannot interpret the decrypted blob as a key record. ${reRegisterGuidance}`,
        ),
      );
    }
    return record;
  }
  return yield* Effect.fail(
    cliError("Recovery-code entry failed repeatedly. Check the code and re-run"),
  );
});

/**
 * `maruhi key generate`'s tail: generating the reserve key and its first
 * sealing (K4-2 — a reserve key is born at the first ledger sealing).
 * The order is seal → record locally (→ chain registration at the next
 * sync — K4-1 counterexample 1). Under an agent environment the sealing
 * (ceremony) itself is skipped (guided rather than refused) while the
 * device key's generation still succeeds. The reserve key is made by a
 * later `maruhi key recovery`.
 */
export const issueRecoveryAfterKeygen = Effect.fn("recovery.issueRecoveryAfterKeygen")(
  function* (input: {
    readonly session: CliSession;
    readonly client: MaruhiClient;
  }): Effect.fn.Return<
    void,
    CliError,
    CliIo | Stdio.Stdio | HttpClient.HttpClient | OwnDeviceStore
  > {
    const io = yield* CliIo;
    if (io.agentProfile().isAgent) {
      yield* io.log(
        "Skipped creating the reserve key and its recovery code because this is an AI agent environment. Run `maruhi key recovery` on a human interactive terminal (until then you have no reserve key: losing this device means losing access)",
      );
      return;
    }
    yield* sealNewReserve(input).pipe(
      Effect.mapError((error) =>
        cliError(
          `${error.message} (the device key generation itself is complete; create the reserve key later with \`maruhi key recovery\`)`,
        ),
      ),
    );
  },
);

/**
 * Generates a reserve key, seals it with a fresh recovery code and records its
 * public side locally (K4-1's order: seal → record. Chain registration
 * happens at the next sync).
 */
export const sealNewReserve = Effect.fn("recovery.sealNewReserve")(function* (input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
}): Effect.fn.Return<void, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient | OwnDeviceStore> {
  const reserve = yield* generateReserveKeys();
  yield* issueRecoveryCodeOp({
    session: input.session,
    client: input.client,
    record: reserve.record,
  });
  yield* recordReserveLocally(input.session, reserve);
  yield* logNote(
    `created your reserve key (fingerprint ${reserve.fingerprintHex}). It lives only in the recovery ledger; it is registered on each project the next time this device syncs it`,
  );
});
