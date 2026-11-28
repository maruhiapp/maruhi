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

import { ensureSensitiveTerminalAllowed } from "../agent-gate.ts";
import type { MaruhiClient } from "../api.ts";
import { escapeText } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import { toCliError } from "../failure.ts";
import { CliIo, type CliIoShape } from "../io.ts";
import {
  classifyUnreadableMasterKey,
  declaredSuiteOf,
  hasRedactedPlaceholder,
  parseStoredMasterKey,
  placeholderCause,
  serializeStoredMasterKey,
  type StoredMasterKey,
} from "../keychain.ts";
import { logNote } from "../notice.ts";
import { OwnDeviceStore } from "../own-devices.ts";
import {
  type CliSession,
  cryptoBackendUsable,
  type MasterKeyImportError,
  retryOnSupportedRuntime,
  unsupportedCryptoCause,
} from "../session.ts";
import { formatRecoveryCode, parseRecoveryCode } from "./recovery-code.ts";
import { generateReserveKeys, recordReserveLocally } from "./reserve.ts";

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

export const issueRecoveryCodeOp = Effect.fn("recovery.issueRecoveryCodeOp")(function* (input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly record: StoredMasterKey;
}): Effect.fn.Return<void, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient> {
  const io = yield* CliIo;
  yield* ensureRecoveryCodeInteractionAllowed(io, "issue");

  const status = yield* input.client.auth.recoveryStatus({}).pipe(Effect.mapError(toCliError));
  if (status.registered) {
    yield* io.logError(
      "Replacing the existing recovery registration (previous recovery codes become invalid)",
    );
  }

  const secret = Redacted.make(generateRecoverySecret(), { label: "recovery-secret" });
  const blob = new TextEncoder().encode(serializeStoredMasterKey(input.record));
  const wrapped = yield* cryptoEffect(() =>
    wrapMasterSecret({
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

  const code = formatRecoveryCode(secret);
  yield* io.logError("");
  yield* io.logError("Issued your recovery code. Store it somewhere safe now:");
  yield* io.logError("");
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

const confirmCodeSaved = Effect.fn("recovery.confirmCodeSaved")(function* (
  code: Redacted.Redacted<string>,
): Effect.fn.Return<void, CliError, CliIo> {
  const io = yield* CliIo;
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

export const unwrapRecoveryBlobWithCode = Effect.fn("recovery.unwrapRecoveryBlobWithCode")(
  function* (input: {
    readonly session: CliSession;
    readonly client: MaruhiClient;
  }): Effect.fn.Return<StoredMasterKey, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient> {
    const io = yield* CliIo;
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

    return yield* unwrapWithPromptedCode({
      nonce,
      ciphertext,
      userId: input.session.userId,
    });
  },
);

const reRegisterAction =
  "seal a new reserve key by running `maruhi key recovery --replace` on a device of yours that is registered (it does not open the ledger; the reserve keys recorded on that machine are revoked).";

const reRegisterGuidance = `This code cannot restore the key — ${reRegisterAction}`;

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

const unsupportedCryptoOnRecover =
  `${unsupportedCryptoCause}. The recovery code you entered and the registered blob are intact — do not discard them. ${retryOnSupportedRuntime}` as const;

const brokenRecoveryBlobMessage =
  `Cannot load the key material in the registered recovery blob (the record is corrupt, or in a format this version does not know). First update maruhi to the latest version and re-run (the recovery code you just entered may still work — do not discard it). If updating does not fix it, ${reRegisterAction}` as const;

function foreignRecoveryBlobMessage(suite: string | null): string {
  const named = suite === null ? "" : ` (${escapeText(suite)})`;
  return `The registered recovery blob cannot be read by this version${named}. It may have been written by a newer maruhi — update maruhi to the latest version and re-run (the recovery code you just entered still works — do not discard it). If you cannot update, ${reRegisterAction}`;
}

function readRecoveryBlob(bytes: Uint8Array): {
  readonly record: StoredMasterKey | null;
  readonly placeholder: boolean;
  readonly classification: "corrupt" | "foreign";
  readonly declaredSuite: string | null;
} {
  const blob = new TextDecoder().decode(bytes);
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
    const unwrapped = yield* cryptoEffect(() =>
      unwrapMasterSecret({
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
      return yield* Effect.fail(
        cliError(
          parsed.placeholder
            ? `${placeholderCause("The registered recovery blob")}. ${reRegisterGuidance} Also report this as a maruhi bug`
            : parsed.classification === "foreign"
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
