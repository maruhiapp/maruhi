// The passkey PRF path (CRYPTO_SPEC §8.2 / AUTH_SPEC §13-7 — KL3 K5).
//
// Registration `maruhi key seal passkey`: the **reserve key** record
// B the caller obtained by opening the ledger (2026-09-19 DK —
// ledger-open.ts) is wrapped with a KEK derived from the PRF output
// of a passkey made on the CLI-served localhost page
// (passkey-page.ts / passkey-listener.ts), then registered into the
// ledger. The ledger write happens **only once, at the end**, when
// every material is in place (no half-written rows on a mid-failure
// — supplement 20 ruling I).
//
// Opening `maruhi key recover --passkey` / a ledger change's
// `--passkey`: takes the ledger's wrap, re-derives the KEK from the
// same passkey's PRF, decrypts B, and returns the record (does not
// store it — the reserve key is used only for issuing a device key.
// The restore's downstream is key-recover.ts).
//
// Ceremonies (register, restore, delete) run only on a human's
// interactive terminal and are refused in AI agent environments
// (ADR-0016 decision 7's existing gate). The listener stands only
// behind the gate. Plaintext PRF outputs, KEK, and B exist only in
// function locals — never on logs, errors, or the DOM.
//
// Restore order (supplement 20 rulings F / I, 20-6 ②′): the ledger's
// state (`GET /auth/key-wraps`) carries each passkey row's prf_salt
// (a public parameter — AUTH_SPEC §13-7), so every credential goes
// to allowCredentials for the authenticator to pick; the response's
// credential decides the row, and only then is that row's wrap
// (`GET /auth/key-wraps/passkey/:wrapId` — a combined window of 5
// per hour + an audit event requiring monitoring) fetched — one row
// only. A cancelled ceremony does not consume the window.

import { MAX_PASSKEY_WRAPS_PER_USER } from "@maruhi/api-schema";
import { decodeHex, derivePasskeyKek, encodeHex, unwrapMasterBlob } from "@maruhi/crypto";
import { Duration, Effect, Stdio } from "effect";
import type { HttpClient } from "effect/unstable/http";

import { ensureSensitiveTerminalAllowed } from "./agent-gate.ts";
import type { MaruhiClient } from "./api.ts";
import { displayText, formatUtcMinutes } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo, type CliIoShape } from "./io.ts";
import { parseStoredMasterKey, type StoredMasterKey } from "./keychain.ts";
import { newLedgerId, wrapReserveBlob } from "./master-ops.ts";
import { logNote } from "./notice.ts";
import { type PrfListener, type PrfListenerOutcome, startPrfListener } from "./passkey-listener.ts";
import type { PrfPageConfig, PrfPageErrorCode } from "./passkey-page.ts";
import type { ReserveKeys } from "./reserve.ts";
import type { CliSession } from "./session.ts";

/** Cap on the ceremony wait (enough for browser launch + biometric auth. An abandoned terminal is not listened to forever). */
const CEREMONY_TIMEOUT = Duration.minutes(5);
const PRF_SALT_BYTES = 32;
const USER_HANDLE_BYTES = 16;
const CONFIRM_CODE_DIGITS = 6;

/**
 * The confirmation code shown on the terminal, which the user types
 * into the page (ruling A revision 1). A uniform-random 6 digits
 * (modulo bias is eliminated by rejection). Not key material (a
 * value demonstrating co-presence with the page).
 */
function newConfirmCode(): string {
  const modulus = 10 ** CONFIRM_CODE_DIGITS;
  const limit = Math.floor(0x1_0000_0000 / modulus) * modulus;
  const draw = new Uint32Array(1);
  let value = limit;
  while (value >= limit) {
    crypto.getRandomValues(draw);
    value = draw[0] ?? limit;
  }
  return String(value % modulus).padStart(CONFIRM_CODE_DIGITS, "0");
}

function displayConfirmCode(code: string): string {
  return `${code.slice(0, 3)} ${code.slice(3)}`;
}

type CeremonyAction = "register" | "recover" | "remove";

function ensurePasskeyCeremonyAllowed(
  io: CliIoShape,
  action: CeremonyAction,
): Effect.Effect<void, CliError, Stdio.Stdio> {
  const agentError =
    action === "recover"
      ? "Refused to open the reserve key with a passkey because an AI agent environment was detected (the opened key would land in the agent's session; run this yourself on a human interactive terminal)"
      : action === "register"
        ? "Refused to seal the reserve key to a passkey because an AI agent environment was detected (sealing is a key ceremony; run this yourself on a human interactive terminal)"
        : "Refused to remove a passkey wrap because an AI agent environment was detected (this changes how your key can be recovered; run this yourself on a human interactive terminal)";
  const noun =
    action === "recover"
      ? "Passkey recovery"
      : action === "register"
        ? "Passkey sealing"
        : "Passkey wrap removal";
  return ensureSensitiveTerminalAllowed({
    agent: io.agentProfile(),
    stderrIsTerminal: io.stderrIsTerminal(),
    agentError,
    terminalError: `${noun} is only allowed on an interactive terminal (stdin, stdout, and stderr must all be terminals; pipes, redirects, CI, and AI agents are refused)`,
  });
}

/** The page's reason code → guidance for the user (no free-form text is taken from the page). */
function ceremonyFailure(
  code: PrfPageErrorCode | "too-many-code-attempts",
  action: "register" | "recover",
): CliError {
  switch (code) {
    case "too-many-code-attempts":
      return cliError(
        "The confirmation code was rejected too many times, so the passkey step was cancelled. Either the code was mistyped, or another process on this machine is sending requests to the passkey page. Nothing was changed — re-run and type the code shown in the terminal",
      );
    case "not-allowed":
      return cliError(
        action === "register"
          ? "The passkey was not created (the browser prompt was cancelled, timed out, or the authenticator refused). Nothing was registered — re-run to try again"
          : "The passkey was not used (the browser prompt was cancelled, timed out, or no registered passkey is available on this device). Nothing was changed — re-run to try again",
      );
    case "already-registered":
      return cliError(
        "This authenticator already holds a passkey that is registered for your account. Remove that wrap first with `maruhi key seal remove <wrap-id>` (see `maruhi key seal list`), or use another authenticator",
      );
    case "prf-unsupported":
      return cliError(
        "This browser or authenticator does not support the WebAuthn PRF extension with user verification, so it cannot seal or restore the key. Try another browser or authenticator",
      );
    case "unexpected":
      return cliError(
        "The passkey step failed in the browser (unexpected error). Nothing was changed — re-run, or try another browser",
      );
  }
}

/** Displays the URL and confirmation code, and auto-launches the browser (the same single fallback path as login). */
function announceListener(
  io: CliIoShape,
  listener: PrfListener,
  confirmCode: string,
): Effect.Effect<void> {
  return Effect.gen(function* () {
    yield* io.logError("");
    yield* io.logError("Open this page in your browser to continue with your passkey:");
    yield* io.logError("");
    yield* io.logError(`    ${listener.url}`);
    yield* io.logError("");
    yield* io.logError(
      `Confirmation code (type it into the page): ${displayConfirmCode(confirmCode)}`,
    );
    yield* io.logError("");
    yield* io.logError(
      `If this terminal runs on a remote machine (SSH, a dev container, Codespaces), forward port ${listener.port} to your local machine first and open the URL there`,
    );
    const opened = yield* io.openBrowser(listener.url);
    yield* io.logError(
      opened
        ? "Opened your browser. If nothing appeared, open the URL above manually (waiting up to 5 minutes; press Ctrl+C to cancel)"
        : "Could not open a browser automatically. Open the URL above manually (waiting up to 5 minutes; press Ctrl+C to cancel)",
    );
  });
}

/** Waits for the page's accepted POST (cut off at 5 minutes. The listener's own failure is also a ceremony failure). */
function awaitOutcome(listener: PrfListener): Effect.Effect<PrfListenerOutcome, CliError> {
  return Effect.tryPromise({
    try: () => listener.outcome,
    catch: () =>
      cliError(
        "The local listener for the passkey page failed. Nothing was changed — re-run to try again",
      ),
  }).pipe(
    Effect.timeout(CEREMONY_TIMEOUT),
    Effect.catchTag("TimeoutError", () =>
      Effect.fail(
        cliError(
          "Timed out waiting for the passkey page (5 minutes). Nothing was changed — re-run to try again",
        ),
      ),
    ),
  );
}

/** The ceremony's result (the page's one POST). */
interface PrfOutcome {
  readonly credentialIdHex: string;
  readonly prf: Uint8Array;
}

/**
 * Stands up the listener, waits for the page's one POST, and
 * always closes. The token shares the listener's lifetime. The PRF
 * output exists only as the value returned from here.
 */
function runPrfCeremony(
  config: PrfPageConfig,
  action: "register" | "recover",
): Effect.Effect<PrfOutcome, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const confirmCode = newConfirmCode();
    return yield* Effect.acquireUseRelease(
      Effect.tryPromise({
        try: () => startPrfListener(config, confirmCode),
        catch: () =>
          cliError(
            "Cannot listen on 127.0.0.1 for the passkey page (no free local port, or loopback networking is unavailable)",
          ),
      }),
      (listener) =>
        Effect.gen(function* () {
          yield* announceListener(io, listener, confirmCode);
          const post = yield* awaitOutcome(listener);
          if ("error" in post) {
            return yield* Effect.fail(ceremonyFailure(post.error, action));
          }
          const prf = decodeHex(post.prfHex);
          if (prf === null) {
            return yield* Effect.fail(cliError("The passkey page sent a malformed PRF value"));
          }
          return { credentialIdHex: post.credentialIdHex, prf };
        }),
      (listener) => Effect.promise(() => listener.close()),
    );
  });
}

function deriveKek(prf: Uint8Array): Effect.Effect<Uint8Array, CliError> {
  return Effect.gen(function* () {
    const kek = yield* Effect.tryPromise({
      try: () => derivePasskeyKek(prf),
      catch: () => cliError("Failed to derive the wrapping key from the passkey (crypto error)"),
    });
    if (!kek.ok) {
      return yield* Effect.fail(
        cliError(
          "The passkey returned a PRF value of the wrong size, so no wrapping key can be derived",
        ),
      );
    }
    return kek.value;
  });
}

/** The ledger's passkey row (a copy of status). */
interface PasskeyRow {
  readonly wrapId: string;
  readonly label: string | null;
  readonly credentialIdHex: string;
  /** This registration's prf_salt (a public parameter — needed before the ceremony, so status carries it). */
  readonly prfSaltHex: string;
  readonly updatedAtMs: number;
}

function fetchPasskeyRows(
  client: MaruhiClient,
): Effect.Effect<readonly PasskeyRow[], CliError, HttpClient.HttpClient> {
  return client.keyWraps.status({}).pipe(
    Effect.map((status) => status.passkeys),
    Effect.mapError(toCliError),
  );
}

function describeRow(row: PasskeyRow): string {
  const label = row.label === null ? "(no label)" : displayText(row.label);
  return `${row.wrapId}  ${label}  credential ${row.credentialIdHex.slice(0, 16)}…  ${formatUtcMinutes(row.updatedAtMs)}`;
}

/**
 * `maruhi key seal passkey [--label]`: seal the reserve key to a new passkey.
 * `reserve` is the reserve key the caller obtained by opening the
 * ledger (ledger-open.ts — opening is the qualification for
 * changing the ledger. K4-2).
 */
export function sealPasskeyOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly reserve: ReserveKeys;
  readonly label?: string | undefined;
}): Effect.Effect<void, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* ensurePasskeyCeremonyAllowed(io, "register");
    const rows = yield* fetchPasskeyRows(input.client);
    if (rows.length >= MAX_PASSKEY_WRAPS_PER_USER) {
      return yield* Effect.fail(
        cliError(
          `You already have ${MAX_PASSKEY_WRAPS_PER_USER} passkeys registered (the limit). Remove one with \`maruhi key seal remove <wrap-id>\` first (see \`maruhi key seal list\`)`,
        ),
      );
    }
    // wrap_id is bound by AAD, so it is issued before encryption.
    // prf_salt is a per-registration random (a public parameter).
    // The user handle is a per-registration random too (ruling G)
    const wrapId = newLedgerId();
    const prfSaltHex = encodeHex(crypto.getRandomValues(new Uint8Array(PRF_SALT_BYTES)));
    const outcome = yield* runPrfCeremony(
      {
        mode: "register",
        rpId: "localhost",
        userName: `maruhi · ${new URL(input.session.origin).host}`,
        userIdHex: encodeHex(crypto.getRandomValues(new Uint8Array(USER_HANDLE_BYTES))),
        prfSaltHex,
        excludeCredentialIdsHex: rows.map((row) => row.credentialIdHex),
      },
      "register",
    );
    const kek = yield* deriveKek(outcome.prf);
    const wrapped = yield* wrapReserveBlob({
      record: input.reserve.record,
      kek,
      context: { userId: input.session.userId, kind: "passkey-prf", wrapRef: wrapId },
    });
    yield* input.client.keyWraps
      .passkeyRegister({
        payload: {
          wrapId,
          wrap: {
            suite: "maruhi/v1",
            nonceHex: encodeHex(wrapped.nonce),
            ciphertextHex: encodeHex(wrapped.ciphertext),
          },
          credentialIdHex: outcome.credentialIdHex,
          prfSaltHex,
          rpId: "localhost",
          ...(input.label === undefined ? {} : { label: input.label }),
        },
      })
      .pipe(
        Effect.catchTag("KeyWrapPolicy", (error) =>
          Effect.fail(
            error.reason === "too-many-passkeys"
              ? cliError(
                  `The server refused the registration: the passkey limit (${MAX_PASSKEY_WRAPS_PER_USER}) is reached. Remove one with \`maruhi key seal remove <wrap-id>\` first`,
                )
              : cliError(
                  `The server refused the registration (${error.reason}). Re-run to try again`,
                ),
          ),
        ),
        Effect.mapError(toCliError),
      );
    yield* io.log(`Sealed the reserve key to a passkey (wrap ${wrapId})`);
    yield* io.log(`reserve key fingerprint: ${input.reserve.fingerprintHex}`);
    yield* logNote(
      "a machine with no device key can restore the reserve key with `maruhi key recover --passkey` and register itself as a new device. If you delete the passkey from your authenticator, remove this wrap with `maruhi key seal remove` too",
    );
  });
}

const NO_PASSKEY_REGISTERED =
  "No passkey is registered for your account. Seal the reserve key to one with `maruhi key seal passkey` (on a registered device), or open it with the recovery code instead (`maruhi key recover` / omit --passkey)";

/** Fetches the wrap of the row the ceremony selected (consumes the combined window once — an audit event requiring monitoring). */
function fetchWrap(
  client: MaruhiClient,
  wrapId: string,
): Effect.Effect<FetchedWrap, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const wrap = yield* client.keyWraps.passkeyGet({ params: { wrapId } }).pipe(
      Effect.catchTag("KeyWrapNotFound", () =>
        Effect.fail(
          cliError(
            "That passkey wrap no longer exists on the server (it was removed meanwhile). Run `maruhi key seal list` to see what is registered",
          ),
        ),
      ),
      Effect.catchTag("KeyWrapRateLimited", (error) =>
        Effect.fail(
          cliError(
            `The key-wrap fetch limit was reached. Retry after ${error.retryAfterSeconds} seconds`,
          ),
        ),
      ),
      Effect.mapError(toCliError),
    );
    const nonce = decodeHex(wrap.wrap.nonceHex);
    const ciphertext = decodeHex(wrap.wrap.ciphertextHex);
    if (nonce === null || ciphertext === null) {
      return yield* Effect.fail(cliError("The server response is malformed (cannot decode hex)"));
    }
    return {
      prfSaltHex: wrap.prfSaltHex,
      credentialIdHex: wrap.credentialIdHex,
      nonce,
      ciphertext,
    };
  });
}

/** The fetched wrap (salt + credential + ciphertext). */
interface FetchedWrap {
  readonly prfSaltHex: string;
  readonly credentialIdHex: string;
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
}

/** The ceremony's and fetch's result. */
interface RecoveryMaterial {
  readonly wrapId: string;
  readonly wrap: FetchedWrap;
  readonly outcome: PrfOutcome;
}

/**
 * Ceremony with every credential → the row of the response's
 * credential → fetch that row's wrap (rulings F / I). Since the
 * blob fetch is after the ceremony, a cancel consumes no window.
 */
function recoverCeremonyFirst(
  client: MaruhiClient,
  rows: readonly PasskeyRow[],
): Effect.Effect<RecoveryMaterial, CliError, CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const outcome = yield* runPrfCeremony(
      {
        mode: "recover",
        rpId: "localhost",
        credentials: rows.map((row) => ({
          credentialIdHex: row.credentialIdHex,
          prfSaltHex: row.prfSaltHex,
        })),
      },
      "recover",
    );
    const row = rows.find((candidate) => candidate.credentialIdHex === outcome.credentialIdHex);
    if (row === undefined) {
      return yield* Effect.fail(
        cliError(
          "The browser used a passkey that is not registered for your account, so the key cannot be restored. Re-run and choose one of the registered passkeys",
        ),
      );
    }
    const wrap = yield* fetchWrap(client, row.wrapId);
    return { wrapId: row.wrapId, wrap, outcome };
  });
}

/** Decrypt → interpret the record (the PRF output and KEK exist only in this function's locals). */
function unwrapReserveRecord(input: {
  readonly session: CliSession;
  readonly material: RecoveryMaterial;
}): Effect.Effect<StoredMasterKey, CliError> {
  return Effect.gen(function* () {
    const { wrap, outcome, wrapId } = input.material;
    if (outcome.credentialIdHex !== wrap.credentialIdHex) {
      return yield* Effect.fail(
        cliError(
          "The wrap fetched from the server belongs to a different passkey than the one the browser used, so the reserve key cannot be opened. Nothing was changed — re-run, and if it repeats, check `maruhi key seal list` and re-register the passkey",
        ),
      );
    }
    const kek = yield* deriveKek(outcome.prf);
    const unwrapped = yield* Effect.tryPromise({
      try: () =>
        unwrapMasterBlob({
          kek,
          wrapped: { nonce: wrap.nonce, ciphertext: wrap.ciphertext },
          context: { userId: input.session.userId, kind: "passkey-prf", wrapRef: wrapId },
        }),
      catch: () => cliError("Failed to decrypt the wrapped reserve key (crypto error)"),
    });
    if (!unwrapped.ok) {
      return yield* Effect.fail(
        cliError(
          "Cannot decrypt the wrapped reserve key with this passkey. The passkey's PRF output does not match the registration (the wrap or its parameters were altered, or the passkey was re-created) — nothing was changed",
        ),
      );
    }
    const record = parseStoredMasterKey(new TextDecoder().decode(unwrapped.value));
    if (record === null) {
      return yield* Effect.fail(
        cliError(
          "The decrypted blob is not a key record. The device that registered this passkey wrote a broken record, or a newer maruhi wrote it — update maruhi, or open the reserve key another way",
        ),
      );
    }
    return record;
  });
}

/**
 * Opens the reserve key with a registered passkey and returns its record
 * (memory only — nothing is stored). Shared by `maruhi key
 * recover --passkey`'s pre-stage and a ledger change's `--passkey`
 * opening (ledger-open.ts).
 */
export function openReserveWithPasskey(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
}): Effect.Effect<StoredMasterKey, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* ensurePasskeyCeremonyAllowed(io, "recover");
    const rows = yield* fetchPasskeyRows(input.client);
    if (rows.length === 0) {
      return yield* Effect.fail(cliError(NO_PASSKEY_REGISTERED));
    }
    const material = yield* recoverCeremonyFirst(input.client, rows);
    return yield* unwrapReserveRecord({ session: input.session, material });
  });
}

/** `maruhi key seal list`: list the passkey wraps in the ledger (public parameters only). */
export function listPasskeysOp(input: {
  readonly client: MaruhiClient;
}): Effect.Effect<void, CliError, CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const rows = yield* fetchPasskeyRows(input.client);
    if (rows.length === 0) {
      yield* io.log("No passkeys are registered (seal your key with `maruhi key seal passkey`)");
      return;
    }
    for (const row of rows) {
      yield* io.log(describeRow(row));
    }
  });
}

/** `maruhi key seal remove <wrap-id>`: delete one passkey wrap from the ledger. */
export function removePasskeyOp(input: {
  readonly client: MaruhiClient;
  readonly wrapId: string;
}): Effect.Effect<void, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* ensurePasskeyCeremonyAllowed(io, "remove");
    yield* input.client.keyWraps.passkeyDelete({ params: { wrapId: input.wrapId } }).pipe(
      Effect.catchTag("KeyWrapNotFound", () =>
        Effect.fail(
          cliError("No passkey wrap with that ID (list them with `maruhi key seal list`)"),
        ),
      ),
      Effect.mapError(toCliError),
    );
    yield* io.log(`Removed passkey wrap ${displayText(input.wrapId)}`);
    yield* logNote(
      "the passkey itself stays in your authenticator; delete it there if you no longer want it",
    );
  });
}
