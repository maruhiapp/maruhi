import {
  cryptoEffect,
  cryptoPromise,
  type KeyFingerprintHex,
  type UserId,
  userKeyFingerprintHex,
} from "@maruhi/core";
import type { EncryptionKeyPair, SigningKeyPair } from "@maruhi/crypto";
import {
  computeUserKeyFingerprint,
  decodeHex,
  exportEncryptionPrivateKey,
  exportEncryptionPublicKey,
  exportSigningPrivateSeed,
  exportSigningPublicKey,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  importEncryptionKeyPair,
  importSigningKeyPair,
  SUITE_ID,
} from "@maruhi/crypto";
import { Clock, Data, Effect, Exit, Redacted } from "effect";
import type { HttpClient } from "effect/http";

import { makeApiClient } from "./api.ts";
import type { CliConfig } from "./config.ts";
import { formatUtcDate } from "./display.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import {
  classifyUnreadableMasterKey,
  corruptMasterKeyMessage,
  declaredSuiteOf,
  describeStore,
  foreignMasterKeyMessage,
  hasRedactedPlaceholder,
  Keychain,
  type KeychainKind,
  masterKeyEntryName,
  parseStoredMasterKey,
  parseStoredToken,
  REDACTED_PLACEHOLDER_TEXT,
  redactedPlaceholderEnvTokenMessage,
  redactedPlaceholderMasterKeyMessage,
  redactedPlaceholderTokenMessage,
  type StoredMasterKey,
  tokenEntryName,
  tokenRecordNoun,
} from "./keychain.ts";
import { logWarning } from "./notice.ts";

export interface CliSession {
  readonly origin: string;
  readonly token: Redacted.Redacted<string>;
  readonly userId: UserId;
}

export interface MasterKeys {
  readonly record: StoredMasterKey;
  readonly encKeyPair: EncryptionKeyPair;
  readonly sigKeyPair: SigningKeyPair;
  readonly fingerprintHex: KeyFingerprintHex;
}

export function isLoopbackHostname(hostname: string): boolean {
  if (hostname === "localhost" || hostname === "::1" || hostname === "[::1]") {
    return true;
  }
  const match = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(hostname);
  return match !== null && match.slice(1).every((octet) => Number(octet) <= 255);
}

export function normalizeHttpOrigin(
  raw: string,
  label: string,
  source: { readonly fix: string } | "flag" = "flag",
): Effect.Effect<string, CliError> {
  const reject = (message: string): Effect.Effect<never, CliError> =>
    Effect.fail(
      source === "flag" ? usageError(message) : cliError(`${message} — fix ${source.fix}`),
    );
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return reject(`Cannot parse ${label} (use a URL starting with https://)`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    return reject(`${label} must be http(s)`);
  }
  if (url.protocol === "http:" && !isLoopbackHostname(url.hostname)) {
    return reject(
      `http: for ${label} is only allowed on loopback (it would otherwise transmit in cleartext)`,
    );
  }
  return Effect.succeed(url.origin);
}

export function resolveServerOrigin(
  flag: string | undefined,
  config: CliConfig,
): Effect.Effect<string, CliError> {
  const raw = flag ?? config.server;
  if (raw === undefined) {
    return Effect.fail(
      cliError(
        "No server URL is configured. Pass --server <url> or set it with `maruhi config set server <url>`",
      ),
    );
  }
  return normalizeHttpOrigin(
    raw,
    "the server URL",
    flag === undefined ? { fix: "server in your config" } : "flag",
  );
}

function noSessionError(kind: KeychainKind): CliError {
  return cliError(
    kind === "agent"
      ? "Not logged in. Run `maruhi login` (this agent session holds no token yet; it is discarded when the session ends)"
      : "Not logged in. Run `maruhi login` (in environments without a keychain, run it inside `maruhi agent -- <shell>`, or pass a token via the MARUHI_TOKEN env var)",
  );
}

const TOKEN_EXPIRY_WARNING_WINDOW_MS = 14 * 24 * 60 * 60 * 1000;

const warnNearExpiry = Effect.fn("session.warnNearExpiry")(function* (
  expiresAtMs: number | undefined,
  reissueHint: string,
): Effect.fn.Return<void, never, CliIo> {
  if (expiresAtMs === undefined) {
    return;
  }
  const remainingMs = expiresAtMs - (yield* Clock.currentTimeMillis);
  if (remainingMs <= 0 || remainingMs > TOKEN_EXPIRY_WARNING_WINDOW_MS) {
    return;
  }
  const days = Math.ceil(remainingMs / (24 * 60 * 60 * 1000));
  yield* logWarning(
    `the API token expires on ${formatUtcDate(expiresAtMs)} (UTC) — ${days === 1 ? "1 day" : `${days} days`} left. ${reissueHint}`,
  );
});

const sessionFromEnvToken = Effect.fn("session.sessionFromEnvToken")(function* (input: {
  readonly token: string;
  readonly origin: string;
  readonly declaredOrigin: string | undefined;
  readonly variable: "MARUHI_TOKEN" | "MARUHI_MIRROR_TOKEN";
}): Effect.fn.Return<CliSession, CliError, CliIo | HttpClient.HttpClient> {
  if (REDACTED_PLACEHOLDER_TEXT.test(input.token)) {
    return yield* Effect.fail(cliError(redactedPlaceholderEnvTokenMessage));
  }
  const envToken = Redacted.make(input.token, { label: "maruhi-token" });
  if (input.declaredOrigin === undefined || input.declaredOrigin.length === 0) {
    return yield* Effect.fail(
      cliError(
        "Using MARUHI_TOKEN requires MARUHI_TOKEN_ORIGIN to name the target server origin (so the token is never sent to an unintended origin)",
      ),
    );
  }
  const expectedOrigin = yield* normalizeHttpOrigin(input.declaredOrigin, "MARUHI_TOKEN_ORIGIN", {
    fix: "the MARUHI_TOKEN_ORIGIN env var",
  });
  if (expectedOrigin !== input.origin) {
    return yield* Effect.fail(
      cliError(
        `MARUHI_TOKEN_ORIGIN (${expectedOrigin}) does not match the connection target (${input.origin}). The token will not be sent to this origin`,
      ),
    );
  }
  const client = yield* makeApiClient({ baseUrl: input.origin, token: envToken });
  const me = yield* client.auth.me({}).pipe(
    Effect.mapError((error) => {
      const failure = toCliError(error);
      return failure.unreachable === true
        ? failure
        : cliError(
            `Authentication with ${input.variable} failed (the token may be expired or revoked, or the scope or target server may not match). Issue a new token with \`maruhi login --token-name <name> --show-token\` on an interactive workstation terminal, then update the ${input.variable} value in this environment`,
          );
    }),
  );
  yield* warnNearExpiry(
    me.tokenExpiresAtMs,
    `Re-issue it with \`maruhi login --token-name <name> --show-token\` on a workstation and update ${input.variable} before it stops working`,
  );
  return { origin: input.origin, token: envToken, userId: me.userId } satisfies CliSession;
});

export type EnvTokenStatus =
  | { readonly kind: "unset" }
  | { readonly kind: "active" }
  | { readonly kind: "placeholder" }
  | { readonly kind: "originMissing" }
  | { readonly kind: "originInvalid"; readonly reason: string }
  | { readonly kind: "originMismatch" };

export const envTokenStatus = Effect.fn("session.envTokenStatus")(function* (
  origin: string,
): Effect.fn.Return<EnvTokenStatus, never, CliIo> {
  const io = yield* CliIo;
  const token = io.envVar("MARUHI_TOKEN")?.trim();
  if (token === undefined || token.length === 0) {
    return { kind: "unset" };
  }
  if (REDACTED_PLACEHOLDER_TEXT.test(token)) {
    return { kind: "placeholder" };
  }
  const declared = io.envVar("MARUHI_TOKEN_ORIGIN");
  if (declared === undefined || declared.length === 0) {
    return { kind: "originMissing" };
  }
  const normalized = yield* normalizeHttpOrigin(declared, "MARUHI_TOKEN_ORIGIN", {
    fix: "the MARUHI_TOKEN_ORIGIN env var",
  }).pipe(
    Effect.map((value) => ({ ok: true, value }) as const),
    Effect.catch((error) => Effect.succeed({ ok: false, reason: error.message } as const)),
  );
  if (!normalized.ok) {
    return { kind: "originInvalid", reason: normalized.reason };
  }
  return normalized.value === origin ? { kind: "active" } : { kind: "originMismatch" };
});

export type SessionCredential = "server" | "mirror";

export const resolveSession = Effect.fn("session.resolveSession")(function* (
  origin: string,
  credential: SessionCredential = "server",
): Effect.fn.Return<CliSession, CliError, Keychain | CliIo | HttpClient.HttpClient> {
  const io = yield* CliIo;
  if (credential === "mirror") {
    const mirrorToken = io.envVar("MARUHI_MIRROR_TOKEN")?.trim();
    if (mirrorToken !== undefined && mirrorToken.length > 0) {
      return yield* sessionFromEnvToken({
        origin,
        token: mirrorToken,
        declaredOrigin: origin,
        variable: "MARUHI_MIRROR_TOKEN",
      });
    }
    return yield* keychainSession(origin, "the mirror");
  }
  const envToken = io.envVar("MARUHI_TOKEN")?.trim();
  if (envToken !== undefined && envToken.length > 0) {
    return yield* sessionFromEnvToken({
      origin,
      token: envToken,
      declaredOrigin: io.envVar("MARUHI_TOKEN_ORIGIN"),
      variable: "MARUHI_TOKEN",
    });
  }
  return yield* keychainSession(origin, null);
});

const keychainSession = Effect.fn("session.keychainSession")(function* (
  origin: string,
  what: string | null,
): Effect.fn.Return<CliSession, CliError, Keychain | CliIo> {
  const keychain = yield* Keychain;
  const stored = yield* keychain.get(tokenEntryName(origin));
  if (stored === null) {
    return yield* Effect.fail(
      what === null
        ? noSessionError(keychain.kind)
        : cliError(
            `Not logged in to ${what} ${origin}. Run \`maruhi login --server ${origin}\` (or, without a keychain, set MARUHI_MIRROR_TOKEN to a token issued there)`,
          ),
    );
  }
  const record = parseStoredToken(stored);
  if (record === null) {
    return yield* Effect.fail(
      hasRedactedPlaceholder(stored)
        ? cliError(redactedPlaceholderTokenMessage(keychain.kind))
        : cliError(
            `${tokenRecordNoun(keychain.kind)} is corrupt. Log in again with \`maruhi login\``,
          ),
    );
  }
  yield* warnNearExpiry(record.expiresAtMs, "Sign in again with `maruhi login` to rotate it");
  return {
    origin,
    token: record.token,
    userId: record.userId,
  } satisfies CliSession;
});

export function cryptoBackendUsable(): Effect.Effect<boolean> {
  return Effect.map(probeCryptoRoundTrip.pipe(Effect.exit), (exit) =>
    Exit.isSuccess(exit) ? exit.value : false,
  );
}

const probeCryptoRoundTrip = Effect.gen(function* () {
  const enc = yield* cryptoPromise("generateEncryptionKeyPair", () =>
    generateEncryptionKeyPair({ extractable: true }),
  );
  const sig = yield* cryptoPromise("generateSigningKeyPair", () =>
    generateSigningKeyPair({ extractable: true }),
  );
  const encSk = yield* cryptoEffect(() => exportEncryptionPrivateKey(enc.privateKey));
  const sigSeed = yield* cryptoEffect(() => exportSigningPrivateSeed(sig.privateKey));
  const encPub = yield* cryptoPromise("exportEncryptionPublicKey", () =>
    exportEncryptionPublicKey(enc.publicKey),
  );
  const sigPub = yield* cryptoPromise("exportSigningPublicKey", () =>
    exportSigningPublicKey(sig.publicKey),
  );
  yield* cryptoEffect(() => importEncryptionKeyPair({ publicKey: encPub, privateKey: encSk }));
  yield* cryptoEffect(() => importSigningKeyPair({ publicKey: sigPub, privateSeed: sigSeed }));
  yield* cryptoEffect(() => computeUserKeyFingerprint(encPub, sigPub));
  return true;
});

export const unsupportedCryptoCause =
  "This environment's WebCrypto does not support the algorithms maruhi's keys need (Ed25519 / HPKE), so the key cannot be loaded" as const;

export const retryOnSupportedRuntime = "Re-run on a supported runtime (a newer Bun / OS)" as const;

export const unsupportedCryptoMessage =
  `${unsupportedCryptoCause}. The stored key is most likely intact — do not delete it. ${retryOnSupportedRuntime}` as const;

function corruptOrEnvironmentMessage(entryName: string, kind: KeychainKind): Effect.Effect<string> {
  return Effect.map(cryptoBackendUsable(), (usable) =>
    usable ? corruptMasterKeyMessage(entryName, kind) : unsupportedCryptoMessage,
  );
}

function refusalFor(
  existing: string,
  entryName: string,
  refusal: string,
  kind: KeychainKind,
): Effect.Effect<string, never> {
  if (hasRedactedPlaceholder(existing)) {
    return Effect.succeed(redactedPlaceholderMasterKeyMessage(entryName, kind));
  }
  const record = parseStoredMasterKey(existing);
  if (record === null) {
    return Effect.succeed(unreadableMasterKeyMessage(existing, entryName, kind));
  }
  return importMasterKeys(record).pipe(
    Effect.as(refusal),
    Effect.catchTag("MasterKeyUnknownSuite", (error) =>
      Effect.succeed(foreignMasterKeyMessage(error.suite, entryName, kind)),
    ),
    Effect.catchTag("MasterKeyCorrupt", () => corruptOrEnvironmentMessage(entryName, kind)),
  );
}

function unreadableMasterKeyMessage(stored: string, entryName: string, kind: KeychainKind): string {
  return classifyUnreadableMasterKey(stored) === "foreign"
    ? foreignMasterKeyMessage(declaredSuiteOf(stored), entryName, kind)
    : corruptMasterKeyMessage(entryName, kind);
}

export const ensureNoStoredMasterKey = Effect.fn("session.ensureNoStoredMasterKey")(function* (
  session: CliSession,
  refusal: string,
): Effect.fn.Return<string, CliError, Keychain> {
  const keychain = yield* Keychain;
  const entryName = masterKeyEntryName(session.origin, session.userId);
  const existing = yield* keychain.get(entryName);
  if (existing !== null) {
    return yield* Effect.fail(
      cliError(yield* refusalFor(existing, entryName, refusal, keychain.kind)),
    );
  }
  return entryName;
});

export const storeMasterKeyGuarded = Effect.fn("session.storeMasterKeyGuarded")(function* (
  entryName: string,
  serialized: string,
  concurrentMessage: string = concurrentMasterKeyWrite,
): Effect.fn.Return<void, CliError, Keychain> {
  const keychain = yield* Keychain;
  const appeared = yield* keychain.get(entryName);
  if (appeared !== null) {
    return yield* Effect.fail(cliError(concurrentMessage));
  }
  yield* keychain.set(entryName, serialized);
  const stored = yield* keychain.get(entryName);
  if (stored !== serialized) {
    return yield* Effect.fail(cliError(concurrentMessage));
  }
});

const replaceMasterKeyGuarded = Effect.fn("session.replaceMasterKeyGuarded")(function* (input: {
  readonly entryName: string;
  readonly previous: string;
  readonly serialized: string;
}): Effect.fn.Return<void, CliError, Keychain> {
  const keychain = yield* Keychain;
  const current = yield* keychain.get(input.entryName);
  if (current !== input.previous) {
    return yield* Effect.fail(cliError(concurrentDeviceAddWrite));
  }
  yield* keychain.set(input.entryName, input.serialized);
  const stored = yield* keychain.get(input.entryName);
  if (stored !== input.serialized) {
    return yield* Effect.fail(cliError(concurrentDeviceAddWrite));
  }
});

const concurrentDeviceAddWrite =
  "Another process wrote this machine's device key while `maruhi device add` was running, so the new key was not stored and the key now in the keychain was left as it is. The request made for the new key is never approved (its fingerprint was not shown) and expires in 15 minutes. Run `maruhi key show` to see which key is stored now, then re-run `maruhi device add` alone" as const;

const concurrentMasterKeyWrite =
  "Another device key for this account was written to the keychain at the same time, so this key was not stored (nothing was left behind and no recovery code was issued). Run `maruhi key show` to see which key is stored now, and do not run `maruhi key generate` / `maruhi key recover` concurrently for the same account" as const;

function reserveInKeychainMessage(entryName: string, kind: KeychainKind): string {
  return `The key stored in ${describeStore(kind)} (entry ${entryName}) is marked as a reserve key, which lives only in the recovery ledger and is never used as a device key. Remove that entry, then add this machine as a device (\`maruhi device add\`) or run \`maruhi key recover\``;
}

export const storeMasterKeyAndReport = Effect.fn("session.storeMasterKeyAndReport")(
  function* (input: {
    readonly entryName: string;
    readonly serialized: string;
    readonly action: string;
    readonly fingerprintHex: string;
    readonly deviceAdd?: { readonly previous: string | null } | undefined;
  }): Effect.fn.Return<void, CliError, Keychain | CliIo> {
    if (parseStoredMasterKey(input.serialized)?.kind === "reserve") {
      return yield* Effect.fail(
        cliError(
          "Refused to store a reserve key in the keychain: the reserve key lives only in the recovery ledger. Report this as a maruhi bug",
        ),
      );
    }
    const previous = input.deviceAdd?.previous ?? null;
    yield* previous === null
      ? storeMasterKeyGuarded(
          input.entryName,
          input.serialized,
          input.deviceAdd === undefined ? concurrentMasterKeyWrite : concurrentDeviceAddWrite,
        )
      : replaceMasterKeyGuarded({
          entryName: input.entryName,
          previous,
          serialized: input.serialized,
        });
    const keychain = yield* Keychain;
    const io = yield* CliIo;
    yield* io.log(`${input.action} and stored it in ${describeStore(keychain.kind)}`);
    yield* io.log(`key fingerprint: ${input.fingerprintHex}`);
  },
);

export const loadMasterKeys = Effect.fn("session.loadMasterKeys")(function* (
  session: CliSession,
): Effect.fn.Return<MasterKeys, CliError, Keychain> {
  const keychain = yield* Keychain;
  const entryName = masterKeyEntryName(session.origin, session.userId);
  const stored = yield* keychain.get(entryName);
  if (stored === null) {
    return yield* Effect.fail(
      cliError(
        "No device key on this machine. If you still have a device of yours, add this machine as a device: `maruhi device add` here, then `maruhi device approve` there. If no device is left, open the reserve key with `maruhi key recover` (recovery code), `maruhi key recover --passkey` (a registered passkey), or `maruhi key recover --handoff` (approvals from your guardians). If this is your first key, generate one with `maruhi key generate`",
      ),
    );
  }
  const record = parseStoredMasterKey(stored);
  if (record === null) {
    return yield* Effect.fail(
      hasRedactedPlaceholder(stored)
        ? cliError(redactedPlaceholderMasterKeyMessage(entryName, keychain.kind))
        : cliError(unreadableMasterKeyMessage(stored, entryName, keychain.kind)),
    );
  }
  if (record.kind === "reserve") {
    return yield* Effect.fail(cliError(reserveInKeychainMessage(entryName, keychain.kind)));
  }
  return yield* importMasterKeys(record).pipe(
    Effect.catchTag("MasterKeyUnknownSuite", (error) =>
      Effect.fail(cliError(foreignMasterKeyMessage(error.suite, entryName, keychain.kind))),
    ),
    Effect.catchTag("MasterKeyCorrupt", () =>
      Effect.flatMap(corruptOrEnvironmentMessage(entryName, keychain.kind), (message) =>
        Effect.fail(cliError(message)),
      ),
    ),
  );
});

class MasterKeyCorrupt extends Data.TaggedError("MasterKeyCorrupt") {}

class MasterKeyUnknownSuite extends Data.TaggedError("MasterKeyUnknownSuite")<{
  readonly suite: string;
}> {}

export type MasterKeyImportError = MasterKeyCorrupt | MasterKeyUnknownSuite;

export const importMasterKeys = Effect.fn("session.importMasterKeys")(function* (
  record: StoredMasterKey,
): Effect.fn.Return<MasterKeys, MasterKeyImportError> {
  if (record.suite !== SUITE_ID) {
    return yield* Effect.fail(new MasterKeyUnknownSuite({ suite: record.suite }));
  }
  const encPub = decodeHex(record.encPubHex);
  const encSk = decodeHex(Redacted.value(record.encSkHex));
  const sigPub = decodeHex(record.sigPubHex);
  const sigSeed = decodeHex(Redacted.value(record.sigSkSeedHex));
  if (encPub === null || encSk === null || sigPub === null || sigSeed === null) {
    return yield* Effect.fail(new MasterKeyCorrupt());
  }
  const encKeyPair = yield* cryptoEffect(() =>
    importEncryptionKeyPair({ publicKey: encPub, privateKey: encSk }),
  ).pipe(Effect.mapError(() => new MasterKeyCorrupt()));
  const sigKeyPair = yield* cryptoEffect(() =>
    importSigningKeyPair({ publicKey: sigPub, privateSeed: sigSeed }),
  ).pipe(Effect.mapError(() => new MasterKeyCorrupt()));
  const fingerprintHex = yield* userKeyFingerprintHex(encPub, sigPub).pipe(
    Effect.mapError(() => new MasterKeyCorrupt()),
  );
  return { record, encKeyPair, sigKeyPair, fingerprintHex } satisfies MasterKeys;
});
