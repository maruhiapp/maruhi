// Resolution of the authenticated session (maruhi token) and the master key.
//
// Token resolution order: the MARUHI_TOKEN env var (a read-only path for
// keychain-less environments and CI; userId is resolved via /auth/me) → the
// OS keychain.
// The master private key is keychain-only (no env-var path — v1 does not
// create a route that puts key material into the process environment.
// session-11.md handoff).

import type { EncryptionKeyPair, SigningKeyPair } from "@maruhi/crypto";
import {
  computeUserKeyFingerprint,
  decodeHex,
  encodeHex,
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
import { Data, Effect, Redacted } from "effect";
import type { HttpClient } from "effect/unstable/http";

import { makeApiClient } from "./api.ts";
import type { CliConfig } from "./config.ts";
import { formatUtcDate } from "./display.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
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

/** A resolved authenticated session against one server. */
export interface CliSession {
  /** Normalized server origin (keychain scoping key and API base URL). */
  readonly origin: string;
  readonly token: Redacted.Redacted<string>;
  readonly userId: string;
}

/**
 * The master keypair loaded from the keychain, imported and ready to use.
 *
 * `encKeyPair` / `sigKeyPair` are not wrapped in `Redacted`: both are
 * CryptoKeys imported with `extractable: false`, and WebCrypto has no way to
 * take the value out (already opaque). What gets wrapped is `record`, which
 * holds hex.
 */
export interface MasterKeys {
  readonly record: StoredMasterKey;
  readonly encKeyPair: EncryptionKeyPair;
  readonly sigKeyPair: SigningKeyPair;
  readonly fingerprintHex: string;
}

/**
 * Whether the hostname is loopback: localhost / ::1 (including the URL's
 * bracketed form) / an IPv4 literal in 127.0.0.0/8 (DNS names and other
 * notations do not qualify). The decision of "where may http be allowed" is
 * concentrated in this one function inside the CLI (if the rule split across
 * server origins — normalizeHttpOrigin below — and OIDC issuer URLs —
 * oidc-github.ts — a future change that fixed only one side would silently
 * leave the other behind).
 */
export function isLoopbackHostname(hostname: string): boolean {
  if (hostname === "localhost" || hostname === "::1" || hostname === "[::1]") {
    return true;
  }
  const match = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(hostname);
  return match !== null && match.slice(1).every((octet) => Number(octet) <= 255);
}

/**
 * Validates and normalizes a base URL: https anywhere, http only on loopback
 * (tokens travel in cleartext otherwise; wrangler dev and mock test servers
 * on localhost still pass). `label` names the URL in error messages.
 */
export function normalizeHttpOrigin(
  raw: string,
  label: string,
  /**
   * The value's origin. For anything but the command line (config, env var)
   * it is not "a typo", so instead of a usage error (2) it says where to fix.
   */
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
    // The URL itself is not returned (a URL with embedded credentials is one possible written shape)
    return reject(`Cannot parse ${label} (use a URL starting with https://)`);
  }
  // No branch returns the URL (it could carry credentials in the shape
  // `http://user:token@host/x?token=…`). It is a usage error, so the exit code
  // is also aligned on 2
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

/**
 * Resolves the server base URL: --server flag → config. Fails with guidance.
 */
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

/**
 * Guidance for not-logged-in. Inside an agent session, "run it inside agent"
 * is off the mark (you are already inside one), so it only says the store is
 * empty.
 */
function noSessionError(kind: KeychainKind): CliError {
  return cliError(
    kind === "agent"
      ? "Not logged in. Run `maruhi login` (this agent session holds no token yet; it is discarded when the session ends)"
      : "Not logged in. Run `maruhi login` (in environments without a keychain, run it inside `maruhi agent -- <shell>`, or pass a token via the MARUHI_TOKEN env var)",
  );
}

/**
 * The window for the early expiry warning (ruling CL — warn from 14 days
 * remaining; drafted value). Makes expiry (401) observable ahead of time
 * instead of a "sudden stop" — in CI especially, this warning stays in the
 * job log and lets an operator plant a re-issuance before the 401.
 */
const TOKEN_EXPIRY_WARNING_WINDOW_MS = 14 * 24 * 60 * 60 * 1000;

/**
 * Emits one line to stderr when the expiry enters the warning window
 * (ruling CL).
 *
 * - stderr is used to keep stdout machine-readable (not mixing into the
 *   output of commands that pipe values / JSON — the same discipline as
 *   nextStepHint)
 * - Unknown expiry (undefined — old servers / old records) and expiry already
 *   in the past by local judgment (the next request's 401 says so — no
 *   double-saying) emit nothing
 * - Display goes through display.ts's total formatter (the server-declared
 *   unbounded number)
 */
function warnNearExpiry(
  expiresAtMs: number | undefined,
  reissueHint: string,
): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    if (expiresAtMs === undefined) {
      return;
    }
    const remainingMs = expiresAtMs - Date.now();
    if (remainingMs <= 0 || remainingMs > TOKEN_EXPIRY_WARNING_WINDOW_MS) {
      return;
    }
    const days = Math.ceil(remainingMs / (24 * 60 * 60 * 1000));
    yield* logWarning(
      `the API token expires on ${formatUtcDate(expiresAtMs)} (UTC) — ${days === 1 ? "1 day" : `${days} days`} left. ${reissueHint}`,
    );
  });
}

/**
 * Session resolution via the MARUHI_TOKEN path (for keychain-less
 * environments and CI).
 *
 * The env var is the only entry point where a plaintext string arrives, so it
 * is wrapped at the door and afterwards flows only as a {@link CliSession}
 * Redacted.
 */
function sessionFromEnvToken(input: {
  /** The value with surrounding whitespace dropped (already trimmed by the caller — the same value is used for checks and for sending). */
  readonly token: string;
  readonly origin: string;
  readonly declaredOrigin: string | undefined;
}): Effect.Effect<CliSession, CliError, CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    // If the placeholder itself was supplied, name the reason before any
    // traffic. Now that `Redacted` exists, pasting the "<redacted:maruhi-token>"
    // seen in output into an env var is a realistic path, and sending it
    // as-is produces a 401 — landing the user in guidance for a **different
    // cause** ("check revocation, scope, and the connection target") (emit the
    // same diagnosis for the same value as the keychain side)
    if (REDACTED_PLACEHOLDER_TEXT.test(input.token)) {
      return yield* Effect.fail(cliError(redactedPlaceholderEnvTokenMessage));
    }
    const envToken = Redacted.make(input.token, { label: "maruhi-token" });
    // MARUHI_TOKEN is bound to the connection target origin: without this
    // requirement, a Bearer token would be sent to any origin resolved by
    // --server / config (token leakage to an attacker origin the user was led
    // to). The target origin must be declared via MARUHI_TOKEN_ORIGIN and the
    // token is sent only when it matches the resolved origin
    if (input.declaredOrigin === undefined || input.declaredOrigin.length === 0) {
      return yield* Effect.fail(
        cliError(
          "Using MARUHI_TOKEN requires MARUHI_TOKEN_ORIGIN to name the target server origin (so the token is never sent to an unintended origin)",
        ),
      );
    }
    // An env var is not the command line either (say where to fix)
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
    // Since W3a (the default TTL in AUTH_SPEC §6), the most likely cause of
    // this 401 in routinely unattended environments is **expiry** (every token
    // dies at 365 days max). The env-var path's fix differs from the
    // keychain's — "re-issue on a workstation and swap the env value" — so
    // instead of reusing failure.ts's generic 401 guidance (`maruhi login`
    // only), it names a real procedure that can fetch the raw value
    // (--show-token — ruling CK) (ruling CJ — session-44 §11, §12)
    const me = yield* client.auth
      .me({})
      .pipe(
        Effect.mapError(() =>
          cliError(
            "Authentication with MARUHI_TOKEN failed (the token may be expired or revoked, or the scope or target server may not match). Issue a new token with `maruhi login --token-name <name> --show-token` on an interactive workstation terminal, then update the MARUHI_TOKEN value in this environment",
          ),
        ),
      );
    // The early expiry warning (ruling CL): /auth/me is called on this path
    // every run anyway, so tokenExpiresAtMs (ruling CI's self-disclosure) is
    // already at hand with no extra request. It stays in CI job logs and lets
    // a re-issuance be planted before a 401 halts the job
    yield* warnNearExpiry(
      me.tokenExpiresAtMs,
      "Re-issue it with `maruhi login --token-name <name> --show-token` on a workstation and update MARUHI_TOKEN before it stops working",
    );
    return { origin: input.origin, token: envToken, userId: me.userId } satisfies CliSession;
  });
}

/**
 * Whether MARUHI_TOKEN works for this origin.
 *
 * The check exists so logout guidance (the next step of
 * {@link resolveSession}) does not diverge from session resolution, and the
 * rules (trim / placeholder detection / origin binding) are unified here.
 * Every state other than `active` **fails before reaching the keychain**, so
 * "you are still authenticated" must never be said. The fix differs per
 * cause (add / fix / delete), so the states are distinguished rather than
 * lumped together.
 */
export type EnvTokenStatus =
  | { readonly kind: "unset" }
  | { readonly kind: "active" }
  | { readonly kind: "placeholder" }
  | { readonly kind: "originMissing" }
  /** The shape is unusable. **The reason carries the normalization side's
   * wording verbatim** — if we phrased "not parseable as a URL" vs "http: is
   * not loopback" ourselves, it would diverge from the rejection reason the
   * next command emits */
  | { readonly kind: "originInvalid"; readonly reason: string }
  | { readonly kind: "originMismatch" };

export function envTokenStatus(origin: string): Effect.Effect<EnvTokenStatus, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const token = io.envVar("MARUHI_TOKEN")?.trim();
    if (token === undefined || token.length === 0) {
      return { kind: "unset" };
    }
    // The state where the placeholder itself was pasted (sessionFromEnvToken rejects it by name)
    if (REDACTED_PLACEHOLDER_TEXT.test(token)) {
      return { kind: "placeholder" };
    }
    const declared = io.envVar("MARUHI_TOKEN_ORIGIN");
    if (declared === undefined || declared.length === 0) {
      return { kind: "originMissing" };
    }
    // A shape that is unusable vs. a shape that is correct but points at
    // another origin have different fixes. The former's reason **carries the
    // normalization side's wording verbatim** (rephrasing it ourselves would
    // diverge from the rejection reason the next command emits)
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
}

/**
 * Resolves the authenticated session for `origin`. The MARUHI_TOKEN env path
 * resolves the user id via `GET /auth/me` (the keychain record carries it).
 */
export function resolveSession(
  origin: string,
): Effect.Effect<CliSession, CliError, Keychain | CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    // Surrounding whitespace is dropped exactly once here. Newlines and
    // spaces mixed in by pasting are perfectly normal, and using different
    // values for the check and for sending would (a) make the placeholder
    // detection disagree with the value sent, and (b) make a
    // whitespace-bearing value's success depend on the header normalization
    // implementation. An all-whitespace MARUHI_TOKEN is treated as unset — no
    // round-trip with an empty token
    const envToken = io.envVar("MARUHI_TOKEN")?.trim();
    if (envToken !== undefined && envToken.length > 0) {
      return yield* sessionFromEnvToken({
        origin,
        token: envToken,
        declaredOrigin: io.envVar("MARUHI_TOKEN_ORIGIN"),
      });
    }
    const keychain = yield* Keychain;
    const stored = yield* keychain.get(tokenEntryName(origin));
    if (stored === null) {
      return yield* Effect.fail(noSessionError(keychain.kind));
    }
    const record = parseStoredToken(stored);
    if (record === null) {
      // A stored placeholder is distinguished from "a corrupt record":
      // neither the cause (a maruhi bug) nor the recovery steps (a record
      // written by an old build is overwritten by re-login) survive a generic
      // "it is corrupt"
      return yield* Effect.fail(
        hasRedactedPlaceholder(stored)
          ? cliError(redactedPlaceholderTokenMessage(keychain.kind))
          : cliError(
              `${tokenRecordNoun(keychain.kind)} is corrupt. Log in again with \`maruhi login\``,
            ),
      );
    }
    // The early expiry warning (ruling CL): the expiry was saved to the
    // record at login (expiresAtMs in keychain.ts), so a local check without
    // traffic suffices. Old records (pre-W3a logins) lack it = no warning
    // (added on re-login)
    yield* warnNearExpiry(record.expiresAtMs, "Sign in again with `maruhi login` to rotate it");
    return {
      origin,
      token: record.token,
      userId: record.userId,
    } satisfies CliSession;
  });
}

/**
 * The environment check before declaring "the record is corrupt".
 *
 * {@link importMasterKeys} failure happens **both when the key material is
 * broken and when this environment's WebCrypto lacks the algorithms needed
 * (Ed25519 / HPKE)** (the crypto side folds exceptions uniformly into
 * failure). Guiding to "please delete it" without the distinction would have
 * a healthy key deleted and lose the ability to decrypt forever.
 *
 * So **try the same operation with a fresh key**: if generate → export →
 * import does not round-trip with a disposable key, the cause is the
 * environment, not the stored key.
 *
 * **Trying generation alone is not enough**: the failure this guards against
 * happens on the import side (`importKey` / HPKE's DeserializePrivateKey). In
 * an environment that can generate but cannot import, "generation works = the
 * environment is fine" would be a wrong verdict that recommends deleting a
 * healthy key. Check in the same order {@link importMasterKeys} steps
 * through. The check runs only on the failure path, so normal execution pays
 * nothing.
 */
export function cryptoBackendUsable(): Effect.Effect<boolean> {
  return Effect.tryPromise({
    try: probeCryptoRoundTrip,
    catch: () => null,
  }).pipe(Effect.catch(() => Effect.succeed(false)));
}

/** Round-trips generate → export → import with a disposable key (key material never leaves). */
async function probeCryptoRoundTrip(): Promise<boolean> {
  const enc = await generateEncryptionKeyPair({ extractable: true });
  const sig = await generateSigningKeyPair({ extractable: true });
  const encSk = await exportEncryptionPrivateKey(enc.privateKey);
  const sigSeed = await exportSigningPrivateSeed(sig.privateKey);
  if (!encSk.ok || !sigSeed.ok) {
    return false;
  }
  const encPub = await exportEncryptionPublicKey(enc.publicKey);
  const sigPub = await exportSigningPublicKey(sig.publicKey);
  const encPair = await importEncryptionKeyPair({ publicKey: encPub, privateKey: encSk.value });
  const sigPair = await importSigningKeyPair({ publicKey: sigPub, privateSeed: sigSeed.value });
  const fingerprint = await computeUserKeyFingerprint(encPub, sigPub);
  return encPair.ok && sigPair.ok && fingerprint.ok;
}

/**
 * The common part when the environment is the cause (the cause, and the next
 * step identical across paths).
 *
 * **"What is intact" differs per path**, so that part is not shared: only the
 * keychain path can point at the stored key — saying "do not delete the
 * stored key" under recover (nothing stored yet) or generate (about to create
 * one) would be a diagnosis pointing at something that does not exist.
 */
export const unsupportedCryptoCause =
  "This environment's WebCrypto does not support the algorithms maruhi's keys need (Ed25519 / HPKE), so the key cannot be loaded" as const;

/** The next step when the environment is the cause (identical across paths). */
export const retryOnSupportedRuntime = "Re-run on a supported runtime (a newer Bun / OS)" as const;

/** The environment-caused wording for an unloadable keychain key (**never have the user delete** is the point). */
export const unsupportedCryptoMessage =
  `${unsupportedCryptoCause}. The stored key is most likely intact — do not delete it. ${retryOnSupportedRuntime}` as const;

/**
 * The wording when judged corrupt. Decided **only after confirming the
 * environment is not the cause**.
 *
 * Another format (an unknown suite) is not corruption, so it never reaches
 * this function — the caller's {@link Effect.catchTag} tells the branches
 * apart by type.
 */
function corruptOrEnvironmentMessage(entryName: string, kind: KeychainKind): Effect.Effect<string> {
  return Effect.map(cryptoBackendUsable(), (usable) =>
    usable ? corruptMasterKeyMessage(entryName, kind) : unsupportedCryptoMessage,
  );
}

/**
 * Choosing the refusal wording for an existing record.
 *
 * "It already exists" may be said only **when a genuinely usable key is
 * there**. Returning it for a record whose shape checks out but whose key
 * material cannot be read would contradict the facts and leave no exit,
 * while blocking all of generate / recover / show. The decision does not
 * stop at the stored shape — it actually tries importing (once per command
 * run).
 */
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
    // Importable = a genuinely usable key. This alone is the true overwrite refusal
    Effect.as(refusal),
    // The exit differs by why it cannot be read (corrupt / foreign format /
    // environment). Split by tag — if a new failure kind appears, the type
    // check points here
    Effect.catchTag("MasterKeyUnknownSuite", (error) =>
      Effect.succeed(foreignMasterKeyMessage(error.suite, entryName, kind)),
    ),
    Effect.catchTag("MasterKeyCorrupt", () => corruptOrEnvironmentMessage(entryName, kind)),
  );
}

/**
 * Wording for an unreadable record. **Deletion is recommended only when it
 * is judged corrupt** (never have a record written by a future version
 * deleted — see the classification in keychain.ts).
 */
function unreadableMasterKeyMessage(stored: string, entryName: string, kind: KeychainKind): string {
  return classifyUnreadableMasterKey(stored) === "foreign"
    ? foreignMasterKeyMessage(declaredSuiteOf(stored), entryName, kind)
    : corruptMasterKeyMessage(entryName, kind);
}

/**
 * Fails when a master key is already stored for (origin, userId); returns the
 * keychain entry name otherwise. The shared overwrite-protection guard of
 * keygen / recover (losing the key means losing the ability to decrypt, so
 * overwriting is always refused).
 *
 * Placeholder records are distinguished here too: this guard is the
 * **first** place hit inside the read boundary (both `key generate` and
 * `key recover` stop here), and saying "a key already exists" would report an
 * unusable key as present while the true diagnosis (the entry name to
 * delete) would not surface until a different command.
 */
export function ensureNoStoredMasterKey(
  session: CliSession,
  refusal: string,
): Effect.Effect<string, CliError, Keychain> {
  return Effect.gen(function* () {
    const keychain = yield* Keychain;
    const entryName = masterKeyEntryName(session.origin, session.userId);
    const existing = yield* keychain.get(entryName);
    if (existing !== null) {
      // "It already exists" may be said only **when a readable record
      // actually exists**. Returning the refusal wording (a usable key exists)
      // for an unreadable record would contradict the facts and leave no exit
      // while blocking all of generate / recover / show
      return yield* Effect.fail(
        cliError(yield* refusalFor(existing, entryName, refusal, keychain.kind)),
      );
    }
    return entryName;
  });
}

/**
 * Stores a master-key record, re-checking absence immediately before the write
 * and verifying afterwards that the stored record is the one just written.
 *
 * Why "re-check just before storing + read back just after": the
 * overwrite-protection guard ({@link ensureNoStoredMasterKey}) only reads and
 * takes no lock, and key generation (WebCrypto ×6) plus a re-import
 * self-check sit in between, so a window of tens of ms opens between the
 * check and the write. `Bun.secrets.set` is an unconditional put with no
 * compare-and-swap or create-if-absent, and the entry name is deterministic
 * from (origin, userId) — so concurrent `maruhi key generate` on the same
 * account both observe "no key", both write, and last-writer-wins silently
 * loses one key.
 *
 * Since the OS keychain offers no atomic conditional write, this function
 * does not close the window — it **minimizes it and refuses to stay silent
 * about failure**: if the read-back is not our record, it detects a
 * concurrent overwrite and fails (the caller then never proceeds to issuing
 * a recovery code, so the inconsistency of "a recovery blob registered for a
 * discarded key" never happens). The remaining window is between the re-check
 * and the write only; if another process's whole write lands there, both can
 * still succeed — and in that case the surviving key and its recovery blob
 * land on the consistent side.
 */
export function storeMasterKeyGuarded(
  entryName: string,
  serialized: string,
  concurrentMessage: string = concurrentMasterKeyWrite,
): Effect.Effect<void, CliError, Keychain> {
  return Effect.gen(function* () {
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
}

/**
 * Replaces the existing key **only when it matches the value we saw**
 * (`device add --replace` — DK K13-8). Same detection as
 * `storeMasterKeyGuarded` (read → write → read back) — spots a write by
 * another process in between. Never shaped as delete-the-old-key-then-store
 * (a failure after deleting would lose the key).
 */
function replaceMasterKeyGuarded(input: {
  readonly entryName: string;
  readonly previous: string;
  readonly serialized: string;
}): Effect.Effect<void, CliError, Keychain> {
  return Effect.gen(function* () {
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
}

/**
 * The wording when another write is found mid-way through `device add`'s
 * store / replace (shared by storing with no key and `--replace`). The
 * request was created before storing, but the new key's FP has not been
 * shown yet, so it is never approved and the request expires (DK K13-8 /
 * K13-14).
 */
const concurrentDeviceAddWrite =
  "Another process wrote this machine's device key while `maruhi device add` was running, so the new key was not stored and the key now in the keychain was left as it is. The request made for the new key is never approved (its fingerprint was not shown) and expires in 15 minutes. Run `maruhi key show` to see which key is stored now, then re-run `maruhi device add` alone" as const;

/**
 * The wording when a concurrent write is detected. The point is there is
 * nothing to copy down: this key was never stored anywhere and no recovery
 * code was issued, so no cleanup is needed — the only thing to do is "re-run
 * one at a time".
 */
const concurrentMasterKeyWrite =
  "Another device key for this account was written to the keychain at the same time, so this key was not stored (nothing was left behind and no recovery code was issued). Run `maruhi key show` to see which key is stored now, and do not run `maruhi key generate` / `maruhi key recover` concurrently for the same account" as const;

/** The wording when a reserve key bearing the mark sits in the keychain (DK K16). */
function reserveInKeychainMessage(entryName: string, kind: KeychainKind): string {
  return `The key stored in ${describeStore(kind)} (entry ${entryName}) is marked as a reserve key, which lives only in the recovery ledger and is never used as a device key. Remove that entry, then add this machine as a device (\`maruhi device add\`) or run \`maruhi key recover\``;
}

/**
 * {@link storeMasterKeyGuarded} + the 2 success lines (naming the store and
 * the FP). The common ending of `key generate` / `key recover` — never shaped
 * so the store name ({@link describeStore}) is fixed on only one side.
 */
export function storeMasterKeyAndReport(input: {
  readonly entryName: string;
  readonly serialized: string;
  /** What was done (sentence-initial). E.g. "Generated your master key" */
  readonly action: string;
  readonly fingerprintHex: string;
  /**
   * Whether this store came from `device add` (uses `device add`'s
   * concurrent-write wording — the request is already created: DK K13-14).
   * `previous` is the stored value of the key being replaced (`--replace` —
   * replaced only when it matches).
   */
  readonly deviceAdd?: { readonly previous: string | null } | undefined;
}): Effect.Effect<void, CliError, Keychain | CliIo> {
  return Effect.gen(function* () {
    if (parseStoredMasterKey(input.serialized)?.kind === "reserve") {
      // A reserve key is never put in the keychain (CRYPTO_SPEC §8 — DK K16; layered defense of how the type is closed, K4-1 a-5)
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
  });
}

/** Loads and imports the master keypair for (origin, userId) from the keychain. */
export function loadMasterKeys(session: CliSession): Effect.Effect<MasterKeys, CliError, Keychain> {
  return Effect.gen(function* () {
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
      // The reserve key lives only in the recovery ledger (CRYPTO_SPEC §8 —
      // DK K16). A marked key sitting in the keychain is a breach of the store
      // path, and it is not used as a device key for signing
      return yield* Effect.fail(cliError(reserveInKeychainMessage(entryName, keychain.kind)));
    }
    // A record that parsed but cannot be imported as key material is the
    // same dead end (the overwrite-protection guard refuses every command),
    // so the same exit is shown. The reason for splitting by cause is the
    // same as refusalFor's: a corrupt record can be deleted and regenerated,
    // but an unknown suite (a key a future version wrote) is lost even to a
    // newer maruhi once deleted. To keep the two commands from emitting
    // different guidance for the same state, the mapping is aligned to that
    // side too. importMasterKeys itself is also used as the pre-store
    // self-check — that side has no existing entry and deletion guidance
    // would be off the mark, so the mapping happens here
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
}

/**
 * Cannot import the key material itself ({@link importMasterKeys} failure).
 *
 * Distinguished **by type** so the caller can swap the wording by "which
 * artifact is broken" — for the same failure, what to point at and the
 * recovery steps differ between a keychain record and a recovery blob.
 *
 * It is a tag rather than a value-identity check (`error === corruptKeyError`)
 * because getting this branch wrong flips "safe to delete / must not delete"
 * and leads straight to permanent key loss. Let the type checker enforce
 * exhaustiveness.
 */
// It carries no breakdown (hex that cannot be interpreted / WebCrypto that
// cannot read): the caller guides to the same exit either way, so an unread
// payload is not carried
class MasterKeyCorrupt extends Data.TaggedError("MasterKeyCorrupt")<Record<never, never>> {}

/** The record claims a suite this version does not know (not corruption). */
class MasterKeyUnknownSuite extends Data.TaggedError("MasterKeyUnknownSuite")<{
  readonly suite: string;
}> {}

/**
 * {@link importMasterKeys} failure. The caller decides the wording per path.
 *
 * The class itself is not exported: callers split on the `Effect.catchTag`
 * tag name, so no constructor is needed — exporting it would make it "a
 * failure anyone can create" (the source stays singular).
 */
export type MasterKeyImportError = MasterKeyCorrupt | MasterKeyUnknownSuite;

/**
 * Imports a stored master-key record into usable (non-extractable) key
 * objects. keygen also uses it as the pre-store self-check (never writes a
 * broken record).
 */
export function importMasterKeys(
  record: StoredMasterKey,
): Effect.Effect<MasterKeys, MasterKeyImportError> {
  return Effect.gen(function* () {
    if (record.suite !== SUITE_ID) {
      // A future suite's key record is never silently interpreted as v1
      return yield* Effect.fail(new MasterKeyUnknownSuite({ suite: record.suite }));
    }
    const encPub = decodeHex(record.encPubHex);
    // Why unwrap: importing the key material (hex → bytes → non-extractable
    // CryptoKey). The resulting encKeyPair / sigKeyPair are
    // extractable: false, so keys that passed through here are already opaque
    // (not a Redacted target — see the MasterKeys note)
    const encSk = decodeHex(Redacted.value(record.encSkHex));
    const sigPub = decodeHex(record.sigPubHex);
    const sigSeed = decodeHex(Redacted.value(record.sigSkSeedHex));
    if (encPub === null || encSk === null || sigPub === null || sigSeed === null) {
      return yield* Effect.fail(new MasterKeyCorrupt());
    }
    // A WebCrypto reject (an import exception for broken key material) is also treated as corrupt
    const encKeyPair = yield* Effect.tryPromise({
      try: () => importEncryptionKeyPair({ publicKey: encPub, privateKey: encSk }),
      catch: () => new MasterKeyCorrupt(),
    });
    const sigKeyPair = yield* Effect.tryPromise({
      try: () => importSigningKeyPair({ publicKey: sigPub, privateSeed: sigSeed }),
      catch: () => new MasterKeyCorrupt(),
    });
    const fingerprint = yield* Effect.tryPromise({
      try: () => computeUserKeyFingerprint(encPub, sigPub),
      catch: () => new MasterKeyCorrupt(),
    });
    if (!encKeyPair.ok || !sigKeyPair.ok || !fingerprint.ok) {
      return yield* Effect.fail(new MasterKeyCorrupt());
    }
    return {
      record,
      encKeyPair: encKeyPair.value,
      sigKeyPair: sigKeyPair.value,
      fingerprintHex: encodeHex(fingerprint.value),
    } satisfies MasterKeys;
  });
}
