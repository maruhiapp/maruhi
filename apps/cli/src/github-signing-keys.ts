// The backing source `github-signing-keys` (CRYPTO_SPEC §6.5 — IV2).
//
// Machine-checks via GitHub's public API whether the peer's
// (acceptor's / inviter's) maruhi sig public key is included in the
// **SSH signing key** list of the specifically named GitHub login.
//
// Invariants:
// - The only information sent is the **login** (never project, keys,
//   values, or usage). The host is fixed to `api.github.com` with no
//   config-based swap point (tests swap at the HttpClient layer —
//   same boundary as sync-http.ts)
// - Unauthenticated (the maruhi CLI holds no GitHub token at all —
//   AUTH_SPEC §4)
// - **fail-closed**: neither a check **failure** (key absent) nor an
//   **inability** (unfetchable, rate-limited, offline, unknown login)
//   has any effect beyond "return to the ceremony". A backing source
//   can only be grounds to **skip** the ceremony — never grounds to
//   refuse or to excuse. Hence this module never returns CliError and
//   returns results in a closed type
// - Responses are treated as third-party data: shape checked by
//   Effect Schema, key lines parsed by `packages/crypto`'s
//   parseOpenSshEd25519PublicKey (pinned by test vectors). Kinds other
//   than `ssh-ed25519` are skipped as out of scope

import { fromCryptoResult } from "@maruhi/core";
import { decodeHex, encodeHex, parseOpenSshEd25519PublicKey } from "@maruhi/crypto";
import { Duration, Effect, Schema } from "effect";
import { HttpClient, HttpClientRequest } from "effect/http";

import { GITHUB_LOGIN } from "./invite-link.ts";
import { CLI_VERSION } from "./version.ts";

/** The fixed host (not swappable). */
const GITHUB_API_ORIGIN = "https://api.github.com";

/** Time allowed for one inquiry (a check is "grounds to skip", so do not wait long). */
const REQUEST_TIMEOUT = Duration.seconds(10);

/** One element of GitHub's `GET /users/{login}/ssh_signing_keys` (only the fields needed). */
const SigningKeyEntry = Schema.Struct({ key: Schema.String });
const SigningKeysResponse = Schema.Array(SigningKeyEntry);
const decodeSigningKeys = Schema.decodeUnknownEffect(SigningKeysResponse);

/** The check's result (a closed type — the caller decides whether to return to the ceremony). */
export type BackingVerdict =
  /** The named login's signing-key list contains the target sig public key byte-for-byte. */
  | { readonly kind: "match" }
  /** The list was fetched but the target key is absent (the peer is unregistered / registered a different key). */
  | { readonly kind: "not-registered" }
  /** The login does not exist on GitHub (404). */
  | { readonly kind: "no-user" }
  /** Unfetchable (offline, rate-limited, response of the wrong shape). The reason is a short display string. */
  | { readonly kind: "unavailable"; readonly detail: string };

/** Result of fetching the list (the stage before checking — key lines not yet parsed). */
type SigningKeysFetch =
  | { readonly kind: "entries"; readonly entries: readonly { readonly key: string }[] }
  | { readonly kind: "no-user" }
  | { readonly kind: "unavailable"; readonly detail: string };

/** `GET /users/{login}/ssh_signing_keys` (unauthenticated, fixed host, with timeout). */
function fetchSigningKeys(
  login: string,
): Effect.Effect<SigningKeysFetch, never, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const client = yield* HttpClient.HttpClient;
    const request = HttpClientRequest.get(
      `${GITHUB_API_ORIGIN}/users/${encodeURIComponent(login)}/ssh_signing_keys`,
    ).pipe(
      HttpClientRequest.setHeader("accept", "application/vnd.github+json"),
      HttpClientRequest.setHeader("user-agent", `maruhi-cli/${CLI_VERSION}`),
    );
    const outcome = yield* client.execute(request).pipe(
      Effect.flatMap((response) =>
        Effect.map(response.text, (text) => ({ status: response.status, text })),
      ),
      Effect.timeout(REQUEST_TIMEOUT),
      Effect.map((value) => ({ ok: true, value }) as const),
      // Transport-layer failure / timeout: no body or headers are carried in (only a short kind)
      Effect.catch((error) =>
        Effect.succeed({ ok: false, detail: describeFailure(error) } as const),
      ),
    );
    if (!outcome.ok) {
      return { kind: "unavailable", detail: outcome.detail } as const;
    }
    const { status, text } = outcome.value;
    if (status === 404) {
      return { kind: "no-user" } as const;
    }
    if (status !== 200) {
      const rateLimited = status === 403 || status === 429 ? " (rate limited)" : "";
      return {
        kind: "unavailable",
        detail: `github.com answered ${status}${rateLimited}`,
      } as const;
    }
    const entries = yield* parseEntries(text);
    return entries === null
      ? ({ kind: "unavailable", detail: "github.com's response had an unexpected shape" } as const)
      : ({ kind: "entries", entries } as const);
  });
}

/**
 * Checks whether the `sigPubHex` key is contained in the login's
 * signing-key list. Failures and inabilities alike are returned in
 * the type, never as a CliError (the fail-closed definition above).
 */
export function checkSigningKeyBacking(input: {
  readonly login: string;
  readonly sigPubHex: string;
}): Effect.Effect<BackingVerdict, never, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    if (!GITHUB_LOGIN.test(input.login)) {
      return { kind: "unavailable", detail: "the login is not a valid GitHub login" } as const;
    }
    const target = decodeHex(input.sigPubHex);
    if (target === null) {
      return { kind: "unavailable", detail: "the signing key to check is malformed" } as const;
    }
    const fetched = yield* fetchSigningKeys(input.login);
    if (fetched.kind !== "entries") {
      return fetched;
    }
    const targetHex = encodeHex(target);
    for (const entry of fetched.entries) {
      // Kinds other than ssh-ed25519 (RSA / ECDSA / sk-*) and broken
      // lines are out of scope — an InvalidInput is skipped, the same
      // as the pre-bridge `!ok` check; another kind is an invariant
      // break and dies
      const matched = yield* fromCryptoResult(parseOpenSshEd25519PublicKey(entry.key)).pipe(
        Effect.map((key) => encodeHex(key) === targetHex),
        Effect.catchTag("CryptoInvalidInput", () => Effect.succeed(false)),
        Effect.orDie,
      );
      if (matched) {
        return { kind: "match" } as const;
      }
    }
    return { kind: "not-registered" } as const;
  });
}

/** Interprets the response body (a JSON array + `key` string; null when the shape differs). */
function parseEntries(text: string): Effect.Effect<readonly { readonly key: string }[] | null> {
  return Effect.gen(function* () {
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      return null;
    }
    return yield* decodeSigningKeys(json).pipe(
      Effect.map((entries) => entries as readonly { readonly key: string }[]),
      Effect.orElseSucceed(() => null),
    );
  });
}

/** Description of a transport-layer failure (kind only; no body, headers, or URL). */
function describeFailure(error: unknown): string {
  const tag =
    typeof error === "object" && error !== null
      ? (error as Record<string, unknown>)["_tag"]
      : undefined;
  if (tag === "TimeoutError") {
    return "github.com did not answer in time";
  }
  return typeof tag === "string"
    ? `could not reach github.com (${tag})`
    : "could not reach github.com";
}

/** Short display text for a check result (presenting the reason to return to the ceremony). */
export function describeBackingFallback(login: string, verdict: BackingVerdict): string {
  switch (verdict.kind) {
    case "match":
      return `the key is registered as a signing key on github.com/${login}`;
    case "not-registered":
      return `the key is not registered as a signing key on github.com/${login}`;
    case "no-user":
      return `github.com has no user named ${login}`;
    case "unavailable":
      return `the signing keys of github.com/${login} could not be fetched (${verdict.detail})`;
  }
}
