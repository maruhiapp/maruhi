import { fromCryptoResult } from "@maruhi/core";
import { decodeHex, encodeHex, parseOpenSshEd25519PublicKey } from "@maruhi/crypto";
import { Duration, Effect, Schema } from "effect";
import { HttpClient, HttpClientRequest } from "effect/http";

import { GITHUB_LOGIN } from "./invite-link.ts";
import { CLI_VERSION } from "./version.ts";

const GITHUB_API_ORIGIN = "https://api.github.com";

const REQUEST_TIMEOUT = Duration.seconds(10);

const SigningKeyEntry = Schema.Struct({ key: Schema.String });
const SigningKeysResponse = Schema.Array(SigningKeyEntry);
const decodeSigningKeys = Schema.decodeUnknownEffect(Schema.fromJsonString(SigningKeysResponse));

export type BackingVerdict =
  | { readonly kind: "match" }
  | { readonly kind: "not-registered" }
  | { readonly kind: "no-user" }
  | { readonly kind: "unavailable"; readonly detail: string };

type SigningKeysFetch =
  | { readonly kind: "entries"; readonly entries: readonly { readonly key: string }[] }
  | { readonly kind: "no-user" }
  | { readonly kind: "unavailable"; readonly detail: string };

const fetchSigningKeys = Effect.fn("github-signing-keys.fetchSigningKeys")(function* (
  login: string,
): Effect.fn.Return<SigningKeysFetch, never, HttpClient.HttpClient> {
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
    Effect.catch((error) => Effect.succeed({ ok: false, detail: describeFailure(error) } as const)),
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

export const checkSigningKeyBacking = Effect.fn("github-signing-keys.checkSigningKeyBacking")(
  function* (input: {
    readonly login: string;
    readonly sigPubHex: string;
  }): Effect.fn.Return<BackingVerdict, never, HttpClient.HttpClient> {
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
  },
);

const parseEntries = Effect.fn("github-signing-keys.parseEntries")(function* (
  text: string,
): Effect.fn.Return<readonly { readonly key: string }[] | null> {
  return yield* decodeSigningKeys(text).pipe(
    Effect.map((entries) => entries as readonly { readonly key: string }[]),
    Effect.orElseSucceed(() => null),
  );
});

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
