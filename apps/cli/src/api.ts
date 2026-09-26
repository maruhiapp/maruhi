// Typed client derivation from api-schema (the implementation point of
// ADR-0005's "derive the typed client automatically from the schema definition").
//
// Auth is the Authorization: Bearer header (AUTH_SPEC §6). The token rides only
// on the request header and never appears in logs or errors.

import { maruhiApi } from "@maruhi/api-schema";
import type { Effect, Redacted } from "effect";
import { HttpClient, HttpClientRequest } from "effect/unstable/http";
import { HttpApiClient } from "effect/unstable/httpapi";

/** The typed maruhi API client derived from {@link maruhiApi}. */
export type MaruhiClient = HttpApiClient.ForApi<typeof maruhiApi>;

/**
 * Derives the typed client. `token` is attached as a Bearer header when
 * present (authConfig and the CLI login handoff — cliStart / cliPoll — are
 * the only unauthenticated calls the CLI makes).
 *
 * The upstream `bearerToken` accepts `Redacted` as-is (it unwraps inside
 * header assembly), so the CLI needs no unwrapping point — a hand-written
 * Authorization header (template expansion) would send the redacted form
 * verbatim, so it is not used.
 */
export function makeApiClient(options: {
  readonly baseUrl: string;
  readonly token?: Redacted.Redacted<string>;
}): Effect.Effect<MaruhiClient, never, HttpClient.HttpClient> {
  const token = options.token;
  return HttpApiClient.make(maruhiApi, {
    baseUrl: options.baseUrl,
    transformClient:
      token === undefined ? undefined : HttpClient.mapRequest(HttpClientRequest.bearerToken(token)),
  });
}
