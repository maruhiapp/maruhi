// Unit tests for the GitHub API client behind the authentication dance
// (AUTH_SPEC §3-2).
//
// auth.test.ts pins the real path end to end through the worker; this file
// pins failure shapes that are hard to create on it:
//   - an endpoint that never answers fails through the typed error once the
//     per-call timeout elapses (it used to hang forever)
//   - a body whose shape does not match the schema fails the same way
//     instead of being trusted via a cast
//   - /user/emails answering non-ok still degrades to "no email stored"
//     (§3-3), unlike a malformed body
//
// fetch is swapped per run through the FetchHttpClient's `Fetch` context
// reference (no traffic to the real network, no global mutation). A plain
// `globalThis.fetch` reassignment would not work: the reference's default
// is evaluated once per process, so it binds whichever fetch was installed
// at the first request (oidc.test.ts's per-test swap does not hit this
// limitation because the JWKS code calls globalThis.fetch directly).

import { Effect } from "effect";
import { FetchHttpClient } from "effect/http";
import { describe, expect, it } from "vitest";

import { makeGitHubApi } from "../src/auth.package/index.ts";

const OAUTH_TOKEN_URL = "https://github.com/login/oauth/access_token";
const API_USER_URL = "https://api.github.com/user";
const API_EMAILS_URL = "https://api.github.com/user/emails";
const REDIRECT_URI = "https://my.maruhi.app/auth/github/callback";

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** Serves the GitHub endpoints, with the user / emails answers swappable per test. */
function githubStub(options: {
  readonly user?: Response;
  readonly emails?: () => Promise<Response>;
}): typeof fetch {
  return ((input: RequestInfo | URL) => {
    const url = String(input);
    if (url === API_USER_URL) {
      return Promise.resolve(options.user ?? json({ id: 100, login: "user100" }));
    }
    if (url === API_EMAILS_URL) {
      return options.emails?.() ?? Promise.resolve(new Response("missing stub", { status: 500 }));
    }
    return Promise.resolve(new Response(`unexpected url in test: ${url}`, { status: 500 }));
  }) as typeof fetch;
}

/** Runs an operation against the given fetch implementation, folding the outcome into a tagged value. */
const run = <A, E>(effect: Effect.Effect<A, E>, fetchImpl: typeof fetch) =>
  Effect.runPromise(
    effect.pipe(
      Effect.provideService(FetchHttpClient.Fetch, fetchImpl),
      Effect.match({
        onSuccess: (value: A) => ({ ok: true as const, value }),
        onFailure: (error: E) => ({ ok: false as const, error }),
      }),
    ),
  );

const api = () => makeGitHubApi("test-client-id", "test-client-secret");

describe("makeGitHubApi exchangeCode (§3-2)", () => {
  it("returns the access token from a well-formed answer", async () => {
    const fetchImpl = ((input: RequestInfo | URL) => {
      expect(String(input)).toBe(OAUTH_TOKEN_URL);
      return Promise.resolve(json({ access_token: "gho_test1" }));
    }) as typeof fetch;
    const outcome = await run(api().exchangeCode("code-1", REDIRECT_URI), fetchImpl);
    expect(outcome).toEqual({ ok: true, value: "gho_test1" });
  });

  it("fails with code-exchange-failed when GitHub never answers", async () => {
    // The endpoint accepts the connection and never responds: the call now
    // fails through the typed error once REQUEST_TIMEOUT (5 s, the same
    // bound as the JWKS fetch) elapses instead of hanging
    const fetchImpl = (() => new Promise<Response>(() => {})) as typeof fetch;
    const outcome = await run(api().exchangeCode("code-1", REDIRECT_URI), fetchImpl);
    expect(outcome).toEqual({
      ok: false,
      error: expect.objectContaining({ _tag: "GitHubAuth", reason: "code-exchange-failed" }),
    });
  });

  it("fails with code-exchange-failed when the token answer has an unexpected shape", async () => {
    const fetchImpl = (() => Promise.resolve(json({ access_token: 123 }))) as typeof fetch;
    const outcome = await run(api().exchangeCode("code-1", REDIRECT_URI), fetchImpl);
    expect(outcome).toEqual({
      ok: false,
      error: expect.objectContaining({ _tag: "GitHubAuth", reason: "code-exchange-failed" }),
    });
  });
});

describe("makeGitHubApi fetchIdentity (§3-2 / §3-3)", () => {
  it("picks the primary-and-verified email", async () => {
    const outcome = await run(
      api().fetchIdentity("gho_test100"),
      githubStub({
        emails: () =>
          Promise.resolve(
            json([
              { email: "secondary@example.com", primary: false, verified: true },
              { email: "unverified@example.com", primary: true, verified: false },
              { email: "user100@example.com", primary: true, verified: true },
            ]),
          ),
      }),
    );
    expect(outcome).toEqual({
      ok: true,
      value: {
        provider: "github",
        providerUserId: "100",
        providerLogin: "user100",
        verifiedEmail: "user100@example.com",
      },
    });
  });

  it("fails with token-invalid when /user rejects the token", async () => {
    const outcome = await run(
      api().fetchIdentity("gho_bad"),
      githubStub({ user: json({ message: "Bad credentials" }, 401) }),
    );
    expect(outcome).toEqual({
      ok: false,
      error: expect.objectContaining({ _tag: "GitHubAuth", reason: "token-invalid" }),
    });
  });

  it("fails with token-invalid when the emails answer has an unexpected shape", async () => {
    // A malformed body used to be cast and read as "no email" — it now goes
    // through the same failure path as an unreachable GitHub
    const outcome = await run(
      api().fetchIdentity("gho_test100"),
      githubStub({ emails: () => Promise.resolve(json({ message: "not an array" })) }),
    );
    expect(outcome).toEqual({
      ok: false,
      error: expect.objectContaining({ _tag: "GitHubAuth", reason: "token-invalid" }),
    });
  });

  it("still resolves with verifiedEmail null when the emails endpoint answers non-ok", async () => {
    // Non-ok is a "not stored" answer (§3-3), not a dance failure — only
    // transport errors, timeouts, and malformed bodies fold into the error
    const outcome = await run(
      api().fetchIdentity("gho_test100"),
      githubStub({ emails: () => Promise.resolve(json({ message: "Not Found" }, 404)) }),
    );
    expect(outcome).toEqual({
      ok: true,
      value: {
        provider: "github",
        providerUserId: "100",
        providerLogin: "user100",
        verifiedEmail: null,
      },
    });
  });
});
