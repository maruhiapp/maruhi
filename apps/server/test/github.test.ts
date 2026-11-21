import { Effect, Fiber, Redacted } from "effect";
import { FetchHttpClient } from "effect/http";
import { TestClock } from "effect/testing";
import { describe, expect, it } from "vite-plus/test";

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

const CLIENT_SECRET = Redacted.make("dummy-client-secret", { label: "GITHUB_CLIENT_SECRET" });
const api = () => makeGitHubApi("test-client-id", CLIENT_SECRET);

describe("makeGitHubApi exchangeCode (§3-2)", () => {
  it("returns the access token from a well-formed answer", async () => {
    const fetchImpl = ((input: RequestInfo | URL) => {
      expect(String(input)).toBe(OAUTH_TOKEN_URL);
      return Promise.resolve(json({ access_token: "gho_test1" }));
    }) as typeof fetch;
    const outcome = await run(api().exchangeCode("code-1", REDIRECT_URI), fetchImpl);
    expect(outcome).toEqual({ ok: true, value: "gho_test1" });
  });

  it("sends GitHub no trace headers (the egress client adds none of its own)", async () => {
    const sent: string[][] = [];
    const fetchImpl = ((_input: RequestInfo | URL, init?: RequestInit) => {
      sent.push(Object.keys(Object.fromEntries(new Headers(init?.headers))));
      return Promise.resolve(json({ access_token: "gho_test1" }));
    }) as typeof fetch;
    const outcome = await run(
      api().exchangeCode("code-1", REDIRECT_URI).pipe(Effect.withSpan("parent")),
      fetchImpl,
    );
    expect(outcome).toEqual({ ok: true, value: "gho_test1" });
    expect(sent).toHaveLength(1);
    expect(sent[0]).not.toContain("traceparent");
    expect(sent[0]).not.toContain("b3");
  });

  it("unwraps the Redacted client secret into the token-exchange body only", async () => {
    const sent: { url: string; headers: string; body: string }[] = [];
    const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      sent.push({
        url: request.url,
        headers: JSON.stringify([...request.headers]),
        body: new TextDecoder().decode(await request.arrayBuffer()),
      });
      return json({ access_token: "gho_test1" });
    }) as typeof fetch;
    const outcome = await run(api().exchangeCode("code-1", REDIRECT_URI), fetchImpl);
    expect(outcome).toEqual({ ok: true, value: "gho_test1" });
    expect(sent).toHaveLength(1);
    const body = new URLSearchParams(sent[0]?.body);
    expect(body.get("client_id")).toBe("test-client-id");
    expect(body.get("client_secret")).toBe(Redacted.value(CLIENT_SECRET));
    expect(sent[0]?.url).not.toContain(Redacted.value(CLIENT_SECRET));
    expect(sent[0]?.headers).not.toContain(Redacted.value(CLIENT_SECRET));
  });

  it("leaves client_secret out of the body when the secret is unconfigured", async () => {
    const bodies: string[] = [];
    const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
      bodies.push(new TextDecoder().decode(await new Request(input, init).arrayBuffer()));
      return json({ error: "incorrect_client_credentials" });
    }) as typeof fetch;
    const outcome = await run(
      makeGitHubApi("test-client-id", undefined).exchangeCode("code-1", REDIRECT_URI),
      fetchImpl,
    );
    expect(outcome).toEqual({
      ok: false,
      error: expect.objectContaining({ _tag: "GitHubAuth", reason: "code-exchange-failed" }),
    });
    expect(new URLSearchParams(bodies[0]).has("client_secret")).toBe(false);
  });

  it("fails with code-exchange-failed when GitHub never answers", async () => {
    const fetchImpl = (() => new Promise<Response>(() => {})) as typeof fetch;
    const outcome = await run(
      Effect.gen(function* () {
        const fiber = yield* Effect.forkChild(api().exchangeCode("code-1", REDIRECT_URI));
        yield* TestClock.adjust("5 seconds");
        return yield* Fiber.join(fiber);
      }).pipe(Effect.provide(TestClock.layer())),
      fetchImpl,
    );
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

  it("fails with token-invalid when the user answer carries a null login", async () => {
    const outcome = await run(
      api().fetchIdentity("gho_test100"),
      githubStub({ user: json({ id: 100, login: null }) }),
    );
    expect(outcome).toEqual({
      ok: false,
      error: expect.objectContaining({ _tag: "GitHubAuth", reason: "token-invalid" }),
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
    const outcome = await run(
      api().fetchIdentity("gho_test100"),
      githubStub({ emails: () => Promise.resolve(json({ message: "not an array" })) }),
    );
    expect(outcome).toEqual({
      ok: false,
      error: expect.objectContaining({ _tag: "GitHubAuth", reason: "token-invalid" }),
    });
  });

  it("fails with token-invalid when an emails entry has a null email", async () => {
    const outcome = await run(
      api().fetchIdentity("gho_test100"),
      githubStub({
        emails: () => Promise.resolve(json([{ email: null, primary: true, verified: true }])),
      }),
    );
    expect(outcome).toEqual({
      ok: false,
      error: expect.objectContaining({ _tag: "GitHubAuth", reason: "token-invalid" }),
    });
  });

  it("still resolves with verifiedEmail null when the emails endpoint answers non-ok", async () => {
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
