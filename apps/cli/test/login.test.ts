// Tests for login (the server-brokered web-flow handoff — AUTH_SPEC §4: start →
// browser approval → poll → keychain) and logout (self-token revocation +
// keychain removal). The maruhi server is a local HTTP mock. The CLI never
// talks to the identity provider directly (the §4 principle), so there is no GitHub-side mock.

import { afterEach, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { masterKeyEntryName, tokenEntryName } from "../src/keychain.ts";
import { makeTestEnv, seedConfig } from "./support/env.ts";
import {
  type MockHandler,
  type MockRequest,
  type MockResponse,
  MockServer,
  onRequest,
} from "./support/server.ts";

let servers: MockServer[] = [];

/** The exchange response's expiry fixture (AUTH_SPEC §6: 2099-01-01T00:00:00Z). */
const EXPIRES_AT_MS = Date.UTC(2099, 0, 1);

/** The public correlator (128-bit hex — matches api-schema's CliFlowIdSchema). */
const FLOW_ID = "0123456789abcdef0123456789abcdef";

/** Fixture for the CLI-only bearer credential (§4-1 (1) — opaque to the CLI). */
const FLOW_TOKEN = "v1.dGVzdC1mbG93.fixture-mac-value";

const USER_CODE = "ABCD-1234";
const VERIFICATION_URL = `https://maruhi.example/auth/cli/verify?flow=${FLOW_ID}&vsig=feedface`;

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

async function start(handlers: readonly MockHandler[]): Promise<MockServer> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  return server;
}

/** The approved poll response (§4-1 (5) — the raw token appears on the wire only this once). */
function approvedResponse(input?: {
  readonly token?: string;
  readonly expiresAtMs?: number;
}): MockResponse {
  return {
    status: 200,
    json: {
      status: "approved",
      token: input?.token ?? "maruhi_pat_issued",
      tokenId: "tok_1",
      userId: "user-0001",
      expiresAtMs: input?.expiresAtMs ?? EXPIRES_AT_MS,
    },
  };
}

/**
 * The maruhi side of the handoff (start + n polls of pending → final response).
 * The start response's pollIntervalSeconds is 0 (tests pass `--poll-interval 0`
 * so the lower bound is also 0 — no real-time sleep).
 */
function fakeHandoff(
  input: {
    readonly pendingPolls?: number;
    /** The final poll response (default: approved). */
    readonly finalPoll?: MockResponse;
    /** Overrides for the start response (for expiry / interval edge cases). */
    readonly startOverrides?: Readonly<Record<string, unknown>>;
    readonly token?: string;
    readonly expiresAtMs?: number;
  } = {},
): {
  handlers: MockHandler[];
  polls: () => number;
  startBodies: Record<string, unknown>[];
  pollBodies: Record<string, unknown>[];
} {
  const startBodies: Record<string, unknown>[] = [];
  const pollBodies: Record<string, unknown>[] = [];
  let polls = 0;
  const pendingPolls = input.pendingPolls ?? 0;
  const handlers: MockHandler[] = [
    onRequest("POST", "/auth/cli/start", (request: MockRequest) => {
      startBodies.push(request.body as Record<string, unknown>);
      return {
        status: 200,
        json: {
          flowId: FLOW_ID,
          flowToken: FLOW_TOKEN,
          userCode: USER_CODE,
          verificationUrl: VERIFICATION_URL,
          expiresInSeconds: 900,
          pollIntervalSeconds: 0,
          ...input.startOverrides,
        },
      };
    }),
    onRequest("POST", "/auth/cli/poll", (request: MockRequest) => {
      pollBodies.push(request.body as Record<string, unknown>);
      polls += 1;
      if (polls <= pendingPolls) {
        return { status: 200, json: { status: "pending" } };
      }
      return (
        input.finalPoll ??
        approvedResponse({
          ...(input.token === undefined ? {} : { token: input.token }),
          ...(input.expiresAtMs === undefined ? {} : { expiresAtMs: input.expiresAtMs }),
        })
      );
    }),
  ];
  return { handlers, polls: () => polls, startBodies, pollBodies };
}

/** Flags shared by all tests (no real-time sleep). */
const FAST_POLL = ["--poll-interval", "0"] as const;

describe("maruhi login", () => {
  it("fails an overlong --token-name before any communication (never wastes the browser approval)", async () => {
    // If the argument layer skipped the cap (api-schema's MAX_TOKEN_NAME_LENGTH),
    // an overlong name would surface as a request-encode failure **after the
    // browser approval completed**. Worse, a Schema error shares its type with
    // the response side, so the diagnosis would look like "a server-side fault"
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    const code = await runCli(["login", "--token-name", "n".repeat(129), ...FAST_POLL], env.layer);
    // A usage mistake is a usage error (2)
    expect(code).toBe(2);
    expect(env.errors.join("\n")).toContain("--token-name must be at most 128 characters");
    // start is never even called (no browser approval requested)
    expect(maruhi.requests).toHaveLength(0);
    expect(env.errors.join("\n")).not.toContain("Waiting for approval");
  });

  it("fails an out-of-range --token-ttl-days before any communication (AUTH_SPEC §6)", async () => {
    // The cap is shared with api-schema's MAX_TOKEN_TTL_DAYS (same rule as
    // --token-name: never surface a usage mistake after the browser approval has completed)
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    for (const value of ["0", "366"]) {
      const code = await runCli(["login", "--token-ttl-days", value, ...FAST_POLL], env.layer);
      expect(code).toBe(2);
    }
    expect(env.errors.join("\n")).toContain("--token-ttl-days must be between 1 and 365");
    expect(maruhi.requests).toHaveLength(0);
  });

  it("--token-ttl-days rides on the start payload as expiresInDays, and is absent when omitted", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["login", "--token-ttl-days", "365", ...FAST_POLL], env.layer)).toBe(0);
    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
    expect(handoff.startBodies[0]?.["expiresInDays"]).toBe(365);
    // When omitted, the server default (90 days) applies — the key itself is not sent
    expect(Object.hasOwn(handoff.startBodies[1] ?? {}, "expiresInDays")).toBe(false);
    // The validity period is fixed at issuance; when re-login will be needed is displayed
    expect(env.logs.join("\n")).toContain("The token expires on 2099-01-01 (UTC)");
  });

  it("start → wait for approval → poll → saves only the maruhi token to the keychain", async () => {
    const handoff = fakeHandoff({ pendingPolls: 2 });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    const code = await runCli(["login", "--token-name", "cli-test", ...FAST_POLL], env.layer);
    expect(code).toBe(0);
    expect(handoff.polls()).toBe(3);
    // The issuance parameters ride on start (§4-1 (1) — fixed at start, not at issuance)
    expect(handoff.startBodies[0]?.["tokenName"]).toBe("cli-test");
    // poll carries only the two flow-credential identifiers (§4-1 (5))
    expect(handoff.pollBodies[0]).toEqual({ flowId: FLOW_ID, flowToken: FLOW_TOKEN });
    const logs = env.logs.join("\n");
    // The verification URL and user code go to the interactive guidance (stderr —
    // ruling D-2) as phishing-match material (§4-1 (2)). The validity period is derived from the server response
    const guidance = env.errors.join("\n");
    expect(guidance).toContain(VERIFICATION_URL);
    expect(guidance).toContain(`Confirmation code: ${USER_CODE}`);
    expect(guidance).toContain("This request expires in 15 minutes");
    expect(guidance).toContain("Waiting for approval");
    // The result (stdout) is a single success line + the expiry
    expect(logs).toContain("Signed in as user-0001");
    // flowToken is a credential — it appears on neither the browser channel nor the terminal output (§4-1 (1))
    expect(logs).not.toContain(FLOW_TOKEN);
    expect(env.errors.join("\n")).not.toContain(FLOW_TOKEN);
    const stored = env.keychain.get(tokenEntryName(maruhi.origin));
    expect(stored).toBeDefined();
    expect(JSON.parse(stored ?? "{}")).toEqual({
      token: "maruhi_pat_issued",
      userId: "user-0001",
      tokenId: "tok_1",
      // The record also carries the local decision material for the expiry-approaching warning (ruling CL)
      expiresAtMs: EXPIRES_AT_MS,
    });
    expect(stored).not.toContain(FLOW_TOKEN);
    // The raw token never reaches the terminal output (no --show-token)
    expect(logs).not.toContain("maruhi_pat_issued");
  });

  describe("signupPolicy pre-fail-fast (AUTH_SPEC §3 / hosted-design §2-2 (i)(ii))", () => {
    /** A handoff set where /auth/config declares a signupPolicy. */
    function handoffWithConfig(config: Record<string, unknown>): {
      handlers: MockHandler[];
      polls: () => number;
    } {
      const handoff = fakeHandoff();
      return {
        handlers: [
          onRequest("GET", "/auth/config", () => ({
            status: 200,
            json: { githubClientId: "dummy", ...config },
          })),
          ...handoff.handlers,
        ],
        polls: handoff.polls,
      };
    }

    it("invite-only: an interactive terminal confirms keeping the existing account; yes proceeds", async () => {
      const handoff = handoffWithConfig({ signupPolicy: "invite" });
      const maruhi = await start(handoff.handlers);
      const env = await makeTestEnv();
      await seedConfig(env, { server: maruhi.origin });
      env.setPromptResponses(["y"]);

      expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
      expect(env.prompts.join("\n")).toContain("Do you already have a maruhi account");
      expect(env.errors.join("\n")).toContain("invite-only");
      // Past the confirmation, proceed to the usual start → poll
      expect(handoff.polls()).toBeGreaterThan(0);
    });

    it("invite-only: on no (the default), shows guidance and exits before calling start", async () => {
      const handoff = handoffWithConfig({ signupPolicy: "invite" });
      const maruhi = await start(handoff.handlers);
      const env = await makeTestEnv();
      await seedConfig(env, { server: maruhi.origin });
      env.setPromptResponses([""]);

      expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(1);
      // A misoperation guard (not authorization): never begins a wasted browser round trip
      expect(maruhi.requests.map((request) => request.path)).toEqual(["/auth/config"]);
      const output = [...env.logs, ...env.errors].join("\n");
      expect(output).toContain("sign up in your browser first");
      expect(output).toContain("Sign up in the browser first, then run `maruhi login` again");
      expect(env.keychain.size).toBe(0);
    });

    it("closed: an interactive terminal asks for confirmation; no exits", async () => {
      const handoff = handoffWithConfig({ signupPolicy: "closed" });
      const maruhi = await start(handoff.handlers);
      const env = await makeTestEnv();
      await seedConfig(env, { server: maruhi.origin });
      env.setPromptResponses(["n"]);

      expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(1);
      expect(env.errors.join("\n")).toContain("not accepting new sign-ups");
      expect(maruhi.requests.map((request) => request.path)).toEqual(["/auth/config"]);
    });

    it("in a non-interactive environment (agent / pipe), shows only guidance and proceeds (never hangs on a prompt)", async () => {
      for (const shape of ["agent", "piped"] as const) {
        const handoff = handoffWithConfig({ signupPolicy: "invite" });
        const maruhi = await start(handoff.handlers);
        const env = await makeTestEnv();
        await seedConfig(env, { server: maruhi.origin });
        if (shape === "agent") {
          env.setAgent({ isAgent: true, name: "test-agent" });
        } else {
          env.setTerminal({ stdin: false });
        }
        expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
        expect(env.prompts).toHaveLength(0);
        expect(env.errors.join("\n")).toContain("invite-only");
        expect(env.keychain.get(tokenEntryName(maruhi.origin))).toBeDefined();
      }
    });

    it("open: neither confirmation nor guidance is inserted", async () => {
      const handoff = handoffWithConfig({ signupPolicy: "open" });
      const maruhi = await start(handoff.handlers);
      const env = await makeTestEnv();
      await seedConfig(env, { server: maruhi.origin });

      expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
      expect(env.prompts).toHaveLength(0);
      expect(env.errors.join("\n")).not.toContain("invite-only");
    });

    it("proceeds even with signupPolicy undeclared (old server) / no /auth/config (never breaks login on a missing advisory)", async () => {
      // Undeclared: a 200 without the field
      const withoutField = handoffWithConfig({});
      const oldServer = await start(withoutField.handlers);
      const env1 = await makeTestEnv();
      await seedConfig(env1, { server: oldServer.origin });
      expect(await runCli(["login", ...FAST_POLL], env1.layer)).toBe(0);
      expect(env1.prompts).toHaveLength(0);
      // Absent: no /auth/config handler (404) — fakeHandoff left plain
      const bare = fakeHandoff();
      const bareServer = await start(bare.handlers);
      const env2 = await makeTestEnv();
      await seedConfig(env2, { server: bareServer.origin });
      expect(await runCli(["login", ...FAST_POLL], env2.layer)).toBe(0);
      expect(env2.prompts).toHaveLength(0);
    });
  });

  it("attempts browser auto-launch on an interactive terminal × non-agent (the §4-1 (2) UX branch)", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    // The default TestEnv = interactive terminal × non-agent

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
    expect(env.browserOpens).toEqual([VERIFICATION_URL]);
    expect(env.errors.join("\n")).toContain("Opened your browser");
  });

  it("does not open a browser in an agent environment / non-interactive terminal, but completes via display + polling", async () => {
    // The degraded path is a single one (display + polling) covering every
    // environment — it is not a new security gate, so login still succeeds in non-target environments
    for (const shape of ["agent", "piped"] as const) {
      const handoff = fakeHandoff();
      const maruhi = await start(handoff.handlers);
      const env = await makeTestEnv();
      await seedConfig(env, { server: maruhi.origin });
      if (shape === "agent") {
        env.setAgent({ isAgent: true, name: "test-agent" });
      } else {
        env.setTerminal({ stdout: false });
      }
      expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
      expect(env.browserOpens).toHaveLength(0);
      const guidance = env.errors.join("\n");
      expect(guidance).toContain(VERIFICATION_URL);
      expect(guidance).toContain(USER_CODE);
      // Since no auto-launch was attempted, it also never claims "could not open"
      expect(guidance).not.toContain("Could not open a browser");
      expect(env.keychain.get(tokenEntryName(maruhi.origin))).toBeDefined();
    }
  });

  it("completes even when browser launch fails (launch is best-effort)", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.setBrowserOpenSucceeds(false);

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
    expect(env.browserOpens).toEqual([VERIFICATION_URL]);
    // A failed launch is never claimed as "opened" (the manual-open guidance for the URL is always shown)
    expect(env.errors.join("\n")).not.toContain("Opened your browser");
    expect(env.errors.join("\n")).toContain("Could not open a browser automatically");
  });

  it("never passes a non-http(s) or unparsable verificationUrl to the OS opener (fail-closed)", async () => {
    // The OS URL handler dispatches arbitrary schemes. verificationUrl is
    // untrusted input from a server response, so it is validated before reaching
    // the opener; on failure, browser auto-launch is skipped and the flow completes via manual-open guidance (display) + polling
    for (const url of ["file:///etc/passwd", "javascript:alert(1)", "not a url"]) {
      const handoff = fakeHandoff({ startOverrides: { verificationUrl: url } });
      const maruhi = await start(handoff.handlers);
      const env = await makeTestEnv();
      await seedConfig(env, { server: maruhi.origin });
      // The default TestEnv = interactive terminal × non-agent (the auto-launch target environment)
      expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
      expect(env.browserOpens).toHaveLength(0);
      expect(env.keychain.get(tokenEntryName(maruhi.origin))).toBeDefined();
    }
  });

  it("displays server-sourced verificationUrl / userCode with control characters neutralized", async () => {
    // ANSI injection from a hostile / compromised server never reaches the terminal raw (displayText)
    const handoff = fakeHandoff({
      startOverrides: {
        verificationUrl: "https://evil.example/\u001b[2Jverify",
        userCode: "AB\u001bCD",
      },
    });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
    expect(env.logs.join("\n")).not.toContain("\u001b");
    expect(env.errors.join("\n")).not.toContain("\u001b");
    expect(env.errors.join("\n")).toContain("Confirmation code: AB\uFFFDCD");
  });

  it("a browser-side refusal (denied) ends in an error (the §4-1 (4) refusal operation)", async () => {
    const handoff = fakeHandoff({ finalPoll: { status: 200, json: { status: "denied" } } });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("denied in the browser");
    expect(env.keychain.size).toBe(0);
  });

  it("expiry (410 CliFlowExpired) stops polling and guides toward re-login (§4-2)", async () => {
    const handoff = fakeHandoff({
      finalPoll: { status: 410, json: { _tag: "CliFlowExpired" } },
    });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("The sign-in request expired");
    expect(handoff.polls()).toBe(1);
    expect(env.keychain.size).toBe(0);
  });

  it("uniform refusal (400 CliFlowRejected) does not discriminate reasons and guides toward re-login (§4-2)", async () => {
    // Credential mismatch, re-polling a consumed flow, etc. all get the same
    // response (the server builds no oracle for flow state) — the CLI side never fabricates a reason either
    const handoff = fakeHandoff({
      finalPoll: { status: 400, json: { _tag: "CliFlowRejected" } },
    });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("rejected by the server");
    expect(env.keychain.size).toBe(0);
  });

  it("a poll 429 is not a failure — it backs off and continues (§4-1 (5))", async () => {
    let polls = 0;
    const maruhi = await start([
      onRequest("POST", "/auth/cli/start", () => ({
        status: 200,
        json: {
          flowId: FLOW_ID,
          flowToken: FLOW_TOKEN,
          userCode: USER_CODE,
          verificationUrl: VERIFICATION_URL,
          expiresInSeconds: 900,
          pollIntervalSeconds: 0,
        },
      })),
      onRequest("POST", "/auth/cli/poll", () => {
        polls += 1;
        if (polls === 1) {
          return { status: 429, json: { _tag: "AuthRateLimited", retryAfterSeconds: 0 } };
        }
        return approvedResponse();
      }),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
    expect(polls).toBe(2);
    expect(env.keychain.get(tokenEntryName(maruhi.origin))).toBeDefined();
  });

  it("expires locally when the next poll would pass the declared deadline (deadline precedes sleep)", async () => {
    // Server-declared remaining deadline 1ms × interval 10s — the flow would
    // expire while waiting, so it ends with no wasted sleep or request
    const handoff = fakeHandoff({
      startOverrides: { expiresInSeconds: 0.001, pollIntervalSeconds: 10 },
    });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("The sign-in request expired");
    expect(handoff.polls()).toBe(0);
  });

  it("the validity guidance and the expiry wording derive from the server response's expiresInSeconds (ruling D-1)", async () => {
    // Truncated to minutes; only sub-minute is said in seconds. The CLI holds no
    // constant (the guidance cannot disagree if the server changes its TTL). The expiry wording carries the same duration
    for (const [seconds, window] of [
      [600, "10 minutes"],
      [61, "1 minute"],
      [45, "45 seconds"],
    ] as const) {
      const handoff = fakeHandoff({
        startOverrides: { expiresInSeconds: seconds },
        finalPoll: { status: 410, json: { _tag: "CliFlowExpired" } },
      });
      const maruhi = await start(handoff.handlers);
      const env = await makeTestEnv();
      await seedConfig(env, { server: maruhi.origin });
      expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(1);
      const guidance = env.errors.join("\n");
      expect(guidance).toContain(`This request expires in ${window}`);
      expect(guidance).toContain(`The sign-in request expired (it was valid for ${window})`);
    }
    // Non-numeric / non-positive values are rounded to the default (15 minutes, same as the server's drafted value) for the guidance
    const handoff = fakeHandoff({ startOverrides: { expiresInSeconds: -1 } });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("This request expires in 15 minutes");
  });

  it("interactive guidance goes to stderr, results to stdout (guidance stays visible even with `maruhi login > file`)", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    expect(await runCli(["login", "--token-name", "cli-test", ...FAST_POLL], env.layer)).toBe(0);
    // stdout carries only the result (no URL / code / waiting display mixed in)
    expect(env.logs).toEqual([
      "Signed in as user-0001. The token is stored in the OS keychain",
      "The token expires on 2099-01-01 (UTC). Signing in again with the same token name (cli-test) rotates it and revokes the old one",
    ]);
    expect(env.logs.join("\n")).not.toContain(VERIFICATION_URL);
  });

  it("an unconfigured server (503 SetupIncomplete) fails after showing the setup guide", async () => {
    const maruhi = await start([
      onRequest("POST", "/auth/cli/start", () => ({
        status: 503,
        json: { _tag: "SetupIncomplete", reason: "github-oauth-unconfigured" },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("self-hosting setup is incomplete");
    expect(env.errors.join("\n")).toContain("SELF_HOSTING");
  });

  it("degrades explicitly without crashing on an out-of-range expiresAtMs (display.ts's total display)", async () => {
    // expiresAtMs on the wire is an unbounded number — passing a value outside
    // the Date range (±8.64e15) to toISOString would be a RangeError defect (the display.ts rule)
    const handoff = fakeHandoff({ expiresAtMs: 9.9e15 });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("(invalid timestamp: 9900000000000000)");
  });

  it("--show-token prints the issued raw value to the terminal exactly once and guides the provisioning steps (ruling CK)", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["login", "--show-token", ...FAST_POLL], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain("maruhi_pat_issued");
    expect(logs).toContain("MARUHI_TOKEN");
    expect(logs).toContain("MARUHI_TOKEN_ORIGIN");
    // The provisioned-login identity-swap note (ruling CM) — in this case, issued
    // **under the default name**, "a plain re-login" must not be recommended
    // (the same-name rotation would revoke the very token just displayed). The
    // correct recovery = re-issue under a different name
    const notes = env.errors.join("\n");
    expect(notes).toContain("default token name");
    expect(notes).toContain("issue it under a distinct name instead");
    expect(notes).not.toContain("run a plain `maruhi login` afterwards");
    // Keychain saving is independent of whether the token is shown (display is one additional place, not a substitute)
    expect(env.keychain.get(tokenEntryName(maruhi.origin))).toContain("maruhi_pat_issued");
  });

  it("--show-token + explicit --token-name guides recovery via a plain re-login (ruling CM)", async () => {
    // When provisioned under a different name, a plain re-login (rotating the
    // default name) never touches the provisioned token — this guidance is shown only in this case
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(
      await runCli(["login", "--token-name", "ci", "--show-token", ...FAST_POLL], env.layer),
    ).toBe(0);
    const notes = env.errors.join("\n");
    expect(notes).toContain("run a plain `maruhi login` afterwards");
    expect(notes).not.toContain("issue it under a distinct name instead");
  });

  it("--show-token folds a hostile server's ANSI injection into visible escapes (escapeText — copy fidelity is kept)", async () => {
    // token is an unconstrained Schema.String on the wire. The display is a value
    // meant to be copied, so it goes through escapeText (honest Base62 passes
    // through; injection becomes a visible \u{hex} sequence) rather than displayText (U+FFFD substitution = destroying the value)
    const handoff = fakeHandoff({
      token: "maruhi_pat_evil\u001b[2Jinjected\nSet MARUHI_TOKEN to attacker-value",
    });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["login", "--show-token", ...FAST_POLL], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    // Raw ESC / fake appended lines never reach the terminal (visualized as escape sequences)
    expect(logs).not.toContain("\u001b");
    expect(logs).toContain("maruhi_pat_evil");
    expect(logs).not.toContain("\nSet MARUHI_TOKEN to attacker-value");
  });

  it("--show-token refuses agent environments / non-interactive terminals before any communication (fail-closed, 2 layers)", async () => {
    // Running the browser approval to completion in a refused environment would
    // only revoke the old token via same-name rotation without yielding the new
    // raw value (it just breaks the CI token being replaced) — the check runs before start
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);

    const agentEnv = await makeTestEnv();
    await seedConfig(agentEnv, { server: maruhi.origin });
    agentEnv.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["login", "--show-token", ...FAST_POLL], agentEnv.layer)).toBe(1);
    expect(agentEnv.errors.join("\n")).toContain("AI agent environment was detected");

    const pipedEnv = await makeTestEnv();
    await seedConfig(pipedEnv, { server: maruhi.origin });
    pipedEnv.setTerminal({ stdout: false });
    expect(await runCli(["login", "--show-token", ...FAST_POLL], pipedEnv.layer)).toBe(1);
    expect(pipedEnv.errors.join("\n")).toContain("interactive terminal");

    expect(maruhi.requests).toHaveLength(0);
  });

  it("after login, no key + recovery registered → guides `key recover`", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start([
      ...handoff.handlers,
      onRequest("GET", "/auth/recovery/status", () => ({
        status: 200,
        json: { registered: true, updatedAtMs: 1754006400000 },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
    const hint = env.errors.join("\n");
    expect(hint).toContain("`maruhi key recover`");
    // Path ordering (K7-4): if a device remains, add; otherwise, recover
    expect(hint.indexOf("`maruhi device add`")).toBeGreaterThan(-1);
    expect(hint.indexOf("`maruhi device add`")).toBeLessThan(hint.indexOf("`maruhi key recover`"));
  });

  it("after login, key present + recovery unregistered → prompts issuance (the storage reminder)", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start([
      ...handoff.handlers,
      onRequest("GET", "/auth/recovery/status", () => ({
        status: 200,
        json: { registered: false, updatedAtMs: null },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    // Pre-place a device key record for this (origin, user)
    env.keychain.set(
      masterKeyEntryName(maruhi.origin, "user-0001"),
      JSON.stringify({
        suite: "maruhi/v1",
        encPubHex: "00".repeat(32),
        encSkHex: "00".repeat(32),
        sigPubHex: "00".repeat(32),
        sigSkSeedHex: "00".repeat(32),
      }),
    );

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("issue one with `maruhi key recovery`");
  });

  it("a failed status check on post-login guidance does not fail the login; the skip is made explicit", async () => {
    // recovery/status handler absent = the situation where the status check fails
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(0);
    // Never a silent skip (CLAUDE.md: do not swallow silently in a catch)
    expect(env.errors.join("\n")).toContain("skipped the next-step hint");
  });

  it("on keychain-save failure, revokes the issued token before failing (anti-orphaning)", async () => {
    let revoked = 0;
    const handoff = fakeHandoff();
    const maruhi = await start([
      ...handoff.handlers,
      onRequest("POST", "/auth/token/revoke", (request) => {
        expect(request.headers["authorization"]).toBe("Bearer maruhi_pat_issued");
        revoked += 1;
        return { status: 204 };
      }),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.failKeychainWrites();

    expect(await runCli(["login", ...FAST_POLL], env.layer)).toBe(1);
    expect(revoked).toBe(1);
    expect(env.keychain.size).toBe(0);
    expect(env.errors.join("\n")).toContain("キーチェーン"); // english-exempt: asserts literal text owned by apps/cli/test/support/env.ts
  });

  it("never claims 'revoked' when keychain-save fails and revocation also fails", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start([
      ...handoff.handlers,
      onRequest("POST", "/auth/token/revoke", () => ({ status: 500, bodyText: "boom" })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.failKeychainWrites();

    expect(await runCli(["login", "--token-name", "cli-test", ...FAST_POLL], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("revoking the issued token also failed");
    expect(errors).not.toContain("has been revoked on the server");
    // Guidance exists for rotation-revocation via a same-name re-login
    expect(errors).toContain("cli-test");
  });

  it("an invalid config server names the fix target and exits 1", async () => {
    // Nothing was typed on the command line, so it is not "a usage mistake (2)"
    const env = await makeTestEnv();
    await seedConfig(env, { server: "ftp://bad.example" });
    expect(await runCli(["logout"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("fix server in your config");
  });
});

describe("maruhi logout", () => {
  it("revokes the own token and removes it from the keychain", async () => {
    let revoked = 0;
    const maruhi = await start([
      onRequest("POST", "/auth/token/revoke", (request) => {
        expect(request.headers["authorization"]).toBe("Bearer maruhi_pat_stored");
        revoked += 1;
        return { status: 204 };
      }),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.keychain.set(
      tokenEntryName(maruhi.origin),
      JSON.stringify({ token: "maruhi_pat_stored", userId: "user-0001", tokenId: "tok_1" }),
    );
    expect(await runCli(["logout"], env.layer)).toBe(0);
    expect(revoked).toBe(1);
    expect(env.keychain.size).toBe(0);
  });

  it("on revocation-API failure (5xx), deletes from the keychain first (never leaves an invalid token)", async () => {
    const maruhi = await start([
      onRequest("POST", "/auth/token/revoke", () => ({ status: 500, bodyText: "boom" })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.keychain.set(
      tokenEntryName(maruhi.origin),
      JSON.stringify({ token: "maruhi_pat_stored", userId: "user-0001", tokenId: "tok_1" }),
    );
    // Deletion runs before revocation: if revocation succeeded and deletion then
    // failed, an invalid token would remain in the keychain and every later
    // command would 401. A failed revocation is exit 1, but the keychain entry is already removed (recoverable via re-login)
    expect(await runCli(["logout"], env.layer)).toBe(1);
    expect(env.keychain.size).toBe(0);
  });

  it("also succeeds by removing the keychain entry when already revoked (401)", async () => {
    const maruhi = await start([
      onRequest("POST", "/auth/token/revoke", () => ({
        status: 401,
        json: { _tag: "Unauthorized" },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.keychain.set(
      tokenEntryName(maruhi.origin),
      JSON.stringify({ token: "maruhi_pat_stored", userId: "user-0001", tokenId: "tok_1" }),
    );
    expect(await runCli(["logout"], env.layer)).toBe(0);
    expect(env.keychain.size).toBe(0);
  });

  it("warns that a remaining MARUHI_TOKEN 'keeps authenticating'", async () => {
    const maruhi = await start([onRequest("POST", "/auth/token/revoke", () => ({ status: 204 }))]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.keychain.set(
      tokenEntryName(maruhi.origin),
      JSON.stringify({ token: "maruhi_pat_stored", userId: "user-0001", tokenId: "tok_1" }),
    );
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", maruhi.origin);
    expect(await runCli(["logout"], env.layer)).toBe(0);
    expect(env.keychain.size).toBe(0);
    expect(env.errors.join("\n")).toContain("MARUHI_TOKEN is set");
  });

  it("a redacted MARUHI_TOKEN / unset MARUHI_TOKEN_ORIGIN gets per-cause guidance", async () => {
    // Both are states where the next command fails, but the fixes differ (re-paste / add one)
    for (const [token, origin, expected] of [
      ["<redacted:maruhi-token>", "https://x.example", "redaction placeholder"],
      ["maruhi_pat_env", undefined, "MARUHI_TOKEN_ORIGIN is not set"],
      // The reason the shape cannot be used is shown in the resolver's own wording (not paraphrased)
      ["maruhi_pat_env", "not-a-url", "Cannot parse"],
      ["maruhi_pat_env", "http://remote.example", "loopback"],
    ] as const) {
      const maruhi = await start([
        onRequest("POST", "/auth/token/revoke", () => ({ status: 204 })),
      ]);
      const env = await makeTestEnv();
      await seedConfig(env, { server: maruhi.origin });
      env.keychain.set(
        tokenEntryName(maruhi.origin),
        JSON.stringify({ token: "maruhi_pat_stored", userId: "user-0001", tokenId: "tok_1" }),
      );
      env.setEnvVar("MARUHI_TOKEN", token);
      if (origin !== undefined) {
        env.setEnvVar("MARUHI_TOKEN_ORIGIN", origin);
      }
      expect(await runCli(["logout"], env.layer)).toBe(0);
      const notes = env.errors.join("\n");
      expect(notes).toContain(expected);
      expect(notes).not.toContain("stays authenticated with that token");
    }
  });

  it("a mismatched MARUHI_TOKEN_ORIGIN guides that it 'is not used'", async () => {
    // resolveSession requires the origin binding; a mismatch **fails without
    // reaching the keychain**. Saying "keeps authenticating" here would
    // contradict why the next command fails
    const maruhi = await start([onRequest("POST", "/auth/token/revoke", () => ({ status: 204 }))]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.keychain.set(
      tokenEntryName(maruhi.origin),
      JSON.stringify({ token: "maruhi_pat_stored", userId: "user-0001", tokenId: "tok_1" }),
    );
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", "https://other.example");
    expect(await runCli(["logout"], env.layer)).toBe(0);
    const notes = env.errors.join("\n");
    expect(notes).toContain("not used for authentication");
    expect(notes).not.toContain("stays authenticated with that token");
  });

  it("does not warn on a whitespace-only MARUHI_TOKEN (same check as session resolution)", async () => {
    // resolveSession treats an empty-after-trim value as unset. If only this
    // looked at the raw value, it would say "keeps authenticating" right before failing with "Not logged in"
    const maruhi = await start([onRequest("POST", "/auth/token/revoke", () => ({ status: 204 }))]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.keychain.set(
      tokenEntryName(maruhi.origin),
      JSON.stringify({ token: "maruhi_pat_stored", userId: "user-0001", tokenId: "tok_1" }),
    );
    env.setEnvVar("MARUHI_TOKEN", " \n");
    expect(await runCli(["logout"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).not.toContain("MARUHI_TOKEN is set");
  });

  it("an unsaved token is guided via an error message", async () => {
    const maruhi = await start([]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    expect(await runCli(["logout"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("No token for this server in the keychain");
  });
});
