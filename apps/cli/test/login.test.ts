import { testUserId } from "@maruhi/test-kit";
import type { ApiReply, ApiSuccess } from "@maruhi/test-kit/api";
import { afterEach, describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { masterKeyEntryName, tokenEntryName } from "../src/keychain.ts";
import { makeTestEnv, seedConfig } from "./support/env.ts";
import {
  type EndpointAnswer,
  type MockHandler,
  MockServer,
  offSpec,
  onEndpoint,
} from "./support/server.ts";
import { runCliWithClock } from "./support/test-clock.ts";

let servers: MockServer[] = [];

const EXPIRES_AT_MS = Date.UTC(2099, 0, 1);

const FLOW_ID = "0123456789abcdef0123456789abcdef";

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

function approvedResponse(input?: {
  readonly token?: string;
  readonly expiresAtMs?: number;
}): ApiReply<"authCli.cliPoll"> {
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

function fakeHandoff(
  input: {
    readonly pendingPolls?: number;
    readonly finalPoll?: EndpointAnswer<"authCli.cliPoll">;
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
    onEndpoint("authCli.cliStart", (request) => {
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
    onEndpoint("authCli.cliPoll", (request) => {
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

describe("maruhi login", () => {
  it("fails an overlong --token-name before any communication (never wastes the browser approval)", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    const code = await runCliWithClock(["login", "--token-name", "n".repeat(129)], env.layer);
    expect(code).toBe(2);
    expect(env.errors.join("\n")).toContain("--token-name must be at most 128 characters");
    expect(maruhi.requests).toHaveLength(0);
    expect(env.errors.join("\n")).not.toContain("Waiting for approval");
  });

  it("fails an out-of-range --token-ttl-days before any communication (AUTH_SPEC §6)", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    for (const value of ["0", "366"]) {
      const code = await runCliWithClock(["login", "--token-ttl-days", value], env.layer);
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

    expect(await runCliWithClock(["login", "--token-ttl-days", "365"], env.layer)).toBe(0);
    expect(await runCliWithClock(["login"], env.layer)).toBe(0);
    expect(handoff.startBodies[0]?.["expiresInDays"]).toBe(365);
    expect(Object.hasOwn(handoff.startBodies[1] ?? {}, "expiresInDays")).toBe(false);
    expect(env.logs.join("\n")).toContain("The token expires on 2099-01-01 (UTC)");
  });

  it("start → wait for approval → poll → saves only the maruhi token to the keychain", async () => {
    const handoff = fakeHandoff({ pendingPolls: 2 });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    const code = await runCliWithClock(["login", "--token-name", "cli-test"], env.layer);
    expect(code).toBe(0);
    expect(handoff.polls()).toBe(3);
    expect(handoff.startBodies[0]?.["tokenName"]).toBe("cli-test");
    expect(handoff.pollBodies[0]).toEqual({ flowId: FLOW_ID, flowToken: FLOW_TOKEN });
    const logs = env.logs.join("\n");
    const guidance = env.errors.join("\n");
    expect(guidance).toContain(VERIFICATION_URL);
    expect(guidance).toContain(`Confirmation code: ${USER_CODE}`);
    expect(guidance).toContain("This request expires in 15 minutes");
    expect(guidance).toContain("Waiting for approval");
    expect(logs).toContain("Signed in as user-0001");
    expect(logs).not.toContain(FLOW_TOKEN);
    expect(env.errors.join("\n")).not.toContain(FLOW_TOKEN);
    const stored = env.keychain.get(tokenEntryName(maruhi.origin));
    expect(stored).toBeDefined();
    expect(JSON.parse(stored ?? "{}")).toEqual({
      token: "maruhi_pat_issued",
      userId: "user-0001",
      tokenId: "tok_1",
      expiresAtMs: EXPIRES_AT_MS,
    });
    expect(stored).not.toContain(FLOW_TOKEN);
    expect(logs).not.toContain("maruhi_pat_issued");
  });

  describe("signupPolicy pre-fail-fast (AUTH_SPEC §3 / hosted-design §2-2 (i)(ii))", () => {
    function handoffWithConfig(config: Omit<ApiSuccess<"auth.authConfig">, "githubClientId">): {
      handlers: MockHandler[];
      polls: () => number;
    } {
      const handoff = fakeHandoff();
      return {
        handlers: [
          onEndpoint("auth.authConfig", () => ({
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

      expect(await runCliWithClock(["login"], env.layer)).toBe(0);
      expect(env.prompts.join("\n")).toContain("Do you already have a maruhi account");
      expect(env.errors.join("\n")).toContain("invite-only");
      expect(handoff.polls()).toBeGreaterThan(0);
    });

    it("invite-only: on no (the default), shows guidance and exits before calling start", async () => {
      const handoff = handoffWithConfig({ signupPolicy: "invite" });
      const maruhi = await start(handoff.handlers);
      const env = await makeTestEnv();
      await seedConfig(env, { server: maruhi.origin });
      env.setPromptResponses([""]);

      expect(await runCliWithClock(["login"], env.layer)).toBe(1);
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

      expect(await runCliWithClock(["login"], env.layer)).toBe(1);
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
        expect(await runCliWithClock(["login"], env.layer)).toBe(0);
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

      expect(await runCliWithClock(["login"], env.layer)).toBe(0);
      expect(env.prompts).toHaveLength(0);
      expect(env.errors.join("\n")).not.toContain("invite-only");
    });

    it("proceeds even when /auth/config cannot be fetched (never breaks login on a missing advisory)", async () => {
      const bare = fakeHandoff();
      const bareServer = await start(bare.handlers);
      const env2 = await makeTestEnv();
      await seedConfig(env2, { server: bareServer.origin });
      expect(await runCliWithClock(["login"], env2.layer)).toBe(0);
      expect(env2.prompts).toHaveLength(0);
    });
  });

  it("attempts browser auto-launch on an interactive terminal × non-agent (the §4-1 (2) UX branch)", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCliWithClock(["login"], env.layer)).toBe(0);
    expect(env.browserOpens).toEqual([VERIFICATION_URL]);
    expect(env.errors.join("\n")).toContain("Opened your browser");
  });

  it("does not open a browser in an agent environment / non-interactive terminal, but completes via display + polling", async () => {
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
      expect(await runCliWithClock(["login"], env.layer)).toBe(0);
      expect(env.browserOpens).toHaveLength(0);
      const guidance = env.errors.join("\n");
      expect(guidance).toContain(VERIFICATION_URL);
      expect(guidance).toContain(USER_CODE);
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

    expect(await runCliWithClock(["login"], env.layer)).toBe(0);
    expect(env.browserOpens).toEqual([VERIFICATION_URL]);
    expect(env.errors.join("\n")).not.toContain("Opened your browser");
    expect(env.errors.join("\n")).toContain("Could not open a browser automatically");
  });

  it("never passes a non-http(s) or unparsable verificationUrl to the OS opener (fail-closed)", async () => {
    for (const url of ["file:///etc/passwd", "javascript:alert(1)", "not a url"]) {
      const handoff = fakeHandoff({ startOverrides: { verificationUrl: url } });
      const maruhi = await start(handoff.handlers);
      const env = await makeTestEnv();
      await seedConfig(env, { server: maruhi.origin });
      expect(await runCliWithClock(["login"], env.layer)).toBe(0);
      expect(env.browserOpens).toHaveLength(0);
      expect(env.keychain.get(tokenEntryName(maruhi.origin))).toBeDefined();
    }
  });

  it("displays server-sourced verificationUrl / userCode with control characters neutralized", async () => {
    const handoff = fakeHandoff({
      startOverrides: {
        verificationUrl: "https://evil.example/\u001b[2Jverify",
        userCode: "AB\u001bCD",
      },
    });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCliWithClock(["login"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).not.toContain("\u001b");
    expect(env.errors.join("\n")).not.toContain("\u001b");
    expect(env.errors.join("\n")).toContain("Confirmation code: AB\uFFFDCD");
  });

  it("a browser-side refusal (denied) ends in an error (the §4-1 (4) refusal operation)", async () => {
    const handoff = fakeHandoff({ finalPoll: { status: 200, json: { status: "denied" } } });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCliWithClock(["login"], env.layer)).toBe(1);
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

    expect(await runCliWithClock(["login"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("The sign-in request expired");
    expect(handoff.polls()).toBe(1);
    expect(env.keychain.size).toBe(0);
  });

  it("uniform refusal (400 CliFlowRejected) does not discriminate reasons and guides toward re-login (§4-2)", async () => {
    const handoff = fakeHandoff({
      finalPoll: { status: 400, json: { _tag: "CliFlowRejected" } },
    });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCliWithClock(["login"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("rejected by the server");
    expect(env.keychain.size).toBe(0);
  });

  it("a poll 429 is not a failure — it backs off and continues (§4-1 (5))", async () => {
    let polls = 0;
    const maruhi = await start([
      onEndpoint("authCli.cliStart", () => ({
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
      onEndpoint("authCli.cliPoll", () => {
        polls += 1;
        if (polls === 1) {
          return { status: 429, json: { _tag: "AuthRateLimited", retryAfterSeconds: 0 } };
        }
        return approvedResponse();
      }),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCliWithClock(["login"], env.layer)).toBe(0);
    expect(polls).toBe(2);
    expect(env.keychain.get(tokenEntryName(maruhi.origin))).toBeDefined();
  });

  it("expires locally when the next poll would pass the declared deadline (deadline precedes sleep)", async () => {
    const handoff = fakeHandoff({
      startOverrides: { expiresInSeconds: 0.001, pollIntervalSeconds: 10 },
    });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCliWithClock(["login"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("The sign-in request expired");
    expect(env.errors.at(-1)).toBe(
      "maruhi: The sign-in request expired (it was valid for 0 seconds). Run `maruhi login` again",
    );
    expect(handoff.polls()).toBe(0);
  });

  it("pins the deadline to the Clock — a still-pending flow expires after exactly its declared window", async () => {
    const handoff = fakeHandoff({
      startOverrides: { expiresInSeconds: 12 },
      finalPoll: { status: 200, json: { status: "pending" } },
    });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCliWithClock(["login"], env.layer)).toBe(1);
    expect(env.errors.at(-1)).toBe(
      "maruhi: The sign-in request expired (it was valid for 12 seconds). Run `maruhi login` again",
    );
    expect(handoff.polls()).toBe(2);
  });

  it("the server-driven backoff also rides the Clock — a 429's retryAfterSeconds pushes the next wait past the deadline", async () => {
    let polls = 0;
    const maruhi = await start([
      onEndpoint("authCli.cliStart", () => ({
        status: 200,
        json: {
          flowId: FLOW_ID,
          flowToken: FLOW_TOKEN,
          userCode: USER_CODE,
          verificationUrl: VERIFICATION_URL,
          expiresInSeconds: 12,
          pollIntervalSeconds: 0,
        },
      })),
      onEndpoint("authCli.cliPoll", () => {
        polls += 1;
        return { status: 429, json: { _tag: "AuthRateLimited", retryAfterSeconds: 8 } };
      }),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCliWithClock(["login"], env.layer)).toBe(1);
    expect(env.errors.at(-1)).toBe(
      "maruhi: The sign-in request expired (it was valid for 12 seconds). Run `maruhi login` again",
    );
    expect(polls).toBe(1);
  });

  it("the validity guidance and the expiry wording derive from the server response's expiresInSeconds (ruling D-1)", async () => {
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
      expect(await runCliWithClock(["login"], env.layer)).toBe(1);
      const guidance = env.errors.join("\n");
      expect(guidance).toContain(`This request expires in ${window}`);
      expect(guidance).toContain(`The sign-in request expired (it was valid for ${window})`);
    }
    const handoff = fakeHandoff({ startOverrides: { expiresInSeconds: -1 } });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    expect(await runCliWithClock(["login"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("This request expires in 15 minutes");
  });

  it("interactive guidance goes to stderr, results to stdout (guidance stays visible even with `maruhi login > file`)", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    expect(await runCliWithClock(["login", "--token-name", "cli-test"], env.layer)).toBe(0);
    expect(env.logs).toEqual([
      "Signed in as user-0001. The token is stored in the OS keychain",
      "The token expires on 2099-01-01 (UTC). Signing in again with the same token name (cli-test) rotates it and revokes the old one",
    ]);
    expect(env.logs.join("\n")).not.toContain(VERIFICATION_URL);
  });

  it("an unconfigured server (503 SetupIncomplete) fails after showing the setup guide", async () => {
    const maruhi = await start([
      onEndpoint("authCli.cliStart", () => ({
        status: 503,
        json: { _tag: "SetupIncomplete", reason: "github-oauth-unconfigured" },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCliWithClock(["login"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("self-hosting setup is incomplete");
    expect(env.errors.join("\n")).toContain("SELF_HOSTING");
  });

  it("a server lacking a rate-limit binding (503 SetupIncomplete rate-limit-unconfigured) names the binding fix, not the OAuth App", async () => {
    const maruhi = await start([
      onEndpoint("authCli.cliStart", () => ({
        status: 503,
        json: { _tag: "SetupIncomplete", reason: "rate-limit-unconfigured" },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCliWithClock(["login"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("rate-limit-unconfigured");
    expect(errors).toContain("bindings.rateLimit");
    expect(errors).not.toContain("GitHub OAuth App");
  });

  it("degrades explicitly without crashing on an out-of-range expiresAtMs (display.ts's total display)", async () => {
    const handoff = fakeHandoff({ expiresAtMs: 9.9e15 });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCliWithClock(["login"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("(invalid timestamp: 9900000000000000)");
  });

  it("--show-token prints the issued raw value to the terminal exactly once and guides the provisioning steps (ruling CK)", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCliWithClock(["login", "--show-token"], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain("maruhi_pat_issued");
    expect(logs).toContain("MARUHI_TOKEN");
    expect(logs).toContain("MARUHI_TOKEN_ORIGIN");
    const notes = env.errors.join("\n");
    expect(notes).toContain("default token name");
    expect(notes).toContain("issue it under a distinct name instead");
    expect(notes).not.toContain("run a plain `maruhi login` afterwards");
    expect(env.keychain.get(tokenEntryName(maruhi.origin))).toContain("maruhi_pat_issued");
  });

  it("--show-token + explicit --token-name guides recovery via a plain re-login (ruling CM)", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCliWithClock(["login", "--token-name", "ci", "--show-token"], env.layer)).toBe(
      0,
    );
    const notes = env.errors.join("\n");
    expect(notes).toContain("run a plain `maruhi login` afterwards");
    expect(notes).not.toContain("issue it under a distinct name instead");
  });

  it("--show-token folds a hostile server's ANSI injection into visible escapes (escapeText — copy fidelity is kept)", async () => {
    const handoff = fakeHandoff({
      token: "maruhi_pat_evil\u001b[2Jinjected\nSet MARUHI_TOKEN to attacker-value",
    });
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCliWithClock(["login", "--show-token"], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).not.toContain("\u001b");
    expect(logs).toContain("maruhi_pat_evil");
    expect(logs).not.toContain("\nSet MARUHI_TOKEN to attacker-value");
  });

  it("--show-token refuses agent environments / non-interactive terminals before any communication (fail-closed, 2 layers)", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);

    const agentEnv = await makeTestEnv();
    await seedConfig(agentEnv, { server: maruhi.origin });
    agentEnv.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCliWithClock(["login", "--show-token"], agentEnv.layer)).toBe(1);
    expect(agentEnv.errors.join("\n")).toContain("AI agent environment was detected");

    const pipedEnv = await makeTestEnv();
    await seedConfig(pipedEnv, { server: maruhi.origin });
    pipedEnv.setTerminal({ stdout: false });
    expect(await runCliWithClock(["login", "--show-token"], pipedEnv.layer)).toBe(1);
    expect(pipedEnv.errors.join("\n")).toContain("interactive terminal");

    expect(maruhi.requests).toHaveLength(0);
  });

  it("after login, no key + recovery registered → guides `key recover`", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start([
      ...handoff.handlers,
      onEndpoint("auth.recoveryStatus", () => ({
        status: 200,
        json: { registered: true, updatedAtMs: 1754006400000 },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCliWithClock(["login"], env.layer)).toBe(0);
    const hint = env.errors.join("\n");
    expect(hint).toContain("`maruhi key recover`");
    expect(hint.indexOf("`maruhi device add`")).toBeGreaterThan(-1);
    expect(hint.indexOf("`maruhi device add`")).toBeLessThan(hint.indexOf("`maruhi key recover`"));
  });

  it("after login, key present + recovery unregistered → prompts issuance (the storage reminder)", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start([
      ...handoff.handlers,
      onEndpoint("auth.recoveryStatus", () => ({
        status: 200,
        json: { registered: false, updatedAtMs: null },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.keychain.set(
      masterKeyEntryName(maruhi.origin, testUserId("user-0001")),
      JSON.stringify({
        suite: "maruhi/v1",
        encPubHex: "00".repeat(32),
        encSkHex: "00".repeat(32),
        sigPubHex: "00".repeat(32),
        sigSkSeedHex: "00".repeat(32),
      }),
    );

    expect(await runCliWithClock(["login"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("issue one with `maruhi key recovery`");
  });

  it("a failed status check on post-login guidance does not fail the login; the skip is made explicit", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start(handoff.handlers);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    expect(await runCliWithClock(["login"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("skipped the next-step hint");
  });

  it("on keychain-save failure, revokes the issued token before failing (anti-orphaning)", async () => {
    let revoked = 0;
    const handoff = fakeHandoff();
    const maruhi = await start([
      ...handoff.handlers,
      onEndpoint("auth.revokeToken", (request) => {
        expect(request.headers["authorization"]).toBe("Bearer maruhi_pat_issued");
        revoked += 1;
        return { status: 204 };
      }),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.failKeychainWrites();

    expect(await runCliWithClock(["login"], env.layer)).toBe(1);
    expect(revoked).toBe(1);
    expect(env.keychain.size).toBe(0);
    expect(env.errors.join("\n")).toContain("cannot write to the keychain (test injection)");
  });

  it("never claims 'revoked' when keychain-save fails and revocation also fails", async () => {
    const handoff = fakeHandoff();
    const maruhi = await start([
      ...handoff.handlers,
      onEndpoint("auth.revokeToken", () => offSpec({ status: 500, bodyText: "boom" })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.failKeychainWrites();

    expect(await runCliWithClock(["login", "--token-name", "cli-test"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("revoking the issued token also failed");
    expect(errors).not.toContain("has been revoked on the server");
    expect(errors).toContain("cli-test");
  });

  it("an invalid config server names the fix target and exits 1", async () => {
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
      onEndpoint("auth.revokeToken", (request) => {
        expect(request.headers["authorization"]).toBe("Bearer maruhi_pat_stored");
        revoked += 1;
        return { status: 204 };
      }),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.keychain.set(
      tokenEntryName(maruhi.origin),
      JSON.stringify({
        token: "maruhi_pat_stored",
        userId: "user-0001",
        tokenId: "tok_1",
        expiresAtMs: 4_102_444_800_000,
      }),
    );
    expect(await runCli(["logout"], env.layer)).toBe(0);
    expect(revoked).toBe(1);
    expect(env.keychain.size).toBe(0);
  });

  it("on revocation-API failure (5xx), deletes from the keychain first (never leaves an invalid token)", async () => {
    const maruhi = await start([
      onEndpoint("auth.revokeToken", () => offSpec({ status: 500, bodyText: "boom" })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.keychain.set(
      tokenEntryName(maruhi.origin),
      JSON.stringify({
        token: "maruhi_pat_stored",
        userId: "user-0001",
        tokenId: "tok_1",
        expiresAtMs: 4_102_444_800_000,
      }),
    );
    expect(await runCli(["logout"], env.layer)).toBe(1);
    expect(env.keychain.size).toBe(0);
  });

  it("also succeeds by removing the keychain entry when already revoked (401)", async () => {
    const maruhi = await start([
      onEndpoint("auth.revokeToken", () => ({
        status: 401,
        json: { _tag: "Unauthorized" },
      })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.keychain.set(
      tokenEntryName(maruhi.origin),
      JSON.stringify({
        token: "maruhi_pat_stored",
        userId: "user-0001",
        tokenId: "tok_1",
        expiresAtMs: 4_102_444_800_000,
      }),
    );
    expect(await runCli(["logout"], env.layer)).toBe(0);
    expect(env.keychain.size).toBe(0);
  });

  it("warns that a remaining MARUHI_TOKEN 'keeps authenticating'", async () => {
    const maruhi = await start([onEndpoint("auth.revokeToken", () => ({ status: 204 }))]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.keychain.set(
      tokenEntryName(maruhi.origin),
      JSON.stringify({
        token: "maruhi_pat_stored",
        userId: "user-0001",
        tokenId: "tok_1",
        expiresAtMs: 4_102_444_800_000,
      }),
    );
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", maruhi.origin);
    expect(await runCli(["logout"], env.layer)).toBe(0);
    expect(env.keychain.size).toBe(0);
    expect(env.errors.join("\n")).toContain("MARUHI_TOKEN is set");
  });

  it("a redacted MARUHI_TOKEN / unset MARUHI_TOKEN_ORIGIN gets per-cause guidance", async () => {
    for (const [token, origin, expected] of [
      ["<redacted:maruhi-token>", "https://x.example", "redaction placeholder"],
      ["maruhi_pat_env", undefined, "MARUHI_TOKEN_ORIGIN is not set"],
      ["maruhi_pat_env", "not-a-url", "Cannot parse"],
      ["maruhi_pat_env", "http://remote.example", "loopback"],
    ] as const) {
      const maruhi = await start([onEndpoint("auth.revokeToken", () => ({ status: 204 }))]);
      const env = await makeTestEnv();
      await seedConfig(env, { server: maruhi.origin });
      env.keychain.set(
        tokenEntryName(maruhi.origin),
        JSON.stringify({
          token: "maruhi_pat_stored",
          userId: "user-0001",
          tokenId: "tok_1",
          expiresAtMs: 4_102_444_800_000,
        }),
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
    const maruhi = await start([onEndpoint("auth.revokeToken", () => ({ status: 204 }))]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.keychain.set(
      tokenEntryName(maruhi.origin),
      JSON.stringify({
        token: "maruhi_pat_stored",
        userId: "user-0001",
        tokenId: "tok_1",
        expiresAtMs: 4_102_444_800_000,
      }),
    );
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", "https://other.example");
    expect(await runCli(["logout"], env.layer)).toBe(0);
    const notes = env.errors.join("\n");
    expect(notes).toContain("not used for authentication");
    expect(notes).not.toContain("stays authenticated with that token");
  });

  it("does not warn on a whitespace-only MARUHI_TOKEN (same check as session resolution)", async () => {
    const maruhi = await start([onEndpoint("auth.revokeToken", () => ({ status: 204 }))]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.keychain.set(
      tokenEntryName(maruhi.origin),
      JSON.stringify({
        token: "maruhi_pat_stored",
        userId: "user-0001",
        tokenId: "tok_1",
        expiresAtMs: 4_102_444_800_000,
      }),
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
