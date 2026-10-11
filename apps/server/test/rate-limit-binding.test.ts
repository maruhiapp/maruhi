// The failure directions of the per-source-IP rate-limit binding pattern
// (AUTH_SPEC §4-1 (1) — 2026-10-11 S-2): every endpoint the pattern guards
// answers 503 SetupIncomplete (`rate-limit-unconfigured`) when its own
// binding is absent from the deployment, passes the request when a present
// binding's call fails (with one static warning that carries neither the
// address nor the failure's message), and otherwise consults its binding
// keyed by the source address.
//
// The worker is called directly with a swapped env (the auth.test.ts
// pattern); under vitest-pool-workers the worker shares the test's isolate,
// so a console spy sees its log lines (log-hygiene.test.ts).
import { testUserId, testVariableId } from "@maruhi/crypto/test-support";
import { env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import worker from "../src/index.ts";
import { BASE, JSON_HEADERS, resetAuthDb } from "./support/auth.ts";

type TestEnv = typeof env;

type RateLimitBinding =
  | "CLI_START_RATE_LIMIT"
  | "CLI_POLL_RATE_LIMIT"
  | "OAUTH_CALLBACK_RATE_LIMIT"
  | "SIGNUP_START_RATE_LIMIT"
  | "LEASE_RATE_LIMIT";

const SOURCE_IP = "203.0.113.50";

const workloadPath = (suffix: string): string =>
  `${BASE}/projects/${"ab".repeat(32)}/environments/env-app-0001/${suffix}`;

/**
 * The workload credential's wire shape (it passes the Schema and falls at
 * OIDC verification — lease-binding.test.ts's rate-limit barrage).
 */
const WORKLOAD_CREDENTIAL = { oidcToken: "aaaa.bbbb.cccc", ephemeralPubHex: "cd".repeat(32) };

interface LimitedRoute {
  readonly name: string;
  readonly binding: RateLimitBinding;
  readonly method: "GET" | "POST";
  readonly url: string;
  readonly body?: Record<string, unknown>;
  /** The answer once the limiter lets the request through (the handler's next stage). */
  readonly passedStatus: number;
}

const LIMITED_ROUTES: readonly LimitedRoute[] = [
  {
    name: "POST /auth/cli/start",
    binding: "CLI_START_RATE_LIMIT",
    method: "POST",
    url: `${BASE}/auth/cli/start`,
    body: {},
    passedStatus: 200,
  },
  {
    name: "POST /auth/cli/poll",
    binding: "CLI_POLL_RATE_LIMIT",
    method: "POST",
    url: `${BASE}/auth/cli/poll`,
    body: { flowId: "ab".repeat(16), flowToken: "not-a-flow-token" },
    // CliFlowRejected — the stateless MAC check after the limit
    passedStatus: 400,
  },
  {
    name: "GET /auth/github/callback",
    binding: "OAUTH_CALLBACK_RATE_LIMIT",
    method: "GET",
    url: `${BASE}/auth/github/callback?code=dummy-code&state=dummy-state`,
    // AuthFlow state-mismatch — no state cookie
    passedStatus: 400,
  },
  {
    name: "GET /auth/github/start?signup_code",
    binding: "SIGNUP_START_RATE_LIMIT",
    method: "GET",
    url: `${BASE}/auth/github/start?signup_code=maruhi_sgn_unknown`,
    // The script-free invalid-code page — the D1 pre-validation after the limit
    passedStatus: 400,
  },
  {
    name: "POST .../lease",
    binding: "LEASE_RATE_LIMIT",
    method: "POST",
    url: workloadPath("lease"),
    body: WORKLOAD_CREDENTIAL,
    // LeaseUnauthorized malformed-token — OIDC verification after the limit
    passedStatus: 401,
  },
  {
    name: "POST .../rotation-proposals",
    binding: "LEASE_RATE_LIMIT",
    method: "POST",
    url: workloadPath("rotation-proposals"),
    body: {
      ...WORKLOAD_CREDENTIAL,
      proposal: {
        proposalId: "00112233445566778899aabbccddeeff",
        connector: "exec",
        facts: [],
        expiresInDays: 7,
        variables: [
          {
            variableId: testVariableId("var-database-url"),
            baseVersion: 1,
            wraps: [
              {
                recipientUserId: testUserId("user-owner-0001"),
                recipientEncPubHex: "ef".repeat(32),
                encHex: "01".repeat(32),
                ciphertextHex: "02".repeat(17),
              },
            ],
          },
        ],
      },
    },
    passedStatus: 401,
  },
  {
    name: "POST .../rotation-proposals/preflight",
    binding: "LEASE_RATE_LIMIT",
    method: "POST",
    url: workloadPath("rotation-proposals/preflight"),
    body: {
      ...WORKLOAD_CREDENTIAL,
      variables: [{ variableId: testVariableId("var-database-url"), baseVersion: 1 }],
      recipients: [],
    },
    passedStatus: 401,
  },
];

/** Calls the worker for `route` under `routeEnv`, with or without a source address. */
function call(route: LimitedRoute, routeEnv: TestEnv, sourceIp?: string): Promise<Response> {
  const headers: Record<string, string> = route.body === undefined ? {} : { ...JSON_HEADERS };
  if (sourceIp !== undefined) {
    headers["cf-connecting-ip"] = sourceIp;
  }
  const request = new Request(route.url, {
    method: route.method,
    headers,
    body: route.body === undefined ? null : JSON.stringify(route.body),
    redirect: "manual",
  }) as Request<unknown, IncomingRequestCfProperties>;
  return worker.fetch(request, routeEnv);
}

/** The env as a deployment whose config lacks `binding`. */
function envWithout(binding: RateLimitBinding): TestEnv {
  return Object.fromEntries(Object.entries(env).filter(([name]) => name !== binding)) as TestEnv;
}

/** The env with `binding` replaced by a stand-in limiter. */
function envWith(binding: RateLimitBinding, limiter: RateLimit): TestEnv {
  return { ...env, [binding]: limiter };
}

/** A limiter that records the keys it is asked about and answers `success`. */
function recordingLimiter(success: boolean): {
  readonly limiter: RateLimit;
  readonly keys: string[];
} {
  const keys: string[] = [];
  return {
    keys,
    limiter: {
      limit: ({ key }) => {
        keys.push(key);
        return Promise.resolve({ success });
      },
    },
  };
}

const CONSOLE_METHODS = ["log", "info", "warn", "error", "debug"] as const;

/** Spies on every console method; returns each recorded call's arguments as one string. */
function spyConsole(): { readonly lines: () => string[]; readonly warn: () => unknown[][] } {
  const spies = CONSOLE_METHODS.map(
    (method) => [method, vi.spyOn(console, method).mockImplementation(() => {})] as const,
  );
  return {
    lines: () =>
      spies.flatMap(([, spy]) =>
        spy.mock.calls.map((args) =>
          args.map((arg) => (typeof arg === "string" ? arg : JSON.stringify(arg))).join(" "),
        ),
      ),
    warn: () => spies.find(([method]) => method === "warn")?.[1].mock.calls ?? [],
  };
}

beforeEach(async () => {
  await resetAuthDb();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("a missing rate-limit binding fails closed (503 SetupIncomplete)", () => {
  for (const route of LIMITED_ROUTES) {
    it(`${route.name} answers 503 rate-limit-unconfigured without ${route.binding}`, async () => {
      const unconfigured = envWithout(route.binding);
      // Judged ahead of the source-address attribution: an unattributable
      // request (no CF-Connecting-IP) does not slip past a missing binding
      for (const sourceIp of [SOURCE_IP, undefined]) {
        const response = await call(route, unconfigured, sourceIp);
        expect(response.status).toBe(503);
        expect(await response.json()).toEqual({
          _tag: "SetupIncomplete",
          reason: "rate-limit-unconfigured",
        });
      }
    });
  }

  it("a plain /auth/github/start (no signup_code) stays unlimited without SIGNUP_START_RATE_LIMIT", async () => {
    const response = await worker.fetch(
      new Request(`${BASE}/auth/github/start`, {
        headers: { "cf-connecting-ip": SOURCE_IP },
        redirect: "manual",
      }) as Request<unknown, IncomingRequestCfProperties>,
      envWithout("SIGNUP_START_RATE_LIMIT"),
    );
    expect(response.status).toBe(302);
  });
});

describe("a present binding is consulted per source address (the normal path)", () => {
  for (const route of LIMITED_ROUTES) {
    it(`${route.name} asks ${route.binding} and answers by its verdict`, async () => {
      const allowing = recordingLimiter(true);
      const passed = await call(route, envWith(route.binding, allowing.limiter), SOURCE_IP);
      expect(passed.status).toBe(route.passedStatus);
      expect(allowing.keys).toEqual([SOURCE_IP]);

      const refusing = recordingLimiter(false);
      const limited = await call(route, envWith(route.binding, refusing.limiter), SOURCE_IP);
      expect(limited.status).toBe(429);
      expect(refusing.keys).toEqual([SOURCE_IP]);

      // An unattributable request (direct arrival only) is not counted
      const unattributed = recordingLimiter(false);
      const direct = await call(route, envWith(route.binding, unattributed.limiter));
      expect(direct.status).toBe(route.passedStatus);
      expect(unattributed.keys).toEqual([]);
    });
  }
});

describe("a failing limiter call fails open with one static warning", () => {
  for (const route of LIMITED_ROUTES) {
    it(`${route.name} passes the request when ${route.binding} throws`, async () => {
      const logs = spyConsole();
      const failing: RateLimit = {
        limit: ({ key }) =>
          Promise.reject(new TypeError(`limiter outage for ${key} (internal-detail-marker)`)),
      };
      const response = await call(route, envWith(route.binding, failing), SOURCE_IP);
      expect(response.status).toBe(route.passedStatus);
      expect(logs.warn()).toContainEqual([
        "rate limiter call failed; allowing the request (fail-open)",
        "TypeError",
      ]);
      // Neither the address (the limiter key) nor the failure's message
      // reaches any log line
      const logged = logs.lines().join("\n");
      expect(logged).not.toContain(SOURCE_IP);
      expect(logged).not.toContain("internal-detail-marker");
    });
  }
});
