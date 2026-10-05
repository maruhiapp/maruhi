// Operations foundation — tripwire counting, evaluation, and notification
// (docs/notes/hosted-ops.md §2-A / §2-B / §3).
//
// - Sources of counting: GitHub token requests are counted by decorating
//   exchangeCode (the real path — one login via the CLI handoff = one count);
//   reaching the flow cap is counted by noteOpsCounter
// - Evaluation: per-window maximums, window aggregation of existing audit
//   rows (auth.signup_denied etc.)
// - Notification: deriving transitions (firing / resolved) and
//   re-notification is pinned as a pure function; that the body carries no
//   identifiers and that state does not advance on a failed send are pinned
//   against real D1

import { env } from "cloudflare:test";
import { Context, Effect, Fiber, Redacted } from "effect";
import { FetchHttpClient } from "effect/http";
import { TestClock } from "effect/testing";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { makeDbServices, OpsRepo, opsWindowStart } from "../src/db.package/index.ts";
import type { OpsAlertPayload, OpsSignal } from "../src/ops/ops-alerts.ts";
import {
  deriveAlertEvents,
  evaluateOpsSignals,
  makeWebhookNotifier,
  OpsNotifier,
  runOpsAlerts,
} from "../src/ops/ops-alerts.ts";
import {
  OPS_ALERT_RENOTIFY_MS,
  OPS_GITHUB_TOKEN_REQUESTS_PER_HOUR_THRESHOLD,
  OPS_SIGNUP_DENIED_PER_HOUR_THRESHOLD,
} from "../src/ops/ops-policy.ts";
import { noteOpsCounter } from "../src/ops/ops-signals.ts";
import { ServerLoggerLive } from "../src/server-logger.ts";
import { readWorkerSecrets } from "../src/worker-env.ts";
import { cliToken, resetAuthDb, seedUser } from "./support/auth.ts";

const ops = () => Context.get(makeDbServices(env.DB), OpsRepo);
const runOps = <A>(program: Effect.Effect<A, never, OpsRepo>): Promise<A> =>
  Effect.runPromise(program.pipe(Effect.provideService(OpsRepo, ops())));

async function seedCounter(metric: string, windowStart: number, count: number): Promise<void> {
  await env.DB.prepare("INSERT INTO ops_counters (metric, window_start, count) VALUES (?, ?, ?)")
    .bind(metric, windowStart, count)
    .run();
}

async function seedAuditRows(event: string, serverTs: number, n: number): Promise<void> {
  for (let i = 0; i < n; i++) {
    await env.DB.prepare(
      "INSERT INTO user_audit_events (row_id, server_ts, event, actor_type, payload) VALUES (?, ?, ?, 'user', '{}')",
    )
      .bind(`${event}-${serverTs}-${i}`, serverTs, event)
      .run();
  }
}

/** A notification target that captures payloads (delivered is switchable). */
function capturingNotifier(delivered = true): {
  payloads: OpsAlertPayload[];
  service: OpsNotifier["Service"];
} {
  const payloads: OpsAlertPayload[] = [];
  return {
    payloads,
    service: {
      notify: (payload) =>
        Effect.sync(() => {
          payloads.push(payload);
          return delivered;
        }),
    },
  };
}

beforeEach(async () => {
  await resetAuthDb();
});

describe("sources of counting (hosted-ops.md §2-A)", () => {
  it("counts one GitHub token request per CLI handoff login (exchangeCode decoration)", async () => {
    await seedUser("user-ops-0001", 4201);
    await cliToken(4201);
    const windows = await runOps(
      Effect.flatMap(OpsRepo, (repo) => repo.counterWindows("github_token_requests", 0)),
    );
    expect(windows).toEqual([{ windowStart: opsWindowStart(Date.now()), count: 1 }]);
    await cliToken(4201);
    const again = await runOps(
      Effect.flatMap(OpsRepo, (repo) => repo.counterWindows("github_token_requests", 0)),
    );
    expect(again[0]?.count).toBe(2);
  });

  it("noteOpsCounter increments the flow-capacity counter", async () => {
    await runOps(noteOpsCounter("cli_flow_capacity"));
    const windows = await runOps(
      Effect.flatMap(OpsRepo, (repo) => repo.counterWindows("cli_flow_capacity", 0)),
    );
    expect(windows[0]?.count).toBe(1);
  });
});

const firingSignal = (firing: boolean): OpsSignal => ({
  name: "cli_flow_capacity_reached",
  value: firing ? 1 : 0,
  threshold: 1,
  firing,
});

describe("evaluation (hosted-ops.md §3)", () => {
  it("fires on the per-hour token request threshold and on signup-denied rows / suppression markers", async () => {
    const now = Date.now();
    await seedCounter(
      "github_token_requests",
      opsWindowStart(now),
      OPS_GITHUB_TOKEN_REQUESTS_PER_HOUR_THRESHOLD,
    );
    await seedAuditRows("auth.signup_denied", now - 60_000, OPS_SIGNUP_DENIED_PER_HOUR_THRESHOLD);
    await seedAuditRows("auth.login_failed_suppressed", now - 60_000, 1);
    // Old windows (8 days back) are cleaned up before evaluation
    await seedCounter("cli_flow_capacity", opsWindowStart(now - 8 * 24 * 3600_000), 5);
    const signals = await runOps(evaluateOpsSignals(now));
    const byName = Object.fromEntries(signals.map((signal) => [signal.name, signal]));
    expect(byName["github_token_requests_per_hour"]).toMatchObject({
      firing: true,
      value: OPS_GITHUB_TOKEN_REQUESTS_PER_HOUR_THRESHOLD,
    });
    expect(byName["signup_denied_per_hour"]).toMatchObject({
      firing: true,
      value: OPS_SIGNUP_DENIED_PER_HOUR_THRESHOLD,
    });
    expect(byName["signup_denied_suppressed"]).toMatchObject({ firing: false, value: 0 });
    expect(byName["login_failed_suppressed"]).toMatchObject({ firing: true, value: 1 });
    expect(byName["cli_flow_capacity_reached"]).toMatchObject({ firing: false, value: 0 });
    expect(byName["storage_warn_projects"]).toMatchObject({ firing: false, value: 0 });
    const remaining = await env.DB.prepare(
      "SELECT count(*) AS n FROM ops_counters WHERE metric = 'cli_flow_capacity'",
    ).first<{ n: number }>();
    expect(remaining?.n).toBe(0);
  });

  it("derives firing / resolved transitions and a re-notification after the interval (pure)", () => {
    const t0 = 1_000_000;
    const first = deriveAlertEvents([firingSignal(true)], {}, t0);
    expect(first.events).toEqual([
      { signal: "cli_flow_capacity_reached", state: "firing", value: 1, threshold: 1 },
    ]);
    const quiet = deriveAlertEvents([firingSignal(true)], first.next, t0 + 3600_000);
    expect(quiet.events).toEqual([]);
    const reminded = deriveAlertEvents(
      [firingSignal(true)],
      quiet.next,
      t0 + OPS_ALERT_RENOTIFY_MS,
    );
    expect(reminded.events).toHaveLength(1);
    const resolved = deriveAlertEvents(
      [firingSignal(false)],
      reminded.next,
      t0 + OPS_ALERT_RENOTIFY_MS + 1,
    );
    expect(resolved.events).toEqual([
      { signal: "cli_flow_capacity_reached", state: "resolved", value: 0, threshold: 1 },
    ]);
    expect(
      deriveAlertEvents([firingSignal(false)], resolved.next, t0 + 2 * OPS_ALERT_RENOTIFY_MS)
        .events,
    ).toEqual([]);
  });
});

describe("notification (hosted-ops.md §2-B)", () => {
  it("sends static signal names with aggregate values only, persists state on delivery and re-sends after a failed delivery", async () => {
    await seedUser("user-ops-0002", 4202);
    const now = Date.now();
    await seedCounter("cli_flow_capacity", opsWindowStart(now), 1);
    const failing = capturingNotifier(false);
    const first = await Effect.runPromise(
      runOpsAlerts(now).pipe(
        Effect.provideService(OpsNotifier, failing.service),
        Effect.provideService(OpsRepo, ops()),
      ),
    );
    expect(first).toEqual([
      { signal: "cli_flow_capacity_reached", state: "firing", value: 1, threshold: 1 },
    ]);
    // Could not send = state does not advance -> the same transition is
    // derived next time
    expect(await runOps(Effect.flatMap(OpsRepo, (repo) => repo.getState("alerts")))).toBeNull();

    const capturing = capturingNotifier(true);
    const second = await Effect.runPromise(
      runOpsAlerts(now + 1).pipe(
        Effect.provideService(OpsNotifier, capturing.service),
        Effect.provideService(OpsRepo, ops()),
      ),
    );
    expect(second).toHaveLength(1);
    const payload = capturing.payloads[0];
    expect(payload?.service).toBe("maruhi");
    expect(payload?.text).toContain("cli_flow_capacity_reached is firing (value 1, threshold 1)");
    // The body carries no identifiers (user IDs, 64-hex project IDs, token
    // shapes)
    const serialized = JSON.stringify(payload);
    expect(serialized).not.toMatch(/user-ops/);
    expect(serialized).not.toMatch(/[0-9a-f]{64}/);
    expect(serialized).not.toMatch(/mh_|gho_/);
    expect(await runOps(Effect.flatMap(OpsRepo, (repo) => repo.getState("alerts")))).toContain(
      "cli_flow_capacity_reached",
    );

    const third = await Effect.runPromise(
      runOpsAlerts(now + 2).pipe(
        Effect.provideService(OpsNotifier, capturing.service),
        Effect.provideService(OpsRepo, ops()),
      ),
    );
    expect(third).toEqual([]);
  });

  it("the webhook notifier posts to the configured URL and only logs statically without one", async () => {
    const payload: OpsAlertPayload = {
      service: "maruhi",
      at: new Date(0).toISOString(),
      events: [{ signal: "storage_warn_projects", state: "firing", value: 1, threshold: 1 }],
      text: "maruhi ops: storage_warn_projects is firing (value 1, threshold 1)",
    };
    const runNotify = (notifier: OpsNotifier["Service"]): Promise<boolean> =>
      Effect.runPromise(notifier.notify(payload).pipe(Effect.provide(ServerLoggerLive)));
    // The URL arrives Redacted from the env (worker-env.ts)
    expect(await runNotify(makeWebhookNotifier(readWorkerSecrets(env).opsAlertWebhookUrl))).toBe(
      true,
    );
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      expect(await runNotify(makeWebhookNotifier(undefined))).toBe(true);
      expect(warn).toHaveBeenCalledWith(
        "ops signal firing: storage_warn_projects (value 1, threshold 1)",
      );
      // An unreachable URL (the outbound fake answers 500) returns false
      // (resent next time) with the same static line — never swallowed
      // silently
      expect(
        await runNotify(makeWebhookNotifier(Redacted.make("https://unreachable.invalid/hook"))),
      ).toBe(false);
      expect(warn).toHaveBeenCalledWith(
        "ops alert webhook responded with a non-2xx status; retrying on the next evaluation",
      );
      // The URL is a secret: it appears in no warn line
      expect(JSON.stringify(warn.mock.calls)).not.toContain("unreachable.invalid");
      expect(JSON.stringify(warn.mock.calls)).not.toContain("ops-webhook.test");
    } finally {
      warn.mockRestore();
    }
  });

  it("a webhook POST that never answers resolves to false once the timeout elapses (the scheduled run is not blocked)", async () => {
    // The webhook path runs inside the cron Effect (scheduled()) — not in
    // a workerd request handler — so the clock is drivable by TestClock.
    // fetch is swapped per run through the FetchHttpClient's `Fetch`
    // reference (github.test.ts's pattern)
    const payload: OpsAlertPayload = {
      service: "maruhi",
      at: new Date(0).toISOString(),
      events: [{ signal: "storage_warn_projects", state: "firing", value: 1, threshold: 1 }],
      text: "maruhi ops: storage_warn_projects is firing (value 1, threshold 1)",
    };
    const hangingFetch = (() => new Promise<Response>(() => {})) as typeof fetch;
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const outcome = await Effect.runPromise(
        Effect.gen(function* () {
          const fiber = yield* Effect.forkChild(
            makeWebhookNotifier(Redacted.make("https://ops-webhook.test/hook")).notify(payload),
          );
          yield* TestClock.adjust("5 seconds");
          return yield* Fiber.join(fiber);
        }).pipe(
          Effect.provide(TestClock.layer()),
          Effect.provideService(FetchHttpClient.Fetch, hangingFetch),
          Effect.provide(ServerLoggerLive),
        ),
      );
      expect(outcome).toBe(false);
      expect(warn).toHaveBeenCalledWith(
        "ops alert webhook request failed; retrying on the next evaluation",
        "TimeoutError",
      );
      expect(JSON.stringify(warn.mock.calls)).not.toContain("ops-webhook.test");
    } finally {
      warn.mockRestore();
    }
  });

  it("restarts from an empty state on a malformed stored state row (the same static line)", async () => {
    const now = Date.now();
    await seedCounter("cli_flow_capacity", opsWindowStart(now), 1);
    // Stored rows the cast accepted (or crashed on) but the Schema
    // decode rejects — unparseable text, JSON null (the cast's
    // TypeError defect), a bare array, a wrong-shaped entry. The
    // outcome is the same line + restart from "all inactive"
    // (operational state only)
    const malformed = [
      "not json",
      "null",
      "[1,2]",
      '{"cli_flow_capacity_reached":{"active":"yes"}}',
    ];
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      for (const stored of malformed) {
        await runOps(Effect.flatMap(OpsRepo, (repo) => repo.setState("alerts", stored, now)));
        warn.mockClear();
        const capturing = capturingNotifier(true);
        const events = await Effect.runPromise(
          runOpsAlerts(now).pipe(
            Effect.provideService(OpsNotifier, capturing.service),
            Effect.provideService(OpsRepo, ops()),
            Effect.provide(ServerLoggerLive),
          ),
        );
        expect(events).toEqual([
          { signal: "cli_flow_capacity_reached", state: "firing", value: 1, threshold: 1 },
        ]);
        expect(warn).toHaveBeenCalledTimes(1);
        expect(warn).toHaveBeenCalledWith(
          "ops alert state row is not valid JSON; starting from an empty state",
        );
        // The state saved is exactly the freshly derived one (started from {})
        expect(await runOps(Effect.flatMap(OpsRepo, (repo) => repo.getState("alerts")))).toBe(
          JSON.stringify({
            cli_flow_capacity_reached: { active: true, since: now, lastNotifiedAt: now },
          }),
        );
      }
    } finally {
      warn.mockRestore();
    }
  });
});
