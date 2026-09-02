// 運用基盤 H3 — トリップワイヤの計数・評価・通知(docs/notes/hosted-ops.md §2-A / §2-B / §3)。
//
// - 計数の出所: GitHub token 請求は exchangeCode の装飾(実経路 = CLI ハンドオフの
//   ログイン 1 回 = 1 計上)、フロー上限到達は noteOpsCounter
// - 評価: 固定窓の最大値・既存監査行(auth.signup_denied 等)の窓集計
// - 通知: 遷移(firing / resolved)と再通知の導出は純関数で固定し、本文に識別子が
//   載らないこと・送信失敗時に状態を進めないことを実 D1 で固定する

import { env } from "cloudflare:test";
import { Context, Effect } from "effect";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { makeDbServices, OpsRepo, opsWindowStart } from "../src/db.package/index.ts";
import type { OpsAlertPayload, OpsSignal } from "../src/ops-alerts.ts";
import {
  deriveAlertEvents,
  evaluateOpsSignals,
  makeWebhookNotifier,
  OpsNotifier,
  runOpsAlerts,
} from "../src/ops-alerts.ts";
import {
  OPS_ALERT_RENOTIFY_MS,
  OPS_GITHUB_TOKEN_REQUESTS_PER_HOUR_THRESHOLD,
  OPS_SIGNUP_DENIED_PER_HOUR_THRESHOLD,
} from "../src/ops-policy.ts";
import { noteOpsCounter } from "../src/ops-signals.ts";
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

/** 捕捉する通知先(delivered を切り替えられる)。 */
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

describe("計数の出所(hosted-ops.md §2-A)", () => {
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

describe("評価(hosted-ops.md §3)", () => {
  it("fires on the per-hour token request threshold and on signup-denied rows / suppression markers", async () => {
    const now = Date.now();
    await seedCounter(
      "github_token_requests",
      opsWindowStart(now),
      OPS_GITHUB_TOKEN_REQUESTS_PER_HOUR_THRESHOLD,
    );
    await seedAuditRows("auth.signup_denied", now - 60_000, OPS_SIGNUP_DENIED_PER_HOUR_THRESHOLD);
    await seedAuditRows("auth.login_failed_suppressed", now - 60_000, 1);
    // 古い窓(8 日前)は評価前に掃除される
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

describe("通知(hosted-ops.md §2-B)", () => {
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
    // 送れなかった = 状態は進めない → 次回も同じ遷移が導出される
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
    // 本文に識別子が載らない(ユーザー ID・64 hex のプロジェクト ID・トークン形)
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
    expect(
      await Effect.runPromise(makeWebhookNotifier(env.OPS_ALERT_WEBHOOK_URL).notify(payload)),
    ).toBe(true);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      expect(await Effect.runPromise(makeWebhookNotifier(undefined).notify(payload))).toBe(true);
      expect(warn).toHaveBeenCalledWith(
        "ops signal firing: storage_warn_projects (value 1, threshold 1)",
      );
      // 到達不能な URL は false(次回再送)— 無言にしない
      expect(
        await Effect.runPromise(
          makeWebhookNotifier("https://unreachable.invalid/hook").notify(payload),
        ),
      ).toBe(false);
    } finally {
      warn.mockRestore();
    }
  });
});
