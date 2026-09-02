// トリップワイヤの評価と通知 — docs/notes/hosted-ops.md §2-B / §3。
//
// 毎時 cron(index.ts)から呼ばれる。入力は D1 に閉じる(運用カウンタ・退避記録・
// 既存の監査行の窓集計)。出力は「静的な信号名 + 集計値 + 閾値 + 状態」のみで、
// 識別子(プロジェクト ID・ユーザー ID 等)を含まない。
//
// 通知先は Workers Secret `OPS_ALERT_WEBHOOK_URL`(未設定 = 送信しない — 既定は無効)。
// 状態遷移(inactive → active / active → inactive)で通知し、active が続く間は
// OPS_ALERT_RENOTIFY_MS ごとに再通知する。送信失敗は握り潰さず静的 1 行 + 状態を
// 更新しない(次回の評価で再送)。webhook 未設定でも active な信号は静的 1 行を
// Workers Logs に残す(セルフホストの hook)。

import { Context, Effect } from "effect";

import { OpsRepo } from "./db.package/index.ts";
import {
  OPS_ALERT_RENOTIFY_MS,
  OPS_COUNTER_WINDOW_MS,
  OPS_GITHUB_TOKEN_REQUESTS_PER_HOUR_THRESHOLD,
  OPS_SIGNUP_DENIED_PER_HOUR_THRESHOLD,
} from "./ops-policy.ts";

const ALERT_STATE_KEY = "alerts";

/** 信号名(固定語彙 — hosted-ops §3)。 */
export type OpsSignalName =
  | "github_token_requests_per_hour"
  | "cli_flow_capacity_reached"
  | "signup_denied_per_hour"
  | "signup_denied_suppressed"
  | "login_failed_suppressed"
  | "storage_warn_projects"
  | "storage_reject_projects"
  | "backup_stale_projects"
  | "backup_failing_projects"
  | "backup_oversize_projects";

export interface OpsSignal {
  readonly name: OpsSignalName;
  readonly value: number;
  readonly threshold: number;
  readonly firing: boolean;
}

export interface OpsAlertEvent {
  readonly signal: OpsSignalName;
  readonly state: "firing" | "resolved";
  readonly value: number;
  readonly threshold: number;
}

/** webhook へ送る本文(識別子なし)。 */
export interface OpsAlertPayload {
  readonly service: "maruhi";
  readonly at: string;
  readonly events: readonly OpsAlertEvent[];
  readonly text: string;
}

interface AlertState {
  readonly active: boolean;
  readonly since: number;
  readonly lastNotifiedAt: number;
}

type AlertStates = Partial<Record<OpsSignalName, AlertState>>;

/** 通知の送り口(テストは捕捉実装を差す)。true = 送れた / 送る先が無い。 */
export interface OpsNotifierShape {
  readonly notify: (payload: OpsAlertPayload) => Effect.Effect<boolean>;
}

export class OpsNotifier extends Context.Service<OpsNotifier, OpsNotifierShape>()("OpsNotifier") {}

/** 本番実装: webhook URL が設定されていれば JSON を POST する。 */
export function makeWebhookNotifier(webhookUrl: string | undefined): OpsNotifierShape {
  return {
    notify: (payload) =>
      Effect.promise(async () => {
        if (webhookUrl === undefined || webhookUrl === "") {
          for (const event of payload.events) {
            // 静的な信号名 + 集計値のみ
            console.warn(
              `ops signal ${event.state}: ${event.signal} (value ${event.value}, threshold ${event.threshold})`,
            );
          }
          return true;
        }
        try {
          const response = await fetch(webhookUrl, {
            method: "POST",
            headers: { "content-type": "application/json", "user-agent": "maruhi" },
            body: JSON.stringify(payload),
          });
          if (!response.ok) {
            console.warn(
              "ops alert webhook responded with a non-2xx status; retrying on the next evaluation",
            );
            return false;
          }
          return true;
        } catch (error) {
          // URL・応答本文は書かない(種別名のみ)
          console.warn(
            "ops alert webhook request failed; retrying on the next evaluation",
            error instanceof Error ? error.name : "unknown",
          );
          return false;
        }
      }),
  };
}

function maxWindow(windows: readonly { readonly count: number }[]): number {
  return windows.reduce((max, window) => Math.max(max, window.count), 0);
}

function sumWindows(windows: readonly { readonly count: number }[]): number {
  return windows.reduce((sum, window) => sum + window.count, 0);
}

const makeSignal = (name: OpsSignalName, value: number, threshold: number): OpsSignal => ({
  name,
  value,
  threshold,
  firing: value >= threshold,
});

/** 信号の評価(通知しない — 純粋な集計)。 */
export function evaluateOpsSignals(
  nowMs: number,
): Effect.Effect<readonly OpsSignal[], never, OpsRepo> {
  return Effect.gen(function* () {
    const ops = yield* OpsRepo;
    yield* ops.pruneCounters(nowMs);
    const twoWindowsAgo = nowMs - 2 * OPS_COUNTER_WINDOW_MS;
    const lastHour = nowMs - OPS_COUNTER_WINDOW_MS;
    const tokenRequests = maxWindow(
      yield* ops.counterWindows("github_token_requests", twoWindowsAgo),
    );
    const capacity = sumWindows(yield* ops.counterWindows("cli_flow_capacity", twoWindowsAgo));
    const signupDenied = yield* ops.auditEventCountSince("auth.signup_denied", lastHour);
    const signupSuppressed = yield* ops.auditEventCountSince(
      "auth.signup_denied_suppressed",
      lastHour,
    );
    const loginSuppressed = yield* ops.auditEventCountSince(
      "auth.login_failed_suppressed",
      lastHour,
    );
    const backups = yield* ops.backupSummary(nowMs);
    return [
      makeSignal(
        "github_token_requests_per_hour",
        tokenRequests,
        OPS_GITHUB_TOKEN_REQUESTS_PER_HOUR_THRESHOLD,
      ),
      makeSignal("cli_flow_capacity_reached", capacity, 1),
      makeSignal("signup_denied_per_hour", signupDenied, OPS_SIGNUP_DENIED_PER_HOUR_THRESHOLD),
      makeSignal("signup_denied_suppressed", signupSuppressed, 1),
      makeSignal("login_failed_suppressed", loginSuppressed, 1),
      makeSignal("storage_warn_projects", backups.storageWarnProjects, 1),
      makeSignal("storage_reject_projects", backups.storageRejectProjects, 1),
      makeSignal("backup_stale_projects", backups.staleProjects, 1),
      makeSignal("backup_failing_projects", backups.failingProjects, 1),
      makeSignal("backup_oversize_projects", backups.oversizeProjects, 1),
    ];
  });
}

function parseStates(raw: string | null): AlertStates {
  if (raw === null) {
    return {};
  }
  try {
    return JSON.parse(raw) as AlertStates;
  } catch {
    // 破損した状態行は「全て inactive」から始め直す(運用状態のみ — 監査ではない)
    console.warn("ops alert state row is not valid JSON; starting from an empty state");
    return {};
  }
}

/** 遷移(と再通知)の導出 — 純関数(テストが固定する)。 */
export function deriveAlertEvents(
  signals: readonly OpsSignal[],
  states: AlertStates,
  nowMs: number,
): { readonly events: readonly OpsAlertEvent[]; readonly next: AlertStates } {
  const events: OpsAlertEvent[] = [];
  const next: AlertStates = { ...states };
  for (const signal of signals) {
    const previous = states[signal.name] ?? { active: false, since: 0, lastNotifiedAt: 0 };
    if (signal.firing && !previous.active) {
      events.push({
        signal: signal.name,
        state: "firing",
        value: signal.value,
        threshold: signal.threshold,
      });
      next[signal.name] = { active: true, since: nowMs, lastNotifiedAt: nowMs };
    } else if (signal.firing && nowMs - previous.lastNotifiedAt >= OPS_ALERT_RENOTIFY_MS) {
      events.push({
        signal: signal.name,
        state: "firing",
        value: signal.value,
        threshold: signal.threshold,
      });
      next[signal.name] = { ...previous, lastNotifiedAt: nowMs };
    } else if (!signal.firing && previous.active) {
      events.push({
        signal: signal.name,
        state: "resolved",
        value: signal.value,
        threshold: signal.threshold,
      });
      next[signal.name] = { active: false, since: nowMs, lastNotifiedAt: nowMs };
    }
  }
  return { events, next };
}

function describe(events: readonly OpsAlertEvent[]): string {
  return events
    .map(
      (event) =>
        `${event.signal} is ${event.state} (value ${event.value}, threshold ${event.threshold})`,
    )
    .join("; ");
}

/**
 * 評価 → 遷移の導出 → 通知 → 状態の保存。通知に失敗したら状態を保存しない
 * (次回の評価で同じ遷移が再導出され再送される)。
 */
export function runOpsAlerts(
  nowMs: number,
): Effect.Effect<readonly OpsAlertEvent[], never, OpsRepo | OpsNotifier> {
  return Effect.gen(function* () {
    const ops = yield* OpsRepo;
    const notifier = yield* OpsNotifier;
    const signals = yield* evaluateOpsSignals(nowMs);
    const states = parseStates(yield* ops.getState(ALERT_STATE_KEY));
    const { events, next } = deriveAlertEvents(signals, states, nowMs);
    if (events.length === 0) {
      return events;
    }
    const payload: OpsAlertPayload = {
      service: "maruhi",
      at: new Date(nowMs).toISOString(),
      events,
      text: `maruhi ops: ${describe(events)}`,
    };
    const delivered = yield* notifier.notify(payload);
    if (delivered) {
      yield* ops.setState(ALERT_STATE_KEY, JSON.stringify(next), nowMs);
    }
    return events;
  });
}
