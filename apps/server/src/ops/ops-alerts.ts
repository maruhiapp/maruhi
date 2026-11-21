import { egressHttpClientLayer } from "@maruhi/core";
import { Context, Duration, Effect, Redacted, Schema } from "effect";
import { HttpClient, HttpClientRequest } from "effect/http";

import { OpsRepo } from "../db.package/index.ts";
import {
  OPS_ALERT_RENOTIFY_MS,
  OPS_COUNTER_WINDOW_MS,
  OPS_GITHUB_TOKEN_REQUESTS_PER_HOUR_THRESHOLD,
  OPS_SIGNUP_DENIED_PER_HOUR_THRESHOLD,
} from "./ops-policy.ts";

const ALERT_STATE_KEY = "alerts";

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

export interface OpsNotifierShape {
  readonly notify: (payload: OpsAlertPayload) => Effect.Effect<boolean>;
}

export class OpsNotifier extends Context.Service<OpsNotifier, OpsNotifierShape>()("OpsNotifier") {}

const WEBHOOK_REQUEST_TIMEOUT = Duration.seconds(5);

const webhookHttpClient = egressHttpClientLayer();

const webhookRequestFailedWith = (kind: string) =>
  Effect.logWarning("ops alert webhook request failed; retrying on the next evaluation", kind).pipe(
    Effect.as(false),
  );

const webhookRequestFailed = (error: Error) =>
  webhookRequestFailedWith(error.cause instanceof Error ? error.cause.name : "unknown");

export function makeWebhookNotifier(
  webhookUrl: Redacted.Redacted<string> | undefined,
): OpsNotifierShape {
  return {
    notify: (payload) => {
      if (webhookUrl === undefined) {
        return Effect.forEach(
          payload.events,
          (event) =>
            Effect.logWarning(
              `ops signal ${event.state}: ${event.signal} (value ${event.value}, threshold ${event.threshold})`,
            ),
          { discard: true },
        ).pipe(Effect.as(true));
      }
      return Effect.gen(function* () {
        const client = yield* HttpClient.HttpClient;
        const request = yield* HttpClientRequest.post(Redacted.value(webhookUrl)).pipe(
          HttpClientRequest.setHeaders({ "user-agent": "maruhi" }),
          HttpClientRequest.bodyJson(payload),
        );
        const response = yield* client.execute(request);
        if (response.status < 200 || response.status >= 300) {
          yield* Effect.logWarning(
            "ops alert webhook responded with a non-2xx status; retrying on the next evaluation",
          );
          return false;
        }
        return true;
      }).pipe(
        Effect.timeout(WEBHOOK_REQUEST_TIMEOUT),
        Effect.catchTags({
          HttpClientError: webhookRequestFailed,
          HttpBodyError: webhookRequestFailed,
          TimeoutError: () => webhookRequestFailedWith("TimeoutError"),
        }),
        Effect.provide(webhookHttpClient),
      );
    },
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

export const evaluateOpsSignals = Effect.fn("ops-alerts.evaluateOpsSignals")(function* (
  nowMs: number,
): Effect.fn.Return<readonly OpsSignal[], never, OpsRepo> {
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
  const loginSuppressed = yield* ops.auditEventCountSince("auth.login_failed_suppressed", lastHour);
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

const AlertStateSchema = Schema.Struct({
  active: Schema.Boolean,
  since: Schema.Number,
  lastNotifiedAt: Schema.Number,
});

const AlertStatesSchema = Schema.fromJsonString(Schema.Record(Schema.String, AlertStateSchema));

function parseStates(raw: string | null): Effect.Effect<AlertStates> {
  if (raw === null) {
    return Effect.succeed({});
  }
  return Schema.decodeUnknownEffect(AlertStatesSchema)(raw).pipe(
    Effect.catchTag("SchemaError", () =>
      Effect.logWarning("ops alert state row is not valid JSON; starting from an empty state").pipe(
        Effect.as<AlertStates>({}),
      ),
    ),
  );
}

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

export const runOpsAlerts = Effect.fn("ops-alerts.runOpsAlerts")(function* (
  nowMs: number,
): Effect.fn.Return<readonly OpsAlertEvent[], never, OpsRepo | OpsNotifier> {
  const ops = yield* OpsRepo;
  const notifier = yield* OpsNotifier;
  const signals = yield* evaluateOpsSignals(nowMs);
  const states = yield* parseStates(yield* ops.getState(ALERT_STATE_KEY));
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
