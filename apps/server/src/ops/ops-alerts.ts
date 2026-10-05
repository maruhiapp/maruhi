// Tripwire evaluation and notification — docs/notes/hosted-ops.md
// §2-B / §3.
//
// Called from the hourly cron (index.ts). Inputs stay inside D1 (ops
// counters, evacuation records, and windowed aggregation over the
// existing audit rows). Outputs are only "static signal name +
// aggregate + threshold + state" — they contain no identifiers
// (project IDs, user IDs, etc.).
//
// The destination is the Workers Secret `OPS_ALERT_WEBHOOK_URL`
// (unset = do not send — disabled by default; carried as Redacted
// through worker-env.ts). Notifications fire on state transitions
// (inactive → active / active → inactive); while a signal stays
// active it re-notifies every OPS_ALERT_RENOTIFY_MS. A send failure
// is not swallowed: a static 1-line log is left and the state is not
// updated (the next evaluation re-sends). Even without a webhook
// configured, an active signal leaves a static 1-line entry in
// Workers Logs (the self-hosted hook).

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

/** Signal names (fixed vocabulary — hosted-ops §3). */
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

/** The payload sent to the webhook (no identifiers). */
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

/** The notification sink (tests plug in a capturing implementation). true = sent / nowhere to send. */
export interface OpsNotifierShape {
  readonly notify: (payload: OpsAlertPayload) => Effect.Effect<boolean>;
}

export class OpsNotifier extends Context.Service<OpsNotifier, OpsNotifierShape>()("OpsNotifier") {}

/**
 * Timeout of one webhook POST — the same bound as github.ts's
 * REQUEST_TIMEOUT and jwks.ts's FETCH_TIMEOUT_MS: the scheduled run
 * must not hang on a peer that accepts the connection and never
 * answers.
 */
const WEBHOOK_REQUEST_TIMEOUT = Duration.seconds(5);

/** The outbound client: no header of its own (packages/core/src/egress.ts). */
const webhookHttpClient = egressHttpClientLayer();

const webhookRequestFailedWith = (kind: string) =>
  Effect.logWarning("ops alert webhook request failed; retrying on the next evaluation", kind).pipe(
    Effect.as(false),
  );

/**
 * A webhook send failure folds into the static line + `false` (kind
 * name only — never the URL or the body). HttpClientError carries the
 * underlying failure (the fetch rejection, the URL-parse TypeError)
 * in `.cause` — its name is the same transport kind the raw-fetch
 * implementation logged.
 */
const webhookRequestFailed = (error: Error) =>
  webhookRequestFailedWith(error.cause instanceof Error ? error.cause.name : "unknown");

/** The production implementation: POSTs JSON when a webhook URL is configured. */
export function makeWebhookNotifier(
  webhookUrl: Redacted.Redacted<string> | undefined,
): OpsNotifierShape {
  return {
    notify: (payload) => {
      if (webhookUrl === undefined) {
        return Effect.forEach(
          payload.events,
          (event) =>
            // Static signal name + aggregates only
            Effect.logWarning(
              `ops signal ${event.state}: ${event.signal} (value ${event.value}, threshold ${event.threshold})`,
            ),
          { discard: true },
        ).pipe(Effect.as(true));
      }
      return Effect.gen(function* () {
        const client = yield* HttpClient.HttpClient;
        // The URL's only unwrap: the request build (a Workers Secret).
        // It appears in no log line or error
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
          // The new timeout has no transport underneath — its own name
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

/** Signal evaluation (does not notify — pure aggregation). */
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

/** The stored state row's entry shape (decoded, not cast — a malformed value restarts from empty). */
const AlertStateSchema = Schema.Struct({
  active: Schema.Boolean,
  since: Schema.Number,
  lastNotifiedAt: Schema.Number,
});

/** The stored row: a JSON object of per-signal entries (unknown keys carry over to the next save). */
const AlertStatesSchema = Schema.fromJsonString(Schema.Record(Schema.String, AlertStateSchema));

function parseStates(raw: string | null): Effect.Effect<AlertStates> {
  if (raw === null) {
    return Effect.succeed({});
  }
  return Schema.decodeUnknownEffect(AlertStatesSchema)(raw).pipe(
    Effect.catchTag("SchemaError", () =>
      // A corrupted state row restarts from "all inactive" (operational
      // state only — not audit)
      Effect.logWarning("ops alert state row is not valid JSON; starting from an empty state").pipe(
        Effect.as<AlertStates>({}),
      ),
    ),
  );
}

/** Derivation of transitions (and re-notifications) — a pure function (pinned by tests). */
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
 * Evaluate → derive transitions → notify → save state. If
 * notification fails, the state is not saved (the next evaluation
 * re-derives the same transition and re-sends).
 */
export function runOpsAlerts(
  nowMs: number,
): Effect.Effect<readonly OpsAlertEvent[], never, OpsRepo | OpsNotifier> {
  return Effect.gen(function* () {
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
}
