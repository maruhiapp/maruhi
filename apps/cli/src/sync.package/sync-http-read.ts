// The vendor-response readers of `maruhi sync`'s http driver
// (sync-http.ts): one per preset's `response` kind — Cloudflare's v4
// envelope (`success` plus error codes), Vercel's `{created, failed[]}`
// (a partial success is split by name), Netlify's 2xx (the response's
// `key` must carry the name) — and the failure's display lines. The
// extracted fragments go through sync-http-send.ts's `scrubbed` before
// they are shown; readResponse dispatches on ResponseKind for the run
// procedures (sync-http-run.ts).

import { displayText } from "../display.ts";
import { isRecord } from "../json-record.ts";
import { scrubbed } from "./sync-http-send.ts";
import {
  arrayOf,
  type HttpBatch,
  type HttpOutcome,
  type HttpRequestResult,
  type HttpTargetInput,
  parseJson,
  recordsOf,
  type ResponseKind,
} from "./sync-http.ts";

/** Turns a Cloudflare envelope's errors / messages into lines. */
function cloudflareLines(body: unknown, status: number): string[] {
  if (!isRecord(body)) {
    return [`HTTP ${status}`];
  }
  return [
    `HTTP ${status}`,
    ...recordsOf(body["errors"]).map(
      (entry) => `error ${String(entry["code"] ?? "")}: ${String(entry["message"] ?? "")}`,
    ),
    ...arrayOf(body["messages"]).map((message) =>
      typeof message === "string" ? message : String(isRecord(message) ? message["message"] : ""),
    ),
  ];
}

/** The set of Cloudflare errors[].code values. */
function cloudflareCodes(body: unknown): Set<number> {
  const codes = new Set<number>();
  if (isRecord(body) && Array.isArray(body["errors"])) {
    for (const entry of body["errors"]) {
      if (isRecord(entry) && typeof entry["code"] === "number") {
        codes.add(entry["code"]);
      }
    }
  }
  return codes;
}

// wrangler's isWorkerNotFoundError (worker-not-found-error.ts)
const CLOUDFLARE_WORKER_NOT_FOUND = new Set([10007, 10090]);

/** The Cloudflare v4 envelope check: 2xx and `success: true`. */
function readCloudflare(
  outcome: HttpOutcome,
  batch: HttpBatch,
  input: HttpTargetInput,
): HttpRequestResult {
  const body = parseJson(outcome.text);
  if (outcome.status >= 200 && outcome.status < 300 && isRecord(body) && body["success"] === true) {
    return { delivered: batch.names, failure: null };
  }
  const codes = cloudflareCodes(body);
  const lines = cloudflareLines(body, outcome.status);
  if ([...codes].some((code) => CLOUDFLARE_WORKER_NOT_FOUND.has(code))) {
    lines.push(
      `No Worker named ${displayText(String(input.options["scriptName"]))} exists in this account. maruhi does not create one: deploy the Worker first (\`wrangler deploy\`), then apply again`,
    );
  }
  return {
    delivered: [],
    failure: {
      names: batch.names,
      what: `${input.preset.label} refused the request`,
      lines: scrubbed(lines, batch.writes, input.token),
    },
  };
}

/** Reading Vercel's `{created, failed[]}` (partial success is split by name). */
function readVercel(
  outcome: HttpOutcome,
  batch: HttpBatch,
  input: HttpTargetInput,
): HttpRequestResult {
  const body = parseJson(outcome.text);
  if (outcome.status < 200 || outcome.status >= 300 || !isRecord(body)) {
    return {
      delivered: [],
      failure: {
        names: batch.names,
        what: `${input.preset.label} refused the request`,
        lines: scrubbed(vercelErrorLines(outcome.status, body), batch.writes, input.token),
      },
    };
  }
  if (batch.kind === "delete") {
    return { delivered: batch.names, failure: null };
  }
  if (!("created" in body)) {
    // A write 2xx without `created` = not the expected response shape (a
    // schema change, an intermediary's response). Not read as delivered
    return {
      delivered: [],
      failure: {
        names: batch.names,
        what: `${input.preset.label} did not confirm the write`,
        lines: scrubbed(
          [`HTTP ${outcome.status} without a created field (unexpected response shape)`],
          batch.writes,
          input.token,
        ),
      },
    };
  }
  const failed = recordsOf(body["failed"]);
  if (failed.length === 0) {
    // An empty failed means everything was delivered (created's shape wobbles between one entry and an array)
    return { delivered: batch.names, failure: null };
  }
  const created = body["created"];
  const createdKeys = new Set(keysOf(Array.isArray(created) ? created : [created]));
  const failures = failed.map(vercelFailureOf);
  const failedNames = new Set(failures.flatMap((entry) => (entry.key === null ? [] : [entry.key])));
  // If the failed names cannot be identified, the whole batch is undelivered (don't mis-record as delivered)
  const delivered =
    failedNames.size === 0
      ? []
      : batch.names.filter((name) => !failedNames.has(name) && createdKeys.has(name));
  const names = batch.names.filter((name) => !delivered.includes(name));
  const lines = [`HTTP ${outcome.status}`, ...failures.map((entry) => entry.line)];
  return {
    delivered,
    failure: {
      names,
      what: `${input.preset.label} refused the request`,
      lines: scrubbed(lines, batch.writes, input.token),
    },
  };
}

/** The display lines of Vercel's non-2xx response (`{error: {code, message}}`). */
function vercelErrorLines(status: number, body: unknown): string[] {
  const error = isRecord(body) && isRecord(body["error"]) ? body["error"] : null;
  return error === null
    ? [`HTTP ${status}`]
    : [`HTTP ${status}`, `error ${String(error["code"] ?? "")}: ${String(error["message"] ?? "")}`];
}

/** The `key` of a response entry (string ones only). */
function keysOf(entries: readonly unknown[]): readonly string[] {
  return entries.filter(isRecord).flatMap((entry) => {
    const key = entry["key"];
    return typeof key === "string" ? [key] : [];
  });
}

/** One Vercel `failed[]` entry → the failed name and a display line (redaction is the caller's). */
function vercelFailureOf(entry: Record<string, unknown>): {
  readonly key: string | null;
  readonly line: string;
} {
  const error = isRecord(entry["error"]) ? entry["error"] : {};
  const named = [error["key"], error["envVarKey"]].find((value) => typeof value === "string");
  const key = typeof named === "string" ? named : null;
  return {
    key,
    line: `error ${String(error["code"] ?? "")}${key === null ? "" : ` (${key})`}: ${String(error["message"] ?? "")}`,
  };
}

/** The display lines of Netlify's non-2xx response (`{code, message}`) (only the status when the body is not JSON). */
function netlifyErrorLines(status: number, body: unknown): string[] {
  return isRecord(body) && typeof body["message"] === "string"
    ? [`HTTP ${status}`, `error ${String(body["code"] ?? status)}: ${body["message"]}`]
    : [`HTTP ${status}`];
}

/**
 * Reading Netlify: 2xx. For a write (POST = array / PATCH = one variable)
 * the response's `key` must also carry the name (a differently-shaped 2xx
 * is not read as "delivered" — same posture as Vercel's `created`). A
 * delete is a 204 with no body. The response echoes the value (discarded).
 */
function readNetlify(
  outcome: HttpOutcome,
  batch: HttpBatch,
  input: HttpTargetInput,
): HttpRequestResult {
  const body = parseJson(outcome.text);
  const failure = (what: string, lines: readonly string[]): HttpRequestResult => ({
    delivered: [],
    failure: { names: batch.names, what, lines: scrubbed(lines, batch.writes, input.token) },
  });
  if (outcome.status < 200 || outcome.status >= 300) {
    return failure(
      `${input.preset.label} refused the request`,
      netlifyErrorLines(outcome.status, body),
    );
  }
  if (batch.kind === "delete") {
    return { delivered: batch.names, failure: null };
  }
  const keys = new Set(keysOf(Array.isArray(body) ? body : [body]));
  return batch.names.every((name) => keys.has(name))
    ? { delivered: batch.names, failure: null }
    : failure(`${input.preset.label} did not confirm the write`, [
        `HTTP ${outcome.status} without the variable in the response (unexpected response shape)`,
      ]);
}

export function readResponse(
  kind: ResponseKind,
  outcome: HttpOutcome,
  batch: HttpBatch,
  input: HttpTargetInput,
) {
  switch (kind) {
    case "cloudflare-v4":
      return readCloudflare(outcome, batch, input);
    case "vercel-env":
      return readVercel(outcome, batch, input);
    case "netlify-env":
      return readNetlify(outcome, batch, input);
  }
}
