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

const CLOUDFLARE_WORKER_NOT_FOUND = new Set([10007, 10090]);

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
    return { delivered: batch.names, failure: null };
  }
  const created = body["created"];
  const createdKeys = new Set(keysOf(Array.isArray(created) ? created : [created]));
  const failures = failed.map(vercelFailureOf);
  const failedNames = new Set(failures.flatMap((entry) => (entry.key === null ? [] : [entry.key])));
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

function vercelErrorLines(status: number, body: unknown): string[] {
  const error = isRecord(body) && isRecord(body["error"]) ? body["error"] : null;
  return error === null
    ? [`HTTP ${status}`]
    : [`HTTP ${status}`, `error ${String(error["code"] ?? "")}: ${String(error["message"] ?? "")}`];
}

function keysOf(entries: readonly unknown[]): readonly string[] {
  return entries.filter(isRecord).flatMap((entry) => {
    const key = entry["key"];
    return typeof key === "string" ? [key] : [];
  });
}

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

function netlifyErrorLines(status: number, body: unknown): string[] {
  return isRecord(body) && typeof body["message"] === "string"
    ? [`HTTP ${status}`, `error ${String(body["code"] ?? status)}: ${body["message"]}`]
    : [`HTTP ${status}`];
}

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
