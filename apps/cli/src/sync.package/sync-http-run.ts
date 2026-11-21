import { Effect } from "effect";
import { HttpClient, HttpClientRequest } from "effect/http";

import { displayText } from "../display.ts";
import type { CliError } from "../errors.ts";
import { isRecord } from "../json-record.ts";
import type { SyncWrite } from "./sync-exec.ts";
import { readResponse } from "./sync-http-read.ts";
import { scrubbed, send } from "./sync-http-send.ts";
import {
  buildWriteRequest,
  type DerivedOptions,
  type HttpBatch,
  type HttpDeleteSpec,
  type HttpListSpec,
  type HttpRemoveSpec,
  type HttpRequestResult,
  type HttpTargetInput,
  type HttpWriteStrategy,
  NO_SUBJECT,
  parseJson,
  type PathSubject,
  recordsOf,
  renderPath,
  renderQuery,
} from "./sync-http.ts";

type Listing =
  | { readonly items: readonly Record<string, unknown>[]; readonly complete: boolean }
  | { readonly failure: readonly string[] };

const fetchListing = Effect.fn("sync-http-run.fetchListing")(function* (
  input: HttpTargetInput,
  spec: HttpListSpec,
): Effect.fn.Return<Listing, CliError, HttpClient.HttpClient> {
  const request = HttpClientRequest.get(
    `https://${input.preset.host}${renderPath(spec.path, input.options, NO_SUBJECT)}`,
    { urlParams: renderQuery(spec.query, input.options) },
  );
  const outcome = yield* send(input, request);
  const body = parseJson(outcome.text);
  const listed: unknown =
    spec.itemsField === null ? body : isRecord(body) ? body[spec.itemsField] : undefined;
  if (outcome.status < 200 || outcome.status >= 300 || !Array.isArray(listed)) {
    return {
      failure: scrubbed(
        [`HTTP ${outcome.status} while listing variables at the target`],
        [],
        input.token,
      ),
    };
  }
  return { items: listed.filter(isRecord), complete: isListingComplete(spec, body) };
});

function isListingComplete(spec: HttpListSpec, body: unknown): boolean {
  if (spec.nextPage === undefined || !isRecord(body)) {
    return true;
  }
  const [pageField, nextField] = spec.nextPage;
  const pagination = body[pageField];
  const next = isRecord(pagination) ? pagination[nextField] : undefined;
  return next === undefined || next === null || next === false;
}

function listedByKey(
  items: readonly Record<string, unknown>[],
  keyField: string,
): Map<string, Record<string, unknown>> {
  const byKey = new Map<string, Record<string, unknown>>();
  for (const item of items) {
    const key = item[keyField];
    if (typeof key === "string") {
      byKey.set(key, item);
    }
  }
  return byKey;
}

function guardUpdate(
  write: Extract<HttpWriteStrategy, { kind: "create-or-update" }>,
  name: string,
  item: Record<string, unknown>,
  options: DerivedOptions,
): string | null {
  for (const guard of write.updateGuards ?? []) {
    if (options[guard.option] === true && item[guard.field] !== true) {
      return `${displayText(name)} already exists at the target with ${guard.field} off, and the config asks for it on. ${guard.hint}`;
    }
  }
  return null;
}

function matchesTarget(
  element: Record<string, unknown>,
  match: Extract<HttpDeleteSpec, { kind: "lookup" }>["match"],
  options: DerivedOptions,
): boolean {
  const target = options[match.targetOption];
  const branch = options[match.branchOption];
  const targets = element[match.targetField];
  const elementBranch = element[match.branchField];
  const targetMatches = Array.isArray(targets) ? targets.includes(target) : targets === target;
  const branchMatches =
    typeof branch === "string"
      ? elementBranch === branch
      : elementBranch === undefined || elementBranch === null;
  return targetMatches && branchMatches;
}

function lookupIds(
  items: readonly Record<string, unknown>[],
  spec: Extract<HttpDeleteSpec, { kind: "lookup" }>,
  name: string,
  options: DerivedOptions,
): { readonly ids: readonly string[]; readonly whole: boolean } {
  const ids: string[] = [];
  let matchedItems = 0;
  let wholeItems = 0;
  for (const item of items.filter((entry) => entry[spec.list.keyField] === name)) {
    const { valuesField } = spec.match;
    const elements = valuesField === undefined ? [item] : recordsOf(item[valuesField]);
    const hits = elements.filter((element) => matchesTarget(element, spec.match, options));
    if (hits.length === 0) {
      continue;
    }
    matchedItems += 1;
    if (valuesField !== undefined && hits.length === elements.length) {
      wholeItems += 1;
    }
    for (const hit of hits) {
      const id = hit[spec.match.idField];
      if (typeof id === "string") {
        ids.push(id);
      }
    }
  }
  return { ids, whole: matchedItems > 0 && wholeItems === matchedItems };
}

function singleBatch(write: SyncWrite): HttpBatch {
  return { kind: "write", names: [write.name], writes: [write], deletes: [] };
}

const createOrUpdate = Effect.fn("sync-http-run.createOrUpdate")(function* (
  input: HttpTargetInput,
  write: Extract<HttpWriteStrategy, { kind: "create-or-update" }>,
  batch: HttpBatch,
): Effect.fn.Return<HttpRequestResult, CliError, HttpClient.HttpClient> {
  const listing = yield* fetchListing(input, write.list);
  if ("failure" in listing) {
    return {
      delivered: [],
      failure: {
        names: batch.names,
        what: `${input.preset.label} did not list the existing variables`,
        lines: listing.failure,
      },
    };
  }
  if (!listing.complete) {
    return {
      delivered: [],
      failure: {
        names: batch.names,
        what: "maruhi did not send the request",
        lines: [
          `${input.preset.label} returned a paginated list of variables, so maruhi could not tell which of them already exist at the target. Nothing was written; apply again later`,
        ],
      },
    };
  }
  return yield* writeOneByOne(input, write, batch, listedByKey(listing.items, write.list.keyField));
});

const writeOneByOne = Effect.fn("sync-http-run.writeOneByOne")(function* (
  input: HttpTargetInput,
  write: Extract<HttpWriteStrategy, { kind: "create-or-update" }>,
  batch: HttpBatch,
  existing: ReadonlyMap<string, Record<string, unknown>>,
): Effect.fn.Return<HttpRequestResult, CliError, HttpClient.HttpClient> {
  const delivered: string[] = [];
  for (const item of batch.writes) {
    const one = singleBatch(item);
    const listed = existing.get(item.name);
    const result = yield* (
      listed === undefined
        ? createOrRecover(input, write, one)
        : updateOne(input, write, one, listed)
    ).pipe(
      Effect.catch((error: CliError) =>
        Effect.succeed({
          delivered: [],
          failure: {
            names: one.names,
            what: `the request to ${input.preset.label} failed`,
            lines: [error.message],
          },
        }),
      ),
    );
    if (result.failure !== null) {
      return { delivered, failure: result.failure };
    }
    delivered.push(item.name);
  }
  return { delivered, failure: null };
});

function updateOne(
  input: HttpTargetInput,
  write: Extract<HttpWriteStrategy, { kind: "create-or-update" }>,
  one: HttpBatch,
  listed: Record<string, unknown>,
): Effect.Effect<HttpRequestResult, CliError, HttpClient.HttpClient> {
  const refused = guardUpdate(write, one.names[0] ?? "", listed, input.options);
  if (refused !== null) {
    return Effect.succeed({
      delivered: [],
      failure: { names: one.names, what: "maruhi did not send the request", lines: [refused] },
    });
  }
  return Effect.map(send(input, buildWriteRequest(input, write.update, one)), (outcome) =>
    readResponse(input.preset.response, outcome, one, input),
  );
}

const createOrRecover = Effect.fn("sync-http-run.createOrRecover")(function* (
  input: HttpTargetInput,
  write: Extract<HttpWriteStrategy, { kind: "create-or-update" }>,
  one: HttpBatch,
): Effect.fn.Return<HttpRequestResult, CliError, HttpClient.HttpClient> {
  const outcome = yield* send(input, buildWriteRequest(input, write.create, one));
  const created = readResponse(input.preset.response, outcome, one, input);
  if (created.failure === null) {
    return created;
  }
  const listing = yield* fetchListing(input, write.list).pipe(
    Effect.catch((error: CliError) => Effect.succeed({ failure: [error.message] })),
  );
  if ("failure" in listing) {
    return withRecheckFailure(created, listing.failure);
  }
  if (!listing.complete) {
    return created;
  }
  const listed = listedByKey(listing.items, write.list.keyField).get(one.names[0] ?? "");
  return listed === undefined ? created : yield* updateOne(input, write, one, listed);
});

function withRecheckFailure(
  created: HttpRequestResult,
  lines: readonly string[],
): HttpRequestResult {
  return created.failure === null
    ? created
    : {
        delivered: created.delivered,
        failure: {
          names: created.failure.names,
          what: created.failure.what,
          lines: [
            ...created.failure.lines,
            `Could not re-check the target after the failed create: ${lines.join(" ")}`,
          ],
        },
      };
}

export const runBatch: (
  input: HttpTargetInput,
  batch: HttpBatch,
) => Effect.Effect<HttpRequestResult, never, HttpClient.HttpClient> = Effect.fn(
  "sync-http-run.runBatch",
)(
  function* (input, batch) {
    if (batch.kind === "write") {
      const { write } = input.preset;
      if (write.kind === "create-or-update") {
        return yield* createOrUpdate(input, write, batch);
      }
      const outcome = yield* send(input, buildWriteRequest(input, write.request, batch));
      return readResponse(input.preset.response, outcome, batch, input);
    }
    const spec = input.preset.delete;
    if (spec.kind !== "lookup") {
      throw new Error("a delete batch was built for a preset whose deletes ride along");
    }
    return yield* lookupAndRemove(input, spec, batch);
  },
  (effect, input, batch) =>
    effect.pipe(
      Effect.catch((error: CliError) =>
        Effect.succeed({
          delivered: [],
          failure: {
            names: batch.names,
            what: `the request to ${input.preset.label} failed`,
            lines: [error.message],
          },
        }),
      ),
    ),
);

const lookupAndRemove = Effect.fn("sync-http-run.lookupAndRemove")(function* (
  input: HttpTargetInput,
  spec: Extract<HttpDeleteSpec, { kind: "lookup" }>,
  batch: HttpBatch,
): Effect.fn.Return<HttpRequestResult, CliError, HttpClient.HttpClient> {
  const name = batch.names[0] ?? "";
  const listing = yield* fetchListing(input, spec.list);
  if ("failure" in listing) {
    return {
      delivered: [],
      failure: {
        names: batch.names,
        what: `${input.preset.label} did not list the existing variables`,
        lines: listing.failure,
      },
    };
  }
  const looked = lookupIds(listing.items, spec, name, input.options);
  if (looked.ids.length === 0 && !listing.complete) {
    return {
      delivered: [],
      failure: {
        names: batch.names,
        what: "maruhi did not send the request",
        lines: [
          `${input.preset.label} returned a paginated list of variables, so maruhi could not confirm that ${displayText(name)} is gone from the target. It stays in the receipt; remove it at the target yourself, or apply again`,
        ],
      },
    };
  }
  if (looked.whole && spec.removeItem !== undefined) {
    return yield* removeOne(input, spec.removeItem, batch, { id: null, name });
  }
  return yield* removeByIds(input, spec, batch, name, looked.ids);
});

const removeByIds = Effect.fn("sync-http-run.removeByIds")(function* (
  input: HttpTargetInput,
  spec: Extract<HttpDeleteSpec, { kind: "lookup" }>,
  batch: HttpBatch,
  name: string,
  ids: readonly string[],
): Effect.fn.Return<HttpRequestResult, CliError, HttpClient.HttpClient> {
  for (const id of ids) {
    const result = yield* removeOne(input, spec.remove, batch, { id, name });
    if (result.failure !== null) {
      return result;
    }
  }
  return { delivered: batch.names, failure: null };
});

const removeOne = Effect.fn("sync-http-run.removeOne")(function* (
  input: HttpTargetInput,
  spec: HttpRemoveSpec,
  batch: HttpBatch,
  subject: PathSubject,
): Effect.fn.Return<HttpRequestResult, CliError, HttpClient.HttpClient> {
  const request = HttpClientRequest.make(spec.method)(
    `https://${input.preset.host}${renderPath(spec.path, input.options, subject)}`,
    { urlParams: renderQuery(spec.query, input.options) },
  );
  const outcome = yield* send(input, request);
  return outcome.status === 404
    ? { delivered: batch.names, failure: null }
    : readResponse(input.preset.response, outcome, batch, input);
});
