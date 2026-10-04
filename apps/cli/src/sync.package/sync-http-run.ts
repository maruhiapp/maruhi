// The run procedures of `maruhi sync`'s http driver (sync-http.ts):
// runBatch — the entry point sync-plan.ts's runBatches folds per batch
// — and the pieces it is built from. A target's list is read once for
// name/ID matching only (values are never read); a create-or-update
// write then sends one variable at a time, stopping at the first
// failure (a create that hits an existing key re-reads the list and
// switches to an update); a lookup delete matches the target's
// environment in the list, then deletes per looked-up ID — or per item
// when the match was the item's last values.

import { Effect } from "effect";
import { HttpClient, HttpClientRequest } from "effect/http";

import { displayText } from "../display.ts";
import type { CliError } from "../errors.ts";
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
  isRecord,
  NO_SUBJECT,
  parseJson,
  type PathSubject,
  recordsOf,
  renderPath,
  renderQuery,
} from "./sync-http.ts";

/** Reading a list (the array of items and its completeness). On failure, already-redacted lines. */
type Listing =
  | { readonly items: readonly Record<string, unknown>[]; readonly complete: boolean }
  | { readonly failure: readonly string[] };

/**
 * Reads the list once (values are discarded unread — used only for
 * name/ID matching). Also returns whether there might be a next page (if
 * there is, "absent" is not evidence — fail-closed).
 */
function fetchListing(
  input: HttpTargetInput,
  spec: HttpListSpec,
): Effect.Effect<Listing, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
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
}

/** Whether there is no next page (Vercel's `pagination.next`. No declaration / null = the list is complete). */
function isListingComplete(spec: HttpListSpec, body: unknown): boolean {
  if (spec.nextPage === undefined || !isRecord(body)) {
    return true;
  }
  const [pageField, nextField] = spec.nextPage;
  const pagination = body[pageField];
  const next = isRecord(pagination) ? pagination[nextField] : undefined;
  return next === undefined || next === null || next === false;
}

/** The list items in name-addressable form (only those with a string `keyField`). */
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

/**
 * The guard of an attribute an update cannot change (`updateGuards`): the
 * message when broken (variable name and attribute name only — no value),
 * null when honored.
 */
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

/** The delete's matching: whether the element belongs to "this target's environment" (a same-named variable of a different environment is never deleted). */
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

/**
 * The delete's first step: look up the target-side IDs in the list.
 * `whole` = the matched elements were all of that name's item's elements
 * (the item may be deleted whole — only presets with a `removeItem` use
 * this).
 */
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

/** A batch of exactly one variable (each step of create-or-update goes through readResponse). */
function singleBatch(write: SyncWrite): HttpBatch {
  return { kind: "write", names: [write.name], writes: [write], deletes: [] };
}

/**
 * The create-or-update write: look the names up in the list, send a create
 * for each absent name and an update for each present one, one variable at
 * a time. Stop at the first failure and return the delivered names (if a
 * same-named variable gets created between the listing and the send, the
 * create surfaces as a target-side failure — the next apply becomes an
 * update).
 */
function createOrUpdate(
  input: HttpTargetInput,
  write: Extract<HttpWriteStrategy, { kind: "create-or-update" }>,
  batch: HttpBatch,
): Effect.Effect<HttpRequestResult, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const listing = yield* fetchListing(input, write.list);
    if ("failure" in listing) {
      // The listing did get a response back (lines state the HTTP status),
      // so don't say "not sent" — what failed is reported as the listing's
      // failure
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
      // Judging by a list that has a continuation would create a name that
      // already exists and fail (or create it twice under the target's
      // rules). Stop without sending anything
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
    return yield* writeOneByOne(
      input,
      write,
      batch,
      listedByKey(listing.items, write.list.keyField),
    );
  });
}

/** The sending part of create-or-update: one variable at a time, stopping at the first failure. */
function writeOneByOne(
  input: HttpTargetInput,
  write: Extract<HttpWriteStrategy, { kind: "create-or-update" }>,
  batch: HttpBatch,
  existing: ReadonlyMap<string, Record<string, unknown>>,
): Effect.Effect<HttpRequestResult, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const delivered: string[] = [];
    for (const item of batch.writes) {
      const one = singleBatch(item);
      const listed = existing.get(item.name);
      // Even if sending one variable fails with a typed error (attempts
      // exhausted, Retry-After exceeded), the names delivered earlier in
      // this batch are not lost: reported as that variable's failure, and
      // the delivered ones go to the receipt (in create-or-update the whole
      // write is one batch, so letting it fall erases the run's progress)
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
}

/** A name in the list: pass the guard (`updateGuards`), then send one update. */
function updateOne(
  input: HttpTargetInput,
  write: Extract<HttpWriteStrategy, { kind: "create-or-update" }>,
  one: HttpBatch,
  listed: Record<string, unknown>,
): Effect.Effect<HttpRequestResult, CliError, HttpClient.HttpClient> {
  const refused = guardUpdate(write, one.names[0] ?? "", listed, input.options);
  if (refused !== null) {
    // Stop without sending (no value lands. The delivered share goes to the receipt)
    return Effect.succeed({
      delivered: [],
      failure: { names: one.names, what: "maruhi did not send the request", lines: [refused] },
    });
  }
  return Effect.map(send(input, buildWriteRequest(input, write.update, one)), (outcome) =>
    readResponse(input.preset.response, outcome, one, input),
  );
}

/**
 * A name not in the list: send the create. create is not an upsert (it
 * refuses an existing key), so shapes like a delivered response lost and
 * resent (`send`'s retry) or a same-named variable created between the
 * listing and the send come back as a target-side failure. In that case,
 * **re-read the list** and switch to an update if the name is there
 * (regardless of the response's wording). If not, the create's failure
 * stands.
 */
function createOrRecover(
  input: HttpTargetInput,
  write: Extract<HttpWriteStrategy, { kind: "create-or-update" }>,
  one: HttpBatch,
): Effect.Effect<HttpRequestResult, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const outcome = yield* send(input, buildWriteRequest(input, write.create, one));
    const created = readResponse(input.preset.response, outcome, one, input);
    if (created.failure === null) {
      return created;
    }
    // Even if the re-read listing fails (transport layer, attempts
    // exhausted = a typed error), fall back to reporting the create's
    // failure: failing here would keep names already delivered in the same
    // batch off the receipt
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
}

/** Attaches the re-read listing's failure (already-redacted lines) to a create's failure. */
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

/**
 * Runs one batch against the vendor API: the write request(s), or the
 * lookup-then-delete pair for presets whose delete does not ride along.
 *
 * Even when the batch's send fails with a typed error (attempts exhausted,
 * Retry-After exceeded), return it as that batch's failure: the caller
 * (sync-plan.ts's runBatches) is mid-way folding the names earlier batches
 * delivered, and failing here would erase that progress (a delete batch's
 * listing and DELETEs, an upsert's second-and-later batches). Uniform
 * across every http preset and batch kind (exec's runInvocations has the
 * same shape — a launch failure is folded into that invocation's
 * failure). A create-or-update write receives one variable at a time
 * inside and keeps the delivered share.
 */
export function runBatch(
  input: HttpTargetInput,
  batch: HttpBatch,
): Effect.Effect<HttpRequestResult, never, HttpClient.HttpClient> {
  return Effect.gen(function* () {
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
  }).pipe(
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
  );
}

/** A delete batch (one name): look the ID up in the list, then delete per value (or per item). */
function lookupAndRemove(
  input: HttpTargetInput,
  spec: Extract<HttpDeleteSpec, { kind: "lookup" }>,
  batch: HttpBatch,
): Effect.Effect<HttpRequestResult, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const name = batch.names[0] ?? "";
    const listing = yield* fetchListing(input, spec.list);
    if ("failure" in listing) {
      // The listing did get a response back (lines state the HTTP status),
      // so don't say "not sent"
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
      // A name missing from a list that has a continuation: cannot say
      // it's "gone". Don't record it as delivered and leave it on the
      // receipt (the next apply tries again — fail-closed)
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
    // Absent from a complete list = already deleted at the target (the re-read only matches IDs; values are never read)
    if (looked.whole && spec.removeItem !== undefined) {
      return yield* removeOne(input, spec.removeItem, batch, { id: null, name });
    }
    return yield* removeByIds(input, spec, batch, name, looked.ids);
  });
}

/** The delete's second step: DELETE each looked-up ID (404 = deleted concurrently right after the listing). */
function removeByIds(
  input: HttpTargetInput,
  spec: Extract<HttpDeleteSpec, { kind: "lookup" }>,
  batch: HttpBatch,
  name: string,
  ids: readonly string[],
): Effect.Effect<HttpRequestResult, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    for (const id of ids) {
      const result = yield* removeOne(input, spec.remove, batch, { id, name });
      if (result.failure !== null) {
        return result;
      }
    }
    return { delivered: batch.names, failure: null };
  });
}

/** One DELETE (by ID or name). 404 is "already gone" = success. */
function removeOne(
  input: HttpTargetInput,
  spec: HttpRemoveSpec,
  batch: HttpBatch,
  subject: PathSubject,
): Effect.Effect<HttpRequestResult, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const request = HttpClientRequest.make(spec.method)(
      `https://${input.preset.host}${renderPath(spec.path, input.options, subject)}`,
      { urlParams: renderQuery(spec.query, input.options) },
    );
    const outcome = yield* send(input, request);
    return outcome.status === 404
      ? { delivered: batch.names, failure: null }
      : readResponse(input.preset.response, outcome, batch, input);
  });
}
