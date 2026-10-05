// The server's Effect logger: `Effect.logWarning` / `Effect.logError` reach
// Workers Logs exactly as the plain `console.warn` / `console.error` lines
// they replace (hosted-ops.md §1 Workers Logs row, DC-2).
//
// Effect's default logger writes every level through `console.log` with a
// `[date] LEVEL (#fiber) spans:` prefix and appends the fiber's log
// annotations and the failure Cause. On the server that would move warnings
// off the warn / error streams the operator reads, and annotations or a Cause
// can carry request-derived identifiers (a project id is a capability —
// AUTH_SPEC §11-2) or DO error text. This logger prints the message parts
// only:
//
// - Level routing: WARN → `console.warn`; ERROR and FATAL → `console.error`.
//   INFO, DEBUG and TRACE are dropped. The server has no info-level line of
//   its own, and the one library source of INFO lines on this runtime is
//   HttpMiddleware.logger's "Sent HTTP response" (annotated with `http.url`),
//   which index.ts already disables — dropping the level keeps that hole
//   closed in depth. A future operator-facing line is a WARN (something to
//   act on) or not logged at all.
// - Rendering: the message parts are passed to the console method as its
//   arguments, in order — `Effect.logWarning("text", detail)` prints exactly
//   what `console.warn("text", detail)` printed. Nothing is prepended or
//   appended: no date, level, fiber id, log spans, or annotations.
// - A `Cause` passed as a message part is lifted out of the message by
//   Effect (it becomes the log event's cause) and is never printed: its
//   rendering would include error messages that can carry data.
//
// `ServerLoggerLive` replaces the default logger set (Logger.layer without
// mergeWithExisting), so neither the default logger nor the tracer logger
// stays installed. It is provided at every Effect root of the worker and the
// chain DO: the HTTP handler and the `scheduled()` runs (index.ts), the chain
// DO's ManagedRuntime (do/chain-do.ts), and deriveAuditHeads's per-chunk run
// (audit-store.ts). The restore worker and its helpers (restore-worker.ts,
// import-check.ts, db.package/import.ts) run no Effect runtime and log with
// console directly.

import { Layer, Logger } from "effect";

const serverLogger = Logger.make<unknown, void>(({ logLevel, message }) => {
  const parts: readonly unknown[] = Array.isArray(message) ? message : [message];
  switch (logLevel) {
    case "Warn":
      console.warn(...parts);
      return;
    case "Error":
    case "Fatal":
      console.error(...parts);
      return;
    default:
      // INFO / DEBUG / TRACE: dropped (see the header)
      return;
  }
});

/** Replaces Effect's default loggers with the console.warn / console.error router above. */
export const ServerLoggerLive: Layer.Layer<never> = Logger.layer([serverLogger]);
