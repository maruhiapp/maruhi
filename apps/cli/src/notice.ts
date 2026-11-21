import { Context, Effect, Option } from "effect";

import { CliIo } from "./io.ts";

export class NoticeLedger extends Context.Service<NoticeLedger, Set<string>>()(
  "cli/NoticeLedger",
) {}

export class NoticeObserver extends Context.Service<
  NoticeObserver,
  (kind: NoticeKind, text: string) => void
>()("cli/NoticeObserver") {}

export type NoticeKind = "note" | "warning" | "error";

const RESET = "\u001B[0m";
const PREFIXES: Readonly<Record<NoticeKind, { readonly label: string; readonly color: string }>> = {
  note: { label: "Note:", color: "\u001B[36m" },
  warning: { label: "Warning:", color: "\u001B[33m" },
  error: { label: "maruhi:", color: "\u001B[31m" },
};

export function shouldUseColor(input: {
  readonly stderrIsTerminal: boolean;
  readonly envVar: (name: string) => string | undefined;
}): boolean {
  const force = input.envVar("FORCE_COLOR");
  if (force !== undefined && force !== "") {
    return force !== "0";
  }
  const noColor = input.envVar("NO_COLOR");
  if (noColor !== undefined && noColor !== "") {
    return false;
  }
  if (input.envVar("TERM") === "dumb") {
    return false;
  }
  return input.stderrIsTerminal;
}

export function formatNotice(kind: NoticeKind, text: string, color: boolean): string {
  const prefix = PREFIXES[kind];
  const label = color ? `${prefix.color}${prefix.label}${RESET}` : prefix.label;
  return `${label} ${text}`;
}

export interface NoticeOptions {
  readonly scope?: "run" | "prompt";
}

const logNotice = Effect.fn("notice.logNotice")(function* (
  kind: NoticeKind,
  text: string,
  options: NoticeOptions,
): Effect.fn.Return<void, never, CliIo> {
  const io = yield* CliIo;
  const scope = options.scope ?? "run";
  const ledger = yield* Effect.serviceOption(NoticeLedger);
  if (kind !== "error" && scope === "run" && Option.isSome(ledger)) {
    const key = `${kind}\u0000${text}`;
    if (ledger.value.has(key)) {
      return;
    }
    ledger.value.add(key);
  }
  const observer = yield* Effect.serviceOption(NoticeObserver);
  if (Option.isSome(observer)) {
    observer.value(kind, text);
  }
  const line = formatNotice(kind, text, io.colorEnabled());
  yield* io.logError(scope === "prompt" ? `  ${line}` : line);
});

export function logNote(text: string, options: NoticeOptions = {}) {
  return logNotice("note", text, options);
}

export function logWarning(text: string, options: NoticeOptions = {}) {
  return logNotice("warning", text, options);
}

export function logFailure(message: string) {
  return logNotice("error", message, {});
}
