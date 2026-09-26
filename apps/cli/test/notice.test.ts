// Vocabulary and color discipline for stderr notices (notice.ts) — DP5
// rulings A / B.
//
// - Only three prefixes: `Note:` / `Warning:` / `maruhi:`, and the
//   destination is always stderr
// - Color goes on the prefix alone (no ANSI inside the body — it can
//   contain values, identifiers, URLs)
// - Color enablement: FORCE_COLOR > NO_COLOR (non-empty disables) >
//   TERM=dumb > whether stderr is a terminal

import { Effect } from "effect";
import { describe, expect, it } from "vitest";

import { formatNotice, logNote, logWarning, NoticeLedger, shouldUseColor } from "../src/notice.ts";
import { makeTestEnv } from "./support/env.ts";

const ESC = "\u001B";

/** Fakes the environment-variable lookup (table → envVar). */
const envOf = (vars: Readonly<Record<string, string>>) => (name: string) => vars[name];

describe("shouldUseColor (color enablement)", () => {
  it("defaults to whether stderr is a terminal", () => {
    expect(shouldUseColor({ stderrIsTerminal: true, envVar: envOf({}) })).toBe(true);
    expect(shouldUseColor({ stderrIsTerminal: false, envVar: envOf({}) })).toBe(false);
  });

  it("NO_COLOR disables when non-empty regardless of value (no-color.org)", () => {
    expect(shouldUseColor({ stderrIsTerminal: true, envVar: envOf({ NO_COLOR: "1" }) })).toBe(
      false,
    );
    expect(shouldUseColor({ stderrIsTerminal: true, envVar: envOf({ NO_COLOR: "yes" }) })).toBe(
      false,
    );
    expect(shouldUseColor({ stderrIsTerminal: true, envVar: envOf({ NO_COLOR: "" }) })).toBe(true);
  });

  it("FORCE_COLOR beats the terminal check and NO_COLOR; only `0` means disable", () => {
    expect(shouldUseColor({ stderrIsTerminal: false, envVar: envOf({ FORCE_COLOR: "1" }) })).toBe(
      true,
    );
    expect(
      shouldUseColor({
        stderrIsTerminal: false,
        envVar: envOf({ FORCE_COLOR: "1", NO_COLOR: "1" }),
      }),
    ).toBe(true);
    expect(shouldUseColor({ stderrIsTerminal: true, envVar: envOf({ FORCE_COLOR: "0" }) })).toBe(
      false,
    );
  });

  it("TERM=dumb is colorless even on a terminal", () => {
    expect(shouldUseColor({ stderrIsTerminal: true, envVar: envOf({ TERM: "dumb" }) })).toBe(false);
  });
});

describe("formatNotice (rendering the prefix)", () => {
  it("without color it's a bare prefix + the body", () => {
    expect(formatNotice("note", "hello", false)).toBe("Note: hello");
    expect(formatNotice("warning", "hello", false)).toBe("Warning: hello");
    expect(formatNotice("error", "hello", false)).toBe("maruhi: hello");
  });

  it("color goes on the prefix alone; the body carries no ANSI", () => {
    const line = formatNotice("warning", "value=abc", true);
    expect(line).toBe(`${ESC}[33mWarning:${ESC}[0m value=abc`);
    expect(line.slice(line.indexOf(" ") + 1)).toBe("value=abc");
    expect(formatNotice("note", "x", true).startsWith(`${ESC}[36mNote:${ESC}[0m `)).toBe(true);
    expect(formatNotice("error", "x", true).startsWith(`${ESC}[31mmaruhi:${ESC}[0m `)).toBe(true);
  });
});

describe("logNote / logWarning (destination and continuation lines)", () => {
  it("writes to stderr and nothing to stdout (color on the prefix only)", async () => {
    const env = await makeTestEnv();
    env.setColor(true);
    await Effect.runPromise(
      Effect.gen(function* () {
        yield* logNote("first");
        yield* logWarning("second");
      }).pipe(Effect.provide(env.layer)),
    );
    expect(env.logs).toEqual([]);
    expect(env.errors).toEqual([
      `${ESC}[36mNote:${ESC}[0m first`,
      `${ESC}[33mWarning:${ESC}[0m second`,
    ]);
  });

  it("prompt-scope notices are indented and re-emitted on every retry even with a ledger", async () => {
    const env = await makeTestEnv();
    await Effect.runPromise(
      Effect.gen(function* () {
        yield* logWarning("per-candidate", { scope: "prompt" });
        yield* logWarning("per-candidate", { scope: "prompt" });
        yield* logNote("run-level");
        yield* logNote("run-level");
      }).pipe(Effect.provideService(NoticeLedger, new Set<string>()), Effect.provide(env.layer)),
    );
    expect(env.errors).toEqual([
      "  Warning: per-candidate",
      "  Warning: per-candidate",
      "Note: run-level",
    ]);
  });

  it("the same-worded Note / Warning appears once per ledger (one command run)", async () => {
    const env = await makeTestEnv();
    await Effect.runPromise(
      Effect.gen(function* () {
        yield* logNote("same");
        yield* logNote("same");
        yield* logWarning("same");
        yield* logWarning("same");
        yield* logNote("other");
      }).pipe(Effect.provideService(NoticeLedger, new Set<string>()), Effect.provide(env.layer)),
    );
    expect(env.errors).toEqual(["Note: same", "Warning: same", "Note: other"]);
  });

  it("the test environment defaults to colorless (so assertions can be plain strings)", async () => {
    const env = await makeTestEnv();
    await Effect.runPromise(logNote("plain").pipe(Effect.provide(env.layer)));
    expect(env.errors).toEqual(["Note: plain"]);
  });
});
