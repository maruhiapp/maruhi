// stderr 通知(notice.ts)の語彙・色の規律(DP5 裁定 A / B)。
//
// - 接頭辞は `Note:` / `Warning:` / `maruhi:` の 3 語だけ、宛先は stderr
// - 色は接頭辞にだけ付く(本文に ANSI を混ぜない — 値・識別子・URL を含みうる)
// - 色の可否: FORCE_COLOR > NO_COLOR(非空で無効)> TERM=dumb > stderr が端末か

import { Effect } from "effect";
import { describe, expect, it } from "vitest";

import { formatNotice, logNote, logWarning, NoticeLedger, shouldUseColor } from "../src/notice.ts";
import { makeTestEnv } from "./support/env.ts";

const ESC = "\u001B";

/** 環境変数の読み取りの偽装(テーブル → envVar)。 */
const envOf = (vars: Readonly<Record<string, string>>) => (name: string) => vars[name];

describe("shouldUseColor(色の可否)", () => {
  it("既定は stderr が端末かどうかで決まる", () => {
    expect(shouldUseColor({ stderrIsTerminal: true, envVar: envOf({}) })).toBe(true);
    expect(shouldUseColor({ stderrIsTerminal: false, envVar: envOf({}) })).toBe(false);
  });

  it("NO_COLOR は値を問わず非空なら無効にする(no-color.org)", () => {
    expect(shouldUseColor({ stderrIsTerminal: true, envVar: envOf({ NO_COLOR: "1" }) })).toBe(
      false,
    );
    expect(shouldUseColor({ stderrIsTerminal: true, envVar: envOf({ NO_COLOR: "yes" }) })).toBe(
      false,
    );
    // 空文字列は未設定と同じ
    expect(shouldUseColor({ stderrIsTerminal: true, envVar: envOf({ NO_COLOR: "" }) })).toBe(true);
  });

  it("FORCE_COLOR は端末判定と NO_COLOR に勝ち、`0` だけは無効化を意味する", () => {
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

  it("TERM=dumb は端末でも無色", () => {
    expect(shouldUseColor({ stderrIsTerminal: true, envVar: envOf({ TERM: "dumb" }) })).toBe(false);
  });
});

describe("formatNotice(接頭辞の描画)", () => {
  it("無色では素の接頭辞 + 本文", () => {
    expect(formatNotice("note", "hello", false)).toBe("Note: hello");
    expect(formatNotice("warning", "hello", false)).toBe("Warning: hello");
    expect(formatNotice("error", "hello", false)).toBe("maruhi: hello");
  });

  it("色は接頭辞だけに付き、本文には ANSI を混ぜない", () => {
    const line = formatNotice("warning", "value=abc", true);
    expect(line).toBe(`${ESC}[33mWarning:${ESC}[0m value=abc`);
    // 本文側(接頭辞の後ろ)は無変換
    expect(line.slice(line.indexOf(" ") + 1)).toBe("value=abc");
    expect(formatNotice("note", "x", true).startsWith(`${ESC}[36mNote:${ESC}[0m `)).toBe(true);
    expect(formatNotice("error", "x", true).startsWith(`${ESC}[31mmaruhi:${ESC}[0m `)).toBe(true);
  });
});

describe("logNote / logWarning(宛先と継続行)", () => {
  it("stderr へ出し、詳細行は 2 スペースの字下げで続く(色は付かない)", async () => {
    const env = await makeTestEnv();
    env.setColor(true);
    await Effect.runPromise(
      Effect.gen(function* () {
        yield* logNote("first");
        yield* logWarning("second", ["item-a", "item-b"]);
      }).pipe(Effect.provide(env.layer)),
    );
    expect(env.logs).toEqual([]);
    expect(env.errors).toEqual([
      `${ESC}[36mNote:${ESC}[0m first`,
      `${ESC}[33mWarning:${ESC}[0m second`,
      "  item-a",
      "  item-b",
    ]);
  });

  it("同一文面の Note / Warning は台帳(1 コマンド実行)あたり 1 回だけ出る", async () => {
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

  it("テスト環境の既定は無色(断言を素の文字列で書ける)", async () => {
    const env = await makeTestEnv();
    await Effect.runPromise(logNote("plain").pipe(Effect.provide(env.layer)));
    expect(env.errors).toEqual(["Note: plain"]);
  });
});
