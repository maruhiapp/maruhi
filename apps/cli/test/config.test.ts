// 非機密設定(config.ts)と CLI の config コマンドのテスト。

import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { defaultConfigPath } from "../src/config.ts";
import { makeTestEnv } from "./support/env.ts";

describe("defaultConfigPath", () => {
  it("MARUHI_CONFIG_DIR を最優先する", () => {
    const path = defaultConfigPath((name) => (name === "MARUHI_CONFIG_DIR" ? "/tmp/x" : undefined));
    expect(path).toBe(join("/tmp/x", "config.json"));
  });

  it("XDG_CONFIG_HOME → ~/.config の順で解決する", () => {
    const withXdg = defaultConfigPath((name) => (name === "XDG_CONFIG_HOME" ? "/xdg" : undefined));
    expect(withXdg).toBe(join("/xdg", "maruhi", "config.json"));
    const fallback = defaultConfigPath(() => undefined);
    expect(fallback).toContain(join(".config", "maruhi", "config.json"));
  });
});

describe("maruhi config", () => {
  it("set → get が往復し、ファイルには known key のみ永続化される", async () => {
    const env = await makeTestEnv();
    expect(await runCli(["config", "set", "server", "https://maruhi.example"], env.layer)).toBe(0);
    expect(await runCli(["config", "get", "server"], env.layer)).toBe(0);
    expect(env.logs).toContain("https://maruhi.example");
    const raw = JSON.parse(await readFile(env.configPath, "utf8")) as Record<string, string>;
    expect(raw).toEqual({ server: "https://maruhi.example" });
  });

  it("未知キーの set は usage エラー(2)で拒否する", async () => {
    const env = await makeTestEnv();
    // 打ち間違いは実行の失敗(1)と区別する
    expect(await runCli(["config", "set", "token", "x"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Unknown config key");
  });

  it("壊れた設定ファイルは get で報告され、set で作り直せる", async () => {
    const env = await makeTestEnv();
    const { writeFile, mkdir } = await import("node:fs/promises");
    const { dirname } = await import("node:path");
    await mkdir(dirname(env.configPath), { recursive: true });
    await writeFile(env.configPath, "{ broken json");
    expect(await runCli(["config", "get", "server"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("corrupt");
    // set は破棄して作り直せる(非機密のみのファイル)
    expect(await runCli(["config", "set", "server", "https://maruhi.example"], env.layer)).toBe(0);
    expect(await runCli(["config", "get", "server"], env.layer)).toBe(0);
    expect(env.logs).toContain("https://maruhi.example");
  });

  it("JSON 配列の設定ファイルは破損として扱う", async () => {
    const env = await makeTestEnv();
    const { writeFile, mkdir } = await import("node:fs/promises");
    const { dirname } = await import("node:path");
    await mkdir(dirname(env.configPath), { recursive: true });
    await writeFile(env.configPath, "[]");
    expect(await runCli(["config", "get", "server"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("corrupt");
  });

  it("サブコマンドなしは使い方を表示する", async () => {
    const env = await makeTestEnv();
    expect(await runCli([], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("使い方");
    // 一覧は登録済みサブコマンドから導く(手書きだと、コマンドを増やしたときに
    // ヘルプだけ古いまま残る)。エントリコマンド自身(`maruhi`)は出さない。
    // 移行済み(effect/unstable/cli 側)のコマンドは gunshi の表に居ないので
    // 末尾へ合流する — 一覧から消えないことがここの要点
    expect(env.logs).toContain(
      "commands: login / logout / pull / run / push / env / server / invite / member / key / project / rotation / audit / config",
    );
  });
});
