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

  it("未知キーの set は拒否する", async () => {
    const env = await makeTestEnv();
    expect(await runCli(["config", "set", "token", "x"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("不明な設定キー");
  });

  it("サブコマンドなしは使い方を表示する", async () => {
    const env = await makeTestEnv();
    expect(await runCli([], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("使い方");
  });
});
