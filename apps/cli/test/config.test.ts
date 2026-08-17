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
    // 報告文は**設定キー名**を言う(宣言オブジェクトの取り違え — レビュー指摘 —
    // の回帰検査。Effect の内部表現が stdout へ出る形を固定で塞ぐ)
    expect(env.logs).toContain("Set server");
    expect(env.logs.join("\n")).not.toContain("_id");
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

  it("サブコマンドなしは使い方を表示する(exit 0・出力は stderr)", async () => {
    // bare `maruhi` はヘルプ要求として扱う(第 3 段階の裁定 — gunshi 時代の
    // exit 0 を維持。出力先は決定 9 に合わせて stdout → stderr へ変更)。
    // 一覧はコマンド定義から描かれる(手書きだと、コマンドを増やしたときに
    // ヘルプだけ古いまま残る)
    const env = await makeTestEnv();
    expect(await runCli([], env.layer)).toBe(0);
    expect(env.logs).toEqual([]);
    const help = env.errors.join("\n");
    expect(help).toContain("maruhi <subcommand>");
    // 部分一致だと他コマンドの説明文("run the command…" 等)で満たされて
    // しまい、一覧からの脱落を検出できない(Pullfrog 指摘)。SUBCOMMANDS
    // 節に**行として**並んでいることを見る
    const section = help.slice(help.indexOf("SUBCOMMANDS"));
    expect(section).toContain("SUBCOMMANDS");
    for (const command of [
      "login",
      "logout",
      "pull",
      "run",
      "push",
      "env",
      "server",
      "invite",
      "member",
      "key",
      "project",
      "rotation",
      "audit",
      "config",
    ]) {
      expect(section, command).toMatch(new RegExp(`^\\s+${command} `, "m"));
    }
  });
});
