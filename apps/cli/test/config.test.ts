import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { defaultConfigPath } from "../src/config.ts";
import { makeTestEnv } from "./support/env.ts";

describe("defaultConfigPath", () => {
  it("prefers MARUHI_CONFIG_DIR above all", () => {
    const path = defaultConfigPath((name) => (name === "MARUHI_CONFIG_DIR" ? "/tmp/x" : undefined));
    expect(path).toBe(join("/tmp/x", "config.json"));
  });

  it("resolves XDG_CONFIG_HOME then ~/.config", () => {
    const withXdg = defaultConfigPath((name) => (name === "XDG_CONFIG_HOME" ? "/xdg" : undefined));
    expect(withXdg).toBe(join("/xdg", "maruhi", "config.json"));
    const fallback = defaultConfigPath(() => undefined);
    expect(fallback).toContain(join(".config", "maruhi", "config.json"));
  });
});

describe("maruhi config", () => {
  it("set → get round-trips, and only known keys are persisted to the file", async () => {
    const env = await makeTestEnv();
    expect(await runCli(["config", "set", "server", "https://maruhi.example"], env.layer)).toBe(0);
    expect(env.logs).toContain("Set server");
    expect(env.logs.join("\n")).not.toContain("_id");
    expect(await runCli(["config", "get", "server"], env.layer)).toBe(0);
    expect(env.logs).toContain("https://maruhi.example");
    const raw = JSON.parse(await readFile(env.configPath, "utf8")) as Record<string, string>;
    expect(raw).toEqual({ server: "https://maruhi.example" });
  });

  it("rejects set of an unknown key as a usage error (2)", async () => {
    const env = await makeTestEnv();
    expect(await runCli(["config", "set", "token", "x"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Unknown config key");
  });

  it("a corrupt config file is reported by get and can be rebuilt by set", async () => {
    const env = await makeTestEnv();
    const { writeFile, mkdir } = await import("node:fs/promises");
    const { dirname } = await import("node:path");
    await mkdir(dirname(env.configPath), { recursive: true });
    await writeFile(env.configPath, "{ broken json");
    expect(await runCli(["config", "get", "server"], env.layer)).toBe(1);
    expect(env.errors).toEqual([
      `maruhi: Cannot read the config file (it is corrupt): ${env.configPath}`,
    ]);
    expect(await runCli(["config", "set", "server", "https://maruhi.example"], env.layer)).toBe(0);
    expect(env.errors).toEqual([
      `maruhi: Cannot read the config file (it is corrupt): ${env.configPath}`,
      `Warning: Cannot read the config file (it is corrupt): ${env.configPath} — discarding the existing config and recreating it with only this key`,
    ]);
    expect(await runCli(["config", "get", "server"], env.layer)).toBe(0);
    expect(env.logs).toContain("https://maruhi.example");
  });

  it("a read failure other than ENOENT is not folded into empty config — it is reported as a typed error", async () => {
    const env = await makeTestEnv();
    const { mkdir } = await import("node:fs/promises");
    await mkdir(env.configPath, { recursive: true });
    expect(await runCli(["config", "get", "server"], env.layer)).toBe(1);
    expect(env.errors).toEqual([
      `maruhi: Cannot read the config file (EISDIR). Fix the file's permissions or move it out of the way, then retry: ${env.configPath}`,
    ]);
    expect(await runCli(["config", "set", "server", "https://maruhi.example"], env.layer)).toBe(1);
    expect(env.errors).toEqual([
      `maruhi: Cannot read the config file (EISDIR). Fix the file's permissions or move it out of the way, then retry: ${env.configPath}`,
      `maruhi: Cannot read the config file (EISDIR). Fix the file's permissions or move it out of the way, then retry: ${env.configPath}`,
    ]);
  });

  it("treats a JSON-array config file as corrupt", async () => {
    const env = await makeTestEnv();
    const { writeFile, mkdir } = await import("node:fs/promises");
    const { dirname } = await import("node:path");
    await mkdir(dirname(env.configPath), { recursive: true });
    await writeFile(env.configPath, "[]");
    expect(await runCli(["config", "get", "server"], env.layer)).toBe(1);
    expect(env.errors).toEqual([
      `maruhi: Cannot read the config file (it is corrupt): ${env.configPath}`,
    ]);
  });

  it("with no subcommand shows usage (exit 0, output to stderr)", async () => {
    const env = await makeTestEnv();
    expect(await runCli([], env.layer)).toBe(0);
    expect(env.logs).toEqual([]);
    const help = env.errors.join("\n");
    expect(help).toContain("maruhi <subcommand>");
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
