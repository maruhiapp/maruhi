// Tests for non-sensitive config (config.ts) and the CLI's config command.

import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

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
    // The report names the **config key** (blocks the shape where a
    // declaration-object mix-up prints Effect's internal representation to
    // stdout)
    expect(env.logs).toContain("Set server");
    expect(env.logs.join("\n")).not.toContain("_id");
    expect(await runCli(["config", "get", "server"], env.layer)).toBe(0);
    expect(env.logs).toContain("https://maruhi.example");
    const raw = JSON.parse(await readFile(env.configPath, "utf8")) as Record<string, string>;
    expect(raw).toEqual({ server: "https://maruhi.example" });
  });

  it("rejects set of an unknown key as a usage error (2)", async () => {
    const env = await makeTestEnv();
    // A typo is distinguished from an execution failure (1)
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
    expect(env.errors.join("\n")).toContain("corrupt");
    // set can discard and rebuild it (a non-sensitive-only file)
    expect(await runCli(["config", "set", "server", "https://maruhi.example"], env.layer)).toBe(0);
    expect(await runCli(["config", "get", "server"], env.layer)).toBe(0);
    expect(env.logs).toContain("https://maruhi.example");
  });

  it("a read failure other than ENOENT is not folded into empty config — it is reported as a typed error", async () => {
    const env = await makeTestEnv();
    const { mkdir } = await import("node:fs/promises");
    // Place a directory where the config file goes (EISDIR: a read failure
    // that is not ENOENT)
    await mkdir(env.configPath, { recursive: true });
    expect(await runCli(["config", "get", "server"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Cannot read the config file (");
    expect(env.errors.join("\n")).not.toContain("corrupt");
    // set likewise must not silently replace an existing (unreadable)
    // config — it fails for the same reason
    expect(await runCli(["config", "set", "server", "https://maruhi.example"], env.layer)).toBe(1);
  });

  it("treats a JSON-array config file as corrupt", async () => {
    const env = await makeTestEnv();
    const { writeFile, mkdir } = await import("node:fs/promises");
    const { dirname } = await import("node:path");
    await mkdir(dirname(env.configPath), { recursive: true });
    await writeFile(env.configPath, "[]");
    expect(await runCli(["config", "get", "server"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("corrupt");
  });

  it("with no subcommand shows usage (exit 0, output to stderr)", async () => {
    // Bare `maruhi` is treated as a help request (exit 0; the destination is
    // stderr per decision 9). The list is drawn from the command definitions
    // (hand-written help would go stale when commands are added)
    const env = await makeTestEnv();
    expect(await runCli([], env.layer)).toBe(0);
    expect(env.logs).toEqual([]);
    const help = env.errors.join("\n");
    expect(help).toContain("maruhi <subcommand>");
    // A substring match would be satisfied by other commands' description
    // text ("run the command…" etc.) and could not detect a missing entry.
    // Check that they appear **as lines** in the SUBCOMMANDS section
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
