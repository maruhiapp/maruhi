import { describe, expect, it, vi } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { startEnv } from "./support/argument-layer.ts";

describe("config's nested subcommands (ADR-0016 stage 3 ①)", () => {
  it("an unknown operation / bare `maruhi config` is a usage error (2)", async () => {
    const bogus = await startEnv();
    expect(await runCli(["config", "bogus"], bogus.env.layer)).toBe(2);
    expect(bogus.env.errors.join("\n")).toContain(
      "Unknown subcommand (expected one of: get | set)",
    );

    const bare = await startEnv();
    expect(await runCli(["config"], bare.env.layer)).toBe(2);
    expect(bare.env.logs).toEqual([]);
    expect(bare.env.errors.join("\n")).toContain("maruhi config");
  });

  it("an unknown config key never returns the typed word and lists the possible keys", async () => {
    const evil = "[2K\rmaruhi: OK";
    const get = await startEnv();
    expect(await runCli(["config", "get", evil], get.env.layer)).toBe(2);
    const getOutput = [...get.env.logs, ...get.env.errors].join("\n");
    expect(getOutput).toContain("Unknown config key (server | mirror | defaultProject");
    expect(getOutput).not.toContain("");
    expect(getOutput).not.toContain("\r");

    const action = await startEnv();
    expect(await runCli(["config", evil, "server"], action.env.layer)).toBe(2);
    const actionOutput = [...action.env.logs, ...action.env.errors].join("\n");
    expect(actionOutput).toContain("Unknown subcommand");
    expect(actionOutput).not.toContain("");
    expect(actionOutput).not.toContain("\r");
  });

  it("an empty / whitespace-only `config set` value fails without overwriting the existing setting", async () => {
    for (const value of ["", "  "]) {
      const { env } = await startEnv();
      expect(await runCli(["config", "set", "defaultEnvironment", value], env.layer)).toBe(2);
      expect(env.errors.join("\n")).toContain("Unacceptable value for positional argument value");
      expect(await runCli(["config", "get", "defaultEnvironment"], env.layer)).toBe(0);
      expect(env.logs).toContain("prod");
    }
  });

  it("a valueless `config set` fails at the declaration (required positional arg)", async () => {
    const { env } = await startEnv();
    expect(await runCli(["config", "set", "defaultEnvironment"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Missing positional argument value");
  });

  it("tokens behind `--` fill the positional-arg slots (ADR-0016 addendum 8)", async () => {
    const { env } = await startEnv();
    expect(await runCli(["config", "set", "--", "defaultEnvironment", "dev"], env.layer)).toBe(0);
    expect(env.logs).toContain("Set defaultEnvironment");
    expect(await runCli(["config", "get", "defaultEnvironment"], env.layer)).toBe(0);
    expect(env.logs).toContain("dev");
  });

  it("`config get`'s extra arguments fail, breaking neither the setting nor the read", async () => {
    const single = await startEnv();
    expect(await runCli(["config", "get", "defaultEnvironment", "dev"], single.env.layer)).toBe(2);
    const errors = single.env.errors.join("\n");
    expect(errors).toContain("Unexpected extra arguments (1;");
    expect(errors).toContain("maruhi config get only takes these positional arguments: key");
    expect(single.env.logs).toHaveLength(0);

    const multiple = await startEnv();
    expect(
      await runCli(["config", "get", "defaultEnvironment", "a", "b"], multiple.env.layer),
    ).toBe(2);
    expect(multiple.env.errors.join("\n")).toContain("Unexpected extra arguments (2;");

    const set = await startEnv();
    expect(
      await runCli(["config", "set", "defaultEnvironment", "dev", "extra"], set.env.layer),
    ).toBe(2);
    expect(set.env.errors.join("\n")).toContain("Unexpected extra arguments (1;");
    expect(await runCli(["config", "get", "defaultEnvironment"], set.env.layer)).toBe(0);
    expect(set.env.logs).toContain("prod");
  });

  it("a successful run's stdout is only the command's output (the value)", async () => {
    const { env } = await startEnv();
    const stdout = vi.spyOn(console, "log").mockImplementation(() => {});

    expect(await runCli(["config", "get", "defaultEnvironment"], env.layer)).toBe(0);
    expect(stdout).not.toHaveBeenCalled();
    expect(env.logs).toEqual(["prod"]);
  });
});
