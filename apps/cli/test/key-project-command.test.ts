import { describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { expectNoLeak, startEnv } from "./support/argument-layer.ts";
import { makeTestEnv } from "./support/env.ts";

describe("key / project nested subcommands (ADR-0016 stage 3 ②)", () => {
  it("an unknown operation lists the possible operations and fails before login / server contact", async () => {
    const key = await makeTestEnv();
    expect(await runCli(["key", "bogus"], key.layer)).toBe(2);
    expect(key.errors.join("\n")).toContain(
      "Unknown subcommand (expected one of: generate | show | publish | recover | recovery | seal | reserve)",
    );
    expect(key.errors.join("\n")).not.toContain("Not logged in");

    const project = await makeTestEnv();
    expect(await runCli(["project", "bogus"], project.layer)).toBe(2);
    expect(project.errors.join("\n")).toContain(
      "Unknown subcommand (expected one of: init | list | verify | anchor | checkpoint | export | policy)",
    );
  });

  it("the operation name never returns the typed word (neither control chars nor the value reach the terminal)", async () => {
    const evil = "[2K\rmaruhi: OK";
    for (const command of ["key", "project"]) {
      const { env } = await startEnv();
      expect(await runCli([command, evil], env.layer), command).toBe(2);
      const output = [...env.logs, ...env.errors].join("\n");
      expect(output, command).toContain("Unknown subcommand");
      expect(output, command).not.toContain("");
      expect(output, command).not.toContain("\r");
    }
  });

  it("the leaves take no positional args (`key generate extra` fails as an extra argument)", async () => {
    const { env, server } = await startEnv();
    expect(await runCli(["key", "generate", "extra"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Unexpected extra arguments (1;");
    expect(errors).toContain("maruhi key generate takes no positional arguments");
    expect(server.requests).toHaveLength(0);
  });

  it("project verify / anchor / checkpoint / export refuse a malformed --project at its declaration, before login", async () => {
    for (const subcommand of ["verify", "anchor", "checkpoint", "export"]) {
      const env = await makeTestEnv();
      expect(
        await runCli(["project", subcommand, "--project", "not-a-genesis"], env.layer),
        subcommand,
      ).toBe(2);
      expect(env.errors.join("\n"), subcommand).toContain(
        "Unacceptable value for flag --project (expected: project id (lowercase hex SHA-256 of the genesis entry))",
      );
      expect(env.errors.join("\n"), subcommand).not.toContain("Not logged in");
      expectNoLeak(env, ["not-a-genesis"]);
    }
  });

  it("bare `maruhi key` / `maruhi project` is a usage error (2)", async () => {
    for (const command of ["key", "project"]) {
      const { env, server } = await startEnv();
      expect(await runCli([command], env.layer), command).toBe(2);
      expect(env.logs, command).toEqual([]);
      expect(env.errors.join("\n"), command).toContain(`maruhi ${command}`);
      expect(server.requests, command).toHaveLength(0);
    }
  });
});
