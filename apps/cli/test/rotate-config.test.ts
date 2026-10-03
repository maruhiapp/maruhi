// Tests for the rotation config parser (rotate-config.ts — PF6 ruling R1):
// strict shape (unknown keys refused, the header shared with the other
// repository configs), per-connector rules and inputs, the AWS key id
// companion's uniqueness, and the rule lookup by companion.

import { describe, expect, it } from "vitest";

import { parseRotateConfig, ruleFor } from "../src/rotate-config.ts";
import { rotationAction } from "../src/rotation.ts";

const PROJECT = "a".repeat(64);

function parse(config: unknown, configDir?: string) {
  return parseRotateConfig(
    typeof config === "string" ? config : JSON.stringify(config),
    configDir === undefined ? {} : { configDir },
  );
}

function expectValid(config: unknown, configDir?: string) {
  const parsed = parse(config, configDir);
  if (typeof parsed === "string") {
    throw new Error(parsed);
  }
  return parsed;
}

describe("parseRotateConfig", () => {
  it("parses every connector's rule with defaults", () => {
    const parsed = expectValid({
      version: 1,
      project: PROJECT,
      variables: {
        DATABASE_URL: {
          connector: "postgres",
          roles: ["app_a", "app_b"],
          inputs: { adminUrl: "ADMIN_DATABASE_URL" },
        },
        MYSQL_URL: { connector: "mysql" },
        AWS_SECRET_ACCESS_KEY: {
          connector: "aws-iam-access-key",
          accessKeyIdVariable: "AWS_ACCESS_KEY_ID",
          inputs: {
            accessKeyId: { environment: "ops", name: "AWS_ADMIN_KEY_ID" },
            secretAccessKey: { environment: "ops", name: "AWS_ADMIN_SECRET" },
          },
        },
        CF_API_TOKEN: { connector: "cloudflare-api-token", accountId: "0".repeat(32) },
      },
    });
    expect(parsed.projectId).toBe(PROJECT);
    expect(parsed.variables.get("DATABASE_URL")).toEqual({
      connector: "postgres",
      roles: ["app_a", "app_b"],
      inputs: { adminUrl: { environment: null, name: "ADMIN_DATABASE_URL" } },
    });
    expect(parsed.variables.get("MYSQL_URL")).toEqual({
      connector: "mysql",
      roles: null,
      host: "%",
      inputs: {},
    });
    expect(parsed.variables.get("AWS_SECRET_ACCESS_KEY")).toEqual({
      connector: "aws-iam-access-key",
      accessKeyIdVariable: "AWS_ACCESS_KEY_ID",
      user: null,
      inputs: {
        accessKeyId: { environment: "ops", name: "AWS_ADMIN_KEY_ID" },
        secretAccessKey: { environment: "ops", name: "AWS_ADMIN_SECRET" },
      },
    });
    expect(parsed.variables.get("CF_API_TOKEN")).toEqual({
      connector: "cloudflare-api-token",
      accountId: "0".repeat(32),
      inputs: {},
    });
  });

  it("refuses unknown keys, versions, and connectors, naming the key and never the value", () => {
    expect(parse({ version: 2, variables: {} })).toBe("unsupported config version (expected 1)");
    expect(parse({ version: 1, variables: {}, hosts: [] })).toContain(
      "unknown top-level keys (hosts)",
    );
    expect(parse({ version: 1, variables: { X: { connector: "vault" } } })).toBe(
      "variables.X.connector must be one of aws-iam-access-key, cloudflare-api-token, postgres, mysql, exec",
    );
    expect(
      parse({ version: 1, variables: { X: { connector: "postgres", host: "db" } } }),
    ).toContain("variables.X has unknown keys (host)");
    expect(
      parse({ version: 1, variables: { X: { connector: "postgres", inputs: { token: "T" } } } }),
    ).toContain(
      "variables.X.inputs has unknown keys (token); the postgres connector takes adminUrl",
    );
    expect(parse({ version: 1, variables: { "bad-name": { connector: "postgres" } } })).toContain(
      "variables keys must be variable names",
    );
    expect(parse("[]")).toBe("the top level must be an object");
  });

  it("validates the shapes of roles, inputs, and the AWS pair", () => {
    expect(
      parse({ version: 1, variables: { X: { connector: "postgres", roles: ["a"] } } }),
    ).toContain("exactly two role names");
    expect(
      parse({ version: 1, variables: { X: { connector: "postgres", roles: ["a", "a"] } } }),
    ).toContain("two different roles");
    expect(
      parse({ version: 1, variables: { X: { connector: "postgres", roles: ["a'; DROP", "b"] } } }),
    ).toContain("exactly two role names");
    expect(
      parse({
        version: 1,
        variables: { X: { connector: "postgres", inputs: { adminUrl: { name: "A" } } } },
      }),
    ).toContain("inputs.adminUrl.environment must be an environment id");
    expect(
      parse({
        version: 1,
        variables: {
          S: {
            connector: "aws-iam-access-key",
            accessKeyIdVariable: "I",
            inputs: { accessKeyId: "A" },
          },
        },
      }),
    ).toContain("must name both accessKeyId and secretAccessKey");
    expect(
      parse({
        version: 1,
        variables: { S: { connector: "aws-iam-access-key", accessKeyIdVariable: "S" } },
      }),
    ).toContain("must differ from the rule's own variable");
    expect(
      parse({
        version: 1,
        variables: { X: { connector: "cloudflare-api-token", accountId: "nope" } },
      }),
    ).toContain("accountId must be a Cloudflare account id");
    expect(parse({ version: 1, variables: { X: { connector: "mysql", host: "a b" } } })).toContain(
      "host must be the account's host part",
    );
  });

  it("keeps the access key id companion unique and rule-less", () => {
    expect(
      parse({
        version: 1,
        variables: {
          S: { connector: "aws-iam-access-key", accessKeyIdVariable: "I" },
          I: { connector: "cloudflare-api-token" },
        },
      }),
    ).toBe("variables.I is the access key id of S and cannot carry a rule of its own");
    expect(
      parse({
        version: 1,
        variables: {
          S: { connector: "aws-iam-access-key", accessKeyIdVariable: "I" },
          T: { connector: "aws-iam-access-key", accessKeyIdVariable: "I" },
        },
      }),
    ).toContain("name the same access key id variable (I)");
  });

  it("resolves a rule by its variable or by the AWS companion", () => {
    const parsed = expectValid({
      version: 1,
      variables: {
        AWS_SECRET_ACCESS_KEY: {
          connector: "aws-iam-access-key",
          accessKeyIdVariable: "AWS_ACCESS_KEY_ID",
        },
      },
    });
    expect(ruleFor(parsed, "AWS_ACCESS_KEY_ID")?.primary).toBe("AWS_SECRET_ACCESS_KEY");
    expect(ruleFor(parsed, "AWS_SECRET_ACCESS_KEY")?.primary).toBe("AWS_SECRET_ACCESS_KEY");
    expect(ruleFor(parsed, "OTHER")).toBeNull();
  });

  it("parses an exec rule: scripts as argv, cwd from the config's directory, companions and free-form inputs (PF8)", () => {
    const parsed = expectValid(
      {
        version: 1,
        variables: {
          STRIPE_SECRET_KEY: {
            connector: "exec",
            rotate: ["./scripts/rotate-stripe.sh", "--live"],
            finalize: "./scripts/finalize-stripe.sh",
            cwd: "ops",
            output: "json",
            companions: { STRIPE_KEY_ID: "STRIPE_KEY_ID" },
            inputs: { STRIPE_ADMIN_KEY: { environment: "ops", name: "STRIPE_ADMIN_KEY" } },
          },
          PLAIN: { connector: "exec", rotate: ["./rotate.sh"] },
        },
      },
      "/repo",
    );
    expect(parsed.variables.get("STRIPE_SECRET_KEY")).toEqual({
      connector: "exec",
      rotate: ["./scripts/rotate-stripe.sh", "--live"],
      finalize: ["./scripts/finalize-stripe.sh"],
      cwd: "/repo/ops",
      output: "json",
      companions: { STRIPE_KEY_ID: "STRIPE_KEY_ID" },
      inputs: { STRIPE_ADMIN_KEY: { environment: "ops", name: "STRIPE_ADMIN_KEY" } },
    });
    expect(parsed.variables.get("PLAIN")).toEqual({
      connector: "exec",
      rotate: ["./rotate.sh"],
      finalize: null,
      cwd: "/repo",
      output: "value",
      companions: {},
      inputs: {},
    });
    // A companion resolves the rule, like the AWS key id
    expect(ruleFor(parsed, "STRIPE_KEY_ID")?.primary).toBe("STRIPE_SECRET_KEY");
  });

  it("refuses exec rules whose scripts, names, or shapes a child could not carry", () => {
    const exec = (rule: Record<string, unknown>) =>
      parse({ version: 1, variables: { KEY: { connector: "exec", ...rule } } });
    expect(exec({})).toContain("variables.KEY.rotate must be the script's command");
    expect(exec({ rotate: [] })).toContain("variables.KEY.rotate must be the script's command");
    expect(exec({ rotate: [" "] })).toContain("variables.KEY.rotate must be the script's command");
    expect(exec({ rotate: ["./r.sh"], finalize: 7 })).toContain(
      "variables.KEY.finalize must be the script's command",
    );
    expect(exec({ rotate: ["./r.sh"], cwd: "/abs" })).toContain(
      "variables.KEY.cwd must be a non-empty relative path",
    );
    expect(exec({ rotate: ["./r.sh"], output: "yaml" })).toContain(
      'variables.KEY.output must be "value"',
    );
    expect(exec({ rotate: ["./r.sh"], companions: { ID: "KEY_ID" } })).toContain(
      'variables.KEY.companions needs "output": "json"',
    );
    expect(exec({ rotate: ["./r.sh"], output: "json", companions: { ID: "KEY" } })).toContain(
      "must differ from the rule's own variable",
    );
    expect(exec({ rotate: ["./r.sh"], output: "json", companions: { "bad-name": "X" } })).toContain(
      "variables.KEY.companions.bad-name: must be an environment variable name",
    );
    expect(exec({ rotate: ["./r.sh"], inputs: { PATH: "ADMIN" } })).toContain(
      "variables.KEY.inputs.PATH: is an execution-control environment variable",
    );
    expect(exec({ rotate: ["./r.sh"], inputs: { MH_ROTATE_X: "ADMIN" } })).toContain(
      "variables.KEY.inputs.MH_ROTATE_X: starts with MH_ROTATE_",
    );
    expect(exec({ rotate: ["./r.sh"], inputs: { KEY: "ADMIN" } })).toContain(
      "variables.KEY.inputs.KEY collides with the rule's own variable",
    );
    expect(
      exec({
        rotate: ["./r.sh"],
        output: "json",
        companions: { ID: "KEY_ID" },
        inputs: { ID: "ADMIN" },
      }),
    ).toContain("variables.KEY.companions.ID is also an input name");
    // The credential is injected under the rule's own name, so that name
    // must be one a script may carry
    expect(
      parse({
        version: 1,
        variables: { LD_PRELOAD: { connector: "exec", rotate: ["./r.sh"] } },
      }),
    ).toContain(
      "variables.LD_PRELOAD: the exec connector injects the credential under the variable's own name, which is an execution-control environment variable",
    );
    expect(
      parse({
        version: 1,
        variables: { MH_ROTATE_KEY: { connector: "exec", rotate: ["./r.sh"] } },
      }),
    ).toContain(
      "variables.MH_ROTATE_KEY: the exec connector injects the credential under the variable's own name, which starts with MH_ROTATE_",
    );
    // A companion under the rule's own name would overwrite the credential
    expect(exec({ rotate: ["./r.sh"], output: "json", companions: { KEY: "OTHER" } })).toContain(
      "variables.KEY.companions.KEY collides with the rule's own variable",
    );
    // Collisions are judged case-insensitively (a script may run where names are)
    expect(exec({ rotate: ["./r.sh"], inputs: { key: "ADMIN" } })).toContain(
      "variables.KEY.inputs.key collides with the rule's own variable",
    );
    expect(exec({ rotate: ["./r.sh"], inputs: { Admin: "A", ADMIN: "B" } })).toContain(
      "variables.KEY.inputs has two names that differ only by case (Admin and ADMIN)",
    );
    expect(
      exec({ rotate: ["./r.sh"], output: "json", companions: { ID: "X", id: "Y" } }),
    ).toContain("variables.KEY.companions.id repeats another companion name");
    expect(
      exec({
        rotate: ["./r.sh"],
        output: "json",
        companions: { Admin: "X" },
        inputs: { ADMIN: "A" },
      }),
    ).toContain("variables.KEY.companions.Admin is also an input name");
    // The working directory stays inside the config's directory
    expect(exec({ rotate: ["./r.sh"], cwd: "../elsewhere" })).toContain(
      "variables.KEY.cwd must stay inside the rotation config's directory (../elsewhere climbs out of it)",
    );
    expect(exec({ rotate: ["./r.sh"], cwd: "ops/../.." })).toContain(
      "variables.KEY.cwd must stay inside the rotation config's directory",
    );
    expect(exec({ rotate: ["./r.sh"], cwd: ".." })).toContain(
      "variables.KEY.cwd must stay inside the rotation config's directory",
    );
    const inside = parse({
      version: 1,
      variables: { KEY: { connector: "exec", rotate: ["./r.sh"], cwd: "ops/../ops" } },
    });
    expect(typeof inside).not.toBe("string");
    // A companion is a variable of exactly one rule and carries no rule of its own
    expect(
      parse({
        version: 1,
        variables: {
          KEY: {
            connector: "exec",
            rotate: ["./r.sh"],
            output: "json",
            companions: { ID: "KEY_ID" },
          },
          KEY_ID: { connector: "exec", rotate: ["./r.sh"] },
        },
      }),
    ).toContain("variables.KEY_ID is a companion of KEY and cannot carry a rule of its own");
    expect(
      parse({
        version: 1,
        variables: {
          KEY: {
            connector: "exec",
            rotate: ["./r.sh"],
            output: "json",
            companions: { ID: "KEY_ID", ID2: "KEY_ID" },
          },
        },
      }),
    ).toContain("variables.KEY.companions name the variable KEY_ID twice");
  });
});

describe("rotationAction (the checklist's next step — PF6 R3)", () => {
  const config = expectValid({
    version: 1,
    variables: {
      AWS_SECRET_ACCESS_KEY: {
        connector: "aws-iam-access-key",
        accessKeyIdVariable: "AWS_ACCESS_KEY_ID",
      },
    },
  });
  it("names the rotate command for a covered variable (the companion included), the by-hand route otherwise", () => {
    expect(
      rotationAction({
        environmentId: "prod",
        variableId: "v1",
        state: { name: "AWS_ACCESS_KEY_ID", deleted: false },
        config,
      }),
    ).toBe(
      "`maruhi var rotate AWS_SECRET_ACCESS_KEY --env prod` (aws-iam-access-key connector in maruhi.rotate.json)",
    );
    expect(
      rotationAction({
        environmentId: "prod",
        variableId: "v2",
        state: { name: "OTHER", deleted: false },
        config,
      }),
    ).toBe(
      "rotate at the issuer, then `maruhi push OTHER --env prod` (runbooks: https://maruhi.app/docs/rotation)",
    );
    expect(
      rotationAction({
        environmentId: "prod",
        variableId: "v3",
        state: { name: "GONE", deleted: true },
        config,
      }),
    ).toContain("`maruhi rotation dismiss v3 --env prod`");
    expect(
      rotationAction({ environmentId: "prod", variableId: "v4", state: undefined, config: null }),
    ).toContain("could not be resolved here");
  });
});
