// Tests for the rotation config parser (rotate-config.ts — PF6 ruling R1):
// strict shape (unknown keys refused, the header shared with the other
// repository configs), per-connector rules and inputs, the AWS key id
// companion's uniqueness, and the rule lookup by companion.

import { describe, expect, it } from "vitest";

import { parseRotateConfig, ruleFor } from "../src/rotate-config.ts";
import { rotationAction } from "../src/rotation.ts";

const PROJECT = "a".repeat(64);

function parse(config: unknown) {
  return parseRotateConfig(JSON.stringify(config));
}

function expectValid(config: unknown) {
  const parsed = parse(config);
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
      "variables.X.connector must be one of aws-iam-access-key, cloudflare-api-token, postgres, mysql",
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
