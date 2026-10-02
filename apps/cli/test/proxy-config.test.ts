// Tests for `maruhi.proxy.json` (proxy-config.ts — PF4 ruling P5): the
// strict parser — host grammar, shorthands, defaults, unknown keys,
// connector inputs, and the "a consumed input is never injected" rule.
// Error wording never echoes a typed value.

import { describe, expect, it } from "vitest";

import { parseHostPattern, parseProxyConfig } from "../src/proxy-config.ts";

const PROJECT = "a".repeat(64);

function parse(config: unknown) {
  return parseProxyConfig(JSON.stringify(config));
}

describe("parseHostPattern", () => {
  it("reads scheme, wildcard, and port with https defaults", () => {
    expect(parseHostPattern("api.github.com")).toEqual({
      scheme: "https",
      host: "api.github.com",
      wildcard: false,
      port: 443,
    });
    expect(parseHostPattern("*.GoogleAPIs.com:8443")).toEqual({
      scheme: "https",
      host: "googleapis.com",
      wildcard: true,
      port: 8443,
    });
    expect(parseHostPattern("http://localhost:8787")).toEqual({
      scheme: "http",
      host: "localhost",
      wildcard: false,
      port: 8787,
    });
    expect(parseHostPattern("http://app.localhost:3000")).toEqual({
      scheme: "http",
      host: "app.localhost",
      wildcard: false,
      port: 3000,
    });
    expect(parseHostPattern("http://127.0.0.1")).toEqual({
      scheme: "http",
      host: "127.0.0.1",
      wildcard: false,
      port: 80,
    });
  });

  it("refuses paths, other schemes, bad ports, and one-label wildcards", () => {
    expect(parseHostPattern("api.github.com/v3")).toMatch(/no path/);
    expect(parseHostPattern("ftp://x.example")).toMatch(/scheme/);
    expect(parseHostPattern("x.example:0")).toMatch(/port/);
    expect(parseHostPattern("x.example:70000")).toMatch(/port/);
    expect(parseHostPattern("*.com")).toMatch(/two labels/);
    // Plain HTTP would carry a value in cleartext: only the loopback is accepted
    expect(parseHostPattern("http://api.example.com")).toMatch(
      /plain http:\/\/ is accepted only for loopback hosts/,
    );
    expect(parseHostPattern("http://10.0.0.5:8080")).toMatch(/loopback/);
    expect(parseHostPattern("http://*.example.com")).toMatch(/loopback/);
    expect(parseHostPattern("bad_host.example")).toMatch(/DNS name/);
    expect(parseHostPattern("")).toMatch(/DNS name/);
  });
});

describe("parseProxyConfig", () => {
  it("accepts every rule shape, with defaults for unmatched / unlisted / surfaces", () => {
    const config = parse({
      version: 1,
      project: PROJECT,
      variables: {
        GITHUB_TOKEN: ["api.github.com", "*.githubusercontent.com"],
        OPENAI_API_KEY: {
          mode: "broker",
          hosts: ["api.openai.com"],
          surfaces: ["header", "body"],
          placeholder: "sk-placeholder-0000000000",
        },
        DATABASE_URL: "passthrough",
        LOG_LEVEL: { mode: "passthrough" },
        LEGACY: "withhold",
        GH_INSTALLATION_TOKEN: {
          mode: "connector",
          connector: "github-app",
          inputs: {
            appId: "GH_APP_ID",
            privateKey: "GH_APP_PRIVATE_KEY",
            installationId: "GH_APP_INSTALLATION_ID",
          },
          hosts: ["api.github.com"],
        },
      },
    });
    expect(typeof config).not.toBe("string");
    if (typeof config === "string") {
      return;
    }
    expect(config.projectId).toBe(PROJECT);
    expect(config.unmatched).toBe("allow");
    expect(config.unlisted).toBe("withhold");
    expect(config.variables.get("GITHUB_TOKEN")).toEqual({
      mode: "broker",
      hosts: [
        { scheme: "https", host: "api.github.com", wildcard: false, port: 443 },
        { scheme: "https", host: "githubusercontent.com", wildcard: true, port: 443 },
      ],
      surfaces: ["header"],
      placeholder: undefined,
    });
    expect(config.variables.get("OPENAI_API_KEY")).toMatchObject({
      mode: "broker",
      surfaces: ["header", "body"],
      placeholder: "sk-placeholder-0000000000",
    });
    expect(config.variables.get("DATABASE_URL")).toEqual({ mode: "passthrough" });
    expect(config.variables.get("LOG_LEVEL")).toEqual({ mode: "passthrough" });
    expect(config.variables.get("LEGACY")).toEqual({ mode: "withhold" });
    expect(config.variables.get("GH_INSTALLATION_TOKEN")).toMatchObject({
      mode: "connector",
      connector: "github-app",
      inputs: {
        appId: "GH_APP_ID",
        privateKey: "GH_APP_PRIVATE_KEY",
        installationId: "GH_APP_INSTALLATION_ID",
      },
    });
  });

  it("reads explicit unmatched / unlisted and an empty variables object", () => {
    const config = parse({
      version: 1,
      unmatched: "block",
      unlisted: "passthrough",
      variables: {},
    });
    expect(config).toMatchObject({ unmatched: "block", unlisted: "passthrough" });
  });

  it("refuses unknown keys, bad versions, bad modes, and bad values — naming the key, never the value", () => {
    expect(parse({ version: 2, variables: {} })).toMatch(/version/);
    expect(parse({ version: 1, variables: {}, extra: 1 })).toMatch(
      /unknown top-level keys \(extra\)/,
    );
    expect(parse({ version: 1, variables: {}, project: "nope" })).toMatch(/project must be/);
    expect(parse({ version: 1, variables: {}, unmatched: "deny" })).toMatch(/unmatched must be/);
    expect(parse({ version: 1, variables: {}, unlisted: "inject" })).toMatch(/unlisted must be/);
    expect(parse({ version: 1, variables: [] })).toMatch(/variables must be an object/);
    expect(parse({ version: 1, variables: { "BAD-NAME": "passthrough" } })).toMatch(
      /environment variable names/,
    );
    expect(parse({ version: 1, variables: { X: { mode: "magic" } } })).toMatch(
      /variables.X.mode must be/,
    );
    expect(parse({ version: 1, variables: { X: 42 } })).toMatch(/variables.X must be an object/);
    expect(parse({ version: 1, variables: { X: { mode: "broker", hosts: [] } } })).toMatch(
      /variables.X.hosts must be a non-empty array/,
    );
    expect(parse({ version: 1, variables: { X: { mode: "broker", hosts: ["a b"] } } })).toMatch(
      /variables.X.hosts has an invalid entry/,
    );
    expect(
      parse({ version: 1, variables: { X: { mode: "broker", hosts: ["x.example"], extra: 1 } } }),
    ).toMatch(/variables.X has unknown keys \(extra\)/);
    expect(
      parse({
        version: 1,
        variables: { X: { mode: "broker", hosts: ["x.example"], surfaces: ["cookie"] } },
      }),
    ).toMatch(/variables.X.surfaces accepts only/);
    const secretLooking = "SECRET-VALUE-THAT-MUST-NOT-ECHO";
    const short = parse({
      version: 1,
      variables: { X: { mode: "broker", hosts: ["x.example"], placeholder: "password-ish" } },
    });
    expect(short).toMatch(/variables.X.placeholder must be 16 to 256/);
    // One placeholder inside another is refused like a duplicate
    const nested = parse({
      version: 1,
      variables: {
        X: { mode: "broker", hosts: ["x.example"], placeholder: "fixed-placeholder-value" },
        Y: { mode: "broker", hosts: ["y.example"], placeholder: "fixed-placeholder-value-longer" },
      },
    });
    expect(nested).toMatch(/variables.Y.placeholder is also used by another rule, or contains/);
    const dup = parse({
      version: 1,
      variables: {
        X: { mode: "broker", hosts: ["x.example"], placeholder: secretLooking },
        Y: { mode: "broker", hosts: ["y.example"], placeholder: secretLooking },
      },
    });
    expect(dup).toMatch(/variables.Y.placeholder is also used/);
    expect(dup).not.toContain(secretLooking);
    expect(parse({ version: 1, variables: { X: { mode: "passthrough", hosts: [] } } })).toMatch(
      /a passthrough rule takes only "mode"/,
    );
  });

  it("validates connector rules: kind, required inputs, and no injection of a consumed input", () => {
    const base = { mode: "connector", hosts: ["api.github.com"] };
    expect(
      parse({ version: 1, variables: { T: { ...base, connector: "aws-sts", inputs: {} } } }),
    ).toMatch(/variables.T.connector must be one of github-app/);
    expect(
      parse({
        version: 1,
        variables: { T: { ...base, connector: "github-app", inputs: { appId: "A" } } },
      }),
    ).toMatch(/variables.T.inputs.privateKey must name a maruhi variable/);
    expect(
      parse({
        version: 1,
        variables: {
          T: {
            ...base,
            connector: "github-app",
            inputs: { appId: "A", privateKey: "K", installationId: "I", extra: "E" },
          },
        },
      }),
    ).toMatch(/variables.T.inputs has unknown keys \(extra\)/);
    const consumedAndPassed = parse({
      version: 1,
      variables: {
        T: {
          ...base,
          connector: "github-app",
          inputs: { appId: "A", privateKey: "K", installationId: "I" },
        },
        K: "passthrough",
      },
    });
    expect(consumedAndPassed).toMatch(
      /variables.K is consumed by a connector \(T.inputs.privateKey\) and cannot also have a passthrough rule/,
    );
    // An explicit withhold on a consumed input is consistent and accepted
    const withheld = parse({
      version: 1,
      variables: {
        T: {
          ...base,
          connector: "github-app",
          inputs: { appId: "A", privateKey: "K", installationId: "I" },
        },
        K: "withhold",
      },
    });
    expect(typeof withheld).not.toBe("string");
  });

  it("reports a non-JSON file and a non-object top level", () => {
    expect(parseProxyConfig("{")).toBe("not valid JSON");
    expect(parseProxyConfig("[]")).toBe("the top level must be an object");
  });
});
