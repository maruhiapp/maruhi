import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vite-plus/test";

const REPO_ROOT = join(import.meta.dirname, "../../..");

function addPropertyRuleNames(properties: unknown, into: Set<string>): void {
  if (typeof properties !== "object" || properties === null) {
    return;
  }
  for (const name of Object.keys(properties)) {
    if (name.startsWith("effecttsgo/")) {
      into.add(name);
    }
  }
}

function collectRuleNames(node: unknown, into: Set<string>): void {
  if (Array.isArray(node)) {
    for (const item of node) {
      collectRuleNames(item, into);
    }
    return;
  }
  if (typeof node !== "object" || node === null) {
    return;
  }
  for (const [key, value] of Object.entries(node)) {
    if (key === "properties") {
      addPropertyRuleNames(value, into);
    }
    collectRuleNames(value, into);
  }
}

function registryRules(): ReadonlySet<string> {
  const schema: unknown = JSON.parse(
    readFileSync(join(REPO_ROOT, "node_modules/@effect/tsgo/oxlint-schema.json"), "utf8"),
  );
  const rules = new Set<string>();
  collectRuleNames(schema, rules);
  return rules;
}

interface LintConfig {
  readonly rules: Readonly<Record<string, unknown>>;
}

async function pinnedRules(): Promise<ReadonlySet<string>> {
  const { default: config } = (await import("../../../vite.config.ts")) as {
    readonly default: { readonly lint: LintConfig };
  };
  return new Set(Object.keys(config.lint.rules).filter((rule) => rule.startsWith("effecttsgo/")));
}

describe("the effecttsgo rule pins in vite.config.ts", () => {
  it("reads the registry and the pinned set", async () => {
    const registry = registryRules();
    const pinned = await pinnedRules();
    expect(registry.size).toBeGreaterThan(0);
    expect(registry.has("effecttsgo/floating-effect")).toBe(true);
    expect(pinned.has("effecttsgo/floating-effect")).toBe(true);
  });

  it("pins every rule @effect/tsgo ships", async () => {
    const registry = registryRules();
    const pinned = await pinnedRules();
    const uncovered = [...registry].filter((rule) => !pinned.has(rule)).toSorted();
    expect(
      uncovered,
      `effecttsgo rules shipped by @effect/tsgo but not pinned in vite.config.ts: ${uncovered.join(", ")}`,
    ).toEqual([]);
  });
});
