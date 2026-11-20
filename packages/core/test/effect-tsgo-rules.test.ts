// Watchdog: the root vite.config.ts pins every effecttsgo rule
// @effect/tsgo ships — the correctness preset at error, everything
// else off — because enabling the plugin switches rules on by
// category. The pin set is built from the package's presets, but a
// rule that appears in no preset escapes it: preferSchemaOverJson
// (deprecated, off in the language service) is the one such rule in
// @effect/tsgo 0.70.0 — harmless today, and pinned by name in the
// config. The failure mode this guards is the next one: a future
// @effect/tsgo release adding a rule outside the presets, in a
// category the config enables, would switch on with no config diff.
// This test derives the rule registry from the installed package and
// fails, naming the rule, until the config pins it — the
// deliberate-update discipline the repo applies to the package
// itself.

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vite-plus/test";

const REPO_ROOT = join(import.meta.dirname, "../../..");

/** Adds the `effecttsgo/*` keys of one `properties` map to the set. */
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

/** Collects the `effecttsgo/*` keys of every `properties` map in a parsed JSON document. */
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

/**
 * The rule registry of the installed @effect/tsgo: the `effecttsgo/*`
 * keys of the rule map in the package's oxlint-schema.json (the
 * schema its oxlint configuration is validated against — every rule
 * the plugin implements is a key there).
 */
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

/** The `effecttsgo/*` rules the root vite.config.ts lint block pins, at any severity. */
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
    // A schema restructure or a config refactor must fail here,
    // loudly, rather than let the coverage check below pass vacuously.
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
