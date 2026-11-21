import { maruhiApi } from "@maruhi/api-schema";
import { env } from "cloudflare:test";
import { describe, expect, it } from "vite-plus/test";

interface PathedApi {
  readonly groups: {
    readonly [group: string]: {
      readonly endpoints: {
        readonly [endpoint: string]: { readonly path: string };
      };
    };
  };
}

function listEndpointPaths(api: PathedApi): Array<{ key: string; path: string }> {
  return Object.entries(api.groups).flatMap(([groupName, group]) =>
    Object.entries(group.endpoints).map(([endpointName, endpoint]) => ({
      key: `${groupName}.${endpointName}`,
      path: endpoint.path,
    })),
  );
}

function ruleCovers(rule: string, path: string): boolean {
  if (rule.startsWith("!")) {
    throw new Error(
      `run_worker_first has a negated rule: ${rule} — re-rule the coverage sweep's semantics`,
    );
  }
  const starIndex = rule.indexOf("*");
  if (starIndex === -1) return rule === path;
  if (starIndex !== rule.length - 1) {
    throw new Error(
      `run_worker_first has a mid-rule wildcard: ${rule} — re-rule the coverage sweep's semantics`,
    );
  }
  return path.startsWith(rule.slice(0, -1));
}

describe("serving topology (W2 ruling BM): run_worker_first covers the whole API path space", () => {
  it("routes every registered HttpApi endpoint to the worker, never the asset layer", () => {
    const rules = env.TEST_RUN_WORKER_FIRST;
    expect(Array.isArray(rules), "assets.run_worker_first must be a string list").toBe(true);
    const ruleList = rules as string[];
    const uncovered = listEndpointPaths(maruhiApi as unknown as PathedApi).filter(
      ({ path }) => !ruleList.some((rule) => ruleCovers(rule, path)),
    );
    expect(
      uncovered,
      "an api-schema endpoint is not covered by run_worker_first — " +
        "navigation requests are silently swallowed by the SPA shell's 200 (session-43 §9). " +
        "Add the prefix to assets.run_worker_first in apps/server/wrangler.jsonc " +
        "and to SPA_ASSETS.runWorkerFirst in apps/server/cloudflare.config.ts",
    ).toEqual([]);
  });

  it("keeps the static / SPA route space outside the worker-first rules (regression guard)", () => {
    const rules = env.TEST_RUN_WORKER_FIRST;
    expect(Array.isArray(rules)).toBe(true);
    const ruleList = rules as string[];
    for (const path of [
      "/invite",
      "/dashboard",
      `/dashboard/projects/${"ab".repeat(32)}`,
      "/dashboard/account",
    ]) {
      expect(
        ruleList.some((rule) => ruleCovers(rule, path)),
        `${path} must stay on the asset layer`,
      ).toBe(false);
    }
  });
});
