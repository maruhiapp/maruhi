// Coverage sweep for the serving topology (W2 ruling BM —
// docs/notes/session-43.md).
//
// maruhi-server serves web assets from the same Worker and pins the
// API path space to the Worker side via `assets.run_worker_first` in
// wrangler.jsonc. That list is a hand-maintained copy of api-schema's
// path space, and drift **breaks silently**: under compatibility_date
// 2026-07-01 navigation requests prefer asset serving
// (assets_navigation_prefers_asset_serving), so an endpoint missed by
// the list is swallowed by the SPA shell's 200 without appearing in
// errors or logs (session-43 §9).
//
// So, in the same shape as session-capability.ts's sweep, we check at
// test time that every registered HttpApi endpoint path is covered by
// some run_worker_first rule. If a new endpoint introduces a new
// prefix, this test fails and forces the addition to wrangler.jsonc
// (fail-loud).
import { maruhiApi } from "@maruhi/api-schema";
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

/** The structural slice under inspection (a structural type for the same reason as session-capability.ts's SweepableApi). */
interface PathedApi {
  readonly groups: {
    readonly [group: string]: {
      readonly endpoints: {
        readonly [endpoint: string]: { readonly path: string };
      };
    };
  };
}

/** Enumerate (identifier, path) for every registered endpoint. */
function listEndpointPaths(api: PathedApi): Array<{ key: string; path: string }> {
  return Object.entries(api.groups).flatMap(([groupName, group]) =>
    Object.entries(group.endpoints).map(([endpointName, endpoint]) => ({
      key: `${groupName}.${endpointName}`,
      path: endpoint.path,
    })),
  );
}

/**
 * Does one run_worker_first rule cover a path? Workers Static
 * Assets rules are globs (`*` = any continuation); this repository
 * uses only "exact match" and "prefix + `*`". If any other shape (a
 * mid-rule `*`, a negated rule) appears, fail the check
 * conservatively and force this test's revision.
 */
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
    // Only the list form is valid: `true` (all Worker) would break
    // /invite and all asset serving, while an omission would drop the
    // whole API onto the SPA fallback — neither is viable
    expect(Array.isArray(rules), "assets.run_worker_first must be a string list").toBe(true);
    const ruleList = rules as string[];
    const uncovered = listEndpointPaths(maruhiApi as unknown as PathedApi).filter(
      ({ path }) => !ruleList.some((rule) => ruleCovers(rule, path)),
    );
    expect(
      uncovered,
      "an api-schema endpoint is not covered by run_worker_first — " +
        "navigation requests are silently swallowed by the SPA shell's 200 (session-43 §9). " +
        "Add the prefix to assets.run_worker_first in apps/server/wrangler.jsonc",
    ).toEqual([]);
  });

  it("keeps the static / SPA route space outside the worker-first rules (regression guard)", () => {
    // Pin that /invite (a static guidance page — AUTH_SPEC §15-3)
    // and the SPA route space (the /dashboard prefix — ruling BO) stay
    // served by the asset layer: guard against a future edit making
    // run_worker_first swallow them with an over-broad prefix (e.g.
    // /inv* or /*)
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
