// The non-intersection sweep of the SPA route space vs
// run_worker_first (ruling BZ — session-43 §12).
//
// Ruling BO (session-43 §3) cleanly separated the two spaces: "the
// SPA is /dashboard-prefixed; the API is /auth-, /projects-,
// /invites-prefixed". Half of that separation (coverage on the API
// side) is checked by the server-side serving-topology.test.ts, but
// the reverse direction — "no SPA route is swallowed by the Worker"
// — was only checked by hand until now: if an over-broad prefix
// (e.g. `/*`) enters run_worker_first, a navigation to an SPA route
// hits the Worker's 404 JSON and the whole screen disappears. Here
// the actual route definitions (SPA_ROUTES — the only catalog App.tsx
// binds with bindRoute) and the actual serving config
// (apps/server/wrangler.jsonc) are collated as-is to make
// non-intersection fail-loud.
import { describe, expect, it } from "vitest";
import { unstable_readConfig } from "wrangler";

import { SAMPLE_PROJECT_ID } from "../../src/dashboard/endpoints.ts";
import { SPA_ROUTES, spaPaths } from "../../src/dashboard/routes.ts";

/** The same semantics as serving-topology.test.ts's ruleCovers (exact match / prefix + `*`). */
function ruleCovers(rule: string, path: string): boolean {
  if (rule.startsWith("!")) {
    throw new Error(
      `run_worker_first has a negative rule: ${rule} — re-rule the non-intersection sweep's semantics`,
    );
  }
  const starIndex = rule.indexOf("*");
  if (starIndex === -1) return rule === path;
  if (starIndex !== rule.length - 1) {
    throw new Error(
      `run_worker_first has a mid-pattern wildcard: ${rule} — re-rule the non-intersection sweep's semantics`,
    );
  }
  return path.startsWith(rule.slice(0, -1));
}

/** Materializes a route path's `:param` with a sample value (a navigation is always a concrete path). */
function samplePath(template: string): string {
  return template.replace(/:projectId/g, SAMPLE_PROJECT_ID);
}

describe("SPA route space vs run_worker_first (ruling BZ)", () => {
  it("keeps every SPA route on the asset layer (never swallowed by the worker)", () => {
    const config = unstable_readConfig({
      config: new URL("../../../server/wrangler.jsonc", import.meta.url).pathname,
    });
    const rules = config.assets?.run_worker_first;
    expect(Array.isArray(rules), "assets.run_worker_first must be a string list").toBe(true);
    const ruleList = rules as string[];
    for (const spaRoute of SPA_ROUTES) {
      // path is optional in the type (pathless route), but every
      // SPA_ROUTES entry has one
      expect(spaRoute.path, "every SPA route must declare a path").toBeDefined();
      const path = samplePath(spaRoute.path ?? "");
      expect(
        path.includes(":"),
        `route "${spaRoute.path}" has an unsubstituted param — extend samplePath`,
      ).toBe(false);
      const covering = ruleList.filter((rule) => ruleCovers(rule, path));
      expect(
        covering,
        `SPA route ${path} is covered by run_worker_first — navigation would hit the worker's 404`,
      ).toEqual([]);
    }
  });

  it("binds every spaPaths builder to a declared route (ruling CA)", () => {
    // Builders and route definitions read the same constants in
    // routes.ts; this pins that adding a builder comes with
    // registration into SPA_ROUTES (= becoming a target of the
    // non-intersection sweep) and that parameter substitution is
    // complete (a missed :param is a runtime 404)
    const declaredPaths = new Set(SPA_ROUTES.map((r) => r.path));
    const built = [
      spaPaths.home(),
      spaPaths.dashboard(),
      spaPaths.account(),
      spaPaths.tokens(),
      spaPaths.devices(),
      spaPaths.project(SAMPLE_PROJECT_ID),
    ];
    for (const path of built) {
      expect(path.includes(":"), `builder output ${path} has an unsubstituted param`).toBe(false);
    }
    // project is checked after sample substitution, so the template
    // side is reverse-substituted for the collation
    expect(declaredPaths.has(spaPaths.dashboard())).toBe(true);
    expect(declaredPaths.has(spaPaths.account())).toBe(true);
    expect(declaredPaths.has(spaPaths.tokens())).toBe(true);
    expect(declaredPaths.has(spaPaths.devices())).toBe(true);
    expect(declaredPaths.has(spaPaths.home())).toBe(true);
    expect(declaredPaths.has(spaPaths.project(":projectId"))).toBe(true);
  });
});
