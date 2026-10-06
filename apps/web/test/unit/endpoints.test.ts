// The sweep of the dashboard's consumed surfaces (ruling BW —
// docs/notes/session-43.md §11).
//
// The catalog (src/dashboard/endpoints.ts) is collated against the
// registered HttpApi (api-schema — value imports are allowed only in
// the test process) to make "path agreement" and "session allowance"
// fail-loud. The client-side counterpart of serving-topology.test.ts
// (the server-side run_worker_first coverage).
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, sep } from "node:path";

import { isSessionAllowedEndpoint, maruhiApi, UNAUTHENTICATED_ENDPOINTS } from "@maruhi/api-schema";
import { describe, expect, it } from "vitest";

import {
  apiPaths,
  DASHBOARD_ENDPOINTS,
  SAMPLE_ENVIRONMENT_ID,
  SAMPLE_INVITE_ID,
  SAMPLE_PROJECT_ID,
  SAMPLE_TOKEN_ID,
} from "../../src/dashboard/endpoints.ts";

/** The structural slice of one registered endpoint surface. */
interface RegisteredEndpoint {
  readonly path: string;
  /** The query Schema (undefined on an endpoint that does not declare one). */
  readonly query?: {
    readonly ast?: {
      readonly propertySignatures?: ReadonlyArray<{ readonly name: PropertyKey }>;
    };
  };
}

/** The structural slice under inspection (a structural type for the same reason as session-capability.ts's SweepableApi). */
interface PathedApi {
  readonly groups: {
    readonly [group: string]: {
      readonly endpoints: {
        readonly [endpoint: string]: RegisteredEndpoint;
      };
    };
  };
}

const api = maruhiApi as unknown as PathedApi;

/**
 * Materializes a path template's `:param` with the same sample values
 * the catalog uses. An unknown parameter name stays in place, fails
 * the equality comparison, and forces a catalog revision (fail-loud).
 */
function substituteTemplate(template: string): string {
  return template
    .replace(/:projectId/g, SAMPLE_PROJECT_ID)
    .replace(/:environmentId/g, SAMPLE_ENVIRONMENT_ID)
    .replace(/:tokenId/g, SAMPLE_TOKEN_ID)
    .replace(/:id/g, SAMPLE_INVITE_ID);
}

describe("dashboard endpoint sweep (ruling BW)", () => {
  it("binds every consumed path builder to a real api-schema endpoint", () => {
    for (const { group, endpoint, sample } of DASHBOARD_ENDPOINTS) {
      const registered = api.groups[group]?.endpoints[endpoint];
      expect(registered, `${group}.${endpoint} is not a registered endpoint`).toBeDefined();
      expect(substituteTemplate(registered?.path ?? ""), `${group}.${endpoint}`).toBe(sample);
    }
  });

  it("classifies every consumed endpoint's auth surface correctly (AUTH_SPEC §5)", () => {
    // access: "session" must be inside the session-allowance
    // enumeration (a screen calling an unlisted API fails here, not
    // as a runtime 403). access: "unauthenticated" must be inside the
    // unauthenticated-surface enumeration (consuming an
    // auth-required surface as a navigation funnel also fails here)
    const unauthenticated = new Set(UNAUTHENTICATED_ENDPOINTS.map(([g, e]) => `${g}.${e}`));
    for (const { group, endpoint, access } of DASHBOARD_ENDPOINTS) {
      if (access === "session") {
        expect(
          isSessionAllowedEndpoint(group, endpoint),
          `${group}.${endpoint} is not session-allowed — a browser session cannot call it`,
        ).toBe(true);
      } else {
        expect(
          unauthenticated.has(`${group}.${endpoint}`),
          `${group}.${endpoint} is marked unauthenticated in the manifest but not in AUTH_SPEC §5`,
        ).toBe(true);
      }
    }
  });

  it("has no duplicate entries (each consumed endpoint is listed once)", () => {
    const keys = DASHBOARD_ENDPOINTS.map(({ group, endpoint }) => `${group}.${endpoint}`);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it("declares every consumed cursor query in the endpoint's query schema (ruling CB)", () => {
    // The cursor name withCursor attaches must be declared in
    // api-schema's query Schema: renaming the parameter fails here,
    // not as "paging silently going unresponsive" (the server ignores
    // an unknown query, so no runtime error ever surfaces)
    for (const { group, endpoint, cursor } of DASHBOARD_ENDPOINTS) {
      if (cursor === undefined) continue;
      expect(
        queryKeys(requireEndpoint(group, endpoint)),
        `${group}.${endpoint} does not declare a "${cursor}" query parameter in api-schema`,
      ).toContain(cursor);
    }
  });

  it("appends the declared cursor name from inside the paged builders (ruling CB)", () => {
    // Callers never touch the name (a mix-up is impossible
    // syntactically). The name the builders actually attach is pinned
    // here: the expected-value literals are deliberate (avoid
    // tautological repetition between builders)
    expect(apiPaths.projects("x")).toBe("/projects?after=x");
    expect(apiPaths.auditEvents(SAMPLE_PROJECT_ID, "y")).toBe(
      `/projects/${SAMPLE_PROJECT_ID}/audit/events?before=y`,
    );
    expect(apiPaths.auditInvites(SAMPLE_PROJECT_ID, "y")).toBe(
      `/projects/${SAMPLE_PROJECT_ID}/audit/invites?before=y`,
    );
    expect(apiPaths.auditSelf("y")).toBe("/auth/audit/events?before=y");
  });

  it("keeps path literals out of screen code (builders are the only source)", () => {
    // Source tripwire (rulings BY / CA): the catalog's completeness
    // rests on the discipline that "every path a screen uses goes
    // through a builder" (API = endpoints.ts, SPA = routes.ts). Here
    // we mechanically check that no API-prefixed or /dashboard-
    // prefixed path literal appears under src/ (excluding the two
    // builder homes), and drop the mixing-in of a builder-bypassing
    // consumer as drift
    const srcRoot = join(import.meta.dirname, "../../src");
    expect(
      findSourceOffenders(
        srcRoot,
        /["']\/(auth|projects|invites|dashboard)\b/,
        new Set([BUILDER_API_MODULE, BUILDER_SPA_MODULE].map((p) => join(srcRoot, p))),
      ),
      "path literal outside the builder modules — use apiPaths (endpoints.ts) or spaPaths (routes.ts)",
    ).toEqual([]);
  });

  it("keeps effect / api-schema imports type-only in bundle sources (rulings BR/CD)", () => {
    // Ruling BR — "no Effect / Schema executable code enters the
    // bundle (= the TCB)" — used to be a mere convention: a value
    // import passed both build and run silently while the bundle and
    // the supply chain quietly grew. Under verbatimModuleSyntax a
    // type-only import is spelled `import type`, so a value import
    // mixing in is mechanically checkable. This is the web half of the
    // Effect fence (CLAUDE.md "Architecture"); the crypto half is the
    // packages/crypto override of no-restricted-imports in .oxlintrc.json
    const srcRoot = join(import.meta.dirname, "../../src");
    expect(
      findSourceOffenders(
        srcRoot,
        // Subpath imports (effect/schema etc. — this repository's
        // mainstream form) are in scope.
        // The line-start anchor (m): an import statement is a
        // top-level declaration appearing at the start of a line —
        // without the anchor a match would bridge from the word
        // "import" in a comment to a real import's from clause and
        // false-positive (the ruling-CN note comment in api.ts was the
        // first trip). Re-exports (`export { X } from …` /
        // `export * from …`) pull the same executable code into the
        // bundle, so they are in scope too
        /^(?:import|export)\s+(?!type\b)[^;]*?from\s*["'](?:effect|@maruhi\/api-schema)(?:\/[^"']*)?["']/m,
        new Set(),
      ),
      "value import of effect / @maruhi/api-schema in bundle source — use `import type` (ruling BR)",
    ).toEqual([]);
  });

  it("keeps route() declarations inside the SPA route catalog (rulings BZ/CA)", () => {
    // SPA_ROUTES's authority rests on the discipline that "route()
    // declarations live only in routes.ts" (an inline route() in
    // App.tsx would silently narrow the non-intersection sweep).
    // bindRoute( is a different name and never false-positives
    const srcRoot = join(import.meta.dirname, "../../src");
    expect(
      findSourceOffenders(srcRoot, /\broute\(/, new Set([join(srcRoot, BUILDER_SPA_MODULE)])),
      "route() declared outside src/dashboard/routes.ts — add it to the SPA_ROUTES catalog instead",
    ).toEqual([]);
  });
});

/** The builder homes (excluded from the tripwire) — identified uniquely by resolved path. */
const BUILDER_API_MODULE = "dashboard/endpoints.ts";
const BUILDER_SPA_MODULE = "dashboard/routes.ts";

/** Fetches a registered endpoint (absence is fail-loud — the same premise as the path-agreement test). */
function requireEndpoint(group: string, endpoint: string): RegisteredEndpoint {
  const registered = api.groups[group]?.endpoints[endpoint];
  if (registered === undefined) throw new Error(`${group}.${endpoint} is not registered`);
  return registered;
}

/** The query Schema's declared property names (empty when undeclared). */
function queryKeys(registered: RegisteredEndpoint): PropertyKey[] {
  return (registered.query?.ast?.propertySignatures ?? []).map((p) => p.name);
}

/**
 * The tripwire's scan target: TS/TSX sources (exclusions are compared
 * by resolved path — a filename comparison would silently exempt a
 * same-named file in another directory).
 */
function isSweepTarget(
  entry: { isFile(): boolean; name: string },
  filePath: string,
  excluded: ReadonlySet<string>,
): boolean {
  return entry.isFile() && /\.(ts|tsx)$/.test(entry.name) && !excluded.has(filePath);
}

/**
 * The shared scan listing src/ files that hit pattern (excluded is a
 * set of resolved paths). The path-literal check covers only
 * double/single-quoted strings — backticks are out of scope because
 * they collide with path examples inside comments (`/auth/me` etc.),
 * and the resulting evasion gap is accepted (the same "good-faith
 * drift detection" standing as the word-hash tripwire — session-41
 * BG).
 */
function findSourceOffenders(
  srcRoot: string,
  pattern: RegExp,
  excluded: ReadonlySet<string>,
): string[] {
  const offenders: string[] = [];
  for (const entry of readdirSync(srcRoot, { recursive: true, withFileTypes: true })) {
    const filePath = join(entry.parentPath, entry.name);
    if (!isSweepTarget(entry, filePath, excluded)) continue;
    if (pattern.test(readFileSync(filePath, "utf8"))) {
      offenders.push(filePath.slice(srcRoot.length + 1));
    }
  }
  return offenders;
}

// ---------------------------------------------------------------------------
// The sweep of the consumption surfaces' envelope types (DK K8-2 /
// K8-7).
//
// Ruling BR says "the dashboard's wire types are only ever derived
// from api-schema's Schemas" (types.ts). A hand-written copy silently
// goes stale when api-schema is revised (backward compatible in the
// K7-8 sense). There are two claims, and both compare counts to
// counts (no recounting needed). If the target disappears, a
// readFileSync / 0-count fails (never passes vacuously). The
// type-only-import discipline is already held across all of src/ by
// "keeps effect / api-schema imports type-only" above, so it is not
// repeated here (one claim in one place — K6-R).
// ---------------------------------------------------------------------------

const TYPES_MODULE = "dashboard/types.ts";

/** The body with comments stripped (block / JSDoc / line comments). */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^[ \t]*\/\/.*$/gm, "");
}

/**
 * The type arguments from just after a `<` to the matching `>` (spans
 * nested `<…>` / `{…}` — a `[^<>]+` regexp never survives nesting and
 * would miss a hand-written envelope).
 */
function typeArgumentAt(source: string, start: number): string {
  let depth = 1;
  for (const bracket of source.slice(start).matchAll(/[<>]/g)) {
    depth += bracket[0] === "<" ? 1 : -1;
    if (depth === 0) return source.slice(start, start + bracket.index).trim();
  }
  throw new Error("unterminated type argument list");
}

describe("dashboard envelope types are derived from api-schema (DK K8)", () => {
  const srcRoot = join(import.meta.dirname, "../../src");
  const typesSource = stripComments(readFileSync(join(srcRoot, TYPES_MODULE), "utf8"));
  const exportedNames = [...typesSource.matchAll(/^export type (\w+)\b/gm)].map((m) => m[1]);

  it("keeps types.ts to `typeof XxxSchema.Type` derivations only (no interface, no literal)", () => {
    expect(typesSource.match(/^(?:export )?interface\s/gm), "hand-written interface").toBeNull();
    // Count across a wrap (oxfmt may break after `=`)
    const derived = typesSource.match(/^export type \w+\s*=\s*typeof \w+Schema\.Type;/gm) ?? [];
    expect(exportedNames.length, "types.ts must export at least one type").toBeGreaterThan(0);
    expect(derived.length, "every exported type must be `typeof XxxSchema.Type`").toBe(
      exportedNames.length,
    );
  });

  it("names a types.ts export at every consumption site (no inline envelope in screens)", () => {
    // Collect the type arguments of the consumption entrances
    // (apiGet / useApiResource / ApiResult / ResourceState) across all
    // of src/ and require each to be a types.ts export name —
    // widening the check's reach from the single types.ts file to the
    // whole consumption surface (pullfrog's point)
    const known = new Set(exportedNames);
    // Out of scope: the 2 modules that declare the entrances (`<T>` /
    // `<void>`) and types.ts itself
    const entranceModules = new Set(
      [TYPES_MODULE, "dashboard/api.ts", "dashboard/use-api-resource.ts"].map((p) =>
        join(srcRoot, p),
      ),
    );
    const sites: Array<{ file: string; typeArg: string }> = [];
    for (const entry of readdirSync(srcRoot, { recursive: true, withFileTypes: true })) {
      const filePath = join(entry.parentPath, entry.name);
      if (!isSweepTarget(entry, filePath, entranceModules)) continue;
      const source = stripComments(readFileSync(filePath, "utf8"));
      for (const match of source.matchAll(
        /\b(?:apiGet|useApiResource|ApiResult|ResourceState)</g,
      )) {
        sites.push({
          file: filePath.slice(srcRoot.length + 1),
          typeArg: typeArgumentAt(source, match.index + match[0].length),
        });
      }
    }
    expect(sites.length, "no consumption site found — the sweep pattern is stale").toBeGreaterThan(
      0,
    );
    const offenders = sites.filter((site) => !known.has(site.typeArg));
    expect(
      offenders,
      "consumption site whose type argument is not a types.ts export — derive it there",
    ).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The boundary on dashboard imports from the RSC (server graph).
//
// CLAUDE.md "RSC is the static shell only": when a server-graph file
// (App.tsx / Root.tsx / a pages/*.tsx without "use client") imports
// src/dashboard/*, the target is limited to a module behind a
// "use client" boundary (replaced by a client reference) or the
// allowlist known to be safe to evaluate server-side (routes.ts —
// route definitions and path constants only). Directly importing a
// dashboard module without a boundary (api.ts etc.) gets its body
// evaluated by the build-time RSC. A type-only import is erased, so it
// is out of scope. If routes.ts itself had a relative import, any
// module could enter the server graph via the allowlist, so routes.ts
// is not allowed to carry a relative import.
// ---------------------------------------------------------------------------

/** The dashboard modules without "use client" that the server graph may import. */
const SERVER_GRAPH_DASHBOARD_ALLOWLIST: ReadonlySet<string> = new Set(["dashboard/routes.ts"]);

/** Whether the comment-stripped body begins with the "use client" directive. */
function hasUseClientDirective(source: string): boolean {
  return /^\s*(["'])use client\1/.test(stripComments(source));
}

/** The specifiers of value imports / re-exports (`import type` / `export type` excluded). */
function valueImportSpecifiers(source: string): string[] {
  const stripped = stripComments(source);
  return [
    ...stripped.matchAll(/\b(?:import|export)\s+(type\s+)?(?:[^'";]*?\bfrom\s+)?(["'])([^"']+)\2/g),
  ]
    .filter((match) => match[1] === undefined)
    .map((match) => match[3] ?? "");
}

/** Resolves a relative specifier to a path relative to srcRoot ("/"-separated). undefined when not relative. */
function resolveRelative(fromFile: string, specifier: string): string | undefined {
  if (!specifier.startsWith(".")) return undefined;
  return join(dirname(fromFile), specifier).split(sep).join("/");
}

/**
 * For each server-graph file (srcRoot-relative), returns its
 * boundary-violating dashboard imports.
 * `read` maps a srcRoot-relative path → its body (undefined when
 * absent). Kept a pure function so the negative self-test below can
 * run the same checker against fake sources.
 */
function serverGraphDashboardOffenders(
  serverGraphFiles: ReadonlyArray<string>,
  read: (relativePath: string) => string | undefined,
): string[] {
  return serverGraphFiles.flatMap((file) =>
    valueImportSpecifiers(read(file) ?? "")
      .map((specifier) => resolveRelative(file, specifier))
      .filter((target) => target !== undefined && isUnboundedDashboardImport(target, read))
      .map((target) => `${file} -> ${target}`),
  );
}

/** Whether an import target under dashboard/ is outside the allowlist and has no confirmable "use client" boundary. */
function isUnboundedDashboardImport(
  target: string,
  read: (relativePath: string) => string | undefined,
): boolean {
  if (!target.startsWith("dashboard/") || SERVER_GRAPH_DASHBOARD_ALLOWLIST.has(target)) {
    return false;
  }
  return !hasUseClientDirective(read(target) ?? "");
}

describe("server-graph imports of src/dashboard stay behind a client boundary (RSC is the static shell only)", () => {
  const srcRoot = join(import.meta.dirname, "../../src");
  const read = (relativePath: string): string | undefined => {
    const filePath = join(srcRoot, relativePath);
    // An unresolvable import target is made an offender by the
    // checker as "no confirmable boundary"
    return existsSync(filePath) ? readFileSync(filePath, "utf8") : undefined;
  };
  const pageFiles = readdirSync(join(srcRoot, "pages"))
    .filter((name) => name.endsWith(".tsx"))
    .map((name) => `pages/${name}`);
  const serverGraphFiles = ["App.tsx", "Root.tsx", ...pageFiles].filter(
    (file) => !hasUseClientDirective(read(file) ?? ""),
  );

  it("finds the server-graph files and the dashboard imports they make (not vacuous)", () => {
    expect(serverGraphFiles).toEqual(expect.arrayContaining(["App.tsx", "Root.tsx"]));
    expect(pageFiles.length, "no pages/*.tsx found").toBeGreaterThan(0);
    const dashboardImports = serverGraphFiles.flatMap((file) =>
      valueImportSpecifiers(read(file) ?? "")
        .map((specifier) => resolveRelative(file, specifier))
        .filter((target) => target?.startsWith("dashboard/")),
    );
    expect(dashboardImports.length, "sweep pattern is stale").toBeGreaterThan(0);
  });

  it("imports only 'use client' dashboard modules or the allowlist from server-graph files", () => {
    expect(serverGraphDashboardOffenders(serverGraphFiles, read)).toEqual([]);
  });

  it("keeps the allowlisted routes.ts free of relative imports", () => {
    const routes = read("dashboard/routes.ts");
    expect(routes, "dashboard/routes.ts not found").toBeDefined();
    // Even a type-only relative import could be the entry of a
    // dependency via the allowlist, so it is banned
    expect(stripComments(routes ?? "")).not.toMatch(/\b(?:from|import)\s+["']\./);
  });

  it("flags a server-graph import of a dashboard module without 'use client' (self-test)", () => {
    const fake = new Map<string, string>([
      [
        "pages/Fake.tsx",
        [
          "// server component",
          'import { apiGet } from "../dashboard/api.ts";',
          'import { Screen } from "../dashboard/Screen.tsx";',
          'import { spaPaths } from "../dashboard/routes.ts";',
          'import type { Me } from "../dashboard/types.ts";',
          'export { helper } from "../dashboard/helper.ts";',
          'import { missing } from "../dashboard/missing.ts";',
          'import { Other } from "../components/Other.tsx";',
        ].join("\n"),
      ],
      ["dashboard/api.ts", "// fetch layer\nexport const apiGet = 1;"],
      ["dashboard/Screen.tsx", '// comment first\n"use client";\nexport const Screen = 1;'],
      ["dashboard/routes.ts", "export const spaPaths = 1;"],
      ["dashboard/types.ts", "export type Me = string;"],
      ["dashboard/helper.ts", "export const helper = 1;"],
    ]);
    expect(serverGraphDashboardOffenders(["pages/Fake.tsx"], (p) => fake.get(p))).toEqual([
      "pages/Fake.tsx -> dashboard/api.ts",
      "pages/Fake.tsx -> dashboard/helper.ts",
      "pages/Fake.tsx -> dashboard/missing.ts",
    ]);
    // The "use client" check: a directive-looking statement on a later
    // line is not a boundary
    expect(hasUseClientDirective('const x = 1;\n"use client";')).toBe(false);
    expect(hasUseClientDirective("'use client';\nexport {}")).toBe(true);
    // The routes.ts relative-import check also fails against fake
    // sources
    expect(stripComments('import { x } from "./api.ts";')).toMatch(/\b(?:from|import)\s+["']\./);
  });
});
