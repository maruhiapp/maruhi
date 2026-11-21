import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, sep } from "node:path";

import { isSessionAllowedEndpoint, maruhiApi, UNAUTHENTICATED_ENDPOINTS } from "@maruhi/api-schema";
import { describe, expect, it } from "vite-plus/test";

import {
  apiPaths,
  DASHBOARD_ENDPOINTS,
  SAMPLE_ENVIRONMENT_ID,
  SAMPLE_INVITE_ID,
  SAMPLE_PROJECT_ID,
  SAMPLE_TOKEN_ID,
} from "../../src/dashboard/endpoints.ts";

interface RegisteredEndpoint {
  readonly path: string;
  readonly query?: {
    readonly ast?: {
      readonly propertySignatures?: ReadonlyArray<{ readonly name: PropertyKey }>;
    };
  };
}

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
    for (const { group, endpoint, cursor } of DASHBOARD_ENDPOINTS) {
      if (cursor === undefined) continue;
      expect(
        queryKeys(requireEndpoint(group, endpoint)),
        `${group}.${endpoint} does not declare a "${cursor}" query parameter in api-schema`,
      ).toContain(cursor);
    }
  });

  it("appends the declared cursor name from inside the paged builders (ruling CB)", () => {
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

  it("keeps effect / @effect / api-schema / core imports type-only in bundle sources (rulings BR/CD)", () => {
    const srcRoot = join(import.meta.dirname, "../../src");
    const specifier = String.raw`["'](?:effect|@effect\/[^"'/]+|@maruhi\/(?:api-schema|core))(?:\/[^"']*)?["']`;
    expect(
      findSourceOffenders(
        srcRoot,
        new RegExp(
          String.raw`^(?:import|export)\s+(?!type\b)[^;]*?from\s*${specifier}|\b(?:import\s*\(?|require\s*\()\s*${specifier}`,
          "m",
        ),
        new Set(),
      ),
      "value import of effect / @effect/* / @maruhi/api-schema / @maruhi/core in bundle source — use `import type` (ruling BR)",
    ).toEqual([]);
  });

  it("keeps @maruhi/crypto out of bundle sources entirely (ADR-0018)", () => {
    const srcRoot = join(import.meta.dirname, "../../src");
    expect(
      findSourceOffenders(srcRoot, /["']@maruhi\/crypto(?:\/[^"']*)?["']/, new Set()),
      "@maruhi/crypto referenced in bundle source — the web ships no crypto (ADR-0018)",
    ).toEqual([]);
  });

  it("keeps route() declarations inside the SPA route catalog (rulings BZ/CA)", () => {
    const srcRoot = join(import.meta.dirname, "../../src");
    expect(
      findSourceOffenders(srcRoot, /\broute\(/, new Set([join(srcRoot, BUILDER_SPA_MODULE)])),
      "route() declared outside src/dashboard/routes.ts — add it to the SPA_ROUTES catalog instead",
    ).toEqual([]);
  });
});

const BUILDER_API_MODULE = "dashboard/endpoints.ts";
const BUILDER_SPA_MODULE = "dashboard/routes.ts";

function requireEndpoint(group: string, endpoint: string): RegisteredEndpoint {
  const registered = api.groups[group]?.endpoints[endpoint];
  if (registered === undefined) throw new Error(`${group}.${endpoint} is not registered`);
  return registered;
}

function queryKeys(registered: RegisteredEndpoint): PropertyKey[] {
  return (registered.query?.ast?.propertySignatures ?? []).map((p) => p.name);
}

function isSweepTarget(
  entry: { isFile(): boolean; name: string },
  filePath: string,
  excluded: ReadonlySet<string>,
): boolean {
  return entry.isFile() && /\.[cm]?[jt]sx?$/.test(entry.name) && !excluded.has(filePath);
}

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

const TYPES_MODULE = "dashboard/types.ts";

function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^[ \t]*\/\/.*$/gm, "");
}

function typeArgumentAt(source: string, start: number): string {
  let depth = 1;
  for (const bracket of source.slice(start).matchAll(/[<>]/g)) {
    depth += bracket[0] === "<" ? 1 : -1;
    if (depth === 0) return source.slice(start, start + bracket.index).trim();
  }
  throw new Error("unterminated type argument list");
}

function firstTypeArgument(typeArguments: string): string {
  let flat = typeArguments;
  for (let before = ""; flat !== before;) {
    before = flat;
    flat = flat.replace(/<[^<>]*>|\{[^{}]*\}|\([^()]*\)|\[[^[\]]*\]/g, (group) =>
      "_".repeat(group.length),
    );
  }
  const comma = flat.indexOf(",");
  return comma === -1 ? typeArguments : typeArguments.slice(0, comma).trim();
}

const ENVELOPE_ENTRANCES = [
  "apiGet",
  "useApiResource",
  "useRevocableList",
  "RevocableList",
  "ApiResult",
  "ResourceState",
  "RevocableListState",
] as const;

describe("dashboard envelope types are derived from api-schema (DK K8)", () => {
  const srcRoot = join(import.meta.dirname, "../../src");
  const typesSource = stripComments(readFileSync(join(srcRoot, TYPES_MODULE), "utf8"));
  const exportedNames = [...typesSource.matchAll(/^export type (\w+)\b/gm)].map((m) => m[1]);

  it("keeps types.ts to `typeof XxxSchema.Type` derivations only (no interface, no literal)", () => {
    expect(typesSource.match(/^(?:export )?interface\s/gm), "hand-written interface").toBeNull();
    const derived = typesSource.match(/^export type \w+\s*=\s*typeof \w+Schema\.Type;/gm) ?? [];
    expect(exportedNames.length, "types.ts must export at least one type").toBeGreaterThan(0);
    expect(derived.length, "every exported type must be `typeof XxxSchema.Type`").toBe(
      exportedNames.length,
    );
  });

  it("names a types.ts export at every consumption site (no inline envelope in screens)", () => {
    const known = new Set(exportedNames);
    const passThrough = new Map<string, ReadonlySet<string>>([
      [join(srcRoot, "dashboard/api.ts"), new Set(["T", "void"])],
      [join(srcRoot, "dashboard/use-api-resource.ts"), new Set(["T"])],
      [join(srcRoot, "dashboard/revocable-list.tsx"), new Set(["T"])],
    ]);
    const outOfScope = new Set([join(srcRoot, TYPES_MODULE)]);
    const entrance = new RegExp(String.raw`\b(${ENVELOPE_ENTRANCES.join("|")})<`, "g");
    const sites: Array<{ file: string; entrance: string; typeArg: string }> = [];
    for (const entry of readdirSync(srcRoot, { recursive: true, withFileTypes: true })) {
      const filePath = join(entry.parentPath, entry.name);
      if (!isSweepTarget(entry, filePath, outOfScope)) continue;
      const source = stripComments(readFileSync(filePath, "utf8"));
      for (const match of source.matchAll(entrance)) {
        const typeArgs = typeArgumentAt(source, match.index + match[0].length);
        sites.push({
          file: filePath.slice(srcRoot.length + 1),
          entrance: match[1] ?? "",
          typeArg: match[1] === "RevocableList" ? firstTypeArgument(typeArgs) : typeArgs,
        });
      }
    }
    expect(
      ENVELOPE_ENTRANCES.filter((name) => !sites.some((site) => site.entrance === name)),
      "entrance with no site — the sweep pattern is stale",
    ).toEqual([]);
    expect(
      sites.filter((site) => !passThrough.has(join(srcRoot, site.file))).length,
      "no consumption site outside the declaring modules",
    ).toBeGreaterThan(0);
    const offenders = sites.filter(
      (site) =>
        !known.has(site.typeArg) &&
        passThrough.get(join(srcRoot, site.file))?.has(site.typeArg) !== true,
    );
    expect(
      offenders,
      "consumption site whose type argument is not a types.ts export — derive it there",
    ).toEqual([]);
  });
});

const SERVER_GRAPH_DASHBOARD_ALLOWLIST: ReadonlySet<string> = new Set(["dashboard/routes.ts"]);

function hasUseClientDirective(source: string): boolean {
  return /^\s*(["'])use client\1/.test(stripComments(source));
}

function valueImportSpecifiers(source: string): string[] {
  const stripped = stripComments(source);
  return [
    ...stripped.matchAll(/\b(?:import|export)\s+(type\s+)?(?:[^'";]*?\bfrom\s+)?(["'])([^"']+)\2/g),
  ]
    .filter((match) => match[1] === undefined)
    .map((match) => match[3] ?? "");
}

function resolveRelative(fromFile: string, specifier: string): string | undefined {
  if (!specifier.startsWith(".")) return undefined;
  return join(dirname(fromFile), specifier).split(sep).join("/");
}

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
    expect(hasUseClientDirective('const x = 1;\n"use client";')).toBe(false);
    expect(hasUseClientDirective("'use client';\nexport {}")).toBe(true);
    expect(stripComments('import { x } from "./api.ts";')).toMatch(/\b(?:from|import)\s+["']\./);
  });
});
