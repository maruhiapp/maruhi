import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vite-plus/test";

const REPO_ROOT = join(import.meta.dirname, "../../..");
const SOURCE_ROOTS = ["apps", "packages"];

const BRAND_ASSERTION =
  /\bas\s+(?:UserId|ProviderUserId|KeyFingerprintHex|OrgId|ProjectId|EnvironmentId|VariableId)\b/;

const BRAND_PREDICATE =
  /\w+\s+is\s+(?:UserId|ProviderUserId|KeyFingerprintHex|OrgId|ProjectId|EnvironmentId|VariableId)\b/;

const PREDICATE_ROOT = "packages/core/src/";

const ALLOWED = new Set(["packages/crypto/src/internal.package/chain-verify.ts"]);

const ALLOWED_COUNTS: Readonly<Record<string, number>> = {
  "packages/crypto/src/internal.package/chain-verify.ts": 5,
};

function walk(dir: string): string[] {
  return readdirSync(join(REPO_ROOT, dir), { withFileTypes: true }).flatMap((entry) => {
    const path = `${dir}/${entry.name}`;
    if (!entry.isDirectory()) {
      return [path];
    }
    return entry.name === "node_modules" || entry.name === "dist" || entry.name.startsWith(".")
      ? []
      : walk(path);
  });
}

function shippedSources(): readonly string[] {
  return SOURCE_ROOTS.flatMap(walk).filter(
    (path) => /\/src\//.test(path) && /\.(?:ts|tsx)$/.test(path),
  );
}

describe("identity brands are never asserted in shipped source", () => {
  it("finds the sources it scans", () => {
    const sources = shippedSources();
    expect(sources).toContain("packages/core/src/identity.ts");
    expect(sources).toContain("apps/server/src/audit-store.ts");
  });

  it("has no type assertion to a brand outside crypto's fingerprint computation", () => {
    const offenders = shippedSources().flatMap((path) => {
      if (ALLOWED.has(path)) {
        return [];
      }
      const text = readFileSync(join(REPO_ROOT, path), "utf8");
      return text
        .split("\n")
        .flatMap((line, index) =>
          BRAND_ASSERTION.test(line) ? [`${path}:${index + 1}: ${line.trim()}`] : [],
        );
    });
    expect(offenders).toEqual([]);
  });

  it("has no brand-returning type predicate outside the core guard declarations", () => {
    const offenders = shippedSources().flatMap((path) => {
      if (path.startsWith(PREDICATE_ROOT)) {
        return [];
      }
      const text = readFileSync(join(REPO_ROOT, path), "utf8");
      return text
        .split("\n")
        .flatMap((line, index) =>
          BRAND_PREDICATE.test(line) ? [`${path}:${index + 1}: ${line.trim()}`] : [],
        );
    });
    expect(offenders).toEqual([]);
  });

  it("keeps the sanctioned mints where the allowlist says, at the pinned count", () => {
    for (const path of ALLOWED) {
      const text = readFileSync(join(REPO_ROOT, path), "utf8");
      const count = text.split("\n").filter((line) => BRAND_ASSERTION.test(line)).length;
      expect(count, path).toBe(ALLOWED_COUNTS[path]);
    }
  });
});

interface LintConfig {
  readonly overrides: readonly {
    readonly files: readonly string[];
    readonly rules?: Readonly<Record<string, unknown>>;
  }[];
}

async function readLintConfig(): Promise<LintConfig> {
  const { default: config } = (await import("../../../vite.config.ts")) as {
    readonly default: { readonly lint: LintConfig };
  };
  return config.lint;
}

type RestrictedImportsRule = readonly [
  string,
  { readonly paths: readonly { name: string; importNames?: string[] }[] },
];

function restrictedMintNames(config: LintConfig): readonly string[] {
  const shipped = config.overrides.find((override) => {
    const rule = override.rules?.["no-restricted-imports"] as RestrictedImportsRule | undefined;
    return rule?.[1].paths.some((path) => path.name === "@maruhi/core") ?? false;
  });
  const rule = shipped?.rules?.["no-restricted-imports"] as RestrictedImportsRule | undefined;
  return rule?.[1].paths.find((path) => path.name === "@maruhi/core")?.importNames ?? [];
}

function mintSiteFiles(config: LintConfig): readonly string[] {
  const override = config.overrides.find((candidate) =>
    candidate.files.includes("packages/api-schema/src/**"),
  );
  return (override?.files ?? []).filter((file) => !file.includes("*"));
}

function coreValueImports(text: string): ReadonlySet<string> {
  const names = new Set<string>();
  for (const match of text.matchAll(/import\s+(type\s+)?\{([^}]*)\}\s+from\s+"@maruhi\/core"/g)) {
    if (match[1] !== undefined) {
      continue;
    }
    for (const specifier of (match[2] ?? "").split(",")) {
      const name = specifier.trim();
      if (name !== "" && !name.startsWith("type ")) {
        names.add(name);
      }
    }
  }
  return names;
}

describe("the mint-site allowlist in vite.config.ts", () => {
  it("reads the restricted mints and the mint-site files", async () => {
    const config = await readLintConfig();
    expect(restrictedMintNames(config)).toContain("decodeUserId");
    expect(mintSiteFiles(config)).toContain("apps/server/src/ids.ts");
  });

  it("lists only files that still import a mint (a stale entry widens the boundary silently)", async () => {
    const config = await readLintConfig();
    const mints = new Set(restrictedMintNames(config));
    const stale = mintSiteFiles(config).filter((file) => {
      const path = join(REPO_ROOT, file);
      return (
        !existsSync(path) ||
        ![...coreValueImports(readFileSync(path, "utf8"))].some((name) => mints.has(name))
      );
    });
    expect(stale).toEqual([]);
  });
});
