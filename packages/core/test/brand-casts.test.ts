// Tripwire: the identity brands (identity.ts — UserId, ProviderUserId,
// KeyFingerprintHex) are minted only by the mints there and by crypto's own
// fingerprint computation. `.oxlintrc.json` gates who may import the mints;
// this pins the other way around them — a type assertion to a brand in
// shipped source. Tests mint their data through crypto's test-support
// (`testUserId` / `testKeyFingerprintHex`), which the lint rule keeps out of
// shipped source. The last block keeps the lint rule's mint-site allowlist
// honest: every listed file must still import a mint.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const REPO_ROOT = join(import.meta.dirname, "../../..");
const SOURCE_ROOTS = ["apps", "packages"];

/**
 * `as Brand` for each of the seven brands (the angle-bracket form is not used
 * in this codebase's TypeScript; `$type<UserId>()` on a Drizzle column is a
 * branded column, the sanctioned DB mint).
 */
const BRAND_ASSERTION =
  /\bas\s+(?:UserId|ProviderUserId|KeyFingerprintHex|OrgId|ProjectId|EnvironmentId|VariableId)\b/;

/**
 * A hand-written type predicate returning a brand (`x is Brand`) is a mint
 * with no boundary: any caller's string becomes branded by `if` alone. Such
 * predicates live only in packages/core/src, as module-private functions
 * that feed the Schema.refine mints (identity.ts's isUserId and the narrows*).
 */
const BRAND_PREDICATE =
  /\w+\s+is\s+(?:UserId|ProviderUserId|KeyFingerprintHex|OrgId|ProjectId|EnvironmentId|VariableId)\b/;

const PREDICATE_ROOT = "packages/core/src/";

/**
 * The one sanctioned mint file: the chain verifier's own mints in crypto —
 * the fingerprint computation (`encodeHex` over 16 digest bytes) and
 * sealChainState's map-key mints (keys out of verified entry slots). The
 * count is pinned so a sixth cast here fails loudly.
 */
const ALLOWED = new Set(["packages/crypto/src/internal.package/chain-verify.ts"]);

/** The expected number of `as Brand` assertions inside each ALLOWED file. */
const ALLOWED_COUNTS: Readonly<Record<string, number>> = {
  "packages/crypto/src/internal.package/chain-verify.ts": 5,
};

function shippedSources(): readonly string[] {
  return SOURCE_ROOTS.flatMap((root) =>
    readdirSync(join(REPO_ROOT, root), { recursive: true, encoding: "utf8" })
      .map((path) => `${root}/${path}`)
      .filter(
        (path) =>
          /\/src\//.test(path) &&
          /\.(?:ts|tsx)$/.test(path) &&
          !path.includes("node_modules") &&
          !path.includes("/dist/"),
      ),
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

/** `.oxlintrc.json` is JSONC; its comments are whole lines, so dropping them leaves plain JSON. */
function readOxlintConfig(): {
  readonly overrides: readonly {
    readonly files: readonly string[];
    readonly rules?: Readonly<Record<string, unknown>>;
  }[];
  readonly rules: Readonly<Record<string, unknown>>;
} {
  const text = readFileSync(join(REPO_ROOT, ".oxlintrc.json"), "utf8");
  return JSON.parse(
    text
      .split("\n")
      .filter((line) => !line.trimStart().startsWith("//"))
      .join("\n"),
  );
}

/** The `@maruhi/core` names the shipped-source rule restricts (the mints). */
function restrictedMintNames(config: ReturnType<typeof readOxlintConfig>): readonly string[] {
  const shipped = config.overrides.find((override) => override.files.includes("apps/*/src/**"));
  const rule = shipped?.rules?.["no-restricted-imports"] as
    | readonly [string, { readonly paths: readonly { name: string; importNames?: string[] }[] }]
    | undefined;
  return rule?.[1].paths.find((path) => path.name === "@maruhi/core")?.importNames ?? [];
}

/** The concrete files of the mint-site override (the one that lifts the mint restriction). */
function mintSiteFiles(config: ReturnType<typeof readOxlintConfig>): readonly string[] {
  const override = config.overrides.find((candidate) =>
    candidate.files.includes("packages/api-schema/src/**"),
  );
  return (override?.files ?? []).filter((file) => !file.includes("*"));
}

/** The value (non-`type`) names a file imports from `@maruhi/core`. */
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

describe("the mint-site allowlist in .oxlintrc.json", () => {
  it("reads the restricted mints and the mint-site files", () => {
    const config = readOxlintConfig();
    expect(restrictedMintNames(config)).toContain("decodeUserId");
    expect(mintSiteFiles(config)).toContain("apps/server/src/ids.ts");
  });

  it("lists only files that still import a mint (a stale entry widens the boundary silently)", () => {
    const config = readOxlintConfig();
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
