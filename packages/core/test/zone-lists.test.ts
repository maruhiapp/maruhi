import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vite-plus/test";

const REPO_ROOT = join(import.meta.dirname, "../../..");

interface Zone {
  readonly name: string;
  readonly patterns: readonly string[];
}

function zones(): readonly Zone[] {
  const text = readFileSync(join(REPO_ROOT, ".fallowrc.json"), "utf8")
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("//"))
    .join("\n");
  const config = JSON.parse(text) as { readonly boundaries: { readonly zones: readonly Zone[] } };
  return config.boundaries.zones;
}

function entriesOf(directory: string): readonly string[] {
  return existsSync(directory) ? readdirSync(directory) : [];
}

function segmentMatcher(segment: string): RegExp {
  const escaped = segment
    .split("*")
    .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
    .join("[^/]*");
  return new RegExp(`^${escaped}$`);
}

function matchesSomething(directory: string, segments: readonly string[]): boolean {
  const [segment, ...rest] = segments;
  if (segment === undefined) {
    return existsSync(directory);
  }
  if (segment === "**") {
    return entriesOf(directory).length > 0;
  }
  if (!segment.includes("*")) {
    return matchesSomething(join(directory, segment), rest);
  }
  const matcher = segmentMatcher(segment);
  return entriesOf(directory)
    .filter((entry) => matcher.test(entry))
    .some((entry) => matchesSomething(join(directory, entry), rest));
}

describe("the boundary zones in .fallowrc.json", () => {
  it("reads zones with patterns", () => {
    const all = zones();
    expect(all.length).toBeGreaterThan(10);
    expect(all.every((zone) => zone.patterns.length > 0)).toBe(true);
  });

  it("has no pattern that matches nothing", () => {
    const unmatched = zones().flatMap((zone) =>
      zone.patterns
        .filter((pattern) => !matchesSomething(REPO_ROOT, pattern.split("/")))
        .map((pattern) => `${zone.name}: ${pattern}`),
    );
    expect(unmatched).toEqual([]);
  });

  it("lists no pattern twice", () => {
    const seen = new Map<string, string>();
    const repeated: string[] = [];
    for (const zone of zones()) {
      for (const pattern of zone.patterns) {
        const first = seen.get(pattern);
        if (first === undefined) {
          seen.set(pattern, zone.name);
        } else {
          repeated.push(`${pattern}: ${first} and ${zone.name}`);
        }
      }
    }
    expect(repeated).toEqual([]);
  });

  it("flags a pattern without a file and accepts the glob forms in use", () => {
    expect(matchesSomething(REPO_ROOT, "apps/cli/src/no-such-file.ts".split("/"))).toBe(false);
    expect(matchesSomething(REPO_ROOT, "apps/cli/src/no-such-*.ts".split("/"))).toBe(false);
    expect(matchesSomething(REPO_ROOT, "apps/no-such-app/**".split("/"))).toBe(false);
    expect(matchesSomething(REPO_ROOT, "apps/cli/src/*.package/command.ts".split("/"))).toBe(true);
    expect(matchesSomething(REPO_ROOT, "apps/cli/src/commands/**".split("/"))).toBe(true);
  });
});
