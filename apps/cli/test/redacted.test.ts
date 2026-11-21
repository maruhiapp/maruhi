import { readdir, readFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vite-plus/test";

const SRC_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "src");

const EXPECTED_UNWRAP_SITES: Readonly<Record<string, number>> = {
  "ci-lease.ts": 1,
  "ci-rotate.ts": 5,
  "rotation-proposals.ts": 1,
  "dek-wrap.ts": 1,
  "display.ts": 2,
  "env-create.ts": 1,
  "env-file.ts": 1,
  "env-rotate.ts": 1,
  "invite.ts": 2,
  "invite-link.ts": 2,
  "keychain.ts": 3,
  "login.ts": 1,
  "oidc-github.ts": 2,
  "pull.ts": 1,
  "push.ts": 3,
  "recovery-code.ts": 1,
  "schema-import.ts": 1,
  "recovery.ts": 5,
  "live.ts": 1,
  "run.ts": 3,
  "proxy-run.ts": 3,
  "session.ts": 2,
  "sync-exec.ts": 3,
  "sync-http.ts": 1,
  "sync-plan.ts": 3,
  "sync-receipt.ts": 1,
  "var-rotate.ts": 8,
};

const SPELLING_PATTERN = /Redacted\s*\.\s*value/g;
const LINE_COMMENT = "//";
const BLOCK_OPEN = "/*";
const BLOCK_CLOSE = "*/";

function scanComments(source: string, mask: boolean[]): void {
  let index = 0;
  let inBlock = false;
  let inLine = false;
  while (index < source.length) {
    const pair = source.slice(index, index + 2);
    if (inBlock) {
      mask[index] = true;
      if (pair === BLOCK_CLOSE) {
        mask[index + 1] = true;
        index += 2;
        inBlock = false;
        continue;
      }
    } else if (inLine) {
      if (source[index] === "\n") {
        inLine = false;
        index += 1;
        continue;
      }
      mask[index] = true;
    } else if (pair === BLOCK_OPEN || pair === LINE_COMMENT) {
      mask[index] = true;
      mask[index + 1] = true;
      inBlock = pair === BLOCK_OPEN;
      inLine = pair === LINE_COMMENT;
      index += 2;
      continue;
    }
    index += 1;
  }
}

function commentMask(source: string): readonly boolean[] {
  const mask = Array.from({ length: source.length }, () => false);
  scanComments(source, mask);
  return mask;
}

function lineAt(source: string, index: number): number {
  return source.slice(0, index).split("\n").length;
}

function commentMentions(source: string): readonly number[] {
  const mask = commentMask(source);
  const lines: number[] = [];
  for (const match of source.matchAll(SPELLING_PATTERN)) {
    if (mask[match.index] === true) {
      lines.push(lineAt(source, match.index));
    }
  }
  return lines;
}

async function srcFiles(): Promise<readonly string[]> {
  const entries = await readdir(SRC_DIR, { recursive: true });
  return entries.filter((name) => name.endsWith(".ts")).toSorted();
}

async function collectUnwrapSites(): Promise<Record<string, number>> {
  const files = await srcFiles();
  const counts: Record<string, number> = {};
  const collisions = new Map<string, string[]>();
  for (const name of files) {
    const source = await readFile(join(SRC_DIR, name), "utf8");
    const matches = source.match(SPELLING_PATTERN);
    if (matches !== null) {
      const rel = name.replaceAll("\\", "/");
      const base = basename(rel);
      const collided = collisions.get(base) ?? [];
      collisions.set(base, [...collided, rel]);
      counts[base] = matches.length;
    }
  }
  const duplicates = [...collisions].filter(([, rels]) => rels.length > 1);
  if (duplicates.length > 0) {
    throw new Error(
      `unwrap sites exist under a shared basename — the ledger key would collide: ${duplicates
        .map(([base, rels]) => `${base} (${rels.join(", ")})`)
        .join("; ")}`,
    );
  }
  return counts;
}

describe("the inventory of sites that unwrap Redacted", () => {
  it("the unwrap sites have not grown (to grow them, update EXPECTED_UNWRAP_SITES)", async () => {
    expect(await collectUnwrapSites()).toEqual(EXPECTED_UNWRAP_SITES);
  });

  it("the spelling always appears in code (no mentions inside comments allowed)", async () => {
    const offenders: string[] = [];
    for (const name of await srcFiles()) {
      const source = await readFile(join(SRC_DIR, name), "utf8");
      offenders.push(...commentMentions(source).map((line) => `${name}:${line}`));
    }
    expect(
      offenders,
      "either a comment mentions the spelling, or real unwrap code follows a comment marker inside a string literal — if the latter, split the line",
    ).toEqual([]);
  });

  it("Redacted is never carried out under an alias · a deep import · destructuring (shapes that slip past the match)", async () => {
    const offenders: string[] = [];
    for (const name of await srcFiles()) {
      const source = await readFile(join(SRC_DIR, name), "utf8");
      if (/\bRedacted\s+as\s+\w+/.test(source)) {
        offenders.push(`${name}(aliased import)`);
      }
      if (/from\s+"effect\/Redacted"/.test(source)) {
        offenders.push(`${name}(deep import of effect/Redacted)`);
      }
      if (/(?:const|let|var)\s+\w+\s*=\s*Redacted\s*[;\n]/.test(source)) {
        offenders.push(`${name}(local alias)`);
      }
      if (/\{[^}]*\bvalue\b[^}]*\}\s*=\s*Redacted\b/.test(source)) {
        offenders.push(`${name}(destructuring)`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("the token is never unwrapped to ride Bearer (it uses the upstream bearerToken)", async () => {
    const source = await readFile(join(SRC_DIR, "api.ts"), "utf8");
    expect(source).not.toContain("Redacted.value");
    expect(source).not.toMatch(/Bearer \$\{/);
  });
});
