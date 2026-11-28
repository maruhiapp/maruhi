import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";

import { describe, expect, it } from "vite-plus/test";

const REPO_ROOT = join(import.meta.dirname, "../../..");
const BASELINE_PATH = join(import.meta.dirname, "comment-ratchet-baseline.json");

interface RawComment {
  readonly start: number;
  readonly end: number;
  readonly kind: "line" | "block" | "html";
}

const VALUE_END = new Set(["identifier", "number", "string", "template", "regex", ")", "]", "}"]);
const CLOSERS = new Set([")", "]", "}"]);
const REGEX_OK_KEYWORDS = new Set([
  "return",
  "typeof",
  "case",
  "in",
  "of",
  "new",
  "delete",
  "void",
  "yield",
  "await",
  "else",
  "do",
  "instanceof",
  "throw",
]);

function isIdStart(c: string): boolean {
  return /[A-Za-z_$]/.test(c);
}

function isIdChar(c: string): boolean {
  return /[A-Za-z0-9_$]/.test(c);
}

function skipQuoted(text: string, i: number): number {
  const q = text.charAt(i);
  const n = text.length;
  i++;
  while (i < n && text.charAt(i) !== q) {
    if (text.charAt(i) === "\\") i++;
    i++;
  }
  return Math.min(n, i + 1);
}

function skipLineComment(text: string, i: number, out: RawComment[]): number {
  const start = i;
  const n = text.length;
  while (i < n && text.charAt(i) !== "\n") i++;
  out.push({ start, end: i, kind: "line" });
  return i;
}

function skipBlockComment(text: string, i: number, out: RawComment[]): number {
  const start = i;
  const n = text.length;
  i += 2;
  while (i < n && !(text.charAt(i) === "*" && text.charAt(i + 1) === "/")) i++;
  i = Math.min(n, i + 2);
  out.push({ start, end: i, kind: "block" });
  return i;
}

interface RegexStep {
  readonly escape: boolean;
  readonly done: boolean;
  readonly inClass: boolean;
}

function regexStep(r: string, inClass: boolean): RegexStep {
  if (r === "\\") return { escape: true, done: false, inClass };
  if (r === "[") return { escape: false, done: false, inClass: true };
  if (r === "]") return { escape: false, done: false, inClass: false };
  if (r === "/" && !inClass) return { escape: false, done: true, inClass };
  if (r === "\n") return { escape: false, done: true, inClass };
  return { escape: false, done: false, inClass };
}

function skipRegexFlags(text: string, i: number): number {
  const n = text.length;
  while (i < n && /[a-z]/i.test(text.charAt(i))) i++;
  return i;
}

function skipRegex(text: string, i: number): number {
  const n = text.length;
  i++;
  let inClass = false;
  while (i < n) {
    const step = regexStep(text.charAt(i), inClass);
    if (step.escape) {
      i += 2;
      continue;
    }
    inClass = step.inClass;
    i++;
    if (step.done) break;
  }
  return skipRegexFlags(text, i);
}

function templateExprStep(text: string, i: number, out: RawComment[]): readonly [number, number] {
  const e = text.charAt(i);
  const f = text.charAt(i + 1);
  if (e === "/") {
    if (f === "/") return [skipLineComment(text, i, out), 0];
    if (f === "*") return [skipBlockComment(text, i, out), 0];
  }
  if (e === "'" || e === '"') return [skipQuoted(text, i), 0];
  if (e === "`") return [skipTemplate(text, i, out), 0];
  if (e === "{") return [i + 1, 1];
  if (e === "}") return [i + 1, -1];
  return [i + 1, 0];
}

function skipTemplateExpression(text: string, i: number, out: RawComment[]): number {
  const n = text.length;
  let depth = 1;
  while (i < n && depth > 0) {
    const [next, delta] = templateExprStep(text, i, out);
    i = next;
    depth += delta;
  }
  return i;
}

function skipTemplate(text: string, i: number, out: RawComment[]): number {
  const n = text.length;
  i++;
  while (i < n) {
    const t = text.charAt(i);
    if (t === "\\") {
      i += 2;
      continue;
    }
    if (t === "`") return i + 1;
    if (t === "$" && text.charAt(i + 1) === "{") {
      i = skipTemplateExpression(text, i + 2, out);
      continue;
    }
    i++;
  }
  return i;
}

function scanValueToken(
  text: string,
  i: number,
  out: RawComment[],
  last: string,
): readonly [number, string] | null {
  const c = text.charAt(i);
  if (c === "'" || c === '"') return [skipQuoted(text, i), "string"];
  if (c === "`") return [skipTemplate(text, i, out), "template"];
  if (c === "/" && !VALUE_END.has(last)) return [skipRegex(text, i), "regex"];
  return null;
}

function skipIdentifier(text: string, i: number): readonly [number, string] {
  const n = text.length;
  const start = i;
  while (i < n && isIdChar(text.charAt(i))) i++;
  const kind = REGEX_OK_KEYWORDS.has(text.slice(start, i)) ? "operator" : "identifier";
  return [i, kind];
}

function skipNumber(text: string, i: number): number {
  const n = text.length;
  while (i < n && /[0-9A-Za-z._]/.test(text.charAt(i))) i++;
  return i;
}

const WHITESPACE = new Set([" ", "\t", "\n", "\r", "\f", "\v"]);

function scanWordToken(text: string, i: number): readonly [number, string] | null {
  const c = text.charAt(i);
  if (isIdStart(c)) return skipIdentifier(text, i);
  if (/[0-9]/.test(c)) return [skipNumber(text, i), "number"];
  return null;
}

function scanCommentToken(text: string, i: number, out: RawComment[]): number | null {
  const c = text.charAt(i);
  const d = text.charAt(i + 1);
  if (c !== "/") return null;
  if (d === "/") return skipLineComment(text, i, out);
  if (d === "*") return skipBlockComment(text, i, out);
  return null;
}

function scanTsComments(text: string): RawComment[] {
  const out: RawComment[] = [];
  const n = text.length;
  let i = 0;
  let last = "start";
  while (i < n) {
    const c = text.charAt(i);
    if (WHITESPACE.has(c)) {
      i++;
      continue;
    }
    const comment = scanCommentToken(text, i, out);
    if (comment !== null) {
      i = comment;
      continue;
    }
    const value = scanValueToken(text, i, out, last);
    if (value !== null) {
      i = value[0];
      last = value[1];
      continue;
    }
    const word = scanWordToken(text, i);
    if (word !== null) {
      i = word[0];
      last = word[1];
      continue;
    }
    last = CLOSERS.has(c) ? c : "operator";
    i++;
  }
  return out;
}

function scanCssComments(text: string, segStart: number, segEnd: number): RawComment[] {
  const seg = text.slice(segStart, segEnd);
  const re = /\/\*[\s\S]*?\*\//g;
  const out: RawComment[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(seg)) !== null) {
    out.push({ start: segStart + m.index, end: segStart + m.index + m[0].length, kind: "block" });
  }
  return out;
}

function findHashStart(ln: string): number {
  for (let j = 0; j < ln.length; j++) {
    if (ln.charAt(j) !== "#") continue;
    const before = ln.slice(0, j);
    if (!(/^\s*$/.test(before) || /\s$/.test(before))) return -1;
    const dq = (before.match(/"/g) ?? []).length;
    const sq = (before.match(/'/g) ?? []).length;
    if (dq % 2 === 1 || sq % 2 === 1) return -1;
    return j;
  }
  return -1;
}

function scanHashComments(text: string): RawComment[] {
  const out: RawComment[] = [];
  const lines = text.split("\n");
  let offset = 0;
  for (let idx = 0; idx < lines.length; idx++) {
    const ln = lines[idx] ?? "";
    const lineStart = offset;
    offset += ln.length + 1;
    if (idx === 0 && ln.startsWith("#!")) continue;
    const j = findHashStart(ln);
    if (j >= 0) out.push({ start: lineStart + j, end: lineStart + ln.length, kind: "line" });
  }
  return out;
}

function offsetRaw(raw: RawComment[], by: number): RawComment[] {
  return raw.map((r) => ({ start: r.start + by, end: r.end + by, kind: r.kind }));
}

function scanAstroComments(text: string): RawComment[] {
  const out: RawComment[] = [];
  const spans: [number, number][] = [];
  let bodyStart = 0;
  if (text.startsWith("---")) {
    const close = text.indexOf("\n---", 3);
    if (close >= 0) {
      const fmEnd = close + 4;
      out.push(...scanTsComments(text.slice(0, fmEnd)));
      spans.push([0, fmEnd]);
      bodyStart = fmEnd;
    }
  }
  const scriptRe = /<script[\s\S]*?<\/script>/g;
  let m: RegExpExecArray | null;
  while ((m = scriptRe.exec(text)) !== null) {
    if (m.index < bodyStart) continue;
    const open = m[0].indexOf(">") + 1;
    const contentStart = m.index + open;
    const contentEnd = m.index + m[0].length - "</script>".length;
    out.push(...offsetRaw(scanTsComments(text.slice(contentStart, contentEnd)), contentStart));
    spans.push([m.index, m.index + m[0].length]);
  }
  const styleRe = /<style[\s\S]*?<\/style>/g;
  while ((m = styleRe.exec(text)) !== null) {
    const open = m[0].indexOf(">") + 1;
    out.push(...scanCssComments(text, m.index + open, m.index + m[0].length - "</style>".length));
    spans.push([m.index, m.index + m[0].length]);
  }
  const htmlRe = /<!--[\s\S]*?-->/g;
  while ((m = htmlRe.exec(text)) !== null) {
    const s = m.index;
    const e = m.index + m[0].length;
    if (spans.some(([a, b]) => s >= a && s < b)) continue;
    out.push({ start: s, end: e, kind: "html" });
  }
  return out;
}

function lineOffsets(text: string): number[] {
  const offs = [0];
  for (let i = 0; i < text.length; i++) {
    if (text.charAt(i) === "\n") offs.push(i + 1);
  }
  return offs;
}

function lineOf(offs: number[], pos: number): number {
  let lo = 0;
  let hi = offs.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if ((offs[mid] ?? 0) <= pos) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

function normalizeCommentLine(line: string): string {
  let s = line.trim();
  s = s.replace(/^<!--/, "").replace(/-->$/, "");
  if (s === "*/") return "";
  s = s.replace(/^(?:\/\/|\/\*\*?|\*|#)/, "");
  s = s.replace(/\*\/$/, "");
  return s.trim();
}

function normalizeCommentText(raw: string): string {
  const out: string[] = [];
  for (const line of raw.split("\n")) {
    const s = normalizeCommentLine(line);
    if (s !== "") out.push(s);
  }
  return out.join("\n");
}

const DIRECTIVE_PATTERNS = [
  "@ts-expect-error",
  "@ts-ignore",
  "@ts-nocheck",
  "english-exempt",
  "fallow-ignore",
  "oxlint-disable",
  "eslint-disable",
  "shellcheck disable=",
  "jactionlint ignore=",
  "@vite-ignore",
];

function lineLeadsWithDirective(line: string): boolean {
  for (const p of DIRECTIVE_PATTERNS) {
    if (!line.startsWith(p)) continue;
    const next = line.charAt(p.length);
    if (next === "" || next === " " || next === ":" || next === "-") return true;
    if (p.endsWith("=")) return true;
  }
  return false;
}

function hasDirectivePattern(normalized: string): boolean {
  return normalized.split("\n").some((ln) => lineLeadsWithDirective(ln));
}

const IMPORT_LINT_TAGS = ["@public", "@package", "@private", "@access"];

function hasImportLintTag(normalized: string): boolean {
  const lines = normalized.split("\n");
  for (const tag of IMPORT_LINT_TAGS) {
    if (lines.some((ln) => ln === tag || ln.startsWith(tag + " "))) return true;
  }
  return false;
}

function isCodegenBanner(normalized: string, startLine: number): boolean {
  const lower = normalized.toLowerCase();
  if (startLine <= 5 && (lower.includes("do not edit") || normalized.includes("@generated"))) {
    return true;
  }
  return startLine <= 10 && (lower.split("\n")[0] ?? "").includes("generated by");
}

function isLicenseHeader(normalized: string, startLine: number): boolean {
  return startLine <= 3 && (normalized.includes("SPDX") || normalized.includes("Copyright"));
}

function isFunctional(normalized: string, startLine: number): boolean {
  if (hasDirectivePattern(normalized)) return true;
  if (hasImportLintTag(normalized)) return true;
  if (isCodegenBanner(normalized, startLine)) return true;
  if (isLicenseHeader(normalized, startLine)) return true;
  const first = normalized.split("\n")[0] ?? "";
  if (first.startsWith("/ <reference")) return true;
  return /^v\d+\.\d+\.\d+([-+.][0-9A-Za-z.-]+)?$/.test(normalized);
}

interface ProseUnit {
  readonly normalized: string;
  readonly startLine: number;
}

function mergeRawComments(text: string, raw: RawComment[], offs: number[]): RawComment[] {
  const sorted = [...raw].sort((a, b) => a.start - b.start);
  const merged: RawComment[] = [];
  for (const r of sorted) {
    const prev = merged[merged.length - 1];
    if (prev && prev.kind === "line" && r.kind === "line") {
      const between = text.slice(prev.end, r.start);
      const prevEndLine = lineOf(offs, Math.max(prev.start, prev.end - 1));
      if (/^\s*$/.test(between) && lineOf(offs, r.start) === prevEndLine + 1) {
        merged[merged.length - 1] = { start: prev.start, end: r.end, kind: "line" };
        continue;
      }
    }
    merged.push(r);
  }
  return merged;
}

function proseUnits(text: string, raw: RawComment[]): ProseUnit[] {
  const offs = lineOffsets(text);
  const units: ProseUnit[] = [];
  for (const r of mergeRawComments(text, raw, offs)) {
    const startLine = lineOf(offs, r.start);
    const normalized = normalizeCommentText(text.slice(r.start, r.end));
    if (normalized === "") continue;
    if (isFunctional(normalized, startLine)) continue;
    units.push({ normalized, startLine });
  }
  return units;
}

const TS_EXTS = new Set(["ts", "tsx", "js", "jsx", "mjs", "cjs", "mts", "cts"]);
const HASH_EXTS = new Set(["toml", "yml", "yaml", "sh", "rb", "py"]);
const SCANNED_EXTS = new Set([...TS_EXTS, ...HASH_EXTS, "json", "jsonc", "astro", "css"]);

function rawCommentsFor(ext: string, text: string): RawComment[] {
  if (TS_EXTS.has(ext) || ext === "json" || ext === "jsonc") return scanTsComments(text);
  if (ext === "css") return scanCssComments(text, 0, text.length);
  if (ext === "astro") return scanAstroComments(text);
  if (HASH_EXTS.has(ext)) return scanHashComments(text);
  return [];
}

const SKIP_DIRS = new Set([
  "node_modules",
  "dist",
  ".git",
  ".astro",
  ".deepsec",
  ".agents",
  ".claude",
]);
const WALK_TOPS = ["apps", "packages", "scripts", "actions", "packaging", ".github"];
const ROOT_FILES = [
  "vite.config.ts",
  "vitest.config.ts",
  "alchemy.run.ts",
  "tsconfig.base.json",
  "bunfig.toml",
  ".importlintrc.jsonc",
  ".fallowrc.json",
  ".oxlintrc.json",
  ".oxlintrc.jsonc",
];

function collectFiles(): string[] {
  const files: string[] = [];
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      const st = statSync(p);
      if (st.isDirectory()) {
        if (!SKIP_DIRS.has(name)) walk(p);
        continue;
      }
      const ext = name.split(".").pop()?.toLowerCase() ?? "";
      if (SCANNED_EXTS.has(ext)) files.push(p);
    }
  };
  for (const top of WALK_TOPS) {
    const dir = join(REPO_ROOT, top);
    if (existsSync(dir)) walk(dir);
  }
  for (const f of ROOT_FILES) {
    const p = join(REPO_ROOT, f);
    if (existsSync(p)) files.push(p);
  }
  return files;
}

function scanTree(): Map<string, string[]> {
  const result = new Map<string, string[]>();
  for (const path of collectFiles()) {
    const rel = relative(REPO_ROOT, path).split("\\").join("/");
    const text = readFileSync(path, "utf8");
    const ext = rel.split(".").pop()?.toLowerCase() ?? "";
    const units = proseUnits(text, rawCommentsFor(ext, text));
    if (units.length > 0) {
      result.set(rel, units.map((u) => u.normalized).toSorted());
    }
  }
  return result;
}

function readBaseline(): Map<string, string[]> {
  const parsed: unknown = JSON.parse(readFileSync(BASELINE_PATH, "utf8"));
  const map = new Map<string, string[]>();
  if (typeof parsed === "object" && parsed !== null) {
    for (const [k, v] of Object.entries(parsed)) {
      if (Array.isArray(v))
        map.set(
          k,
          v.map((x) => String(x)),
        );
    }
  }
  return map;
}

function diffFile(file: string, actual: string[], expected: string[]): string[] {
  if (JSON.stringify(actual) === JSON.stringify(expected)) return [];
  const problems: string[] = [];
  const aSet = new Set(actual);
  const eSet = new Set(expected);
  for (const t of actual) {
    if (!eSet.has(t)) {
      problems.push(`${file}: new prose comment not in baseline: ${t.slice(0, 120)}`);
    }
  }
  for (const t of expected) {
    if (!aSet.has(t)) {
      problems.push(`${file}: baseline entry no longer present: ${t.slice(0, 120)}`);
    }
  }
  if (actual.length !== expected.length && aSet.size === eSet.size) {
    problems.push(`${file}: prose comment count changed (${expected.length} -> ${actual.length})`);
  }
  return problems;
}

function diffBaseline(actual: Map<string, string[]>, expected: Map<string, string[]>): string[] {
  const problems: string[] = [];
  const files = new Set([...actual.keys(), ...expected.keys()]);
  for (const f of [...files].toSorted()) {
    problems.push(...diffFile(f, actual.get(f) ?? [], expected.get(f) ?? []));
  }
  return problems;
}

describe("the comment ratchet (ADR-0020)", () => {
  it("finds the ADR pointers left in gate configuration", () => {
    const tree = scanTree();
    const vite = tree.get("vite.config.ts") ?? [];
    expect(vite).toContain("See ADR-0028.");
    const alchemy = tree.get("alchemy.run.ts") ?? [];
    expect(alchemy).toContain("See ADR-0026.");
  }, 120_000);

  it("matches the baseline of remaining prose comments", () => {
    const actual = scanTree();
    if (process.env.COMMENT_RATCHET_UPDATE === "1") {
      const obj: Record<string, string[]> = {};
      for (const [k, v] of [...actual.entries()].toSorted()) obj[k] = v;
      writeFileSync(BASELINE_PATH, JSON.stringify(obj, null, 2) + "\n");
      return;
    }
    const problems = diffBaseline(actual, readBaseline());
    expect(
      problems,
      "prose comments differ from packages/core/test/comment-ratchet-baseline.json; " +
        "remove the comment, move the decision into an ADR, or regenerate the baseline " +
        "through the /delete-comment process (COMMENT_RATCHET_UPDATE=1)",
    ).toEqual([]);
  }, 120_000);
});
