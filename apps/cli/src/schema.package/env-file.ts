import type { MetaVarType } from "@maruhi/crypto";
import { Redacted } from "effect";

const ENV_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;

export const MAX_NAME_LENGTH = 256;

export type EnvFileSkipReason = "not-an-assignment" | "invalid-name" | "duplicate-name";

export interface EnvFileSkippedLine {
  readonly line: number;
  readonly reason: EnvFileSkipReason;
  readonly name?: string;
}

export interface EnvFileEntry {
  readonly name: string;
  readonly line: number;
  readonly value: Redacted.Redacted<string>;
  readonly valueFaithful: boolean;
  readonly descriptionCandidate: string;
}

export interface ParsedEnvFile {
  readonly entries: readonly EnvFileEntry[];
  readonly skipped: readonly EnvFileSkippedLine[];
}

interface ParsedValue {
  readonly text: string;
  readonly faithful: boolean;
}

function parseValue(raw: string): ParsedValue {
  const first = raw[0];
  if (first === '"' || first === "'") {
    if (raw.length >= 2 && raw.endsWith(first)) {
      const inner = raw.slice(1, -1);
      return { text: inner, faithful: !inner.includes("\\") && !inner.includes(first) };
    }
    return { text: raw, faithful: false };
  }
  return { text: raw.replace(/\s+#.*$/, "").trim(), faithful: true };
}

export function parseEnvFile(content: string): ParsedEnvFile {
  const entries: EnvFileEntry[] = [];
  const skipped: EnvFileSkippedLine[] = [];
  const seen = new Set<string>();
  let comments: string[] = [];
  const lines = content.split(/\r?\n/);
  for (const [index, rawLine] of lines.entries()) {
    const lineNumber = index + 1;
    const line = rawLine.trim();
    if (line === "") {
      comments = [];
      continue;
    }
    if (line.startsWith("#")) {
      comments.push(line.replace(/^#+\s?/, ""));
      continue;
    }
    const assignment = line.startsWith("export ") ? line.slice("export ".length).trim() : line;
    const separator = assignment.indexOf("=");
    if (separator < 0) {
      skipped.push({ line: lineNumber, reason: "not-an-assignment" });
      comments = [];
      continue;
    }
    const name = assignment.slice(0, separator).trim().normalize("NFC");
    if (!ENV_NAME_PATTERN.test(name) || name.length > MAX_NAME_LENGTH) {
      skipped.push({ line: lineNumber, reason: "invalid-name" });
      comments = [];
      continue;
    }
    if (seen.has(name)) {
      skipped.push({ line: lineNumber, reason: "duplicate-name", name });
      comments = [];
      continue;
    }
    seen.add(name);
    const parsedValue = parseValue(assignment.slice(separator + 1).trim());
    entries.push({
      name,
      line: lineNumber,
      value: Redacted.make(parsedValue.text, { label: "env-file-value" }),
      valueFaithful: parsedValue.faithful,
      descriptionCandidate: comments.join(" ").trim(),
    });
    comments = [];
  }
  return { entries, skipped };
}

const NUMBER_TEXT = /^-?(?:\d+)(?:\.\d+)?(?:[eE][+-]?\d+)?$/;

const PLACEHOLDER_PATTERNS = [
  /^<[^>]*>$/,
  /^\$\{[^}]*\}$/,
  /^(changeme|change-me|change_me|todo|tbd|placeholder|dummy|sample|xxx+|\.{3})$/i,
  /^your[-_]/i,
];

export interface ObservedValue {
  readonly varType: MetaVarType;
  readonly looksReal: boolean;
}

export function observeValue(value: Redacted.Redacted<string>): ObservedValue {
  const text = Redacted.value(value).trim();
  if (text === "") {
    return { varType: "", looksReal: false };
  }
  const looksReal = !PLACEHOLDER_PATTERNS.some((pattern) => pattern.test(text));
  if (text === "true" || text === "false") {
    return { varType: "boolean", looksReal };
  }
  if (NUMBER_TEXT.test(text)) {
    return { varType: "number", looksReal };
  }
  if (/^https?:\/\/\S+$/.test(text) && URL.canParse(text)) {
    return { varType: "url", looksReal };
  }
  return { varType: "", looksReal };
}
