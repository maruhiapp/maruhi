// Vector-delta review aid for packages/crypto (CI step 7d, pull requests).
//
// Compares packages/crypto between the merge-base and the PR head and
// writes a Markdown report: how every test-vector entry moved (unchanged /
// removed / added / changed, and for a changed one whether its expected
// outcome changed), which domain-separation strings, chain ops and
// SUPPORTED_* constants changed, and a conservative risk class R0–R3. The
// classes and how to read the report are in ../README.md ("Reviewing a
// crypto change").
//
// It is an aid for a human reviewer and never approves anything: the class
// only says how much reading a change deserves, and every fact behind it is
// printed so a wrong class is visible. Whenever a rule cannot tell, it picks
// the higher class.
//
// Usage (in this directory):
//   bun run delta -- --base <rev> [--head <rev>]
// The report goes to stdout (CI appends it to $GITHUB_STEP_SUMMARY). Exit 0
// unless the tool itself fails.

import { execFileSync, spawnSync } from "node:child_process";

// ---------------------------------------------------------------------------
// Source canonicalization (TS / JS)
//
// R0 needs "only comments or formatting changed". Two independent checks
// must both agree: the comment-free token text below, and the transpiled
// runtime form (Bun.Transpiler, injected by the CLI). A lexer mistake here
// can then only hide a type-level edit, never a runtime one.

const IDENT_CHAR = /[\w$]/;
// After one of these, a `/` starts a regular expression, not a division
const REGEX_AFTER_CHAR = "(,=:[!&|?{};+-*%<>~^";
const REGEX_AFTER_WORD =
  /\b(?:return|typeof|case|do|else|in|of|new|delete|void|throw|instanceof|yield|await)$/;

/** Index just past the quoted string starting at `start`. */
function skipQuoted(src, start) {
  const quote = src[start];
  let i = start + 1;
  while (i < src.length && src[i] !== quote && src[i] !== "\n") {
    i += src[i] === "\\" ? 2 : 1;
  }
  return i + 1;
}

/** Index just past the template literal starting at `start` (handles `${…}` nesting). */
function skipTemplate(src, start) {
  let i = start + 1;
  while (i < src.length) {
    if (src[i] === "\\") {
      i += 2;
    } else if (src[i] === "`") {
      return i + 1;
    } else if (src[i] === "$" && src[i + 1] === "{") {
      let depth = 1;
      i += 2;
      while (i < src.length && depth > 0) {
        const c = src[i];
        if (c === "'" || c === '"') i = skipQuoted(src, i);
        else if (c === "`") i = skipTemplate(src, i);
        else {
          if (c === "{") depth += 1;
          if (c === "}") depth -= 1;
          i += 1;
        }
      }
    } else {
      i += 1;
    }
  }
  return i;
}

/** Index just past the regular expression literal starting at `start`. */
function skipRegex(src, start) {
  let i = start + 1;
  let inClass = false;
  while (i < src.length && src[i] !== "\n") {
    const c = src[i];
    if (c === "\\") i += 1;
    else if (c === "[") inClass = true;
    else if (c === "]") inClass = false;
    else if (c === "/" && !inClass) break;
    i += 1;
  }
  i += 1;
  while (i < src.length && /[a-z]/.test(src[i])) i += 1;
  return i;
}

/**
 * Splits TS / JS source into tokens with comments and whitespace removed:
 * `str` (quoted string, raw), `tpl` (template literal, raw), `re` (regex
 * literal) and `code` (any other run of non-blank characters).
 */
export function scanTokens(src) {
  const tokens = [];
  let code = "";
  let last = ""; // the last significant text, for the regex-or-division call
  const flush = () => {
    if (code !== "") tokens.push({ t: "code", v: code });
    if (code !== "") last = code;
    code = "";
  };
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    const next = src[i + 1];
    if (/\s/.test(c)) {
      flush();
      i += 1;
    } else if (c === "/" && next === "/") {
      flush();
      while (i < src.length && src[i] !== "\n") i += 1;
    } else if (c === "/" && next === "*") {
      flush();
      const end = src.indexOf("*/", i + 2);
      i = end === -1 ? src.length : end + 2;
    } else if (c === "'" || c === '"' || c === "`" || c === "/") {
      const prev = code !== "" ? code : last;
      const isRegex =
        c === "/" &&
        (prev === "" || REGEX_AFTER_CHAR.includes(prev.at(-1)) || REGEX_AFTER_WORD.test(prev));
      if (c === "/" && !isRegex) {
        code += c;
        i += 1;
        continue;
      }
      flush();
      const end =
        c === "`" ? skipTemplate(src, i) : c === "/" ? skipRegex(src, i) : skipQuoted(src, i);
      const t = c === "`" ? "tpl" : c === "/" ? "re" : "str";
      tokens.push({ t, v: src.slice(i, end) });
      last = src.slice(i, end);
      i = end;
    } else {
      code += c;
      i += 1;
    }
  }
  flush();
  return tokens;
}

/**
 * Comment- and formatting-free text of a source: tokens joined, with one
 * space kept only where two identifier characters would otherwise merge.
 */
export function canonicalSource(src) {
  let out = "";
  for (const { v } of scanTokens(src)) {
    if (out !== "" && IDENT_CHAR.test(out.at(-1)) && IDENT_CHAR.test(v[0])) out += " ";
    out += v;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Facts extracted from packages/crypto/src

const SUITE_LITERAL = /^maruhi\/v\d+$/;
const DOMAIN_LITERAL = /^maruhi\/v\d+\/[a-z0-9][a-z0-9/-]*$/;
// WebCrypto algorithm names a primitive change would introduce
const ALGORITHM_LITERAL =
  /^(?:AES-[A-Z]+|HKDF|PBKDF2|HMAC|ECDSA|ECDH|Ed25519|Ed448|X25519|X448|RSA[\w-]*|SHA-\d+)$/;

/** `maruhi/v1/dek-wrap` → `<suite>/dek-wrap` (the suite is tracked separately). */
function normalizeDomain(domain) {
  return domain.replace(/^maruhi\/v\d+\//, "<suite>/");
}

/**
 * Domain strings, suites, primitives, string `case` labels and SUPPORTED_*
 * constants in one source file. A template like
 * `${context.suite}/var-meta-sig-v${layout}` yields the pattern
 * `<suite>/var-meta-sig-v*`.
 *
 * A string `case` label is a member of a closed set the crypto code
 * dispatches on. The one such switch is the chain payload canonicalization
 * (§6.1): its labels are the chain ops, the domain separation of a chain
 * entry (its signed bytes begin with the bare suite, so no domain string
 * shows it), and tsc keeps that switch exhaustive. Any new label counts.
 */
export function sourceFacts(src) {
  const tokens = scanTokens(src);
  const canonical = canonicalSource(src);
  const domains = new Set();
  const suites = new Set();
  const primitives = new Set();
  const caseLabels = new Set();
  for (const [i, { t, v }] of tokens.entries()) {
    if (t === "str") {
      const text = v.slice(1, -1);
      if (DOMAIN_LITERAL.test(text)) domains.add(normalizeDomain(text));
      if (SUITE_LITERAL.test(text)) suites.add(text);
      if (ALGORITHM_LITERAL.test(text)) primitives.add(`algorithm ${text}`);
      const before = tokens[i - 1];
      const after = tokens[i + 1];
      if (
        before?.t === "code" &&
        /(?:^|[^\w$])case$/.test(before.v) &&
        after?.t === "code" &&
        after.v.startsWith(":")
      ) {
        caseLabels.add(text);
      }
    } else if (t === "tpl") {
      const m = /^`\$\{[^}]*\}\/([a-z0-9][a-z0-9/-]*)(\$\{)?/.exec(v);
      if (m !== null) domains.add(`<suite>/${m[1]}${m[2] === undefined ? "" : "*"}`);
    }
  }
  for (const m of canonical.matchAll(/\bsubtle\.(\w+)/g)) primitives.add(`subtle.${m[1]}`);
  for (const m of canonical.matchAll(/(?:\bfrom|\bimport\(?)(["'])([^"'.][^"']*)\1/g)) {
    primitives.add(`module ${m[2]}`);
  }
  // Named and namespace bindings taken from external modules (hpke's suite
  // constants are how a new KEM / KDF / AEAD would arrive)
  for (const m of canonical.matchAll(/\bimport(?: type)?\{([^}]*)\}from(["'])([^"'.][^"']*)\2/g)) {
    for (const part of m[1].split(",")) {
      const name = part
        .replace(/^type /, "")
        .split(" as ")[0]
        .trim();
      if (name !== "") primitives.add(`${m[3]}:${name}`);
    }
  }
  for (const m of canonical.matchAll(/\bimport\*as (\w+) from(["'])([^"'.][^"']*)\2/g)) {
    for (const use of canonical.matchAll(new RegExp(`\\b${m[1]}\\.(\\w+)`, "g"))) {
      primitives.add(`${m[3]}:${use[1]}`);
    }
  }
  const supported = new Map();
  for (const m of canonical.matchAll(/\bconst (SUPPORTED_[A-Z0-9_]+)(?::[^=]*)?=([^;]*)/g)) {
    const literal = /^\[([^\]]*)\]$/.exec(m[2]);
    supported.set(
      m[1],
      literal === null
        ? { parsed: false, raw: m[2] }
        : { parsed: true, values: literal[1].split(",").filter((x) => x !== "") },
    );
  }
  return { domains, suites, primitives, caseLabels, supported };
}

// ---------------------------------------------------------------------------
// Vector entries
//
// Every object in an array of objects is one entry, named by `name`, `seq`
// or `after_seq` (else by index). Whatever is left of a top-level key once
// its entry arrays are taken out (keys, field orders, descriptions) is one
// "fixture" entry named after the key.

// Outcome keys, an explicit allow-list: the verdict and the expected
// verifier state. Every other key is data — including expected bytes such
// as `expected_hex` / `expected_*_hex` / `expected_line` and any expected_*
// key added later — so an unlisted key is classified upward (a byte change
// is R3 unless rebased; an outcome change is R2). `kind` is an outcome only
// in a negative (its rejection class); in a positive it is data (e.g. the
// wrap kind in master-key-wrap.json)
const OUTCOME_KEYS = new Set([
  "must_fail",
  "expected_reason",
  "expected_error",
  "expected_head_states",
  "expected_members",
  "expected_environments",
  "expected_server_grants",
  "expected_checkpoints",
  "expected_policy",
  "expected_pending",
]);
const PROSE_KEY = /^(?:note|description)$|_note$/;
const HEX = /^(?:[0-9a-f]{2})+$/;

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function entryKey(element, index) {
  if (typeof element.name === "string") return element.name;
  if (element.seq !== undefined) return `seq=${element.seq}`;
  if (element.after_seq !== undefined) return `after_seq=${element.after_seq}`;
  return `#${index}`;
}

/** All entries of one parsed vector file, keyed by a stable id. */
export function collectEntries(file, json) {
  const entries = new Map();
  const addEntry = (arrayPath, key, value, fixture) => {
    let id = `${file} › ${arrayPath === "" ? "" : `${arrayPath} › `}${key}`;
    for (let n = 2; entries.has(id); n += 1) id = `${id} (${n})`;
    const negative = !fixture && (value.must_fail === true || /negative/.test(arrayPath));
    entries.set(id, { id, file, arrayPath, value, fixture, negative });
  };
  // Returns `node` with its entry arrays cut out (registering them)
  const take = (node, path) => {
    if (Array.isArray(node) && node.length > 0 && node.every(isPlainObject)) {
      node.forEach((element, index) => addEntry(path, entryKey(element, index), element, false));
      return undefined;
    }
    if (isPlainObject(node)) {
      const rest = {};
      for (const [key, value] of Object.entries(node)) {
        const kept = take(value, path === "" ? key : `${path}.${key}`);
        if (kept !== undefined) rest[key] = kept;
      }
      return Object.keys(rest).length > 0 ? rest : undefined;
    }
    return node;
  };
  if (isPlainObject(json)) {
    for (const [key, value] of Object.entries(json)) {
      const rest = take(value, key);
      if (rest !== undefined) addEntry("", key, { [key]: rest }, true);
    }
  } else {
    take(json, "");
  }
  return entries;
}

/** Flattens a value to leaf path → primitive (paths use `.` and `[i]`). */
function leaves(value, path = "", out = new Map()) {
  if (Array.isArray(value)) value.forEach((v, i) => leaves(v, `${path}[${i}]`, out));
  else if (isPlainObject(value)) {
    for (const [k, v] of Object.entries(value)) leaves(v, path === "" ? k : `${path}.${k}`, out);
  } else out.set(path, value);
  return out;
}

/**
 * The kind of one leaf: `outcome` (the verdict a check must reach), `prose`
 * (explanatory text) or `data` (everything else — bytes and inputs).
 * Prose is a note / description key, or sentence-like text (six or more
 * words) outside expected_* keys. Treating an input sentence as prose hides
 * nothing: the regeneration check pins every input to its output bytes, so
 * a meaningful input edit also shows as a `data` change.
 */
export function leafKind(entry, leafPath, value) {
  const keys = `${entry.arrayPath}.${leafPath}`
    .split(/[.[\]]+/)
    .filter((k) => k !== "" && !/^\d+$/.test(k));
  if (keys.some((k) => OUTCOME_KEYS.has(k))) return "outcome";
  if (entry.negative && keys.at(-1) === "kind") return "outcome";
  const last = keys.at(-1) ?? "";
  if (PROSE_KEY.test(last)) return "prose";
  if (typeof value === "string" && !HEX.test(value) && value.trim().split(/\s+/).length >= 6) {
    return "prose";
  }
  return "data";
}

/** Which kinds of leaves differ between two versions of an entry. */
function changedKinds(entry, before, after) {
  const a = leaves(before);
  const b = leaves(after);
  const kinds = new Set();
  for (const path of new Set([...a.keys(), ...b.keys()])) {
    if (!Object.is(a.get(path), b.get(path))) {
      kinds.add(leafKind(entry, path, b.has(path) ? b.get(path) : a.get(path)));
    }
  }
  return kinds;
}

/**
 * Parses `hex` as a §2.1 length-prefixed encoding whose first field is a
 * domain string or a bare suite; returns { domain, fields } or null.
 *
 * A bare suite leads the encodings whose domain separation is not a leading
 * domain string: chain entries (§6.1 — the op is their fourth field) and
 * the variable AAD (§4). Their shape is the suite and the field count only;
 * a chain op and its payload order are surface through the chain-op and
 * field-order facts.
 */
export function lpShape(hex) {
  if (!HEX.test(hex) || hex.length < 16) return null;
  const bytes = Uint8Array.from(hex.match(/../g), (h) => Number.parseInt(h, 16));
  const fields = [];
  let i = 0;
  while (i < bytes.length) {
    if (i + 4 > bytes.length) return null;
    const length =
      ((bytes[i] << 24) | (bytes[i + 1] << 16) | (bytes[i + 2] << 8) | bytes[i + 3]) >>> 0;
    i += 4;
    if (i + length > bytes.length) return null;
    fields.push(bytes.subarray(i, i + length));
    i += length;
  }
  if (fields.length < 2) return null;
  const domain = new TextDecoder().decode(fields[0]);
  return DOMAIN_LITERAL.test(domain) || SUITE_LITERAL.test(domain)
    ? { domain, fields: fields.length }
    : null;
}

const FACT_KEYS = ["domains", "suites", "shapes", "fieldOrders", "ops"];

function emptyFacts() {
  return Object.fromEntries(FACT_KEYS.map((key) => [key, new Set()]));
}

/**
 * Domains, suites, encoding shapes (leading domain or suite + field count
 * of every length-prefixed hex value), field orders and chain ops seen in
 * a set of entries, in two layers: `accepted` from non-negative entries
 * (positives and fixtures) and `all` including negatives. Negatives are malformed or foreign on
 * purpose, so they never vouch for a surface: every comparison that could
 * lower a class (what base already knew, what head retired) reads
 * `accepted`; only "what head now carries" reads `all`, which errs upward.
 */
function vectorFacts(entries) {
  const accepted = emptyFacts();
  const all = emptyFacts();
  for (const entry of entries.values()) {
    const facts = entryFacts(entry);
    collectFieldOrders(entry.value, facts.fieldOrders);
    for (const target of entry.negative ? [all] : [all, accepted]) {
      for (const key of FACT_KEYS) {
        for (const x of facts[key]) target[key].add(x);
      }
    }
  }
  return { accepted, all };
}

// Keys whose value is the op of a chain entry being signed (§6.1 `op`, a
// proposal's `inner_op` — §6.2). The op is a chain entry's domain
// separation, but its signed bytes begin with the bare suite
const OP_KEY = /(?:^|\.)(?:inner_)?op$/;

/** Domains, suites, §2.1 shapes and chain ops (negatives included) one entry carries. */
function entryFacts(entry) {
  const domains = new Set();
  const suites = new Set();
  const shapes = new Set();
  const ops = new Set();
  for (const [path, value] of leaves(entry.value)) {
    if (typeof value !== "string") continue;
    if (OP_KEY.test(path)) ops.add(value);
    if (SUITE_LITERAL.test(value)) suites.add(value);
    if (DOMAIN_LITERAL.test(value)) {
      domains.add(normalizeDomain(value));
      suites.add(value.split("/").slice(0, 2).join("/"));
    }
    const shape = lpShape(value);
    if (shape !== null) {
      // A suite-led shape is labeled `<suite>`, which is no domain string
      const label = SUITE_LITERAL.test(shape.domain) ? "<suite>" : normalizeDomain(shape.domain);
      if (label !== "<suite>") domains.add(label);
      suites.add(shape.domain.split("/").slice(0, 2).join("/"));
      shapes.add(`${label} ×${shape.fields}`);
    }
  }
  return { domains, suites, shapes, fieldOrders: new Set(), ops };
}

const shapeDomain = (shape) => shape.slice(0, shape.lastIndexOf(" ×"));

/**
 * The accepted surface that left head, from non-negative entries only:
 * shapes gone, domains whose every shape is gone (a retired layout keeps
 * negatives that use its domain, so domain presence alone would not show
 * it), and suites no longer used by any non-negative entry nor by src.
 */
function retiredSurface(baseFacts, headFacts, headSrcSuites) {
  const base = baseFacts.accepted;
  const head = headFacts.accepted;
  const headDomains = new Set([...head.shapes].map(shapeDomain));
  const headSuites = new Set([...head.suites, ...headSrcSuites]);
  return {
    shapes: new Set(setDiff(base.shapes, head.shapes)),
    domains: new Set([...base.shapes].map(shapeDomain).filter((d) => !headDomains.has(d))),
    suites: new Set(setDiff(base.suites, headSuites)),
  };
}

/**
 * The retired surface a removed negative exercised (empty = its surface is
 * still in head, so removing it may widen acceptance).
 */
function retiredBy(entry, retired) {
  const facts = entryFacts(entry);
  return [
    ...[...facts.shapes].filter((s) => retired.shapes.has(s)),
    ...[...facts.domains].filter((d) => retired.domains.has(d)),
    ...[...facts.suites].filter((s) => retired.suites.has(s)),
  ];
}

/**
 * Field orders (lists of field names) describe encodings: a string list
 * under a `*_order` key, directly or inside a map there. A map's keys name
 * the structure each list orders and are part of its identity — in
 * chain-entries.json `payload_field_order.<op>` is the chain op table the
 * generator builds every payload from (verify_reference.mjs checks it
 * against its own copy), so a new op is a new field order even when its
 * list equals another op's. The `*_order` key itself is not part of it:
 * renaming a declaration adds no encoding.
 */
function collectFieldOrders(node, out, member = null) {
  if (Array.isArray(node)) {
    if (member !== null && node.every((x) => typeof x === "string")) {
      out.add(`${member === "" ? "" : `${member}: `}${JSON.stringify(node)}`);
    }
  } else if (isPlainObject(node)) {
    for (const [k, v] of Object.entries(node)) {
      let inner = null;
      if (member !== null) inner = member === "" ? k : `${member}.${k}`;
      else if (k.endsWith("_order")) inner = "";
      collectFieldOrders(v, out, inner);
    }
  }
}

/** Non-hex strings and long (≥ 16-byte) hex values of an entry (rebase detection). */
function referenceValues(value) {
  const out = new Set();
  for (const v of leaves(value).values()) {
    if (typeof v === "string" && (!HEX.test(v) || v.length >= 32)) out.add(v);
  }
  return out;
}

// ---------------------------------------------------------------------------
// The analysis

// Keys through which one entry names another (`base: "var-v2-create-typed"`).
// Name references are read only here, never from free text
const REFERENCE_KEYS = new Set(["base", "prev_base", "predecessor"]);

/** Entry names an entry references through REFERENCE_KEYS. */
function referencedNames(value) {
  const out = new Set();
  for (const [path, v] of leaves(value)) {
    if (typeof v === "string" && REFERENCE_KEYS.has(path.split(".").at(-1))) out.add(v);
  }
  return out;
}

const VECTOR_FILE = /^test-vectors\/(?:hpke\/)?[^/]+\.json$/;
const CODE_FILE = /\.(?:ts|mts|mjs|js|py)$/;
const DOC_FILE = /(?:\.md|\.txt|(?:^|\/)LICENSE)$/;

function setDiff(a, b) {
  return [...a].filter((x) => !b.has(x)).toSorted();
}

/** Whether `domain` (possibly a `*` pattern) is covered by `known`. */
function domainKnown(domain, known) {
  if (known.has(domain)) return true;
  // The `*` of `name-v${layout}` stands for a layout number only: it covers
  // `name-v3` (or another pattern `name-v*`), never `name-vault` / `-v2-hybrid`
  return [...known].some(
    (k) =>
      k.endsWith("*") &&
      domain.startsWith(k.slice(0, -1)) &&
      /^(?:\d+|\*)$/.test(domain.slice(k.length - 1)),
  );
}

function mergeFacts(perFile, pick) {
  const out = new Set();
  for (const facts of perFile.values()) for (const x of pick(facts)) out.add(x);
  return out;
}

// Python has no runtime form to compare, so only whitespace is ignored there
// (a comment edit in the generator counts as a logic change)
function normalizePython(text) {
  return text.replace(/[ \t]+$/gm, "").replace(/\n+/g, "\n");
}

/** Sorts the changed paths into docs / cosmetic code / logic code / config / vectors. */
function classifyFiles(base, head, runtimeForm) {
  const paths = [...new Set([...base.keys(), ...head.keys()])].toSorted();
  const files = { docs: [], cosmetic: [], code: [], config: [], vectors: [] };
  for (const path of paths.filter((p) => base.get(p) !== head.get(p))) {
    const before = base.get(path);
    const after = head.get(path);
    if (VECTOR_FILE.test(path)) files.vectors.push(path);
    else if (DOC_FILE.test(path)) files.docs.push(path);
    else if (!CODE_FILE.test(path)) files.config.push(path);
    else if (before === undefined || after === undefined) files.code.push(path);
    else if (path.endsWith(".py")) {
      (normalizePython(before) === normalizePython(after) ? files.cosmetic : files.code).push(path);
    } else {
      // Both checks must agree (see "Source canonicalization")
      const runtime = runtimeForm(path, before);
      const cosmetic =
        canonicalSource(before) === canonicalSource(after) &&
        runtime !== undefined &&
        runtime === runtimeForm(path, after);
      (cosmetic ? files.cosmetic : files.code).push(path);
    }
  }
  return files;
}

function runtimeDependencies(packageJson) {
  return packageJson === undefined
    ? ""
    : JSON.stringify(JSON.parse(packageJson).dependencies ?? {});
}

/** Every vector entry of a snapshot, keyed by id. */
function entriesOf(files) {
  const all = new Map();
  for (const [path, text] of files) {
    if (!VECTOR_FILE.test(path)) continue;
    const file = path.replace(/^test-vectors\//, "");
    for (const [id, entry] of collectEntries(file, JSON.parse(text))) all.set(id, entry);
  }
  return all;
}

const lastSegment = (id) => id.split(" › ").at(-1);

/**
 * Marks each changed entry with the removed material it referenced.
 * A changed entry is "rebased" when its old version referenced material only
 * removed (or likewise changed) non-negative entries had: a removed
 * positive of the same file named through a reference key, or a long hex
 * value of a removed positive / fixture that no unchanged entry carries.
 * Such an entry had to move with the deletion. It cannot hide an encoding
 * change on its own: that would also move the unchanged vectors of the same
 * encoding. Removed negatives never explain a byte change.
 */
function markRebased(baseEntries, headEntries, removed, changedEntries) {
  const removedNames = new Set(); // "file|name"
  const removedValues = new Set();
  for (const id of removed) {
    const entry = baseEntries.get(id);
    if (entry.negative) continue;
    if (!entry.fixture) removedNames.add(`${entry.file}|${lastSegment(id)}`);
    for (const v of referenceValues(entry.value)) if (HEX.test(v)) removedValues.add(v);
  }
  const survivingNames = new Set(
    [...headEntries.values()].map((e) => `${e.file}|${lastSegment(e.id)}`),
  );
  const changedIds = new Set(changedEntries.map((c) => c.id));
  const keptValues = new Set();
  for (const [id, entry] of baseEntries) {
    if (!headEntries.has(id) || changedIds.has(id)) continue;
    for (const v of referenceValues(entry.value)) keptValues.add(v);
  }
  for (const c of changedEntries) {
    const name = (v) => `${c.entry.file}|${v}`;
    c.rebasedOff = [
      ...[...referencedNames(c.before)].filter(
        (v) => removedNames.has(name(v)) && !survivingNames.has(name(v)),
      ),
      ...[...referenceValues(c.before)].filter((v) => removedValues.has(v) && !keptValues.has(v)),
    ];
  }
}

/**
 * A negative built from retired material also exercised that surface even
 * when its own bytes do not show it — e.g. a v2 signature replayed under the
 * v1 domain. It counts when it references (by name through a reference key,
 * or by a long hex value no head entry carries) a removed positive that
 * itself exercised retired surface.
 */
function markDerivedFromRetired(removedVectors, removedNegatives, retired, headEntries) {
  const headValues = new Set();
  for (const entry of headEntries.values()) {
    for (const v of referenceValues(entry.value)) headValues.add(v);
  }
  const sources = removedVectors.filter((e) => !e.negative && retiredBy(e, retired).length > 0);
  for (const negative of removedNegatives) {
    const file = negative.id.split(" › ")[0];
    const refs = referenceValues(negative.value);
    const names = referencedNames(negative.value);
    for (const source of sources) {
      const name = lastSegment(source.id);
      const sameFileName = source.file === file && names.has(name);
      const sharedHex = [...referenceValues(source.value)].some(
        (v) => HEX.test(v) && refs.has(v) && !headValues.has(v),
      );
      if (sameFileName || sharedHex) negative.retiredBy.push(`derived from ${name}`);
    }
  }
}

/** Entry-level delta of the vector files. */
function vectorDelta(base, head, headSrcSuites) {
  const baseEntries = entriesOf(base);
  const headEntries = entriesOf(head);
  const removed = [...baseEntries.keys()].filter((id) => !headEntries.has(id));
  const added = [...headEntries.keys()].filter((id) => !baseEntries.has(id));
  const changed = [];
  let unchanged = 0;
  for (const [id, before] of baseEntries) {
    const after = headEntries.get(id);
    if (after === undefined) continue;
    if (JSON.stringify(before.value) === JSON.stringify(after.value)) {
      unchanged += 1;
    } else {
      const kinds = changedKinds(after, before.value, after.value);
      changed.push({ id, entry: after, before: before.value, kinds });
    }
  }
  markRebased(baseEntries, headEntries, removed, changed);
  const data = changed.filter((c) => c.kinds.has("data"));
  const baseFacts = vectorFacts(baseEntries);
  const headFacts = vectorFacts(headEntries);
  // Removing an acceptance pin (a positive) can only narrow; removing a
  // rejection pin (a negative) can widen, so a removed negative counts as
  // narrowing only together with the surface it exercised
  const retired = retiredSurface(baseFacts, headFacts, headSrcSuites);
  const removedVectors = removed.map((id) => baseEntries.get(id)).filter((e) => !e.fixture);
  const removedNegatives = removedVectors
    .filter((e) => e.negative)
    .map((e) => ({ id: e.id, value: e.value, retiredBy: retiredBy(e, retired) }));
  markDerivedFromRetired(removedVectors, removedNegatives, retired, headEntries);
  return {
    unchanged,
    removed,
    added,
    changed,
    rebased: data.filter((c) => c.rebasedOff.length > 0),
    unexplained: data.filter((c) => c.rebasedOff.length === 0),
    outcomeChanged: changed.filter((c) => c.kinds.has("outcome")),
    removedPositives: removedVectors.filter((e) => !e.negative).map((e) => e.id),
    removedNegatives,
    baseFacts,
    headFacts,
  };
}

function sourceFactsOf(files) {
  const out = new Map();
  for (const [path, text] of files) {
    if (/^src\/.*\.ts$/.test(path)) out.set(path, sourceFacts(text));
  }
  return out;
}

function supportedOf(perFile) {
  const out = new Map();
  for (const facts of perFile.values()) for (const [name, v] of facts.supported) out.set(name, v);
  return out;
}

function showSupported(v) {
  if (v === undefined) return "(absent)";
  return v.parsed ? `[${v.values.join(", ")}]` : v.raw;
}

/** SUPPORTED_* constants whose value changed, and whether each only shrank. */
function supportedDelta(baseSrc, headSrc) {
  const before = supportedOf(baseSrc);
  const after = supportedOf(headSrc);
  const out = [];
  for (const name of [...new Set([...before.keys(), ...after.keys()])].toSorted()) {
    const a = before.get(name);
    const b = after.get(name);
    if (showSupported(a) === showSupported(b)) continue;
    const shrinks =
      a?.parsed === true && b?.parsed === true && b.values.every((x) => a.values.includes(x));
    out.push({ name, before: showSupported(a), after: showSupported(b), shrinks });
  }
  return out;
}

/**
 * What head adds to one kind of surface, compared like with like: an item
 * is new when it newly appears as accepted surface (src or a non-negative
 * entry; a base negative never vouches for it) or newly appears anywhere
 * (negatives included). Both halves err upward; a negative that merely
 * survives unchanged adds nothing.
 */
function grown(srcBase, srcHead, base, head, known = (x, set) => set.has(x)) {
  const acceptedBase = new Set([...srcBase, ...base.accepted]);
  const allBase = new Set([...srcBase, ...base.all]);
  const out = new Set();
  for (const x of [...srcHead, ...head.accepted]) if (!known(x, acceptedBase)) out.add(x);
  for (const x of head.all) if (!known(x, allBase)) out.add(x);
  return [...out].toSorted();
}

/** One kind of fact from both layers, for grown(). */
function layers(facts, key) {
  return { accepted: facts.accepted[key], all: facts.all[key] };
}

/** Domain, suite, encoding, primitive and SUPPORTED_* delta of src + the vectors. */
function surfaceDelta(baseSrc, headSrc, vectors) {
  const srcBase = mergeFacts(baseSrc, (f) => f.domains);
  const srcHead = mergeFacts(headSrc, (f) => f.domains);
  const srcSuitesBase = mergeFacts(baseSrc, (f) => f.suites);
  const srcSuitesHead = mergeFacts(headSrc, (f) => f.suites);
  const base = vectors.baseFacts;
  const head = vectors.headFacts;
  const primitivesBase = mergeFacts(baseSrc, (f) => f.primitives);
  const primitivesHead = mergeFacts(headSrc, (f) => f.primitives);
  const opsBase = mergeFacts(baseSrc, (f) => f.caseLabels);
  const opsHead = mergeFacts(headSrc, (f) => f.caseLabels);
  const suitesHeadAll = new Set([...srcSuitesHead, ...head.all.suites]);
  return {
    domains: {
      new: grown(srcBase, srcHead, layers(base, "domains"), layers(head, "domains"), domainKnown),
      srcAdded: setDiff(srcHead, srcBase),
      srcRemoved: setDiff(srcBase, srcHead),
      vectorAdded: setDiff(head.all.domains, base.all.domains),
      vectorRemoved: setDiff(base.all.domains, head.all.domains),
    },
    shapes: {
      added: setDiff(head.accepted.shapes, base.accepted.shapes),
      removed: setDiff(base.accepted.shapes, head.accepted.shapes),
    },
    fieldOrders: {
      added: grown([], [], layers(base, "fieldOrders"), layers(head, "fieldOrders")),
      removed: setDiff(base.all.fieldOrders, head.all.fieldOrders),
    },
    suites: {
      added: grown(srcSuitesBase, srcSuitesHead, layers(base, "suites"), layers(head, "suites")),
      removed: setDiff(new Set([...srcSuitesBase, ...base.all.suites]), suitesHeadAll),
    },
    primitives: {
      added: setDiff(primitivesHead, primitivesBase),
      removed: setDiff(primitivesBase, primitivesHead),
    },
    ops: {
      new: grown(opsBase, opsHead, layers(base, "ops"), layers(head, "ops")),
      srcAdded: setDiff(opsHead, opsBase),
      srcRemoved: setDiff(opsBase, opsHead),
      vectorAdded: setDiff(head.all.ops, base.all.ops),
      vectorRemoved: setDiff(base.all.ops, head.all.ops),
    },
    supported: supportedDelta(baseSrc, headSrc),
  };
}

/** R3 reasons: the encoding surface grows. */
function surfaceGrowth(vectors, surface, runtimeDependencyChange) {
  const { domains, shapes, fieldOrders, suites, primitives, ops } = surface;
  const out = [];
  if (domains.new.length > 0) out.push(`new domain string(s): ${domains.new.join(", ")}`);
  if (suites.added.length > 0) out.push(`new suite identifier(s): ${suites.added.join(", ")}`);
  if (shapes.added.length > 0) out.push(`new signed-bytes shape(s): ${shapes.added.join(", ")}`);
  if (fieldOrders.added.length > 0) {
    out.push(`new field order(s): ${fieldOrders.added.join("; ")}`);
  }
  if (ops.new.length > 0) out.push(`new chain op(s) / src case label(s): ${ops.new.join(", ")}`);
  if (primitives.added.length > 0) {
    out.push(`new primitive / library use: ${primitives.added.join(", ")}`);
  }
  if (runtimeDependencyChange) out.push("packages/crypto runtime dependencies changed");
  if (vectors.unexplained.length > 0) {
    out.push(
      `${vectors.unexplained.length} surviving vector(s) changed bytes without referencing removed material`,
    );
  }
  return out;
}

/**
 * The risk class and its reasons (highest class wins):
 * R3 — the encoding surface grows: a new domain string, suite, signed-bytes
 *      shape (domain- or suite-led), field order (a chain op's payload order
 *      included), chain op (a src string case label or a vector `op` /
 *      `inner_op`) or primitive, a runtime dependency change, or a surviving
 *      vector whose bytes changed without being rebased.
 * R2 — the surface is kept but behavior moves: a surviving vector's expected
 *      outcome changed, a SUPPORTED_* set did anything but shrink, a
 *      negative was removed while the surface it exercised remains, or code /
 *      config / vectors changed without any narrowing.
 * R1 — a narrowing (positives removed, negatives removed with their retired
 *      surface, or a supported set shrunk) and nothing above;
 *      implementation changes that carry it out are admitted.
 * R0 — nothing but docs, prose and comment / formatting edits.
 */
function classify(files, vectors, surface, runtimeDependencyChange) {
  const reasons = { R3: surfaceGrowth(vectors, surface, runtimeDependencyChange), R2: [], R1: [] };
  const { supported } = surface;
  if (vectors.outcomeChanged.length > 0) {
    reasons.R2.push(
      `${vectors.outcomeChanged.length} surviving vector(s) changed their expected outcome`,
    );
  }
  for (const s of supported.filter((x) => !x.shrinks)) {
    reasons.R2.push(`${s.name} changed without only shrinking: ${s.before} → ${s.after}`);
  }
  const shrank = supported.some((s) => s.shrinks);
  const kept = vectors.removedNegatives.filter((n) => n.retiredBy.length === 0);
  if (kept.length > 0) {
    reasons.R2.push(
      `${kept.length} rejection vector(s) removed while their surface remains: ` +
        kept.map((n) => n.id).join(", "),
    );
  }
  const narrowedBy =
    vectors.removedPositives.length + vectors.removedNegatives.length - kept.length;
  const narrowing = narrowedBy > 0 || shrank;
  const substantive =
    files.code.length + files.config.length + supported.length > 0 ||
    vectors.added.length + vectors.removed.length + vectors.rebased.length > 0 ||
    vectors.unexplained.length > 0;
  if (substantive && !narrowing) {
    reasons.R2.push(
      "code, config or vector changes without a narrowing (nothing removed, no supported set shrunk)",
    );
  }
  if (narrowing) {
    const n = narrowedBy;
    const shrinkNote = shrank ? ", a supported set shrank" : "";
    reasons.R1.push(`narrowing: ${n} vector entr${n === 1 ? "y" : "ies"} removed${shrinkNote}`);
  }
  let risk = "R0";
  if (reasons.R3.length > 0) risk = "R3";
  else if (reasons.R2.length > 0) risk = "R2";
  else if (substantive) risk = "R1";
  return { risk, reasons };
}

/**
 * Compares two snapshots of packages/crypto.
 * @param base, head  Map of path (relative to packages/crypto) → file text
 * @param runtimeForm (path, text) → transpiled text, or undefined when the
 *   file cannot be transpiled; omitted = no code edit ever counts as cosmetic
 */
export function analyze(base, head, runtimeForm = () => undefined) {
  const files = classifyFiles(base, head, runtimeForm);
  const runtimeDependencyChange =
    runtimeDependencies(base.get("package.json")) !== runtimeDependencies(head.get("package.json"));
  const baseSrc = sourceFactsOf(base);
  const headSrc = sourceFactsOf(head);
  const vectors = vectorDelta(
    base,
    head,
    mergeFacts(headSrc, (f) => f.suites),
  );
  const surface = surfaceDelta(baseSrc, headSrc, vectors);
  return {
    ...classify(files, vectors, surface, runtimeDependencyChange),
    files,
    vectors,
    ...surface,
    runtimeDependencyChange,
  };
}

// ---------------------------------------------------------------------------
// Report

const CLASS_MEANING = {
  R0: "comments / docs / prose only",
  R1: "deletion or narrowing — existing encodings untouched",
  R2: "logic or acceptance change keeping the encodings",
  R3: "new signed bytes, primitive or domain — full crypto review",
};
const LIST_CAP = 200;

/** A bullet list, capped so the job summary stays small. */
function list(items, render = (x) => `\`${x}\``) {
  if (items.length === 0) return "_none_\n";
  const shown = items.slice(0, LIST_CAP).map((x) => `- ${render(x)}`);
  if (items.length > LIST_CAP) shown.push(`- … and ${items.length - LIST_CAP} more`);
  return `${shown.join("\n")}\n`;
}

/** Inline code spans joined by commas, or _none_. */
function inline(items) {
  return items.length === 0 ? "_none_" : items.map((x) => `\`${x}\``).join(", ");
}

function changedLine(c) {
  const kinds = [...c.kinds].toSorted().join(" + ");
  const flags = [];
  if (c.kinds.has("outcome")) flags.push("**expected outcome changed**");
  if (c.rebasedOff.length > 0) {
    const refs = c.rebasedOff.map((v) => (v.length > 20 ? `${v.slice(0, 16)}…` : v));
    flags.push(`rebased off removed ${inline(refs)}`);
  }
  return `\`${c.id}\` — ${kinds}${flags.length > 0 ? `; ${flags.join("; ")}` : ""}`;
}

function vectorSection(v) {
  return [
    "### Vector entries\n",
    "| unchanged | removed | added | changed | outcome changed | rebased | unexplained byte change |",
    "|---:|---:|---:|---:|---:|---:|---:|",
    `| ${v.unchanged} | ${v.removed.length} | ${v.added.length} | ${v.changed.length} | ` +
      `${v.outcomeChanged.length} | ${v.rebased.length} | ${v.unexplained.length} |\n`,
    "<details><summary>Removed</summary>\n",
    list(v.removed, (id) => {
      const negative = v.removedNegatives.find((n) => n.id === id);
      if (negative === undefined) return `\`${id}\``;
      const why =
        negative.retiredBy.length > 0
          ? `retired: ${inline([...new Set(negative.retiredBy)])}`
          : "**surface remains**";
      return `\`${id}\` — rejection vector; ${why}`;
    }),
    "</details>\n<details><summary>Added</summary>\n",
    list(v.added),
    "</details>\n<details open><summary>Changed (leaf kinds: data / outcome / prose)</summary>\n",
    list(v.changed, changedLine),
    "</details>\n",
  ];
}

function surfaceSection(result) {
  const { domains, shapes, fieldOrders, suites, primitives, ops } = result;
  return [
    "### Domain-separation strings\n",
    `- new (in no base src or base vector): ${inline(domains.new)}`,
    `- src added: ${inline(domains.srcAdded)}`,
    `- src removed: ${inline(domains.srcRemoved)}`,
    `- vectors added: ${inline(domains.vectorAdded)}`,
    `- vectors removed: ${inline(domains.vectorRemoved)}\n`,
    "### Chain ops (src string `case` labels, vector `op` / `inner_op`)\n",
    `- new (in no base src or base vector): ${inline(ops.new)}`,
    `- src added: ${inline(ops.srcAdded)}; removed: ${inline(ops.srcRemoved)}`,
    `- vectors added: ${inline(ops.vectorAdded)}; removed: ${inline(ops.vectorRemoved)}\n`,
    "### SUPPORTED_* constants\n",
    list(
      result.supported,
      (s) => `\`${s.name}\`: ${s.before} → ${s.after}${s.shrinks ? " (shrinks)" : ""}`,
    ),
    "### Encodings, suites and primitives\n",
    `- signed-bytes shapes added: ${inline(shapes.added)}`,
    `- signed-bytes shapes removed: ${inline(shapes.removed)}`,
    `- field orders added: ${inline(fieldOrders.added)}`,
    `- field orders removed: ${inline(fieldOrders.removed)}`,
    `- suites added: ${inline(suites.added)}; removed: ${inline(suites.removed)}`,
    `- primitives added: ${inline(primitives.added)}`,
    `- primitives removed: ${inline(primitives.removed)}`,
    `- runtime dependencies changed: ${result.runtimeDependencyChange ? "**yes**" : "no"}\n`,
  ];
}

/** Renders an analysis as GitHub-flavored Markdown. */
export function renderReport(result, { baseLabel, headLabel, specChanged }) {
  const why = ["R3", "R2", "R1"].flatMap((r) => result.reasons[r].map((x) => `${r}: ${x}`));
  const { files } = result;
  const out = [
    `## Crypto change review aid — ${result.risk} (${CLASS_MEANING[result.risk]})\n`,
    `Advisory only: this report approves nothing. Range \`${baseLabel}\`…\`${headLabel}\` ` +
      "(merge-base to head), packages/crypto only. Classes and how to read this: " +
      'packages/crypto/test-vectors/README.md, "Reviewing a crypto change".\n',
    "### Why this class\n",
    list(why, (x) => x),
  ];
  if (result.risk === "R1" && files.code.some((p) => p.startsWith("src/"))) {
    out.push(
      "> R1 admits src changes that carry out the narrowing. Read the src diffs listed below.\n",
    );
  }
  if (specChanged) out.push("docs/CRYPTO_SPEC.md changed in this range.\n");
  out.push(
    ...vectorSection(result.vectors),
    ...surfaceSection(result),
    "### Changed files (packages/crypto)\n",
    `- code (logic): ${inline(files.code)}`,
    `- code (comments / formatting only): ${inline(files.cosmetic)}`,
    `- vectors: ${inline(files.vectors)}`,
    `- config: ${inline(files.config)}`,
    `- docs: ${inline(files.docs)}`,
  );
  return `${out.join("\n")}\n`;
}

// ---------------------------------------------------------------------------
// CLI (git I/O)

const PACKAGE = "packages/crypto";

// Every git call runs at the repository root (ls-tree paths are relative to
// the working directory otherwise). Resolved on first use, not on import
let repoRoot;
function root() {
  repoRoot ??= execFileSync("git", ["rev-parse", "--show-toplevel"], {
    cwd: import.meta.dirname,
    encoding: "utf8",
  }).trim();
  return repoRoot;
}

function git(args) {
  return execFileSync("git", args, { cwd: root(), encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
}

/** packages/crypto at `rev` as path → text (node_modules and lockfiles skipped). */
function readSnapshot(rev) {
  const out = new Map();
  const names = git(["ls-tree", "-r", "-z", "--name-only", rev, "--", PACKAGE]).split("\0");
  for (const name of names) {
    if (name === "" || /\/node_modules\/|\.lock$/.test(name)) continue;
    out.set(name.slice(PACKAGE.length + 1), git(["show", `${rev}:${name}`]));
  }
  return out;
}

function main(argv) {
  const arg = (flag) => {
    const i = argv.indexOf(flag);
    return i === -1 ? undefined : argv[i + 1];
  };
  const baseRev = arg("--base");
  const headRev = arg("--head") ?? "HEAD";
  if (baseRev === undefined) {
    console.error("usage: bun run delta -- --base <rev> [--head <rev>]");
    return 2;
  }
  const mergeBase = git(["merge-base", baseRev, headRev]).trim();
  const transpiler = new Bun.Transpiler({ loader: "ts" });
  const runtimeForm = (path, text) => {
    if (!/\.(?:ts|mts|mjs|js)$/.test(path)) return undefined;
    try {
      return transpiler.transformSync(text);
    } catch {
      // Not transpilable means "cannot show the runtime is unchanged": the
      // file then counts as a logic change (the conservative side)
      return undefined;
    }
  };
  const result = analyze(readSnapshot(mergeBase), readSnapshot(headRev), runtimeForm);
  // `git diff --quiet` answers through its exit status: 0 same, 1 changed
  const spec = spawnSync(
    "git",
    ["diff", "--quiet", mergeBase, headRev, "--", "docs/CRYPTO_SPEC.md"],
    { cwd: root() },
  );
  if (spec.status !== 0 && spec.status !== 1)
    throw new Error("git diff failed on docs/CRYPTO_SPEC.md");
  const specChanged = spec.status === 1;
  process.stdout.write(
    renderReport(result, {
      baseLabel: mergeBase.slice(0, 12),
      headLabel: git(["rev-parse", "--short=12", headRev]).trim(),
      specChanged,
    }),
  );
  return 0;
}

if (import.meta.main) process.exitCode = main(process.argv.slice(2));
