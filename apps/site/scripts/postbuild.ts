// Post-processing of `blume build` (ruling D — docs/notes/
// web-design-pass.md §4 "rulings made while implementing DP2"). Finishes the
// shipped output (dist/) for Workers Static Assets. Three stages:
//
//   1. **Externalizing style attributes**: Blume's docs pages carry inline
//      `style` attributes on Shiki tokens (`style="--shiki-light:…"`) and on
//      parts of the chrome (sidebar indents, CardGroup column counts).
//      Attribute inline styles cannot be allowed by a CSP hash (that needs
//      `'unsafe-hashes'` + enumerating every attribute value), so each
//      attribute value is mapped to a class (`.sa-<hash>`) written into one
//      CSS file, and the HTML side is rewritten to a class reference (the
//      same technique as Shiki's official `transformerStyleToClass`, applied
//      to the shipped output — Blume does not expose transformers). As a
//      result, no `style` attribute remains in the HTML.
//   2. **CSP and inline hashes**: `default-src 'none'` baseline; no
//      `'unsafe-inline'` for script or style. The inline scripts Blume's
//      chrome ships (theme init / header handling / nav / ClientRouter's
//      style loading) and the `@font-face` `<style>` the Astro Fonts API
//      (`<Font>`) always emits have deterministic content, so they are
//      allowed individually via SHA-256 hashes collected from the shipped
//      output (same scheme as apps/web/scripts/write-headers.ts). Every
//      other inline style is pinned to external CSS by the blume.config.ts
//      integration (`build.inlineStylesheets: 'never'`). The
//      transition-suppression `<style>` Blume's theme toggle inserts on
//      click is a fixed string, so its hash is added after confirming it
//      exists.
//   3. **Mechanical check for zero external references and `_headers`**:
//      "say nothing" (CLAUDE.md §1-5) — verify the shipped output's src /
//      href never point outside, then append the `/*` security headers while
//      keeping the `_headers` Blume emitted (charset for .md / .txt, the top
//      Link header).
// Violations fail the build (throw). The checks ride on the quality-gate
// path (the site build step in CI).
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";

const distDir = join(import.meta.dirname, "..", "dist");
const siteOrigin = "https://maruhi.app";

const htmlFiles = readdirSync(distDir, { recursive: true, encoding: "utf8" })
  .filter((name) => name.endsWith(".html"))
  .map((name) => join(distDir, name));
if (htmlFiles.length === 0) throw new Error(`no HTML in ${distDir} — run blume build first`);

const sha256base64 = (body: string): string =>
  `'sha256-${createHash("sha256").update(body, "utf8").digest("base64")}'`;
const shortHash = (body: string): string =>
  createHash("sha256").update(body, "utf8").digest("hex").slice(0, 10);

// ---- 1. Externalizing style attributes ----
// Rewrite only inside element tags, avoiding script / style bodies (which
// may contain `style="` as a string). Restore entity references in attribute
// values. &amp; is folded last (so the first halves of &#39; etc. are not
// altered first)
const decodeAttr = (value: string): string =>
  value
    .replace(/&#(x[0-9a-fA-F]+|[0-9]+);/g, (_m, code: string) =>
      String.fromCodePoint(
        code.startsWith("x") ? Number.parseInt(code.slice(1), 16) : Number.parseInt(code, 10),
      ),
    )
    .replaceAll("&quot;", '"')
    .replaceAll("&apos;", "'")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&amp;", "&");

// The 3 attribute-value forms (double-quoted, single-quoted, unquoted) — so
// nothing escapes the check even if the generator emits something other
// than "
const ATTR_VALUE_PATTERN = String.raw`(?:"[^"]*"|'[^']*'|[^\s>]+)`;

/** The first group that matched any of the 3 forms (a miss is ""). */
const firstDefined = (...values: readonly (string | undefined)[]): string =>
  values.find((v) => v !== undefined) ?? "";

/** The value of a `name="..."` attribute (all 3 forms). undefined if absent. */
const attrValueOf = (attrs: string, name: string): string | undefined => {
  const m = new RegExp(String.raw`\b${name}\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`).exec(attrs);
  return m === null ? undefined : firstDefined(m[1], m[2], m[3]);
};

const styleRules = new Map<string, string>(); // class → declarations

/** Maps a declaration list to a class name (a hash collision fails the build). An empty style attribute is undefined. */
const registerStyle = (declarations: string): string | undefined => {
  if (declarations === "") return undefined;
  const className = `sa-${shortHash(declarations)}`;
  const previous = styleRules.get(className);
  if (previous !== undefined && previous !== declarations) {
    throw new Error(`style attribute hash collision: ${className}`);
  }
  styleRules.set(className, declarations);
  return className;
};

/** Adds className alongside an existing class attribute (appended at the end if none). No-op without className. */
const mergeClass = (rest: string, className: string | undefined): string => {
  if (className === undefined) return rest;
  const classAttr = new RegExp(String.raw`\sclass\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`).exec(
    rest,
  );
  if (classAttr === null) return `${rest} class="${className}"`;
  return rest.replace(
    classAttr[0],
    ` class="${firstDefined(classAttr[1], classAttr[2], classAttr[3])} ${className}"`,
  );
};

/** Rewrites a tag's attribute list (externalizing style attributes + injecting class). undefined when there is no style. */
const externalizeAttrs = (attrs: string): string | undefined => {
  const styleAttr = new RegExp(String.raw`\sstyle\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`, "g");
  let className: string | undefined;
  const rest = attrs.replace(
    styleAttr,
    (_m, dq: string | undefined, sq: string | undefined, uq: string | undefined) => {
      className = registerStyle(
        decodeAttr(firstDefined(dq, sq, uq))
          .trim()
          .replace(/;$/, ""),
      );
      return "";
    },
  );
  if (rest === attrs) return undefined; // no style attribute (no replacement happened)
  return mergeClass(rest, className);
};

function externalizeStyleAttributes(html: string): string {
  const segments = html.split(
    /(<script\b[^>]*>[\s\S]*?<\/script>|<style\b[^>]*>[\s\S]*?<\/style>)/,
  );
  return segments
    .map((segment, i) => {
      if (i % 2 === 1) return segment; // script / style blocks pass through
      return segment.replace(
        new RegExp(
          `<([a-zA-Z][\\w:-]*)((?:\\s+[^\\s=>/]+(?:=${ATTR_VALUE_PATTERN})?)*)\\s*(\\/?)>`,
          "g",
        ),
        (tag, name: string, attrs: string, selfClose: string) => {
          const next = externalizeAttrs(attrs);
          return `<${name}${next ?? attrs}${selfClose}>`;
        },
      );
    })
    .join("");
}

const rewritten = new Map<string, string>();
for (const file of htmlFiles)
  rewritten.set(file, externalizeStyleAttributes(readFileSync(file, "utf8")));

if (styleRules.size > 0) {
  const css = [...styleRules.entries()]
    .toSorted(([a], [b]) => a.localeCompare(b))
    .map(([className, declarations]) => `.${className}{${declarations}}`)
    .join("\n");
  const cssName = `style-attributes.${shortHash(css)}.css`;
  writeFileSync(join(distDir, "_astro", cssName), `${css}\n`);
  const link = `<link rel="stylesheet" href="/_astro/${cssName}">`;
  for (const [file, html] of rewritten) {
    // Inject link only into pages that reference an externalized class
    // (after Blume's other stylesheets = just before </head>)
    if (!html.includes('class="sa-') && !html.includes(" sa-")) continue;
    if (!html.includes("</head>"))
      throw new Error(`${file}: no </head> to inject the style-attributes stylesheet`);
    rewritten.set(file, html.replace("</head>", `${link}</head>`));
  }
}
for (const [file, html] of rewritten) {
  if (
    new RegExp(String.raw`\sstyle\s*=\s*${ATTR_VALUE_PATTERN}`).test(
      html.replace(/<script\b[^>]*>[\s\S]*?<\/script>|<style\b[^>]*>[\s\S]*?<\/style>/g, ""),
    )
  ) {
    throw new Error(`${file}: a style attribute survived externalization`);
  }
  writeFileSync(file, html);
}

// ---- 2. Collecting inline hashes and the mechanical check ----
// JSON data blocks (scripts whose type is not JS) are not executed, so they
// are outside CSP's scope
const isJavaScriptType = (attrs: string): boolean => {
  const type = attrValueOf(attrs, "type");
  return type === undefined || type === "module" || /javascript/i.test(type);
};

const scriptHashes = new Set<string>();
const styleHashes = new Set<string>();
const inlineScriptBodies: string[] = [];
const externalRefs: string[] = [];
const allowedExternalHref = [
  "https://github.com/maruhiapp/maruhi",
  "https://my.maruhi.app",
  siteOrigin,
];

for (const [file, html] of rewritten) {
  for (const m of html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)) {
    const attrs = m[1] ?? "";
    const body = m[2] ?? "";
    const scriptSrc = attrValueOf(attrs, "src");
    if (scriptSrc !== undefined) {
      if (!scriptSrc.startsWith("/") || scriptSrc.startsWith("//"))
        externalRefs.push(`${relative(distDir, file)}: <script src="${scriptSrc}">`);
      continue;
    }
    if (body.length === 0 || !isJavaScriptType(attrs)) continue;
    scriptHashes.add(sha256base64(body));
    inlineScriptBodies.push(body);
  }
  for (const m of html.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/g)) {
    const body = m[1] ?? "";
    if (body.length > 0) styleHashes.add(sha256base64(body));
  }
  // Inline event handlers and javascript: URLs are blocked by CSP = lost
  // functionality, so they are detected at build time
  if (/\son[a-z]+\s*=\s*(?:"|'|[^\s>])/i.test(html))
    throw new Error(`${file}: inline event handler attribute`);
  if (/javascript:/i.test(html)) throw new Error(`${file}: javascript: URL`);
  // Check for external resource references (comments excluded — the logo
  // SVG's provenance comment carries a URL). href is navigation, so only the
  // own repository's GitHub and the product origin are allowed; load-bearing
  // references are same-origin only
  const withoutComments = html.replace(/<!--[\s\S]*?-->/g, "");
  for (const m of withoutComments.matchAll(
    /\b(src|href|srcset|poster|data|action)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g,
  )) {
    const attr = m[1]!;
    const url = firstDefined(m[2], m[3], m[4]);
    const isLocal =
      (url.startsWith("/") && !url.startsWith("//")) ||
      url.startsWith("#") ||
      url.startsWith("data:") ||
      url.startsWith("./") ||
      url === "";
    if (isLocal) continue;
    if (
      attr === "href" &&
      (url.startsWith("mailto:") ||
        allowedExternalHref.some(
          (p) => url === p || url.startsWith(`${p}/`) || url.startsWith(`${p}#`),
        ))
    )
      continue;
    // Neither a scheme nor `//` = a same-origin relative reference
    if (!/^[a-z][a-z0-9+.-]*:/i.test(url) && !url.startsWith("//")) continue;
    externalRefs.push(`${relative(distDir, file)}: ${attr}="${url}"`);
  }
}

if (externalRefs.length > 0) {
  throw new Error(
    `external resource references in the built site ("say nothing" — all assets are self-served):\n  ${externalRefs.join("\n  ")}`,
  );
}
if (scriptHashes.size === 0)
  throw new Error(
    "no inline scripts found — Blume's output format may have changed. Revisit CSP generation",
  );

// The transition-suppression style inserted by Blume's theme toggle
// (Header.astro's inline script). Its body must be confirmed inside the
// shipped output's inline scripts before its hash is allowed (a change in a
// Blume update fails this)
const themeToggleStyle = "*,*::before,*::after{transition:none!important}";
if (!inlineScriptBodies.some((body) => body.includes(themeToggleStyle))) {
  throw new Error(
    "Blume's theme toggle script lacks the expected transition-suppression style string (did a Blume update change it?). " +
      "Match postbuild.ts's themeToggleStyle to the real thing",
  );
}
styleHashes.add(sha256base64(themeToggleStyle));

// ---- 3. `_headers` ----
const csp = [
  "default-src 'none'",
  `script-src 'self' ${[...scriptHashes].toSorted().join(" ")}`,
  `style-src 'self' ${[...styleHashes].toSorted().join(" ")}`,
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "manifest-src 'self'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

// Cloudflare's _headers caps a line at 2,000 characters and silently drops
// the excess (a silent loss of security headers). The hash set grows with
// the number of distinct inline bodies, so the limit is enforced as a build
// failure
const HEADERS_LINE_LIMIT = 2000;
const cspLine = `  Content-Security-Policy: ${csp}`;
if (cspLine.length > HEADERS_LINE_LIMIT) {
  throw new Error(
    `the _headers CSP line is ${cspLine.length} characters, over Cloudflare's limit of ${HEADERS_LINE_LIMIT}. ` +
      "The number of distinct inline scripts / styles grew (a Blume update?) — revisit the hash set",
  );
}

// The _headers Blume emitted (charset for /docs/*.md etc., the top Link
// header) is kept and the `/*` security headers are appended (a request that
// matches several blocks inherits the headers of all of them). Blume 2 also
// ships a scoped `Content-Security-Policy: sandbox` for `/blume-assets/*.svg`.
// `/*` matches those paths too, so Cloudflare comma-joins the two CSPs there
// and the browser enforces both policies (stricter, intended). The
// double-run tripwire therefore checks only for our own `/*` block. HSTS is
// apex-only (includeSubDomains / preload are a zone-operations decision = a
// human task)
const headersPath = join(distDir, "_headers");
const existing = existsSync(headersPath) ? readFileSync(headersPath, "utf8").trimEnd() : "";
if (/^\/\*\n {2}Content-Security-Policy:/m.test(existing)) {
  throw new Error(
    "_headers already has a /* CSP (double run?). Delete dist and redo from blume build",
  );
}
const securityBlock = `/*
  Content-Security-Policy: ${csp}
  X-Content-Type-Options: nosniff
  Referrer-Policy: no-referrer
  Strict-Transport-Security: max-age=31536000
`;
writeFileSync(headersPath, `${existing}${existing === "" ? "" : "\n\n"}${securityBlock}`);

const written = readFileSync(headersPath, "utf8");
if (!written.includes(`Content-Security-Policy: ${csp}`))
  throw new Error("failed to write _headers");

console.log(
  `postbuild: ${htmlFiles.length} pages — ${styleRules.size} style attribute(s) externalized, ` +
    `${scriptHashes.size} inline script hash(es), ${styleHashes.size} inline style hash(es), ` +
    "no external resource references; _headers written",
);
