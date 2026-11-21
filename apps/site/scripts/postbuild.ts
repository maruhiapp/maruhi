import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";

const distDir = join(import.meta.dirname, "..", "dist");
const siteOrigin = "https://maruhi.app";

const htmlFiles = readdirSync(distDir, { recursive: true, encoding: "utf8" })
  .filter((name) => name.endsWith(".html"))
  .map((name) => join(distDir, name));
if (htmlFiles.length === 0) throw new Error(`no HTML in ${distDir} — run astro build first`);

const sha256base64 = (body: string): string =>
  `'sha256-${createHash("sha256").update(body, "utf8").digest("base64")}'`;
const shortHash = (body: string): string =>
  createHash("sha256").update(body, "utf8").digest("hex").slice(0, 10);

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

const ATTR_VALUE_PATTERN = String.raw`(?:"[^"]*"|'[^']*'|[^\s>]+)`;

const firstDefined = (...values: readonly (string | undefined)[]): string =>
  values.find((v) => v !== undefined) ?? "";

const attrValueOf = (attrs: string, name: string): string | undefined => {
  const m = new RegExp(String.raw`\b${name}\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`).exec(attrs);
  return m === null ? undefined : firstDefined(m[1], m[2], m[3]);
};

const styleRules = new Map<string, string>();

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
  if (rest === attrs) return undefined;
  return mergeClass(rest, className);
};

function externalizeStyleAttributes(html: string): string {
  const segments = html.split(
    /(<script\b[^>]*>[\s\S]*?<\/script>|<style\b[^>]*>[\s\S]*?<\/style>)/,
  );
  return segments
    .map((segment, i) => {
      if (i % 2 === 1) return segment;
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

const isJavaScriptType = (attrs: string): boolean => {
  const type = attrValueOf(attrs, "type");
  return type === undefined || type === "module" || /javascript/i.test(type);
};

const scriptHashes = new Set<string>();
const styleHashes = new Set<string>();
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
  }
  for (const m of html.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/g)) {
    const body = m[1] ?? "";
    if (body.length > 0) styleHashes.add(sha256base64(body));
  }
  if (/\son[a-z]+\s*=\s*(?:"|'|[^\s>])/i.test(html))
    throw new Error(`${file}: inline event handler attribute`);
  if (/javascript:/i.test(html)) throw new Error(`${file}: javascript: URL`);
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
    "no inline scripts found — Nimbus's output format may have changed. Revisit CSP generation",
  );

const csp = [
  "default-src 'none'",
  `script-src 'self' 'wasm-unsafe-eval' ${[...scriptHashes].toSorted().join(" ")}`,
  `style-src 'self' ${[...styleHashes].toSorted().join(" ")}`,
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "manifest-src 'self'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

const HEADERS_LINE_LIMIT = 2000;
const cspLine = `  Content-Security-Policy: ${csp}`;
if (cspLine.length > HEADERS_LINE_LIMIT) {
  throw new Error(
    `the _headers CSP line is ${cspLine.length} characters, over Cloudflare's limit of ${HEADERS_LINE_LIMIT}. ` +
      "The number of distinct inline scripts / styles grew (a Nimbus update?) — revisit the hash set",
  );
}

const headersPath = join(distDir, "_headers");
const existing = existsSync(headersPath) ? readFileSync(headersPath, "utf8").trimEnd() : "";
if (/^\/\*\n {2}Content-Security-Policy:/m.test(existing)) {
  throw new Error(
    "_headers already has a /* CSP (double run?). Delete dist and redo from astro build",
  );
}
const securityBlock = `/*
  Content-Security-Policy: ${csp}
  X-Content-Type-Options: nosniff
  Referrer-Policy: no-referrer
  Strict-Transport-Security: max-age=31536000
`;

const twinBlocks = readdirSync(distDir, { recursive: true, encoding: "utf8" })
  .filter((name) => name.endsWith(".md") || name.endsWith(".txt"))
  .toSorted()
  .map(
    (name) =>
      `/${name.replaceAll("\\", "/")}\n  Content-Type: ${name.endsWith(".md") ? "text/markdown" : "text/plain"}; charset=utf-8`,
  );
const linkBlock = `/\n  Link: </llms.txt>; rel="describedby"; type="text/plain", </llms-full.txt>; rel="describedby"; type="text/plain"`;
writeFileSync(
  headersPath,
  `${existing}\n\n${[linkBlock, ...twinBlocks, securityBlock].join("\n\n")}`,
);

const written = readFileSync(headersPath, "utf8");
if (!written.includes(`Content-Security-Policy: ${csp}`))
  throw new Error("failed to write _headers");

const HEADERS_RULE_LIMIT = 100;
const ruleCount = written.split("\n").filter((line) => line.startsWith("/")).length;
if (ruleCount > HEADERS_RULE_LIMIT) {
  throw new Error(
    `the _headers has ${ruleCount} rules, over Cloudflare's limit of ${HEADERS_RULE_LIMIT}. ` +
      "The shipped .md / .txt twins grew — consolidate the exact-path charset rules (e.g. back to splat patterns)",
  );
}

console.log(
  `postbuild: ${htmlFiles.length} pages — ${styleRules.size} style attribute(s) externalized, ` +
    `${scriptHashes.size} inline script hash(es), ${styleHashes.size} inline style hash(es), ` +
    "no external resource references; _headers written",
);
