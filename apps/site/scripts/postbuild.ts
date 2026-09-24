// `blume build` の後処理(裁定 D — docs/notes/web-design-pass.md §4「DP2 実装時の裁定録」)。
// 配信物(dist/)を Workers Static Assets 用に仕上げる。3 段:
//
//   1. **style 属性の外部化**: Blume の docs ページは Shiki のトークン(`style="--shiki-light:…"`)と
//      chrome の一部(サイドバーのインデント・CardGroup の列数)に inline `style` 属性を持つ。
//      属性の inline style は CSP のハッシュで許可できない(`'unsafe-hashes'` + 全属性値の列挙が要る)
//      ため、各属性値をクラス(`.sa-<hash>`)へ写像した 1 本の CSS ファイルに書き出し、HTML 側は
//      class 参照に置き換える(Shiki 公式の `transformerStyleToClass` と同じ手法を配信物に対して
//      行う — Blume はトランスフォーマを露出しないため)。結果、HTML に `style` 属性は残らない。
//   2. **CSP と inline ハッシュ**: `default-src 'none'` 基調、`'unsafe-inline'` は script にも style にも
//      使わない。Blume の chrome が持つ inline script(テーマ初期化 / ヘッダー操作 / ナビ / ClientRouter
//      のスタイル読み込み)と Astro Fonts API(`<Font>`)が必ず出す `@font-face` の `<style>` は内容が
//      決定的なので、配信物から収集した SHA-256 ハッシュで個別に許可する(apps/web/scripts/
//      write-headers.ts と同じ方式)。それ以外の inline style は blume.config.ts の integration
//      (`build.inlineStylesheets: 'never'`)で外部 CSS に固定してある。Blume のテーマトグルが
//      クリック時に挿す遷移抑制 `<style>` は固定文字列なので、実在を確認したうえでハッシュを加える。
//   3. **外部参照ゼロの機械検査と `_headers`**: 「言わざる」(CLAUDE.md §1-5)— 配信物の src / href が
//      外部を指さないことを検査し、Blume が出した `_headers`(.md / .txt の charset・トップの Link
//      ヘッダー)を保持したまま `/*` のセキュリティヘッダーを追記する。
// 違反はビルド失敗(throw)。検査は品質ゲート(CI の site ビルドステップ)の経路に載る。
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

// ---- 1. style 属性の外部化 ----
// script / style の本文(文字列として `style="` を含みうる)を避け、要素タグの中だけを書き換える
// 属性値の実体参照を戻す。&amp; は最後に畳む(&#39; 等の前半を先に変えないため)
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

// 属性値の 3 形(二重引用符・単一引用符・引用符なし) — 生成器が " 以外を出しても検査漏れしない
const ATTR_VALUE_PATTERN = String.raw`(?:"[^"]*"|'[^']*'|[^\s>]+)`;

/** 3 形のどれかに一致した最初のグループ(取りこぼしは "")。 */
const firstDefined = (...values: readonly (string | undefined)[]): string =>
  values.find((v) => v !== undefined) ?? "";

/** `name="..."` 属性の値(3 形対応)。無ければ undefined。 */
const attrValueOf = (attrs: string, name: string): string | undefined => {
  const m = new RegExp(String.raw`\b${name}\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`).exec(attrs);
  return m === null ? undefined : firstDefined(m[1], m[2], m[3]);
};

const styleRules = new Map<string, string>(); // class → declarations

/** 宣言列をクラス名へ写像する(ハッシュ衝突はビルド失敗)。空の style 属性は undefined。 */
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

/** className を既存 class 属性に併記(無ければ末尾に追加)。className が無ければそのまま。 */
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

/** タグの属性列を書き換える(style 属性の外部化 + class 差し込み)。style が無ければ undefined。 */
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
  if (rest === attrs) return undefined; // style 属性なし(置換は起きなかった)
  return mergeClass(rest, className);
};

function externalizeStyleAttributes(html: string): string {
  const segments = html.split(
    /(<script\b[^>]*>[\s\S]*?<\/script>|<style\b[^>]*>[\s\S]*?<\/style>)/,
  );
  return segments
    .map((segment, i) => {
      if (i % 2 === 1) return segment; // script / style ブロックはそのまま
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
    // 外部化したクラスを参照するページにだけ link を差す(Blume の他の stylesheet の後 = </head> 直前)
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

// ---- 2. inline ハッシュの収集と機械検査 ----
// JSON のデータブロック(型が JS でない script)は実行されないので CSP の対象外
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
  // インラインイベントハンドラ・javascript: URL は CSP で弾かれる = 機能欠落なのでビルド時に検知する
  if (/\son[a-z]+\s*=\s*(?:"|'|[^\s>])/i.test(html))
    throw new Error(`${file}: inline event handler attribute`);
  if (/javascript:/i.test(html)) throw new Error(`${file}: javascript: URL`);
  // 外部リソース参照の検査(コメントは除く — ロゴ SVG の由来コメントに URL がある)。href は
  // ナビゲーションなので自リポジトリの GitHub と製品オリジンのみ許可、読み込み系は同一オリジン限定
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
    // スキームも `//` も無い = 同一オリジンの相対参照
    if (!/^[a-z][a-z0-9+.-]*:/i.test(url) && !url.startsWith("//")) continue;
    externalRefs.push(`${relative(distDir, file)}: ${attr}="${url}"`);
  }
}

if (externalRefs.length > 0) {
  throw new Error(
    `external resource references in the built site (「言わざる」 — all assets are self-served):\n  ${externalRefs.join("\n  ")}`,
  );
}
if (scriptHashes.size === 0)
  throw new Error(
    "no inline scripts found — Blume の出力形式が変わった可能性。CSP 生成を見直すこと",
  );

// Blume のテーマトグル(Header.astro の inline script)が挿す遷移抑制スタイル。実体が配信物の
// inline script に含まれていることを確認してからハッシュを許可する(Blume 更新で変われば失敗する)
const themeToggleStyle = "*,*::before,*::after{transition:none!important}";
if (!inlineScriptBodies.some((body) => body.includes(themeToggleStyle))) {
  throw new Error(
    "Blume の theme toggle script に想定の遷移抑制スタイル文字列が無い(Blume の更新で変わった?)。" +
      "postbuild.ts の themeToggleStyle を実物に合わせること",
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

// Cloudflare の _headers は 1 行 2,000 文字が上限で、超過は黙って落ちる(セキュリティヘッダーの
// 無言の欠落)。ハッシュの集合は inline 本文の種類数で増えるため、上限をビルド失敗で守る
const HEADERS_LINE_LIMIT = 2000;
const cspLine = `  Content-Security-Policy: ${csp}`;
if (cspLine.length > HEADERS_LINE_LIMIT) {
  throw new Error(
    `_headers の CSP 行が ${cspLine.length} 文字で Cloudflare の上限 ${HEADERS_LINE_LIMIT} を超える。` +
      "inline script / style の種類が増えた(Blume の更新?)— ハッシュの集合を見直すこと",
  );
}

// Blume が出した _headers(/docs/*.md 等の charset・トップの Link ヘッダー)は保持し、`/*` の
// セキュリティヘッダーを追記する(同じパスに複数ブロックが一致しても、ヘッダー名が異なれば併記される)。
// HSTS は apex 単独(includeSubDomains / preload はゾーン運用側の判断 = 人間タスク)
const headersPath = join(distDir, "_headers");
const existing = existsSync(headersPath) ? readFileSync(headersPath, "utf8").trimEnd() : "";
if (existing.includes("Content-Security-Policy")) {
  throw new Error(
    "_headers に既に CSP がある(二重実行?)。dist を消して blume build からやり直すこと",
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
  throw new Error("_headers の書き込みに失敗");

console.log(
  `postbuild: ${htmlFiles.length} pages — ${styleRules.size} style attribute(s) externalized, ` +
    `${scriptHashes.size} inline script hash(es), ${styleHashes.size} inline style hash(es), ` +
    "no external resource references; _headers written",
);
