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
const decodeAttr = (value: string): string =>
  value
    .replaceAll("&quot;", '"')
    .replaceAll("&#39;", "'")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&amp;", "&");

const styleRules = new Map<string, string>(); // class → declarations

function externalizeStyleAttributes(html: string): string {
  const segments = html.split(
    /(<script\b[^>]*>[\s\S]*?<\/script>|<style\b[^>]*>[\s\S]*?<\/style>)/,
  );
  return segments
    .map((segment, i) => {
      if (i % 2 === 1) return segment; // script / style ブロックはそのまま
      return segment.replace(
        /<([a-zA-Z][\w:-]*)((?:\s+[^\s=>/]+(?:="[^"]*")?)*)\s*(\/?)>/g,
        (tag, name: string, attrs: string, selfClose: string) => {
          if (!/\sstyle="/.test(attrs)) return tag;
          let className: string | undefined;
          let rest = attrs.replace(/\sstyle="([^"]*)"/g, (_m, value: string) => {
            const declarations = decodeAttr(value).trim().replace(/;$/, "");
            if (declarations === "") return "";
            className = `sa-${shortHash(declarations)}`;
            const previous = styleRules.get(className);
            if (previous !== undefined && previous !== declarations) {
              throw new Error(`style attribute hash collision: ${className}`);
            }
            styleRules.set(className, declarations);
            return "";
          });
          if (className === undefined) return `<${name}${rest}${selfClose}>`;
          if (/\sclass="/.test(rest)) {
            rest = rest.replace(
              /\sclass="([^"]*)"/,
              (_m, classes: string) => ` class="${classes} ${className}"`,
            );
          } else {
            rest = `${rest} class="${className}"`;
          }
          return `<${name}${rest}${selfClose}>`;
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
    /\sstyle="/.test(
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
  const type = /\btype="([^"]*)"/.exec(attrs)?.[1];
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
    if (/\bsrc="/.test(attrs)) {
      const src = /\bsrc="([^"]*)"/.exec(attrs)?.[1] ?? "";
      if (!src.startsWith("/") || src.startsWith("//"))
        externalRefs.push(`${relative(distDir, file)}: <script src="${src}">`);
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
  if (/\son[a-z]+\s*=\s*["']/i.test(html))
    throw new Error(`${file}: inline event handler attribute`);
  if (/javascript:/i.test(html)) throw new Error(`${file}: javascript: URL`);
  // 外部リソース参照の検査(コメントは除く — ロゴ SVG の由来コメントに URL がある)。href は
  // ナビゲーションなので自リポジトリの GitHub と製品オリジンのみ許可、読み込み系は同一オリジン限定
  const withoutComments = html.replace(/<!--[\s\S]*?-->/g, "");
  for (const m of withoutComments.matchAll(/\b(src|href|srcset|poster|data|action)="([^"]*)"/g)) {
    const attr = m[1]!;
    const url = m[2]!;
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
