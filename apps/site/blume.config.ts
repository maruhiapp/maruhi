// apex `maruhi.app` の静的サイト = LP(`/`)+ docs(`/docs/*`)。Blume 一本(ADR-0008 改訂 1、
// docs/notes/web-design-pass.md §4)。製品オリジン `my.maruhi.app`(TCB)とは別デプロイ。
//
// スタイリングは 3 層のみ: (1) この theme tokens(値は apps/web/theme/maruhi.css から生成した
// theme/tokens.ts と theme.css — 裁定 B)(2) LP のカスタムページ(pages/index.astro)の scoped
// <style>(素の CSS、値は CSS 変数参照)(3) docs は Blume 既定。Tailwind / StyleX / Astryx の
// React 部品は入れない。
//
// 「言わざる」: analytics は宣言しない(Blume は無宣言なら何も注入しない)。Ask AI / MCP は
// off(既定)。フォントはローカル woff2(Astro Fonts API 経由で自己配信 — 既定の Google Fonts
// ビルド時取得を置き換える)。Open in chat(第三者 AI へのリンク)は off にする。
import { defineConfig } from "blume";

import { accent, background, border, foreground, mutedForeground } from "./theme/tokens.ts";

/**
 * Astro の `build.inlineStylesheets` を 'never' に固定する統合(裁定 D)。既定 'auto' は 4 kB 未満の
 * スタイルを HTML の <style> にインライン化し、`style-src 'self'` と両立しない。Blume は Astro 設定を
 * 直接露出しないが `integrations` は透過するので、統合の `astro:config:setup` で更新する。
 * (Blume は config を 2 回評価するため、統合のファクトリは副作用を持たない)
 */
const noInlineStylesheets = () => ({
  name: "maruhi-no-inline-stylesheets",
  hooks: {
    "astro:config:setup": ({ updateConfig }: { updateConfig: (config: object) => void }) => {
      updateConfig({ build: { inlineStylesheets: "never" } });
    },
  },
});

const description =
  "Diskless, end-to-end encrypted secrets manager on Cloudflare. Self-hostable with a single wrangler deploy.";

export default defineConfig({
  title: "maruhi",
  description,
  // ヘッダーのブランド: ㊙ の自前 SVG(DP1)。light は朱 #C1330B の原本、dark は fill を dark accent に
  // 差し替えた生成物(scripts/build-theme.ts)。ワードマークはテキスト
  logo: {
    image: { light: "/logo.svg", dark: "/logo-dark.svg", alt: "maruhi" },
    text: "maruhi",
    href: "/",
  },
  banner: {
    content: "maruhi is in private preview. Sign-up is invite-only for now.",
    link: { text: "How to get access", href: "/#access" },
    dismissible: true,
    id: "private-preview",
  },
  // docs は `/docs/*` に載せ、サイトのルートは LP(pages/index.astro)が持つ
  basePath: "/docs",
  github: { owner: "maruhiapp", repo: "maruhi", dir: "apps/site" },
  integrations: [noInlineStylesheets()],
  theme: {
    accent: { light: accent.light, dark: accent.dark },
    background: { light: background.light, dark: background.dark },
    radius: "md",
    // システム追従(web-design-pass.md §1-2)。docs のヘッダートグルは Blume 既定のまま
    mode: "system",
    // Archivo(見出し・本文、可変 wdth 62〜125% / wght 100〜900)+ Martian Mono(コード、可変 wght)。
    // Fontsource の Latin サブセット woff2(Google Fonts と同じ原本)。OFL 全文は public/fonts/OFL-*.txt
    fonts: {
      display: {
        name: "Archivo",
        variants: [{ src: "./public/fonts/archivo-latin-wdth-normal.woff2", weight: "100..900" }],
      },
      body: {
        name: "Archivo",
        variants: [{ src: "./public/fonts/archivo-latin-wdth-normal.woff2", weight: "100..900" }],
      },
      mono: {
        name: "Martian Mono",
        variants: [
          { src: "./public/fonts/martian-mono-latin-wght-normal.woff2", weight: "100..800" },
        ],
      },
    },
  },
  search: { provider: "orama" },
  ai: {
    // llms.txt / raw Markdown / Copy as Markdown は自己配信の静的物なので既定のまま。
    // Open in chat(ChatGPT / Claude 等へのリンク)は第三者への導線なので置かない
    openInChat: false,
  },
  seo: {
    // OG カードはビルド時にローカルで描画される(外部通信なし)。LP は DP1 の og.png を使う
    og: {
      logo: "/logo.svg",
      palette: {
        accent: accent.dark,
        background: background.dark,
        foreground: foreground.dark,
        muted: mutedForeground.dark,
        border: border.dark,
      },
    },
    rss: { enabled: false },
  },
  deployment: {
    output: "static",
    site: "https://maruhi.app",
  },
});
