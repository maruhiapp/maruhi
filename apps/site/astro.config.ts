import nimbus, { defineConfig as defineNimbusConfig } from "@cloudflare/nimbus-docs";
import { tableScroll } from "@cloudflare/nimbus-docs/markdown";
// The apex `maruhi.app` static site = LP (`/`) + docs (`/docs/*`). Nimbus
// (ADR-0008 revision 2). Deployed separately from the product origin
// `my.maruhi.app` (TCB).
//
// The docs collection is mounted at `/docs` by its route folder
// (src/pages/docs/[...slug].astro); the site root is owned by the LP
// (src/pages/index.astro).
//
// "Say nothing": no analytics, no trackers, no external requests. Fonts are
// local woff2 (public/fonts, self-hosted — see src/styles/brand.css). The
// remote MCP server stays off (the site is static; `agents.mcp` defaults
// to false), and search is the local Pagefind index.
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "astro/config";

const description =
  "Diskless, end-to-end encrypted secrets manager on Cloudflare. Self-hostable with a single cf deploy.";

const nimbusConfig = defineNimbusConfig({
  site: "https://maruhi.app",
  title: "maruhi",
  description,
  locale: "en",
  github: "https://github.com/maruhiapp/maruhi",
  editPattern: "https://github.com/maruhiapp/maruhi/blob/main/apps/site/{path}",
  socialImage: "/og.png",
  socialImageAlt:
    "The maruhi mark (the kanji for 'secret' in a vermilion circle) next to the word maruhi",
  // The docs index leads the sidebar; every other page joins it in
  // `sidebar.order` frontmatter order.
  sidebar: {
    items: [{ autogenerate: { collection: "guide" } }],
  },
});

export default defineConfig({
  output: "static",
  // Ruling D: stylesheets are never inlined into HTML — the CSP is
  // `style-src 'self'` (scripts/postbuild.ts allows the few deterministic
  // inline scripts and styles by hash).
  build: { inlineStylesheets: "never" },
  vite: {
    plugins: [tailwindcss()],
  },
  prefetch: {
    prefetchAll: true,
    defaultStrategy: "hover",
  },
  integrations: [
    nimbus(nimbusConfig, {
      // The load-bearing authoring rules: frontmatter must validate
      // against the content schema, and broken internal links are 404s
      // for readers. `bun run validate` runs them in CI.
      rules: {
        "nimbus/frontmatter-shape": "error",
        "nimbus/internal-link": "error",
      },
      markdown: {
        hastPlugins: [tableScroll()],
        features: { headingAttributes: true },
      },
    }),
  ],
});
