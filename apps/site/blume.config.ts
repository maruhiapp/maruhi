// The apex `maruhi.app` static site = LP (`/`) + docs (`/docs/*`). Blume only
// (ADR-0008 revision 1, docs/notes/web-design-pass.md §4). Deployed
// separately from the product origin `my.maruhi.app` (TCB).
//
// Styling has only 3 layers: (1) these theme tokens (values are theme/
// tokens.ts and theme.css generated from apps/web/theme/maruhi.css — ruling
// B) (2) the LP custom page's (pages/index.astro) scoped <style> (plain CSS,
// values reference CSS variables) (3) docs use the Blume default. No
// Tailwind / StyleX / Astryx React parts.
//
// "Say nothing": no analytics are declared (Blume injects nothing when
// undeclared). Ask AI / MCP are off (the default). Fonts are local woff2
// (self-hosted via the Astro Fonts API — replacing the default Google Fonts
// build-time fetch). Open in chat (links to third-party AI) is off.
import { defineConfig } from "blume";

import { accent, background, border, foreground, mutedForeground } from "./theme/tokens.ts";

/**
 * Integration that pins Astro's `build.inlineStylesheets` to 'never'
 * (ruling D). The default 'auto' inlines styles under 4 kB into HTML <style>,
 * which is incompatible with `style-src 'self'`. Blume does not expose Astro
 * config directly but `integrations` passes through, so it is updated in the
 * integration's `astro:config:setup`.
 * (Blume evaluates config twice, so the integration's factory has no side
 * effects)
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
  "Diskless, end-to-end encrypted secrets manager on Cloudflare. Self-hostable with a single cf deploy.";

export default defineConfig({
  title: "maruhi",
  description,
  // Header brand: a bespoke SVG of ㊙. light is the original vermilion
  // #C1330B; dark is a generated file with fill swapped to the dark accent
  // (scripts/build-theme.ts). The wordmark is text
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
  // docs are served under `/docs/*`; the site root is owned by the LP
  // (pages/index.astro)
  basePath: "/docs",
  github: { owner: "maruhiapp", repo: "maruhi", dir: "apps/site" },
  integrations: [noInlineStylesheets()],
  theme: {
    accent: { light: accent.light, dark: accent.dark },
    background: { light: background.light, dark: background.dark },
    radius: "md",
    // Follows the system (web-design-pass.md §1-2). The docs header toggle
    // stays at the Blume default
    mode: "system",
    // Archivo (headings and body, variable wdth 62-125% / wght 100-900) +
    // Martian Mono (code, variable wght). Fontsource Latin-subset woff2 (same
    // originals as Google Fonts). The full OFL text is in
    // public/fonts/OFL-*.txt
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
    // llms.txt / raw Markdown / Copy as Markdown are self-hosted static
    // files, so they stay at the default. Open in chat (links to ChatGPT /
    // Claude etc.) is not offered — it is a channel to third parties. Ask AI
    // and MCP would become live external calls / resident endpoints, so they
    // are explicitly off (Blume 1.7's default is also off; do not let a
    // future default change silently enable them). The JSON docs API and AI
    // catalog are static indexes of the public docs (same kind as llms.txt)
    // and are not sent anywhere beyond the build output; they are kept
    // intentionally — they became default-on in Blume 1.7.
    openInChat: false,
    ask: { enabled: false },
    mcp: { enabled: false },
    api: true,
    catalog: true,
  },
  seo: {
    // OG cards are rendered locally at build time (no external calls). The
    // LP uses og.png
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
