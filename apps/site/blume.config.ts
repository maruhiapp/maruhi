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
// undeclared). The assistant / MCP are off. Fonts are local woff2
// (self-hosted via the Astro Fonts API — replacing the default Google Fonts
// build-time fetch). Open in chat (links to third-party AI) is off.
import { defineConfig } from "blume";
import { orama } from "blume/search";

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
    // Absolute: Blume 2 mounts a root-relative banner link under basePath
    // unless it exactly names a custom page route, and `/#access` (with its
    // fragment) does not, so it would become `/docs/#access`. The docs body
    // links to the LP the same way
    link: { text: "How to get access", href: "https://maruhi.app/#access" },
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
  // Local Orama search (self-hosted index, no hosted service). Pinned
  // explicitly so a future default change cannot silently switch providers.
  search: orama(),
  ai: {
    // Open in chat (links to ChatGPT / Claude etc.) is not offered — it is a
    // channel to third parties. The assistant (Ask AI in Blume 1) would
    // become a live external call, so it is explicitly off (do not let a
    // future default change silently enable it).
    openInChat: false,
    assistant: { enabled: false },
  },
  agents: {
    // llms.txt / raw Markdown / Copy as Markdown are self-hosted static
    // files, so they stay at the default. MCP would become a resident
    // endpoint, so it is explicitly off. The JSON docs API and AI catalog
    // are static indexes of the public docs (same kind as llms.txt) and are
    // not sent anywhere beyond the build output; they are kept
    // intentionally — they became default-on in Blume 1.7.
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
  // Static build on any host (Blume 2: the `{ site, base }` form IS the
  // static deployment — host adapters like `cloudflare()` switch to server
  // output). Served via the cf Workers Static Assets deploy.
  deployment: {
    site: "https://maruhi.app",
  },
});
