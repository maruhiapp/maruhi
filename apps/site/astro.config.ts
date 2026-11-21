import nimbus, { defineConfig as defineNimbusConfig } from "@cloudflare/nimbus-docs";
import { tableScroll } from "@cloudflare/nimbus-docs/markdown";
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
  sidebar: {
    items: [{ autogenerate: { collection: "guide" } }],
  },
});

export default defineConfig({
  output: "static",
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
