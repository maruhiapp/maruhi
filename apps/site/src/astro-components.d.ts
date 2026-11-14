// Type shim for importing .astro components from TypeScript files (the
// MDX globals registry in src/components.ts and the ui/* barrels).
// Astro's compiler resolves these imports at build time, but
// `astro/client` declares no "*.astro" wildcard module, so the
// declaration lives here — the same shape astro's own content types
// use for MDX components.
declare module "*.astro" {
  import type { AstroComponentFactory } from "astro/runtime/server/index.js";

  const component: AstroComponentFactory;
  export default component;
}
