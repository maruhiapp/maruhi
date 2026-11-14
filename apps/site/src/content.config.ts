import { docsCollection, partialsCollection } from "@cloudflare/nimbus-docs/content";
// `z` re-exported from `astro:content` is deprecated; import it from
// `astro/zod` (the pattern nimbus-docs' own schema helpers document).
import { z } from "astro/zod";
import { defineCollection } from "astro:content";

export const collections = {
  // The collection is named `guide`, not `docs`: Nimbus 0.20 fixes the
  // primary `docs` collection at the site root, and maruhi serves its
  // docs under /docs (the route-folder mount in src/pages/docs/). A
  // non-primary collection mounts at its route's folder instead. The
  // files stay in src/content/docs (`base`).
  guide: defineCollection(
    docsCollection({
      base: "docs",
      schemaFields: {
        // Nimbus docs are agent-friendly by default. Set `audience: human`
        // to flag a page that's written primarily for human readers.
        audience: z.literal("human").optional(),
        // The "Related pages" cards at the foot of a docs page (carried
        // over from the Blume `related:` frontmatter): `/docs/<slug>`
        // links, rendered by src/pages/docs/[...slug].astro. Every page
        // but the index names 2–4 (test/unit/related-pages.test.ts).
        related: z.array(z.string()).optional(),
      },
    }),
  ),
  partials: defineCollection(partialsCollection()),
};
