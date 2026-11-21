import { docsCollection, partialsCollection } from "@cloudflare/nimbus-docs/content";
import { z } from "astro/zod";
import { defineCollection } from "astro:content";

export const collections = {
  guide: defineCollection(
    docsCollection({
      base: "docs",
      schemaFields: {
        audience: z.literal("human").optional(),
        related: z.array(z.string()).optional(),
      },
    }),
  ),
  partials: defineCollection(partialsCollection()),
};
