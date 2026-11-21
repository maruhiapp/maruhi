import { getOgImagePages, getPageSection } from "@cloudflare/nimbus-docs/runtime";
import type { APIRoute, GetStaticPaths } from "astro";

import { renderPageCard } from "./_card";

export const prerender = true;

export const getStaticPaths = (async () =>
  Object.entries(await getOgImagePages()).map(([slug, page]) => ({
    params: { slug },
    props: { page },
  }))) satisfies GetStaticPaths;

type Page = NonNullable<Awaited<ReturnType<typeof getOgImagePages>>[string]>;

export const GET: APIRoute<{ page: Page }> = async ({ props: { page } }) => {
  const section = await getPageSection(page);
  return new Response(
    await renderPageCard({ ...(section !== undefined ? { section } : {}), title: page.title }),
    { headers: { "Content-Type": "image/png" } },
  );
};
