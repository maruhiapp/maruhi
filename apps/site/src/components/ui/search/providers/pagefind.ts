import { mergeSearchIndexes } from "@cloudflare/nimbus-docs/client";
import type { SearchProvider, SearchResult } from "@cloudflare/nimbus-docs/types";
import { config, searchIndex } from "virtual:nimbus/config";

interface PagefindSubResult {
  title?: string;
  url?: string;
}

interface PagefindResultData {
  url: string;
  excerpt?: string;
  meta?: { title?: string };
  sub_results?: PagefindSubResult[];
}

interface PagefindSearchResponse {
  results: Array<{ data(): Promise<PagefindResultData> }>;
}

interface PagefindFilters {
  [key: string]: string | string[] | { none?: string | string[]; any?: string | string[] };
}

interface PagefindApi {
  init(): Promise<void>;
  options(options: { baseUrl?: string }): Promise<void>;
  mergeIndex(indexPath: string, options?: { baseUrl?: string }): Promise<void>;
  search(query: string, options?: { filters?: PagefindFilters }): Promise<PagefindSearchResponse>;
}

let pagefind: PagefindApi | undefined;

const excludeDeprecated: PagefindFilters | undefined =
  config.versions && config.versions.deprecated && config.versions.deprecated.length > 0
    ? { status: { none: "deprecated" } }
    : undefined;

function filtersForPage(): PagefindFilters | undefined {
  const deprecated = document.querySelector('[data-pagefind-filter="status:deprecated"]');
  const version = document
    .querySelector('[data-pagefind-filter^="version:"]')
    ?.getAttribute("data-pagefind-filter")
    ?.slice("version:".length);
  if (deprecated && version) return { version };
  return excludeDeprecated;
}

export const provider: SearchProvider = {
  async init() {
    if (pagefind) return;
    const pagefindUrl = new URL(`${searchIndex.bundle}pagefind.js`, window.location.origin);
    const loaded = (await import(/* @vite-ignore */ pagefindUrl.href)) as PagefindApi;
    const baseUrl = `${(import.meta.env.BASE_URL ?? "/").replace(/\/+$/, "")}/`;
    await loaded.options({ baseUrl });
    await loaded.init();
    await mergeSearchIndexes(loaded, searchIndex.merge, { baseUrl });
    pagefind = loaded;
  },

  async search(query) {
    if (!pagefind) await this.init?.();
    if (!pagefind) return [];

    const filters = filtersForPage();
    const search = await pagefind.search(query, filters ? { filters } : undefined);
    const results = await Promise.all(search.results.slice(0, 10).map((result) => result.data()));
    return results.map((result): SearchResult => {
      const subResults = result.sub_results
        ?.filter((sub): sub is Required<PagefindSubResult> => Boolean(sub.title && sub.url))
        .map((sub) => ({ title: sub.title, url: sub.url }));
      return {
        title: result.meta?.title ?? "Untitled",
        url: result.url,
        ...(result.excerpt !== undefined ? { snippet: result.excerpt } : {}),
        ...(subResults !== undefined ? { subResults } : {}),
      };
    });
  },
};
