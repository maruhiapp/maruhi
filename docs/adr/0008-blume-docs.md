# ADR-0008: docs on Blume, landing on FunStack (Revision 2: LP + docs on Nimbus — apex `maruhi.app`)

**Decision**: The documentation site is Blume (Astro-based; MCP / llms.txt / search / OpenAPI built in).
**Rationale**: A docs site's asset is its content (Markdown), not the framework, so migration cost is low — an "easy-to-change-later" decision. We take the current fastest zero-config, AI-ready option. Fumadocs is rejected for dragging in a meta-framework we have not adopted. In-house is rejected as undifferentiated labor.

## Revision 1 (2026-09-03): Landing also on Blume — apex `maruhi.app` = LP (`/`) + docs (`/docs`)

Status: 2026-09-03 owner ruling (docs/notes/web-design-pass.md §1-4 / §4). Accepted upon merge of the DP2 PR. The title's "landing is FunStack" is replaced by this revision (not a re-debate — a sync to the ruling).

**Decision**: The landing page (LP) is not FunStack (`apps/web`) but a **Blume custom page** (Astro `pages/index.astro`), placed in the same static site `apps/site` as docs. Served from apex `maruhi.app` (an independent Worker `maruhi-site` with Workers Static Assets only). Deployed separately from the product origin `my.maruhi.app` (dashboard = TCB). The `apps/docs` stub is absorbed into `apps/site`.

**Rationale**:
1. **TCB separation**: The LP is a marketing surface; colocating it on the dashboard origin would make every LP change a TCB release. A separate origin and a separate Worker let CSP strictness and change frequency each fit their site (the LP still honors "say nothing" — zero external scripts, external fonts, or trackers).
2. **One site, one deploy**: Putting the LP and docs in the same Blume project lets them share the theme (vermilion accent, warm neutrals, Archivo / Martian Mono), search, OG, and `llms.txt`, on a single domain (consolidated SEO). Blume officially supports this shape: `basePath: "/docs"` mounts docs at `/docs/*` and leaves the root to custom pages (verified live in DP2).
3. **Simplification on the FunStack side**: `apps/web` holds only the product (dashboard + ceremony pages), and `my.maruhi.app/` becomes a minimal guidance page. ADR-0007 (frontend is FunStack) is unchanged for the dashboard.

**Consequences**: `apps/site` depends on `blume` itself (plus wrangler / playwright / vitest for development). Because Blume bundles Astro / Tailwind / React / mermaid etc., node_modules is large, but the delivered static output only ships the JS that Blume's chrome requires. No Tailwind / StyleX / Astryx React parts are brought into the LP (the three layers in web-design-pass.md §4). If the LP ever needs to be built outside Blume, it is presented as a further revision of this ADR.

## Revision 2 (2026-11-14): LP + docs on Nimbus

Status: 2026-11-13 owner direction (replace Blume with Nimbus); accepted upon merge of the PR containing this revision. The framework named by the original decision and Revision 1 is replaced; the shape they decided (one static site on apex `maruhi.app`, LP `/` + docs `/docs`, separate Worker `maruhi-site`, Workers Static Assets, deployed via `cf` from `apps/site/cloudflare.config.ts`) is unchanged.

**Decision**: `apps/site` is built with Cloudflare Nimbus (`@cloudflare/nimbus-docs` 0.20.0 on Astro 7). The scaffold's site source (components, layouts, styles, routes) is generated once and owned in the repository under `apps/site/src/`; the framework logic ships as the pinned integration. The LP is a custom page on the site's BaseLayout at `/`; the docs content (MDX in `src/content/docs/`) is served at `/docs/*`. `scripts/postbuild.ts` keeps its three stages (style-attribute externalization, CSP hash collection, zero-external-reference check + `_headers`), unchanged in contract.

**Rationale**:
1. **The Blume subtree cost more than it returned.** Blume's transitive closure was ≈608 of the repo lockfile's ≈1,706 packages (≈36%) — Astro, the old MCP SDK (→ Hono / express), Scalar, Mermaid, Shiki, Orama, epub-gen, KaTeX, sharp, Tailwind — while maruhi uses only static generation plus search (its MCP server and API features are off). It was also the sole source of a recurring audit-fix class: advisories in packages maruhi never runs (PR #456 for Hono, PR #459 for Astro, both build-time only). Nimbus's tree is smaller, and its MCP dependency is the new `@modelcontextprotocol/server` (no Hono / express).
2. **The ownership model caps the downside.** Nimbus scaffolds the site's source into the repo instead of importing a theme at runtime. If Nimbus stalls, what remains is a plain Astro site we own outright — the original decision's premise ("the asset is the content; the framework is easy to change later") applied to the framework itself.
3. **Agent surfaces are first-class build outputs.** `/llms.txt`, `/llms-full.txt`, raw Markdown twins of every page, JSON-LD and prose lint / MDX validation (`nimbus-docs lint`, replacing `blume validate` in CI) are built in — matching how this repo's docs are actually written and consumed (by agents, under the PR rule).
4. **Pre-1.0 risk is the ADR-0011 class.** Nimbus is 0.20.0 with breaking minors possible; it is pinned exactly, the blast radius is one static site, and the fallback is the owned Astro source (rationale 2).

**Consequences**:
- The `blume` dependency is removed (≈1,000 lockfile lines net). The site-only audit-fix PR class disappears with the subtree.
- Docs mounting: Nimbus 0.20 fixes the primary `docs` collection at the site root; a non-primary collection mounts at its route file's folder. The content collection is therefore named `guide` (its files stay in `src/content/docs/`) and is served from `src/pages/docs/[...slug].astro`. If a future Nimbus release supports mounting the primary collection, renaming back is a contained change.
- Agent-surface URL changes: a page's raw Markdown twin is now `/docs/<slug>/index.md` (was `/docs/<slug>.md`); the apex `/llms.txt` points at the section document `/docs/llms.txt`, which lists the pages; JSON-LD no longer carries `dateModified`. "Last updated" now derives from the git **author** date (Blume used the committer date).
- Carried over as site-owned code, no longer framework features: the `related:` frontmatter (resolved and rendered by the docs route + DocsLayout), the site-wide private-preview banner, and the footer copyright line.
- Search moves from Orama to Pagefind (the Nimbus default). The brand theme is still generated from `apps/web/theme/maruhi.css`, now mapped onto Nimbus's `--nb-*` tokens in `src/styles/brand.css`.
- The two Blume agent skills (`.agents/skills/blume*`) are removed with the framework.
