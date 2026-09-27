# ADR-0008: docs on Blume, landing on FunStack (Revision 1: landing also on Blume — LP + docs on apex `maruhi.app`)

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
