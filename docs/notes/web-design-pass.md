# web-design-pass — rulings for the DP series (design pass)

Status: drafted 2026-09-03, owner-ruled (the premises of DP1 / DP2). The design document for ROADMAP.md's "DP series".
Each of DP1–DP5's PRs implements this document as the source of truth; if something changes, revise this file first.

Premise disciplines (unchanged):

- **ADR-0013**: changes to appearance go in the order ① defineTheme (tokens · variants) → ② Astryx components'
  `xstyle` → ③ composition in `ui.package` → ④ custom in `ui.package` → ⑤ upstream. No `swizzle`, no `className` /
  inline `style`, raw hex only in theme definitions
- **ADR-0018**: the Web holds no keys or plaintext (read + revocation kinds only). Value and key operations are the CLI's
- **The TCB rule (CLAUDE.md)**: no third-party scripts, CDNs, external fonts, or analytics on the dashboard origin
  (`my.maruhi.app`). Strict CSP
- **"Never-tell"**: no client → external transmissions. Applies to the LP too (§5)

## 1. Owner rulings (2026-09-03)

| # | Topic | Ruling |
|---|---|---|
| 1 | Logo & colors | **㊙ becomes the logo** — not the emoji but **our own SVG** (the circle + 秘; the glyph is converted to paths from an OFL CJK font [Noto Sans CJK / Source Han]). **The accent color code matches the SVG's red**; it doesn't follow emoji vendors' colors (our SVG is the source of truth; the emoji is an approximation). The red's **saturation is not reduced** (Hanko's deep-red examples). The direction is **vermilion (an orange-leaning red)**, separated from danger (a crimson family) by hue. In text contexts (CLI output, README headings) keep using the ㊙ emoji <!-- english-exempt: references the 秘 brand-glyph character --> |
| 2 | Dark mode | **System-following, both modes** (`defineTheme`'s `[light, dark]` tuple = CSS `light-dark()`). No manual toggle (don't add a place state is saved). The design is **created dark-first**. Custom customization is minimal (accent seed, neutral `warm`), **staying close to Astryx defaults**. Fine color tweaks can come later via `tokens` overrides |
| 3 | Fonts | **The dashboard (`my.maruhi.app` — the TCB) uses Astryx defaults (system fonts)**: body / heading = `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, …`, code = `"SF Mono", Monaco, Consolas, monospace`. No web fonts are loaded (zero bytes). Self-hosting a monospace (0/O, 1/l disambiguation) is **added only if real-device checks at DP3 / DP4 show a problem**. Confirmation-code readability is guaranteed not by the font but by the **character set** (excluding ambiguous characters) — DP4 checks the existing generation rules. **The LP / docs (apex — not the TCB) use 2 self-hosted variable fonts (added 2026-09-03)**: headings & body = **Archivo** (SIL OFL, weight 100–900, width 62–125% — the ultra-bold / wide headings are made with this width axis), code = **Martian Mono** (SIL OFL, variable). Reference = bun.com self-hosts the same 2 families (a font choice is not an imitation of design). woff2, `font-display: swap`, drop italic if unneeded. No external CDN (§1-5). **The OFL's distribution obligations (copyright notice + the full license text bundled; both families have no Reserved Font Name declared, so subset versions may keep the original name) are covered in §4**. The families' look is checked next to the logo SVG at DP2, and can be swapped to Geist / Inter if they don't fit |
| 4 | LP & docs placement | **The LP is served on apex `maruhi.app` as an independent static site** (separate from the product origin `my.maruhi.app` = TCB separation). **docs is `maruhi.app/docs`** (a path inside the same static site. SEO consolidation, 1 deploy, 1 URL). `maruhi.dev` stays registered and **301s to `maruhi.app`** (defensive hold). LP / docs are stood up under **their own wrangler config**, shaped so O9 (the Alchemy v2 migration) can wrap them into declarations later |
| 5 | Analytics | **None**. Make it a selling point ("this site has no trackers"). Visit counts come only from **Cloudflare Web Analytics's server-side aggregation** (no script injection, no cookies, zone-level HTTP aggregation). Forms like the waitlist only POST to Workers; no third-party SaaS in between |
| 6 | Ordering vs O9 | **O9 (Alchemy v2 migration) comes after DP**. DP is the beta gate; O9 is optional. If DP2 puts LP / docs on their own wrangler config, the migration cost is the same |

## 2. Tone direction (reference sites — without over-fitting)

The owner's references: [WorkOS](https://workos.com/) (enterprise feel), [Resend](https://resend.com/) (a growing
developer product), [Phase](https://phase.dev/) and [Shelve](https://www.shelve.cloud/) (competitors — a
security-focused impression). **Prioritize finishing with Astryx components over forcing a fit**. Common elements:

- Dark-based. neutrals are almost monochrome; **one accent color** used very sparingly (buttons, links, one emphasis)
- **Code / terminal is the star**: the hero carries the install command and CLI output, explaining the product by
  "the command you type and the result that comes back" rather than UI screenshots. maruhi is "Everything happens
  in the CLI" so this shape fits
- Generous whitespace, restrained decoration (gradients, illustrations). The enterprise feel comes from **how little
  decoration there is and how well information is aligned**
- Security is conveyed not by frightening but by "plainly describing the mechanism" (E2EE, zero-knowledge,
  open-source, self-hostable)

maruhi-specific differentiators: the vermilion ㊙ mark (competitors are blue–purple–green), "diskless", "never-tell
(zero telemetry)", one-shot self-host (`wrangler deploy`), zero-knowledge operations.

## 3. DP1 brand foundation — deliverables

- `apps/web/theme/maruhi.ts`: the accent seed to the settled vermilion value (derive light / dark in HCT — leave it
  to Astryx's accent generation; if needed raise only the dark side's lightness via the `[light, dark]` tuple).
  neutral `warm` kept. typography / radius stay default
- The logo SVG (static assets under `apps/web/public/` etc. + for the LP): ㊙'s circle and 秘. <!-- english-exempt: 秘 is the literal glyph referenced --> A single-color version
  (accent) and an inverted version. favicon (SVG + PNG fallback), OG image (1200×630, ㊙ + `maruhi` on dark)
- danger/accent contrast check (revoke/delete buttons are also distinguished by shape via Astryx's danger variant)
- Raw hex exists only in the theme definition and the SVG (ADR-0013)

### DP1 implementation-time ruling record (2026-09-03)

Each ruling point was decided by the loop "enumerate ≥3 options → search for upward compat / a silver bullet →
iterate until no new options → select". Judgment criteria: staying in a shallow layer of ADR-0013's evaluation order,
the TCB rules and minimal dependencies, few generated artifacts, cheap reversibility. Numbers were computed with
Astryx 0.5.2's HCT implementation (`@astryxdesign/core/src/theme/hct.ts` — actually CIELAB LCh; "HCT" below) and
`contrast.ts`.

**A premise correction (a fact found during implementation)**: `defineTheme`'s `color.accent` derives
`--color-accent` **tone-pinned** to `light-dark(P[40], P[80])` (`expandColorScale.ts`). The `[light, dark]` tuple
only swaps each scheme's palette's **hue and saturation** — the dark side always lands at tone 80 (pastel,
saturation ≈ 31). So §3's opening "raise only the dark side's lightness via the tuple" doesn't work, and the settled
vermilion values are made explicit in `tokens` (ruling A). **The reason for making them explicit isn't saturation
itself** (owner 2026-09-03: "don't reduce the saturation" is not an absolute condition; a pastel that's not odd is
fine): (1) the derived dark accent `#FFB3A8` sits ΔE76 = 10.5 from neutralTheme's dark error `#FFC6C1` with 1.15:1
mutual contrast — links and error text look the same color (§1-1's "separate from danger by hue" breaks in dark).
(2) It's ΔE76 = 58 from the brand red `#C1330B`, so the ㊙ logo and the accent on the same screen look like different
colors (the explicit `#FF693C` is ΔE76 = 19). Astryx's own default dark accent (`#2694FE`) is also around tone 60 —
tone 80 is just the generic generator's choice. Comparison images are attached to PR #146.

**A. How the accent and the SVG's red are matched** — options: (i) set only the seed and let the SVG follow the
derived value / (ii) pin `--color-accent` via `tokens` and sync `--color-on-accent` by hand / (iii) back-solve the
seed so the derivation lands on the target / (iv) combine the seed tuple + `tokens` (upward compat) / (v) leave the
accent to the derivation and make the SVG `currentColor`, eliminating the very problem of "matching" (the silver
bullet candidate). **Selected = (iv)**: with `color.accent: [vermilionL, vermilionD]` the warm neutral's hue and the
derived palette are aligned to vermilion, and `tokens` then overrides just the 2 tokens `--color-accent` and
`--color-on-accent` with the settled values. The SVG's red = the light side's `--color-accent` (`#C1330B`), which
appears verbatim in the generated CSS (the e2e "matches the generated CSS" contract still passes). Rejected: (i)
makes dark pastel, violating §1-1. (iii): light's tone 40 can be back-solved but dark's tone 80 can't. (ii) alone
leaves neutral's hue seed-derived (the combination fixes that). (v) can't remove the "matching" since favicon / OG
need a fixed color (partially adopted as the monochrome `logo-mono.svg` — `currentColor` inherits the context's text
color for inline `<svg>` / CSS mask use; referenced via `<img>` it draws black). The `--color-on-accent` override is
because the value baked from the seed
is needed because the dark side `P[20]` (`#780000`) reaches only 4.1:1 over vermilion-D, short of AA (the explicit
value `#241915` = warm neutral tone 10 = the same value as the derived dark surface. 6.0:1).

**B. The vermilion's concrete values and its separation from danger** — candidates were varied by hue (tones pinned
at light 44 / dark 63 for comparison. light 44 is the ceiling that still holds 4.9:1 for link text on the warm body
`#FFEDE7`; dark 63 holds 4.6:1 on the popover `#3A2E29` while keeping saturation 76):

| # | Option | light | HCT | dark | HCT | Δhue vs `--color-error`(H28) | L: on body / on surface / white on accent | D: on body / on surface / on-accent on accent |
|---|---|---|---|---|---|---|---|---|
| B0 | Status quo (`#C73E3A` seed → derived) | `#B22A2B` | H32 C63 T40 | `#FFB3A8` | H33 C31 T80 | 3.8° | 5.7 / 6.3 / 6.4 | 11.0 / 10.0 / 10.0 |
| B1 | Pigment vermilion (vermilion pigment family) | `#C92621` | H36 C76 T44 | `#FF6551` | H36 C71 T63 | 7.8° | 4.9 / 5.4 / 5.6 | 6.5 / 5.9 / 5.9 |
| **B2** | **Vermilion (orange-leaning) — adopted** | **`#C1330B`** | H44 C76 T44 | **`#FF693C`** | H44 C76 T63 | **15.8°** | 4.9 / 5.5 / 5.6 | 6.6 / 6.0 / 6.0 |
| B3 | Vermilion (JIS-shuiro-leaning) | `#BA3E00` | H49 C73 T44 | `#F77027` | H52 C78 T63 | 21.0° | 4.9 / 5.4 / 5.6 | 6.6 / 6.0 / 6.0 |
| B4 | Silver vermilion / ink-pad family | `#CF1033` | H27 C76 T44 | `#FF6366` | H27 C67 T63 | 1.0° | 4.9 / 5.4 / 5.6 | 6.5 / 5.9 / 5.9 |

**Selected = B2**. It sits 16° away in hue from danger (`--color-error` = `#A50C25` / `#FFC6C1`, the neutralTheme's
crimson) (ΔE76 = 24 light / 59 dark), while staying in a range still readable as "red". B3 is close to JIS's vermilion
but leans too orange, weakening the "red seal" impression. B1's 8° separation is insufficient. B4 shares danger's
hue (rejected). B0 is pastel in dark (violates §1-1) and separates only 4°. **The vermilion's final hex is the one
point needing owner confirmation** — they can direct a swap to B1 / B3 on the PR (the 2 constants in
`theme/maruhi.ts` + the SVG's fill + regeneration).

**C. The tool for converting the 秘 glyph to paths** <!-- english-exempt: literal glyph name --> — options: (i) run Python fontTools once in /tmp / (ii) a
devDependency like opentype.js / (iii) the font's SVG table or manual extraction / (iv) `<text>` + embedded font
(no path conversion) / (v) extract the ㊙ glyph from an emoji font. **Selected = (i)**. The deliverable is only the
SVG; the tool doesn't stay in the repo (minimal dependencies, doesn't grow the supply chain). The procedure is
recorded reproducibly: `NotoSansCJKjp-Bold.otf` (notofonts/noto-cjk v2.004)'s U+79D8 is converted to a path with
`fontTools`' `SVGPathPen` + `TransformPen` (y-flip) and placed in a 1000×1000 viewBox (E below). Rejected: (ii) adds
a devDependency for a one-time extraction. (iii): Noto CJK has no SVG table and manual extraction isn't reproducible.
(iv) is font delivery = adding a web font (violates §1-3). (v) depends on an emoji glyph's colors and license
(against §1-1's spirit). The chosen font is Noto Sans CJK JP (OFL 1.1, © 2014-2021 Adobe) — same source outlines as
Source Han Sans; Noto's distribution form is simpler.

**D. favicon / OG formats and generation** — formats: favicon = `favicon.svg` (inverted = a vermilion disc with the
glyph knocked out white) + PNG 32 / 192 + `apple-touch-icon.png` 180 (iOS fills transparency with black, so an
opaque dark body-color ground). OG = `og.png` 1200×630 (㊙ + `maruhi` on dark body `#1B0D07`. The wordmark is also
the same font's Latin glyphs converted to paths, so the raster doesn't depend on the environment's fonts).
Rasterization options: (i) resvg / sharp as devDependencies / (ii) a one-off ImageMagick etc. / (iii) **screenshot
the SVG with the existing devDependency Playwright Chromium** (upward compat: zero new dependencies, the same
renderer as e2e) / (iv) no PNG, SVG only (impossible — iOS and OG scrapers don't support SVG). **Selected = (iii)**,
run as a one-off script and commit only the PNGs. `<head>` gains `description`, `icon` (svg / png),
`apple-touch-icon`, `og:*`, `twitter:card=summary_large_image` (English — ADR-0017). **The OG absolute URL**:
options = write the hosted origin statically / a relative URL (some scrapers don't resolve it — impossible) / a
build-time env var / the Worker rewriting at request time (against the static-shell principle). **Selected =
build-time env var `MARUHI_WEB_ORIGIN`, default `https://my.maruhi.app`** (`Root.tsx` is a build-time RSC so it can
read `process.env`. Self-hosters specify their deploy URL — one line in SELF_HOSTING.md). CSP unchanged (everything
self-hosted, within `img-src 'self'`).

**E. The circle-to-glyph proportions** — options (in 1000 units): (a) faithful to the ㊙ glyph (ring 40, glyph 66%) /
(b) seal-style (ring 64, glyph 60–62%) / (c) favicon-optimized (ring 80, glyph 64%) / (d) the glyph alone, no ring /
(e) the inverted version's glyph larger (to fill where the ring was) — (b)+(e) combined as upward compat. Weights
Bold and Black were compared at 16 / 24 / 32 / 64 / 160 px. **Selected = Bold, the outlined version at ring 64 (6.7%
of diameter) and glyph 62%, the inverted (favicon) at glyph 66%**. Black's strokes crush into a blob at 32 px and
below; Bold's 秘 stays readable at 32 px. <!-- english-exempt: literal glyph referenced --> At 16 px nothing is readable, so the favicon prioritizes being recognized
as "a vermilion circle" and uses the inverted version. (a)'s ring disappears at 16–24 px. (c) is cramped at 160 px
and up. (d) loses ㊙'s identity.

**Reproducing the deliverables and verification**: `apps/web/theme/maruhi.ts` (the only raw hex: 2 vermilion values +
2 on-accent values) → `bun run --filter @maruhi/web theme:build && bunx oxfmt apps/web/theme` (generated artifacts
are committed oxfmt'd — checking for a zero diff uses the same order). The 4 SVGs + 4 PNGs go in `apps/web/public/`.
The OFL full text and copyright notice go in `apps/web/public/fonts/OFL-NotoSansCJK.txt` (readable from the
distributed site too. DP2's Archivo / Martian Mono go in the same directory — §4). Each SVG's leading comment notes
its provenance.

## 4. DP2 LP + docs — structure

- A new package (`apps/site` is the plan. It may absorb the existing `apps/docs` stub): **Blume** (decided in
  ADR-0008 — Astro-based)'s static output makes the LP and docs one site. If a real need to build the LP outside
  Blume (plain Astro etc.) emerges, raise it as an ADR-0008 revision (don't rehash). LP = `/`, docs = `/docs/*`.
  **Its own `wrangler.jsonc`** (Workers Static Assets, custom domain `maruhi.app`). Deployed separately from the
  product Worker (`maruhi-server-hosted`)
- **Styling (2026-09-03 owner ruling — Astryx is the dashboard, the LP is Blume)**: 3 layers only. (1) **Blume's
  theme tokens** (colors, radii, fonts) get the same values as Astryx `defineTheme` (the vermilion accent, warm
  neutral, Archivo / Martian Mono), affecting both docs and the LP — to avoid double bookkeeping, a generation
  script that writes CSS variables out of `apps/web/theme/maruhi.ts` (decided at DP1). (2) **The LP's custom pages
  use Astro components' scoped `<style>` (plain CSS)**. Values reference CSS variables; no raw hex or magic numbers
  (ADR-0013's spirit applied to the LP too). **Relationship to CSP (correction)**: Astro's
  `build.inlineStylesheets` default `'auto'` inlines styles under 4 kB into the HTML's `<style>`, so as-is it needs
  `style-src 'unsafe-inline'` (or hash enumeration). The LP pins `build.inlineStylesheets: 'never'` to external CSS
  and keeps `style-src 'self'` (whether Blume exposes the Astro setting is a DP2 check item — if it doesn't, that
  joins the component overrides / eject decision). (3) docs stay at Blume defaults (component overrides only when
  needed). **Not added**: Tailwind (more deps, duplicate tokens), StyleX (a static site doesn't need the compiler),
  Astryx's React parts (unused in principle — individually via React islands if ever needed). The only added
  dependency is `blume` itself. **Deferred**: how far theme tokens reach for font swaps, header / footer, and custom
  pages is settled by actually installing Blume and reading `node_modules/blume/docs` (DP2's first task). For what
  doesn't reach, decide there between component overrides and taking eject-level freedom for the LP only
- `maruhi.dev` → `maruhi.app` 301 (a zone redirect rule. No Worker is placed)
- A structure leading to the "first 5 minutes" (ADR-0014 revision 1): the value proposition (one screen) → install
  (the command) → `maruhi login` → the invite-only notice / waitlist → the route to self-hosting (SELF_HOSTING.md)
- The LP's CSP needn't be as strict as the TCB's, but **no external scripts, external fonts, or trackers** (§1-5).
  If embeds (video etc.) are needed, they're self-hosted
- Fonts (§1-3): Archivo (headings, body) + Martian Mono (code) self-hosted from `/fonts/` (variable woff2, Latin
  subset, `font-display: swap`). docs (Blume) shares the same 2 families. **Decomposing Bun's impression**: ultra-bold /
  wide headings (Archivo's width axis), a black ground, code blocks on par with body text, a mascot — the mascot's
  role is played by the ㊙ logo
- **OFL 1.1's distribution obligations** (don't drop these in DP2's implementation): (a) bundle each family's
  copyright notice and the full OFL text alongside the distributed assets (`/fonts/OFL-Archivo.txt` /
  `/fonts/OFL-MartianMono.txt` etc. — a place users can read from the distribution. Also appended to the repo's
  `LICENSE` set). (b) Subsetting and pruning variable axes count as an OFL Modified Version, but **neither family
  declares a Reserved Font Name** (no "with Reserved Font Name" phrase in the copyright line of the upstream
  `OFL.txt` — checked Omnibus-Type/Archivo and evilmartians/mono on 2026-09-03), so **the modified versions may still
  carry the original family names (`Archivo` / `Martian Mono`)**. Hence the Latin subset (≈ half the size) is the
  default and no rename is needed. The bundled OFL full text is the upstream one verbatim (the obligations don't
  change with modification)
- The current `apps/web/src/pages/HomePage.tsx` (the spike skeleton) is replaced by a redirect from `my.maruhi.app/`
  to `/dashboard` (or a minimal notice) once the LP stands on apex. The e2e mechanism-verification hooks (built-at /
  counter / about) move to a different verification page, or the tests' premise is revised (don't break e2e by
  deleting)
- hosted-design.md §7 L1's revision: "`maruhi.dev` = docs" → "docs = `maruhi.app/docs`; `maruhi.dev` is a 301"

### DP2 implementation-time ruling record (2026-09-03)

Each ruling point was decided by the same loop as DP1 (enumerate ≥3 options → search for upward compat / a silver
bullet → iterate with varied generation rules until no new options → select). Judgment criteria: staying inside §4's
3 layers, consistency with "never-tell" and minimal dependencies, few generated artifacts, wrappable later by O9
(the Alchemy v2 migration), cheap reversibility.

**Blume check results (resolving the deferral — Blume 1.5.3, measured on `node_modules/blume/docs`, `blume --help`,
and a trial-install build)**: (1) **theme tokens' reach**: `theme.accent` / `background` take `{ light, dark }`
pairs; `theme.css` (project root) can override `--blume-background / foreground / muted / muted-foreground / border
/ accent / accent-foreground / action / code-background / radius / font-*` on `:root` and
`:root[data-theme="dark"]`, affecting both docs and the LP. (2) **Fonts**: `theme.fonts`' 3 roles (display / body /
mono) accept local woff2 `variants` (variable ranges like `"100..900"` OK), and the Astro Fonts API self-hosts them
at `/_astro/fonts/<hash>.woff2`. **The default fetches Inter / IBM Plex Mono from Google Fonts at build time** and,
being a schema default, can't be disabled = local specification is a "never-tell" hard requirement (fetching happens
only at build time — not external communication from the shipped assets — but we don't create a build's external
dependency either). `<Font>` always emits `@font-face` inside an **inline `<style>`** (D's premise). (3) **Astro
config exposure**: `build.inlineStylesheets` isn't directly exposed, but `integrations` is transparent, so an
integration's `astro:config:setup` → `updateConfig` pins it to 'never' (measured to work). (4) **Custom pages**:
`pages/*.astro` are mounted at the same root, and `PageLayout` (header + theme + fonts, no sidebar) gives enough
freedom for the LP. config / navigation / fontCssVars are read from `blume:data`. With `basePath: "/docs"` docs sit
at `/docs/*` and the root belongs to custom pages (officially supported — the equivalent of Docusaurus's
`routeBasePath`). (5) **component overrides / eject**: `components.ts`'s `layout` slots (Header / Footer / Logo …)
and `blume eject` exist. Neither is needed at DP2. (6) **External communication**: search = Orama (in-browser, index
`/blume-search.json`); `llms.txt` / raw Markdown / Copy as Markdown / WebMCP (in-page registration only) / OG cards
(Takumi, drawn locally at build time) / sitemap / robots — no external communication. **Analytics is opt-in: nothing
is injected if undeclared** (Vercel / PostHog / arbitrary scripts only when declared). Ask AI / the MCP server are
opt-in features needing server output (default off). **Open in chat** is a navigation link to ChatGPT / Claude / v0 /
Cursor etc. (only on user action; no automatic sends). "Give feedback" is a pre-filled GitHub issue link.
`@vercel/analytics` is bundled in Blume but is a no-op without `window.va` (measured: every LP / docs request stays
same-origin). (7) **Runtime**: Blume requires Node 22.12+ but `bunx --bun blume build` completes on Bun (measured.
Adopted so CI doesn't depend on a Node version). **Answers to the Bun-impression decomposition**: the ultra-bold /
wide headings are Archivo's `font-stretch: 112%` + weight 800, the black ground is system-following dark, the code
blocks are on par with body text (the LP's hero is a terminal), and the mascot's role is the ㊙ logo.

**A. The package's placement and name** — options: (i) create `apps/site` + delete the `apps/docs` stub / (ii) expand
`apps/docs` to include the LP / (iii) separate packages for LP and docs / (iv) Astro cohabiting `apps/web` / (v) no
package, Blume at the repo root. **Selected = (i)** `@maruhi/site` (FSL-1.1-MIT = the repo default). The name says
"the apex site = LP + docs"; under `apps/docs` the LP would be a foreign body. Quality gate: `typecheck` covers
`blume.config.ts` / `scripts` / `test` / `theme` (`.astro` / `.mdx` are outside tsc's scope — Blume's `blume check`
is optional); oxfmt / oxlint target only TS and ignore `.astro`; ImportLint covers TS relative imports (`../web/theme`
is not referenced — B); fallow declares entries (`blume.config.ts` / `scripts/*.ts` / unit tests) and ignores
(`public/**` / `.blume/**`). `apps/site/vitest.unit.config.ts` is added to the root vitest projects. Rejected: (iii)
loses theme / search / OG sharing and becomes 2 deploys. (iv) puts Blume's dependency tree (≈ 850 packages) into the
TCB. (v) breaks the workspace convention.

**B. Sharing theme tokens** — options: (i) a generation script writing CSS variables out of `apps/web/theme/maruhi.ts`
/ (ii) duplicate the values by hand and detect drift via a diff check / (iii) constants in `packages/brand` both
import / (iv) separate constants into `apps/web/theme/brand.ts` and have site relative-import / (v) site's config
imports `maruhi.ts` directly (evaluating Astryx's `defineTheme`) / (vi) **a generation script taking the artifact
`maruhi.css` as input** (upward compat: not just the 2 vermilion values — the HCT-derived warm neutrals [body /
surface / popover / text / border] come down the same path, and the web side's source is untouched). **Selected =
(vi)**: `apps/site/scripts/theme.ts` extracts `maruhi.css`'s `light-dark(#…, #…)` declarations and writes
`theme.css` (Blume tokens) / `theme/tokens.ts` (constants the config reads) / `public/logo-dark.svg` (the fill to
the dark accent) / duplicated assets (favicon / logo / og / apple-touch-icon). The artifacts are committed, and
`test/unit/theme.test.ts` checks "regeneration = committed" (the same shape as DP1's "matches the generated CSS"
contract). Hand-written hex on the site side is zero (a unit test checks). Rejected: (i)(v) bring `@astryxdesign/core`
evaluation into site. (ii) is double bookkeeping. (iii)(iv) touch web's theme, and neutral's derived values exist
only in `maruhi.css`, so it reads the CSS anyway. The mapping: Blume's `--blume-muted` ← Astryx `surface`,
`--blume-code-background` ← `popover` (a face brighter than the body in dark), `--blume-radius` ← `--radius-element`.

**C. Font acquisition, subsetting, and delivery** — options: (i) place the upstream repos' variable TTF / woff2 as-is
/ (ii) subset to Latin via `pyftsubset` (one-off /tmp) / (iii) a subsetting tool as a devDependency / (iv) **take them
once out of Fontsource's variable packages (`@fontsource-variable/archivo` / `martian-mono` 5.3.0 — the same source
files as Google Fonts, already split into Latin etc. subset woff2 + the OFL full text)** (a silver bullet: the
subsetting tool itself isn't needed) / (v) specify the Google provider in Blume's `theme.fonts` (fetches from Google
at build time — impossible under "never-tell"'s spirit and the build's external dependency). **Selected = (iv)**:
`archivo-latin-wdth-normal.woff2` (90 KB — width axis 62–125% + weight 100–900. The headings' width needs the width
axis) and `martian-mono-latin-wght-normal.woff2` (24 KB — weight 100–800. Code doesn't need the width axis). Italic
is dropped (§1-3). `unicode-range` is unneeded with 1 file per Latin subset (the Astro Fonts API's `@font-face`
carries `font-display: swap` and fallback metrics). The location is `apps/site/public/fonts/` (the same directory
as the OFL full texts `OFL-Archivo.txt` / `OFL-MartianMono.txt` = the distribution unit. Linked from the LP's
footer). **Astro Fonts
API duplicates the source to `/_astro/fonts/<hash>.woff2` and references it** — so fonts ride the distribution via 2 paths (≈ 113 KB of duplication)
— accepted as the price of taking both the readable `/fonts/` URL co-located with the licenses and the hashed optimized delivery. Re-verified
via Fontsource's LICENSE (a copy of the upstream one) that neither family's upstream OFL carries a Reserved Font Name phrase (no rename needed).
One line added to README's license table. Rejected: (i) is several hundred KB including 3 scripts. (ii)(iii) add a tool (Fontsource already
distributes the same result).

**D. How the LP is built and its CSP** — options: (i) a PageLayout custom page + scoped `<style>` / (ii) RootLayout (with docs' chrome) /
(iii) build the shell via the `layout.Layout` slot / (iv) `blume eject` / (v) plain Astro for the LP only (an ADR-0008 revision). **Selected = (i)**.
CSP measurements and handling: (a) Astro's `inlineStylesheets` 'auto' → **'never'** via the integration (small CSS like medium-zoom was
externalized). (b) Blume chrome's **6 inline `<script>`s** (theme init, header ops, nav, ClientRouter style loading, etc. — their content is
deterministic per Blume version) → allowed via **SHA-256 hashes collected from the distribution** (the `apps/web/scripts/write-headers.ts`
method). (c) Astro Fonts' **2 `@font-face` `<style>`s** (can't be disabled — check (2) above) → hashed the same way. (d) The transition-suppression
`<style>` the theme toggle inserts via JS → hashed after confirming the fixed string actually exists. (e) **Shiki's token `style` attributes**
(`--shiki-light/dark`) and parts of the chrome (the sidebar's `padding-inline-start`, CardGroup's `--blume-cols`) — `style-src-attr` can't allow by
hash → options: `style-src-attr 'unsafe-inline'` / `'unsafe-hashes'` + enumerating every attribute value / disabling highlighting (not available in
Blume) / **externalize after build into a single CSS mapping attribute values to classes `.sa-<hash>`** (the same technique as Shiki's official
`transformerStyleToClass`, applied to the distribution — Blume doesn't expose transformers). **Selected = externalize** (`scripts/postbuild.ts`
stage 1. The build checks that not a single `style` attribute remains in the HTML; e2e verifies `[style]` = 0 and that token coloring survives on
docs). The resulting CSP: `default-src 'none'; script-src 'self' 'sha256-…'×6; style-src 'self' 'sha256-…'×3; img-src 'self' data:;
font-src 'self'; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` — **no `'unsafe-inline'` on
either script or style**. §4's "keep `style-src 'self'`" is satisfied in the form "'self' + hashes of deterministic content" (the same reading as
the TCB's `apps/web`). Together, `postbuild.ts` mechanically checks the distribution for zero external src / href references (href allows only our
repo's GitHub and the product origin) and no inline event handlers, and keeps the `_headers` Blume emits (.md / .txt charset, the top Link) while
appending CSP / nosniff / `Referrer-Policy: no-referrer` / HSTS (apex standalone) for `/*`. Rejected: (ii) — the LP doesn't need a sidebar.
(iii)(iv) throw away Blume defaults and lose upstream-tracking. (v) needed an ADR-0008 revision, and measurements showed Blume suffices.

**E. The wrangler config's shape** — options: (i) an independent `apps/site/wrangler.jsonc` (assets only, no `main`) / (ii) add a named environment
`site` to `apps/server/wrangler.jsonc` / (iii) Cloudflare Pages / (iv) bundle `/docs` into the product Worker. **Selected = (i)**:
`name: maruhi-site`, `routes: [{ pattern: "maruhi.app", custom_domain: true }]`, `workers_dev: false`, `preview_urls: false`,
`assets.directory: ./dist`, `html_handling: "drop-trailing-slash"` (Blume's internal links, canonical, and sitemap are trailing-slash-less and the
output is `x/index.html`. `/docs/x/` 308s to `/docs/x`), `not_found_handling: "404-page"` (Blume's `404.html` — with chrome). No env vars, one
config file — easy to wrap into O9's declarativization. CI checks validity via `wrangler deploy --dry-run` (same shape as the product Worker's 8b).
Preview is local `wrangler dev` (`bun run --filter @maruhi/site preview`) only — don't create origins other than apex. Rejected: (ii) pollutes the
product side's config under the env-inheritance rules. (iii) Pages isn't adopted for new work under the Workers convergence policy. (iv) puts the
LP inside the TCB (violates §1-4).

**F. `my.maruhi.app/` and the e2e hooks' destination** — options: (i) `_redirects` for `/` → `/dashboard` 302 / (ii) a minimal notice page / (iii)
keep as-is / (iv) a notice page + move the mechanism-verification hooks to `/about` ("About this deployment" = a diagnostics page) (upward compat:
doesn't break the sign-in round trip's `ResumeToDashboard` [ruling BU] and gives the hooks an operational meaning [build time, client-operation
check]). **Selected = (iv)**: `HomePage` = the SVG logo (`/logo.svg`, replacing the ㊙ emoji) + "Open the dashboard" + a route to `maruhi.app` +
"About this deployment". `AboutPage` = the explanation + Diagnostics (`built-at`, `CounterCard`). e2e moved its hydrate check to `/about` and
changed `/`'s wait to `home-heading` (the SPA / MPA degradation, zero-API-call, and marker-return checks are unchanged. All 25 pass). Rejected:
(i) — with the static shell's `_redirects` the OAuth round trip's landing (`/`) changes, and verifying the auth flow exceeds DP2's scope. (iii)
duplicates the LP.

**G. The LP's information-structure granularity** — options: (i) everything on 1 page / (ii) install / self-host on subpages / (iii) the LP is 1
screen and everything goes to docs. **Selected = (i)** (1 page, 6 sections: hero [a terminal] → How it works [4 cards] → 1. Install [the same
pre-release steps as README] → 2. Sign in [`config set server` + `login`, honest about the key-generation ceremony] → 3. Get access [the current
invite-only state. The waitlist's slot = `#access`'s `data-waitlist-placeholder`, swapped in at H6] → Or run it yourself [`/docs/self-hosting`] →
footer [GitHub / Docs / License / "No analytics, no trackers" / the fonts' OFL links]). docs' initial content is 3 pages (index / getting-started /
self-hosting), with routes into the specs and SELF_HOSTING.md (the write-up is minimal — follow-ups go to `blume-update-docs`). Rejected: (ii) adds
hierarchy while content is thin. (iii) doesn't complete the "first 5 minutes" route within the LP.

**H. Picking among Blume's features** — on (no external communication, the defaults): search (local Orama) / `llms.txt` / raw Markdown / Copy as
Markdown / WebMCP (in-page registration only) / OG cards (drawn locally. palette from the generated tokens; the LP uses DP1's `og.png`) / sitemap /
robots / JSON-LD / agent-readability.json / the theme toggle (docs stay at Blume's default — §1-2's "no manual toggle" was the dashboard's ruling) /
banner (the private-preview notice; dismiss goes to localStorage) / Edit on GitHub · Give feedback (GitHub links). **off**: `ai.openInChat` (links to
third-party AIs — against "never-tell"'s spirit. Copy as Markdown remains) / RSS (no blog) / analytics (undeclared) / Ask AI · the MCP server
(default off — needs server output) / `lastModified` (default off — breaks under a shallow clone). **No external communication exists that can't
be turned off** (measured: zero requests to external origins and zero CSP violations across every LP / docs / theme-toggle / search / client-side
navigation path).

**Ruling points that emerged**: (L) **`bun audit`'s transitive deps**: Blume's dependency tree contains image-size@2.0.2 (no fixed version) and
@vercel/routing-utils' path-to-regexp@6.1.0 (strictly pinned), failing CI's audit. Options: name-level `overrides` (would pull router's ^8 range
in too) / excluding the audit step / advisory-ID-level `--ignore` (adopted — a maintainer-side toolchain that runs only at build time, doesn't ride
the distribution, and has no execution path. The rationale is a comment in ci.yml. Expected to disappear on a Blume update). (I) **The dark-mode
logo**: `logo.image`'s `{ light, dark }` shape serves 2 `<img>`s. The dark SVG is a generated artifact with the original's fill swapped to the dark
accent (`#FF693C`) (B's generation script — zero hand-written hex). The currentColor version (`logo-mono.svg`) was rejected because the mark would
take the text color and stop being "the vermilion seal". (J) **Blume's runtime**: `bunx --bun blume` (Bun). The Node 22.12+ requirement is
substituted by a measured full run on Bun; no Node setup is added to CI. (K) **Duplicated fonts in the distribution** (C).

**Verification (2026-09-03)**: `bun run check`'s 7 stages pass (site rides fmt / lint / typecheck / ImportLint / fallow / unit test). web e2e
25 pass (after F). site e2e 11 pass — every request same-origin, zero CSP violations (LP / docs / toggle / search / client-side navigation),
Archivo / Martian Mono applied, light / dark accent and body match `tokens.ts`, `/docs` reachable, trailing-slash normalization, 404. Screenshots
(light / dark / mobile) are in the PR body. Human tasks = hosted-ops.md §7 O10 (first deploy) / O11 (`maruhi.dev` 301) / O12 (visit counts are
server-side aggregation only).

**G revision 1 (2026-09-04, after the owner's review)**: responding to the owner's assessment "the design isn't bad but the structure is iffy and
the appeal doesn't come across", I actually read the competitor LPs (Phase / Infisical / Doppler / Shelve / Keyway) and organized the diffs. Common
thread: every one puts AI-agent support front and center. Phase advertises E2EE but decrypts Console-side and has a `.env` export. Keyway's hero
is "agents can read `.env`" with server-side AES. Infisical / Doppler speak in compliance, scale, and integration counts. maruhi's diffs: "the
decryptor is a single MIT-licensed CLI — neither the server, the dashboard, nor the operator can hold plaintext", "there is no `.env` export
feature", "`wrangler deploy` once into your own CF account", "agents get only the `maruhi schema` contract, and value display is fail-closed"
and "writing the non-guarantees ourselves (CRYPTO_SPEC §14.3)" — the diffs aggregate to these 5 points ("No telemetry" is stated by Phase too,
so it isn't pressed as a differentiator). Structures enumerated: **(A)** trust-boundary axis (the "who can read plaintext" table goes first) /
(B) diskless axis (enter from a `maruhi run` demo) / (C) self-host axis (enter from `wrangler deploy`). **Selected = (A)** (owner ruling).
(B): "there's a diskless run" alone doesn't differentiate (ADR-0014). (C): competes on Infisical's same ground.
The hero copy, per the owner's "short and impact-first" direction, is **"Secrets only you can read. / Not even us."** (the second line in the
accent color). The new structure (1 page, 7 sections): Hero [a `push` → `run` terminal] → Who can read your secrets [a table: CLI / the `run`
process = yes; server / dashboard / operator / AI agent = no] → Nothing to leak from disk [demos of `printenv | wc -c` and `ls .env*`] → Agents get
the contract, not the values [`maruhi schema`'s real output + the value-display refusal message] → Your Cloudflare account. One deploy. [3 commands]
→ What we don't promise [4 points from §14.3] → Get started [install / sign in / Access (`#access`; the waitlist placeholder stays)].
ADR-0014's rails: don't say "most secure", don't compete on feature counts, don't name competitors on the LP, and terminal output uses the CLI's
real strings (`Pushed … (version=1, epoch=1)` / `Confirmation code:` / the agent gate's refusal text / `schema`'s table). `THREAT_MODEL.md` is
unwritten (H5), so the non-guarantees link to CRYPTO_SPEC §14.3. Verification: site e2e 11 (the h1 assertions updated to the new copy),
`blume validate --strict`, fmt / lint / tsc pass. Copy refinement continues after the first deploy (§4's "structure now, copy later").

**G revision 2 (2026-09-04, second owner review)**: the owner's points against revision 1 = (a) maybe competitors don't list commands on their
LPs but instead write the threats and the "why E2EE / why diskless" (b) too much text — hard to read; add illustrations for readability (c) with
only 2 Whys it becomes "a competitor is fine" — make a chain of Whys that naturally lands on maruhi (d) Cursor / Copilot / Claude Code aren't
competitors, so they may be named. Re-measured the competitor LPs (command count / threat explanation): Keyway 4 / yes ("AI agents read .env" →
"if it isn't on disk they can't" is the clearest causality), Infisical 2 / yes (sprawl, long-lived credentials, agents can't hold credentials),
Doppler 0 / yes (breach statistics), 1Password dev 0 / yes, Phase 3 / **no** (only a feature enumeration — the E2EE competitor closest to maruhi
doesn't tell the "why" = an open seat), Shelve 1 / nearly none. Revision 1's maruhi had 5 terminals, the most of the 6.
**Selected = the "chain of Whys" structure**: an ordering where crushing 5 questions in sequence can only land on maruhi's design —
01 Who reads your files? (editors and agents read every file as context → secrets can't live in files → `maruhi run`) → 02 Then where do they
live? (a server. Many let the server / console decrypt → encrypt before it leaves) → 03 Who holds the key? (E2EE means nothing if the decryptor
isn't small. A dashboard that decrypts is one XSS away; an export .env returns 01 to nothing → the decryptor is a single MIT-licensed CLI, the
dashboard holds no keys, no `.env` writer exists) → 04 How does the agent still work? (it needs only name, type, and whether it's set →
`maruhi schema`; value display is fail-closed) → 05 Who runs the server? (even ciphertext has an operator → `wrangler deploy` into your own CF
account, or ours; neither has telemetry) → the close "what remains is you and the processes you chose to run". By design: at 01 alone it could be
Keyway / Doppler, up to 02 it could be Phase, and from 03 onward only maruhi (the answer to point c). Each question is "the question → 1–2
sentences of fact → So: the answer (accent left-rule)" + an illustration; the illustrations are inline SVG line drawings (lines = muted; only the
key and `.env` are accent. No style attributes — colors come from classes, so CSP's style-src-attr isn't grown). 03's illustration is a "who can
read plaintext" tile set (revision 1's table compressed). Commands are cut to 2 spots (the hero's push → run and 04's schema); the install /
sign-in / self-host procedures defer to docs (getting-started / self-hosting). Terminals wrap with `pre-wrap` (no horizontal scrolling in narrow
columns / mobile). Rejected: telling threats in prose only (against point b) / making the illustrations image files (can't follow the theme and
grows `img-src` distribution) / keeping the table (the tiles show the same information shorter). Verification: site e2e 11 · `blume validate
--strict` · postbuild (zero external references; the style-attribute externalization unchanged at 9) · fmt / lint.

**G revision 2 supplement — the illustrations' touch (2026-09-04, owner ruling)**: the same subject (02's "the device holding the key → ciphertext
→ the keyless server") drawn in 7 options and compared — A thin lines (revision 2's first version) / B thick-line pictograms / C flat 2-tone faces /
D isometric / E blueprint (grid + dimension lines) / F ASCII box-drawing / G seal (㊙'s vermilion stamp). Evaluation axes = §2's tone fit,
small-size readability, light / dark, the cost of aligning 5+ of them, and overlap with competitors. **Selected = B + G as an accent color**:
objects are 3px round-cap lines in the foreground color + faces in the code background color (same line weight as the ㊙ logo, readable on mobile.
One line weight, one face, one accent = easy to keep consistent), and in each illustration the accent marks only the 1 "thing holding the key"
(01 `.env`, 02 the key, 03 the CLI tile's ㊙ mark = reusing `/logo.svg` / `/logo-dark.svg` via `<img>` so it doesn't depend on a CJK font, 04 the
guarded value, 05 the deploy). Rejected: A (too thin a presence next to the Archivo headings — looks like a SaaS line drawing) / C (same shelf as
Keyway / Linear families) / D (overlaps Cloudflare / Doppler's design language; the cost of aligning 5 at the same angle and light is highest) /
E is reserved for docs' architecture diagrams / F is reserved as a one-off play on e.g. the 404 page (weak for screen-reading and wrapping). The
comparison page is an owner-facing artifact (private).

## 5. The entrance to DP3–DP5 (details in each PR)

- DP3 (the dashboard): unify the app shell, empty states / loading / errors (13 `FailureNotice` spots), the audit viewer's
  readability (keep web-dashboard-design.md §4's display discipline), responsive, a11y. **When the same xstyle override
  appears 2–3 times, propose to a human before promoting it to `ui.package`**
- DP4 (the ceremony pages): the CLI approval page (confirmation-code visibility = the phishing guard's UX), the sign-up notice /
  the refusal landing, `/invite`. Keep CSP `script-src 'none'`; unify the brand via self-hosted CSS. Check the confirmation
  code's character set
- DP5 (the CLI): output consistency (TTY discipline), `login`'s deadline and guidance, suppressing repeated Notes, English
  copy editing, `--help` consistency

### DP3 implementation-time ruling record (2026-09-04)

Each ruling point was decided by the same loop as DP1 / DP2 (enumerate ≥3 options → search for upward compat / a silver bullet →
iterate until no new options → select). Judgment criteria: staying in a shallow layer of ADR-0013's evaluation order, leaning to
Astryx defaults (§1-2), not breaking a single display-discipline rule (web-dashboard-design.md §4), not mixing preview-only code
into the distribution, cheap reversibility. Measurements used `apps/web/test/screenshots.ts` (ruling F) and a one-off axe-core /
keyboard-walk script (ruling E).

**Premise corrections (facts found during implementation)**: (1) Astryx's `Table` has its own horizontal scroll frame (a
`role="group"` scroll wrapper, `tabindex=0`) and bleeds left and right by the Layout's padding. The W-series mobile-width tables
"looking cut off" is because the frame doesn't show a visual scrollbar — structurally they're readable. So a home-made table
scroll frame (the first version's `TableFrame`) isn't needed; it was removed from DP3's initial implementation. (2) `Text`'s
`wordBreak` applies even without maxLines, but a whitespace-free 64-hex identifier expands a flex item's min-content, so it won't
wrap on that alone (`overflow-wrap: anywhere` + `min-width: 0` are needed — ruling H's `HexText`). (3) The internal user_id is a
ULID (26 chars — AUTH_SPEC §9), and "Signed in as + ULID + Sign out + the toggle" doesn't fit the mobile-width compressed bar
(ruling A's narrow-width rule). (4) `useMediaQuery` always returns false on first paint for SSR compat — an authenticated screen's
body renders after the fetch, so a Table → List flip is never visible.

**A. The app shell's composition and placement** — options: (i) per-screen ad-hoc headers (status quo: only /dashboard has the user
display and Sign out; subpages have just a "← Dashboard" link) / (ii) `AppShell` + `TopNav` (logo, the 3 destinations, the user,
Sign out) on every authenticated screen / (iii) `AppShell` + `SideNav` / (iv) only `Layout`'s header slot on each screen / (v)
**`DashboardShell` (upward compat)**: on top of (ii), **the shell holds the session state (`GET /auth/me`) in one place**, a 401
shows the same sign-in card on every screen, and the body renders only on ok (the old `DashboardScreen`'s S3 moves into the shell).
Breadcrumbs pass only the parent levels; the current location comes from the heading. The display discipline's proviso (`ServerReportedNote`)
is placed once at the end of the page by the shell. **Selected = (v)**. Rejected: (i) — can't sign out from a subpage, and no user display.
(iii) — with 3 destinations it doesn't meet SideNav's requirements (grouping, room to grow), and Astryx's layout docs also say "a shallow, stable
nav is a TopNav". (iv) — would mean hand-making the landmarks (skip link / main / nav) and the mobile drawer. **Attached rulings**: (a) the body
renders after me is confirmed (accepting the 1-round-trip serialization — avoiding the shape where the body flashes in then disappears on a 401,
and where child resources' 401 branches run in parallel). (b) `height="auto"` + `variant="section"` — the default `elevated` either ends the face
at the body's height (auto) or makes main internally scroll (fill). Since HP5's mobile reading is naturally document scrolling (the address bar's
collapse, inertia to the end), auto is taken, and section avoids a face-height step (the only deviation from Astryx defaults; no visual tokens were
touched). (c) At narrow widths (AppShell `md` = 768px and below) the user display moves into the drawer side (`startContent`) alongside the
destinations, and only Sign out stays on the bar. (d) e2e follows by mocking `/auth/me` in every authenticated-screen test (`routeSession`).

**B. Unifying empty / loading / error states** — options: (i) status quo (empty = a mix of `EmptyState` and bare `Text`; failure =
`FailureNotice`; loading = `LoadingRow`) / (ii) just align all empties to `EmptyState` / (iii) fold the 3 states into one `ResourceView` (can't
cover non-`useApiResource` states — pagination appends, revocation failures, the shell's auth — leaving 2 disciplines side by side) / (iv) add a
placement arg to `FailureNotice` (more API for the same look) / (v) **keep `FailureNotice`'s API (failure / onRetry / subject) unchanged, pin the
placement discipline to 2 kinds, and align only empty states to a new part `EmptyNotice` (upward compat)**. **Selected = (v)**. The discipline:
(a) **replacement** = render instead of the resource body; pass `onRetry` if a re-fetch path exists. (b) **append** = add below a body that did
render (a Load more failure, a revocation failure). Failures re-operable from the row don't take `onRetry`. The 13 spots (the old
DashboardScreen's session-failure display moved into the shell — the count is unchanged) split into 9 replacements / 4 appends; each call site got
a marker comment. `EmptyNotice` is a heading + the prescribed wording "as reported by the server" and doesn't show counts (§4-4). `LoadingRow`
passes the Spinner's `role="status"`-visible text the same label. **Attached**: the overview tab makes the chain fetch its leading resource and
reads the env list after it (avoiding a shape where the same Banner lines up per section on a uniform 404 / 403 — accepting the 1-round-trip
serialization). Rejected: (ii) leaves the failure and loading disciplines undocumented. (iii)(iv) — as above.

**C. The audit viewer's readability** — options: (i) status quo (5 columns; actor = `user · key FP · token id` as 1 string; details also ` · `
-joined) / (ii) decompose cells into **labeled fragments** (actor = the principal on 1 line + `key` / `token` fragments; details = `target` /
`env` / `var` / `epoch` / `v` / `chain seq` pairs; `var.read`'s count summary on its own line) / (iii) replace Table with `List` (1 event = 1 item —
loses desktop column scanning) / (iv) only adjust column widths / (v) **(ii) + switch to (iii) only at narrow widths (upward compat — ruling D)**.
**Selected = (v)**. Display-discipline check: items, order, and wording unchanged (seq stays response-adaptive; the prescribed wording "Events
visible to your role"; `Server time (UTC)`; FPs stay reference values — the added `key` label doesn't carry a "verify this" reading); no count
display added either. Rejected: (i) — FP and target can't be told apart in the same blob. (iii) alone loses column scanning. (iv) doesn't change
the root problem (1 string).

**D. The responsive policy** — options: (i) nothing (leave it to Astryx's scroll wrapper) / (ii) List-ify every table at narrow widths / (iii)
List-ify only the audit list and leave other tables to Astryx's horizontal scroll frame / (iv) the classic trick of CSS-ifying `td` into blocks
(breaks Table's ARIA structure — would mean overriding Astryx internals with StyleX) / (v) pin the breakpoint constant to one value and do (iii).
**Selected = (v)**: `NARROW_VIEWPORT_QUERY = "(max-width: 768px)"` (the same expression as AppShell's `md` — the nav's drawer conversion and the
body's display-form switch happen at the same width) defined once in `shared.tsx`. Only HP5's main use (reading audits) takes the List shape; the
S5 / S8 / S9 tables stay horizontal-scrollable (the frame is `tabindex=0` so a keyboard can scroll too). Identifiers wrap at any position via
`HexText` (the project ID below the heading, chain head, member id, key FP, token prefix). Rejected: (ii) gains little for the work of rebuilding
the revocation 2-stage buttons and Token inside items. (iv) — as above.

**E. The a11y audit's method and fix scope** — options: (i) eyeballing code only / (ii) add `@axe-core/playwright` as a devDependency / (iii)
Playwright's ARIA snapshot + manual keyboard walk / (iv) only React Doctor + `astryx doctor` / (v) **inject axe-core one-off (a scratchpad
`page.evaluate` — via CDP, so outside CSP's scope) and combine with (iii)(iv) (upward compat adding no dependency)**. **Selected = (v)**. Scope:
wcag2a / 2aa / 21a / 21aa + best-practice run across S4 / S5 / S6 (the admin, reader, and self axes) / S8 / S9 × light / dark / mobile = 18 states.
**Findings and handling**: (a) `empty-table-header` (minor) — the empty headings of the revoke and variable-name columns → added `Actions` /
`Variables`. (b) `color-contrast` (serious) — `SegmentedControl`'s unselected label is 4.26:1 in dark (12px; AA is 4.5) → resolved by replacing the
audit-axis switch with `ToggleButtonGroup` (single) (it's an Astryx-internal color, so it's noted on the PR as an upstream candidate. Theme color
values untouched — settled at DP1). (c) Heading hierarchy: the page h1 is the shell's (before sign-in, the card's "Sign in" is the h1); sections
are h2 (old h3s promoted); empty-state headings are h3. (d) Landmarks: AppShell's skip link → `nav[Dashboard]` → main; breadcrumbs are
`nav[Breadcrumb]`; the mobile drawer is `dialog[Navigation]` and closes on Escape with focus returning to the toggle. (e) Visible focus: a 2px
accent outline in both light and dark (TextInput is border color + an inner ring). (f) Tabs move focus with arrows and select with Enter (manual
activation). **Not fixed**: the `TopNavHeading` logo link's focus ring is a fixed 1px color (Astryx-internal) — measured as visible in both modes,
so kept as-is (included among upstream candidates).

**F. Visual checks and screenshots of auth-required screens** — options: (i) a scratchpad-only script (unreproducible) / (ii) **commit
`apps/web/test/screenshots.ts`** (the same `page.route` mocks as e2e. Fixtures extracted to `test/fixtures.ts` and shared with e2e) / (iii)
preview routes + mock data inside the distribution (forbidden) / (iv) log in via real OAuth (needs GitHub App setup — impossible in this session) /
(v) (ii) + lay out results on an owner-facing private page (a Claude Artifact) by light / dark / mobile and before/after (same as DP2).
**Selected = (v)**. The procedure is written at the head of `screenshots.ts` (`build` → `preview` (port 8788) → `screenshots`. Output goes to
`apps/web/screenshots/` — gitignored). 11 screens × 3 states = 33 shots; it fails if there's a CSP violation.

**G. PR splitting** — options: (i) 1 PR / (ii) DP3a (the shell + state unification) / DP3b (audit readability + responsive + a11y) / (iii) 3+ PRs.
**Selected = (i)**: the shell is the foundation for the breakpoint (D), the landmarks and heading hierarchy (E), and the state unification (B) —
split, and DP3a alone would leave a11y and e2e updates half-done. The diff is reviewable at 12 web files + docs (commits were split by concern).

**H. xstyle repetition** — the xstyle that came out of DP3 is **just 1 kind**: identifiers' any-position wrapping (`overflowWrap: anywhere` +
`wordBreak: break-all` + `minWidth: 0`). Options: (i) write `stylex.create` on each screen (3+ duplicates) / (ii) 1 definition in `shared.tsx` +
the `HexText` part (defined once, used in 12 places) / (iii) create `ui.package` and put it there (③) / (iv) a `defineTheme` Text variant (①).
**Selected = (ii)** — no duplicate definitions; promotion is left to human judgment (CLAUDE.md "don't let it flow backward"). **Promotion
candidates (listed on the PR)**: `HexText` to a ui.package part or a Text variant (`code-breakable` etc.). No other repetition exists (the existing
tabpanel `display: none` override stays at its one W-series spot).
**Ruling points that emerged**: (I) **The axis-switch part**: SegmentedControl → ToggleButtonGroup (E-(b)). How e2e
points at it changed `radio` → `button[pressed=false]`. (J) **The logo's color**: the shell's logo isn't
`public/logo.svg` (pinned to light's vermilion) but the inline SVG part `MaruhiMark` (the same paths as
`public/logo-mono.svg`) drawn via `Icon color="accent"`, inheriting light / dark's `--color-accent` (the partial
adoption of DP1 ruling A's (v) "currentColor-ification"). The duplicated path data is tied to the SVG as the source
of truth via a comment. (K) **The pre-sign-in page heading**: until me resolves, the shell emits no page heading and
the sign-in card's "Sign in" becomes the h1 (avoiding the shape where a sign-in card sits under "API tokens"). (L)
**The project heading's short form**: the h1 is `Project ab…ab` (first + last 8 digits); the full form sits directly
below as `HexText` (`data-testid="project-id"` kept).

**A revision 1 (2026-09-04, after the owner's review — sidebar type + starting from Astryx templates)**: on the
owner's directions "make the layout sidebar-type (SaaS's mainstream, and easier for me to use)" and "use Astryx's
templates more aggressively (login and sidebar both exist as templates)", the TopNav option (A-(v)) was **swapped for
the SideNav option (A-(iii))**. It is the owner's ruling, and A's rejection reason "3 destinations are TopNav's
range" loses to "a shape they're used to". The shape takes the templates as-is for a start (`astryx template
shell-side-nav` / `AppShellSideNavOnly` / `SideNavWithHeaderMenu` / `login` / `table-page` /
`LayoutHeaderWithActions`): (a) **the frame** = AppShell + `SideNav` (`collapsible`. The header = `SideNavHeading` +
`NavIcon` [an accent disc with an on-accent ㊙ = the same inverted version as the favicon]; the body = a
`SideNavSection` with the 3 destinations [Folder / Key / ClipboardDocumentList] — on project screens, the current
project [short ID] appears selected under Projects' children; the footer = a `SideNavSection` "Account" [user id →
Account audit, Sign out] — the `shell-side-nav` footer composition). At mobile widths AppShell moves the SideNav into
a drawer (A-(c)'s "user display into the drawer" holds naturally under SideNav, so the `useMediaQuery` branch was
removed). (b) **Pages** = `Layout` (fill)'s header slot carrying breadcrumbs + h1 + description (`LayoutHeader
hasDivider`), the content slot carrying the body + `ServerReportedNote`. main's internal scroll (the `table-page`
shape. A-(b)'s "document scrolling" is retracted — lean to the template's default). (c) **Sign-in** = the `login`
template's shape (Center + logo + Card [h1 "Sign in", description, primary "Sign in with GitHub"]). There are no
credential fields (GitHub OAuth only), so the Button takes `href` and renders as a link. Right after sign-out, an
info Banner sits inside the Card. (d) **Icons**: the templates either use `@heroicons/react` or hold SVGs inline.
Keeping dependencies flat, the latter was taken: 5 heroicons (MIT) outlines were transcribed into `icons.tsx`.
Other options enumerated: SideNav + TopNav together (suite-oriented — destinations are thin and the second bar is
leftover) / `LayoutPanelNavigation` (nav in Layout's start panel — loses AppShell's drawer and skip link) /
`Shell Nav` (with a command palette — nothing to search). Rejected. e2e unchanged (the `signed-in-user` / `sign-out` /
`login-card` / `sign-in-link` testids pass through SideNavItem / Card / Button). axe at 18 states: 0 violations; the
keyboard walk confirmed every SideNav item, the collapse button, and the drawer (Escape closes and focus returns to
the toggle). E's "not fixed" `TopNavHeading` focus ring is out of scope since TopNav isn't used anymore
(SideNavHeading is accent 2px).

**A revision 2 (2026-09-04, second owner review — the logo, sign-in's position, whitespace, Table / Settings
templates)**: handling the owner's 4 points. (a) **The logo**: a ringed `MaruhiMark` sat inside the NavIcon (the
accent disc), so it read as "a circle inside a circle". `MaruhiMark` gained `hasRing`; inside the disc it shows only
the ring-less glyph (`size="md"`, about 60% of the disc), aligning it with the favicon's "disc + glyph" (DP1 ruling
E's inverted version). (b) **Sign-in's position**: `Center minHeight="100%"` has no parent height so it didn't
resolve and the card sat high → `minHeight="100dvh"` (the `login` template presumes body's height and sets
`minHeight: '100%'` via style. This repo forbids style, so the viewport unit reaches the same result). (c)
**Referencing the Table / Form / Settings templates**: revision 1 started only from `shell-side-nav` / `login` /
`LayoutHeaderWithActions`. After reading `table-page` (`density="balanced"` + `hasHover`, LayoutHeader's h1 +
LayoutContent's VStack gap 4), `settings` (a section = heading level 3 + a one-line description + content; sections
separated by Divider; sections with inputs use `Grid columns={{minWidth: 320}} gap={10}`'s 2 columns = heading |
input), and `SectionWithDividers`, these were taken: all Tables become `balanced` + `hasHover` (compact is for
"regions scanned fast like logs"; the audit too goes balanced, deferring to the owner's "it's cramped" assessment);
section heading blocks unified to `SectionHeader` (`shared.tsx` — `Heading level={3} accessibilityLevel={2}` + a
supporting description. The look is the template's level 3 while the document structure keeps an h2 directly under
the h1); S4's "Open a project by ID" moved to the settings template's 2-column Grid; control sizes to md (paired with
balanced). `contact-form` doesn't apply to a dashboard with no input fields. (d) **Whitespace**: page-body
inter-section gap 6 → 8, in-section (heading block → content) gap 4, overview-tab inter-section gap 5 → 8, around
audit / Load more gap 4. Following Astryx's spacing docs ("tight is 0.5–2, section is 4–8"), the cramped 2–3 values
aren't used. e2e 26 and axe 18 states pass unchanged.

**A / C / J revision 3 (2026-09-04, third owner review — "implement referencing the templates", width, a real
SVG)**: on the owner's point "Table / Form / Settings isn't an adopt/reject question — implement referencing the
templates", the closest template per screen was picked and its structure transcribed. (a) **The audit viewer (C
revised) = `incident-console`** ("a queue of rows + an inspector of the selected row". Rows, not cards). A row =
`List`'s `ListItem` (label = the event name; description = seq [response-adaptive] + the principal + the coordinates
fragment; endContent = the server time; `onClick` + `isSelected`); the selected row's full fields = `MetadataList`
(label width 96) + the payload as recorded (`CodeBlock` json) + var.read's enumeration. Above 1024px
(`INSPECTOR_VIEWPORT_QUERY` — the template's same boundary) the inspector sits to the right (inside a tab panel, so
not Layout's end slot — HStack + a vertical Divider + `aside`); at or below it, a full-screen `Dialog` (detail-page's
mobile form — Escape closes). **Table isn't used** (D's Table → List switch is unneeded too — `NARROW_VIEWPORT_QUERY`
removed). Items, order, wording, and count-hiding are unchanged (§4). (b) **Project screens = `detail-page` (Order
Detail)**: the header slot carries "← All projects" → h1 → the full ID → `TabList` (tabs live in the header so they
stay visible while the body scrolls internally). The overview is a side-by-side `MetadataList` (Chain head / Head
digest / Member head attestations) → Members → Environments. "Head hash" hit the SPA bundle's forbidden word `hash`
(AUTH_SPEC §15-3's tripwire — `write-headers.ts`), so it's "Head digest". (c) **Notices = `CardCallout` blocks** (a
muted Card + a heading + a body): the tokens / invites / rotation CLI guidance. (d) **Lists = `table-page`** (as last
time's revision 2: balanced + hasHover + LayoutHeader). (e) **The logo (J revised)**: DP1's real asset
`public/logo-inverted.svg` (the 秘 knocked out white on a vermilion disc = same shape as the favicon) is used via <!-- english-exempt: literal glyph referenced -->
`<img>` (32px in the sidebar, 56px on sign-in). The inline SVG part (`MaruhiMark`) was deleted. The color stays
vermilion (the same look as the browser tab's favicon. Making it follow accent in dark was possible via the same
generated artifact as site, `logo-inverted-dark.svg` + `<picture>`, but was declined to not grow assets). (f)
**Width**: on the owner's "content fills the full width" observation — Layout's `contentWidth` is 1040, so at 1920px
it's capped at center (the Artifact's 1920 screenshot). At 1280px the sidebar's 260 leaves a 1020 cap so it looks
full. Astryx's layout docs say "tables and boards fill the region; prose and forms are capped", and the templates
match: `table-page` = no cap, `settings` = 1440, `detail-page` = 1000. So table pages keep the status quo (1040) and
prose is narrowed via `SectionHeader`'s descriptions and notice Cards. A 960 proposal wasn't taken — it would squeeze
the tables' column widths. e2e 26 (the audit's selectors followed to row + inspector), axe 24 states (1920 added), 0
violations.

**Revision 4 (2026-09-05, fourth owner review — self-questioning "is it really good" through the user experience,
width, the logo)**:
Answers and handling for the owner's 3 points (evaluate it yourself on user-experience grounds / per-page width
changes are unthinkable / the logo is too big). (a) **Weaknesses found in self-review and their handling**: ① the
revoke confirmation was an in-row Cancel / Confirm revoke, stacked vertically in the narrow Actions column and
changing row heights → moved to the shape of Astryx's `AlertDialogAsyncAction` template (a modal confirmation + the
target's name and consequence in the body + a spinner on the action while running). **Ruling CO's (session-45 —
the inline 2-stage) implementation shape is revised** (arming is always 1 row, disarming is a separate row's arming,
other rows are disabled while in-flight [PR #109] — unchanged. The consequence note is read at the confirmation site
in the dialog body and also kept in the CardCallout below the table). ② The audit row's description was a blob of
monospace fragments like `seq 2 user_e2e target … chain seq 2`, hard to scan → "by <actor>" now leads, and seq moved
below the time in endContent (the order: who, what, when). ③ A token's Scopes ballooned to 5 lines of 64-hex × N and
broke the table → a `Token` chip (shortened ID:permission; the full text in aria-description). ④ The overview's
side-by-side MetadataList had 64-hex digests wrapping unreadably → single column (label width 200). ⑤ Things judged
not to change: the page-tail `ServerReportedNote` (§4-1's discipline — once per screen), the project list's 64-hex
display (the server declaration carries only the ID and role — there is no name; the ID is the capability), Row id
(referenced in support). (b) **Width**: there was no per-page intent — revision 3's explanation invited the
misreading. The implementation has been a single shell value (`contentWidth`) for all pages from the start. The value
is unified at **1040 → 1200** (exactly fills a 1180 region on a 1440px notebook and sits centered at 1920px. Even
with the audit's 380 inspector beside it, a row keeps ~800). (c) **The logo**: agreed — at 32px it floated 2× larger
than the heading text (bold 16px). Sidebar 24px (on par with text height), sign-in 40px (56 → 40). (d) Verification:
e2e 26 (the revoke's selector followed to alertdialog; the in-flight lock is checked via the modal + the row's
isDisabled), axe 24 states, 0 violations.

**Revision 5 (2026-09-05, fifth owner review — too many dividers · the tab/header-line combination · the audit's
left-right split)**: the owner's 2 points: (1) the line between header and body, lines inside the body, and table
borders overlap so "where one content ends and another begins" can't be read, and the tab underline + header line
combination sits poorly too. A proposal was offered to separate by whitespace instead of lines. (2) The audit's
(project axis / self axis) left-right split leaves too much space between the row and the detail in a 1200-wide
region — looks wrong on wide screens.

**O. The separation discipline (lines or whitespace)** — options: (i) status quo (the header's full-width divider +
the tab underline + section Dividers + table row lines + the audit's vertical Divider) / (ii) **whitespace only** (the
owner's option): remove the header's divider and the inter-section Dividers, widen inter-section to gap 10 (40px),
and leave lines only on table rows / (iii) **make the tab row the only boundary**: on top of (ii), on screens with
tabs `TabList hasDivider` (the same line as the tab underline) doubles as the header/body boundary. Screens without
tabs get whitespace only / (iv) pin the header but remove the divider / (v) wrap sections in `Section` (dividers) or
Cards (more lines — rejected). → **(ii) + (iii) adopted**. Per Astryx layout docs' order of weakening containers
(gap → Divider → Section → Card): "don't draw boundaries in lines — read them from the whitespace contrast (4 inside
a section / 10 between), and fix lines to only the inside of collections (table rows, audit-row hairlines) and the
tab row". (iv) isn't taken — a borderless pinned header overlaps the body and can't be read; **Layout becomes
`height="auto"` and the whole page scrolls** (the same shape as GitHub's repo pages. Pages are short and AppShell
pins the sidebar). The header's bottom margin 16px + the body's `paddingBlockStart` 24px = 40px, the same contrast as
inter-section. Section headings (`SectionHeader`) mark a section's start by the heading's weight instead of a line,
so level 3 → **level 2**. On the Projects screen the h1 doubles as the list's heading (one main heading per region —
the layout docs), so the "Your projects" section heading was removed and its description merged into the intro.
Tables keep `dividers="rows"` (row separation is inside the collection).

**P. The audit's shape (retracting the left-right split)** — options: (i) keep the row + right inspector
(`incident-console`) and only fix the row-width bug (`align="start"` shrinks the List) / (ii) 1 column + the detail in
a full-width Dialog (extend the current mobile shape to full width) / (iii) **1 column + expand the row in place**
(`Collapsible` × `CollapsibleGroup hasDividers` — the `CollapsibleDividedAccordion` block's shape. Trigger = the
summary; the expanded part = MetadataList + payload + var.read's enumeration) / (iv) Table + expandable rows (5
columns scroll horizontally on mobile — against HP5) / (v) keep the left-right split and pin the row width to 560
(the split remains). → **(iii) adopted**. Same 1 column at every width, and the detail appears directly under the row
being read (the gaze doesn't jump sideways; the 1024px shape switch and the vertical Divider disappear; the same
operation as mobile). With `single` (only 1 row open), other rows don't move while reading the expansion. A closed
expansion stays in the DOM (hidden), so e2e counts only visible elements. The row order keeps revision 4's
"principal → target → time / seq (right end)" and gains a chevron at the row's end. `INSPECTOR_VIEWPORT_QUERY` and
`Dialog` / `EmptyState` / the vertical `Divider` became unnecessary and were removed. Items, wording, seq's
response-adaptiveness, and count-hiding unchanged.

Verification: e2e 26 (the audit's selectors followed to "row = button [aria-expanded] + the visible Row id"; the
mobile Dialog check was replaced by "expands in the same column; under single, the earlier row closes"), axe 24
states, 0 violations.

**Revision 6 (2026-09-05, sixth owner review — the audit row's time is 2 lines · is there a good Astryx part?)**:

**Q. How the server time is shown** — options: (i) status quo (`formatServerTime`'s UTC ISO string
`2025-08-24T01:48:20.000Z` in a Text — on audit rows the time and seq sit 2-deep at the right edge) / (ii) keep ISO
and put it on 1 line with seq / (iii) **Astryx `Timestamp` (`format="date_time"` + `isTimezoneShown`)**: in the
viewer's timezone as `Aug 24, 2025, 1:48 AM UTC`; a hover card carries UTC and Unix seconds (copyable —
`tooltipEntries`) / (iv) `Timestamp format="auto"` (recent = relative time) / (v) `system_date_time` (ISO-ish).
→ **(iii) adopted**, and not just audit rows — every server-time display (tokens' Last used / Expires, invites'
Expires, rotation's Recommended at, `ExpiryCell`) is unified into one `ServerTime` part in `shared.tsx`. Astryx's
Timestamp docs norm "don't emit raw ISO", "on audit logs show the timezone abbreviation", and "for records needing
the exact value, attach a copyable line via tooltipEntries" — followed as-is. (iv) was rejected as mismatched to
audit's precision (when is the protagonist). "(UTC)" was dropped from table column headings (the display is the
viewer's timezone + abbreviation; UTC lives in the hover card). The value is the server-declared ms itself — only the
rendering converts — so §4's "as reported by the server" isn't broken. Inside an audit row's trigger (a button) the
hover card is turned off (`hasTooltip={false}` — don't nest interactive elements); instead the expanded part shows
"Recorded at" with the UTC ISO as recorded. `formatServerTime` stays for that 1 use. Out-of-range ms (deepsec
2026-08-22 — Invalid Date) stays the raw number as before. The audit row's right edge is 1 line of seq + time,
continuing right after the event name (not right-aligned — avoids a gap between name and time on wide screens; it
wraps under the name at narrow widths). Verification: e2e 26, axe 24 states, 0 violations (a Timestamp inside a
button doesn't create nested interactive elements).

**Revision 7 (2026-09-05, seventh owner review — an inventory of places hand-rolled where an Astryx part exists)**:

**R. Inventory of replacements by Astryx parts** — every JSX in `apps/web/src` was cross-checked against Astryx's 163
parts (`astryx component --list`). **Replaced**: (1) `LoadingRow`'s Spinner + Text side-by-side → `Spinner`'s `label`
slot (the string doubles as aria-label — the visible wording and the screen-reading are one thing). (2) Projects' ID
direct-input format error (Text `role="alert"`) → `TextInput`'s `status` (error + message, `statusVariant="detached"`).
Alongside, `onEnter` makes Enter Open too. (3) The project screen's back link (`Link`'s "← All projects") →
`Breadcrumbs` / `BreadcrumbItem` (`variant="supporting"`. Parent = a link to Projects; current = the short ID with
aria-current. Gains a nav landmark). The `detail-page` template is a Link + an arrow icon, but since a part that
represents hierarchy exists, that one is followed.
(4) The variable-name list (hand-assembled HStack rows) and granted server keys (same) → `Table` (compact, row
hairlines. Collections are drawn as rows — the layout docs). Server keys get a section heading (`SectionHeader`).
(5) The CLI-guidance notices (muted Card + Heading + Text, the same shape × 3) → 1 `Callout` definition in
`shared.tsx` (Astryx composition unchanged — duplicate removal). (6) The invalid-ID page (`InvalidProjectPage`)'s Text
→ `Banner` (warning — the same shape as other notices). **Not replaced (reasons)**: (a) `icons.tsx`'s inline heroicons —
Astryx holds no icon set (`Icon` only takes an SVG part), and the templates themselves use either @heroicons/react or
inline SVGs. The no-new-dependencies policy takes the latter. (b) `HexText` (xstyle's anywhere-wrap) — `Text` has no
equivalent prop (ruling H's promotion decision is human). (c) The tab panel (`VStack role="tabpanel"`) — Astryx has no
TabPanel part (the design ties it via `Tab`'s `panelId`). (d) `EmptyNotice` / `SectionHeader` / `FailureNotice` /
`RevokeDialog` — thin wrappers around Astryx parts (they hold the prescribed wording and the placement discipline in
one place). (e) The Load more `Button` — `Pagination` is page-numbered and doesn't fit the cursor style. (f) The audit's
caption + ToggleButtonGroup HStack — `Toolbar` is for a row of actions (above a table), excessive for a prescribed
wording + 1 switch. (g) The env-table's "Variable names" button revealing a variable table below — `Collapsible` or
Table's tree rows (`useTableTreeData`) could do it, but that's a table inside a table's row, so kept (a candidate for
the next review). (h) `HomePage` / `AboutPage` / `CounterCard` (an RSC static shell + the spike) — stay raw `<main>` /
`<h1>` / `<a>`. Outside DP3's scope (W-series spike-a); Astryx-ifying them needs a design for applying `Theme` on the
static shell, so a separate PR. Verification: e2e 26, axe 24 states, 0 violations (Breadcrumbs adds one nav landmark).

**Revision 8 (2026-09-05, eighth owner review — the discomfort of table borders extending past a section's width ·
the wrap-in-Card option)**:

**S. The section container (how to hold a table's bleed)** — facts: Astryx's `Table` (scroll wrapper) reaches to the
region's edges with a negative margin of Layout's padding (24px). Section likewise reaches the edges. Under the
layout docs' alignment model ("1 content line per region — text sits on the line; a row's hover background bleeds to
the edges"), the `detail-page` template looks the same. Options: (i) status quo (section heading + table; the table
extends past the heading left and right) / (ii) **wrap in Card** (the owner's option — prototyped. The table fits,
but `component Section` says "If you are tempted to use a Card for a page section, use Section instead", `component
Card` says "Don't: Wrap page sections in cards", and the layout docs say "x full-width Cards stacked as page
structure") / (iii) wrap in `Section` (per the norm, but under the neutral theme a section's face = surface = the body
region's color, invisible) / (iv) **Section + face color via the theme**: give defineTheme's
`components.section['variant:section']` (customization order ①) `color-mix(in oklab, var(--color-background-body) 55%,
var(--color-background-surface))`, making the default Section a "line-less thin panel" / (v) Section `dividers` (top
and bottom hairlines — the lines return) / (vi) Section `variant="muted"` (the docs limit it to attention) / (vii)
move Layout's padding to AppShell to zero the bleed (prototyped — AppShell's contentPadding doesn't take, and on
mobile the text touches the screen edge — rejected). → **(iv) adopted** (the owner's choice). Per Section docs' "Use
it ... any time you need visual separation between parts of a page", separation is Section's job and color is the
theme's. Following Astryx's surface hierarchy (body → surface → card), the color leans halfway toward body; no raw
hex is added (token reference + color-mix). `shared.tsx`'s `SectionBlock` (Section padding 6 = the same 24px as
Layout's padding; the heading sits on the page's content line. With `title` omitted, a list's panel where the page h1
doubles as the heading) wraps **every collection** (Members / Environments / Granted servers / Invitations /
Projects / API tokens / Rotation flags / audit rows). Table rows extend to the Section's edges, so they look
contained in the section. Callout (a muted Card) stays a notice; its hue differs from the panels'. The theme's
artifacts (`maruhi.css` / `.js`) are regenerated via `bun run theme:build` (the diff is only the 1 section rule). The
site side holds token copies so there's no drift (a `apps/site` theme:build shows a 0 diff). Verification: e2e 26,
axe 24 states, 0 violations (text contrast on the panel is body-equivalent, AA).

**Revision 9 (2026-09-05, ninth owner review — the Section panel is not acceptable. Fixed width + border)**:

**S revision: collections' container is `Card` (a fixed-width box with a border)**. Revision 8's Section + theme face
color was rejected at the owner's judgment (with a thin wash a section doesn't read as a section). "Fixed width +
border" = a Card per collection. Astryx's docs (`component Section` / `component Card` / `docs layout`) say "don't
use Card for a page's sections", but under maruhi's theme a Section doesn't read as a section, and only a border can
show the boundary — **the owner's judgment overrides Astryx's wording** (the reason is left in the ruling record.
Card docs' reading "a hard boundary around critical content" is noted alongside). 2 prototypes: (A) **headings inside
the box** (the shape of GitHub's settings Boxes. Heading, description, and table enter one boundary; heading-less
collections [audit rows, Projects, API tokens] also uniform in the same box) / (B) headings outside the box (Vercel's
shape. The box shows only the data's container; whitespace carries the box–heading affiliation). → **(A) adopted**
(the owner's final judgment is pending — switching to B is 3 lines in `SectionBlock`). Implementation: `shared.tsx`'s
`SectionBlock` = `Card padding={4}` + VStack (SectionHeader? + children). The Table inside reaches the Card's edges
(Astryx's alignment model), so row lines stop inside the border. Only collections go in the box (Members /
Environments / Granted servers / Invitations / Projects / API tokens / Rotation flags / audit rows); the overview's
metadata (MetadataList), "Open a project by ID", and the CLI-guidance notices (muted Card) don't. The theme's
`components.section` override is rolled back (theme/ returns identical to main). Verification: e2e 26, axe 24 states,
0 violations.

**Revision 10 (2026-09-05, tenth owner review — the final call on options A / B: headings outside the box)**:

**S revision 2: headings and descriptions live on the page's content line; the `Card` wraps only collections (option
B)**. The owner's reasoning — under option A a section heading shifts right by the Card's 1px border + 16px padding,
misaligning its start from the text outside the Card (the h1, breadcrumbs, description, the overview's MetadataList).
The text's starting line splitting into 2 per page is the discomfort. Under option B the text's starting line is 1;
only the bordered box's contents shift right (the border explains "a separate frame starts here"). The agent's
evaluation is the same (the Vercel / GitHub settings shape. Option A's merit "the box's meaning completes inside the
box" doesn't pay off on this short-paged dashboard). A side effect: since the Card wraps collections (tables, audit
rows) rather than sections, the distance from Astryx's "don't use Card for a page's sections" shrinks, nearing Card
docs' "a hard boundary around self-contained parts" use. Implementation: `SectionBlock` = VStack gap 4
(SectionHeader + `Card padding={4}` [children of VStack gap 4]). With `title` omitted, only the Card. The audit tab's
description text (prescribed wording) and axis switch (ToggleButtonGroup) have been outside the box since revision 5
(equivalent to the heading row); unchanged. `Callout` (a muted Card)'s inset is a bordered box, inside the same
principle. The vertical rhythm: heading → box 16px, box → next heading 40px (the inter-section `SECTION_GAP`) — the
contrast keeps a heading from appearing attached to the previous box. Verification: `bun run check` 7 stages pass,
e2e 26, axe 24 states 0 violations, CSP violations 0.

**Revision 11 (2026-09-05, PR #148 Cursor Bugbot finding — the shell remounts on every navigation)**:

**T: auth-required screens sit under the pathless parent route (`DashboardLayout`), and the shell mounts only once**.
The finding: because each screen holds its own `DashboardShell` (session state + AppShell + SideNav), every
navigation among Projects → a project → API tokens → Account audit unmounts AppShell / SideNav, shows the full-screen
"Checking your session" frame, re-fetches `GET /auth/me`, and only then draws the destination.
The sidebar isn't kept (its collapsed state disappears too), and every authenticated navigation pays 1 round trip
plus a chrome flash. Verification of the facts: routes are `bindRoute`d in parallel in App.tsx, and `DashboardShell`
holds `useSession`. Options: (1) **nested routes** (funstack-router's `children` + `Outlet` — the docs' "a dashboard
whose sidebar stays" is exactly this use) / (2) a module-level session cache (the re-fetch and the loading frame
disappear, but the AppShell / SideNav DOM is rebuilt per navigation and the collapsed state dies) / (3) conditional
rendering on the screen side (a shape the docs say to avoid). → **(1) adopted**. Implementation: routes.ts gets
`dashboardShellRoute = route({ id: "dashboard-shell" })` (pathless — consumes no path name, so the 4 leaf routes'
paths are unchanged; SPA_ROUTES and the spa-topology tests too. With no path it isn't listed in the catalog). In
App.tsx the 4 routes become its children. `DashboardShell.tsx` becomes 2 layers: `DashboardLayout` (the parent —
useSession + AppShell + SideNav + `Outlet`) and `DashboardShell` (a screen's frame — Layout's header = the heading,
content = the body). The sidebar's current location and a project's child item are declared by each screen via
`destination` / `project` and raised to the parent through context (a useState setter) + `useLayoutEffect` (reflected
before paint, so the previous screen's selection doesn't linger for a frame after navigation). Rejected: deriving it
from the URL via `useLocation` — the router's Location carries `.hash`, which would put the word "hash" in the SPA
bundle and trip AUTH_SPEC §15-3's tripwire (write-headers.ts — ruling BG) (the build actually failed). An SSG note:
the router draws a pathless route under URL-less SSR, but this project's static shell emits only the entry span into
`#app` (the client tree isn't rendered at build time), so it's unaffected. Side effect: the project-ID format check
(64 hex) was consolidated into `ids.ts`'s `isProjectId` (removing the duplicated literal in DashboardScreen /
ProjectScreen). 1 e2e added: SPA-navigate from the sidebar API tokens → Account audit and check that `/auth/me` stays
at 1 call, "Checking your session" doesn't appear, the sidebar's DOM node is identical (the data-attribute mark
persists), and aria-current moves. No visual change (29 of the 33 screenshots byte-identical; the remaining 4 differ
mid-animation, e.g. a dialog's backdrop). Verification: `bun run check` 7 stages pass, e2e 27, axe 24 states 0
violations, CSP violations 0.

Also handled pullfrog's 3 items (a re-review after ready-for-review): (a) heading-less boxes (the lists, audit,
rotation — directly under a page h1) had `EmptyNotice` at the default h3, jumping h1 → h3 → `headingLevel={2}` in 4
spots (ruling E-(c)'s "section h2 → empty-state h3" presumed a section heading; a heading-less box needs h2). (b)
`test/screenshots.ts`'s s8 didn't wait for the dialog after clicking Revoke, and its note still described the pre-
revision-4 inline 2-stage → wait for the `alertdialog` to appear + updated the note (with the wait, s8's screenshot
byte-matched revision 10's — it had been flaky from the race before). (c) The vendored heroicons (5 paths) were
missing the MIT license text → `src/dashboard/MIT-heroicons.txt` (placed next to the transcribed asset, same as the
fonts' `public/fonts/OFL-*.txt`) + a reference at the head of icons.tsx. (d) The review body's point "the axe 24-state
evidence covers only non-empty screens" — fixtures were all non-empty, and empty states and FailureNotice states had
never passed through an audit (in fact (a) was an empty-state-only violation). `test/screenshots.ts` gained an
`empty` mode (mocks returning every collection empty) and 7 empty-state screens (projects / overview [environments] /
audit [project · self] / rotation / invites / tokens × light / dark / mobile = 21 shots), and axe ran on the same 7
screens × light / mobile = 14 states (0 violations. Heading hierarchy: heading-less boxes are h1 → h2; Environments'
empty state is h1 → h2 → h3). Ruling E's "0 violations" scope is now stated explicitly as "the fixtures' non-empty 24
states + the empty-state 14 states". Unaudited: the variable-names empty state (environments exist but variables
don't — empty mode empties environments too, so it can't be drawn) and each FailureNotice state (a Banner's simple
structure; a next-time candidate). On pullfrog's re-re-review pointing out the discrepancy "the script is 6 states
vs the ruling record's 14", the environments' empty state was added to the script side (`/environments` and the
metadata pull also follow `empty`) to match. (e) nit: ProjectScreen's `Banner` import moved under the leading
comment; the shared.tsx imports alphabetized. (f) A side effect of nested routes (pullfrog re-re-review): if the
session expires mid-navigation and a screen's fetch returns 401, the shell checks /auth/me only once, so it can't
return from "signed in" — and the "Signed out" Banner's "Go to sign-in" (an SPA navigation to /dashboard) also lands
as a child of the same shell, looping the Banner (before revision 11, navigation remounted and re-checked → the
sign-in screen appeared). Options: (1) **a 401 notification path** (`session-expiry.ts`'s context — when a
FailureNotice renders a 401 it tells the parent, and the shell drops to signed-out on the spot and renders the
sign-in screen) / (2) make the recovery link a `hardNavigate` (a full reload — explicitly reproduces the
pre-revision-11 behavior) / (3) re-check /auth/me on every navigation (the round trip returns — against revision 11's
purpose). → (1) adopted (reacting to the first 401 only; no added round trip, no reload needed). 1 e2e added
(/auth/tokens 401 → the sign-in screen at the same URL + "You are signed out.").

**Verification (2026-09-04)**: `bun run check` 7 stages pass (fallow's CRAP finding on `DashboardShell` resolved by
splitting parts). web e2e 25 pass (following the `/auth/me` mocks and the axis-switch selector change). `astryx
doctor` no new findings. React Doctor (diff) none. axe-core 18 states, 0 violations. 33 screenshots (the Artifact in
the PR body).

### DP4 implementation-time ruling record (2026-09-05)

The subjects are the scriptless ceremony pages' 11 states: CLI login's approve / complete / refuse / uniform error /
the sign-up notice (the 3 signupPolicy kinds), sign-up control's closed / invite-required / invite-invalid, `/invite`.
Each ruling point was decided by the same loop as DP1–DP3 (enumerate ≥3 options → search for upward compat / a
silver bullet → end once a round produces no new options → select). Judgment criteria: don't break CSP
`script-src 'none'` or the meta / headers duplication; styles come only from self-hosted external CSS
(`style-src 'self'` — don't grow the inline-hash allowances); don't duplicate brand values outside `apps/web/theme/`
(ADR-0013); don't break a single AUTH_SPEC display requirement or uniformity rule; don't mix preview-only code into
the distribution; cheap reversibility.

**Premise corrections (facts found during implementation)**: (1) `theme/maruhi.css` (an `astryx theme build`
artifact)'s brand tokens (`--color-accent` / `--font-family-*` / `--radius-*` etc.) are defined not on `:root` but on
`:scope` under `@layer astryx-theme`'s `@scope ([data-astryx-theme="maruhi"])`. Only the data-visualization colors are
on `:root`. So a page consuming the theme needs `<html data-astryx-theme="maruhi">` (the same mark as the dashboard's
root). (2) Workers Static Assets' default delivery headers are `Cache-Control: public, max-age=0, must-revalidate` +
ETag (measured via wrangler dev — same as Cloudflare's default). The browser revalidates every load, so swapping a
fixed-name CSS file takes effect on the first read after deploy (ruling G). (3) Even against an unconfigured server
(`wrangler dev` with no `.dev.vars` = e2e), `GET /auth/cli/verify?flow=…` returns the uniform error page (400 /
HTML), so server-delivered pages' actual delivery can be checked from e2e, styles included (ruling I). (4) axe found
1 violation that predates the change: `/invite`'s `pre` (horizontal scroll) isn't keyboard-reachable at 390px
(`scrollable-region-focusable`, serious).

**A. The CSS's placement and delivery** — options: (i) `apps/web/public` static assets (the same path as
`/invite.css`. Same origin,
self-hosts bundle it too · covered by `write-headers.ts`'s byte-equivalence check) / (ii) serve CSS on a Worker route (server self-contained,
but a style endpoint mixes into api-schema, and `index.ts`'s `no-store` would have to come off) / (iii) inline `<style>` + hash allowance
(forbidden by the invariants) / (iv) the Worker embeds the CSS in its bundle as a text module and serves it (a variant of (ii) — web/server
double bookkeeping) / (v) unify into 1 file with `/invite.css`. Round 1's new option: **(i)+(v) = make `apps/web/public/pages.css` the shared
stylesheet for /invite and the server-delivered pages** (yes, novel). Round 2: none. **Selected = (i)+(v)**. The server-side HTML just references
`/pages.css`; its real-delivery reachability, content-type, and match to source are pinned by web's e2e in the combined configuration (the same
`apps/server/wrangler.jsonc` as production). `vite.config.ts`'s `PUBLIC_PASSTHROUGH` and `write-headers.ts`'s equivalence check move `invite.css`
→ `pages.css`. The `_redirects` `/invite.css` shield (a 200 rewrite) became unnecessary and was removed (66 → 65). The name avoids the internal
word "ceremony" → `pages.css` (use = scriptless pages in general). Rejected: (ii)(iv) — as above. (iii) is forbidden.

**B. Taking in the brand tokens** — enumerated on the premise that ROADMAP DP4's "unify the brand via self-hosted CSS" (owner ruling 2026-09-03)
overrides the session-41 ruling BB-b (achromatic only): (i) keep achromatic and show only ㊙ and the wordmark (against the owner ruling) / (ii)
hand-copy hex (violates ADR-0013) / (iii) generate from `maruhi.css` + a divergence test (the `apps/site` `scripts/theme.ts` pattern — needs a
generation script, an artifact, and a duplicated extractor) / (iv) **bundle `theme/maruhi.css` itself unconverted as `/theme.css`, and let
`pages.css` only read `var(--…)`** (the artifact = the theme file itself. 24 KB / gzip 4 KB, read once per ceremony page) / (v) extract only the
`@layer astryx-base` `:root` block at build time (another small generator would be needed, and per premise correction (1) the tokens that matter
aren't there). Round 1's new option: (iv) (yes — keeps (iii)'s merits [single source of truth, zero drift] and removes the generator and the
copy). Round 2: none. **Selected = (iv)**. `write-headers.ts` copies `theme/maruhi.css` → `dist/public/theme.css` after build and checks byte
equivalence (the same contract as `pages.css` / `invite.html`). Pages carry `data-astryx-theme="maruhi"` on `<html>` (premise correction (1)).
Corollary: Astryx's `@layer reset` (the `:where(h1…p, code)` type setup) also applies in the same scope, but being inside a layer, `pages.css`'s
unlayered rules always win — a ceremony page's typography is fully readable in `pages.css` alone. `--font-family-body`'s leading Figtree isn't
loaded (falls to system fonts, same as the dashboard — §1-3). Rejected: (i)(ii)(v) — as above. (iii) is implied by (iv).

**C. The shared frame `page()`'s structure** — options: (i) status quo (h1 = "㊙ maruhi"; a page's title is h2) / (ii) a document-style single
column (40rem) + a brand header (a non-heading `header` = logo + wordmark) + **the page's title becomes the h1** (old h2 → h1, h3 → h2) / (iii)
a `login`-template-style centered card (same shape as the dashboard's sign-in — doesn't fit notice-style long text, and on mobile it's full width
anyway) / (iv) the same shape as `/invite` (= the document style). Round 1's new option: integrate (ii)+(iv) into 1 frame and bring `/invite`
onto the same frame (yes). Round 2: none. **Selected = (ii)+(iv)**. The logo: (a) the ㊙ emoji as text (status quo) / (b) **`<img
src="/logo-inverted.svg">` + `img-src 'self'`** (the same real asset and the same pinned vermilion as DP3 ruling J revision 3) / (c) an inline SVG
at currentColor (path duplication — already rejected at DP3) / (d) a CSS background-image (also needs `img-src 'self'`, with less alt-text
control) → **(b)**. CSP in both meta and headers widens to `style-src 'self'; img-src 'self'` (no `'unsafe-inline'`, no hashes), and `/invite`'s
per-path CSP took the same shape. `<meta name="color-scheme">` is placed for dark rendering before CSS arrives, and the favicon's `<link
rel="icon">` is included like the SPA's.

**D. The confirmation code's visibility (the phishing guard's UX)** — character-set check: `generateUserCode` (cli-flow.ts) displays Crockford
Base32's 32 chars (I / L / O / U excluded) × 8 chars as `XXXX-XXXX`. The remaining confusables: 0 / D, 8 / B, 5 / S, 2 / Z. Options: (i) system
monospace enlarged (2.5rem), letter-spacing 0.14em, on its own element / (ii) self-host a monospace font (§1-3's "add if a problem shows") /
(iii) `font-variant-numeric: slashed-zero` (works only when the font has the `zero` feature — otherwise nothing happens) / (iv) split each group
into `span`s with wider spacing / (v) color-differentiate by character class (the shape emphasizing part of the code invites the misreading "only
this part matters"). Round 1's new option: (i)+(iii) (yes — gets 0 / D disambiguation without a self-hosted font). Round 2: none. **Selected =
(i)+(iii)**. On the real machine (Linux Chromium: Liberation Mono / DejaVu Sans Mono) 0 shows a slash and is distinguishable from D; 8 / B, 5 / S,
and 2 / Z were also distinguishable (screenshot). macOS's SF Mono / Menlo and Windows's Consolas carry a slashed / dotted 0 by default or via
`zero`. **A self-hosted monospace is not proposed** (no problem surfaced. The CLI side's display is DP5). The wording keeps **"Approve only if
this code matches the one shown in your terminal."** in bold, and the code sits on a face labeled "Confirmation code". **Distinguishing Approve /
Deny**: (a) Approve = accent fill + on-accent, Deny = same-size outline, order Approve → Deny / (b) Deny first (reading order puts refusal in view
first, but every legitimate use pays the reversed order) / (c) both outline (indistinguishable) / (d) a "I confirmed the match" checkbox before
Approve (making it mandatory without a script is possible via `required`, but the approval's entitlement is the ticket — it adds only ceremonial
friction) → **(a)**. With no text field, Enter doesn't implicitly submit, and focus doesn't land on either button automatically.

**E. The wording and composition of the sign-up-notice / refusal pages (H6's specified items)** — options: (i) keep the wording and change only
the look / (ii) **align the 4 families (closed / invite-required / invite-invalid / the CLI-originated notice × the 3 signupPolicy kinds) to the
same 3 stages: what happened (h1 + 1 sentence) → what did not happen (an `outcome` line = a left accent rule) → what you can do next (h2 + a list)**
/ (iii) merge closed and invite-required into 1 page (the policy is public information; since varying the page isn't varying the failure reason,
the value of separating them remains) / (iv) give detailed reasons (against §3 / §4-2's uniformity — forbidden). **Selected = (ii)**. The 3 refusal
pages' outcome line is "No account was created."; the CLI notice's is "Nothing has been created or changed by opening this page."; the uniform
error and refusal-complete's is "No token was issued.". Uniformity is unchanged (invite-invalid doesn't distinguish invalid / expired / consumed;
the error page doesn't distinguish flow states). No waitlist collection surface is built — it goes as far as "contact the operator of this server"
(hosted-design.md §2-2). The existing tests' assertions only followed the wording change (`no account was\ncreated` → `No account was created.`).

**F. `/invite`'s treatment** — options: (i) keep `invite.css` and only align the look (2 CSSes carrying the same rules) / (ii) **move it onto the
shared frame (`/theme.css` + `/pages.css` + the brand header); its structure as an independent static asset (per-path CSP, `write-headers.ts`'s
mechanical checks, the near-miss 301) stays as-is** / (iii) move `/invite` to server delivery (changes the very structure of §15-3's "independent
static asset" — rejected). **Selected = (ii)**. The h1 is "You have been invited to a maruhi project" (the old h1 was the brand name). `pre` gets
`tabindex="0"` (the fix for premise correction (4) — gets the shared focus ring). The mechanical checks pass `src="/logo-inverted.svg"`
(root-relative) under the existing rules, and `img-src 'self'` was added to both the meta and the per-path CSP. e2e's assertion "`/invite.css` is
passed through by the shield" was removed since its subject no longer exists; only `/invite`'s own 200 remains.

**G. Propagating CSS updates (caching)** — options: (i) **do nothing** (premise correction (2): the default revalidates every load) / (ii) append
`?v=<hash>` on the HTML side (needs a path for server to learn web's build hash) / (iii) content-hash names (the name isn't stable — can't be
referenced from server-rendered HTML, same as session-41 BB-c) / (iv) an explicit `cache-control` in `_headers` (just writes the same value as
the default). **Selected = (i)** + e2e pins `/theme.css` / `/pages.css`'s `must-revalidate` and ETag (we'd notice if the default changed). The
window where a Worker response's (`no-store`) HTML grabs an old CSS is "right after a deploy,
the revalidation returns 304" case, and the ETag is computed from the content so it can't happen.

**H. a11y** — the method is the same as DP3 ruling E (a one-off axe-core injection — adds no dependency). Scope: 11
pages × light / dark / 390px light / 390px dark = **44 states, 0 violations** (wcag2a / 2aa / 21a / 21aa /
best-practice). The heading hierarchy is h1 = the page's title → h2 = sections (What will be granted / What you can do
/ What to do next / Accept the invite). The landmarks are `header` (banner) → `main`. The focus ring is accent 2px
offset 2px (the same look as DP3 E-(e)). Contrast follows the theme values (text-primary / secondary on body,
on-accent on accent, accent links), and axe reported no color-contrast findings. Fixed: `/invite`'s `pre` (F).

**I. The visual-check and screenshot method** — options: (i) **feed the render functions (`render*`) fixed inputs,
write the HTML out, serve it same-origin as `pages.css` / `theme.css` / the logo, and shoot it in Chromium (a
scratchpad one-off script. The distribution is untouched)**; only `/invite` is really served (wrangler dev) / (ii) run
the real flow (`POST /auth/cli/start` → verify → GitHub OAuth) (needs an OAuth App — impossible in this session) /
(iii) put preview routes or mock data in the distribution (forbidden). **Selected = (i)**. Additionally, e2e opens the
really-delivered uniform error page (premise correction (3)) in Chromium and checks `.page`'s width (40rem), body's
background color (that the theme's variables resolved), the logo loading, 0 CSP violations, and 0 script elements.
before / after is 11 pages × 4 states = 44 shots each (the Artifact in the PR body).

**Ruling points that emerged**: (J) the stylesheet path constant `PAGE_STYLESHEETS` was exported but had no consumers
— hit fallow's dead-export rule → made private (the referenced files' reachability is e2e's job). (K) adding CSP /
style assertions to the approval page's success-path test hit cyclomatic 13 and fallow's complexity threshold →
extracted to the `expectStyledScriptFreePage` helper (both header / meta CSPs carry `style-src 'self'` /
`img-src 'self'` / no `'unsafe-inline'` / no hashes; 2 `<link>`s; no script / style elements or style attributes).
(L) the approval page's grant list went `<ul>` → `<dl>` (label / value; 1 column at narrow widths). tokenName stays an
inert `<code>` rendering, and the supplement "Chosen by the requester, shown verbatim." moved to `<small>`.

**B revision 1 (2026-09-05, pullfrog's first review — undefined tokens)**: the finding = `--font-weight-semibold` /
`--font-weight-medium`, which `pages.css` references, are **referenced but never defined** in `theme/maruhi.css` (they're
defined in Astryx core's `astryx.css`, which the dashboard additionally loads but the ceremony pages don't). The
unresolved `var()` fails silently at computed-value time, and every h1 / h2 / `strong` (the phishing guard's sentence)
/ outcome line had lost its bold. A defect none of visual check, axe, or e2e could catch (the screenshots serve the
same 2 CSS files so they reproduce the same gap; axe doesn't check weight; e2e was only checking the background
color). Options: (i) add `--font-weight-*` to `defineTheme`'s `tokens` and `theme:build` (the theme is outside this
PR's scope — touching it needs owner confirmation) / (ii) write the numbers (600 / 500) in `pages.css` (copies of
Astryx's values) / (iii) **use the CSS keyword `bold`** (h1 / h2 / `strong` are bold at the UA default so this just
replaces the declaration; brand and the outcome line also take `bold`. `.code-label` and `.button`'s medium is dropped
— uppercase + letter-spacing / fill is enough) / (iv) a `var(--font-weight-semibold, bold)` fallback (the
below-described mechanical check would then carry an "undefined but tolerated" exception) / (v) bundle Astryx core's
stylesheet too (tens of KB of rules the ceremony pages don't need). Round 1's new option: check "reference set ⊆
definition set" at build time in `write-headers.ts` (yes — blocks this defect class structurally regardless of the
approach). Round 2: none. **Selected = (iii) + the mechanical check**. Adding `tokens` to the theme (i) is left on the
PR as an owner decision (if semibold 600 is wanted on ceremony pages, adding it to `maruhi.ts` is the correct route,
and `pages.css` would then go back to `var()`). The check collects `pages.css`'s `var(--…)` references and throws if
their difference from `theme/maruhi.css`'s `--…:` definition set is non-empty (run against the old `pages.css` it
detects 2; the new version 0). e2e added `font-weight` = 700 on the h1 / outcome line. The same review also raised
"`theme.css`'s byte-equivalence check always matches because the same script just wrote both files (it guarantees
nothing)" — `theme.css` was removed from the equivalence check (`invite.html` / `pages.css` do go through vite's
publicDir copy, so it means something for them), and `/theme.css`'s contract was reworked to be carried by the token-
resolution check above.
**Revision 1 addendum (pullfrog re-review)**: the finding that the check only sees name existence — a definition that
exists but whose *value* `var()`-references an Astryx-core token (`theme/maruhi.css` carries 16+ such, e.g.
`--text-heading-1-weight: var(--font-weight-semibold)`) would still pass if `pages.css` used it → the check now holds
definitions as a `Map<name, value>`, recursively follows `var()`s inside values, and fails with the path shown when it
hits an undefined one (verified: the composed CSS `var(--text-heading-1-weight)` detects `--text-heading-1-weight ->
--font-weight-semibold`).

**Verification (2026-09-05)**: `bun run check` 7 stages pass (fallow with `FALLOW_AUDIT_BASE=origin/main`). The
server's auth / signup-policy tests: 87 pass. web e2e 30 pass (`/theme.css` / `/pages.css` real delivery, byte-match,
revalidation headers; added the uniform error page's style application and weight). axe 44 states, 0 violations.
Screenshots before / after, 44 each (re-shot after revision 1), CSP violations 0.

### DP5 implementation-time ruling record (2026-09-05)

The subject is the CLI's output surface: stderr's notices (Note / Warning / failure) and colors, suppression of
repeating Notes, `login`'s guidance, English copy editing, `--help` consistency, and ADR-0016 decision 7's wording.
Each ruling point was decided by the same loop as DP1–DP4 (enumerate ≥3 options → search for upward compat / a
silver bullet → end once a round produces no new options → select). Judgment criteria: don't break a single ADR-0016
decision (don't put typed values into diagnostics · the exit code is the error kind · the only built-in flags are
`--help` / `--version` · don't read `process.*` directly · stdout carries only the command's output) or decision 7's
verdict semantics; the diskless invariants (Note suppression mustn't hold plaintext or secret state); add no
dependencies; don't touch the server / web / specs; cheap reversibility.

**Premise corrections (facts found during implementation)**: (1) **Bun's `console.error` paints its whole output red
when stderr is a terminal** (measured `\e[0m\e[31m…\e[0m`). "ANSI colors are used nowhere today" was wrong — help text,
Notes, Warnings, and prompt guidance were **all coming out red** (a terminal's red means danger, so a Note looked
like a warning). (2) `process.stderr.write` / `process.stdout.write` are async against a pipe, and `bin.ts`'s
`process.exit` truncates the tail (measured: cut off at 7,401 of 50,000 lines). `node:fs`'s `writeSync` returns after
completion on a terminal, pipe, or file alike. (3) For an effective-admin user, **since the day the project was
created**, every push / pull emitted a checkpoint proposal: criterion (iii)'s admin-side criterion is "the latest
checkpoint that is notarized (non-empty audit_head_hash)", but the boundary checkpoint bundled into the env-creation /
rotate compound (`boundary-checkpoint.ts`) has `auditHeadHashHex: ""` so it doesn't count — "unissued" = propose
immediately. On push, the anchor's Note rides the same route, so 2 Note lines have been emitted per push since day
one. (4) An execution that passes through a sync → re-sync route twice (e.g. a re-sync after a floor violation) lists
the same Note (the head-declaration send failure) twice within one command. (5) 4 places emitted Notes to stdout
(`io.log`) (`audit list` / `audit self` / `logout`'s MARUHI_TOKEN note / `key generate`) — an oversight of decision 9
(stdout carries only the command's output). (6) The server's flow TTL is `CLI_FLOW_TTL_MS` = 15 minutes,
and `POST /auth/cli/start`'s `expiresInSeconds` comes from it too. ROADMAP's "10 minutes" is wrong. (7) Upstream's
(`CliOutput.defaultFormatter`) automatic color detection looks at `process.stdout.isTTY` and `NO_COLOR === "1"` —
an stdout basis (help goes to stderr) that also disagrees with the NO_COLOR convention (disabled when non-empty).

**A. The TTY discipline for color and symbols** — options: (i) colorless, ASCII only (just switching stderr writes to
`writeSync` stops Bun's red painting) / (ii) **color only on the prefix** (`Note:` cyan, `Warning:` yellow, `maruhi:`
red) + full help uses upstream's default palette (bold headings, cyan usage, green flag names); detection = "is stderr
a terminal" + `NO_COLOR` / `FORCE_COLOR` / `TERM=dumb` / (iii) whole lines colored (the same shape as Bun's current
behavior — color bleeds into values, identifiers, and URLs in the body) / (iv) Unicode symbols (✓ / ⚠ / ✗) / (v) a
`--color` flag (against decision 5 — it adds a global built-in flag). Round 1's new option: narrowing (ii) to "color
only the **constant prefixes**" makes "no color on values or identifiers" guaranteed **by structure** rather than by
discipline (yes). Round 2: none. **Selected = (ii)**. No symbols (avoids mojibake on Windows terminals / non-UTF-8
locales — the prefix words carry that role). DP1's vermilion is not imitated in terminal colors (a 16-color red is
danger). Detection is the pure function `shouldUseColor({ stderrIsTerminal, envVar })` (`FORCE_COLOR` non-empty >
`NO_COLOR` non-empty > `TERM=dumb` > is stderr a terminal), supplied by production (`live.ts` — the only place
`process.*` is read) as `CliIo.colorEnabled()`; tests default to colorless (`setColor(true)` exercises the color
path). stdout never gets color (it's data). Upstream's auto-detection isn't used (premise correction (7)) — it's
passed explicitly to `defaultFormatter({ colors })`. Rejected: (i) — a diagnostic's kind isn't recognizable at a
glance (there are 60+ Notes). (iii)(iv)(v) — as above.

**B. The Note / Warning / Error vocabulary and destinations** — vocabulary: `Note:` = information (the command
succeeded. An optional next step or a description of the situation. Missing it doesn't lower safety) / `Warning:` =
degraded · needs attention (the command continued but a state the user should check exists. Anything whose being
missed can lower safety always goes here — floor corruption, anchor mismatch, signature-verification failure) /
`maruhi:` = failure (exit code ≠ 0. Sentence 1 = what happened, sentence 2 = the next step). All 3 go to stderr
(decision 9). Options: (i) keep string concatenation / (ii) helpers in `display.ts` / (iii) methods on `CliIo`
(`io.note`) / (iv) **a new module `notice.ts`** (`logNote` / `logWarning` / `logFailure` + the pure `formatNotice`).
Round 1's new option: (iv) + giving continuation lines (`details`) the same function's 2-space indent (yes). Round 2:
none. **Selected = (iv)**. All ~60 `\`Note: ${…}\`` / `Warning:` concatenations were replaced, and the 4 places
emitting to stdout (premise correction (5)) moved to stderr. `display.ts`'s `logWarnings` and `cli-formatter.ts`'s
`maruhi:` prefix use the same rendering. Rejected: (iii) — a fake `CliIo` would end up implementing the decoration
too, and tests couldn't capture the pre-decoration line.

**C. The rules for suppressing repeated Notes** — options: (i) **count "unissued" against genesis's timestamp** (the
same 7-day threshold. No state held) / (ii) record "already shown" per project in a non-secret config file, once a day
(a new persistence location and cross-device drift) / (iii) a `--quiet`-style flag (the user has to remember it; it
doesn't fix the default) / (iv) shorten the wording and emit it every time / (v) drop the anchor note on push and keep
it only on rotate / (vi) **fold the anchor's advice into the same 1 line as the checkpoint proposal**. Round 1's new
options: (i)+(vi), and **"a Note / Warning with identical wording emits at most once per command run"**
(`NoticeLedger` — `runEffectCli` supplies a fresh ledger per run; contexts without a ledger don't suppress. Resolves
premise correction (4)) (yes). Round 2: none. **Selected = (i)+(vi)+the ledger**. CRYPTO_SPEC §6.3 (iii)'s "7 days
elapsed or unissued" is read as "unissued = the baseline is still genesis"; within 7 days of genesis nothing is
proposed (the proposal is a SHOULD's accessory — the spec's detection condition itself is unchanged — a human task if
the owner wants the spec's wording amended). The anchor note after rotate / sweep stays unconditional ("the epoch
advanced = it's certainly stale" — session-35 ruling P), with a shorter wording. **Not suppressed**: Warnings like
floor corruption, anchor mismatch, signature-verification failure, or an unconverged obligation keep their conditions
and strength. The first-sync "no floor" Note stays as-is (it's one-shot — it stops once the floor file exists).

**D. `login`'s deadline and guidance text** — D-1 the deadline: (i) write the 15-minute constant into the CLI / (ii)
**derive "This request expires in 15 minutes" from the server response's `expiresInSeconds` (the same rounded value
as the deadline check)** (truncate to minutes; under 1 minute shows seconds). The expiry text carries the same
duration ("The sign-in request expired (it was valid for 15 minutes). Run `maruhi login` again") / (iii) don't show
it. **Selected = (ii)**. ROADMAP's "10 minutes" is the error — it should be 15 (corrected in ROADMAP's completion
note. The server's TTL is unchanged). D-2 destinations: (i) as now, guidance and result both to stdout / (ii) **the
interactive guidance (the URL, the confirmation code, the deadline, the wait, the browser notice) goes to stderr; the
result ("Signed in as …", the token's expiry) goes to stdout** / (iii) everything to stderr. **Selected = (ii)** —
the prompt is already on stderr (`live.ts`), and `maruhi login > file` still shows the guidance. D-3 progress while
waiting: (i) emit "still waiting" on an interval (pollutes the log) / (ii) a `\r` countdown (a TTY-only drawing path)
/ (iii) **emit nothing** (the deadline's 1 line conveys the window). **Selected = (iii)**. D-4 the browser: only when
an auto-launch was tried and failed: "Could not open a browser automatically. Open the URL above manually"; on
success: "Opened your browser. If nothing appeared, open the URL above manually"; environments that don't try
(agents, non-interactive) get nothing added (the URL guidance is already there). D-5 vocabulary: matching the approval
page (DP4) — "Confirmation code: XXXX-XXXX" + "Approve only if the browser shows this exact code (it protects you
against phishing)" (the internal word "AUTH_SPEC's phishing guard" is gone). D-6 signupPolicy's upfront fail-fast
guidance also goes to stderr.

**E. English copy editing of error texts (the glossary)** — conventions: sentence case / a single sentence gets no
trailing period; multiple sentences are separated by in-line periods with none at the end (the existing 96 entries
already follow this — the real inconsistency was command-name notation) / commands and flags always backquoted
(`maruhi project checkpoint`) / sentence 1 = what happened, sentence 2 = the next step / Markdown's `**emphasis**`
never reaches the terminal. Terms: **sign in / sign-in** (prose. The command stays `maruhi login`), **server** (origin
survives only in the env-var name `MARUHI_TOKEN_ORIGIN`), **token** (never "PAT"), **environment variable** (never
"env var" — the flag name `--env` and IDs are separate), **master key** (never "keypair"), **recovery code**, **OS
keychain**, **user ID** (prose. `user_id` stays as a field name), **epoch DEK** (CRYPTO_SPEC's term). A diagnostic's
trailing spec reference "(CRYPTO_SPEC §6.3)" is kept (traceability when pasted into an issue) but never appears in
help (F). Decision 7's wording (G) and the ceremony-family refusal texts (invite accept / member add / server grant /
schema import) are unified to the order "Refused to …: what was detected. why. what to do".

**F. `--help` consistency** — options: (i) only unify the descriptions / (ii) **a golden file** (`test/golden/help.txt`
— all 54 levels + bare `maruhi` + `maruhi --help`. Update via `UPDATE_GOLDEN=1` and read the diff in review) +
mechanical checks (descriptions start with a capitalized verb, contain no `§`, no ANSI, don't pollute stdout) / (iii)
assertions only (breakages leak through the assertions' gaps). **Selected = (ii)**. Conventions: a description is one
verb-initial line; no spec § references (users can't read the spec); document stdin / stdout behavior and dangerous
operations (permanently / forces a rotation); groups are "Manage X (a / b / c)". Added: a product one-liner at root
(the head of bare `maruhi`), `--` in the usage lines of `run` / `ci run` (`maruhi run [flags] -- <command...>` —
decision 8's notation itself), shared-flag defaults as "(default: the `server` setting)".

**G. ADR-0016 decision 7's wording** — the verdict's semantics are unchanged (primary boundary = stdin and stdout both
terminals, second layer = a known agent, fail-closed). Agent detection: "Refused to display values: an AI agent
environment was detected (name). Values are shown only to a person at an interactive terminal, so they never land in
an agent's transcript. Run this command yourself in a terminal". The TTY boundary: "Refused to display values: stdin
and stdout are not both an
interactive terminal. Values are shown only to a person at a terminal (pipes, redirects, CI, and AI agents are
refused), so they never land in a file or a log. Run this command yourself in a terminal, without redirecting its
input or output". The discipline of not recommending `maruhi run` (don't hand out a bypass recipe) stays.

**H. How TTY behavior is verified** — unit (`CliIo` / `Stdio` swaps): the color detection (`shouldUseColor`'s 4
conditions), that only the prefix is colored, the ledger's suppression, login's deadline (3 `expiresInSeconds`
shapes + a non-number), the stdout / stderr split (`env.logs` / `env.errors`), the golden. Real processes (`script
-qec`'s pseudo-TTY and `| cat` / `2>&1` pipes): Bun's red painting is gone and only the prefix is colored; no ANSI on
a pipe; `NO_COLOR=1` / `FORCE_COLOR=1` take effect; `maruhi --version` / `config get`'s stdout stays clean; a real
`maruhi login` against wrangler dev (a dummy `.dev.vars` + local D1 migrations) (`POST /auth/cli/start` — no
approval is performed). The before / after is an Artifact for the owner.

**I. User-facing docs** — `apps/site/docs/getting-started.mdx`'s description (matching the confirmation code in the
browser) stays correct after the change (untouched). `README.md` has no CLI output examples. `docs/SELF_HOSTING.md`'s
`maruhi login` line comment "client_id is resolved from the server" is a leftover of the mechanism removed in the
2026-08-31 §4 revision, so just that 1 line was fixed.

**Ruling points that emerged**: (J) Bun's `console.error` red painting (premise correction (1)) → `live.ts`'s `log` /
`logError` moved to `writeSync(1 | 2, …)` (per premise correction (2), `writeSync`, not `process.stdout.write`). (K)
The 4 Notes on stdout → stderr (the tests' assertions followed to `env.errors`). (L) `run`'s usage gains `--`
(included in F). (M) fallow's complexity (`checkpointProposal`'s closure) → `baselineIsStale` extracted into a
function; the duplication (`schema set` / `var rm`'s env resolution) → `requireVerifiedEnvironment` is shared.

**J revision 1 (2026-09-05, Cursor Bugbot's first review — a closed pipe)**: the finding = `writeSync` throws `EPIPE`
on a pipe whose reader already closed (anything past line 1 of `maruhi pull | head -1`), and being inside
`Effect.sync` it ends as a defect = internal error (the old `console.log` silently discarded it — measured). Options:
(i) swallow only `EPIPE` (the reader already said they don't need it; there's nobody and no path to report to) / (ii)
swallow all errors (would swallow real failures like EBADF too) / (iii) go back to `console.log` (the red painting
comes back). **Selected = (i)** — `writeLine` is exported, and a check pinning exit code 0 under a real process (a
bun writer | `head -1`) was added to `live-io.test.ts`.

**Revision 2 (2026-09-05, pullfrog's first review)**: (1) `writeLine` became a loop that, beyond `EPIPE`, retries
`EAGAIN` (a non-blocking fd) and continues partial writes (per pullfrog's proposal. Since CI's fallow judged
`writeLine` a dead export, a check that imports it directly from the test [a full write to a file] was also added).
(2) **B's ledger doesn't fit per-item notices** — `schema import`'s per-candidate high-entropy warning would be
suppressed on a retry of the same candidate (after editing with `e`) or on a different candidate of the same shape,
producing "a yes prompt with no visible reason". Options: (i) put the candidate name in the wording (still suppressed
on retry) / (ii) **add `scope: "prompt"` to the notice — it bypasses the ledger and is emitted every time, 2-space
indented directly under the candidate** (the old implementation's indent also returns) / (iii) include the call site
in the ledger's key (the site is unrelated to the wording's identity). **Selected = (ii)**. Alongside, the unused
`details` arg was dropped (a pullfrog nitpick). (3) 2 backquote slips (`maruhi rotation list` / `maruhi config set
defaultProject <id>`), `logWarning(\`${warning}\`)`, `Re-login` → `Sign in again`. (4) `help.test.ts`'s "contains no
ANSI" assertion was vacuous since the test environment is colorless → replaced with a check that under `setColor(true)`
headings become bold, and when disabled there's no ANSI — pinning both. **Compatibility note**: since `login`'s
guidance and several Notes moved stdout → stderr, a wrapper logging via `maruhi login | tee` loses the URL and the
confirmation code (the intended separation. Written in the release notes).

**Revision 3 (2026-09-05, Cursor Bugbot's re-review)**: revision 2 (ii)'s `scope: "prompt"` doesn't fit a
long-description Note — that Note is emitted **before** the candidate's presentation (`approvalStep`'s
`describeCandidate`), so the indent would attach to the preceding item. It was returned to run scope (no indent):
containing a line number, it's unique per candidate, and being emitted only once there's no need to repeat it on
retry. Only the high-entropy warning emitted right after the presentation uses prompt scope.

**Verification (2026-09-05)**: `bun run check` 7 stages pass (fallow with `FALLOW_AUDIT_BASE=origin/main`). CLI tests
867 (+ 9 notice · 2 help golden · 2 login · the checkpoint's genesis basis). The real-process TTY / pipe captures and
the real `maruhi login` output against wrangler dev are in the PR's Artifact.

### DP5 addendum: re-looping the thin ruling points (2026-09-05)

After PR #151 merged, answering the owner's question with a self-inspection found that the ruling record's A / B / C
had been looped until "a round produces no new options", but D onward had been decided after 1 round or just
enumeration (J's EPIPE and B's per-item ledger problem are the kind of hole I could have produced myself by asking
one more round of "what breaks under this option" — they were caught by review bots). Here D / E / F / G / J are
re-run through the same loop, noting whether each round produced a new option. E / G, where an upward compat
appeared, are implemented in this addendum (PR #152); F-(iv) is a proposal to the owner; D / J are kept as-is (with
reasons).

**D login (re-looped)** — D-1 the deadline: round 1's new option = also writing the absolute time "(at 09:52 UTC)"
(yes) → the relative display suffices; a UTC absolute time would clash with the user's local clock and add confusion
(rejected). Round 2: none. D-2 the destination: round 1's new option = write directly to `/dev/tty` (bypasses both
pipes and redirects) (yes) → against the rule of not touching `process.*` / fds directly (ADR-0016 decision 5) and
testability; the confirmation code isn't secret so no bypass is needed (rejected). Round 2: none. D-3 progress while
waiting: round 1's new option = at the window's halfway point emit 1 line, "Still waiting (7 minutes left)" (yes) →
useful for a user who stepped away, but it adds a line to non-TTY logs too and the deadline's line already conveys
the window (rejected — revisit if the wait feels long on a real machine). Round 2: none. **Conclusion: kept as-is**.

**E English copy editing (re-looped)** — the trailing period: (i) none (all 96 current entries already this shape) /
(ii) always / (iii) only on multi-sentence. Round 1's new option = **make the convention a mechanical check** (yes —
the problem is keeping it honored rather than the choice itself; a glossary drifts the moment it's written). Round 2:
none. **Selected = (i) + the check** `apps/cli/test/message-style.test.ts`: scan the string literals passed directly
to `cliError` / `usageError` / `evidenceError` / `io.log` / `io.logError` / `logNote` / `logWarning` and pin (1) no
trailing period, (2) `maruhi <command>` always backquoted, (3) no `**` (also asserts there are 300+ collected wordings —
guards the check against going vacuous). The first scan found 1 remaining (2) miss (`member.ts`'s "and maruhi project
verify") — fixed. A check on the terms (sign in / server / token …) isn't included: occurrences are context-dependent
and false-positives abound.

**F --help (re-looped)** — round 1's new option = (iv) **generate the docs site's CLI reference from the golden
(`test/golden/help.txt`)** (yes — removes the `--help`-vs-docs divergence structurally. The single source of truth =
the declaration). Since it touches `apps/site`, this addendum doesn't implement it — left as a proposal to the owner
(a shape adding a generated page to DP2's Blume structure; needs the choice between committing the artifact and
generating at build). (v) adding examples (an EXAMPLES section) → upstream's HelpDoc has no such section, and mixing
them into the description breaks the 1-line convention
(rejected). Round 2: none. **Conclusion: the golden stays; (iv) is a proposal**.

**G decision 7's wording (re-looped)** — (i) status quo "stdin and stdout are not both an interactive terminal" /
(ii) shorten to 1 line / (iii) recommend `maruhi run` (a bypass recipe — forbidden). Round 1's new option = **name the
side that failed** ("stdout is not an interactive terminal" / "stdin is not …" / "neither stdin nor stdout …") (yes —
the user can judge from the wording whether to drop `| less` or stop a heredoc. It only uses the verdict's result as
material for the wording; no new check is added = decision 7's semantics unchanged). Round 2: none. **Selected =
naming** (`agent-gate.ts`'s `describeNonTerminal`. Applied to `schema import`'s same-shaped refusal too).

**J writeSync (re-looped)** — the "what breaks under this option" round was re-run: EPIPE (revision 1) and EAGAIN /
partial writes (revision 2) are done. The remaining candidates: (a) `writeSync` to a Windows console handle
(non-ASCII mojibake, partial writes) — unverifiable in this environment; stays a human task. (b) the alternative =
go back to `process.stdout.write` and await a flush via a callback'd empty write before `bin.ts`'s `process.exit`
(on a stream, EPIPE arrives as an `error` event; on Windows it goes through libuv's tty path). **Rejected by
measurement**: under Bun 1.4.0 the callback returns before the data arrives, and a 50,000-line pipe write still cut
at 7,401 lines even awaiting the flush (`writeSync` delivers every line). (c) `Bun.stderr.writer()` (a FileSink) —
flush synchronicity isn't documented, and there's no advantage to leaving the Node-compatible path (`node:fs`)
(rejected). Round 2: none. **Conclusion: kept as-is**. The EAGAIN busy-spin is inherent to synchronous writes — if a
real-machine check on macOS / Windows shows "an unwritable fd persisting long", revisit.

## 6. Out of scope

- A manual dark toggle · **the dashboard (TCB) side's** self-hosted web fonts (revisit if needed — §1-2 / §1-3)
- `maruhi ui` (ADR-0018 stage 2) · a UI carrying values (stage 3)
- A billing page · a status page (H4 / GA)
