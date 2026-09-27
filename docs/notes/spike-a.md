# Spike A results: the front-end stack (funstack-static + funstack-router + Astryx)

Date: 2026-08-01. A ROADMAP Phase 0 verification spike (ADR-0007 / ADR-0013).
The working location is `apps/web` (this spike is not throwaway code — it was left in apps/web as a skeleton Phase 1 can build on. Discarding it is also an option). E2E verification is automated in `apps/web/test/e2e.test.ts` (wrangler dev = real Workers Static Assets delivery + Playwright/Chromium), **4/4 passing**.

## Versions used (all exact-pinned)

react 19.2.8 / react-dom 19.2.8 / @funstack/static 1.2.0 / @funstack/router 1.2.0 / @astryxdesign/{core,cli,build,theme-neutral} 0.2.0 / @stylexjs/stylex 0.19.0 / vite 8.2.0 / @vitejs/plugin-react 6.0.5 / wrangler 4.118.0 / playwright 1.62.1

## Items verified and results

### 1. Build-time RSC and the "use client" boundary — ✅ holds

- `vite build` emits a static shell `index.html` + the RSC payload (`funstack__/fun__rsc-payload/<hash>.txt`) + assets into `dist/public`. The server components' (HomePage / AboutPage) content is **serialized into the RSC payload at build time** (confirmed via an embedded build timestamp)
- `"use client"` boundaries appear inside the payload as module references (`I["...","CounterCard",...]`), and the client island (the counter) hydrates and works in the browser
- Astryx's dist carries a `'use client'` directive on every component, so importing directly from a server module (App.tsx) correctly becomes a client boundary
- With the default (ssr: false) the shell contains no app-body HTML (the mount point only). A landing page that needs SEO has room to consider `ssr: true` (unverified)

### 2. Degradation on browsers without the Navigation API — ✅ degrades per spec

- funstack-router has no `<Link>`; the design has the **Navigation API intercept plain `<a>` elements**. On Chromium, SPA transitions (no page teardown) were confirmed in e2e
- With `<Router fallback="static">`, environments without the Navigation API switch to the StaticAdapter and **every link becomes a full page load (MPA)**. `navigate()` calls console.warn. With no fallback specified it is the NullAdapter (navigation impossible), so **`fallback="static"` should be considered mandatory**
- The unsupported environment was reproduced via `delete window.navigation` (Playwright addInitScript). Page display still works after MPA degradation (thanks to Workers Static Assets' `not_found_handling: "single-page-application"`, a direct `/about` request returns index.html)
- Navigation API support as of 2026: Chromium-family + Firefox support it; **Safari does not (TP only)**, so Safari users get the MPA degradation for now. Whether that is acceptable for a dashboard is a human judgment (E2EE decryption itself works in degraded mode)

### 3. Astryx prebuilt CSS + theme delivery via Workers Static Assets — ✅ holds

- `@astryxdesign/core/reset.css` + `astryx.css` (prebuilt, with cascade layers) are `@import`ed in global.css → Vite bundles them into one CSS asset that can be served statically
- The brand theme `apps/web/theme/maruhi.ts` (defineTheme, extending neutralTheme) is **prebuilt into static CSS + JS via `astryx theme build`**; the CSS is imported and the JS (the theme object with `__built: true`) is passed to `<Theme theme={...}>`. This means **no runtime CSS injection** = compatible with a strict CSP
- Verification finding: `defineTheme`'s `color.accent` (#C73E3A) derives its palette in HCT, so the final `--color-accent` is a derived value (#B22A2B), not the specified hex itself. To match the brand color exactly, use the explicit override `tokens: { '--color-accent': [...] }`
- The generated artifacts (maruhi.css / maruhi.js / *.d.ts) are committed and regenerated via the `theme:build` script. The generated d.ts trips oxlint, so it is excluded via `apps/web/.oxlintrc.json`'s ignorePatterns

### 4. Strict CSP (script-src 'self') — ⚠ holds (but requires one workaround)

- **funstack-static 1.2.0 embeds an inline `<script id="_R_">` in index.html as the bootstrap** (configuring the RSC payload manifest + the entry's dynamic import). Under a plain `script-src 'self'` this is blocked and **the app does not start at all**
- The workaround: after the build, compute that script's SHA-256 and write `script-src 'self' 'sha256-...'` into `_headers` (`apps/web/scripts/write-headers.ts`, already wired into `bun run build`). The script's contents include the payload's content hash and change every build, so the hash generation must always live in the build pipeline
- In this state the full e2e suite (hydration, counter operation, SPA transitions, the theme, xstyle) works with zero CSP violations
- **Human judgment needed**: CLAUDE.md says "no inline scripts, no eval". A hash-allowed inline script is effectively as safe as a self-served script (it won't execute if tampered), but literally speaking it is an inline script. Two options: (a) codify the hash approach and allow it, (b) file an issue / PR upstream (funstack-static) for "an option to externalize the bootstrap file". b is the cleaner route
- A small upstream bug: the shell's `<link rel="preload" as="stylesheet">` uses an invalid `as` value (correct: `style`), so the browser warns (the only harm is the preload not applying). A candidate for an upstream report
- Under a `default-src 'none'` base, what is needed: script-src 'self' + hash / style-src 'self' / connect-src 'self' (the RSC payload fetch) / img-src 'self' data: / font-src 'self'

### 5. The StyleX compiler (for xstyle) × Vite — ✅ holds (with an important correction)

- Adding `@astryxdesign/build/vite`'s `astryxStylex` as a Vite plugin confirmed that `stylex.create` + typed tokens (`spacingVars['--spacing-5']`) xstyle **compiles to static CSS (`.xqifx2i { margin-top: var(--spacing-5) }`) appended to the CSS asset**. E2E-verified via computed style showing 20px applied
- **Correction to the session-01 memo**: "with no compiler configured it renders unstyled with no warning" is inaccurate for @stylexjs/stylex 0.19.0. In reality **the build succeeds without warnings**, and in the browser `stylex.create` **throws `Unexpected 'stylex.create' call at runtime`, so the whole client island fails to render** (an error only in the console). In other words, not a "silent visual breakage" but "the build passes while everything is lost at runtime". It was reproducible via `SPIKE_NO_STYLEX=1 bun run build` (the verification record at the time — this reproduction switch was removed from vite.config.ts on 2026-08-11 after verification completed. To reproduce, temporarily remove `astryxStylex` from the plugin array). The fact that CI can pass while the deploy breaks is the same either way, so **including the e2e (this spike's 4 tests) in the quality gate is the effective defense**
- `astryxStylex`'s API has two forms — take note: passing the `stylexOptions` key gives **legacy mode** (used here: consumes the prebuilt CSS and compiles only app code; the output layer is `priority1`). The new form (direct options) switches to a **library-source build that aliases `@astryxdesign/core` to src**, and additionally injects a layer-ordering inline `<style>` via `transformIndexHtml` (which does not apply to funstack-static's HTML generation and may collide with the CSP). **The right answer for maruhi is legacy mode (consuming the prebuilt)**. The README does not explain the new form, so watch whether behavior changes on upgrades
- StyleX HMR on the dev server (`vite dev`) is unverified (build + delivery verification was prioritized)

### 6. Agent integration / quality-gate integration — ✅ done (root integration is a note only)

- `astryx init --features agents --agent all` → generated `apps/web/AGENTS.md` and `apps/web/.claude/CLAUDE.md` (committed). Their content is Astryx's operating discipline (no divs, mandatory tokens, the discover workflow), consistent with this repository's CLAUDE.md styling rules
- `astryx doctor` passed all checks (6 passed). The theme-wiring warning is resolved by package.json's `astryx.theme` field. Already added to apps/web as the `doctor:astryx` script
- `@stylexjs/eslint-plugin` (0.19.0) was demonstrated to **work via oxlint's jsPlugins** (`stylex/valid-styles` detects invalid properties / invalid values). It was enabled via **`apps/web/.oxlintrc.json` (a nested config inheriting the root via extends)** without touching the root `.oxlintrc.json`
- Added a web vitest project (`apps/web/vitest.config.ts`, the 4 e2e tests). **Deliberately not registered in the root `vitest.config.ts`** (it needs a build + a browser, so it should not share the unit-test lane)

## Root changes to integrate when adopting for real

1. `.fallowrc.json` (done on this branch): add apps/web's entry to `entry` (funstackStatic's root/app are string references in vite.config and cannot be auto-detected) + add @stylexjs/unplugin and @stylexjs/eslint-plugin to `ignoreDependencies`. **Spikes B / C's branches also modify the same file's ignorePatterns line with identical content, so depending on merge order a manual resolution may be needed**
2. Root `vitest.config.ts` / `ci.yml` (not done — a proposal): since web e2e requires the build artifact, adding `bun run --filter @maruhi/web build && bunx vitest run --config apps/web/vitest.config.ts` as an independent CI step (after test step 7) is the right shape. Add `doctor:astryx` to the quality gate too (next to `bun run doctor`)
3. `bun.lock`: apps/web is a workspace, so the root lockfile updates (spikes B / C use standalone installs, so no conflict)

## Remaining questions (to resolve in Phase 1)

1. **The CSP / inline-bootstrap question** (item 4 above — awaiting a human decision + an upstream issue candidate)
2. How to treat Safari (no Navigation API): whether MPA degradation is officially supported. The degraded-mode UX (loaders, forms) is unchecked
3. `ssr: true` (full build-time HTML) mode is unverified. Likely wanted for the landing page
4. The `vite dev` experience (StyleX HMR, Astryx source maps) is unverified
5. Astryx 0.2.0 is 0.x semver. The `astryx upgrade` codemod's real-world behavior is also unverified (the first update PR is the first opportunity)
6. react-doctor now actually inspects apps/web (rules gated on). Currently all passing
7. A real deploy (`wrangler deploy` with Static Assets + _headers applied) is undone — no Cloudflare credentials. Verified up to header attachment under `wrangler dev`
