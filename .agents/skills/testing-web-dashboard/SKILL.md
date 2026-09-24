---
name: testing-web-dashboard
description: How to run and interactively drive the maruhi web dashboard e2e/UI tests — bunx shim, serving the built app via wrangler preview, page.route API mocking, and headful Playwright on DISPLAY :0 for recorded sessions.
---

# Testing the maruhi web dashboard end-to-end

## Toolchain quirks on this box

- Bun lives at `~/.bun-pinned/bun` (export PATH first). **`bunx` does not exist** — use
  `bun x <pkg>` / `bun run <script>` yourself, BUT `apps/web/test/e2e.test.ts` spawns the
  literal string `bunx` to start wrangler. If `bunx` is missing, create it once:
  `ln -sf ~/.bun-pinned/bun ~/.bun-pinned/bunx` (bun dispatches on argv[0]).
- Playwright chromium: `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH` may point at
  `/opt/pw-browsers/chromium`, which does not exist on every image. If unset, Playwright
  uses its managed browser at `~/.cache/ms-playwright/chromium-*/chrome-linux64/chrome`
  — both e2e and ad-hoc scripts work without the env var. Do NOT run `playwright install`.
- `DISPLAY=:0` works: `chromium.launch({ headless: false, args: ["--start-maximized"] })`
  renders a real window for screen recordings. Maximize with
  `wmctrl -r "<title>" -b add,maximized_vert,maximized_horz`.

## Commands

- Unit: `(cd apps/web && bun x vitest run --config vitest.unit.config.ts)`
- E2E (needs build first; spawns its own `wrangler dev`): 
  `(cd apps/web && bun run build && bun x vitest run --config vitest.config.ts)`
- Serve built app for manual driving: `(cd apps/web && bun run preview)` →
  `wrangler dev --config ../server/wrangler.jsonc --port 8788` (production-like combined
  worker + assets, strict CSP). The vite dev server (5173) does not apply `_headers`/CSP.
- curl probes need `-H "Accept: text/html"` (dev server) — not needed for wrangler preview.

## Mocking the API for UI sessions

- There is no test login. `apps/web/test/e2e.test.ts` and `test/screenshots.ts` mock the
  API with Playwright `page.route` — reuse their fixtures from `test/fixtures.ts`
  (`meFixture`, `chainFixture`, `environmentsFixture`, project pages).
- `src/dashboard/api.ts` deliberately does NO schema decoding (裁定 BR): arbitrary JSON —
  including malformed/hostile shapes — reaches the display layer, so crafted chain
  snapshots exercise `chain-view.ts` hardening in the real UI.
- Key paths to mock: `GET /auth/me` (session gate — every authed screen calls it once),
  `GET /projects` (cursor `?after=`), `GET /projects/:id/chain`,
  `GET /projects/:id/environments`, `GET .../environments/:env/pull/metadata`,
  `GET /projects/:id/audit/events`, `/invites`, `/rotation/flags`,
  `GET /auth/tokens`, `GET /auth/devices`, `GET /auth/audit/events`.
- Pass non-schema shapes (string entries, non-record payloads, `op: "__proto__"`,
  missing actor fields) to exercise hostile-server handling; hash of entry *i* is the
  NEXT entry's `prevHashHex` (last = `headHashHex`) — a `propose` only becomes pending
  if a following entry exists.

## Driving interactively

- Pattern used: a bun script in `apps/web/test/` (module resolution needs the app's
  node_modules) launching headful Playwright, registering routes, then reading step
  commands from stdin — run it under an interactive shell and feed one line per step.
- **CSP blocks injected inline styles** (`style-src 'self'`): don't add styled DOM
  overlays for instrumentation. `document.title = "..."` is CSP-safe and readable in
  the browser tab while recording. `page.evaluate` itself is unaffected by CSP.
- Useful testids: `project-list`, `load-more-projects`, `member-table`, `env-table`,
  `variable-list`, `proposal-table`, `unreadable-entries`, `login-card`,
  `audit-list-project`, `rotation-table`, `invite-table`, `token-table`, `device-table`.

## Devin secrets needed

- None — the whole dashboard can be exercised with mocked API responses.
