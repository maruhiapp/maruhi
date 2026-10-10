---
name: testing-web-dashboard
description: How to run and interactively drive the maruhi web dashboard e2e/UI tests — bunx shim, serving the built app via cf dev, page.route API mocking, and headful Playwright on DISPLAY :0 for recorded sessions.
---

# Testing the maruhi web dashboard end-to-end

## Toolchain quirks on this box

- Bun lives at `~/.bun-pinned/bun` (export PATH first). **`bunx` does not exist** — use
  `bun x <pkg>` / `bun run <script>` yourself, BUT `apps/web/test/e2e.test.ts` spawns the
  literal string `bunx` to start cf. If `bunx` is missing, create it once:
  `ln -sf ~/.bun-pinned/bun ~/.bun-pinned/bunx` (bun dispatches on argv[0]).
- Playwright chromium: `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH` points at the browser the
  environment set up — the SHA-256-verified headless shell from
  `scripts/install-headless-shell.sh` (CI, Cursor Cloud) or `/opt/pw-browsers/chromium`
  (Claude Code on the web). e2e and ad-hoc headless scripts pass it as `executablePath`.
  Do NOT run `playwright install` (it fetches an unverified browser; the environments
  point `PLAYWRIGHT_DOWNLOAD_HOST` at an unresolvable host so it fails).
- Headful sessions for screen recordings: the headless shell cannot open a window, so
  launch the image's Chrome instead —
  `chromium.launch({ channel: "chrome", headless: false, args: ["--start-maximized"] })`
  on the desktop's `DISPLAY` (`:0` or `:1` depending on the image). Maximize with
  `wmctrl -r "<title>" -b add,maximized_vert,maximized_horz`.

## Commands

- Unit: `(cd apps/web && bun x vitest run --config vitest.unit.config.ts)`
- E2E (needs build first; spawns its own `cf dev`): 
  `(cd apps/web && bun run build && bun x vitest run --config vitest.config.ts)`
- Serve built app for manual driving: `(cd apps/web && bun run preview)` →
  `cd ../server && bun x cf dev --port 8788` (production-like combined
  worker + assets, strict CSP). The vite dev server (5173) does not apply `_headers`/CSP.
- curl probes need `-H "Accept: text/html"` (dev server) — not needed for cf preview.

## Mocking the API for UI sessions

- There is no test login. `apps/web/test/e2e.test.ts` and `test/screenshots.ts` mock the
  API with Playwright `page.route` — reuse their fixtures from `test/fixtures.ts`
  (`meFixture`, `chainFixture`, `environmentsFixture`, project pages).
- `src/dashboard/api.ts` deliberately does NO schema decoding (ruling BR): arbitrary JSON —
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
