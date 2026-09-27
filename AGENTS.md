# AGENTS

For the repository-wide development guide (absolute rules, tech stack, quality
gate), see `CLAUDE.md`.

## Claude Code on the web specific instructions

- Setup is handled by the SessionStart hook (`.claude/hooks/session-start.sh`):
  syncing Bun to `.bun-version` and running `bun install`. Do NOT download
  Playwright's Chromium — use the environment's preinstalled build
  (`/opt/pw-browsers/chromium`)
- The hook writes `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH` into the session
  environment, and `apps/web/test/e2e.test.ts`, `apps/web/test/screenshots.ts`,
  `apps/site/test/e2e.test.ts`, and `packages/crypto/vitest.browser.config.ts`
  pass it as Chromium's `executablePath` (when unset they fall back to the
  Playwright-managed browser, so Cursor / CI are unaffected)
- Do not run `bunx playwright install` (it conflicts with the preinstalled build
  and consumes the disk quota)
- Everything else (quality gate, how to run e2e, dev-server caveats) is shared
  with the Cursor Cloud section below

## Cursor Cloud specific instructions

- Bun is installed to `~/.bun/bin` per `.bun-version` (strict pin; PATH comes
  via `~/.bashrc`). The startup install script syncs the version, runs
  `bun install`, and fetches the Playwright Chromium
- The quality gate is `bun run check` (see root `package.json`), the same order
  as CI (`.github/workflows/ci.yml`)
- Root `bun run test` intentionally does not include the `apps/web` e2e. Run it
  with `cd apps/web && bun run build && bunx vitest run --config vitest.config.ts`.
  A prior build is required, and the test spawns its own `wrangler dev`
  (port 8791)
- The web dev server (`bun run --filter @maruhi/web dev`, port 5173) returns 404
  for requests without `Accept: text/html`. Pass `-H "Accept: text/html"` when
  probing with curl (browsers are fine)
- `apps/server` is a stub (no dev script). If needed,
  `cd apps/server && bunx wrangler dev`. No DB, secrets, or external services
  are required today
- Some entries under `.agents/skills` are symlinks into node_modules, so they
  look broken until `bun install` has run
- To use the deepsec skill (`/deepsec`, `.agents/skills/deepsec`), run
  `cd .deepsec && pnpm install --frozen-lockfile`. Do not run
  `npx deepsec init` (the SKILL.md maruhi overlay; `docs/DEEPSEC.md`)
