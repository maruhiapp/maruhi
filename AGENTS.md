# AGENTS

For the repository-wide development guide (absolute rules, tech stack, quality
gate), see `CLAUDE.md`.

**Language rule (ADR-0019):** everything written to this repository or to
GitHub is English — code, comments, docs, commit messages, PR titles and
descriptions, issues, review comments and replies. Japanese is used only when
talking with the owner directly, and in the files listed in
`scripts/english-exemptions.txt`.

## Claude Code on the web specific instructions

- Setup is handled by the SessionStart hook (`.claude/hooks/session-start.sh`):
  syncing Bun to `.bun-version` through `scripts/install-bun.sh` (the release
  zip checked against a pinned SHA-256), putting `~/.bun/bin` on the session's
  PATH (through `CLAUDE_ENV_FILE`), and running `bun install`. Do NOT download
  Playwright's Chromium — use the environment's preinstalled build
  (`/opt/pw-browsers/chromium`)
- The hook writes `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH` into the session
  environment, and `apps/web/test/e2e.test.ts`, `apps/web/test/screenshots.ts`,
  `apps/site/test/e2e.test.ts`, and `packages/crypto/vitest.browser.config.ts`
  pass it as Chromium's `executablePath` (when unset they fall back to the
  Playwright-managed browser; CI and Cursor Cloud set it to the SHA-256-verified
  headless shell `scripts/install-headless-shell.sh` installs)
- Do not run `bunx playwright install` (it conflicts with the preinstalled build
  and consumes the disk quota). The hook also sets `PLAYWRIGHT_DOWNLOAD_HOST`
  to an unresolvable host, so any Playwright browser download fails
- Everything else (quality gate, how to run e2e, dev-server caveats) is shared
  with the Cursor Cloud section below

## Cursor Cloud specific instructions

- Bun is installed to `~/.bun/bin` per `.bun-version` (strict pin; PATH comes
  via `~/.bashrc`). The startup install script syncs the version, runs
  `bun install`, and installs the browser. It must install Bun with
  `bash scripts/install-bun.sh`, which checks the release zip against the
  SHA-256 pinned there (the pin CI uses) before running it — never
  `curl https://bun.sh/install | bash`, which runs an unverified script. The
  script edits no shell profile, so the startup script also adds
  `export PATH="$HOME/.bun/bin:$PATH"` to `~/.bashrc` when it is missing
- The browser is the Chrome Headless Shell from
  `bash scripts/install-headless-shell.sh` (the archive checked against the
  SHA-256 pinned there, the pin CI uses), installed into
  `~/.cache/chrome-headless-shell` — never `bunx playwright install`, which
  runs an unverified download. The startup script adds
  `export PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH="$HOME/.cache/chrome-headless-shell/chrome-headless-shell-linux64/chrome-headless-shell"`
  and `export PLAYWRIGHT_DOWNLOAD_HOST="https://playwright-download.invalid"`
  (any Playwright browser download fails, as in CI) to `~/.bashrc` when they
  are missing. The headless shell cannot open a window: a headful session
  (screen recordings) launches the image's Chrome with
  `chromium.launch({ channel: "chrome", headless: false })` instead of
  `executablePath`
- The quality gate is `bun run check` (see root `package.json`), the same order
  as CI (`.github/workflows/ci.yml`)
- Root `bun run test` intentionally does not include the `apps/web` e2e. Run it
  with `cd apps/web && bun run build && bunx vitest run --config vitest.config.ts`.
  A prior build is required, and the test spawns its own `cf dev`
  (port 8791)
- The web dev server (`bun run --filter @maruhi/web dev`, port 5173) returns 404
  for requests without `Accept: text/html`. Pass `-H "Accept: text/html"` when
  probing with curl (browsers are fine)
- `apps/server` is a stub (no dev script). If needed,
  `cd apps/server && bunx cf dev`. No DB, secrets, or external services
  are required today
- Some entries under `.agents/skills` are symlinks into node_modules, so they
  look broken until `bun install` has run
- To use the deepsec skill (`/deepsec`, `.agents/skills/deepsec`), run
  `cd .deepsec && corepack pnpm install --frozen-lockfile` (corepack checks
  the sha512 pinned in `packageManager` when it downloads pnpm; without
  corepack, add `--config.manage-package-manager-versions=false` to a plain
  `pnpm install --frozen-lockfile`). Do not run
  `npx deepsec init` (the SKILL.md maruhi overlay; `docs/DEEPSEC.md`)
