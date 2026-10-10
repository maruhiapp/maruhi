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
  pass it as Chromium's `executablePath`. CI and Cursor Cloud set it to the
  SHA-256-verified headless shell `scripts/install-headless-shell.sh` installs.
  Unset, they fall back to Playwright's own browser directory, which those two
  environments keep empty, so a shell without the variable fails to launch
- Do not run `bunx playwright install` (it conflicts with the preinstalled build
  and consumes the disk quota). The hook also sets `PLAYWRIGHT_DOWNLOAD_HOST`
  to an unresolvable host, so any Playwright browser download fails
- Everything else (quality gate, how to run e2e, dev-server caveats) is shared
  with the Cursor Cloud section below

## Cursor Cloud specific instructions

- The environment's install command is only `bash scripts/dev-setup-cursor.sh`,
  so setup changes ship in a reviewed pull request, not a dashboard edit. The
  script installs Bun with `scripts/install-bun.sh` and the tests' browser (the
  Chrome Headless Shell) with `scripts/install-headless-shell.sh` — each
  checks its download against the SHA-256 pinned there, the pins CI uses —
  runs `bun install --frozen-lockfile`, and removes Playwright's own browser
  directory `~/.cache/ms-playwright`. Never install with
  `curl https://bun.sh/install | bash` or `bunx playwright install`: both run
  unverified downloads
- Agent shells get `~/.bun/bin` on PATH, `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH`
  (the headless shell under `~/.cache/chrome-headless-shell`), and a
  `PLAYWRIGHT_DOWNLOAD_HOST` that makes any Playwright browser download fail,
  as in CI, through lines the script adds to `~/.bashrc`. A shell that does
  not read `~/.bashrc` (a plain `bash -c`) has none of them: browser tests
  there fail to launch instead of finding an unverified browser
- The headless shell cannot open a window: a headful session (screen
  recordings) launches the image's Chrome with
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
