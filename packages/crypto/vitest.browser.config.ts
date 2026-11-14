// Runs the tests in a browser (headless Chromium) (CRYPTO_SPEC §11).
// Not picked up by the root vitest.config.ts glob; run from a dedicated CI step
// (after Playwright Chromium is provisioned) / `bun run test:browser`.
//
// This package deliberately declares its own vitest devDependency —
// the only one in the repo. Browser mode dedupes every "vitest"
// resolution to the project copy so the browser client and the test
// modules share one module instance (and its runner state). With no
// project copy installed, the two sides land on different copies of
// vite-plus's bundled vitest in a workspace layout and every suite
// fails to start ("Cannot read properties of undefined (reading
// 'config')"; verified against vite-plus 1.6.0 with a minimal
// workspace repro). The runner itself is still `vp test`; the local
// pin only anchors the in-browser module identity, at the same
// version vite-plus bundles — when vite-plus is upgraded, this pin
// must move to whatever vitest version the new vite-plus bundles,
// or the lockfile gains a second vitest copy and the split returns.
// @vitest/browser-playwright stays a direct devDependency for a
// different reason: it is vite-plus's optional peer, which the
// consuming package must supply for the
// vite-plus/test/browser-playwright shim to resolve.
import { playwright } from "vite-plus/test/browser-playwright";
import { defineConfig } from "vite-plus/test/config";

// Allows swapping the Chromium executable via the same env var as the apps/web e2e
// (the SHA-256-verified headless shell from scripts/install-headless-shell.sh in
// CI and Cursor Cloud, or an environment's pre-installed browser; default
// resolution when unset)
const executablePath = process.env["PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"];

export default defineConfig({
  test: {
    name: "crypto-browser",
    include: ["test/**/*.test.ts"],
    browser: {
      enabled: true,
      headless: true,
      provider: playwright({
        launchOptions: executablePath ? { executablePath } : {},
      }),
      instances: [{ browser: "chromium" }],
    },
  },
});
