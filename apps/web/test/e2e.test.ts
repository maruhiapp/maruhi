// e2e verification. The built dist/public is served in the
// **combined configuration (apps/server's cf dev — the same
// maruhi-server as production serving it as Workers Static Assets.
// Rulings BM/BT — docs/notes/session-43.md)**, and Playwright
// (Chromium) verifies:
//   1. Serving and hydration of the static shell (build-time RSC)
//   2. Every feature working under the strict CSP (script-src 'self'
//      / style-src 'self')
//   3. SPA navigation (the Navigation API) and MPA degradation under
//      a browser without it
//   4. Astryx prebuilt CSS + the maruhi theme + xstyle (StyleX
//      compiler) applying
//   5. The serving topology (run_worker_first's API reach, the SPA
//      fallback, per-path headers) pinned against the **deployed real
//      configuration** (ruling BT. preview uses the same
//      configuration too — a single cf config in apps/server —
//      ruling BX)
// Requires `bun run build` beforehand. Since the API is mocked inside
// the test via page.route (ruling BS), the local server needs no D1 /
// OAuth setup (a bare 401 / 503 response is itself evidence that "the
// Worker was reached").
import { type ChildProcess, spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer } from "node:net";

import {
  AuditEventSchema,
  ChainSnapshotSchema,
  CSRF_HEADER_NAME,
  DeviceSummarySchema,
  EnvironmentMetadataPullSchema,
  EnvironmentSummarySchema,
  InvitationSummarySchema,
  MeSchema,
  ProjectListSchema,
  RotationFlagSchema,
  TokenSummarySchema,
} from "@maruhi/api-schema";
import { Schema } from "effect";
import { type Browser, chromium, type Page, type Route } from "playwright";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  chainFixture,
  chainWithUnreadableEntry,
  devicesFixture,
  environmentsFixture,
  FP_D2,
  invitationsAfterRevoke,
  invitationsFixture,
  meFixture,
  metadataPullFixture,
  PROJECT_1,
  PROJECT_2,
  PROJECT_GHOST_CURSOR,
  projectAuditEvents,
  projectsPage1,
  projectsPage2,
  projectsPageEmpty,
  rotationFlagsFixture,
  selfAuditEvents,
  tokensAfterRevoke,
  tokensFixture,
} from "./fixtures.ts";

// The port is not pinned — the OS assigns a free one (no collision
// across CI's parallel runs)
function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        server.close();
        reject(new Error("failed to allocate a free port"));
        return;
      }
      server.close((err) => (err ? reject(err) : resolve(address.port)));
    });
  });
}

let BASE: string;
let wranglerProcess: ChildProcess;
let browser: Browser;

// cf dev's output is not discarded (stdio: "ignore" would leave no
// clues at all) — it goes into a buffer that is printed when (1) the
// startup wait fails after 60 seconds or (2) SIGTERM has not worked
// after 10 seconds (when the step's timeout-minutes is reached the
// runner kills the whole process and nothing is printed — the point
// is to catch the failure on the 2 paths just before that)
const wranglerLogs: string[] = [];

function wranglerOutput(): string {
  const text = wranglerLogs.join("").trim();
  return text === "" ? "(no output captured)" : text;
}

async function waitForServer(url: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch {
      // Not up yet
    }
    if (Date.now() > deadline) throw new Error(`server at ${url} did not start`);
    await new Promise((r) => setTimeout(r, 500));
  }
}

// Falls back to SIGKILL when SIGTERM does not end it. With SIGTERM
// alone, a lingering dev server keeps the vitest process from exiting
// and CI has actually hung to the job limit (30 minutes), not the
// step's
async function stopWrangler(proc: ChildProcess | undefined): Promise<void> {
  if (proc === undefined) return;
  try {
    if (proc.exitCode !== null || proc.signalCode !== null) return;
    const exited = new Promise<void>((resolve) => proc.once("exit", () => resolve()));
    proc.kill("SIGTERM");
    const timedOut = await Promise.race([
      exited.then(() => false),
      new Promise<boolean>((resolve) => setTimeout(() => resolve(true), 10_000).unref()),
    ]);
    if (timedOut) {
      console.error(
        `cf dev did not exit within 10s of SIGTERM; sending SIGKILL\n--- cf dev output ---\n${wranglerOutput()}`,
      );
      proc.kill("SIGKILL");
      await exited;
    }
  } finally {
    // Unconditionally close the pipe's read end: if a dev-server
    // descendant survives holding the write end, EOF never arrives and
    // the ref'd handle keeps vitest from exiting (a hang path created
    // by piping stdio).
    // The early-return side also takes this path to cover the case
    // where the dev server itself dies first and only descendants remain
    proc.stdout?.destroy();
    proc.stderr?.destroy();
  }
}

beforeAll(async () => {
  const port = await getFreePort();
  BASE = `http://127.0.0.1:${port}`;
  // The combined configuration (ruling BT): the thing deployed to
  // production is apps/server/cloudflare.config.ts (assets bundled), and e2e
  // boots that very thing as the serving layer (`cf dev` runs the same
  // workerd dev server wrangler dev does)
  wranglerProcess = spawn("bunx", ["cf", "dev", "--port", String(port)], {
    cwd: import.meta.dirname + "/../../server",
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, CI: "1" },
  });
  wranglerProcess.stdout?.on("data", (chunk: Buffer) => wranglerLogs.push(chunk.toString()));
  wranglerProcess.stderr?.on("data", (chunk: Buffer) => wranglerLogs.push(chunk.toString()));
  try {
    await waitForServer(BASE, 60_000);
  } catch (cause) {
    await stopWrangler(wranglerProcess);
    throw new Error(`cf dev did not become ready\n--- cf dev output ---\n${wranglerOutput()}`, {
      cause,
    });
  }
  // In environments that cannot download a browser (Claude Code on
  // the web etc.), the preinstalled Chromium's path is received via
  // PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH
  const executablePath = process.env["PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"];
  browser = await chromium.launch(executablePath ? { executablePath } : {});
});

afterAll(async () => {
  await browser?.close();
  await stopWrangler(wranglerProcess);
});

describe("web e2e: funstack-static + funstack-router + Astryx on Workers Static Assets", () => {
  it("serves the static shell with strict CSP headers", async () => {
    const res = await fetch(BASE);
    expect(res.status).toBe(200);
    const csp = res.headers.get("content-security-policy");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("style-src 'self'");
    const html = await res.text();
    // The static shell: the RSC-derived body lives on the payload
    // side; the shell carries only the mount point
    expect(html).toContain('<div id="app">');
    expect(html).toContain("fun__rsc-payload");
  });

  it("hydrates under strict CSP: build-time RSC content + working client island", async () => {
    const page = await browser.newPage();
    const violations: string[] = [];
    page.on("console", (msg) => {
      if (msg.text().includes("Content Security Policy")) violations.push(msg.text());
    });
    // The mechanism-verification hooks (built-at / counter) live on
    // /about ("About this deployment")
    // (DP2 ruling F — docs/notes/web-design-pass.md §4. The top page
    // is a minimal landing page)
    await page.goto(`${BASE}/about`, { waitUntil: "networkidle" });

    // Build-time RSC: the build time embedded by a server component
    // is displayed
    await expect(page.getByTestId("built-at").textContent()).resolves.toMatch(
      /server-rendered at build time: 20\d\d-/,
    );

    // The client island hydrates and interaction works under CSP
    const button = page.getByTestId("counter-button");
    await expect(button.textContent()).resolves.toContain("count: 0");
    await button.click();
    await expect(button.textContent()).resolves.toContain("count: 1");

    // xstyle (static CSS via the StyleX compiler) is applied
    const marginTop = await button.evaluate((el) => getComputedStyle(el).marginTop);
    expect(marginTop).toBe("20px");

    // The maruhi theme's accent color (defineTheme → astryx theme
    // build) is in effect.
    // A finding from verification: defineTheme's color.accent derives
    // the palette via HCT, so the final --color-accent is not the
    // given hex (#C73E3A) itself but a derived value.
    // Here we confirm that it differs from the Astryx default
    // (#0064E0) and that it matches the value in the generated CSS
    // (theme/maruhi.css).
    const accent = await page.evaluate(() =>
      getComputedStyle(document.documentElement).getPropertyValue("--color-accent").trim(),
    );
    expect(accent).not.toBe("");
    expect(accent.toLowerCase()).not.toContain("#0064e0");
    const themeCss = readFileSync(new URL("../theme/maruhi.css", import.meta.url), "utf8");
    expect(themeCss.toLowerCase()).toContain(accent.toLowerCase());

    expect(violations).toEqual([]);
    await page.close();
  });

  it("navigates as SPA via Navigation API (no full page load)", async () => {
    const page = await browser.newPage();
    await page.goto(BASE, { waitUntil: "networkidle" });
    // Place a marker that a full reload would erase
    await page.evaluate(() => {
      (window as unknown as Record<string, unknown>)["__spike_marker"] = "alive";
    });
    await page.getByTestId("to-about").click();
    await page.getByTestId("about-heading").waitFor();
    const marker = await page.evaluate(
      () => (window as unknown as Record<string, unknown>)["__spike_marker"],
    );
    expect(marker).toBe("alive"); // SPA transition (the page was not destroyed)
    await page.close();
  });

  // /invite (AUTH_SPEC §15-3 / ADR-0018 amendments 2 and 5): a
  // standalone static asset outside the SPA + a per-path CSP
  // `script-src 'none'`. "Carries no script at all and never
  // interprets the fragment" is pinned against the real serving
  // (cf dev)
  it("serves /invite as a script-free static page with per-path CSP script-src 'none'", async () => {
    const res = await fetch(`${BASE}/invite`);
    expect(res.status).toBe(200);
    const csp = res.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("script-src 'none'");
    // Styles and the logo are self-hosted only (DP4 — /theme.css +
    // /pages.css + the logo SVG)
    expect(csp).toContain("style-src 'self'");
    expect(csp).toContain("img-src 'self'");
    expect(csp).not.toContain("unsafe-inline");
    // The SPA's CSP ('self' + the bootstrap-hash allowance) is
    // detached — it does not linger as a second CSP
    expect(csp).not.toContain("'self' 'sha256-");
    expect(csp).not.toContain("script-src 'self'");
    // The other /* security headers keep applying to /invite too
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("referrer-policy")).toBe("no-referrer");
    const html = await res.text();
    expect(html.toLowerCase()).not.toContain("<script");
    expect(html).toContain("maruhi invite accept");
    // The meta CSP built into the served bytes (a second enforcement,
    // independent of the serving layer's header)
    expect(html).toMatch(
      /<meta\s+http-equiv="Content-Security-Policy"\s+content="[^"]*script-src 'none'/i,
    );
  });

  it("normalizes near-miss paths to the canonical /invite (link format §15-3)", async () => {
    // The _redirects normalization (301): the whole class of
    // case variants x arbitrary trailing junk
    // (the browser preserves the fragment across the redirect)
    for (const path of [
      "/invite/",
      "/invite/x",
      "/invite.html",
      "/inviteXYZ",
      "/Invite",
      "/INVITE",
      "/iNvItE",
      "/Invite/x",
      "/InviteXYZ",
    ]) {
      const res = await fetch(`${BASE}${path}`, { redirect: "manual" });
      expect(res.status, `path: ${path}`).toBe(301);
      expect(res.headers.get("location"), `path: ${path}`).toBe("/invite");
    }
    // The shield of the 200 rewrite: the canonical path passes
    // through unswallowed by the /invite* catch-all
    // (if the shield dropped and looped, the 3xx on /invite would be
    // caught here)
    const inviteRes = await fetch(`${BASE}/invite`, { redirect: "manual" });
    expect(inviteRes.status).toBe(200);
  });

  // The shared assets of the script-less pages (DP4 —
  // docs/notes/web-design-pass.md §5):
  // the /theme.css (bundled untransformed from apps/web/theme/
  // maruhi.css) and /pages.css referenced by /invite and by the
  // server-served ceremony pages
  // (apps/server/src/auth.package/cli-pages.ts) arrive with the right
  // content-type under the same combined configuration as production,
  // and the served bytes match the source
  it("serves /theme.css and /pages.css for the script-free pages (self-served, byte-identical)", async () => {
    const theme = await fetch(`${BASE}/theme.css`);
    expect(theme.status).toBe(200);
    expect(theme.headers.get("content-type")).toContain("text/css");
    expect(await theme.text()).toBe(
      readFileSync(new URL("../theme/maruhi.css", import.meta.url), "utf8"),
    );
    const pages = await fetch(`${BASE}/pages.css`);
    expect(pages.status).toBe(200);
    expect(pages.headers.get("content-type")).toContain("text/css");
    expect(await pages.text()).toBe(
      readFileSync(new URL("../public/pages.css", import.meta.url), "utf8"),
    );
    // Update propagation of the fixed-name CSS: Workers Static
    // Assets' default is revalidation on every load (max-age=0,
    // must-revalidate + ETag), so the fixed-name CSS referenced by a
    // Worker response's HTML (no-store) also switches to the new
    // version on the first load after a deploy (DP4 ruling G — the
    // grounds for not versioning URLs. If the default changes, this
    // is where we notice)
    for (const res of [theme, pages]) {
      expect(res.headers.get("cache-control")).toContain("must-revalidate");
      expect(res.headers.get("etag")).not.toBeNull();
    }
  });

  // That a server-served ceremony page receives the shared styles
  // under the real serving. The arrival point is the uniform error
  // page (a fabricated flow for `GET /auth/cli/verify` — an
  // unconfigured server returns the same page. AUTH_SPEC §4-2). The
  // approval page itself needs OAuth, so a server-side test
  // (apps/server/test/auth.test.ts) checks the same page() output
  it("renders a server-delivered ritual page with the shared stylesheet under CSP", async () => {
    const res = await fetch(`${BASE}/auth/cli/verify?flow=not-a-real-flow`);
    expect(res.status).toBe(400);
    expect(res.headers.get("content-type")).toContain("text/html");
    const csp = res.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("script-src 'none'");
    expect(csp).toContain("style-src 'self'");
    expect(csp).toContain("img-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    const page = await browser.newPage();
    const violations: string[] = [];
    page.on("console", (msg) => {
      if (msg.text().includes("Content Security Policy")) violations.push(msg.text());
    });
    const failed: string[] = [];
    page.on("response", (r) => {
      if (r.status() >= 400 && !r.url().endsWith("not-a-real-flow")) failed.push(r.url());
    });
    await page.goto(`${BASE}/auth/cli/verify?flow=not-a-real-flow`, { waitUntil: "networkidle" });
    await expect(page.locator("h1").textContent()).resolves.toContain("can't be used");
    await expect(page.evaluate(() => document.scripts.length)).resolves.toBe(0);
    // Both /pages.css's frame (40rem) and /theme.css's tokens (the
    // body background) are in effect
    const maxWidth = await page.locator(".page").evaluate((el) => getComputedStyle(el).maxWidth);
    expect(maxWidth).toBe("640px");
    const background = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    expect(background).not.toBe("rgba(0, 0, 0, 0)");
    // A weight regression: in the first version a var() on an
    // undefined token silently dropped font-weight, leaving the h1
    // and the emphasized sentence at normal. The h1 and the outcome
    // line must be bold
    for (const selector of ["h1", ".outcome"]) {
      const weight = await page.locator(selector).evaluate((el) => getComputedStyle(el).fontWeight);
      expect(weight, selector).toBe("700");
    }
    // The logo (a self-hosted SVG) renders under img-src 'self'
    const logoLoaded = await page
      .locator(".brand img")
      .evaluate(
        (el) => (el as HTMLImageElement).complete && (el as HTMLImageElement).naturalWidth > 0,
      );
    expect(logoLoaded).toBe(true);
    expect(violations).toEqual([]);
    expect(failed).toEqual([]);
    await page.close();
  });

  it("renders /invite with zero scripts under a fragment-bearing URL", async () => {
    const page = await browser.newPage();
    const violations: string[] = [];
    page.on("console", (msg) => {
      if (msg.text().includes("Content Security Policy")) violations.push(msg.text());
    });
    // The fragment is a dummy modeled on the §15-3 link format (never
    // sent to the server)
    await page.goto(`${BASE}/invite#v=1&t=dummy-invite-token&p=dummy-project&r=member`, {
      waitUntil: "networkidle",
    });
    await expect(page.locator("h1").textContent()).resolves.toContain("maruhi");
    // Zero scripts (no <script> element in the DOM at all)
    await expect(page.evaluate(() => document.scripts.length)).resolves.toBe(0);
    // The stylesheet (self-hosted /pages.css) applies under CSP
    const maxWidth = await page.locator(".page").evaluate((el) => getComputedStyle(el).maxWidth);
    expect(maxWidth).toBe("640px"); // 40rem
    expect(violations).toEqual([]);
    await page.close();
  });

  it("degrades to MPA (full page loads) when Navigation API is unavailable", async () => {
    const page = await browser.newPage();
    // Reproduce a browser without the Navigation API (delete
    // window.navigation before any script runs)
    await page.addInitScript(() => {
      // @ts-expect-error an intentional deletion for verification
      delete window.navigation;
    });
    await page.goto(BASE, { waitUntil: "networkidle" });
    await page.evaluate(() => {
      (window as unknown as Record<string, unknown>)["__spike_marker"] = "alive";
    });
    await page.getByTestId("to-about").click();
    await page.getByTestId("about-heading").waitFor();
    const marker = await page.evaluate(
      () => (window as unknown as Record<string, unknown>)["__spike_marker"],
    );
    expect(marker).toBeUndefined(); // A full page load = MPA
    // degradation (fallback="static")
    // Even after degradation the page content itself displays via
    // the SPA fallback (not_found_handling)
    await expect(page.getByTestId("about-heading").textContent()).resolves.toBe("about maruhi");
    await page.close();
  });
});

// ---------------------------------------------------------------------------
// W2: e2e of the read-only dashboard (S3-S7) (ruling BS —
// docs/notes/session-43.md).
// Serving, real rendering, and CSP stay on the real thing (cf
// dev + Chromium); only the API responses are swapped via Playwright's
// page.route (staying same-origin, so the connect-src 'self'
// verification is not weakened). The fixtures are literals conforming
// to the api-schema-derived types (src/dashboard/types.ts); tsc
// detects any divergence.
// ---------------------------------------------------------------------------

function fulfillJson(route: Route, status: number, body: unknown): Promise<void> {
  return route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
}

/** A handler returning 401 (unauthenticated) (Unauthorized — api-schema's wire shape). */
function unauthorized(route: Route): Promise<void> {
  return fulfillJson(route, 401, { _tag: "Unauthorized" });
}

/**
 * The session-check mock. DP3's app shell (DashboardShell) calls
 * `GET /auth/me` once on every screen that needs auth and draws the
 * body only on ok — a real server's 401 response keeps networkidle
 * from settling without its body being read, so every authenticated
 * screen's test registers this
 */
async function routeSession(page: Page): Promise<void> {
  await page.route("**/auth/me", (route) => fulfillJson(route, 200, meFixture));
}

/**
 * A mock of the consumed surfaces of the project screen's initial
 * display (the Overview tab)
 * (shared by W3b's S8 tests).
 */
async function routeProjectOverview(page: Page): Promise<void> {
  await routeSession(page);
  await page.route(
    (url) => url.pathname === `/projects/${PROJECT_1}/chain`,
    (route) => fulfillJson(route, 200, chainFixture),
  );
  await page.route(
    (url) => url.pathname === `/projects/${PROJECT_1}/environments`,
    (route) => fulfillJson(route, 200, environmentsFixture),
  );
}

/**
 * The revocation confirmation (DP3 amendment 4 — ruling CO's inline
 * two-step became an AlertDialog). The row's Revoke opens the modal,
 * and the Revoke inside it fires the DELETE.
 */
async function confirmRevoke(page: Page): Promise<void> {
  const dialog = page.getByRole("alertdialog");
  await dialog.waitFor();
  await dialog.getByRole("button", { name: "Revoke", exact: true }).click();
}

/** The project screen tabpanel's computed `display` (`none` when not selected). */
function panelDisplay(page: Page, tab: string): Promise<string> {
  return page.locator(`#project-panel-${tab}`).evaluate((el) => getComputedStyle(el).display);
}

/** CSP-violation collection for the dashboard (same detection method as the existing tests). */
function collectViolations(page: Page): string[] {
  const violations: string[] = [];
  page.on("console", (msg) => {
    if (msg.text().includes("Content Security Policy")) violations.push(msg.text());
  });
  return violations;
}

describe("web e2e: serving topology (W2 rulings BM/BT — combined worker)", () => {
  it("routes API paths to the worker, not the asset layer", async () => {
    // Pin run_worker_first's actual effect (blocking navigation
    // absorption) against the deployed real configuration. The bare
    // response of an unconfigured local server (a 503 / 401 JSON) is
    // itself evidence that "the Worker was reached" — it was not
    // swallowed by the SPA shell (200 text/html)
    const config = await fetch(`${BASE}/auth/config`);
    // CI = an unconfigured server's 503 SetupIncomplete. With a
    // developer-local .dev.vars it is 200 — both are JSON = the
    // Worker's response (not the SPA shell's 200 html)
    expect([200, 503]).toContain(config.status);
    expect(config.headers.get("content-type") ?? "").toContain("application/json");
    const projects = await fetch(`${BASE}/projects`);
    expect(projects.status).toBe(401);
    expect(projects.headers.get("content-type") ?? "").toContain("application/json");
  });

  it("does not let the /invite* redirect catch-all swallow POST /invites/accept", async () => {
    // A regression test for the defect fixed in session-43 §9: on an
    // enumeration miss, _redirects' lowercase catch-all 301s the
    // acceptance POST into /invite (a failure mode confirmed by
    // measurement)
    const res = await fetch(`${BASE}/invites/accept`, { method: "POST", redirect: "manual" });
    expect(res.status).toBe(401); // The unauthenticated Worker
    // response (not a 301)
  });
});

describe("web e2e: read dashboard (W2 — S3-S7, mocked API via page.route)", () => {
  it("keeps every mocked fixture wire-valid against the api-schema contracts (ruling BV)", () => {
    // Type conformance (tsc) sees no runtime constraints like hex
    // length or patterns. Decode each fixture against the real Schemas
    // to make drift between mock and wire contract a machine check
    // (Schema executable code runs only in the test process — never in
    // the bundle)
    Schema.decodeUnknownSync(MeSchema)(meFixture);
    for (const page of [projectsPage1, projectsPageEmpty, projectsPage2]) {
      Schema.decodeUnknownSync(ProjectListSchema)(page);
    }
    Schema.decodeUnknownSync(ChainSnapshotSchema)(chainFixture);
    Schema.decodeUnknownSync(ChainSnapshotSchema)(chainWithUnreadableEntry);
    for (const env of environmentsFixture.environments) {
      Schema.decodeUnknownSync(EnvironmentSummarySchema)(env);
    }
    Schema.decodeUnknownSync(EnvironmentMetadataPullSchema)(metadataPullFixture);
    for (const event of [...projectAuditEvents.events, ...selfAuditEvents.events]) {
      Schema.decodeUnknownSync(AuditEventSchema)(event);
    }
    for (const flag of rotationFlagsFixture.flags) {
      Schema.decodeUnknownSync(RotationFlagSchema)(flag);
    }
    for (const invite of [
      ...invitationsFixture.invitations,
      ...invitationsAfterRevoke.invitations,
    ]) {
      Schema.decodeUnknownSync(InvitationSummarySchema)(invite);
    }
    for (const token of tokensFixture.tokens) {
      Schema.decodeUnknownSync(TokenSummarySchema)(token);
    }
    for (const device of devicesFixture.devices) {
      Schema.decodeUnknownSync(DeviceSummarySchema)(device);
    }
  });

  it("serves /dashboard routes with the strict SPA CSP header", async () => {
    // The zero-violation checks (the tests below) would also pass
    // when the CSP header is missing entirely, so the header's
    // presence is pinned directly.
    // That a deep path arriving via the SPA fallback also carries the
    // /* CSP
    for (const path of [
      "/dashboard",
      `/dashboard/projects/${PROJECT_1}`,
      "/dashboard/account",
      "/dashboard/tokens",
      "/dashboard/devices",
    ]) {
      const res = await fetch(`${BASE}${path}`);
      expect(res.status, `path: ${path}`).toBe(200);
      const csp = res.headers.get("content-security-policy") ?? "";
      expect(csp, `path: ${path}`).toContain("script-src 'self'");
      expect(csp, `path: ${path}`).toContain("connect-src 'self'");
    }
  });

  it("shows the sign-in screen when the server reports no session (401)", async () => {
    const page = await browser.newPage();
    const violations = collectViolations(page);
    await page.route("**/auth/me", unauthorized);
    await page.goto(`${BASE}/dashboard`, { waitUntil: "networkidle" });
    await page.getByTestId("login-card").waitFor();
    const signIn = page.getByTestId("sign-in-link");
    await expect(signIn.getAttribute("href")).resolves.toBe("/auth/github/start");
    // The per-screen document.title of the SPA (the static shell's
    // <title> is fixed to "maruhi")
    await expect.poll(() => page.title()).toBe("Sign in — maruhi");
    // A main landmark exists even outside AppShell (Center has
    // role="main"). On the initial display it does not steal focus
    await expect(page.getByRole("main").count()).resolves.toBe(1);
    await expect(page.getByRole("main").getByTestId("login-card").count()).resolves.toBe(1);
    await expect(
      page.getByTestId("sign-in-heading").evaluate((el) => el === document.activeElement),
    ).resolves.toBe(false);
    expect(violations).toEqual([]);
    await page.close();
  });

  it("titles the session-check frames (loading / failure) per state", async () => {
    // The frames shown while checking the session and on failure
    // (StatusFrame) also carry a document.title
    const page = await browser.newPage();
    const violations = collectViolations(page);
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    await page.route("**/auth/me", async (route) => {
      await gate;
      return fulfillJson(route, 500, { _tag: "InternalError" });
    });
    await page.goto(`${BASE}/dashboard`);
    await page.getByText("Checking your session").first().waitFor();
    await expect.poll(() => page.title()).toBe("Checking your session — maruhi");
    await expect(page.getByRole("main").count()).resolves.toBe(1);
    release?.();
    await expect.poll(() => page.title()).toBe("Session check failed — maruhi");
    await expect(page.getByRole("main").count()).resolves.toBe(1);
    expect(violations).toEqual([]);
    await page.close();
  });

  it("lists projects with roles, pages with nextAfter, and signs out with the CSRF header", async () => {
    const page = await browser.newPage();
    const violations = collectViolations(page);
    let sawCsrfHeader: string | null = null;
    let signedOut = false;
    await page.route("**/auth/me", (route) =>
      signedOut ? unauthorized(route) : fulfillJson(route, 200, meFixture),
    );
    await page.route(
      (url) => url.pathname === "/projects",
      (route) => {
        const after = new URL(route.request().url()).searchParams.get("after");
        if (after === PROJECT_1) return fulfillJson(route, 200, projectsPageEmpty);
        if (after === PROJECT_GHOST_CURSOR) return fulfillJson(route, 200, projectsPage2);
        return fulfillJson(route, 200, projectsPage1);
      },
    );
    await page.route("**/auth/logout", (route) => {
      sawCsrfHeader = route.request().headers()[CSRF_HEADER_NAME] ?? null;
      signedOut = true;
      return route.fulfill({ status: 204 });
    });

    await page.goto(`${BASE}/dashboard`, { waitUntil: "networkidle" });
    await page.getByTestId("project-list").waitFor();
    // Page 1: 1 admin row + Load more (nextAfter present)
    await expect(page.getByText(PROJECT_1).count()).resolves.toBeGreaterThan(0);
    // Load more follows an intervening empty page (with nextAfter)
    // without misjudging it as the end
    await page.getByTestId("load-more-projects").click();
    await page.getByText(PROJECT_2).waitFor();
    // Page 2 has no nextAfter, so Load more disappears
    await expect(page.getByTestId("load-more-projects").count()).resolves.toBe(0);
    // The role is shown as a Token of the server-reported value
    await expect(page.getByText("admin", { exact: true }).count()).resolves.toBeGreaterThan(0);
    await expect(page.getByText("reader", { exact: true }).count()).resolves.toBeGreaterThan(0);

    // Logout (POST + x-maruhi-csrf: 1 — AUTH_SPEC §11-4)
    await page.getByTestId("sign-out").click();
    await page.getByTestId("login-card").waitFor();
    expect(sawCsrfHeader).toBe("1");
    await expect(page.getByText("You are signed out.").count()).resolves.toBeGreaterThan(0);
    // Right after sign-out, focus moves to the sign-in screen's
    // heading
    await expect
      .poll(() =>
        page.getByTestId("sign-in-heading").evaluate((el) => el === document.activeElement),
      )
      .toBe(true);
    expect(violations).toEqual([]);
    await page.close();
  });

  it("keeps the focused Load more button mounted while the next page loads", async () => {
    // Swapping Load more for a LoadingRow while loading would make
    // the focused element disappear and focus fall to body. The
    // button stays as isLoading (aria-busy) and a double load is
    // blocked in the handler
    const page = await browser.newPage();
    const violations = collectViolations(page);
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let secondPageRequests = 0;
    await routeSession(page);
    await page.route(
      (url) => url.pathname === "/projects",
      async (route) => {
        const after = new URL(route.request().url()).searchParams.get("after");
        if (after === PROJECT_1) {
          secondPageRequests += 1;
          await gate;
          return fulfillJson(route, 200, {
            projects: [{ projectId: PROJECT_2, role: "reader" }],
            nextAfter: PROJECT_2,
          });
        }
        if (after === PROJECT_2) return fulfillJson(route, 200, { projects: [] });
        return fulfillJson(route, 200, projectsPage1);
      },
    );
    await page.goto(`${BASE}/dashboard`, { waitUntil: "networkidle" });
    await page.getByTestId("project-list").waitFor();
    const loadMore = page.getByTestId("load-more-projects");
    await loadMore.focus();
    await page.keyboard.press("Enter");
    await expect.poll(() => loadMore.getAttribute("aria-busy")).toBe("true");
    await expect(loadMore.evaluate((el) => el === document.activeElement)).resolves.toBe(true);
    await expect(loadMore.isDisabled()).resolves.toBe(false);
    // Pressing again while loading starts no new load
    await page.keyboard.press("Enter");
    await loadMore.click();
    expect(secondPageRequests).toBe(1);
    release?.();
    await page.getByText(PROJECT_2).waitFor();
    await expect.poll(() => loadMore.getAttribute("aria-busy")).toBe(null);
    await expect(loadMore.evaluate((el) => el === document.activeElement)).resolves.toBe(true);
    expect(secondPageRequests).toBe(1);
    expect(violations).toEqual([]);
    await page.close();
  });

  it("renders project overview / audit / rotation tabs from server-reported data", async () => {
    const page = await browser.newPage();
    const violations = collectViolations(page);
    await page.route("**/auth/me", (route) => fulfillJson(route, 200, meFixture));
    await page.route(
      (url) => url.pathname === `/projects/${PROJECT_1}/chain`,
      (route) => fulfillJson(route, 200, chainFixture),
    );
    await page.route(
      (url) => url.pathname === `/projects/${PROJECT_1}/environments`,
      (route) => fulfillJson(route, 200, environmentsFixture),
    );
    await page.route(
      (url) => url.pathname === `/projects/${PROJECT_1}/environments/production/pull/metadata`,
      (route) => fulfillJson(route, 200, metadataPullFixture),
    );
    await page.route(
      (url) => url.pathname === `/projects/${PROJECT_1}/audit/events`,
      (route) => fulfillJson(route, 200, projectAuditEvents),
    );
    await page.route(
      (url) => url.pathname === `/projects/${PROJECT_1}/audit/invites`,
      (route) => fulfillJson(route, 403, { _tag: "Forbidden", reason: "insufficient-role" }),
    );
    await page.route(
      (url) => url.pathname === `/projects/${PROJECT_1}/rotation/flags`,
      (route) => fulfillJson(route, 200, rotationFlagsFixture),
    );

    await page.goto(`${BASE}/dashboard/projects/${PROJECT_1}`, { waitUntil: "networkidle" });

    // Astryx 0.5: switching panels within one screen is WAI-ARIA
    // tabs (not a nav landmark)
    await expect(page.getByRole("tablist", { name: "Project" }).count()).resolves.toBe(1);
    await expect(
      page.getByRole("tab", { name: "Overview" }).getAttribute("aria-selected"),
    ).resolves.toBe("true");
    await expect(
      page.getByRole("tab", { name: "Audit" }).getAttribute("aria-controls"),
    ).resolves.toBe("project-panel-audit");
    // A tabpanel takes its name from the corresponding tab (APG)
    await expect(
      page.locator("#project-panel-audit").getAttribute("aria-labelledby"),
    ).resolves.toBe(await page.getByRole("tab", { name: "Audit" }).getAttribute("id"));
    // An unselected panel is empty (height 0), so isVisible() cannot
    // detect a `display` override losing. The computed display is
    // pinned directly
    await expect(panelDisplay(page, "overview")).resolves.toBe("flex");
    await expect(panelDisplay(page, "audit")).resolves.toBe("none");
    await expect(page.getByRole("tabpanel").count()).resolves.toBe(1);

    // S5 overview: chain-derived members (server-reported) +
    // environments + variable names (metadata-only pull)
    await page.getByTestId("member-table").waitFor();
    await expect(page.getByText("user_colleague").count()).resolves.toBeGreaterThan(0);
    // Devices (DK K5): user_e2e = D1 (FP bound — the genesis actor)
    // + R (the add_device wire carries no FP, so "fingerprint not
    // reported"). D2 was revoked at seq 5.
    // user_colleague = 1 first key (never signed, so the FP is
    // unbound)
    const members = page.getByTestId("member-table");
    await expect(members.getByText("565656…565656", { exact: true }).count()).resolves.toBe(1);
    await expect(
      members.getByText("fingerprint not reported", { exact: true }).count(),
    ).resolves.toBe(2);
    await expect(members.getByText("d2d2d2…d2d2d2").count()).resolves.toBe(0);
    // Device counts: user_e2e's row is 2 (D1 + R), user_colleague's
    // row is 1 (the first key)
    const e2eRow = members.getByRole("row").filter({ hasText: "user_e2e" });
    await expect(e2eRow.getByText("2", { exact: true }).count()).resolves.toBe(1);
    const colleagueRow = members.getByRole("row").filter({ hasText: "user_colleague" });
    await expect(colleagueRow.getByText("1", { exact: true }).count()).resolves.toBe(1);
    await page.getByTestId("env-table").waitFor();
    // The discloser: while closed it is aria-expanded=false with no
    // aria-controls; opened, it points at the variable-names section
    // (id) below the table
    const namesToggle = page.getByRole("button", { name: "Variable names", exact: true });
    await expect(namesToggle.getAttribute("aria-expanded")).resolves.toBe("false");
    await expect(namesToggle.getAttribute("aria-controls")).resolves.toBeNull();
    await namesToggle.click();
    await page.getByTestId("variable-list").waitFor();
    const hideToggle = page.getByRole("button", { name: "Hide names", exact: true });
    await expect(hideToggle.getAttribute("aria-expanded")).resolves.toBe("true");
    const controls = await hideToggle.getAttribute("aria-controls");
    expect(controls).not.toBeNull();
    await expect(page.getByTestId("variables-region").getAttribute("id")).resolves.toBe(controls);
    await expect(
      page.getByTestId("variables-region").getByTestId("variable-list").count(),
    ).resolves.toBe(1);
    await expect(page.getByText("DATABASE_URL").count()).resolves.toBeGreaterThan(0);

    // S6 audit: the prescribed wording + the seq column sourced from
    // the admin response (response-adaptive)
    await page.getByRole("tab", { name: "Audit" }).click();
    await expect(
      page.getByRole("tab", { name: "Audit" }).getAttribute("aria-selected"),
    ).resolves.toBe("true");
    await expect(panelDisplay(page, "audit")).resolves.toBe("flex");
    await expect(panelDisplay(page, "overview")).resolves.toBe("none");
    await page.getByTestId("audit-caption").waitFor();
    await expect(page.getByTestId("audit-caption").textContent()).resolves.toContain(
      "Events visible to your role",
    );
    await page.getByTestId("audit-list-project").waitFor();
    // DP3 amendment 5: one column of rows + expand in place
    // (Collapsible). seq is only on the admin response and appears at
    // the row's right edge as "seq N" (response-adaptive)
    await expect(page.getByText("seq 2", { exact: true }).count()).resolves.toBe(1);
    await expect(page.getByText("chain.member_added").count()).resolves.toBeGreaterThan(0);
    // The 2 device events (AUDIT_SPEC §3.4 — DK) do not fall through
    // the generic rendering (K5-6): the row appears, and opening it
    // shows the payload (FP) as recorded
    await expect(page.getByText("chain.device_added").count()).resolves.toBe(1);
    await expect(page.getByText("chain.device_revoked").count()).resolves.toBe(1);
    // Opening a row (trigger = button) shows every field
    // (MetadataList) directly under it.
    // A closed expanded part stays in the DOM (hidden), so only the
    // visible elements are counted
    const list = page.getByTestId("audit-list-project");
    const visibleRowIds = list.getByText("Row id", { exact: true }).locator("visible=true");
    await expect(visibleRowIds.count()).resolves.toBe(0);
    const row = list.getByRole("button", { name: /chain\.member_added/ });
    await row.click();
    await expect(row.getAttribute("aria-expanded")).resolves.toBe("true");
    await visibleRowIds.waitFor();
    await expect(visibleRowIds.count()).resolves.toBe(1);
    // The expanded part also shows target (user_colleague) as
    // recorded (1 in the summary row + 1 in the expanded part)
    await expect(
      list.getByText("user_colleague", { exact: true }).locator("visible=true").count(),
    ).resolves.toBe(2);
    // The invites axis (below admin) displays as-is with the role
    // wording (never hints at existence or counts).
    // In W3b the management tab "Invites" (S8) sits beside it with
    // the same word, so the pressed button of the ToggleButtonGroup
    // (which replaced SegmentedControl in DP3) is pointed at by role
    await page.getByRole("button", { name: "Invites", pressed: false }).click();
    await page.getByText("Not available to your role").first().waitFor();

    // S7 flags: display + static guidance for dismiss (no dismiss
    // operation exists). The device-revocation variant is
    // "device revoked: <userId> (chain seq N)" (K5-5 — the seq lets
    // one trace the mirrored row on Audit), and remove_member takes
    // the removal wording
    await page.getByRole("tab", { name: "Rotation flags" }).click();
    await page.getByTestId("rotation-table").waitFor();
    await expect(
      page.getByText("device revoked: user_e2e (chain seq 5)", { exact: true }).count(),
    ).resolves.toBe(1);
    await expect(
      page.getByText("member removed: user_colleague (chain seq 3)", { exact: true }).count(),
    ).resolves.toBe(1);
    await expect(page.getByTestId("rotation-note").textContent()).resolves.toContain(
      "maruhi rotation dismiss",
    );

    expect(violations).toEqual([]);
    await page.close();
  });

  it("resumes to /dashboard after sign-in, driven through the real affordance (ruling BU)", async () => {
    // The marker is not injected by the test — a **real click** (the
    // Link's onClick) writes it — a regression where Link stops
    // writing the marker, or the consume guard regresses, fails this
    // test. Only the real OAuth flow is e2e-impossible (ruling BS),
    // so the real navigation to /auth/github/start is folded into and
    // replaced by "authorization success → the callback 302s to
    // ${origin}/"
    const page = await browser.newPage();
    const violations = collectViolations(page);
    let signedIn = false;
    await page.route("**/auth/me", (route) =>
      signedIn ? fulfillJson(route, 200, meFixture) : unauthorized(route),
    );
    await page.route(
      (url) => url.pathname === "/projects",
      (route) => fulfillJson(route, 200, projectsPage2),
    );
    await page.route("**/auth/github/start", (route) => {
      signedIn = true;
      return route.fulfill({ status: 302, headers: { location: "/" } });
    });
    await page.goto(`${BASE}/dashboard`, { waitUntil: "networkidle" });
    await page.getByTestId("login-card").waitFor();
    await page.getByTestId("sign-in-link").click();
    // Lands on "/" → ResumeToDashboard consumes the marker →
    // /auth/me check → /dashboard
    await page.getByTestId("project-list").waitFor();
    expect(new URL(page.url()).pathname).toBe("/dashboard");
    expect(violations).toEqual([]);
    await page.close();
  });

  it("keeps the marker-free landing free of API calls (the boundary of BP round 3, pinned)", async () => {
    // Pin via request collection that BU has not regressed into BP's
    // rejected approach (a constant /auth/me check on S1) — if the
    // consume guard disappears this fails
    const page = await browser.newPage();
    const apiRequests: string[] = [];
    page.on("request", (request) => {
      const { pathname } = new URL(request.url());
      if (pathname.startsWith("/auth") || pathname.startsWith("/projects")) {
        apiRequests.push(pathname);
      }
    });
    await page.goto(`${BASE}/`, { waitUntil: "networkidle" });
    await page.getByTestId("home-heading").waitFor();
    expect(apiRequests).toEqual([]);
    // An RSC page (Home) keeps the static shell's <title>
    await expect(page.title()).resolves.toBe("maruhi");
    await page.close();
  });

  it("stays on the landing page when the marker is set but no session exists", async () => {
    const page = await browser.newPage();
    await page.route("**/auth/me", unauthorized);
    await page.addInitScript(() => {
      try {
        sessionStorage.setItem("maruhi-resume-dashboard", "1");
      } catch {
        // Does nothing in an environment without storage
      }
    });
    await page.goto(`${BASE}/`, { waitUntil: "networkidle" });
    await page.getByTestId("home-heading").waitFor();
    // On an aborted / failed OAuth (no session established), it
    // stays on the landing
    expect(new URL(page.url()).pathname).toBe("/");
    await page.close();
  });

  it("lists invitations, revokes via inline confirm with the CSRF header, and refreshes (S8)", async () => {
    const page = await browser.newPage();
    const violations = collectViolations(page);
    let revoked = false;
    let deleteMethod: string | null = null;
    let deleteCsrf: string | null = null;
    // The Overview tab's (initial display) consumed surfaces are also
    // mocked: a real server's 401 response keeps networkidle from
    // settling with its body unread (the reason the W2 tests are fully
    // mocked)
    await routeProjectOverview(page);
    await page.route(
      (url) => url.pathname === `/projects/${PROJECT_1}/invites`,
      (route) => fulfillJson(route, 200, revoked ? invitationsAfterRevoke : invitationsFixture),
    );
    await page.route(
      (url) => url.pathname === `/projects/${PROJECT_1}/invites/inv-pending`,
      (route) => {
        deleteMethod = route.request().method();
        deleteCsrf = route.request().headers()[CSRF_HEADER_NAME] ?? null;
        revoked = true;
        return route.fulfill({ status: 204 });
      },
    );

    await page.goto(`${BASE}/dashboard/projects/${PROJECT_1}`, { waitUntil: "networkidle" });
    await page.getByRole("tab", { name: "Invites" }).click();
    await page.getByTestId("invite-table").waitFor();
    // No issuance UI — only static guidance to the CLI (ADR-0018
    // amendment 2)
    await expect(page.getByTestId("invite-notes").textContent()).resolves.toContain(
      "maruhi invite create",
    );
    // Revoke exists only on pending | accepted rows (a completed row
    // has no button)
    await expect(page.getByRole("button", { name: "Revoke" }).count()).resolves.toBe(2);
    // The spoken name identifies the row by the columns visible in
    // the table (status, role, inviter). The visible wording is
    // "Revoke"
    const pendingRevoke = page.getByRole("button", {
      name: /^Revoke pending member invitation from user_e2e, expires /,
    });
    await expect(pendingRevoke.count()).resolves.toBe(1);
    await expect(pendingRevoke.textContent()).resolves.toBe("Revoke");
    await expect(
      page
        .getByRole("button", { name: /^Revoke accepted reader invitation from user_e2e, expires / })
        .count(),
    ).resolves.toBe(1);
    // The two-step confirmation (ruling CO — became an AlertDialog
    // in DP3 amendment 4): the row's Revoke → the modal's Revoke
    // executes
    await page.getByRole("button", { name: "Revoke" }).first().click();
    await confirmRevoke(page);
    // After completion it transcribes from a server refetch (no
    // optimistic update) — the pending row becomes revoked
    await page.getByText("revoked", { exact: true }).waitFor();
    await expect(page.getByTestId("revocation-success").textContent()).resolves.toContain(
      "Invitation revoked.",
    );
    expect(deleteMethod).toBe("DELETE");
    expect(deleteCsrf).toBe("1");
    expect(violations).toEqual([]);
    await page.close();
  });

  it("shows the server-reported gone wording when a revocation races to 410 (S8)", async () => {
    // Transcribes the server-reported reason of the side that lost
    // the revocation CAS (already transitioned to completed / revoked
    // elsewhere) (the api layer's gone classification — wording
    // verification attached to ruling CN)
    const page = await browser.newPage();
    await routeProjectOverview(page);
    await page.route(
      (url) => url.pathname === `/projects/${PROJECT_1}/invites`,
      (route) => fulfillJson(route, 200, invitationsFixture),
    );
    await page.route(
      (url) => url.pathname === `/projects/${PROJECT_1}/invites/inv-pending`,
      (route) => fulfillJson(route, 410, { _tag: "InviteGone", reason: "completed" }),
    );
    await page.goto(`${BASE}/dashboard/projects/${PROJECT_1}`, { waitUntil: "networkidle" });
    await page.getByRole("tab", { name: "Invites" }).click();
    await page.getByTestId("invite-table").waitFor();
    await page.getByRole("button", { name: "Revoke" }).first().click();
    await confirmRevoke(page);
    await page.getByText("The server reports this invitation as completed.").waitFor();
    await expect(page.getByTestId("revocation-success").count()).resolves.toBe(0);
    await page.close();
  });

  it("shows the role wording when the invites listing reports 403 (S8 — below admin)", async () => {
    const page = await browser.newPage();
    await routeProjectOverview(page);
    await page.route(
      (url) => url.pathname === `/projects/${PROJECT_1}/invites`,
      (route) => fulfillJson(route, 403, { _tag: "Forbidden", reason: "insufficient-role" }),
    );
    await page.goto(`${BASE}/dashboard/projects/${PROJECT_1}`, { waitUntil: "networkidle" });
    // The tab is not hidden in advance by role (ruling CP round 3) —
    // a 403 displays with the role wording
    await page.getByRole("tab", { name: "Invites" }).click();
    await page.getByText("Not available to your role").first().waitFor();
    await page.close();
  });

  it("lists tokens with server-reported expiry: Expired, never (S9)", async () => {
    const page = await browser.newPage();
    const violations = collectViolations(page);
    await routeSession(page);
    await page.route(
      (url) => url.pathname === "/auth/tokens",
      (route) => fulfillJson(route, 200, tokensFixture),
    );
    await page.goto(`${BASE}/dashboard/tokens`, { waitUntil: "networkidle" });
    await page.getByTestId("token-table").waitFor();
    // An expired (past) one shows Expired (ruling CQ)
    await expect(page.getByText("Expired", { exact: true }).count()).resolves.toBe(1);
    // lastUsedAtMs null is "never"
    await expect(page.getByText("never", { exact: true }).count()).resolves.toBe(1);
    // The row's Revoke keeps the visible wording "Revoke"; the
    // spoken name carries the row's identity (the token name)
    const table = page.getByTestId("token-table");
    for (const name of ["ci", "old-laptop"]) {
      const button = table.getByRole("button", { name: `Revoke token "${name}"`, exact: true });
      await expect(button.count()).resolves.toBe(1);
      await expect(button.textContent()).resolves.toBe("Revoke");
    }
    // No issuance UI and no raw-value display — only static guidance
    // to the CLI login
    await expect(page.getByTestId("token-notes").textContent()).resolves.toContain("maruhi login");
    expect(violations).toEqual([]);
    await page.close();
  });

  it("revokes a token via inline confirm with the CSRF header and refreshes (S9)", async () => {
    const page = await browser.newPage();
    const violations = collectViolations(page);
    let revoked = false;
    let deleteMethod: string | null = null;
    let deleteCsrf: string | null = null;
    // Hold the post-revocation refetch and check that the previous
    // list stays meanwhile (never swapped for a LoadingRow)
    let releaseRefetch: (() => void) | undefined;
    const refetchGate = new Promise<void>((resolve) => {
      releaseRefetch = resolve;
    });
    await routeSession(page);
    await page.route(
      (url) => url.pathname === "/auth/tokens",
      async (route) => {
        if (!revoked) return fulfillJson(route, 200, tokensFixture);
        await refetchGate;
        return fulfillJson(route, 200, tokensAfterRevoke);
      },
    );
    await page.route(
      (url) => url.pathname === "/auth/tokens/tok-active",
      (route) => {
        deleteMethod = route.request().method();
        deleteCsrf = route.request().headers()[CSRF_HEADER_NAME] ?? null;
        revoked = true;
        return route.fulfill({ status: 204 });
      },
    );
    await page.goto(`${BASE}/dashboard/tokens`, { waitUntil: "networkidle" });
    await page.getByTestId("token-table").waitFor();
    await page.getByRole("button", { name: "Revoke" }).first().click();
    await confirmRevoke(page);
    // Success is announced by a role="status" Banner, and focus moves
    // to it (the revoked row is gone)
    const success = page.getByTestId("revocation-success");
    await success.waitFor();
    await expect(success.getAttribute("role")).resolves.toBe("status");
    await expect(success.textContent()).resolves.toContain('Token "ci" revoked.');
    await expect.poll(() => success.evaluate((el) => el === document.activeElement)).toBe(true);
    // While refetching, the previous list stays (not replaced) and
    // the rows' Revoke is disabled
    await expect(page.getByText("Loading tokens").count()).resolves.toBe(0);
    await expect(
      page.getByTestId("token-table").getByText("ci", { exact: true }).count(),
    ).resolves.toBe(1);
    await expect
      .poll(() => page.getByTestId("token-table").getByRole("button").first().isDisabled())
      .toBe(true);
    releaseRefetch?.();
    // A targeted revocation deletes the row — after the refetch the
    // "ci" row is gone from the list
    await page.getByText("ci", { exact: true }).waitFor({ state: "detached" });
    await page.getByText("old-laptop", { exact: true }).waitFor();
    await expect(page.getByText("ci", { exact: true }).count()).resolves.toBe(0);
    await expect(success.evaluate((el) => el === document.activeElement)).resolves.toBe(true);
    expect(deleteMethod).toBe("DELETE");
    expect(deleteCsrf).toBe("1");
    expect(violations).toEqual([]);
    await page.close();
  });

  it("keeps the confirmation modal open and other rows locked while a revoke is in flight", async () => {
    // If another row could be armed while the DELETE is in flight,
    // the late-arriving completion would overwrite the armed state and
    // the failure would look attributed to the other revocation (the
    // use-revocation.ts guard). Under DP3 amendment 4 the
    // confirmation is an AlertDialog (modal), so while it runs the
    // dialog stays open (Escape does not close it) and no other row
    // can be touched; after completion the dialog closes and the list
    // is refetched.
    // The DELETE is held behind a gate and measured
    const page = await browser.newPage();
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let revoked = false;
    await routeSession(page);
    await page.route(
      (url) => url.pathname === "/auth/tokens",
      (route) => fulfillJson(route, 200, revoked ? tokensAfterRevoke : tokensFixture),
    );
    await page.route(
      (url) => url.pathname === "/auth/tokens/tok-active",
      async (route) => {
        await gate;
        revoked = true;
        return route.fulfill({ status: 204 });
      },
    );
    await page.goto(`${BASE}/dashboard/tokens`, { waitUntil: "networkidle" });
    await page.getByTestId("token-table").waitFor();
    await page.getByRole("button", { name: "Revoke" }).first().click();
    await confirmRevoke(page);
    const dialog = page.getByRole("alertdialog");
    // While in flight: the modal stays open (Escape does not work
    // either). The rows' Revoke is disabled via isLocked
    // (RevokeButton — a second layer of the guard even behind the
    // modal)
    await page.keyboard.press("Escape");
    await expect(dialog.count()).resolves.toBe(1);
    const rowRevoke = page
      .getByTestId("token-table")
      .getByRole("button", { name: 'Revoke token "old-laptop"', exact: true });
    await expect.poll(() => rowRevoke.isDisabled()).toBe(true);
    release?.();
    // On completion → the dialog closes, the refetch drops the row,
    // and the remaining rows' Revoke is enabled again
    await dialog.waitFor({ state: "hidden" });
    await page.getByText("ci", { exact: true }).waitFor({ state: "detached" });
    await page.getByText("old-laptop", { exact: true }).waitFor();
    await expect
      .poll(() =>
        page.getByRole("button", { name: 'Revoke token "old-laptop"', exact: true }).isDisabled(),
      )
      .toBe(false);
    await page.close();
  });

  it("shows the token 404 wording on the uniform not-found of targeted revocation (S9)", async () => {
    const page = await browser.newPage();
    await routeSession(page);
    await page.route(
      (url) => url.pathname === "/auth/tokens",
      (route) => fulfillJson(route, 200, tokensFixture),
    );
    await page.route(
      (url) => url.pathname === "/auth/tokens/tok-active",
      (route) => fulfillJson(route, 404, { _tag: "TokenNotFound" }),
    );
    await page.goto(`${BASE}/dashboard/tokens`, { waitUntil: "networkidle" });
    await page.getByTestId("token-table").waitFor();
    await page.getByRole("button", { name: "Revoke" }).first().click();
    await confirmRevoke(page);
    // The uniform 404 (no distinction between someone else's and
    // nonexistent) is transcribed in token nouns (attached to ruling
    // CN)
    await page.getByText("The server reports no such token for your account.").waitFor();
    await page.close();
  });

  it("renders the audit log as expandable rows at mobile width (DP3 rulings D / P)", async () => {
    // The audit list is one column of rows (Collapsible) at any
    // width, and on mobile the detail opens directly under the row in
    // the same shape. At 768px and below (AppShell's md) the sidebar
    // moves into a drawer.
    // This path is pinned in CI
    const page = await browser.newPage();
    const violations = collectViolations(page);
    await page.setViewportSize({ width: 390, height: 844 });
    await routeProjectOverview(page);
    await page.route(
      (url) => url.pathname === `/projects/${PROJECT_1}/audit/events`,
      (route) => fulfillJson(route, 200, projectAuditEvents),
    );
    await page.goto(`${BASE}/dashboard/projects/${PROJECT_1}`, { waitUntil: "networkidle" });
    await page.getByRole("tab", { name: "Audit" }).click();
    const list = page.getByTestId("audit-list-project");
    await list.waitFor();
    // Drawn as rows (trigger buttons), not a Table, and the row's
    // meaning (event name, seq, actor, target) is preserved
    await expect(list.locator("table").count()).resolves.toBe(0);
    await expect(list.getByRole("button", { expanded: false }).count()).resolves.toBe(4);
    await expect(list.getByText("chain.member_added").count()).resolves.toBe(1);
    await expect(list.getByText("user_colleague").count()).resolves.toBeGreaterThan(0);
    await expect(list.getByText("seq 2", { exact: true }).count()).resolves.toBe(1);
    await expect(list.getByText("seq 1", { exact: true }).count()).resolves.toBe(1);
    // Opening a row shows every field directly under it in the same
    // column (not a Dialog). Since it is `single`, opening another row
    // closes the previous one
    const genesis = list.getByRole("button", { name: /chain\.genesis/ });
    const visibleRowIds = list.getByText("Row id", { exact: true }).locator("visible=true");
    await genesis.click();
    await visibleRowIds.waitFor();
    await expect(page.getByRole("dialog").count()).resolves.toBe(0);
    await list.getByRole("button", { name: /chain\.member_added/ }).click();
    await expect(genesis.getAttribute("aria-expanded")).resolves.toBe("false");
    await expect(visibleRowIds.count()).resolves.toBe(1);
    // Opening the mirrored device-revocation row shows the revoked
    // device's FP in the payload as recorded (K5-6)
    await list.getByRole("button", { name: /chain\.device_revoked/ }).click();
    await list.getByText(FP_D2).locator("visible=true").first().waitFor();
    // The sidebar moves into a drawer: opened by the toggle, it
    // lines up the destinations and the user id
    await page.getByRole("button", { name: "Open navigation" }).click();
    const drawer = page.getByRole("dialog", { name: "Navigation" });
    await drawer.waitFor();
    await expect(drawer.getByRole("link", { name: "API tokens" }).count()).resolves.toBe(1);
    await expect(drawer.getByTestId("signed-in-user").count()).resolves.toBe(1);
    expect(violations).toEqual([]);
    await page.close();
  });

  it("renders the account (self) audit axis without a seq column", async () => {
    const page = await browser.newPage();
    const violations = collectViolations(page);
    await routeSession(page);
    await page.route(
      (url) => url.pathname === "/auth/audit/events",
      (route) => fulfillJson(route, 200, selfAuditEvents),
    );
    await page.goto(`${BASE}/dashboard/account`, { waitUntil: "networkidle" });
    await page.getByTestId("audit-list-self").waitFor();
    await expect(page.getByText("auth.login_succeeded").count()).resolves.toBeGreaterThan(0);
    // The D1 path never returns seq (AUDIT_SPEC §7) — the row does
    // not show it either (response-adaptive)
    await expect(page.getByText(/^seq /).count()).resolves.toBe(0);
    expect(violations).toEqual([]);
    await page.close();
  });

  it("keeps the shell mounted across SPA navigation without re-checking the session", async () => {
    // DP3 amendment 11: every authenticated screen is a child of the
    // pathless parent route (DashboardLayout), so navigating between
    // screens never remounts the shell and causes neither an
    // /auth/me refetch nor another "Checking your session". The
    // no-remount check is that the sidebar's DOM node stays identical
    // (= the collapsed state etc. is preserved)
    const page = await browser.newPage();
    const violations = collectViolations(page);
    let sessionChecks = 0;
    await page.route("**/auth/me", (route) => {
      sessionChecks += 1;
      return fulfillJson(route, 200, meFixture);
    });
    await page.route(
      (url) => url.pathname === "/projects",
      (route) => fulfillJson(route, 200, projectsPage2),
    );
    await page.route(
      (url) => url.pathname === "/auth/tokens",
      (route) => fulfillJson(route, 200, tokensFixture),
    );
    await page.route(
      (url) => url.pathname === "/auth/audit/events",
      (route) => fulfillJson(route, 200, selfAuditEvents),
    );
    await page.goto(`${BASE}/dashboard`, { waitUntil: "networkidle" });
    await page.getByTestId("project-list").waitFor();
    expect(sessionChecks).toBe(1);
    // document.title follows the screen's h1 (updated on SPA
    // transitions too)
    await expect.poll(() => page.title()).toBe("Projects — maruhi");
    const userItem = page.getByTestId("signed-in-user");
    await userItem.evaluate((el) => {
      (el as HTMLElement).dataset["shellProbe"] = "mounted";
    });
    // From the sidebar to API tokens (an SPA transition). The h1
    // changes and no extra session check happens
    await page.getByRole("link", { name: "API tokens" }).click();
    await page.getByTestId("token-table").waitFor();
    await expect(page.getByRole("heading", { level: 1 }).textContent()).resolves.toBe("API tokens");
    await expect(
      page.getByRole("link", { name: "API tokens" }).getAttribute("aria-current"),
    ).resolves.toBe("page");
    await expect.poll(() => page.title()).toBe("API tokens — maruhi");
    expect(sessionChecks).toBe(1);
    await expect(page.getByText("Checking your session").count()).resolves.toBe(0);
    await expect(
      userItem.evaluate((el) => (el as HTMLElement).dataset["shellProbe"]),
    ).resolves.toBe("mounted");
    // Then on to Account audit (also reachable via the footer's user
    // id)
    await userItem.click();
    await page.getByTestId("audit-list-self").waitFor();
    await expect(page.getByRole("heading", { level: 1 }).textContent()).resolves.toBe(
      "Account audit",
    );
    await expect.poll(() => page.title()).toBe("Account audit — maruhi");
    expect(sessionChecks).toBe(1);
    expect(violations).toEqual([]);
    await page.close();
  });

  it("returns to the sign-in screen in place when a screen fetch reports 401", async () => {
    // A side effect of DP3 amendment 11 keeping the shell across
    // transitions: even when the session is revoked mid-way, the
    // screen's 401 → notifies the shell → the sign-in screen appears
    // in place (no reload, no re-navigation)
    const page = await browser.newPage();
    const violations = collectViolations(page);
    await routeSession(page);
    await page.route((url) => url.pathname === "/auth/tokens", unauthorized);
    await page.goto(`${BASE}/dashboard/tokens`, { waitUntil: "networkidle" });
    await page.getByTestId("login-card").waitFor();
    await expect(page.getByText("You are signed out.").count()).resolves.toBe(1);
    await expect(page.getByTestId("signed-in-user").count()).resolves.toBe(0);
    expect(new URL(page.url()).pathname).toBe("/dashboard/tokens");
    // The focus that fell to body when the element disappeared in
    // the switch moves to the sign-in screen's heading
    await expect(page.getByRole("main").count()).resolves.toBe(1);
    await expect
      .poll(() =>
        page.getByTestId("sign-in-heading").evaluate((el) => el === document.activeElement),
      )
      .toBe(true);
    expect(violations).toEqual([]);
    await page.close();
  });

  it("notes how many device entries the fold could not read, without changing the readable sets (K5-17)", async () => {
    const page = await browser.newPage();
    const violations = collectViolations(page);
    await routeSession(page);
    await page.route(
      (url) => url.pathname === `/projects/${PROJECT_1}/chain`,
      (route) => fulfillJson(route, 200, chainWithUnreadableEntry),
    );
    await page.route(
      (url) => url.pathname === `/projects/${PROJECT_1}/environments`,
      (route) => fulfillJson(route, 200, environmentsFixture),
    );
    await page.goto(`${BASE}/dashboard/projects/${PROJECT_1}`, { waitUntil: "networkidle" });
    await page.getByTestId("member-table").waitFor();
    const note = page.getByTestId("unreadable-entries");
    await expect(note.textContent()).resolves.toContain(
      "1 entry in the reported chain could not be read and was left out",
    );
    await expect(note.textContent()).resolves.toContain("maruhi project verify");
    // The set derived from the readable rows is unchanged (user_e2e
    // = 2 devices)
    const e2eRow = page
      .getByTestId("member-table")
      .getByRole("row")
      .filter({ hasText: "user_e2e" });
    await expect(e2eRow.getByText("2", { exact: true }).count()).resolves.toBe(1);
    expect(violations).toEqual([]);
    await page.close();
  });

  // -------------------------------------------------------------------------
  // S11 device registry (DK K5 — design record dk-design.md §10
  // K5-7 through K5-10)
  // -------------------------------------------------------------------------

  it("lists the device registry with token links resolved against the token list (S11)", async () => {
    const page = await browser.newPage();
    const violations = collectViolations(page);
    await routeSession(page);
    await page.route(
      (url) => url.pathname === "/auth/devices",
      (route) => fulfillJson(route, 200, devicesFixture),
    );
    await page.route(
      (url) => url.pathname === "/auth/tokens",
      (route) => fulfillJson(route, 200, tokensFixture),
    );
    await page.goto(`${BASE}/dashboard/devices`, { waitUntil: "networkidle" });
    await page.getByTestId("device-table").waitFor();
    await expect(page.getByRole("heading", { level: 1 }).textContent()).resolves.toBe("Devices");
    await expect(
      page.getByRole("link", { name: "Devices" }).getAttribute("aria-current"),
    ).resolves.toBe("page");
    const table = page.getByTestId("device-table");
    // The display name (text node) and the full-length FP (a
    // reference value)
    for (const label of ["macbook", "phone", "codespace"]) {
      await expect(table.getByText(label, { exact: true }).count()).resolves.toBe(1);
    }
    await expect(table.getByText(FP_D2, { exact: true }).count()).resolves.toBe(1);
    // The tokenId collation (K5-8): present in the listing → name +
    // prefix; absent → id only; missing → none linked
    await expect(table.getByText("ci", { exact: true }).count()).resolves.toBe(1);
    await expect(table.getByText("maruhi_pat_abcdefgh", { exact: true }).count()).resolves.toBe(1);
    await expect(table.getByText("tok-gone", { exact: true }).count()).resolves.toBe(1);
    await expect(
      table.getByText("not among your tokens (revoked or expired?)", { exact: true }).count(),
    ).resolves.toBe(1);
    await expect(table.getByText("none linked", { exact: true }).count()).resolves.toBe(1);
    // The revocation entry exists only on a collated row ("Revoke
    // token" — not a device revocation). The spoken name identifies
    // the row by token name and device name
    await expect(table.getByRole("button", { name: "Revoke token" }).count()).resolves.toBe(1);
    const deviceRevoke = table.getByRole("button", {
      name: 'Revoke token "ci" of device macbook',
      exact: true,
    });
    await expect(deviceRevoke.count()).resolves.toBe(1);
    await expect(deviceRevoke.textContent()).resolves.toBe("Revoke token");
    // No register/delete/approve operations. The lost-device path is
    // the CLI's device revoke → token revocation
    await expect(
      page.getByRole("button", { name: /register|approve|remove device/i }).count(),
    ).resolves.toBe(0);
    const notes = page.getByTestId("device-notes");
    await expect(notes.textContent()).resolves.toContain("maruhi device revoke <fingerprint>");
    await expect(
      notes.getByRole("link", { name: "API tokens" }).getAttribute("href"),
    ).resolves.toBe("/dashboard/tokens");
    // The advisory caveat (the registry is not a source of truth —
    // the CLI verifies the chain)
    await expect(page.getByText(/maruhi device list/).count()).resolves.toBeGreaterThan(0);
    expect(violations).toEqual([]);
    await page.close();
  });

  it("revokes the linked token from a device row with the CSRF header and refreshes both lists (S11)", async () => {
    const page = await browser.newPage();
    const violations = collectViolations(page);
    let revoked = false;
    let deleteMethod: string | null = null;
    let deleteCsrf: string | null = null;
    let deviceFetches = 0;
    await routeSession(page);
    await page.route(
      (url) => url.pathname === "/auth/devices",
      (route) => {
        deviceFetches += 1;
        return fulfillJson(route, 200, devicesFixture);
      },
    );
    await page.route(
      (url) => url.pathname === "/auth/tokens",
      (route) => fulfillJson(route, 200, revoked ? tokensAfterRevoke : tokensFixture),
    );
    await page.route(
      (url) => url.pathname === "/auth/tokens/tok-active",
      (route) => {
        deleteMethod = route.request().method();
        deleteCsrf = route.request().headers()[CSRF_HEADER_NAME] ?? null;
        revoked = true;
        return route.fulfill({ status: 204 });
      },
    );
    await page.goto(`${BASE}/dashboard/devices`, { waitUntil: "networkidle" });
    await page.getByTestId("device-table").waitFor();
    await page.getByRole("button", { name: "Revoke token" }).click();
    // The confirmation dialog names the token and states that this
    // is not a device-key revocation
    const dialog = page.getByRole("alertdialog");
    await dialog.waitFor();
    await expect(dialog.textContent()).resolves.toContain('Revoke token "ci"?');
    await expect(dialog.textContent()).resolves.toContain("does not revoke the device key");
    await dialog.getByRole("button", { name: "Revoke", exact: true }).click();
    // After the refetch: the registry's tokenId column remains
    // (advisory), so it falls to no-collated-target and the Revoke
    // token is gone
    await page
      .getByText("not among your tokens (revoked or expired?)", { exact: true })
      .nth(1)
      .waitFor();
    await expect(page.getByRole("button", { name: "Revoke token" }).count()).resolves.toBe(0);
    await expect(page.getByTestId("revocation-success").textContent()).resolves.toContain(
      'Token "ci" revoked.',
    );
    expect(deleteMethod).toBe("DELETE");
    expect(deleteCsrf).toBe("1");
    expect(deviceFetches).toBe(2);
    expect(violations).toEqual([]);
    await page.close();
  });

  it("shows the empty registry, the older-server 404 wording, and the sign-in screen on 401 (S11)", async () => {
    const page = await browser.newPage();
    await routeSession(page);
    await page.route(
      (url) => url.pathname === "/auth/tokens",
      (route) => fulfillJson(route, 200, tokensFixture),
    );
    let mode: "empty" | "not-found" | "unauthorized" = "empty";
    await page.route(
      (url) => url.pathname === "/auth/devices",
      (route) => {
        if (mode === "empty") return fulfillJson(route, 200, { devices: [] });
        if (mode === "not-found") return fulfillJson(route, 404, { _tag: "NotFound" });
        return unauthorized(route);
      },
    );
    await page.goto(`${BASE}/dashboard/devices`, { waitUntil: "networkidle" });
    await page.getByTestId("device-empty").waitFor();
    await expect(page.getByText("No devices registered").count()).resolves.toBe(1);
    // A 404 is not folded into the empty state — transcribed in the
    // registry's nouns (K5-9)
    mode = "not-found";
    await page.reload({ waitUntil: "networkidle" });
    await page.getByText("The server reports no device registry for your account.").waitFor();
    // On 401 the shell moves to the sign-in screen in place
    mode = "unauthorized";
    await page.reload({ waitUntil: "networkidle" });
    await page.getByTestId("login-card").waitFor();
    await page.close();
  });
});
