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
import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";

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
    } catch {}
    if (Date.now() > deadline) throw new Error(`server at ${url} did not start`);
    await new Promise((r) => setTimeout(r, 500));
  }
}

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
    proc.stdout?.destroy();
    proc.stderr?.destroy();
  }
}

beforeAll(async () => {
  const port = await getFreePort();
  BASE = `http://127.0.0.1:${port}`;
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
    expect(html).toContain('<div id="app">');
    expect(html).toContain("fun__rsc-payload");
  });

  it("hydrates the dashboard under strict CSP with xstyle and the maruhi theme applied", async () => {
    const page = await browser.newPage();
    const violations = collectViolations(page);
    await routeProjectOverview(page);
    const response = await page.goto(`${BASE}/dashboard/projects/${PROJECT_1}`, {
      waitUntil: "networkidle",
    });
    const projectId = page.getByTestId("project-id");
    await expect(projectId.textContent()).resolves.toBe(PROJECT_1);

    const breakable = await projectId.evaluate((el) => {
      const style = getComputedStyle(el);
      return { overflowWrap: style.overflowWrap, minWidth: style.minWidth };
    });
    expect(breakable).toEqual({ overflowWrap: "anywhere", minWidth: "0px" });

    const hiddenPanelDisplay = await page
      .locator("[role=tabpanel][hidden]")
      .first()
      .evaluate((el) => getComputedStyle(el).display);
    expect(hiddenPanelDisplay).toBe("none");

    const accent = await page.evaluate(() =>
      getComputedStyle(document.documentElement).getPropertyValue("--color-accent").trim(),
    );
    expect(accent).not.toBe("");
    expect(accent.toLowerCase()).not.toContain("#0064e0");
    const themeCss = readFileSync(new URL("../theme/maruhi.css", import.meta.url), "utf8");
    expect(themeCss.toLowerCase()).toContain(accent.toLowerCase());

    await page.locator("style#astryx-layer-slide-rules").waitFor({ state: "attached" });
    const slideRules = await page.evaluate(async () => {
      const el = document.querySelector<HTMLStyleElement>("style#astryx-layer-slide-rules");
      const digest = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(el?.textContent ?? ""),
      );
      return {
        applied: el?.sheet !== null && el?.sheet !== undefined,
        hash: btoa(String.fromCharCode(...new Uint8Array(digest))),
      };
    });
    expect(slideRules.applied).toBe(true);
    const styleSrc = (response?.headers()["content-security-policy"] ?? "")
      .split(";")
      .map((directive) => directive.trim())
      .find((directive) => directive.startsWith("style-src "));
    expect(styleSrc).toBe(`style-src 'self' 'sha256-${slideRules.hash}'`);

    expect(violations).toEqual([]);
    await page.close();
  });

  it("navigates as SPA via Navigation API (no full page load)", async () => {
    const page = await browser.newPage();
    const violations = collectViolations(page);
    await page.route("**/auth/me", unauthorized);
    await page.goto(BASE, { waitUntil: "networkidle" });
    await page.evaluate(() => {
      (window as unknown as Record<string, unknown>)["__spa_marker"] = "alive";
    });
    await page.getByTestId("to-dashboard").click();
    await page.getByTestId("login-card").waitFor();
    expect(new URL(page.url()).pathname).toBe("/dashboard");
    const marker = await page.evaluate(
      () => (window as unknown as Record<string, unknown>)["__spa_marker"],
    );
    expect(marker).toBe("alive");
    expect(violations).toEqual([]);
    await page.close();
  });

  it("serves /invite as a script-free static page with per-path CSP script-src 'none'", async () => {
    const res = await fetch(`${BASE}/invite`);
    expect(res.status).toBe(200);
    const csp = res.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("script-src 'none'");
    expect(csp).toContain("style-src 'self'");
    expect(csp).toContain("img-src 'self'");
    expect(csp).not.toContain("unsafe-inline");
    expect(csp).not.toContain("'self' 'sha256-");
    expect(csp).not.toContain("script-src 'self'");
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("referrer-policy")).toBe("no-referrer");
    const html = await res.text();
    expect(html.toLowerCase()).not.toContain("<script");
    expect(html).toContain("maruhi invite accept");
    expect(html).toMatch(
      /<meta\s+http-equiv="Content-Security-Policy"\s+content="[^"]*script-src 'none'/i,
    );
  });

  it("normalizes near-miss paths to the canonical /invite (link format §15-3)", async () => {
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
    const inviteRes = await fetch(`${BASE}/invite`, { redirect: "manual" });
    expect(inviteRes.status).toBe(200);
  });

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
    for (const res of [theme, pages]) {
      expect(res.headers.get("cache-control")).toContain("must-revalidate");
      expect(res.headers.get("etag")).not.toBeNull();
    }
  });

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
    const maxWidth = await page.locator(".page").evaluate((el) => getComputedStyle(el).maxWidth);
    expect(maxWidth).toBe("640px");
    const background = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    expect(background).not.toBe("rgba(0, 0, 0, 0)");
    for (const selector of ["h1", ".outcome"]) {
      const weight = await page.locator(selector).evaluate((el) => getComputedStyle(el).fontWeight);
      expect(weight, selector).toBe("700");
    }
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
    await page.goto(`${BASE}/invite#v=1&t=dummy-invite-token&p=dummy-project&r=member`, {
      waitUntil: "networkidle",
    });
    await expect(page.locator("h1").textContent()).resolves.toContain("maruhi");
    await expect(page.evaluate(() => document.scripts.length)).resolves.toBe(0);
    const maxWidth = await page.locator(".page").evaluate((el) => getComputedStyle(el).maxWidth);
    expect(maxWidth).toBe("640px");
    expect(violations).toEqual([]);
    await page.close();
  });

  it("degrades to MPA (full page loads) when Navigation API is unavailable", async () => {
    const page = await browser.newPage();
    const violations = collectViolations(page);
    await page.route("**/auth/me", unauthorized);
    await page.addInitScript(() => {
      // @ts-expect-error an intentional deletion for verification
      delete window.navigation;
    });
    await page.goto(BASE, { waitUntil: "networkidle" });
    await page.evaluate(() => {
      (window as unknown as Record<string, unknown>)["__spa_marker"] = "alive";
    });
    await page.getByTestId("to-dashboard").click();
    await page.getByTestId("login-card").waitFor();
    expect(new URL(page.url()).pathname).toBe("/dashboard");
    const marker = await page.evaluate(
      () => (window as unknown as Record<string, unknown>)["__spa_marker"],
    );
    expect(marker).toBeUndefined();
    expect(violations).toEqual([]);
    await page.close();
  });
});

function fulfillJson(route: Route, status: number, body: unknown): Promise<void> {
  return route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
}

function unauthorized(route: Route): Promise<void> {
  return fulfillJson(route, 401, { _tag: "Unauthorized" });
}

async function routeSession(page: Page): Promise<void> {
  await page.route("**/auth/me", (route) => fulfillJson(route, 200, meFixture));
}

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

async function confirmRevoke(page: Page): Promise<void> {
  const dialog = page.getByRole("alertdialog");
  await dialog.waitFor();
  await dialog.getByRole("button", { name: "Revoke", exact: true }).click();
}

function panelDisplay(page: Page, tab: string): Promise<string> {
  return page.locator(`#project-panel-${tab}`).evaluate((el) => getComputedStyle(el).display);
}

function collectViolations(page: Page): string[] {
  const violations: string[] = [];
  page.on("console", (msg) => {
    if (msg.text().includes("Content Security Policy")) violations.push(msg.text());
  });
  return violations;
}

describe("web e2e: serving topology (W2 rulings BM/BT — combined worker)", () => {
  it("routes API paths to the worker, not the asset layer", async () => {
    const config = await fetch(`${BASE}/auth/config`);
    expect([200, 503]).toContain(config.status);
    expect(config.headers.get("content-type") ?? "").toContain("application/json");
    const projects = await fetch(`${BASE}/projects`);
    expect(projects.status).toBe(401);
    expect(projects.headers.get("content-type") ?? "").toContain("application/json");
  });

  it("does not let the /invite* redirect catch-all swallow POST /invites/accept", async () => {
    const res = await fetch(`${BASE}/invites/accept`, { method: "POST", redirect: "manual" });
    expect(res.status).toBe(401);
  });
});

describe("web e2e: read dashboard (W2 — S3-S7, mocked API via page.route)", () => {
  it("keeps every mocked fixture wire-valid against the api-schema contracts (ruling BV)", () => {
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
    await expect.poll(() => page.title()).toBe("Sign in — maruhi");
    await expect(page.getByRole("main").count()).resolves.toBe(1);
    await expect(page.getByRole("main").getByTestId("login-card").count()).resolves.toBe(1);
    await expect(
      page.getByTestId("sign-in-heading").evaluate((el) => el === document.activeElement),
    ).resolves.toBe(false);
    expect(violations).toEqual([]);
    await page.close();
  });

  it("titles the session-check frames (loading / failure) per state", async () => {
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
    await expect(
      page.getByRole("alert").filter({ hasText: "Could not reach the server" }).count(),
    ).resolves.toBe(1);
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
    await expect(page.getByText(PROJECT_1).count()).resolves.toBeGreaterThan(0);
    await page.getByTestId("load-more-projects").click();
    await page.getByText(PROJECT_2).waitFor();
    await expect(page.getByTestId("load-more-projects").count()).resolves.toBe(0);
    await expect(page.getByText("admin", { exact: true }).count()).resolves.toBeGreaterThan(0);
    await expect(page.getByText("reader", { exact: true }).count()).resolves.toBeGreaterThan(0);

    await page.getByTestId("sign-out").click();
    await page.getByTestId("login-card").waitFor();
    expect(sawCsrfHeader).toBe("1");
    await expect(page.getByText("You are signed out.").count()).resolves.toBeGreaterThan(0);
    await expect
      .poll(() =>
        page.getByTestId("sign-in-heading").evaluate((el) => el === document.activeElement),
      )
      .toBe(true);
    expect(violations).toEqual([]);
    await page.close();
  });

  it("keeps the focused Load more button mounted while the next page loads", async () => {
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

    await expect(page.getByRole("tablist", { name: "Project" }).count()).resolves.toBe(1);
    await expect(
      page.getByRole("tab", { name: "Overview" }).getAttribute("aria-selected"),
    ).resolves.toBe("true");
    await expect(
      page.getByRole("tab", { name: "Audit" }).getAttribute("aria-controls"),
    ).resolves.toBe("project-panel-audit");
    await expect(
      page.locator("#project-panel-audit").getAttribute("aria-labelledby"),
    ).resolves.toBe(await page.getByRole("tab", { name: "Audit" }).getAttribute("id"));
    await expect(panelDisplay(page, "overview")).resolves.toBe("flex");
    await expect(panelDisplay(page, "audit")).resolves.toBe("none");
    await expect(page.getByRole("tabpanel").count()).resolves.toBe(1);

    await page.getByTestId("member-table").waitFor();
    await expect(page.getByText("user_colleague").count()).resolves.toBeGreaterThan(0);
    const members = page.getByTestId("member-table");
    await expect(members.getByText("565656…565656", { exact: true }).count()).resolves.toBe(1);
    await expect(
      members.getByText("fingerprint not reported", { exact: true }).count(),
    ).resolves.toBe(2);
    await expect(members.getByText("d2d2d2…d2d2d2").count()).resolves.toBe(0);
    const e2eRow = members.getByRole("row").filter({ hasText: "user_e2e" });
    await expect(e2eRow.getByText("2", { exact: true }).count()).resolves.toBe(1);
    const colleagueRow = members.getByRole("row").filter({ hasText: "user_colleague" });
    await expect(colleagueRow.getByText("1", { exact: true }).count()).resolves.toBe(1);
    await page.getByTestId("env-table").waitFor();
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
    await expect(page.getByText("seq 2", { exact: true }).count()).resolves.toBe(1);
    await expect(page.getByText("chain.member_added").count()).resolves.toBeGreaterThan(0);
    await expect(page.getByText("chain.device_added").count()).resolves.toBe(1);
    await expect(page.getByText("chain.device_revoked").count()).resolves.toBe(1);
    const list = page.getByTestId("audit-list-project");
    const visibleRowIds = list.getByText("Row id", { exact: true }).locator("visible=true");
    await expect(visibleRowIds.count()).resolves.toBe(0);
    const row = list.getByRole("button", { name: /chain\.member_added/ });
    await row.click();
    await expect(row.getAttribute("aria-expanded")).resolves.toBe("true");
    await visibleRowIds.waitFor();
    await expect(visibleRowIds.count()).resolves.toBe(1);
    await expect(
      list.getByText("user_colleague", { exact: true }).locator("visible=true").count(),
    ).resolves.toBe(2);
    await page.getByRole("button", { name: "Invites", pressed: false }).click();
    await page.getByText("Not available to your role").first().waitFor();

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
    await page.getByTestId("project-list").waitFor();
    expect(new URL(page.url()).pathname).toBe("/dashboard");
    expect(violations).toEqual([]);
    await page.close();
  });

  it("keeps the marker-free landing free of API calls (the boundary of BP round 3, pinned)", async () => {
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
    await expect(page.title()).resolves.toBe("maruhi");
    await page.close();
  });

  it("stays on the landing page when the marker is set but no session exists", async () => {
    const page = await browser.newPage();
    await page.route("**/auth/me", unauthorized);
    await page.addInitScript(() => {
      try {
        sessionStorage.setItem("maruhi-resume-dashboard", "1");
      } catch {}
    });
    await page.goto(`${BASE}/`, { waitUntil: "networkidle" });
    await page.getByTestId("home-heading").waitFor();
    expect(new URL(page.url()).pathname).toBe("/");
    await page.close();
  });

  it("lists invitations, revokes via inline confirm with the CSRF header, and refreshes (S8)", async () => {
    const page = await browser.newPage();
    const violations = collectViolations(page);
    let revoked = false;
    let deleteMethod: string | null = null;
    let deleteCsrf: string | null = null;
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
    await expect(page.getByTestId("invite-notes").textContent()).resolves.toContain(
      "maruhi invite create",
    );
    await expect(page.getByRole("button", { name: "Revoke" }).count()).resolves.toBe(2);
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
    await page.getByRole("button", { name: "Revoke" }).first().click();
    await confirmRevoke(page);
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
    await expect(page.getByText("Expired", { exact: true }).count()).resolves.toBe(1);
    await expect(page.getByText("never", { exact: true }).count()).resolves.toBe(1);
    const table = page.getByTestId("token-table");
    for (const name of ["ci", "old-laptop"]) {
      const button = table.getByRole("button", { name: `Revoke token "${name}"`, exact: true });
      await expect(button.count()).resolves.toBe(1);
      await expect(button.textContent()).resolves.toBe("Revoke");
    }
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
    const success = page.getByTestId("revocation-success");
    await success.waitFor();
    await expect(success.getAttribute("role")).resolves.toBe("status");
    await expect(success.textContent()).resolves.toContain('Token "ci" revoked.');
    await expect.poll(() => success.evaluate((el) => el === document.activeElement)).toBe(true);
    await expect(page.getByTestId("token-list").getByText("Loading tokens").count()).resolves.toBe(
      0,
    );
    await expect(
      page.getByTestId("token-table").getByText("ci", { exact: true }).count(),
    ).resolves.toBe(1);
    await expect
      .poll(() => page.getByTestId("token-table").getByRole("button").first().isDisabled())
      .toBe(true);
    releaseRefetch?.();
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
    await page.keyboard.press("Escape");
    await expect(dialog.count()).resolves.toBe(1);
    const rowRevoke = page
      .getByTestId("token-table")
      .getByRole("button", { name: 'Revoke token "old-laptop"', exact: true });
    await expect.poll(() => rowRevoke.isDisabled()).toBe(true);
    release?.();
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
    await page.getByText("The server reports no such token for your account.").waitFor();
    await page.close();
  });

  it("renders the audit log as expandable rows at mobile width (DP3 rulings D / P)", async () => {
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
    await expect(list.locator("table").count()).resolves.toBe(0);
    await expect(list.getByRole("button", { expanded: false }).count()).resolves.toBe(4);
    await expect(list.getByText("chain.member_added").count()).resolves.toBe(1);
    await expect(list.getByText("user_colleague").count()).resolves.toBeGreaterThan(0);
    await expect(list.getByText("seq 2", { exact: true }).count()).resolves.toBe(1);
    await expect(list.getByText("seq 1", { exact: true }).count()).resolves.toBe(1);
    const genesis = list.getByRole("button", { name: /chain\.genesis/ });
    const visibleRowIds = list.getByText("Row id", { exact: true }).locator("visible=true");
    await genesis.click();
    await visibleRowIds.waitFor();
    await expect(page.getByRole("dialog").count()).resolves.toBe(0);
    await list.getByRole("button", { name: /chain\.member_added/ }).click();
    await expect(genesis.getAttribute("aria-expanded")).resolves.toBe("false");
    await expect(visibleRowIds.count()).resolves.toBe(1);
    await list.getByRole("button", { name: /chain\.device_revoked/ }).click();
    await list.getByText(FP_D2).locator("visible=true").first().waitFor();
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
    await expect(page.getByText(/^seq /).count()).resolves.toBe(0);
    expect(violations).toEqual([]);
    await page.close();
  });

  it("keeps the shell mounted across SPA navigation without re-checking the session", async () => {
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
    await expect.poll(() => page.title()).toBe("Projects — maruhi");
    const userItem = page.getByTestId("signed-in-user");
    await userItem.evaluate((el) => {
      (el as HTMLElement).dataset["shellProbe"] = "mounted";
    });
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
    const page = await browser.newPage();
    const violations = collectViolations(page);
    await routeSession(page);
    await page.route((url) => url.pathname === "/auth/tokens", unauthorized);
    await page.goto(`${BASE}/dashboard/tokens`, { waitUntil: "networkidle" });
    await page.getByTestId("login-card").waitFor();
    await expect(page.getByText("You are signed out.").count()).resolves.toBe(1);
    await expect(page.getByTestId("signed-in-user").count()).resolves.toBe(0);
    expect(new URL(page.url()).pathname).toBe("/dashboard/tokens");
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
    const e2eRow = page
      .getByTestId("member-table")
      .getByRole("row")
      .filter({ hasText: "user_e2e" });
    await expect(e2eRow.getByText("2", { exact: true }).count()).resolves.toBe(1);
    expect(violations).toEqual([]);
    await page.close();
  });

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
    for (const label of ["macbook", "phone", "codespace"]) {
      await expect(table.getByText(label, { exact: true }).count()).resolves.toBe(1);
    }
    await expect(table.getByText(FP_D2, { exact: true }).count()).resolves.toBe(1);
    await expect(table.getByText("ci", { exact: true }).count()).resolves.toBe(1);
    await expect(table.getByText("maruhi_pat_abcdefgh", { exact: true }).count()).resolves.toBe(1);
    await expect(table.getByText("tok-gone", { exact: true }).count()).resolves.toBe(1);
    await expect(
      table.getByText("not among your tokens (revoked or expired?)", { exact: true }).count(),
    ).resolves.toBe(1);
    await expect(table.getByText("none linked", { exact: true }).count()).resolves.toBe(1);
    await expect(table.getByRole("button", { name: "Revoke token" }).count()).resolves.toBe(1);
    const deviceRevoke = table.getByRole("button", {
      name: 'Revoke token "ci" of device macbook',
      exact: true,
    });
    await expect(deviceRevoke.count()).resolves.toBe(1);
    await expect(deviceRevoke.textContent()).resolves.toBe("Revoke token");
    await expect(
      page.getByRole("button", { name: /register|approve|remove device/i }).count(),
    ).resolves.toBe(0);
    const notes = page.getByTestId("device-notes");
    await expect(notes.textContent()).resolves.toContain("maruhi device revoke <fingerprint>");
    await expect(
      notes.getByRole("link", { name: "API tokens" }).getAttribute("href"),
    ).resolves.toBe("/dashboard/tokens");
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
    const dialog = page.getByRole("alertdialog");
    await dialog.waitFor();
    await expect(dialog.textContent()).resolves.toContain('Revoke token "ci"?');
    await expect(dialog.textContent()).resolves.toContain("does not revoke the device key");
    await dialog.getByRole("button", { name: "Revoke", exact: true }).click();
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
    await expect(
      page.getByTestId("device-empty").getByText("No devices registered").count(),
    ).resolves.toBe(1);
    mode = "not-found";
    await page.reload({ waitUntil: "networkidle" });
    await page.getByText("The server reports no device registry for your account.").waitFor();
    mode = "unauthorized";
    await page.reload({ waitUntil: "networkidle" });
    await page.getByTestId("login-card").waitFor();
    await page.close();
  });
});
