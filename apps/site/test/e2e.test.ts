// e2e for the apex site (LP + docs — Blume). The built dist (+
// scripts/postbuild.ts's _headers) is served under **the same wrangler
// config as production** (apps/site/wrangler.jsonc — Workers Static Assets
// only), and Playwright (Chromium) pins the following (the verification
// items of docs/notes/web-design-pass.md §4):
//   1. all requests same-origin (zero outbound traffic — "say nothing")
//   2. zero CSP violations; `script-src 'self'` / `style-src 'self'`
//      baseline with no 'unsafe-inline'
//   3. fonts are self-hosted (Archivo / Martian Mono actually apply, and
//      the full OFL texts are readable from /fonts/)
//   4. the vermilion accent matches DP1's theme values in light / dark
//      (system-following)
//   5. `/docs` opens, and trailing-slash normalization plus the 404 behave
//      as wrangler.jsonc configures
// Requires `bun run build` beforehand.
import { type ChildProcess, spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer } from "node:net";

import { type Browser, chromium, type Page } from "playwright";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { accent, background } from "../theme/tokens.ts";

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
    } catch {
      // not up yet
    }
    if (Date.now() > deadline) throw new Error(`server at ${url} did not start`);
    await new Promise((r) => setTimeout(r, 500));
  }
}

// Same shutdown procedure as apps/web/test/e2e.test.ts (SIGTERM → SIGKILL
// after 10s; pipes are closed unconditionally)
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
        `wrangler dev did not exit within 10s of SIGTERM; sending SIGKILL\n--- wrangler output ---\n${wranglerOutput()}`,
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
  wranglerProcess = spawn("bunx", ["wrangler", "dev", "--port", String(port)], {
    cwd: import.meta.dirname + "/..",
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, CI: "1" },
  });
  wranglerProcess.stdout?.on("data", (chunk: Buffer) => wranglerLogs.push(chunk.toString()));
  wranglerProcess.stderr?.on("data", (chunk: Buffer) => wranglerLogs.push(chunk.toString()));
  try {
    await waitForServer(BASE, 60_000);
  } catch (cause) {
    await stopWrangler(wranglerProcess);
    throw new Error(
      `wrangler dev did not become ready\n--- wrangler output ---\n${wranglerOutput()}`,
      { cause },
    );
  }
  // In environments that cannot download a browser (Claude Code on the web
  // etc.), the preinstalled Chromium's path arrives via
  // PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH
  const executablePath = process.env["PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"];
  browser = await chromium.launch(executablePath ? { executablePath } : {});
});

afterAll(async () => {
  await browser?.close();
  await stopWrangler(wranglerProcess);
});

/** Collects the URLs of every request a page makes and its CSP violations. */
function observe(page: Page): { requests: string[]; violations: string[] } {
  const requests: string[] = [];
  const violations: string[] = [];
  page.on("request", (request) => requests.push(request.url()));
  page.on("console", (msg) => {
    if (msg.text().includes("Content Security Policy")) violations.push(msg.text());
  });
  return { requests, violations };
}

const foreignOrigins = (requests: string[]): string[] =>
  [...new Set(requests.map((u) => new URL(u).origin))].filter(
    (origin) => origin !== new URL(BASE).origin,
  );

const themeCss = readFileSync(new URL("../theme.css", import.meta.url), "utf8");

describe("site e2e: headers (Workers Static Assets — apps/site/wrangler.jsonc)", () => {
  it("serves the landing page with a self-only CSP and security headers", async () => {
    const res = await fetch(BASE);
    expect(res.status).toBe(200);
    const csp = res.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("style-src 'self'");
    expect(csp).not.toContain("unsafe-inline");
    expect(csp).not.toContain("unsafe-eval");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("referrer-policy")).toBe("no-referrer");
    expect(res.headers.get("strict-transport-security")).toContain("max-age=");
    // postbuild.ts keeps the _headers Blume emitted (the top Link header)
    expect(res.headers.get("link")).toContain("llms.txt");
  });

  it("keeps Blume's charset rule for raw Markdown mirrors", async () => {
    const res = await fetch(`${BASE}/docs/getting-started.md`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("charset=utf-8");
    expect(await res.text()).toContain("maruhi login");
  });

  it("serves the fonts and their OFL license texts from this origin", async () => {
    for (const file of ["OFL-Archivo.txt", "OFL-MartianMono.txt"]) {
      const res = await fetch(`${BASE}/fonts/${file}`);
      expect(res.status, file).toBe(200);
      expect(await res.text(), file).toContain("SIL OPEN FONT LICENSE Version 1.1");
    }
    for (const file of [
      "archivo-latin-wdth-normal.woff2",
      "martian-mono-latin-wght-normal.woff2",
    ]) {
      const res = await fetch(`${BASE}/fonts/${file}`);
      expect(res.status, file).toBe(200);
      expect(res.headers.get("content-type"), file).toContain("font/woff2");
    }
  });

  it("normalizes trailing slashes to Blume's link format and serves the 404 page", async () => {
    const ok = await fetch(`${BASE}/docs/getting-started`, { redirect: "manual" });
    expect(ok.status).toBe(200);
    const slashed = await fetch(`${BASE}/docs/getting-started/`, { redirect: "manual" });
    expect([301, 302, 307, 308]).toContain(slashed.status);
    expect(new URL(slashed.headers.get("location") ?? "", BASE).pathname).toBe(
      "/docs/getting-started",
    );
    const missing = await fetch(`${BASE}/docs/no-such-page`);
    expect(missing.status).toBe(404);
    expect(await missing.text()).toContain("404");
  });
});

describe("site e2e: landing page (Blume custom page under strict CSP)", () => {
  it("loads with zero external requests and zero CSP violations", async () => {
    const page = await browser.newPage();
    const { requests, violations } = observe(page);
    await page.goto(BASE, { waitUntil: "networkidle" });
    await expect(page.locator("h1").first().textContent()).resolves.toContain("Not even us");
    expect(foreignOrigins(requests)).toEqual([]);
    expect(violations).toEqual([]);
    // The self-hosted woff2 fonts are actually fetched
    expect(requests.some((u) => u.endsWith(".woff2"))).toBe(true);
    // No inline style attributes / external stylesheets (style-src 'self' +
    // only the Astro Fonts hash)
    const inlineStyleAttrs = await page.evaluate(() => document.querySelectorAll("[style]").length);
    expect(inlineStyleAttrs).toBe(0);
    await page.close();
  });

  it("leaves the terminal samples as plain preformatted text (no aria-label on a generic role)", async () => {
    // <pre> has the generic role, and assistive tech may or may not read an
    // aria-label. Keep every terminal example treated the same (let the body
    // be read as-is)
    const page = await browser.newPage();
    await page.goto(BASE, { waitUntil: "networkidle" });
    const terminals = page.locator("pre.terminal");
    await expect(terminals.count()).resolves.toBeGreaterThan(1);
    await expect(
      terminals.evaluateAll((els) => els.filter((el) => el.hasAttribute("aria-label")).length),
    ).resolves.toBe(0);
    await page.close();
  });

  it("renders in Archivo (headings, body) and Martian Mono (code)", async () => {
    const page = await browser.newPage();
    await page.goto(BASE, { waitUntil: "networkidle" });
    await page.evaluate(() => document.fonts.ready);
    const h1Font = await page
      .locator("h1")
      .first()
      .evaluate((el) => getComputedStyle(el).fontFamily);
    expect(h1Font).toContain("Archivo");
    const codeFont = await page
      .locator(".terminal")
      .first()
      .evaluate((el) => getComputedStyle(el).fontFamily);
    expect(codeFont).toContain("Martian Mono");
    // Loaded family names (the Astro Fonts API hashes the family name)
    const loaded = await page.evaluate(() =>
      [...document.fonts].filter((f) => f.status === "loaded").map((f) => f.family),
    );
    expect(loaded.some((f) => f.startsWith("Archivo"))).toBe(true);
    expect(loaded.some((f) => f.includes("Martian Mono"))).toBe(true);
    await page.close();
  });

  it.each([
    ["light", accent.light, background.light],
    ["dark", accent.dark, background.dark],
  ] as const)(
    "follows the system color scheme (%s): vermilion accent + warm neutral body",
    async (scheme, expectedAccent, expectedBackground) => {
      const page = await browser.newPage({ colorScheme: scheme });
      const { violations } = observe(page);
      await page.goto(BASE, { waitUntil: "networkidle" });
      const tokens = await page.evaluate(() => {
        const style = getComputedStyle(document.documentElement);
        return {
          theme: document.documentElement.dataset["theme"],
          accent: style.getPropertyValue("--blume-accent").trim(),
          background: style.getPropertyValue("--blume-background").trim(),
        };
      });
      expect(tokens.theme).toBe(scheme);
      expect(tokens.accent.toLowerCase()).toBe(expectedAccent.toLowerCase());
      expect(tokens.background.toLowerCase()).toBe(expectedBackground.toLowerCase());
      // The generated theme.css (a mapping of apps/web/theme/maruhi.css)
      // carries the same value
      expect(themeCss.toLowerCase()).toContain(expectedAccent.toLowerCase());
      // CTA button background = accent (accent is used sparingly — one kind
      // of button)
      const cta = await page
        .locator(".button")
        .first()
        .evaluate((el) => getComputedStyle(el).backgroundColor);
      expect(cta).toBe(hexToRgb(expectedAccent));
      // The header logo shows the mode-appropriate SVG (light = the
      // original, dark = the generated one)
      const visibleLogo = await page
        .locator(`img[src="/logo${scheme === "dark" ? "-dark" : ""}.svg"]`)
        .first()
        .isVisible();
      expect(visibleLogo).toBe(true);
      expect(violations).toEqual([]);
      await page.close();
    },
  );

  it("toggles the theme and opens search without CSP violations or external requests", async () => {
    const page = await browser.newPage({ colorScheme: "dark" });
    const { requests, violations } = observe(page);
    await page.goto(BASE, { waitUntil: "networkidle" });
    // Blume's theme toggle (inserts a transition-suppression <style> via
    // JS — hash-allowed)
    await page.locator("[data-blume-theme-toggle]").first().click();
    await expect(page.evaluate(() => document.documentElement.dataset["theme"])).resolves.toBe(
      "light",
    );
    // Search (Orama — local index /blume-search.json)
    await page.locator("[data-blume-search-open]").first().click();
    const input = page.locator("[data-blume-search-input]").first();
    await input.fill("self-hosting");
    await page.locator("a[href='/docs/self-hosting']").first().waitFor({ timeout: 15_000 });
    expect(foreignOrigins(requests)).toEqual([]);
    expect(violations).toEqual([]);
    await page.close();
  });
});

describe("site e2e: docs (/docs — Blume default chrome)", () => {
  it("opens /docs and a nested page with zero external requests and zero CSP violations", async () => {
    const page = await browser.newPage();
    const { requests, violations } = observe(page);
    await page.goto(`${BASE}/docs`, { waitUntil: "networkidle" });
    await expect(page.locator("h1").first().textContent()).resolves.toContain("Documentation");
    // The docs index cards (MDX <Card href>) resolve to real routes
    // including basePath
    for (const target of [
      "/docs/getting-started",
      "/docs/deploy-targets",
      "/docs/github-actions",
      "/docs/self-hosting",
    ]) {
      await expect(page.locator(`a[data-blume-card][href='${target}']`).count()).resolves.toBe(1);
    }
    // A link from the body to the LP (site root) is an absolute URL not
    // rewritten by basePath
    await expect(page.locator("a[href='/docs/#access']").count()).resolves.toBe(0);
    await page.locator("a[data-blume-card][href='/docs/getting-started']").click();
    await page.locator("h1", { hasText: "Getting started" }).waitFor();
    expect(new URL(page.url()).pathname).toBe("/docs/getting-started");
    expect(foreignOrigins(requests)).toEqual([]);
    expect(violations).toEqual([]);
    // Shiki token colors and the chrome's inline style attributes have been
    // externalized to classes by postbuild.ts (the precondition for not
    // using 'unsafe-inline' in style-src-attr). Code blocks stay colored
    await expect(page.evaluate(() => document.querySelectorAll("[style]").length)).resolves.toBe(0);
    const tokenColor = await page
      .locator("pre code span[class*='sa-']")
      .first()
      .evaluate((el) => getComputedStyle(el).color);
    const bodyColor = await page.locator("body").evaluate((el) => getComputedStyle(el).color);
    expect(tokenColor).not.toBe(bodyColor);
    // No "Open in chat" to third-party AI (ai.openInChat: false)
    await expect(
      page.locator("a[href^='https://chatgpt.com'], a[href^='https://claude.ai']").count(),
    ).resolves.toBe(0);
    await page.close();
  });

  it("emits llms.txt and the sitemap with the apex origin, and no analytics", async () => {
    const llms = await (await fetch(`${BASE}/llms.txt`)).text();
    expect(llms).toContain("https://maruhi.app/docs/getting-started");
    expect(llms).toContain("https://maruhi.app/docs/deploy-targets");
    expect(llms).toContain("https://maruhi.app/docs/github-actions");
    expect(llms).toContain("https://maruhi.app/docs/environment-scopes");
    expect(llms).toContain("https://maruhi.app/docs/four-eyes");
    expect(llms).toContain("https://maruhi.app/docs/devices");
    const sitemap = await (await fetch(`${BASE}/sitemap.xml`)).text();
    expect(sitemap).toContain("<loc>https://maruhi.app/</loc>");
    expect(sitemap).toContain("<loc>https://maruhi.app/docs</loc>");
    const html = await (await fetch(`${BASE}/docs`)).text();
    expect(html).not.toMatch(/posthog|_vercel\/insights|plausible|googletagmanager/i);
  });
});

function hexToRgb(hex: string): string {
  const n = Number.parseInt(hex.slice(1), 16);
  return `rgb(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255})`;
}
