import { type ChildProcess, execFileSync, spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer } from "node:net";

import { type Browser, chromium, type Page } from "playwright";
import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";

import { writeWranglerConfig } from "../scripts/wrangler-config.ts";
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
        `wrangler dev did not exit within 10s of SIGTERM; sending SIGKILL\n--- wrangler dev output ---\n${wranglerOutput()}`,
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
  wranglerProcess = spawn(
    "bunx",
    ["wrangler", "dev", "--config", writeWranglerConfig(), "--port", String(port)],
    {
      cwd: import.meta.dirname + "/..",
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, CI: "1" },
    },
  );
  wranglerProcess.stdout?.on("data", (chunk: Buffer) => wranglerLogs.push(chunk.toString()));
  wranglerProcess.stderr?.on("data", (chunk: Buffer) => wranglerLogs.push(chunk.toString()));
  try {
    await waitForServer(BASE, 60_000);
  } catch (cause) {
    await stopWrangler(wranglerProcess);
    throw new Error(
      `wrangler dev did not become ready\n--- wrangler dev output ---\n${wranglerOutput()}`,
      {
        cause,
      },
    );
  }
  const executablePath = process.env["PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"];
  browser = await chromium.launch(executablePath ? { executablePath } : {});
});

afterAll(async () => {
  await browser?.close();
  await stopWrangler(wranglerProcess);
});

function observe(page: Page): { requests: string[]; violations: string[] } {
  const requests: string[] = [];
  const violations: string[] = [];
  page.on("request", (request) => requests.push(request.url()));
  page.on("console", (msg) => {
    if (msg.text().includes("Content Security Policy")) violations.push(msg.text());
  });
  return { requests, violations };
}

const styleAttributesIn = (html: string): number =>
  html
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>|<style\b[^>]*>[\s\S]*?<\/style>/g, "")
    .match(/\sstyle\s*=/g)?.length ?? 0;

const foreignOrigins = (requests: string[]): string[] =>
  [...new Set(requests.map((u) => new URL(u).origin))].filter(
    (origin) => origin !== new URL(BASE).origin,
  );

const brandCss = readFileSync(new URL("../src/styles/brand.css", import.meta.url), "utf8");

describe("site e2e: headers (Workers Static Assets — apps/site/cloudflare.config.ts)", () => {
  it("serves the landing page with a self-only CSP and security headers", async () => {
    const res = await fetch(BASE);
    expect(res.status).toBe(200);
    const csp = res.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("style-src 'self'");
    expect(csp).not.toContain("unsafe-inline");
    expect(csp).not.toContain("'unsafe-eval'");
    expect(csp).toContain("'wasm-unsafe-eval'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("referrer-policy")).toBe("no-referrer");
    expect(res.headers.get("strict-transport-security")).toContain("max-age=");
    expect(res.headers.get("x-powered-by")).toBeNull();
    expect(res.headers.get("link")).toContain("llms.txt");
  });

  it("keeps the charset rule for raw Markdown mirrors", async () => {
    const res = await fetch(`${BASE}/docs/getting-started/index.md`);
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

  it("normalizes trailing slashes to the site's link format and serves the 404 page", async () => {
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

describe("site e2e: landing page (custom page under strict CSP)", () => {
  it("loads with zero external requests and zero CSP violations", async () => {
    const page = await browser.newPage();
    const { requests, violations } = observe(page);
    await page.goto(BASE, { waitUntil: "networkidle" });
    await expect(page.locator("h1").first().textContent()).resolves.toContain("Not even us");
    expect(foreignOrigins(requests)).toEqual([]);
    expect(violations).toEqual([]);
    expect(requests.some((u) => u.endsWith(".woff2"))).toBe(true);
    expect(styleAttributesIn(await (await fetch(BASE)).text())).toBe(0);
    await page.close();
  });

  it("leaves the terminal samples as plain preformatted text (no aria-label on a generic role)", async () => {
    const page = await browser.newPage();
    await page.goto(BASE, { waitUntil: "networkidle" });
    const terminals = page.locator("pre.terminal");
    await expect(terminals.count()).resolves.toBeGreaterThan(1);
    await expect(
      terminals.evaluateAll((els) => els.filter((el) => el.hasAttribute("aria-label")).length),
    ).resolves.toBe(0);
    await page.close();
  });

  it.each([
    ["two-column", 1280],
    ["stacked", 390],
  ] as const)(
    "shows each step's text before its figure, matching the DOM order (%s)",
    async (_layout, width) => {
      const page = await browser.newPage({ viewport: { width, height: 900 } });
      await page.goto(BASE, { waitUntil: "networkidle" });
      const steps = await page.locator("ol.chain > li.step").evaluateAll((items) =>
        items.map((li) => {
          const [first, second] = [...li.children].map((el) => ({
            kind: el.classList[0],
            box: el.getBoundingClientRect(),
          }));
          return {
            id: li.id,
            order: [first?.kind, second?.kind],
            figureFollows:
              first !== undefined &&
              second !== undefined &&
              (second.box.left >= first.box.right || second.box.top >= first.box.bottom),
          };
        }),
      );
      expect(steps).toHaveLength(5);
      for (const step of steps) {
        expect(step.order, step.id).toEqual(["text", "figure"]);
        expect(step.figureFollows, step.id).toBe(true);
      }
      await page.close();
    },
  );

  it("keeps every figure label clear of the shapes and labels around it", async () => {
    const page = await browser.newPage();
    await page.goto(BASE, { waitUntil: "networkidle" });
    const martianLoaded = await page.evaluate(async () => {
      await document.fonts.ready;
      return [...document.fonts].some(
        (f) => f.family.startsWith("Martian Mono") && f.status === "loaded",
      );
    });
    expect(martianLoaded).toBe(true);
    for (const width of [320, 390, 737, 1280]) {
      await page.setViewportSize({ width, height: 900 });
      const clashes = await page.evaluate(() => {
        type Box = { x0: number; y0: number; x1: number; y1: number };
        const boxOf = (el: SVGGraphicsElement, grow = 0): Box => {
          const b = el.getBBox();
          return {
            x0: b.x - grow,
            y0: b.y - grow,
            x1: b.x + b.width + grow,
            y1: b.y + b.height + grow,
          };
        };
        const within = (a: Box, b: Box): boolean =>
          a.x0 >= b.x0 && a.x1 <= b.x1 && a.y0 >= b.y0 && a.y1 <= b.y1;
        const apart = (a: Box, b: Box): boolean =>
          a.x1 <= b.x0 || a.x0 >= b.x1 || a.y1 <= b.y0 || a.y0 >= b.y1;
        return [...document.querySelectorAll<SVGSVGElement>("svg.ill")].flatMap((svg) => {
          const at = svg.closest("li")?.id ?? "?";
          const { width: w, height: h } = svg.viewBox.baseVal;
          const view = { x0: 0, y0: 0, x1: w, y1: h };
          const rects = [...svg.querySelectorAll("rect")].map((rect) => {
            const half = Number.parseFloat(getComputedStyle(rect).strokeWidth) / 2;
            return { inner: boxOf(rect, -half), outer: boxOf(rect, half) };
          });
          const outlines = [...svg.querySelectorAll<SVGGeometryElement>("path, line, circle")].map(
            (shape) => {
              const half = Number.parseFloat(getComputedStyle(shape).strokeWidth) / 2;
              const length = shape.getTotalLength();
              const points = Array.from({ length: Math.ceil(length) + 1 }, (_, n) =>
                shape.getPointAtLength(Math.min(n, length)),
              );
              return { tag: shape.tagName, half, points };
            },
          );
          const labels = [...svg.querySelectorAll("text")].map((t) => ({
            name: `${at}: ${t.textContent}`,
            box: boxOf(t),
          }));
          return labels.flatMap(({ name, box }, i) => [
            ...(within(box, view) ? [] : [`${name} leaves the viewBox`]),
            ...rects
              .filter((r) => !within(box, r.inner) && !apart(box, r.outer))
              .map((r) => `${name} crosses the rect at ${r.outer.x0},${r.outer.y0}`),
            ...outlines
              .filter(({ half, points }) =>
                points.some(
                  (p) =>
                    p.x > box.x0 - half &&
                    p.x < box.x1 + half &&
                    p.y > box.y0 - half &&
                    p.y < box.y1 + half,
                ),
              )
              .map(
                ({ tag, points: [start] }) =>
                  `${name} crosses the ${tag} from ${start?.x},${start?.y}`,
              ),
            ...labels
              .slice(i + 1)
              .filter((other) => !apart(box, other.box))
              .map((other) => `${name} overlaps ${other.name}`),
          ]);
        });
      });
      expect(clashes, `${width}px`).toEqual([]);
    }
    await page.close();
  });

  it("keeps the space between text and the inline elements that follow a line break", async () => {
    const page = await browser.newPage();
    await page.goto(BASE, { waitUntil: "networkidle" });
    const footer = await page.locator("footer.footer").innerText();
    expect(footer).toContain("GitHub · Docs · License (FSL-1.1-MIT");
    expect(footer).toContain("Type set in Archivo and Martian Mono (SIL");
    const neighbors = await page.evaluate(() => {
      const isInline = (el: Element): boolean => getComputedStyle(el).display === "inline";
      const textOf = (node: Node | null): string =>
        node?.nodeType === Node.TEXT_NODE || (node instanceof Element && isInline(node))
          ? (node.textContent ?? "")
          : "";
      return [...document.querySelectorAll(".lp :is(a, b, code, em, span, strong)")]
        .filter((el) => el.closest("pre, svg") === null)
        .filter(isInline)
        .map((el) => [textOf(el.previousSibling), el.textContent ?? "", textOf(el.nextSibling)]);
    });
    const glued = neighbors.flatMap(([before = "", text = "", after = ""]) => [
      ...(/[\w.,;:!?)·]$/.test(before) ? [`${before.slice(-20)}|${text}`] : []),
      ...(/^[\w(]/.test(after) ? [`${text}|${after.slice(0, 20)}`] : []),
    ]);
    expect(glued).toEqual([]);
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
          mode: document.documentElement.dataset["mode"],
          accent: style.getPropertyValue("--nb-primary").trim(),
          background: style.getPropertyValue("--nb-background").trim(),
        };
      });
      expect(tokens.mode).toBe(scheme === "dark" ? "dark" : undefined);
      expect(tokens.accent.toLowerCase()).toBe(expectedAccent.toLowerCase());
      expect(tokens.background.toLowerCase()).toBe(expectedBackground.toLowerCase());
      expect(brandCss.toLowerCase()).toContain(expectedAccent.toLowerCase());
      const cta = await page
        .locator(".button")
        .first()
        .evaluate((el) => getComputedStyle(el).backgroundColor);
      expect(cta).toBe(hexToRgb(expectedAccent));
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
    await page.locator("[data-nb-theme-toggle]").first().click();
    await expect(page.evaluate(() => document.documentElement.dataset["mode"])).resolves.toBe(
      undefined,
    );
    await page.locator("[data-search-trigger]").first().click();
    const input = page.locator("[data-search-input]").first();
    await input.fill("self-hosting");
    await page
      .locator("[data-search-results] a[href*='/docs/self-hosting']")
      .first()
      .waitFor({ timeout: 15_000 });
    expect(foreignOrigins(requests)).toEqual([]);
    expect(violations).toEqual([]);
    await page.close();
  });
});

describe("site e2e: docs (/docs — Nimbus chrome)", () => {
  it("opens /docs and a nested page with zero external requests and zero CSP violations", async () => {
    const page = await browser.newPage();
    const { requests, violations } = observe(page);
    await page.goto(`${BASE}/docs`, { waitUntil: "networkidle" });
    await expect(page.locator("h1").first().textContent()).resolves.toContain("Documentation");
    for (const target of [
      "/docs/getting-started",
      "/docs/deploy-targets",
      "/docs/github-actions",
      "/docs/self-hosting",
    ]) {
      await expect(
        page.locator(`article a[href='${target}']`).count(),
      ).resolves.toBeGreaterThanOrEqual(1);
    }
    await expect(page.locator("a[href='/docs/#access']").count()).resolves.toBe(0);
    await expect(page.locator("[data-slot='banner'] a").first().getAttribute("href")).resolves.toBe(
      "https://maruhi.app/#access",
    );
    await page.locator("article a[href='/docs/getting-started']").first().click();
    await page.locator("h1", { hasText: "Getting started" }).waitFor();
    expect(new URL(page.url()).pathname).toBe("/docs/getting-started");
    expect(foreignOrigins(requests)).toEqual([]);
    expect(violations).toEqual([]);
    expect(styleAttributesIn(await (await fetch(`${BASE}/docs/getting-started`)).text())).toBe(0);
    const tokenColor = await page
      .locator("pre code span[class*='nb-shiki-']")
      .first()
      .evaluate((el) => getComputedStyle(el).color);
    const bodyColor = await page.locator("body").evaluate((el) => getComputedStyle(el).color);
    expect(tokenColor).not.toBe(bodyColor);
    await expect(
      page.locator("a[href^='https://chatgpt.com'], a[href^='https://claude.ai']").count(),
    ).resolves.toBe(0);
    await page.close();
  });

  it("emits llms.txt and the sitemap with the apex origin, and no analytics", async () => {
    const llms = await (await fetch(`${BASE}/llms.txt`)).text();
    expect(llms).toContain("https://maruhi.app/docs/llms.txt");
    const docsLlms = await (await fetch(`${BASE}/docs/llms.txt`)).text();
    for (const slug of [
      "getting-started",
      "deploy-targets",
      "github-actions",
      "environment-scopes",
      "four-eyes",
      "devices",
      "value-history",
      "rotation",
    ]) {
      expect(docsLlms).toContain(`https://maruhi.app/docs/${slug}/index.md`);
    }
    const sitemap = await (await fetch(`${BASE}/sitemap-0.xml`)).text();
    expect(sitemap).toContain("<loc>https://maruhi.app/</loc>");
    expect(sitemap).toContain("<loc>https://maruhi.app/docs/</loc>");
    const html = await (await fetch(`${BASE}/docs`)).text();
    expect(html).not.toMatch(/posthog|_vercel\/insights|plausible|googletagmanager/i);
  });
});

describe("site e2e: docs last-modified dates (git author date)", () => {
  it("shows the page's last git commit date in the page actions and the sitemap", async () => {
    const committed = execFileSync(
      "git",
      ["log", "-1", "--format=%aI", "--", "src/content/docs/getting-started.mdx"],
      { cwd: `${import.meta.dirname}/..`, encoding: "utf8" },
    ).trim();
    expect(committed).not.toBe("");
    const iso = new Date(committed).toISOString();
    const html = await (await fetch(`${BASE}/docs/getting-started`)).text();
    expect(html).toContain(`<time datetime="${iso}">`);
    expect(html).toContain(`"dateModified":"${iso}"`);
    const sitemap = await (await fetch(`${BASE}/sitemap-0.xml`)).text();
    expect(sitemap).toContain(
      `<loc>https://maruhi.app/docs/getting-started/</loc><lastmod>${iso}</lastmod>`,
    );
  });
});

describe("site e2e: related pages and the footer copyright", () => {
  it("shows a docs page's related cards and the copyright in the docs footer", async () => {
    const html = await (await fetch(`${BASE}/docs/getting-started`)).text();
    const related = /<nav[^>]*data-site-related[^>]*>([\s\S]*?)<\/nav>/.exec(html)?.[1] ?? "";
    expect([...related.matchAll(/href="(\/docs\/[a-z-]+)"/g)].map((m) => m[1])).toEqual([
      "/docs/deploy-targets",
      "/docs/devices",
      "/docs/invite-a-teammate",
      "/docs/linux-keychain",
    ]);
    expect(html).toMatch(/<footer[^>]*data-site-footer[\s\S]*© 2026 maruhi contributors/);
  });

  it("prints the copyright once in the landing page's own footer, with no second footer", async () => {
    const html = await (await fetch(`${BASE}/`)).text();
    expect(html.match(/<footer\b/g)).toHaveLength(1);
    expect(html).not.toContain("data-site-footer");
    expect(html.match(/© 2026 maruhi contributors/g)).toHaveLength(1);
  });
});

function hexToRgb(hex: string): string {
  const n = Number.parseInt(hex.slice(1), 16);
  return `rgb(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255})`;
}
