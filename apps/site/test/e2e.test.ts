// e2e for the apex site (LP + docs — Blume). The built dist (+
// scripts/postbuild.ts's _headers) is served under **the same cf
// config as production** (apps/site/cloudflare.config.ts — Workers Static
// Assets only), and Playwright (Chromium) pins the following (the
// verification items of docs/notes/web-design-pass.md §4):
//   1. all requests same-origin (zero outbound traffic — "say nothing")
//   2. zero CSP violations; `script-src 'self'` / `style-src 'self'`
//      baseline with no 'unsafe-inline'
//   3. fonts are self-hosted (Archivo / Martian Mono actually apply, and
//      the full OFL texts are readable from /fonts/)
//   4. the vermilion accent matches DP1's theme values in light / dark
//      (system-following)
//   5. `/docs` opens, and trailing-slash normalization plus the 404 behave
//      as cloudflare.config.ts configures
// Requires `bun run build` beforehand.
import { type ChildProcess, execFileSync, spawn } from "node:child_process";
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
    throw new Error(`cf dev did not become ready\n--- cf dev output ---\n${wranglerOutput()}`, {
      cause,
    });
  }
  // CI and Cursor Cloud (the SHA-256-verified headless shell from
  // scripts/install-headless-shell.sh) and Claude Code on the web (its
  // preinstalled build) pass the browser's path via
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

describe("site e2e: headers (Workers Static Assets — apps/site/cloudflare.config.ts)", () => {
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
    // blume.config.ts `poweredBy: false`: the build stack is not advertised
    expect(res.headers.get("x-powered-by")).toBeNull();
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

  it.each([
    ["two-column", 1280],
    ["stacked", 390],
  ] as const)(
    "shows each step's text before its figure, matching the DOM order (%s)",
    async (_layout, width) => {
      // A screen reader reads the DOM (text, then figure); a sighted reader
      // must meet the same order: the figure sits right of the text or below
      // it, never left of or above it
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
    // A label sits wholly inside or wholly outside each rect (frames and
    // masks), no other outline (paths, lines, circles) passes through it, it
    // overlaps no other label, and it stays in the viewBox. Widths: the
    // narrowest phone, the stacked and two-column layouts, and the narrowest
    // two-column figure (just above the 46rem breakpoint)
    const page = await browser.newPage();
    await page.goto(BASE, { waitUntil: "networkidle" });
    // The layouts are measured in Martian Mono; a fallback face is narrower
    // and would pass unnoticed
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
          // Each outline sampled once per unit of length, padded by its stroke
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
    // Astro 7's `compressHTML: "jsx"` drops a line break between text and an
    // element, so the source writes `{" "}` there (pages/index.astro). A
    // missing one renders glued words such as "Docs ·License"
    const page = await browser.newPage();
    await page.goto(BASE, { waitUntil: "networkidle" });
    const footer = await page.locator("footer.footer").innerText();
    expect(footer).toContain("GitHub · Docs · License (FSL-1.1-MIT");
    expect(footer).toContain("Type set in Archivo and Martian Mono (SIL");
    // Every rendered inline element outside the terminal samples is
    // separated from the neighboring text or inline element (`</a><a>` counts
    // as glued). Block and grid children are exempt on either side — the
    // layout separates them
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
    // ...and so is the banner's link to the LP's access section
    await expect(page.locator("[data-blume-banner] a").first().getAttribute("href")).resolves.toBe(
      "https://maruhi.app/#access",
    );
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
    expect(llms).toContain("https://maruhi.app/docs/value-history");
    expect(llms).toContain("https://maruhi.app/docs/rotation");
    const sitemap = await (await fetch(`${BASE}/sitemap.xml`)).text();
    expect(sitemap).toContain("<loc>https://maruhi.app/</loc>");
    expect(sitemap).toContain("<loc>https://maruhi.app/docs</loc>");
    const html = await (await fetch(`${BASE}/docs`)).text();
    expect(html).not.toMatch(/posthog|_vercel\/insights|plausible|googletagmanager/i);
    // blume.config.ts `feedback: false`: no widget whose only channel is analytics
    expect(html).not.toContain("data-blume-page-feedback");
  });
});

describe('site e2e: docs last-modified dates (blume.config.ts `lastModified: "git"`)', () => {
  it("shows the page's last git commit date and emits it as schema.org dateModified", async () => {
    // The committer date of the newest commit touching the page, as Blume
    // reads it. Needs full history (CI's check job uses fetch-depth: 0); a
    // shallow clone would date every page at the boundary commit
    const committed = execFileSync(
      "git",
      ["log", "-1", "--format=%cI", "--", "docs/getting-started.mdx"],
      { cwd: `${import.meta.dirname}/..`, encoding: "utf8" },
    ).trim();
    expect(committed).not.toBe("");
    const iso = new Date(committed).toISOString();
    const html = await (await fetch(`${BASE}/docs/getting-started`)).text();
    expect(html).toMatch(new RegExp(`Last updated on <time datetime="${iso}">`));
    const graphs = [
      ...html.matchAll(/<script type="application\/ld\+json"[^>]*>(.*?)<\/script>/gs),
    ].map((match) => JSON.stringify(JSON.parse(match[1] ?? "null")));
    expect(graphs.some((graph) => graph.includes(`"dateModified":"${iso}"`))).toBe(true);
    const sitemap = await (await fetch(`${BASE}/sitemap.xml`)).text();
    expect(sitemap).toContain(
      `<loc>https://maruhi.app/docs/getting-started</loc><lastmod>${iso.slice(0, 10)}</lastmod>`,
    );
  });
});

describe("site e2e: related pages and the footer copyright", () => {
  it("shows a docs page's related cards and the copyright in Blume's footer", async () => {
    const html = await (await fetch(`${BASE}/docs/getting-started`)).text();
    const related = /<nav[^>]*data-blume-related[^>]*>([\s\S]*?)<\/nav>/.exec(html)?.[1] ?? "";
    // The order and targets of apps/site/docs/getting-started.mdx `related:`
    expect([...related.matchAll(/href="(\/docs\/[a-z-]+)"/g)].map((m) => m[1])).toEqual([
      "/docs/deploy-targets",
      "/docs/devices",
      "/docs/invite-a-teammate",
      "/docs/linux-keychain",
    ]);
    expect(html).toMatch(/<footer[^>]*data-blume-footer[\s\S]*© 2026 maruhi contributors/);
  });

  it("prints the copyright once in the landing page's own footer, with no second footer", async () => {
    const html = await (await fetch(`${BASE}/`)).text();
    expect(html.match(/<footer\b/g)).toHaveLength(1);
    expect(html).not.toContain("data-blume-footer");
    expect(html.match(/© 2026 maruhi contributors/g)).toHaveLength(1);
  });
});

function hexToRgb(hex: string): string {
  const n = Number.parseInt(hex.slice(1), 16);
  return `rgb(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255})`;
}
