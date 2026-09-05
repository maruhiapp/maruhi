// apex サイト(LP + docs — Blume)の e2e。ビルド済み dist(+ scripts/postbuild.ts の
// _headers)を **本番と同じ wrangler 設定**(apps/site/wrangler.jsonc — Workers Static Assets のみ)
// で配信し、Playwright(Chromium)で次を固定する(docs/notes/web-design-pass.md §4 の検証項目):
//   1. 全リクエストが同一オリジン(外部への通信ゼロ — 「言わざる」)
//   2. CSP 違反ゼロ、`script-src 'self'` / `style-src 'self'` 基調で 'unsafe-inline' なし
//   3. フォントは自己配信(Archivo / Martian Mono が実際に適用され、OFL 全文が /fonts/ から読める)
//   4. 朱の accent が light / dark(システム追従)で DP1 のテーマ値と一致する
//   5. `/docs` が開き、末尾スラッシュの正規化と 404 が wrangler.jsonc の設定どおり
// 事前に `bun run build` が必要。
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
      // まだ起動していない
    }
    if (Date.now() > deadline) throw new Error(`server at ${url} did not start`);
    await new Promise((r) => setTimeout(r, 500));
  }
}

// apps/web/test/e2e.test.ts と同じ停止手順(SIGTERM → 10 秒で SIGKILL、パイプは無条件に閉じる)
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
  browser = await chromium.launch();
});

afterAll(async () => {
  await browser?.close();
  await stopWrangler(wranglerProcess);
});

/** ページが発した全リクエストの URL と CSP 違反を収集する。 */
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
    // Blume が出した _headers(トップの Link ヘッダー)は postbuild.ts が保持する
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
    // フォントは自己配信の woff2 が実際に取得される
    expect(requests.some((u) => u.endsWith(".woff2"))).toBe(true);
    // インライン style 属性・外部 stylesheet なし(style-src 'self' + Astro Fonts のハッシュのみ)
    const inlineStyleAttrs = await page.evaluate(() => document.querySelectorAll("[style]").length);
    expect(inlineStyleAttrs).toBe(0);
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
    // 読み込まれた書体名(Astro Fonts API は family 名にハッシュを付ける)
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
      // 生成 theme.css(apps/web/theme/maruhi.css の写像)に同じ値がある
      expect(themeCss.toLowerCase()).toContain(expectedAccent.toLowerCase());
      // CTA ボタンの背景 = accent(アクセントは限定的に — ボタン 1 種)
      const cta = await page
        .locator(".button")
        .first()
        .evaluate((el) => getComputedStyle(el).backgroundColor);
      expect(cta).toBe(hexToRgb(expectedAccent));
      // ヘッダーのロゴはモードに応じた SVG(light = 原本、dark = 生成物)が見える
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
    // Blume のテーマトグル(遷移抑制 <style> を JS で挿す — ハッシュ許可済み)
    await page.locator("[data-blume-theme-toggle]").first().click();
    await expect(page.evaluate(() => document.documentElement.dataset["theme"])).resolves.toBe(
      "light",
    );
    // 検索(Orama — ローカル索引 /blume-search.json)
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
    // docs index のカード(MDX の <Card href>)は basePath 込みの実ルートへ解決される(pullfrog 指摘の固定)
    for (const target of ["/docs/getting-started", "/docs/deploy-targets", "/docs/self-hosting"]) {
      await expect(page.locator(`a[data-blume-card][href='${target}']`).count()).resolves.toBe(1);
    }
    // 本文から LP(サイトルート)へのリンクは basePath の書き換えを受けない絶対 URL
    await expect(page.locator("a[href='/docs/#access']").count()).resolves.toBe(0);
    await page.locator("a[data-blume-card][href='/docs/getting-started']").click();
    await page.locator("h1", { hasText: "Getting started" }).waitFor();
    expect(new URL(page.url()).pathname).toBe("/docs/getting-started");
    expect(foreignOrigins(requests)).toEqual([]);
    expect(violations).toEqual([]);
    // Shiki のトークン色・chrome の inline style 属性は postbuild.ts がクラスへ外部化している
    // (style-src-attr に 'unsafe-inline' を使わないための前提)。コードブロックは着色されたまま
    await expect(page.evaluate(() => document.querySelectorAll("[style]").length)).resolves.toBe(0);
    const tokenColor = await page
      .locator("pre code span[class*='sa-']")
      .first()
      .evaluate((el) => getComputedStyle(el).color);
    const bodyColor = await page.locator("body").evaluate((el) => getComputedStyle(el).color);
    expect(tokenColor).not.toBe(bodyColor);
    // 第三者 AI への「Open in chat」は置かない(ai.openInChat: false)
    await expect(
      page.locator("a[href^='https://chatgpt.com'], a[href^='https://claude.ai']").count(),
    ).resolves.toBe(0);
    await page.close();
  });

  it("emits llms.txt and the sitemap with the apex origin, and no analytics", async () => {
    const llms = await (await fetch(`${BASE}/llms.txt`)).text();
    expect(llms).toContain("https://maruhi.app/docs/getting-started");
    expect(llms).toContain("https://maruhi.app/docs/deploy-targets");
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
