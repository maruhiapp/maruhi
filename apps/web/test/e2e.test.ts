// スパイク A の e2e 検証。ビルド済み dist/public を wrangler dev(Workers Static Assets)で
// 配信し、Playwright(Chromium)で以下を検証する:
//   1. 静的シェル(ビルド時 RSC)の配信と hydrate
//   2. 厳格 CSP(script-src 'self' / style-src 'self')下での全機能動作
//   3. SPA ナビゲーション(Navigation API)と、非対応ブラウザ相当での MPA 劣化
//   4. Astryx プリビルド CSS + maruhi テーマ + xstyle(StyleX コンパイラあり)の適用
// 事前に `bun run build` が必要。
import { type ChildProcess, spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer } from "node:net";

import { type Browser, chromium } from "playwright";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

// ポートは固定せず OS に空きを割り当てさせる(CI の並列実行でも衝突しない)
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

// wrangler の出力は捨てず(stdio: "ignore" だと手がかりが一切残らない)バッファへ
// 取り、①起動待ちが 60 秒で失敗したとき ②SIGTERM が 10 秒で効かなかったときに
// 表示する(ステップの timeout-minutes に達した場合はランナーがプロセスごと
// 落とすため表示されない — その手前の 2 経路で拾うのが目的)
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

// SIGTERM で終了しない場合に SIGKILL へフォールバックする。SIGTERM のみだと
// wrangler が残留したとき vitest プロセスが終了できず、CI がステップではなく
// ジョブ上限(30 分)までハングした実績がある(2026-08-19 run 32217317312)
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
    // パイプの読み口を無条件に閉じる: wrangler の子孫が書き口を握ったまま
    // 生き残ると EOF が来ず、ref 付き handle が vitest の終了を妨げる
    // (stdio をパイプ化したことで生じる新たなハング経路 — レビュー指摘)。
    // wrangler 自身が先に死んで子孫だけ残るケースも踏むため早期 return 側も通す
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
  // ブラウザのダウンロードができない環境(Claude Code on the web 等)では、
  // プリインストール Chromium のパスを PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH で受け取る
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
    // 静的シェル: RSC 由来の本文はペイロード側にあり、シェルにはマウントポイントのみ
    expect(html).toContain('<div id="app">');
    expect(html).toContain("fun__rsc-payload");
  });

  it("hydrates under strict CSP: build-time RSC content + working client island", async () => {
    const page = await browser.newPage();
    const violations: string[] = [];
    page.on("console", (msg) => {
      if (msg.text().includes("Content Security Policy")) violations.push(msg.text());
    });
    await page.goto(BASE, { waitUntil: "networkidle" });

    // ビルド時 RSC: サーバーコンポーネントが埋めたビルド時刻が表示される
    await expect(page.getByTestId("built-at").textContent()).resolves.toMatch(
      /server-rendered at build time: 20\d\d-/,
    );

    // クライアント島が hydrate され、CSP 下でインタラクションが動く
    const button = page.getByTestId("counter-button");
    await expect(button.textContent()).resolves.toContain("count: 0");
    await button.click();
    await expect(button.textContent()).resolves.toContain("count: 1");

    // xstyle(StyleX コンパイラ経由の静的 CSS)が適用されている
    const marginTop = await button.evaluate((el) => getComputedStyle(el).marginTop);
    expect(marginTop).toBe("20px");

    // maruhi テーマ(defineTheme → astryx theme build)のアクセント色が効いている。
    // 検証知見: defineTheme の color.accent は HCT でパレット導出されるため、
    // 最終的な --color-accent は指定 hex(#C73E3A)そのものではなく導出値になる。
    // ここでは「Astryx デフォルト(#0064E0)から変わっていること」と
    // 「生成 CSS(theme/maruhi.css)の値と一致すること」を確認する。
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
    // フルリロードで消えるマーカーを置く
    await page.evaluate(() => {
      (window as unknown as Record<string, unknown>)["__spike_marker"] = "alive";
    });
    await page.getByTestId("to-about").click();
    await page.getByTestId("about-heading").waitFor();
    const marker = await page.evaluate(
      () => (window as unknown as Record<string, unknown>)["__spike_marker"],
    );
    expect(marker).toBe("alive"); // SPA 遷移(ページは破棄されていない)
    await page.close();
  });

  it("degrades to MPA (full page loads) when Navigation API is unavailable", async () => {
    const page = await browser.newPage();
    // Navigation API 非対応ブラウザを再現(スクリプト実行前に window.navigation を消す)
    await page.addInitScript(() => {
      // @ts-expect-error 検証用の意図的な削除
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
    expect(marker).toBeUndefined(); // フルページロード = MPA 劣化(fallback="static")
    // 劣化後もページ内容自体は SPA フォールバック(not_found_handling)で表示される
    await expect(page.getByTestId("about-heading").textContent()).resolves.toBe("about maruhi");
    await page.close();
  });
});
