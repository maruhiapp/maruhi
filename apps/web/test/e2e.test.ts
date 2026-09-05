// e2e 検証(スパイク A 起源)。ビルド済み dist/public を **combined 構成
// (apps/server の wrangler dev — 本番と同じ maruhi-server が Workers Static
// Assets として配信する形。裁定 BM/BT — docs/notes/session-43.md)**で配信し、
// Playwright(Chromium)で以下を検証する:
//   1. 静的シェル(ビルド時 RSC)の配信と hydrate
//   2. 厳格 CSP(script-src 'self' / style-src 'self')下での全機能動作
//   3. SPA ナビゲーション(Navigation API)と、非対応ブラウザ相当での MPA 劣化
//   4. Astryx プリビルド CSS + maruhi テーマ + xstyle(StyleX コンパイラあり)の適用
//   5. 配信トポロジ(run_worker_first の API 到達・SPA フォールバック・
//      per-path ヘッダー)を**デプロイされる実構成**に対して固定する(裁定 BT。
//      preview も同じ構成を使い、wrangler 設定は apps/server の 1 本のみ — 裁定 BX)
// 事前に `bun run build` が必要。API はテスト内で page.route によりモックする
// (裁定 BS)ため、ローカルサーバーの D1 / OAuth 設定は不要(素の 401 / 503 応答
// 自体が「Worker に届いた」ことの検証材料になる)。
import { type ChildProcess, spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer } from "node:net";

import {
  AuditEventSchema,
  ChainSnapshotSchema,
  CSRF_HEADER_NAME,
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
  environmentsFixture,
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
  // combined 構成(裁定 BT): 本番にデプロイされるのは apps/server/wrangler.jsonc
  // (assets 同梱)であり、e2e はそれ自体を配信系として起動する
  wranglerProcess = spawn("bunx", ["wrangler", "dev", "--port", String(port)], {
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
    // 機構検証フック(built-at / counter)は /about(「このデプロイについて」)に置く
    // (DP2 裁定 F — docs/notes/web-design-pass.md §4。トップは最小の案内ページ)
    await page.goto(`${BASE}/about`, { waitUntil: "networkidle" });

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

  // /invite(AUTH_SPEC §15-3 / ADR-0018 改訂 2・5 項): SPA 外の独立静的アセット +
  // per-path CSP `script-src 'none'`。「スクリプトを一切持たない・フラグメントを
  // 解釈しない」を実配信(wrangler dev)に対して固定する
  it("serves /invite as a script-free static page with per-path CSP script-src 'none'", async () => {
    const res = await fetch(`${BASE}/invite`);
    expect(res.status).toBe(200);
    const csp = res.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("script-src 'none'");
    // スタイルとロゴは自己配信のみ(DP4 — /theme.css + /pages.css + ロゴ SVG)
    expect(csp).toContain("style-src 'self'");
    expect(csp).toContain("img-src 'self'");
    expect(csp).not.toContain("unsafe-inline");
    // SPA の CSP('self' + ブートストラップハッシュ許可)がデタッチされ、
    // 2 本目の CSP として残っていないこと
    expect(csp).not.toContain("'self' 'sha256-");
    expect(csp).not.toContain("script-src 'self'");
    // /* の他セキュリティヘッダーは /invite にも引き続き付く
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("referrer-policy")).toBe("no-referrer");
    const html = await res.text();
    expect(html.toLowerCase()).not.toContain("<script");
    expect(html).toContain("maruhi invite accept");
    // 配信バイト内蔵の meta CSP(配信層のヘッダーと独立の二重強制)
    expect(html).toMatch(
      /<meta\s+http-equiv="Content-Security-Policy"\s+content="[^"]*script-src 'none'/i,
    );
  });

  it("normalizes near-miss paths to the canonical /invite (link format §15-3)", async () => {
    // _redirects による正規化(301): 大小変種 × 任意の末尾続きのクラス全体
    // (フラグメントはブラウザがリダイレクト越しに保持する)
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
    // 200 リライトの盾: 正規パスは /invite* の総取りに飲まれず素通しされる
    // (盾が落ちてループ化したら /invite の 3xx でここが検知する)
    const inviteRes = await fetch(`${BASE}/invite`, { redirect: "manual" });
    expect(inviteRes.status).toBe(200);
  });

  // スクリプトなしページの共有アセット(DP4 — docs/notes/web-design-pass.md §5):
  // /invite とサーバー配信の儀式ページ(apps/server/src/auth.package/cli-pages.ts)が
  // 参照する /theme.css(apps/web/theme/maruhi.css の無変換同梱)と /pages.css が、
  // 本番と同じ combined 構成で正しい content-type で届き、配信バイトがソースと一致すること
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
    // 名前固定の CSS の更新反映: Workers Static Assets の既定は毎回の再検証
    // (max-age=0, must-revalidate + ETag)なので、Worker 応答(no-store)の HTML が
    // 参照する固定名 CSS もデプロイ直後の読み込みで新版に切り替わる(DP4 裁定 G —
    // URL のバージョン付けを持たない根拠。既定が変わったらここで気付く)
    for (const res of [theme, pages]) {
      expect(res.headers.get("cache-control")).toContain("must-revalidate");
      expect(res.headers.get("etag")).not.toBeNull();
    }
  });

  // サーバー配信の儀式ページが実配信で共有スタイルを受けること。到達点は一様エラー
  // ページ(`GET /auth/cli/verify` の捏造 flow — 未設定サーバーでも同じページを返す。
  // AUTH_SPEC §4-2)。承認ページ本体は OAuth を要するためサーバー側テスト
  // (apps/server/test/auth.test.ts)が同じ page() の出力を検査する
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
    // /pages.css の枠(40rem)と /theme.css のトークン(body の背景色)が両方効いている
    const maxWidth = await page.locator(".page").evaluate((el) => getComputedStyle(el).maxWidth);
    expect(maxWidth).toBe("640px");
    const background = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    expect(background).not.toBe("rgba(0, 0, 0, 0)");
    // 太さの回帰(pullfrog レビュー反映): 初版は未定義トークンの var() で font-weight が
    // 無言に落ち、h1 と強調文が normal になっていた。h1 と outcome 行が太字であること
    for (const selector of ["h1", ".outcome"]) {
      const weight = await page.locator(selector).evaluate((el) => getComputedStyle(el).fontWeight);
      expect(weight, selector).toBe("700");
    }
    // ロゴ(自己配信 SVG)が img-src 'self' 下で読めている
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
    // フラグメントは §15-3 のリンク形式を模したダミー(サーバーへは送信されない)
    await page.goto(`${BASE}/invite#v=1&t=dummy-invite-token&p=dummy-project&r=member`, {
      waitUntil: "networkidle",
    });
    await expect(page.locator("h1").textContent()).resolves.toContain("maruhi");
    // スクリプトゼロ(<script> 要素が DOM に一切ない)
    await expect(page.evaluate(() => document.scripts.length)).resolves.toBe(0);
    // スタイルシート(自己配信 /pages.css)が CSP 下で適用されている
    const maxWidth = await page.locator(".page").evaluate((el) => getComputedStyle(el).maxWidth);
    expect(maxWidth).toBe("640px"); // 40rem
    expect(violations).toEqual([]);
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

// ---------------------------------------------------------------------------
// W2: 読み取りダッシュボード(S3〜S7)の e2e(裁定 BS — docs/notes/session-43.md)。
// 配信・実描画・CSP は実物(wrangler dev + Chromium)のまま、API 応答だけを
// Playwright の page.route で差し替える(同一オリジンのままなので
// connect-src 'self' の検証を弱めない)。フィクスチャは api-schema 由来の型
// (src/dashboard/types.ts)に適合するリテラルで、乖離は tsc が検出する。
// ---------------------------------------------------------------------------

function fulfillJson(route: Route, status: number, body: unknown): Promise<void> {
  return route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
}

/** 401(未認証)を返すハンドラ(Unauthorized — api-schema のワイヤ形)。 */
function unauthorized(route: Route): Promise<void> {
  return fulfillJson(route, 401, { _tag: "Unauthorized" });
}

/**
 * セッション確認のモック。DP3 のアプリシェル(DashboardShell)は認証が要る全画面で
 * `GET /auth/me` を 1 回呼び、ok のときだけ本文を描く — 実サーバーの 401 応答は
 * ボディ未読のまま networkidle を妨げるため、認証済み画面のテストはすべてこれを登録する
 */
async function routeSession(page: Page): Promise<void> {
  await page.route("**/auth/me", (route) => fulfillJson(route, 200, meFixture));
}

/**
 * プロジェクト画面の初期表示(Overview タブ)の消費面のモック(W3b の S8 テストで
 * 共用)。
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
 * 失効の確認(DP3 改訂 4 — 裁定 CO のインライン 2 段階から AlertDialog へ)。行の Revoke で
 * モーダルが開き、その中の Revoke で DELETE が飛ぶ。
 */
async function confirmRevoke(page: Page): Promise<void> {
  const dialog = page.getByRole("alertdialog");
  await dialog.waitFor();
  await dialog.getByRole("button", { name: "Revoke", exact: true }).click();
}

/** ダッシュボード用の CSP violation 収集(既存テストと同じ検出方法)。 */
/** プロジェクト画面の tabpanel の computed `display`(非選択は `none`)。 */
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

describe("web e2e: serving topology (W2 裁定 BM/BT — combined worker)", () => {
  it("routes API paths to the worker, not the asset layer", async () => {
    // run_worker_first の実効(navigation 吸収の遮断)をデプロイされる実構成で
    // 固定する。未設定ローカルサーバーの素の応答(503 / 401 の JSON)自体が
    // 「Worker に届いた」証拠 — SPA シェル(200 text/html)に飲まれていない
    const config = await fetch(`${BASE}/auth/config`);
    // CI = 未設定サーバーの 503 SetupIncomplete。開発者ローカルの .dev.vars が
    // ある場合は 200 — どちらも JSON = Worker の応答(SPA シェルの 200 html でない)
    expect([200, 503]).toContain(config.status);
    expect(config.headers.get("content-type") ?? "").toContain("application/json");
    const projects = await fetch(`${BASE}/projects`);
    expect(projects.status).toBe(401);
    expect(projects.headers.get("content-type") ?? "").toContain("application/json");
  });

  it("does not let the /invite* redirect catch-all swallow POST /invites/accept", async () => {
    // session-43 §9 の欠陥修正の回帰テスト: 列挙漏れ時は _redirects の小文字
    // 総取りが受諾 POST を 301 → /invite で飲む(実測で確認した壊れ方)
    const res = await fetch(`${BASE}/invites/accept`, { method: "POST", redirect: "manual" });
    expect(res.status).toBe(401); // 未認証の Worker 応答(301 ではない)
  });
});

describe("web e2e: read dashboard (W2 — S3〜S7, mocked API via page.route)", () => {
  it("keeps every mocked fixture wire-valid against the api-schema contracts (裁定 BV)", () => {
    // 型適合(tsc)は hex 長・パターン等の実行時制約を見ない。フィクスチャを
    // 実 Schema でデコードし、モックとワイヤ契約の漂流を機械検査にする
    // (Schema の実行コードはテストプロセスのみで動き、バンドルには入らない)
    Schema.decodeUnknownSync(MeSchema)(meFixture);
    for (const page of [projectsPage1, projectsPageEmpty, projectsPage2]) {
      Schema.decodeUnknownSync(ProjectListSchema)(page);
    }
    Schema.decodeUnknownSync(ChainSnapshotSchema)(chainFixture);
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
  });

  it("serves /dashboard routes with the strict SPA CSP header", async () => {
    // violation ゼロの検査(下の各テスト)は「CSP ヘッダーが無い」場合も通って
    // しまうため、ヘッダーの実在を直接固定する(pullfrog レビュー反映)。
    // SPA フォールバック経由の深いパスにも /* の CSP が付くこと
    for (const path of [
      "/dashboard",
      `/dashboard/projects/${PROJECT_1}`,
      "/dashboard/account",
      "/dashboard/tokens",
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
    // 1 ページ目: admin の 1 行 + Load more(nextAfter あり)
    await expect(page.getByText(PROJECT_1).count()).resolves.toBeGreaterThan(0);
    // Load more は途中の空ページ(nextAfter 付き)を終端と誤断せず追跡する
    await page.getByTestId("load-more-projects").click();
    await page.getByText(PROJECT_2).waitFor();
    // 2 ページ目に nextAfter がないので Load more は消える
    await expect(page.getByTestId("load-more-projects").count()).resolves.toBe(0);
    // role はサーバー申告値の Token 表示
    await expect(page.getByText("admin", { exact: true }).count()).resolves.toBeGreaterThan(0);
    await expect(page.getByText("reader", { exact: true }).count()).resolves.toBeGreaterThan(0);

    // ログアウト(POST + x-maruhi-csrf: 1 — AUTH_SPEC §11-4)
    await page.getByTestId("sign-out").click();
    await page.getByTestId("login-card").waitFor();
    expect(sawCsrfHeader).toBe("1");
    await expect(page.getByText("You are signed out.").count()).resolves.toBeGreaterThan(0);
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

    // Astryx 0.5: 同一画面内パネル切替は WAI-ARIA tabs(nav landmark ではない)
    await expect(page.getByRole("tablist", { name: "Project" }).count()).resolves.toBe(1);
    await expect(
      page.getByRole("tab", { name: "Overview" }).getAttribute("aria-selected"),
    ).resolves.toBe("true");
    await expect(
      page.getByRole("tab", { name: "Audit" }).getAttribute("aria-controls"),
    ).resolves.toBe("project-panel-audit");
    // tabpanel は対応する tab から名前を取る(APG)
    await expect(
      page.locator("#project-panel-audit").getAttribute("aria-labelledby"),
    ).resolves.toBe(await page.getByRole("tab", { name: "Audit" }).getAttribute("id"));
    // 非選択パネルは空(高さ 0)なので isVisible() では `display` の上書き負けを
    // 検知できない。computed display を直接固定する(pullfrog レビュー反映)
    await expect(panelDisplay(page, "overview")).resolves.toBe("flex");
    await expect(panelDisplay(page, "audit")).resolves.toBe("none");
    await expect(page.getByRole("tabpanel").count()).resolves.toBe(1);

    // S5 概要: チェーン導出メンバー(サーバー申告)+ 環境 + 変数名(メタのみ pull)
    await page.getByTestId("member-table").waitFor();
    await expect(page.getByText("user_colleague").count()).resolves.toBeGreaterThan(0);
    await page.getByTestId("env-table").waitFor();
    await page.getByText("Variable names", { exact: true }).click();
    await page.getByTestId("variable-list").waitFor();
    await expect(page.getByText("DATABASE_URL").count()).resolves.toBeGreaterThan(0);

    // S6 監査: 規定文言 + admin 応答由来の seq 列(応答適応)
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
    // DP3 改訂 5: 1 列の行 + その場で展開(Collapsible)。seq は admin 応答にだけ載り、
    // 行の右端に "seq N" として出る(応答適応)
    await expect(page.getByText("seq 2", { exact: true }).count()).resolves.toBe(1);
    await expect(page.getByText("chain.member_added").count()).resolves.toBeGreaterThan(0);
    // 行(トリガー = button)を開くとその直下に全フィールド(MetadataList)が出る。
    // 閉じた展開部は DOM に残る(hidden)ので、可視の要素だけを数える
    const list = page.getByTestId("audit-list-project");
    const visibleRowIds = list.getByText("Row id", { exact: true }).locator("visible=true");
    await expect(visibleRowIds.count()).resolves.toBe(0);
    const row = list.getByRole("button", { name: /chain\.member_added/ });
    await row.click();
    await expect(row.getAttribute("aria-expanded")).resolves.toBe("true");
    await visibleRowIds.waitFor();
    await expect(visibleRowIds.count()).resolves.toBe(1);
    // 展開部にも target(user_colleague)が記録どおり出る(要約行の 1 + 展開部の 1)
    await expect(
      list.getByText("user_colleague", { exact: true }).locator("visible=true").count(),
    ).resolves.toBe(2);
    // invites 軸(admin 未満)は役割文言のまま表示(存在・件数を示唆しない)。
    // W3b で管理タブ "Invites"(S8)が同語で並ぶため、ToggleButtonGroup(DP3 で
    // SegmentedControl から置換)の押下ボタンを role で指す
    await page.getByRole("button", { name: "Invites", pressed: false }).click();
    await page.getByText("Not available to your role").first().waitFor();

    // S7 フラグ: 表示 + dismiss の静的案内(dismiss 操作は存在しない)
    await page.getByRole("tab", { name: "Rotation flags" }).click();
    await page.getByTestId("rotation-table").waitFor();
    await expect(page.getByTestId("rotation-note").textContent()).resolves.toContain(
      "maruhi rotation dismiss",
    );

    expect(violations).toEqual([]);
    await page.close();
  });

  it("resumes to /dashboard after sign-in, driven through the real affordance (裁定 BU)", async () => {
    // マーカーはテストが注入せず、**実クリック**(Link の onClick)に書かせる —
    // Link がマーカーを書かなくなる退行・consume ガードの退行がこのテストで
    // 割れる(pullfrog レビュー反映)。OAuth 実フローだけは e2e 不能(裁定 BS)
    // なので、/auth/github/start への実ナビゲーションを「認可成功 → callback が
    // ${origin}/ へ 302」まで畳んで差し替える
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
    // "/" 着地 → ResumeToDashboard がマーカーを消費 → /auth/me 確認 → /dashboard
    await page.getByTestId("project-list").waitFor();
    expect(new URL(page.url()).pathname).toBe("/dashboard");
    expect(violations).toEqual([]);
    await page.close();
  });

  it("keeps the marker-free landing free of API calls (BP 第 3 周の境界の固定)", async () => {
    // BU が BP の棄却案(S1 での常時 /auth/me 照会)に退行していないことを
    // リクエスト収集で固定する — consume ガードが消えるとここが割れる
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
    await page.close();
  });

  it("stays on the landing page when the marker is set but no session exists", async () => {
    const page = await browser.newPage();
    await page.route("**/auth/me", unauthorized);
    await page.addInitScript(() => {
      try {
        sessionStorage.setItem("maruhi-resume-dashboard", "1");
      } catch {
        // storage 不可環境では何もしない
      }
    });
    await page.goto(`${BASE}/`, { waitUntil: "networkidle" });
    await page.getByTestId("home-heading").waitFor();
    // OAuth 中断・失敗(セッション未成立)ではランディングに留まる
    expect(new URL(page.url()).pathname).toBe("/");
    await page.close();
  });

  it("lists invitations, revokes via inline confirm with the CSRF header, and refreshes (S8)", async () => {
    const page = await browser.newPage();
    const violations = collectViolations(page);
    let revoked = false;
    let deleteMethod: string | null = null;
    let deleteCsrf: string | null = null;
    // Overview タブ(初期表示)の消費面もモックする: 実サーバーの 401 応答は
    // ボディ未読のまま networkidle を妨げる(W2 テストが全面モックである理由)
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
    // 発行 UI は置かない — CLI への静的案内のみ(ADR-0018 改訂 2)
    await expect(page.getByTestId("invite-notes").textContent()).resolves.toContain(
      "maruhi invite create",
    );
    // Revoke は pending | accepted 行のみ(completed 行にはボタンが出ない)
    await expect(page.getByRole("button", { name: "Revoke" }).count()).resolves.toBe(2);
    // 2 段階確認(裁定 CO — DP3 改訂 4 で AlertDialog に): 行の Revoke → モーダルの Revoke で実行
    await page.getByRole("button", { name: "Revoke" }).first().click();
    await confirmRevoke(page);
    // 完了後はサーバー再取得で写す(楽観更新しない) — pending 行が revoked に
    await page.getByText("revoked", { exact: true }).waitFor();
    expect(deleteMethod).toBe("DELETE");
    expect(deleteCsrf).toBe("1");
    expect(violations).toEqual([]);
    await page.close();
  });

  it("shows the server-reported gone wording when a revocation races to 410 (S8)", async () => {
    // 失効 CAS が負けた側(他所で completed / revoked に遷移済み)のサーバー
    // 申告 reason を写す(api 層の gone 分類 — 裁定 CN 付随の文言検証)
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
    await page.close();
  });

  it("shows the role wording when the invites listing reports 403 (S8 — admin 未満)", async () => {
    const page = await browser.newPage();
    await routeProjectOverview(page);
    await page.route(
      (url) => url.pathname === `/projects/${PROJECT_1}/invites`,
      (route) => fulfillJson(route, 403, { _tag: "Forbidden", reason: "insufficient-role" }),
    );
    await page.goto(`${BASE}/dashboard/projects/${PROJECT_1}`, { waitUntil: "networkidle" });
    // タブは role で事前に隠さない(裁定 CP 第 3 周)— 403 は役割文言で表示
    await page.getByRole("tab", { name: "Invites" }).click();
    await page.getByText("Not available to your role").first().waitFor();
    await page.close();
  });

  it("lists tokens with server-reported expiry: Expired, no expiry recorded, never (S9)", async () => {
    const page = await browser.newPage();
    const violations = collectViolations(page);
    await routeSession(page);
    await page.route(
      (url) => url.pathname === "/auth/tokens",
      (route) => fulfillJson(route, 200, tokensFixture),
    );
    await page.goto(`${BASE}/dashboard/tokens`, { waitUntil: "networkidle" });
    await page.getByTestId("token-table").waitFor();
    // 期限切れ(過去)+ 移行前 null 行(fail-closed — 裁定 CQ)の両方が Expired
    await expect(page.getByText("Expired", { exact: true }).count()).resolves.toBe(2);
    await expect(page.getByText("no expiry recorded", { exact: true }).count()).resolves.toBe(1);
    // lastUsedAtMs null は "never"(2 行)
    await expect(page.getByText("never", { exact: true }).count()).resolves.toBe(2);
    // 発行 UI・生値表示は置かない — CLI ログインへの静的案内のみ
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
    await routeSession(page);
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
    await page.goto(`${BASE}/dashboard/tokens`, { waitUntil: "networkidle" });
    await page.getByTestId("token-table").waitFor();
    await page.getByRole("button", { name: "Revoke" }).first().click();
    await confirmRevoke(page);
    // 指定失効は行の削除 — 再取得後の一覧から "ci" 行が消える。再取得中は一覧が
    // LoadingRow に置き換わる(裁定 B の置換形)ため、"ci" の detached だけでは
    // 「再取得後の一覧」に到達していない。残る行の再出現を待ってから件数を見る
    // (PR #148 CI の 1 回目で顕在化した競合)
    await page.getByText("ci", { exact: true }).waitFor({ state: "detached" });
    await page.getByText("old-laptop", { exact: true }).waitFor();
    await expect(page.getByText("ci", { exact: true }).count()).resolves.toBe(0);
    expect(deleteMethod).toBe("DELETE");
    expect(deleteCsrf).toBe("1");
    expect(violations).toEqual([]);
    await page.close();
  });

  it("keeps the confirmation modal open and other rows locked while a revoke is in flight (PR #109 Bugbot 指摘の回帰)", async () => {
    // DELETE の in-flight 中に別行を武装できると、後着の完了が武装状態を
    // 上書きし、失敗の帰属が別の失効に見える(use-revocation.ts のガード)。DP3 改訂 4
    // では確認が AlertDialog(モーダル)なので、実行中はダイアログが開いたまま
    // (Escape で閉じない)で他行に触れず、完了後にダイアログが閉じて一覧が再取得される。
    // DELETE をゲートで保留して実測する
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
    // in-flight 中: モーダルは開いたまま(Escape も効かない)。行の Revoke は
    // isLocked で無効(RevokeButton — モーダルの背後でも二層目のガードを保つ)
    await page.keyboard.press("Escape");
    await expect(dialog.count()).resolves.toBe(1);
    const rowRevoke = page
      .getByTestId("token-table")
      .getByRole("button", { name: "Revoke", exact: true })
      .first();
    await expect.poll(() => rowRevoke.isDisabled()).toBe(true);
    release?.();
    // 完了 → ダイアログが閉じ、再取得で行が消え、残る行の Revoke は再び有効
    await dialog.waitFor({ state: "hidden" });
    await page.getByText("ci", { exact: true }).waitFor({ state: "detached" });
    await page.getByText("old-laptop", { exact: true }).waitFor();
    await expect
      .poll(() => page.getByRole("button", { name: "Revoke", exact: true }).first().isDisabled())
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
    // 一様 404(他人の・存在しないを区別しない)を token の名詞で写す(裁定 CN 付随)
    await page.getByText("The server reports no such token for your account.").waitFor();
    await page.close();
  });

  it("renders the audit log as expandable rows at mobile width (DP3 裁定 D / P — HP5)", async () => {
    // 監査一覧は幅によらず 1 列の行(Collapsible)で、モバイルでも同じ形のまま行の直下に
    // 詳細が開く。768px 以下(AppShell の md)ではサイドバーがドロワーへ移る。
    // pullfrog レビュー反映: この経路を CI で固定する
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
    // Table ではなく行(トリガー button)で描かれ、行の意味(イベント名・seq・actor・target)は保たれる
    await expect(list.locator("table").count()).resolves.toBe(0);
    await expect(list.getByRole("button", { expanded: false }).count()).resolves.toBe(2);
    await expect(list.getByText("chain.member_added").count()).resolves.toBe(1);
    await expect(list.getByText("user_colleague").count()).resolves.toBeGreaterThan(0);
    await expect(list.getByText("seq 2", { exact: true }).count()).resolves.toBe(1);
    await expect(list.getByText("seq 1", { exact: true }).count()).resolves.toBe(1);
    // 行を開くと同じ列の直下に全フィールドが出る(Dialog ではない)。single なので
    // 別の行を開くと先の行は閉じる
    const genesis = list.getByRole("button", { name: /chain\.genesis/ });
    const visibleRowIds = list.getByText("Row id", { exact: true }).locator("visible=true");
    await genesis.click();
    await visibleRowIds.waitFor();
    await expect(page.getByRole("dialog").count()).resolves.toBe(0);
    await list.getByRole("button", { name: /chain\.member_added/ }).click();
    await expect(genesis.getAttribute("aria-expanded")).resolves.toBe("false");
    await expect(visibleRowIds.count()).resolves.toBe(1);
    // サイドバーはドロワーへ: トグルで開き、到達点とユーザー id が並ぶ
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
    // D1 経路は seq を返さない(AUDIT_SPEC §7)— 行にも出ない(応答適応)
    await expect(page.getByText(/^seq /).count()).resolves.toBe(0);
    expect(violations).toEqual([]);
    await page.close();
  });

  it("keeps the shell mounted across SPA navigation without re-checking the session", async () => {
    // DP3 改訂 11(PR #148 Bugbot 指摘): 認証が要る画面は pathless の親ルート
    // (DashboardLayout)の子なので、画面間の遷移でシェルは再マウントされず、
    // /auth/me の再取得も「Checking your session」の再表示も起きない。サイドバーの
    // DOM ノードが同一のまま(= 折りたたみ状態などが保たれる)ことで再マウント無しを検査する
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
    const userItem = page.getByTestId("signed-in-user");
    await userItem.evaluate((el) => {
      (el as HTMLElement).dataset["shellProbe"] = "mounted";
    });
    // サイドバーから API tokens へ(SPA 遷移)。h1 が変わり、セッション確認は増えない
    await page.getByRole("link", { name: "API tokens" }).click();
    await page.getByTestId("token-table").waitFor();
    await expect(page.getByRole("heading", { level: 1 }).textContent()).resolves.toBe("API tokens");
    await expect(
      page.getByRole("link", { name: "API tokens" }).getAttribute("aria-current"),
    ).resolves.toBe("page");
    expect(sessionChecks).toBe(1);
    await expect(page.getByText("Checking your session").count()).resolves.toBe(0);
    await expect(
      userItem.evaluate((el) => (el as HTMLElement).dataset["shellProbe"]),
    ).resolves.toBe("mounted");
    // 続けて Account audit へ(フッターのユーザー id からも到達できる)
    await userItem.click();
    await page.getByTestId("audit-list-self").waitFor();
    await expect(page.getByRole("heading", { level: 1 }).textContent()).resolves.toBe(
      "Account audit",
    );
    expect(sessionChecks).toBe(1);
    expect(violations).toEqual([]);
    await page.close();
  });

  it("returns to the sign-in screen in place when a screen fetch reports 401", async () => {
    // 改訂 11 でシェルが遷移をまたいで残るようになった副作用(pullfrog 指摘): 途中で
    // セッションが失効しても、画面の 401 → シェルへの通知 → その場でサインイン画面
    // (再読込・再遷移なし)
    const page = await browser.newPage();
    const violations = collectViolations(page);
    await routeSession(page);
    await page.route((url) => url.pathname === "/auth/tokens", unauthorized);
    await page.goto(`${BASE}/dashboard/tokens`, { waitUntil: "networkidle" });
    await page.getByTestId("login-card").waitFor();
    await expect(page.getByText("You are signed out.").count()).resolves.toBe(1);
    await expect(page.getByTestId("signed-in-user").count()).resolves.toBe(0);
    expect(new URL(page.url()).pathname).toBe("/dashboard/tokens");
    expect(violations).toEqual([]);
    await page.close();
  });
});
