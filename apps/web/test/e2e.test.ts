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

import type {
  AuditEvent,
  ChainSnapshot,
  EnvironmentList,
  EnvironmentMetadataPull,
  InvitationList,
  Me,
  ProjectList,
  RotationFlagList,
  TokenList,
} from "../src/dashboard/types.ts";

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

  // /invite(AUTH_SPEC §15-3 / ADR-0018 改訂 2・5 項): SPA 外の独立静的アセット +
  // per-path CSP `script-src 'none'`。「スクリプトを一切持たない・フラグメントを
  // 解釈しない」を実配信(wrangler dev)に対して固定する
  it("serves /invite as a script-free static page with per-path CSP script-src 'none'", async () => {
    const res = await fetch(`${BASE}/invite`);
    expect(res.status).toBe(200);
    const csp = res.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("script-src 'none'");
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
    // 200 リライトの盾: 正規アセットは /invite* の総取りに飲まれず素通しされる
    // (盾が落ちてループ化したら /invite の 3xx でここが検知する)
    const cssRes = await fetch(`${BASE}/invite.css`, { redirect: "manual" });
    expect(cssRes.status).toBe(200);
    const inviteRes = await fetch(`${BASE}/invite`, { redirect: "manual" });
    expect(inviteRes.status).toBe(200);
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
    // スタイルシート(自己配信 /invite.css)が CSP 下で適用されている
    const maxWidth = await page.locator("main").evaluate((el) => getComputedStyle(el).maxWidth);
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

const PROJECT_1 = "ab".repeat(32);
const PROJECT_2 = "cd".repeat(32);
const HEX64 = "12".repeat(32);
const SIG = "34".repeat(64);
const FP = "56".repeat(16);
const ROW_ID_1 = "78".repeat(16);
const ROW_ID_2 = "9a".repeat(16);

const meFixture: Me = { userId: "user_e2e", orgs: [] };

const PROJECT_GHOST_CURSOR = "ef".repeat(32);

const projectsPage1: ProjectList = {
  projects: [{ projectId: PROJECT_1, role: "admin" }],
  nextAfter: PROJECT_1,
};
// 空ページ + nextAfter(AUTH_SPEC §11-5 — ghost 除外・確認失敗の省略で
// 候補ページが空になる形)。UI はこれを終端と誤断せずカーソルを進める
const projectsPageEmpty: ProjectList = {
  projects: [],
  nextAfter: PROJECT_GHOST_CURSOR,
};
const projectsPage2: ProjectList = {
  projects: [{ projectId: PROJECT_2, role: "reader" }],
};

const chainFixture: ChainSnapshot = {
  projectId: PROJECT_1,
  headSeq: 2,
  headHashHex: HEX64,
  entries: [
    {
      suite: "maruhi/v1",
      seq: 1,
      prevHashHex: "00".repeat(32),
      actor: { userId: "user_e2e", keyFingerprintHex: FP },
      timestampMs: 1_756_000_000_000,
      signatureHex: SIG,
      op: "genesis",
      payload: { encPubHex: HEX64, sigPubHex: HEX64 },
    },
    {
      suite: "maruhi/v1",
      seq: 2,
      prevHashHex: HEX64,
      actor: { userId: "user_e2e", keyFingerprintHex: FP },
      timestampMs: 1_756_000_100_000,
      signatureHex: SIG,
      op: "add_member",
      payload: {
        targetUserId: "user_colleague",
        encPubHex: HEX64,
        sigPubHex: HEX64,
        role: "reader",
      },
    },
  ],
  attestations: [],
};

const environmentStatement = {
  suite: "maruhi/v1",
  environmentId: "production",
  name: "production",
  chainHeadHashHex: HEX64,
  chainHeadSeq: 1,
  signatureHex: SIG,
  status: "active",
  metaVersion: 1,
  prevMetaSigHashHex: "",
  authorUserId: "user_e2e",
  authorKeyFingerprintHex: FP,
} as const;

const environmentsFixture: EnvironmentList = {
  environments: [{ environmentId: "production", currentEpoch: 1, statement: environmentStatement }],
};

const metadataPullFixture: EnvironmentMetadataPull = {
  environmentId: "production",
  currentEpoch: 1,
  statement: environmentStatement,
  variables: [
    {
      ...environmentStatement,
      variableId: "var-database-url",
      name: "DATABASE_URL",
    },
  ],
  deletedVariables: [],
};

// admin 可視の project DO 応答(seq あり — AUDIT_SPEC §7)
const projectAuditEvents: { events: AuditEvent[] } = {
  events: [
    {
      id: ROW_ID_1,
      seq: 2,
      serverTs: 1_756_000_100_000,
      event: "chain.member_added",
      actor: { type: "user", userId: "user_e2e", keyFingerprintHex: FP },
      targetUserId: "user_colleague",
      chainSeq: 2,
    },
    {
      id: ROW_ID_2,
      seq: 1,
      serverTs: 1_756_000_000_000,
      event: "chain.genesis",
      actor: { type: "user", userId: "user_e2e", keyFingerprintHex: FP },
      targetUserId: "user_e2e",
      chainSeq: 1,
    },
  ],
};

// 本人軸(D1 経路 — seq は誰にも返らない)
const selfAuditEvents: { events: AuditEvent[] } = {
  events: [
    {
      id: ROW_ID_1,
      serverTs: 1_756_000_200_000,
      event: "auth.login_succeeded",
      actor: { type: "user", userId: "user_e2e" },
    },
  ],
};

const rotationFlagsFixture: RotationFlagList = {
  flags: [
    {
      environmentId: "production",
      variableId: "var-database-url",
      basis: "read",
      targetUserId: "user_colleague",
      recommendedAtMs: 1_756_000_300_000,
      triggerChainSeq: 3,
    },
  ],
};

// ---------------------------------------------------------------------------
// W3b(S8 招待管理・S9 トークン管理)のフィクスチャ。期限は「未来 = 2100 年 /
// 過去 = 2023 年」の固定値(実行時刻に対して安定 — 裁定 CQ の Expired 表示は
// クライアント時計との比較なので、境界近傍の値を使わない)
// ---------------------------------------------------------------------------

const FUTURE_MS = 4_102_444_800_000; // 2100-01-01
const PAST_MS = 1_700_000_000_000; // 2023-11-14

const acceptanceFixture = {
  inviteeUserId: "user_colleague",
  inviteeEncPubHex: HEX64,
  inviteeSigPubHex: HEX64,
  signatureHex: SIG,
  acceptedAtMs: 1_756_000_100_000,
} as const;

const pendingInvite = {
  id: "inv-pending",
  projectId: PROJECT_1,
  role: "member",
  status: "pending",
  inviterUserId: "user_e2e",
  tokenHashHex: HEX64,
  createdAtMs: 1_756_000_000_000,
  expiresAtMs: FUTURE_MS,
  acceptance: null,
} as const;

const invitationsFixture: InvitationList = {
  invitations: [
    pendingInvite,
    {
      id: "inv-accepted",
      projectId: PROJECT_1,
      role: "reader",
      status: "accepted",
      inviterUserId: "user_e2e",
      tokenHashHex: HEX64,
      createdAtMs: 1_756_000_000_000,
      expiresAtMs: FUTURE_MS,
      acceptance: acceptanceFixture,
    },
    {
      id: "inv-completed",
      projectId: PROJECT_1,
      role: "member",
      status: "completed",
      inviterUserId: "user_e2e",
      tokenHashHex: HEX64,
      createdAtMs: 1_756_000_000_000,
      expiresAtMs: PAST_MS,
      acceptance: acceptanceFixture,
    },
  ],
};

// 失効後のサーバー申告(pending 行が revoked へ) — UI は再取得で写す(裁定 CO)
const invitationsAfterRevoke: InvitationList = {
  invitations: [
    { ...pendingInvite, status: "revoked" },
    ...invitationsFixture.invitations.slice(1),
  ],
};

const tokensFixture: TokenList = {
  tokens: [
    {
      id: "tok-active",
      name: "ci",
      tokenPrefix: "maruhi_pat_abcdefgh",
      scopes: [{ project: "*", permission: "admin" }],
      createdAtMs: 1_756_000_000_000,
      lastUsedAtMs: 1_756_000_100_000,
      expiresAtMs: FUTURE_MS,
    },
    {
      id: "tok-expired",
      name: "old-laptop",
      tokenPrefix: "maruhi_pat_ijklmnop",
      scopes: [{ project: PROJECT_1, permission: "read" }],
      createdAtMs: 1_756_000_000_000,
      lastUsedAtMs: null,
      expiresAtMs: PAST_MS,
    },
    // 移行(AUTH_SPEC §6 裁定 CE)前の旧無期限行 — 検証側は期限切れ扱い
    // (fail-closed)。表示は Expired + no expiry recorded(裁定 CQ)
    {
      id: "tok-legacy",
      name: "legacy",
      tokenPrefix: "maruhi_pat_qrstuvwx",
      scopes: [],
      createdAtMs: 1_756_000_000_000,
      lastUsedAtMs: null,
      expiresAtMs: null,
    },
  ],
};

// 指定失効は行の削除(サーバー実装 — 一覧から消える)
const tokensAfterRevoke: TokenList = { tokens: tokensFixture.tokens.slice(1) };

function fulfillJson(route: Route, status: number, body: unknown): Promise<void> {
  return route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
}

/** 401(未認証)を返すハンドラ(Unauthorized — api-schema のワイヤ形)。 */
function unauthorized(route: Route): Promise<void> {
  return fulfillJson(route, 401, { _tag: "Unauthorized" });
}

/**
 * プロジェクト画面の初期表示(Overview タブ)の消費面のモック(W3b の S8 テストで
 * 共用)。/auth/me は画面が呼ばないが、他テストと同じ既定として登録しておく。
 */
async function routeProjectOverview(page: Page): Promise<void> {
  await page.route("**/auth/me", (route) => fulfillJson(route, 200, meFixture));
  await page.route(
    (url) => url.pathname === `/projects/${PROJECT_1}/chain`,
    (route) => fulfillJson(route, 200, chainFixture),
  );
  await page.route(
    (url) => url.pathname === `/projects/${PROJECT_1}/environments`,
    (route) => fulfillJson(route, 200, environmentsFixture),
  );
}

/** ダッシュボード用の CSP violation 収集(既存テストと同じ検出方法)。 */
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
      sawCsrfHeader = route.request().headers()["x-maruhi-csrf"] ?? null;
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

    // S5 概要: チェーン導出メンバー(サーバー申告)+ 環境 + 変数名(メタのみ pull)
    await page.getByTestId("member-table").waitFor();
    await expect(page.getByText("user_colleague").count()).resolves.toBeGreaterThan(0);
    await page.getByTestId("env-table").waitFor();
    await page.getByText("Variable names", { exact: true }).click();
    await page.getByTestId("variable-list").waitFor();
    await expect(page.getByText("DATABASE_URL").count()).resolves.toBeGreaterThan(0);

    // S6 監査: 規定文言 + admin 応答由来の seq 列(応答適応)
    await page.locator('[data-tab-value="audit"]').click();
    await page.getByTestId("audit-caption").waitFor();
    await expect(page.getByTestId("audit-caption").textContent()).resolves.toContain(
      "Events visible to your role",
    );
    await page.getByTestId("audit-list-project").waitFor();
    await expect(page.getByText("Seq", { exact: true }).count()).resolves.toBe(1);
    await expect(page.getByText("chain.member_added").count()).resolves.toBeGreaterThan(0);
    // invites 軸(admin 未満)は役割文言のまま表示(存在・件数を示唆しない)。
    // W3b で管理タブ "Invites"(S8)が同語で並ぶため、radiogroup(SegmentedControl)
    // 側を role で指す
    await page.getByRole("radio", { name: "Invites" }).click();
    await page.getByText("Not available to your role").first().waitFor();

    // S7 フラグ: 表示 + dismiss の静的案内(dismiss 操作は存在しない)
    await page.locator('[data-tab-value="rotation"]').click();
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
    await page.getByTestId("built-at").waitFor();
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
    await page.getByTestId("built-at").waitFor();
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
        deleteCsrf = route.request().headers()["x-maruhi-csrf"] ?? null;
        revoked = true;
        return route.fulfill({ status: 204 });
      },
    );

    await page.goto(`${BASE}/dashboard/projects/${PROJECT_1}`, { waitUntil: "networkidle" });
    await page.locator('[data-tab-value="invites"]').click();
    await page.getByTestId("invite-table").waitFor();
    // 発行 UI は置かない — CLI への静的案内のみ(ADR-0018 改訂 2)
    await expect(page.getByTestId("invite-notes").textContent()).resolves.toContain(
      "maruhi invite create",
    );
    // Revoke は pending | accepted 行のみ(completed 行にはボタンが出ない)
    await expect(page.getByRole("button", { name: "Revoke" }).count()).resolves.toBe(2);
    // 2 段階確認(裁定 CO): Revoke で武装 → Confirm revoke で実行
    await page.getByRole("button", { name: "Revoke" }).first().click();
    await page.getByRole("button", { name: "Confirm revoke" }).click();
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
    await page.locator('[data-tab-value="invites"]').click();
    await page.getByTestId("invite-table").waitFor();
    await page.getByRole("button", { name: "Revoke" }).first().click();
    await page.getByRole("button", { name: "Confirm revoke" }).click();
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
    await page.locator('[data-tab-value="invites"]').click();
    await page.getByText("Not available to your role").first().waitFor();
    await page.close();
  });

  it("lists tokens with server-reported expiry: Expired, no expiry recorded, never (S9)", async () => {
    const page = await browser.newPage();
    const violations = collectViolations(page);
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
    await page.route(
      (url) => url.pathname === "/auth/tokens",
      (route) => fulfillJson(route, 200, revoked ? tokensAfterRevoke : tokensFixture),
    );
    await page.route(
      (url) => url.pathname === "/auth/tokens/tok-active",
      (route) => {
        deleteMethod = route.request().method();
        deleteCsrf = route.request().headers()["x-maruhi-csrf"] ?? null;
        revoked = true;
        return route.fulfill({ status: 204 });
      },
    );
    await page.goto(`${BASE}/dashboard/tokens`, { waitUntil: "networkidle" });
    await page.getByTestId("token-table").waitFor();
    await page.getByRole("button", { name: "Revoke" }).first().click();
    await page.getByRole("button", { name: "Confirm revoke" }).click();
    // 指定失効は行の削除 — 再取得後の一覧から "ci" 行が消える
    await page.getByText("ci", { exact: true }).waitFor({ state: "detached" });
    await expect(page.getByText("old-laptop", { exact: true }).count()).resolves.toBe(1);
    expect(deleteMethod).toBe("DELETE");
    expect(deleteCsrf).toBe("1");
    expect(violations).toEqual([]);
    await page.close();
  });

  it("shows the token 404 wording on the uniform not-found of targeted revocation (S9)", async () => {
    const page = await browser.newPage();
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
    await page.getByRole("button", { name: "Confirm revoke" }).click();
    // 一様 404(他人の・存在しないを区別しない)を token の名詞で写す(裁定 CN 付随)
    await page.getByText("The server reports no such token for your account.").waitFor();
    await page.close();
  });

  it("renders the account (self) audit axis without a seq column", async () => {
    const page = await browser.newPage();
    const violations = collectViolations(page);
    await page.route(
      (url) => url.pathname === "/auth/audit/events",
      (route) => fulfillJson(route, 200, selfAuditEvents),
    );
    await page.goto(`${BASE}/dashboard/account`, { waitUntil: "networkidle" });
    await page.getByTestId("audit-list-self").waitFor();
    await expect(page.getByText("auth.login_succeeded").count()).resolves.toBeGreaterThan(0);
    // D1 経路は seq を返さない(AUDIT_SPEC §7)— 列も出ない(応答適応)
    await expect(page.getByText("Seq", { exact: true }).count()).resolves.toBe(0);
    expect(violations).toEqual([]);
    await page.close();
  });
});
