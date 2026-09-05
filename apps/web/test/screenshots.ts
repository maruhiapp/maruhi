// 認証済み画面(S3〜S9)のスクリーンショット取得(DP3 裁定 F — docs/notes/web-design-pass.md §5)。
//
// 配信物にプレビュー用ルートやモックデータを混ぜず、e2e と同じ page.route で API だけを
// 差し替えて実配信(wrangler dev)を Chromium で描く。light / dark / mobile(390px)の
// 3 態で撮り、CSP 違反があれば失敗する。各集合の空状態(`empty`)も撮る — fixtures は
// 全件非空なので、空状態はここで明示しない限り一度も描かれない(見出し階層が変わる)。
//
//   bun run --filter @maruhi/web build
//   bun run --filter @maruhi/web preview   # 別ターミナル(port 8788)
//   bun run --filter @maruhi/web screenshots [--only <名前の一部>]
//
// 出力先は SCREENSHOT_DIR(既定 apps/web/screenshots/ — .gitignore 済み)。
// PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH は e2e と同じ扱い(未設定なら Playwright 既定)。
import { mkdirSync } from "node:fs";
import { join } from "node:path";

import { chromium, type Page, type Route } from "playwright";

import {
  chainFixture,
  environmentsFixture,
  invitationsFixture,
  meFixture,
  metadataPullFixture,
  PROJECT_1,
  projectAuditEvents,
  projectsPage1,
  projectsPage2,
  rotationFlagsFixture,
  selfAuditEvents,
  tokensFixture,
} from "./fixtures.ts";

const BASE = process.env["SCREENSHOT_BASE"] ?? "http://127.0.0.1:8788";
const OUT = process.env["SCREENSHOT_DIR"] ?? join(import.meta.dirname, "..", "screenshots");
const FORBIDDEN = { _tag: "Forbidden", reason: "insufficient-role" };
const NOT_FOUND = { _tag: "ProjectNotFound" };
const NO_SUCH_PROJECT = "ff".repeat(32);

function json(route: Route, status: number, body: unknown): Promise<void> {
  return route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
}

function before(route: Route): string | null {
  return new URL(route.request().url()).searchParams.get("before");
}

/**
 * 全消費面のモック。admin=false は監査 invites 軸 / S8 が 403(役割文言)になる。
 * empty=true は各集合を空で返す(空状態 — 見出し階層は集合があるときと変わるので、
 * axe / 目視の対象に含める。pullfrog 指摘: 空状態は fixtures だけでは決して描かれない)。
 */
async function mockApi(
  page: Page,
  opts: { signedIn: boolean; admin: boolean; empty: boolean },
): Promise<void> {
  await page.route("**/auth/me", (r) =>
    opts.signedIn ? json(r, 200, meFixture) : json(r, 401, { _tag: "Unauthorized" }),
  );
  await page.route(
    (u) => u.pathname === "/projects",
    (r) =>
      json(
        r,
        200,
        opts.empty
          ? { projects: [] }
          : new URL(r.request().url()).searchParams.has("after")
            ? projectsPage2
            : projectsPage1,
      ),
  );
  await page.route(
    (u) => u.pathname === `/projects/${PROJECT_1}/chain`,
    (r) => json(r, 200, chainFixture),
  );
  await page.route(
    (u) => u.pathname === `/projects/${PROJECT_1}/environments`,
    (r) => json(r, 200, opts.empty ? { environments: [] } : environmentsFixture),
  );
  await page.route(
    (u) => u.pathname === `/projects/${PROJECT_1}/environments/production/pull/metadata`,
    (r) =>
      json(
        r,
        200,
        opts.empty
          ? { ...metadataPullFixture, variables: [], deletedVariables: [] }
          : metadataPullFixture,
      ),
  );
  await page.route(
    (u) => u.pathname === `/projects/${PROJECT_1}/audit/events`,
    (r) => {
      if (opts.empty || before(r) !== null) return json(r, 200, { events: [] });
      // admin 未満の応答には seq が載らない(AUDIT_SPEC §7)
      const events = opts.admin
        ? projectAuditEvents.events
        : projectAuditEvents.events.map(({ seq: _seq, ...event }) => event);
      return json(r, 200, { events });
    },
  );
  await page.route(
    (u) => u.pathname === `/projects/${PROJECT_1}/audit/invites`,
    (r) => (opts.admin ? json(r, 200, { events: [] }) : json(r, 403, FORBIDDEN)),
  );
  await page.route(
    (u) => u.pathname === `/projects/${PROJECT_1}/rotation/flags`,
    (r) => json(r, 200, opts.empty ? { flags: [] } : rotationFlagsFixture),
  );
  await page.route(
    (u) => u.pathname === `/projects/${PROJECT_1}/invites`,
    (r) =>
      opts.admin
        ? json(r, 200, opts.empty ? { invitations: [] } : invitationsFixture)
        : json(r, 403, FORBIDDEN),
  );
  await page.route(
    (u) => u.pathname.startsWith(`/projects/${NO_SUCH_PROJECT}/`),
    (r) => json(r, 404, NOT_FOUND),
  );
  await page.route(
    (u) => u.pathname === "/auth/tokens",
    (r) => json(r, 200, opts.empty ? { tokens: [] } : tokensFixture),
  );
  await page.route(
    (u) => u.pathname === "/auth/audit/events",
    (r) => json(r, 200, opts.empty || before(r) !== null ? { events: [] } : selfAuditEvents),
  );
}

interface Shot {
  name: string;
  path: string;
  ready: string;
  act?: (page: Page) => Promise<void>;
  signedIn?: boolean;
  admin?: boolean;
  /** 集合を空で描く(空状態の見出し階層・文言の確認用)。 */
  empty?: boolean;
}

const projectPath = `/dashboard/projects/${PROJECT_1}`;

async function openTab(page: Page, tab: string, ready: string): Promise<void> {
  await page.getByRole("tab", { name: tab }).click();
  await page.locator(ready).waitFor();
}

const SHOTS: ReadonlyArray<Shot> = [
  { name: "s3-login", path: "/dashboard", ready: "[data-testid=login-card]", signedIn: false },
  { name: "s4-projects", path: "/dashboard", ready: "[data-testid=project-list]" },
  {
    name: "s5-overview",
    path: projectPath,
    ready: "[data-testid=env-table]",
    act: async (page) => {
      await page.getByText("Variable names", { exact: true }).click();
      await page.locator("[data-testid=variable-list]").waitFor();
      // 表の横スクロール位置をクリック前に戻す(クリックで 4 列目へスクロールする)
      await page.locator("[data-testid=env-table]").evaluate((table) => {
        table.parentElement?.scrollTo({ left: 0 });
      });
    },
  },
  {
    name: "s5-not-found",
    path: `/dashboard/projects/${NO_SUCH_PROJECT}`,
    ready: "[data-testid=project-id]",
    act: (page) => page.getByText("Not found", { exact: true }).first().waitFor(),
  },
  {
    name: "s6-audit-admin",
    path: projectPath,
    ready: "[data-testid=member-table]",
    act: (page) => openTab(page, "Audit", "[data-testid=audit-list-project]"),
  },
  {
    name: "s6-audit-reader",
    path: projectPath,
    ready: "[data-testid=member-table]",
    admin: false,
    act: async (page) => {
      await openTab(page, "Audit", "[data-testid=audit-list-project]");
      await page.getByRole("button", { name: "Invites", pressed: false }).click();
      await page.getByText("Not available to your role").first().waitFor();
    },
  },
  {
    name: "s6-account",
    path: "/dashboard/account",
    ready: "[data-testid=audit-list-self]",
  },
  {
    name: "s7-rotation",
    path: projectPath,
    ready: "[data-testid=member-table]",
    act: (page) => openTab(page, "Rotation flags", "[data-testid=rotation-table]"),
  },
  {
    name: "s8-invites",
    path: projectPath,
    ready: "[data-testid=member-table]",
    act: async (page) => {
      await openTab(page, "Invites", "[data-testid=invite-table]");
      // 失効の確認モーダル(AlertDialog — 改訂 4)を写す。mount / アニメーションと競合しない
      // よう dialog の出現を待つ(pullfrog 指摘: 待たないと素の表を写して黙って通る)
      await page.getByRole("button", { name: "Revoke", exact: true }).first().click();
      await page.getByRole("alertdialog").waitFor();
    },
  },
  {
    name: "s8-invites-reader",
    path: projectPath,
    ready: "[data-testid=member-table]",
    admin: false,
    act: async (page) => {
      await page.getByRole("tab", { name: "Invites" }).click();
      await page.getByText("Not available to your role").first().waitFor();
    },
  },
  { name: "s9-tokens", path: "/dashboard/tokens", ready: "[data-testid=token-table]" },
  // 空状態(見出しの無い箱では空状態の見出しが h2 — shared.tsx の EmptyNotice)。
  // 変数名の空状態(環境はあるが変数が無い)は empty モードでは描けない(環境も空になる)
  {
    name: "s4-projects-empty",
    path: "/dashboard",
    ready: "[data-testid=project-empty]",
    empty: true,
  },
  {
    name: "s5-overview-empty",
    path: projectPath,
    ready: "[data-testid=env-empty]",
    empty: true,
  },
  {
    name: "s6-audit-empty",
    path: projectPath,
    ready: "[data-testid=member-table]",
    empty: true,
    act: (page) => openTab(page, "Audit", "[data-testid=audit-list-project-empty]"),
  },
  {
    name: "s6-account-empty",
    path: "/dashboard/account",
    ready: "[data-testid=audit-list-self-empty]",
    empty: true,
  },
  {
    name: "s7-rotation-empty",
    path: projectPath,
    ready: "[data-testid=member-table]",
    empty: true,
    act: (page) => openTab(page, "Rotation flags", "[data-testid=rotation-empty]"),
  },
  {
    name: "s8-invites-empty",
    path: projectPath,
    ready: "[data-testid=member-table]",
    empty: true,
    act: (page) => openTab(page, "Invites", "[data-testid=invite-empty]"),
  },
  {
    name: "s9-tokens-empty",
    path: "/dashboard/tokens",
    ready: "[data-testid=token-empty]",
    empty: true,
  },
];

const MODES = [
  { name: "light", scheme: "light" as const, viewport: { width: 1280, height: 900 } },
  { name: "dark", scheme: "dark" as const, viewport: { width: 1280, height: 900 } },
  { name: "mobile", scheme: "dark" as const, viewport: { width: 390, height: 844 } },
];

const onlyIndex = process.argv.indexOf("--only");
const only = onlyIndex === -1 ? undefined : process.argv[onlyIndex + 1];

mkdirSync(OUT, { recursive: true });
const executablePath = process.env["PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"];
const browser = await chromium.launch(executablePath ? { executablePath } : {});
const violations: string[] = [];
try {
  for (const shot of SHOTS) {
    if (only !== undefined && !shot.name.includes(only)) continue;
    for (const mode of MODES) {
      const context = await browser.newContext({
        viewport: mode.viewport,
        colorScheme: mode.scheme,
        deviceScaleFactor: 1,
      });
      const page = await context.newPage();
      page.on("console", (message) => {
        if (message.text().includes("Content Security Policy")) {
          violations.push(`${shot.name}/${mode.name}: ${message.text()}`);
        }
      });
      await mockApi(page, {
        signedIn: shot.signedIn ?? true,
        admin: shot.admin ?? true,
        empty: shot.empty ?? false,
      });
      await page.goto(`${BASE}${shot.path}`, { waitUntil: "networkidle" });
      await page.locator(shot.ready).first().waitFor();
      if (shot.act) await shot.act(page);
      // フォーカスリングや遷移アニメーションが落ち着くのを待つ
      await page.waitForTimeout(300);
      const file = join(OUT, `${shot.name}-${mode.name}.png`);
      await page.screenshot({ path: file, fullPage: true });
      console.log(`wrote ${file}`);
      await context.close();
    }
  }
} finally {
  await browser.close();
}
if (violations.length > 0) {
  console.error(`CSP violations:\n${violations.join("\n")}`);
  process.exit(1);
}
