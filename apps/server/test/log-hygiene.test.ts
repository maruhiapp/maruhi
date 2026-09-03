// ログ衛生の回帰検査(hosted-ops.md §1 Workers Logs 行・DC-2)。
//
// 「リクエスト URL(= /projects/:id の capability — AUTH_SPEC §11-2)がログストアに残る」
// 欠陥は 2 回起きた: PR #137 の invocation log(wrangler 設定で塞ぐ — CI 8c)と、
// 2026-09-03 の演習で見つかった Effect `HttpMiddleware.logger`("Sent HTTP response" に
// `http.url` を注釈 — index.ts の disableLogger で塞ぐ)。設定検査はコード経路の退行を
// 見ないため、ここで「正常系リクエストを worker の fetch に通しても console のどこにも
// リクエストパスが現れない」ことを機械的に固定する(PR #139 pullfrog 指摘)。
//
// vitest-pool-workers ではテストと worker が同じ isolate で動くため、テスト側の
// console spy が worker 側の console 呼び出しを捕まえる(storage-guard.test.ts と同じ型)。
import { SELF } from "cloudflare:test";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { resetAuthDb } from "./support/auth.ts";

const CONSOLE_METHODS = ["log", "info", "warn", "error", "debug"] as const;

function spyConsole(): () => string {
  const spies = CONSOLE_METHODS.map((method) =>
    vi.spyOn(console, method).mockImplementation(() => {}),
  );
  return () =>
    spies
      .flatMap((spy) => spy.mock.calls)
      .map((args) =>
        args.map((arg) => (typeof arg === "string" ? arg : JSON.stringify(arg))).join(" "),
      )
      .join("\n");
}

describe("log hygiene: request paths never reach console (DC-2)", () => {
  beforeAll(async () => {
    await resetAuthDb();
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("does not log the project id of a /projects/:id request (authenticated or not)", async () => {
    const collect = spyConsole();
    // 実在しないが形式は正しい project id(64 hex)。認可前に拒否される経路でも、
    // Effect の既定ロガーは応答後に http.url を出していた(認可の成否と無関係)
    const projectId = "ab".repeat(32);
    const response = await SELF.fetch(`https://example.com/projects/${projectId}/audit-head`);
    expect(response.status).not.toBe(500);
    const logged = collect();
    expect(logged, "console output must not contain the request path / project id").not.toContain(
      projectId,
    );
    expect(logged).not.toContain("http.url");
    expect(logged).not.toContain("Sent HTTP response");
  });

  it("does not log the path or query of an OAuth callback request", async () => {
    const collect = spyConsole();
    const response = await SELF.fetch(
      "https://example.com/auth/github/callback?code=dummy-oauth-code&state=dummy",
    );
    expect(response.status).not.toBe(500);
    const logged = collect();
    expect(logged).not.toContain("dummy-oauth-code");
    expect(logged).not.toContain("/auth/github/callback");
  });

  it("keeps a healthy request silent (no per-request log line at all)", async () => {
    const collect = spyConsole();
    const response = await SELF.fetch("https://example.com/auth/config");
    expect(response.status).toBe(200);
    expect(collect()).toBe("");
  });
});
