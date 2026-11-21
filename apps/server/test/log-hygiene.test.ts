import { SELF } from "cloudflare:test";
import { afterEach, beforeAll, describe, expect, it, vi } from "vite-plus/test";

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
