// api.ts(セッション認証つき fetch 層 — 裁定 BP・BR)のユニットテスト。
// HTTP 状態 → 型付き結果の分類と、mutation への CSRF ヘッダー付与
// (AUTH_SPEC §11-4)を fetch スタブで固定する。CSRF ヘッダー名の**実送信値**は
// api-schema の CSRF_HEADER_NAME と照合する(裁定 CN — 型束縛〔satisfies〕と
// 相補の二層目。値 import はテストプロセスのみ — 裁定 BV と同じ位置づけ)。
import { CSRF_HEADER_NAME } from "@maruhi/api-schema";
import { afterEach, describe, expect, it, vi } from "vitest";

import { apiDelete, apiGet, apiPost } from "../../src/dashboard/api.ts";

function stubFetch(response: Response | Promise<Response>): ReturnType<typeof vi.fn> {
  const mock = vi.fn(() => Promise.resolve(response));
  vi.stubGlobal("fetch", mock);
  return mock;
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("apiGet", () => {
  it("returns ok with the parsed body on 200", async () => {
    stubFetch(jsonResponse(200, { userId: "u1", orgs: [] }));
    await expect(apiGet("/auth/me")).resolves.toEqual({
      kind: "ok",
      value: { userId: "u1", orgs: [] },
    });
  });

  it("classifies 401 as unauthorized", async () => {
    stubFetch(jsonResponse(401, { _tag: "Unauthorized" }));
    await expect(apiGet("/auth/me")).resolves.toEqual({ kind: "unauthorized" });
  });

  it("classifies 403 with the typed reason", async () => {
    stubFetch(jsonResponse(403, { _tag: "Forbidden", reason: "insufficient-role" }));
    await expect(apiGet("/projects/x/audit/invites")).resolves.toEqual({
      kind: "forbidden",
      reason: "insufficient-role",
    });
  });

  it("classifies a 403 without a parseable reason as forbidden with undefined reason", async () => {
    stubFetch(new Response("nope", { status: 403 }));
    await expect(apiGet("/x")).resolves.toEqual({ kind: "forbidden", reason: undefined });
  });

  it("classifies 404 as not-found (existence-hiding wording is the screen's job)", async () => {
    stubFetch(jsonResponse(404, { _tag: "ProjectNotFound" }));
    await expect(apiGet("/projects/x/chain")).resolves.toEqual({ kind: "not-found" });
  });

  it("classifies 410 with the typed reason (InviteGone — 裁定 CN 付随)", async () => {
    stubFetch(jsonResponse(410, { _tag: "InviteGone", reason: "completed" }));
    await expect(apiGet("/x")).resolves.toEqual({ kind: "gone", reason: "completed" });
  });

  it("classifies a 410 without a parseable reason as gone with undefined reason", async () => {
    stubFetch(new Response("nope", { status: 410 }));
    await expect(apiGet("/x")).resolves.toEqual({ kind: "gone", reason: undefined });
  });

  it("classifies 5xx and network failures as unreachable", async () => {
    stubFetch(jsonResponse(500, {}));
    await expect(apiGet("/x")).resolves.toEqual({ kind: "unreachable" });
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.reject(new Error("network down"))),
    );
    await expect(apiGet("/x")).resolves.toEqual({ kind: "unreachable" });
  });

  it("classifies a 200 with a non-JSON body as unreachable", async () => {
    stubFetch(new Response("<html></html>", { status: 200 }));
    await expect(apiGet("/x")).resolves.toEqual({ kind: "unreachable" });
  });
});

describe("apiPost", () => {
  it("sends the CSRF custom header (api-schema の実値と照合) and maps 204 to ok", async () => {
    const mock = stubFetch(new Response(null, { status: 204 }));
    await expect(apiPost("/auth/logout")).resolves.toEqual({ kind: "ok", value: undefined });
    expect(mock).toHaveBeenCalledWith("/auth/logout", {
      method: "POST",
      headers: { [CSRF_HEADER_NAME]: "1" },
    });
  });
});

describe("apiDelete", () => {
  it("sends DELETE with the CSRF custom header (失効面 — AUTH_SPEC §11-4)", async () => {
    const mock = stubFetch(new Response(null, { status: 204 }));
    await expect(apiDelete("/auth/tokens/tok-1")).resolves.toEqual({
      kind: "ok",
      value: undefined,
    });
    expect(mock).toHaveBeenCalledWith("/auth/tokens/tok-1", {
      method: "DELETE",
      headers: { [CSRF_HEADER_NAME]: "1" },
    });
  });

  it("classifies the uniform 404 of targeted revocation as not-found", async () => {
    stubFetch(jsonResponse(404, { _tag: "TokenNotFound" }));
    await expect(apiDelete("/auth/tokens/tok-1")).resolves.toEqual({ kind: "not-found" });
  });
});
