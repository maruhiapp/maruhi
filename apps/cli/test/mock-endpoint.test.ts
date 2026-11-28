import { apiRoute } from "@maruhi/test-kit/api";
import { describe, expect, it } from "vite-plus/test";

import { type MockRequest, offSpec, onEndpoint } from "./support/server.ts";

function requestOf(method: string, path: string, body: unknown = ""): MockRequest {
  return { method, path, query: {}, body, headers: {} };
}

describe("onEndpoint (a mock route typed from the API definition)", () => {
  it("answers the endpoint's method and path and passes the decoded path parameters", async () => {
    const seen: string[] = [];
    const handler = onEndpoint("deks.listMine", (request) => {
      seen.push(request.params.environmentId);
      return { status: 404, json: { _tag: "EnvironmentNotFound", environmentId: "dev" } };
    });
    expect(await handler(requestOf("GET", "/projects/p1/environments/dev%20a/deks"))).toEqual({
      status: 404,
      json: { _tag: "EnvironmentNotFound", environmentId: "dev" },
      contentType: "application/json",
    });
    expect(seen).toEqual(["dev a"]);
  });

  it("leaves another method or path to the next handler", async () => {
    const handler = onEndpoint("deks.listMine", () => ({ status: 200, json: { deks: [] } }));
    expect(await handler(requestOf("POST", "/projects/p1/environments/dev/deks"))).toBeNull();
    expect(await handler(requestOf("GET", "/projects/p1/environments/dev/deks/more"))).toBeNull();
    expect(await handler(requestOf("GET", "/projects/p1/environments//deks"))).toBeNull();
  });

  it("leaves a request whose path parameters differ from the given ones", async () => {
    const handler = onEndpoint("deks.listMine", { projectId: "p1" }, () => ({
      status: 200,
      json: { deks: [] },
    }));
    expect(await handler(requestOf("GET", "/projects/p2/environments/dev/deks"))).toBeNull();
    expect(await handler(requestOf("GET", "/projects/p1/environments/dev/deks"))).toEqual({
      status: 200,
      json: { deks: [] },
      contentType: "application/json",
    });
  });

  it("refuses a status the endpoint does not declare", async () => {
    const handler = onEndpoint("deks.listMine", () => ({ status: 418, json: { deks: [] } }));
    await expect(handler(requestOf("GET", "/projects/p1/environments/dev/deks"))).rejects.toThrow(
      "deks.listMine declares no response with status 418",
    );
  });

  it("refuses a body the status does not declare", async () => {
    const request = requestOf("GET", "/projects/p1/environments/dev/deks");
    const extraField = onEndpoint("deks.listMine", () => ({
      status: 200,
      json: { deks: [], extra: 1 },
    }));
    await expect(extraField(request)).rejects.toThrow(
      "deks.listMine declares no such body for status 200",
    );
    const errorAtSuccess = onEndpoint("deks.listMine", () => ({
      status: 200,
      json: { _tag: "EnvironmentNotFound", environmentId: "dev" },
    }));
    await expect(errorAtSuccess(request)).rejects.toThrow(
      "deks.listMine declares no such body for status 200",
    );
    const badFormat = onEndpoint("deks.listMine", () => ({
      status: 404,
      json: { _tag: "EnvironmentNotFound", environmentId: "dev a" },
    }));
    await expect(badFormat(request)).rejects.toThrow(
      "deks.listMine declares no such body for status 404",
    );
  });

  it("refuses a reply that brings its own body text or content type", async () => {
    const request = requestOf("POST", "/projects/p1/environments/dev/deks");
    const bodyText = onEndpoint("deks.register", () => ({ status: 204, bodyText: "done" }));
    await expect(bodyText(request)).rejects.toThrow("is offSpec");
    const contentType = onEndpoint("deks.register", () => ({
      status: 204,
      contentType: "text/html",
    }));
    await expect(contentType(request)).rejects.toThrow("is offSpec");
  });

  it("takes no body where the status has none, and sends a problem as a problem", () => {
    const register = apiRoute("deks.register");
    expect(register.verdictOf(204, undefined)).toEqual({ accepted: true, contentType: undefined });
    expect(register.verdictOf(204, null)).toEqual({ accepted: false, refusal: expect.any(String) });
    expect(register.verdictOf(204, {})).toEqual({ accepted: false, refusal: expect.any(String) });
    expect(register.verdictOf(500, { type: "about:blank", status: 500 })).toEqual({
      accepted: true,
      contentType: "application/problem+json",
    });
    expect(register.verdictOf(500, { _tag: "Internal" })).toEqual({
      accepted: false,
      refusal: expect.stringContaining("declares no such body for status 500"),
    });
  });

  it("sends an off-spec reply as it is", async () => {
    const handler = onEndpoint("deks.listMine", () =>
      offSpec({ status: 502, bodyText: "bad gateway" }),
    );
    expect(await handler(requestOf("GET", "/projects/p1/environments/dev/deks"))).toEqual({
      status: 502,
      bodyText: "bad gateway",
    });
  });
});
