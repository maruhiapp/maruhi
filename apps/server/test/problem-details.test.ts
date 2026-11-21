import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vite-plus/test";

import { BASE, JSON_HEADERS } from "./support/auth.ts";

describe("problem details (RFC 9457)", () => {
  it("renders a request decoding failure as a generic 400 problem", async () => {
    const response = await SELF.fetch(
      `${BASE}/projects/${"a".repeat(64)}/environments/env-app-0001/lease`,
      { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({}) },
    );
    expect(response.status).toBe(400);
    expect(response.headers.get("content-type")).toBe("application/problem+json");
    const body = (await response.json()) as Record<string, unknown>;
    expect(body["type"]).toBe("about:blank");
    expect(body["title"]).toBe("Bad Request");
    expect(body["status"]).toBe(400);
    expect(body["detail"]).toBe("Request validation failed");
    expect(body["errors"]).toBeUndefined();
    expect(JSON.stringify(body)).not.toContain("oidcToken");
  });

  it("keeps declared endpoint errors in their existing typed format", async () => {
    const response = await SELF.fetch(`${BASE}/auth/me`);
    expect(response.status).toBe(401);
    expect(response.headers.get("content-type")).toContain("application/json");
    expect(response.headers.get("content-type")).not.toContain("problem+json");
    const body = (await response.json()) as Record<string, unknown>;
    expect(body["_tag"]).toBe("Unauthorized");
  });
});
