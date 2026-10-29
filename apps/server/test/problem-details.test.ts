import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { BASE, JSON_HEADERS } from "./support/auth.ts";

// RFC 9457 problem details (Effect 4.1) — the applied scope and its
// boundary:
//
// - Applied: framework-level failures only, via the ProblemDetails
//   middleware declared on maruhiApi and `layerProblemDetails()` with
//   default options. A request that fails decoding is a 400
//   `application/problem+json` with a generic detail; per-field
//   `errors` are NOT included (includeDetails stays off — field paths
//   and schema reasons are internal, the same policy as the typed
//   errors' reason-code-only design).
// - Not applied: the declared endpoint errors keep their existing
//   `{_tag, reason, …}` JSON bodies (the AUTH_SPEC contract the web
//   dashboard and the CLI's typed client decode). The second test pins
//   that boundary.

describe("problem details (RFC 9457)", () => {
  it("renders a request decoding failure as a generic 400 problem", async () => {
    // The lease payload requires oidcToken + ephemeralPubHex; an empty
    // object fails decoding before any handler logic runs (the lease
    // group is unauthenticated — the credential is inside the payload)
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
    // No per-field breakdown and no schema internals leave the server
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
