// Unit tests of token-scope judgement (the scope half of AUTH_SPEC §6 /
// §9-2's min). The combination rules (multiple entries, wildcard
// coexistence, empty array) pin their intent here.

import { describe, expect, it } from "vitest";

import { parseTokenScopes, permissionAtLeast, scopePermissionFor } from "../src/auth.ts";
import { decodeProjectId } from "../src/project.ts";

const PROJECT = decodeProjectId("ab".repeat(32));
const OTHER = decodeProjectId("cd".repeat(32));

describe("permissionAtLeast(read < write < admin)", () => {
  it("orders permissions correctly", () => {
    expect(permissionAtLeast("read", "read")).toBe(true);
    expect(permissionAtLeast("read", "write")).toBe(false);
    expect(permissionAtLeast("write", "read")).toBe(true);
    expect(permissionAtLeast("write", "admin")).toBe(false);
    expect(permissionAtLeast("admin", "admin")).toBe(true);
  });
});

describe("scopePermissionFor (scope set → permission level on a project)", () => {
  it("returns null for an empty scope list (caller conceals the project)", () => {
    expect(scopePermissionFor([], PROJECT)).toBeNull();
  });

  it("returns null when no entry covers the project", () => {
    expect(scopePermissionFor([{ project: OTHER, permission: "admin" }], PROJECT)).toBeNull();
  });

  it("matches a wildcard entry", () => {
    expect(scopePermissionFor([{ project: "*", permission: "write" }], PROJECT)).toBe("write");
  });

  it("takes the strongest matching entry (an individual entry cannot narrow a wildcard)", () => {
    // Intent being pinned: entries are additive (strongest match). As
    // long as * × admin exists, adding an individual read entry leaves
    // the project's permission at admin
    const scopes = [
      { project: "*", permission: "admin" },
      { project: PROJECT, permission: "read" },
    ] as const;
    expect(scopePermissionFor(scopes, PROJECT)).toBe("admin");
    expect(scopePermissionFor(scopes.toReversed(), PROJECT)).toBe("admin");
  });

  it("keeps distinct projects independent", () => {
    const scopes = [
      { project: PROJECT, permission: "write" },
      { project: OTHER, permission: "read" },
    ] as const;
    expect(scopePermissionFor(scopes, PROJECT)).toBe("write");
    expect(scopePermissionFor(scopes, OTHER)).toBe("read");
  });
});

describe("parseTokenScopes (restoring a stored JSON)", () => {
  it("round-trips a serialized scope array", () => {
    const scopes = [
      { project: "*", permission: "admin" },
      { project: PROJECT, permission: "read" },
    ];
    expect(parseTokenScopes(JSON.stringify(scopes))).toEqual(scopes);
  });

  it("rejects malformed JSON and non-scope shapes", () => {
    expect(parseTokenScopes("not json")).toBeNull();
    expect(parseTokenScopes('{"project":"*"}')).toBeNull();
    expect(parseTokenScopes('[{"project":"*","permission":"root"}]')).toBeNull();
    expect(parseTokenScopes('[{"permission":"read"}]')).toBeNull();
    expect(parseTokenScopes("[null]")).toBeNull();
  });

  it("rejects a scope whose project is not a ProjectId (owner-approved tightening)", () => {
    // The hand-written guard accepted any string for `project`;
    // TokenScopeSchema requires a ProjectId (64 lowercase hex) or "*"
    expect(parseTokenScopes('[{"project":"not-a-project-id","permission":"read"}]')).toBeNull();
    expect(parseTokenScopes(`[{"project":"${"AB".repeat(32)}","permission":"read"}]`)).toBeNull();
  });
});
