// トークンスコープ判定(AUTH_SPEC §6 / §9-2 の min のスコープ半分)のユニットテスト。
// 結合則(複数エントリ・ワイルドカード併存・空配列)はここで意図を固定する。

import { describe, expect, it } from "vitest";

import { parseTokenScopes, permissionAtLeast, scopePermissionFor } from "../src/auth.ts";

const PROJECT = "ab".repeat(32);
const OTHER = "cd".repeat(32);

describe("permissionAtLeast(read < write < admin)", () => {
  it("orders permissions correctly", () => {
    expect(permissionAtLeast("read", "read")).toBe(true);
    expect(permissionAtLeast("read", "write")).toBe(false);
    expect(permissionAtLeast("write", "read")).toBe(true);
    expect(permissionAtLeast("write", "admin")).toBe(false);
    expect(permissionAtLeast("admin", "admin")).toBe(true);
  });
});

describe("scopePermissionFor(スコープ集合 → プロジェクトへの許可水準)", () => {
  it("returns null for an empty scope list (caller conceals the project)", () => {
    expect(scopePermissionFor([], PROJECT)).toBeNull();
  });

  it("returns null when no entry covers the project", () => {
    expect(scopePermissionFor([{ project: OTHER, permission: "admin" }], PROJECT)).toBeNull();
  });

  it("matches a wildcard entry", () => {
    expect(scopePermissionFor([{ project: "*", permission: "write" }], PROJECT)).toBe("write");
  });

  it("takes the strongest matching entry(個別指定はワイルドカードを絞れない)", () => {
    // 意図の固定: エントリは加算的(最強一致)。* × admin がある限り、個別の
    // read エントリを足しても当該プロジェクトの権限は admin のまま
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

describe("parseTokenScopes(保存 JSON の復元)", () => {
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
});
