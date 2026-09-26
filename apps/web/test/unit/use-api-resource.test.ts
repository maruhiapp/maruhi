// 単発 GET フックの再読込時の状態遷移(src/dashboard/use-api-resource.ts)の unit テスト。
import { describe, expect, it } from "vitest";

import { reloadingState } from "../../src/dashboard/use-api-resource.ts";

describe("reloadingState", () => {
  it("同じ path の再読込は直前の値を残し refreshing にする(表を LoadingRow に差し替えない)", () => {
    expect(
      reloadingState({ path: "/a", state: { kind: "ok", value: 1, refreshing: false } }, "/a"),
    ).toEqual({ kind: "ok", value: 1, refreshing: true });
  });

  it("path が変わったら前の値を持ち越さず loading", () => {
    expect(
      reloadingState({ path: "/a", state: { kind: "ok", value: 1, refreshing: false } }, "/b"),
    ).toEqual({ kind: "loading" });
  });

  it("直前が失敗・読込中なら loading(Retry は従来どおり置換形)", () => {
    expect(
      reloadingState<number>(
        { path: "/a", state: { kind: "failed", failure: { kind: "unreachable" } } },
        "/a",
      ),
    ).toEqual({ kind: "loading" });
    expect(reloadingState<number>({ path: "/a", state: { kind: "loading" } }, "/a")).toEqual({
      kind: "loading",
    });
  });
});
