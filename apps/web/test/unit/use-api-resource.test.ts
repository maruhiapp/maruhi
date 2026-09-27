// Unit test of the single-GET hook's state transitions on reload
// (src/dashboard/use-api-resource.ts).
import { describe, expect, it } from "vitest";

import { reloadingState } from "../../src/dashboard/use-api-resource.ts";

describe("reloadingState", () => {
  it("a reload of the same path keeps the previous value and sets refreshing (never swaps the table for a LoadingRow)", () => {
    expect(
      reloadingState({ path: "/a", state: { kind: "ok", value: 1, refreshing: false } }, "/a"),
    ).toEqual({ kind: "ok", value: 1, refreshing: true });
  });

  it("goes to loading without carrying the previous value over when the path changes", () => {
    expect(
      reloadingState({ path: "/a", state: { kind: "ok", value: 1, refreshing: false } }, "/b"),
    ).toEqual({ kind: "loading" });
  });

  it("goes to loading when the previous state is failed or loading (Retry stays the replacement form)", () => {
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
