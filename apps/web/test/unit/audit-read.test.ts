// 集約形 var.read の表示導出(src/dashboard/audit-read.ts)の unit テスト。
import { describe, expect, it } from "vitest";

import {
  aggregatedReadVariables,
  listedReadVariableLabel,
  readSummaryLabel,
} from "../../src/dashboard/audit-read.ts";

describe("aggregatedReadVariables", () => {
  it("集約形(variableId 欠落 + payload.variables)だけを列挙として返す", () => {
    expect(
      aggregatedReadVariables({
        event: "var.read",
        payload: {
          variables: [
            { variableId: "var-a", epoch: 1, version: 2 },
            { variableId: "var-b", epoch: 1, version: 1 },
          ],
        },
      }),
    ).toEqual([
      { variableId: "var-a", epoch: 1, version: 2 },
      { variableId: "var-b", epoch: 1, version: 1 },
    ]);
  });

  it("旧形(variableId 列あり)・他イベント・列挙なしは null", () => {
    expect(aggregatedReadVariables({ event: "var.read", variableId: "var-a" })).toBeNull();
    expect(
      aggregatedReadVariables({
        event: "var.version_pushed",
        payload: { variables: [{ variableId: "var-a" }] },
      }),
    ).toBeNull();
    expect(aggregatedReadVariables({ event: "var.read", payload: { note: "x" } })).toBeNull();
  });

  it("形の崩れた要素は落とし、整形できる項目だけを残す(サーバー申告の防御)", () => {
    expect(
      aggregatedReadVariables({
        event: "var.read",
        payload: {
          variables: [
            "not-an-object",
            { epoch: 1 },
            { variableId: "var-a", epoch: "1", version: 3 },
            [{ variableId: "var-nested" }],
          ],
        },
      }),
    ).toEqual([{ variableId: "var-a", epoch: undefined, version: 3 }]);
  });
});

describe("labels", () => {
  it("要約は件数に応じて単複を切り替える", () => {
    expect(readSummaryLabel(1)).toBe("read 1 variable");
    expect(readSummaryLabel(3)).toBe("read 3 variables");
  });

  it("展開行は欠落項目を出さない", () => {
    expect(listedReadVariableLabel({ variableId: "var-a", epoch: 2, version: 5 })).toBe(
      "var-a · epoch 2 · v 5",
    );
    expect(
      listedReadVariableLabel({ variableId: "var-a", epoch: undefined, version: undefined }),
    ).toBe("var-a");
  });
});
