// 集約形 var.read の表示導出(src/dashboard/audit-read.ts)の unit テスト。
import { describe, expect, it } from "vitest";

// 正準実装(web はパッケージ依存を持たないため、テストからのみソースを相対参照する)
import { auditReadVariablesOf } from "../../../../packages/core/src/audit.ts";
import {
  aggregatedReadVariables,
  listedReadVariableLabel,
  payloadWithoutVariables,
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

  it("core の auditReadVariablesOf と同じく、variableId 文字列 + 整数 epoch / version 以外の要素は落とす", () => {
    expect(
      aggregatedReadVariables({
        event: "var.read",
        payload: {
          variables: [
            "not-an-object",
            null,
            { epoch: 1, version: 1 },
            { variableId: "var-str-epoch", epoch: "1", version: 3 },
            { variableId: "var-no-version", epoch: 1 },
            { variableId: "var-no-epoch", version: 1 },
            { variableId: "var-float", epoch: 1.5, version: 2 },
            { variableId: "var-nan", epoch: 1, version: Number.NaN },
            [{ variableId: "var-nested", epoch: 1, version: 1 }],
            { variableId: "var-ok", epoch: 2, version: 3 },
          ],
        },
      }),
    ).toEqual([{ variableId: "var-ok", epoch: 2, version: 3 }]);
  });

  it("受理条件が @maruhi/core の auditReadVariablesOf と一致する", () => {
    const variables = [
      "x",
      { variableId: "a", epoch: 1, version: 1 },
      { variableId: "b", epoch: 1.5, version: 1 },
      { variableId: "c", epoch: 1 },
      { variableId: 3, epoch: 1, version: 1 },
      { variableId: "d", epoch: 0, version: 7 },
    ];
    expect(aggregatedReadVariables({ event: "var.read", payload: { variables } })).toEqual(
      auditReadVariablesOf({ variables }),
    );
  });
});

describe("payloadWithoutVariables", () => {
  it("列挙以外のキー(authMethod 等)だけを残し、無ければ null", () => {
    expect(
      payloadWithoutVariables({ variables: [{ variableId: "var-a" }], authMethod: "github_oauth" }),
    ).toEqual({ authMethod: "github_oauth" });
    expect(payloadWithoutVariables({ variables: [] })).toBeNull();
  });
});

describe("labels", () => {
  it("要約は件数に応じて単複を切り替える", () => {
    expect(readSummaryLabel(1)).toBe("read 1 variable");
    expect(readSummaryLabel(3)).toBe("read 3 variables");
  });

  it("展開行は variableId · epoch · version を並べる", () => {
    expect(listedReadVariableLabel({ variableId: "var-a", epoch: 2, version: 5 })).toBe(
      "var-a · epoch 2 · v 5",
    );
  });
});
