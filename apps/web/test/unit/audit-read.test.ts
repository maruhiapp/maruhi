// Unit test of the display derivation of the aggregated var.read
// shape (src/dashboard/audit-read.ts).
import { testVariableId } from "@maruhi/crypto/test-support";
import { describe, expect, it } from "vitest";

// The canonical implementation (web carries no package dependencies,
// so only tests reference the source by relative path)
import { auditReadVariablesOf } from "../../../../packages/core/src/audit.ts";
import {
  aggregatedReadVariables,
  lineageLabel,
  listedReadVariableLabel,
  payloadWithoutVariables,
  readSummaryLabel,
} from "../../src/dashboard/audit-read.ts";

describe("aggregatedReadVariables", () => {
  it("returns only the aggregated shape (missing variableId + payload.variables) as an enumeration", () => {
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

  it("returns null for the old shape (with a variableId column), another event, and no enumeration", () => {
    expect(
      aggregatedReadVariables({ event: "var.read", variableId: testVariableId("var-a") }),
    ).toBeNull();
    expect(
      aggregatedReadVariables({
        event: "var.version_pushed",
        payload: { variables: [{ variableId: "var-a" }] },
      }),
    ).toBeNull();
    expect(aggregatedReadVariables({ event: "var.read", payload: { note: "x" } })).toBeNull();
  });

  it("drops every element that is not variableId string + integer epoch / version, same as core's auditReadVariablesOf", () => {
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

  it("acceptance matches @maruhi/core's auditReadVariablesOf", () => {
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
  it("keeps only non-enumeration keys (authMethod etc.), null when none", () => {
    expect(
      payloadWithoutVariables({ variables: [{ variableId: "var-a" }], authMethod: "github_oauth" }),
    ).toEqual({ authMethod: "github_oauth" });
    expect(payloadWithoutVariables({ variables: [] })).toBeNull();
  });
});

describe("labels", () => {
  it("the summary switches singular/plural by the count", () => {
    const entry = (variableId: string, version: number) => ({ variableId, epoch: 1, version });
    expect(readSummaryLabel([entry("a", 1)])).toBe("read 1 variable");
    expect(readSummaryLabel([entry("a", 1), entry("b", 2), entry("c", 1)])).toBe(
      "read 3 variables",
    );
    // The version value range (VH): several versions of one variable
    expect(readSummaryLabel([entry("a", 2), entry("a", 3), entry("a", 4)])).toBe(
      "read 3 versions of 1 variable",
    );
  });

  it("the expanded row lists variableId · epoch · version", () => {
    expect(listedReadVariableLabel({ variableId: "var-a", epoch: 2, version: 5 })).toBe(
      "var-a · epoch 2 · v 5",
    );
  });
});

describe("lineageLabel (AUDIT_SPEC §3.3 — VH)", () => {
  it("derives re-encryption / rollback from sameValueAs and ignores everything else", () => {
    const pushed = (version: number, payload?: Readonly<Record<string, number | string>>) => ({
      event: "var.version_pushed",
      version,
      ...(payload === undefined ? {} : { payload }),
    });
    expect(lineageLabel(pushed(4, { sameValueAs: 3 }))).toBe("re-encryption of v 3");
    expect(lineageLabel(pushed(4, { sameValueAs: 1 }))).toBe("rollback to v 1");
    expect(lineageLabel(pushed(4))).toBeNull();
    expect(lineageLabel(pushed(4, { sameValueAs: "1" }))).toBeNull();
    expect(lineageLabel({ event: "var.read", version: 4, payload: { sameValueAs: 1 } })).toBeNull();
  });
});
