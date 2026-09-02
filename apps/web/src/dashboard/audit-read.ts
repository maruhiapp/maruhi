// 集約形 `var.read`(AUDIT_SPEC §3.3 — 値付き一括 pull ごとに環境単位 1 行、
// payload に返した変数の列挙)の表示導出。純関数のみ(unit テスト対象)。
//
// サーバー / CLI は @maruhi/core の auditReadVariablesOf を共有するが、Web は
// api-schema からの type-only import しか持たない(TCB を最小に保つ — types.ts
// 冒頭)ため、同じ解釈をここに置く。全値はサーバー申告であり検証はしない —
// 形の崩れは optional アクセスで防御し、整形できる項目だけを表示する。
import type { AuditEvent } from "./types.ts";

/**
 * One variable listed by an aggregated `var.read` row, as reported by the
 * server. epoch / version are `undefined` when the entry did not carry a number.
 */
export interface ListedReadVariable {
  readonly variableId: string;
  readonly epoch: number | undefined;
  readonly version: number | undefined;
}

function isJsonRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function numberOrUndefined(value: unknown): number | undefined {
  return typeof value === "number" ? value : undefined;
}

/** 列挙の 1 要素の整形(variableId が文字列でなければ落とす)。 */
function listedReadVariableOf(entry: unknown): ListedReadVariable | null {
  if (!isJsonRecord(entry) || typeof entry["variableId"] !== "string") {
    return null;
  }
  return {
    variableId: entry["variableId"],
    epoch: numberOrUndefined(entry["epoch"]),
    version: numberOrUndefined(entry["version"]),
  };
}

/** payload の `variables` 列挙(配列でなければ null = 集約形ではない)。 */
function listedVariablesOf(
  payload: AuditEvent["payload"] | undefined,
): ReadonlyArray<ListedReadVariable> | null {
  const listed = payload?.["variables"];
  return Array.isArray(listed)
    ? listed.map(listedReadVariableOf).filter((entry) => entry !== null)
    : null;
}

/** 集約形 var.read の判定: イベント名 + variableId 欠落(旧形は列に持つ)+ 列挙。 */
export function aggregatedReadVariables(
  event: Pick<AuditEvent, "event" | "variableId" | "payload">,
): ReadonlyArray<ListedReadVariable> | null {
  return event.event === "var.read" && event.variableId === undefined
    ? listedVariablesOf(event.payload)
    : null;
}

/** 一覧の要約(英語 — ADR-0017): "read 3 variables" / "read 1 variable". */
export function readSummaryLabel(count: number): string {
  return `read ${count} ${count === 1 ? "variable" : "variables"}`;
}

/** 展開行の表示形: `var-id · epoch 1 · v 2`(欠落項目は出さない)。 */
export function listedReadVariableLabel(variable: ListedReadVariable): string {
  return [
    variable.variableId,
    ...(variable.epoch === undefined ? [] : [`epoch ${variable.epoch}`]),
    ...(variable.version === undefined ? [] : [`v ${variable.version}`]),
  ].join(" · ");
}
