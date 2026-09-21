// ダッシュボードのワイヤ型は api-schema の Schema からの導出だけで持つ(DK K8-2)。
//
// `types.ts` の先頭コメントが述べる 2 つの規律を機械で留める:
// (1) 型は HttpApi の Schema の単一定義に束縛する — 手書きの `interface` / 型リテラルで
//     ワイヤの写しを別に持たない(写しは api-schema の改訂で黙って古くなる — K7-8 の上位互換)。
// (2) api-schema からは type-only import に限る — Effect / Schema の実行コードを
//     バンドル(= TCB)へ持ち込まない(verbatimModuleSyntax が消すのは `import type` の形)。
// lint の override でなくここに置くのは、対象のファイルが無ければ readFileSync が落ちる
// (空虚に通らない)ことと、件数を件数と比べて数え直しを不要にするため。
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const source = readFileSync(new URL("../../src/dashboard/types.ts", import.meta.url), "utf8");
const codeLines = source.split("\n").filter((line) => !line.trimStart().startsWith("//"));

describe("dashboard wire types are derived from api-schema (DK K8-2)", () => {
  it("declares no interface and no hand-written type literal", () => {
    const interfaces = codeLines.filter((line) => /^(export )?interface\s/.test(line));
    expect(interfaces, "types.ts must not hand-write an envelope").toEqual([]);
    const exportedTypes = codeLines.filter((line) => /^export type\s/.test(line));
    const derived = exportedTypes.filter((line) => /=\s*typeof \w+Schema\.Type;$/.test(line));
    expect(exportedTypes.length, "types.ts must export at least one type").toBeGreaterThan(0);
    expect(derived, "every exported type must be `typeof XxxSchema.Type`").toEqual(exportedTypes);
  });

  it("imports api-schema as type-only", () => {
    const imports = codeLines.filter((line) => /^import\s/.test(line));
    expect(imports.length, "types.ts must import from api-schema").toBeGreaterThan(0);
    for (const line of imports) {
      expect(line, "every import must be `import type` (never runtime Schema code)").toMatch(
        /^import type\s/,
      );
    }
  });
});
