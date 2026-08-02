// vitest.config.ts(vite-node = Node 実行)が使う node:fs の最小型宣言。
// server の tsconfig は workers-types のみで @types/node を持たない(worker コードに
// Node グローバルを混入させないため)。設定ファイル専用の狭い表面だけを宣言する。

declare module "node:fs" {
  export interface DirEntry {
    readonly name: string;
    isDirectory(): boolean;
  }
  export function readdirSync(path: string, options: { withFileTypes: true }): DirEntry[];
  export function readFileSync(path: string, encoding: "utf8"): string;
}
