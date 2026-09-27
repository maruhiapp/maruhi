// Minimal type declarations of node:fs used by vitest.config.ts (vite-node =
// runs under Node). The server tsconfig has only workers-types and no
// @types/node (to keep Node globals out of worker code). Only the narrow
// surface the config file needs is declared.

declare module "node:fs" {
  export interface DirEntry {
    readonly name: string;
    isDirectory(): boolean;
  }
  export function readdirSync(path: string, options: { withFileTypes: true }): DirEntry[];
  export function readFileSync(path: string, encoding: "utf8"): string;
}
