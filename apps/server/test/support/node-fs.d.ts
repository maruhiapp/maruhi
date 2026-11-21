declare module "node:fs" {
  export interface DirEntry {
    readonly name: string;
    isDirectory(): boolean;
  }
  export function readdirSync(path: string, options: { withFileTypes: true }): DirEntry[];
  export function readFileSync(path: string, encoding: "utf8"): string;
}
